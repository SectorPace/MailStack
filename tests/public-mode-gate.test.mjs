/**
 * A1 / T-2FA-1 + T-2FA-2: public-mode 2FA enrollment gate.
 *
 * When the deployment is internet-facing (ACCESS_MODE=caddy|direct, or
 * MAILSTACK_SECURITY_PROFILE=high) and admin.json has no `totp.enabled=true`,
 * server.production.ts must NOT serve the normal API. Instead it enters an
 * "enroll window": it binds 127.0.0.1 only, allows just the login + 2FA
 * endpoints, returns 403 for everything else (/api/domains, /api/users, ...),
 * and hard-exits (non-zero) if the window lapses without 2FA being enabled.
 *
 * These tests build the real bundle with esbuild and spawn it against a fake
 * install-args.conf + admin.json in a temp dir, so they exercise the shipped
 * startup path rather than a re-implementation. The window is shortened via
 * MAILSTACK_ENROLL_WINDOW_MS to keep the suite fast.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_TS = path.join(REPO, "backend", "server.production.ts");

// Build the standalone bundle once for the whole file. esbuild is a
// devDependency; the output is self-contained so it can live in a temp dir and
// never clobbers the real dist/ (that is rebuilt by the release gate).
//
// Fallback: when esbuild cannot run here (e.g. the suite is executed under WSL
// against a Windows-installed node_modules, whose esbuild native binary is the
// wrong platform), reuse the prebuilt dist/server.cjs. That bundle is pure JS
// with no native deps, so it runs on any Node; the integration workflow rebuilds
// it from current source (`npm run build:server`) before crossing platforms.
let SERVER_CJS = path.join(os.tmpdir(), `mailstack-gate-server-${process.pid}.cjs`);
try {
  const { build } = await import("esbuild");
  await build({
    entryPoints: [SERVER_TS],
    bundle: true,
    platform: "node",
    format: "cjs",
    outfile: SERVER_CJS,
    logLevel: "silent",
  });
} catch {
  const prebuilt = path.join(REPO, "dist", "server.cjs");
  assert.ok(
    fs.existsSync(prebuilt),
    "neither esbuild nor a prebuilt dist/server.cjs is available; run `npm run build:server`",
  );
  SERVER_CJS = prebuilt;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function tryConnect(port) {
  return new Promise((resolve) => {
    const sock = net.connect(port, "127.0.0.1");
    sock.setTimeout(500);
    sock.once("connect", () => { sock.destroy(); resolve(true); });
    sock.once("timeout", () => { sock.destroy(); resolve(false); });
    sock.once("error", () => { sock.destroy(); resolve(false); });
  });
}

async function waitForReady(port, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await tryConnect(port)) return;
    await sleep(50);
  }
  throw new Error(`server never became ready on 127.0.0.1:${port}`);
}

/**
 * Wait for a line to appear on the child's stdout.
 *
 * The startup banner is written from inside the `listen` callback
 * (server.production.ts L1568), and it crosses a pipe, so a successful TCP
 * connect does NOT mean the parent has already received it: `waitForReady`
 * resolving only proves the socket is bound. Reading `srv.stdout` immediately
 * afterwards is a race with no synchronisation, and it does lose under a busy
 * event loop (seen on Windows under a full parallel `node --test` run). Poll
 * for the expected output instead of assuming it has landed; on timeout, dump
 * both streams so the failure is diagnosable.
 */
async function waitForLog(srv, pattern, message, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pattern.test(srv.stdout)) return;
    await sleep(25);
  }
  throw new Error(
    `${message}; stdout=${JSON.stringify(srv.stdout)} stderr=${JSON.stringify(srv.stderr)}`,
  );
}

/** A minimal, already-configured administrator account (no totp). */
function adminJsonNoTotp(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const iterations = 100000;
  const hash = crypto.pbkdf2Sync(password, Buffer.from(salt, "hex"), iterations, 32, "sha256").toString("hex");
  return JSON.stringify({ username: "admin", algorithm: "pbkdf2-sha256", iterations, salt, hash }, null, 2);
}

/** The same account with 2FA already enabled (envelope-shaped, no plaintext). */
function adminJsonTotpEnabled(password) {
  const base = JSON.parse(adminJsonNoTotp(password));
  base.totp = { enc: "AAAA", nonce: "BBBB", tag: "CCCC", enabled: true, recovery: [] };
  return JSON.stringify(base, null, 2);
}

function startGateServer({ port, accessMode, windowMs, adminJson }) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mailstack-gate-"));
  const confPath = path.join(tmpDir, "install-args.conf");
  const adminPath = path.join(tmpDir, "admin.json");
  fs.writeFileSync(confPath, `ACCESS_MODE=${accessMode}\n`);
  fs.writeFileSync(adminPath, adminJson);
  const env = {
    ...process.env,
    ADMIN_FILE: adminPath,
    INSTALL_ARGS_CONF: confPath,
    ADMIN_PORT: String(port),
    ADMIN_HOST: "127.0.0.1",
    HOST: "127.0.0.1",
    MAILSTACK_ENROLL_WINDOW_MS: String(windowMs),
    DIST_DIR: tmpDir,
    // A5 hard-closes the COOKIE_SECURE=0 escape hatch in public mode (the process
    // refuses to listen), so a caddy/direct test server must use the production
    // value "1". local mode keeps "0" (correct over an SSH tunnel) and is never
    // gated. This mirrors a real deployment: public => Secure cookie, local => not.
    COOKIE_SECURE: accessMode === "local" ? "0" : "1",
    // B1: Node connects to the READ-ONLY socket (helper-ro.sock); the rw change
    // surface is 0600 root:root and unreachable from this process anyway. Point
    // the env at an absent path so the public-mode 503 semantics (no sudo
    // fallback on the ro channel) stay exercised.
    MAILSTACK_HELPER_RO_SOCKET: path.join(tmpDir, "absent-helper.sock"),
  };
  delete env.MAILSTACK_SECURITY_PROFILE;
  const child = spawn(process.execPath, [SERVER_CJS], { env, cwd: tmpDir, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => { stdout += d.toString(); });
  child.stderr.on("data", (d) => { stderr += d.toString(); });
  const exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  return {
    child,
    tmpDir,
    port,
    baseUrl: `http://127.0.0.1:${port}`,
    exited,
    get stdout() { return stdout; },
    get stderr() { return stderr; },
    stop() {
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
    },
  };
}

const PASSWORD = "Sup3r-Secret!Mailbox#Password";

test("T-2FA-1a: public mode without 2FA serves only the enroll window (GET /api/domains -> 403)", async (t) => {
  const port = await getFreePort();
  const srv = startGateServer({ port, accessMode: "caddy", windowMs: 20000, adminJson: adminJsonNoTotp(PASSWORD) });
  t.after(() => srv.stop());
  await waitForReady(port);

  // The startup log must show it bound loopback-only inside the enroll window.
  await waitForLog(srv, /MailStack API on 127\.0\.0\.1:/, "must bind 127.0.0.1 in the enroll window");
  await waitForLog(srv, /\[ENROLL WINDOW\]/, "must announce the enroll window");

  const res = await fetch(`${srv.baseUrl}/api/domains`);
  assert.equal(res.status, 403, "GET /api/domains must be forbidden during the enroll window");
  const body = await res.json();
  assert.equal(body?.error?.code, "ENROLL_WINDOW_ACTIVE");

  // Health stays reachable so orchestrators can see the process is alive.
  const health = await fetch(`${srv.baseUrl}/api/health`);
  assert.equal(health.status, 200, "/api/health must remain reachable in the enroll window");
});

test("T-2FA-1b: the enroll window hard-exits non-zero when it lapses without 2FA", async (t) => {
  const port = await getFreePort();
  const srv = startGateServer({ port, accessMode: "caddy", windowMs: 1500, adminJson: adminJsonNoTotp(PASSWORD) });
  t.after(() => srv.stop());
  await waitForReady(port);

  const { code, signal } = await Promise.race([
    srv.exited,
    sleep(8000).then(() => ({ code: null, signal: "TIMEOUT" })),
  ]);
  assert.notEqual(signal, "TIMEOUT", `server should have exited on window lapse; stderr:\n${srv.stderr}`);
  assert.notEqual(code, 0, "process must exit non-zero when the enroll window lapses without 2FA");
});

test("T-2FA-2: an authenticated session is still fenced inside the enroll window (domains.add -> 403)", async (t) => {
  const port = await getFreePort();
  const srv = startGateServer({ port, accessMode: "caddy", windowMs: 20000, adminJson: adminJsonNoTotp(PASSWORD) });
  t.after(() => srv.stop());
  await waitForReady(port);

  // Login is on the enroll allowlist, so it must succeed even inside the window.
  const login = await fetch(`${srv.baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "admin", password: PASSWORD }),
  });
  assert.equal(login.status, 200, `login must succeed in the enroll window; stderr:\n${srv.stderr}`);
  const loginBody = await login.json();
  const csrf = loginBody.csrf;
  const setCookie = login.headers.getSetCookie().find((c) => c.startsWith("mailstack_session="));
  assert.ok(setCookie, "login must set a session cookie");
  const cookie = setCookie.split(";")[0];

  // A mutating, authenticated call must still be refused: the gate is about the
  // deployment being internet-facing without 2FA, not about being logged out.
  const add = await fetch(`${srv.baseUrl}/api/domains`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf },
    body: JSON.stringify({ name: "example.com" }),
  });
  assert.equal(add.status, 403, "domains.add must be forbidden during the enroll window even when authenticated");
  const addBody = await add.json();
  assert.equal(addBody?.error?.code, "ENROLL_WINDOW_ACTIVE");
});

test("A1: local mode is never gated (no enroll window, normal auth applies)", async (t) => {
  const port = await getFreePort();
  const srv = startGateServer({ port, accessMode: "local", windowMs: 20000, adminJson: adminJsonNoTotp(PASSWORD) });
  t.after(() => srv.stop());
  await waitForReady(port);
  // Await the banner before the negative assertion: on a still-empty stdout it
  // would pass for the wrong reason.
  await waitForLog(srv, /MailStack API on /, "local mode must log its bind address");

  assert.doesNotMatch(srv.stdout, /\[ENROLL WINDOW\]/, "local mode must not enter the enroll window");
  const res = await fetch(`${srv.baseUrl}/api/domains`);
  // Not gated: the request reaches the normal auth layer (401), never the 403 gate.
  assert.notEqual(res.status, 403);
  const body = await res.json().catch(() => ({}));
  assert.notEqual(body?.error?.code, "ENROLL_WINDOW_ACTIVE");
});

test("A1: public mode WITH 2FA enabled starts normally (no enroll window)", async (t) => {
  const port = await getFreePort();
  const srv = startGateServer({ port, accessMode: "caddy", windowMs: 20000, adminJson: adminJsonTotpEnabled(PASSWORD) });
  t.after(() => srv.stop());
  await waitForReady(port);
  // Same reason as above: the banner must have landed before asserting absence.
  await waitForLog(srv, /MailStack API on /, "2FA-enabled public mode must log its bind address");

  assert.doesNotMatch(srv.stdout, /\[ENROLL WINDOW\]/, "2FA-enabled public mode must not enter the enroll window");
  const res = await fetch(`${srv.baseUrl}/api/domains`);
  const body = await res.json().catch(() => ({}));
  assert.notEqual(body?.error?.code, "ENROLL_WINDOW_ACTIVE", "a 2FA-enabled public deployment serves the normal API");
});

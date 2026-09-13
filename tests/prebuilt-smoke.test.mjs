import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import { spawn } from "node:child_process";

import { readPackageVersion, rootDir } from "./_source.mjs";
function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, json: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    }).on("error", reject);
  });
}

async function waitForHealth(url, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await httpGet(url);
      if (res.status === 200 && (res.json?.status === "ok" || res.json?.ok)) {
        return res;
      }
    } catch {
      // Retry
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`Timed out waiting for ${url} to report healthy`);
}

test("Standalone prebuilt server.cjs starts and responds in clean environment with zero node_modules", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mailstack-prebuilt-test-"));
  const serverDist = path.resolve("dist/server.cjs");
  const indexDist = path.resolve("dist/index.html");

  assert.ok(fs.existsSync(serverDist), "dist/server.cjs must exist");
  fs.copyFileSync(serverDist, path.join(tmpDir, "server.cjs"));
  if (fs.existsSync(indexDist)) {
    fs.copyFileSync(indexDist, path.join(tmpDir, "index.html"));
  }

  // Ensure absolutely no node_modules exists in the sandbox
  assert.equal(fs.existsSync(path.join(tmpDir, "node_modules")), false);

  const port = 19181;
  const proc = spawn(process.execPath, ["server.cjs"], {
    cwd: tmpDir,
    env: { ...process.env, PORT: String(port), HOST: "127.0.0.1" },
    stdio: "pipe",
  });

  try {
    const health = await waitForHealth(`http://127.0.0.1:${port}/api/health`);
    assert.equal(health.status, 200);
    assert.equal(health.json.status, "ok");
    assert.equal(health.json.service, "mailstack-admin-api");
    assert.equal(health.json.version, readPackageVersion());
  } finally {
    proc.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 200));
    try {
      proc.kill("SIGKILL");
    } catch {}
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Standalone prebuilt webmail.cjs starts and responds in clean environment with zero node_modules", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mailstack-webmail-prebuilt-test-"));
  const webmailDist = path.resolve("dist/webmail.cjs");

  assert.ok(fs.existsSync(webmailDist), "dist/webmail.cjs must exist");
  fs.copyFileSync(webmailDist, path.join(tmpDir, "webmail.cjs"));

  // Ensure absolutely no node_modules exists in the sandbox
  assert.equal(fs.existsSync(path.join(tmpDir, "node_modules")), false);

  const port = 19182;
  const proc = spawn(process.execPath, ["webmail.cjs"], {
    cwd: tmpDir,
    env: { ...process.env, PORT: String(port), HOST: "127.0.0.1", WEBMAIL_PORT: String(port) },
    stdio: "pipe",
  });

  try {
    const health = await waitForHealth(`http://127.0.0.1:${port}/api/webmail/health`);
    assert.equal(health.status, 200);
    assert.equal(health.json.status, "ok");
    assert.equal(health.json.service, "mailstack-webmail");
    assert.equal(health.json.version, readPackageVersion());
  } finally {
    proc.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 200));
    try {
      proc.kill("SIGKILL");
    } catch {}
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

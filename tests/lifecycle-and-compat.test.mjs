import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readMailstackctl, rootDir } from "./_source.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test("mailstack.sh uninstall thoroughly cleans up mailstack-web and mailstack-webmail", () => {
  const sh = fs.readFileSync(path.join(rootDir, "mailstack.sh"), "utf8");
  assert.match(sh, /systemctl disable --now mailstack-web mailstack-webmail/);
  assert.match(sh, /mailstack-webmail\.service/);
  assert.match(sh, /systemctl daemon-reload/);
  assert.match(sh, /status mailstack-webmail/);
  assert.match(sh, /journalctl -u mailstack-web/);
});

test("privileged helper useradd/del fallback checks returncode and avoids truthy CompletedProcess bug", () => {
  const py = readMailstackctl();
  assert.doesNotMatch(py, /check=False\)\s+or\s+run\(/);
  assert.match(py, /if r\.returncode != 0:/);
  assert.match(py, /raise RuntimeError\(f"useradd failed/);
  assert.match(py, /raise RuntimeError\(f"adduser failed/);
});

test("deploy/install.sh verifies both web and webmail services, handles npm errors strictly", () => {
  const installSh = fs.readFileSync(path.join(rootDir, "deploy", "install.sh"), "utf8");
  assert.doesNotMatch(installSh, /npm install --no-audit --no-fund \|\| true/);
  assert.match(installSh, /fail 'Node\.js 依赖安装失败'/);
  assert.match(installSh, /is-active --quiet mailstack-web/);
  assert.match(installSh, /is-active --quiet mailstack-webmail/);
  assert.match(installSh, /WEBMAIL_PUBLIC_DIR/);
  assert.match(installSh, /fail '创建 mailstack-admin 用户组失败'/);
  assert.match(installSh, /fail '创建 mailstack-admin 系统用户失败'/);
  assert.match(installSh, /id mailstack-admin/);
  assert.match(installSh, /logrotate/);
  assert.match(installSh, /执行安装后服务健康自检/);
  assert.match(installSh, /fail 'Webmail 前端静态入口不存在'/);
});

test("package.json cleanly separates runtime dependencies from build devDependencies", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf8"));
  assert.ok(!pkg.dependencies.vite, "vite should not be in dependencies");
  assert.ok(pkg.devDependencies.vite, "vite should be in devDependencies");
});

test("webmail/server.mjs has robust directory resolution and structured health/error endpoints", () => {
  const webmailSrc = fs.readFileSync(path.join(rootDir, "webmail", "server.mjs"), "utf8");
  assert.match(webmailSrc, /resolvePublicDir/);
  assert.match(webmailSrc, /\/api\/webmail\/health/);
  assert.match(webmailSrc, /uptimeSec/);
  assert.match(webmailSrc, /Retry-After/);
  assert.match(webmailSrc, /RATE_LIMITED/);
  assert.match(webmailSrc, /error:\s*\{\s*code,\s*message:\s*message\s*\|\|\s*code\s*\}/);
});

test("backend/server.production.ts health endpoint includes metadata and security features", () => {
  const serverSrc = fs.readFileSync(path.join(rootDir, "backend", "server.production.ts"), "utf8");
  assert.match(serverSrc, /builtAt/);
  assert.match(serverSrc, /uptimeSec/);
  assert.match(serverSrc, /build-manifest\.json/);
  assert.match(serverSrc, /Retry-After/);
  assert.match(serverSrc, /RATE_LIMITED/);
  assert.match(serverSrc, /resolveDistDir/);
});

test("privileged helper records destructive operations to audit log", () => {
  const py = readMailstackctl();
  assert.match(py, /mailstack-rpc-audit\.log/);
  assert.match(py, /DESTRUCTIVE_ACTIONS/);
  assert.match(py, /audit\(action,\s*True,\s*req_data=data\)/);
});

test("frontend includes robust React ErrorBoundary component", () => {
  assert.ok(fs.existsSync(path.join(rootDir, "src", "components", "ErrorBoundary.tsx")));
  const appSrc = fs.readFileSync(path.join(rootDir, "src", "App.tsx"), "utf8");
  assert.match(appSrc, /<ErrorBoundary>/);
});

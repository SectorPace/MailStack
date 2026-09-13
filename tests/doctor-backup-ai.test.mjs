import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readMailstackctl, rootDir } from "./_source.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test("mailstack.sh contains 1.0 Production CLI command suite", () => {
  const sh = fs.readFileSync(path.join(rootDir, "mailstack.sh"), "utf8");
  assert.match(sh, /doctor_cmd/);
  assert.match(sh, /test_mail_cmd/);
  assert.match(sh, /backup_cmd/);
  assert.match(sh, /restore_cmd/);
  assert.match(sh, /rollback_cmd/);
  assert.match(sh, /--dry-run/);
  assert.match(sh, /--purge/);
  assert.match(sh, /用户邮箱数据 \(\/home\/\*\/Maildir 与 \/var\/vmail\): 完整保留/);
});

test("mailstackctl.py exports all 1.0 Production RPC actions", () => {
  const py = readMailstackctl();
  assert.match(py, /system_doctor\(\)/);
  assert.match(py, /mail_test_loopback/);
  assert.match(py, /backup_create/);
  assert.match(py, /backup_list/);
  assert.match(py, /backup_restore/);
  assert.match(py, /backup_delete/);
  assert.match(py, /ai_config_set/);
  assert.match(py, /ai_request/);
});

test("server.production.ts routes expose doctor, loopback, backup and ai endpoints", () => {
  const ts = fs.readFileSync(path.join(rootDir, "backend", "server.production.ts"), "utf8");
  assert.match(ts, /\/api\/doctor/);
  assert.match(ts, /\/api\/mail\/test-loopback/);
  assert.match(ts, /\/api\/backups\/restore/);
  assert.match(ts, /\/api\/ai\/config/);
});

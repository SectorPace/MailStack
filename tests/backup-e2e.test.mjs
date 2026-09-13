import assert from "node:assert/strict";
import test from "node:test";
import { pythonBin } from "./_source.mjs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

test("Backup and Restore E2E Integrity, Path Traversal, and SHA256 test suite passes", () => {
  const scriptPath = path.join(rootDir, "scripts", "test_backup_e2e.py");
  const child = spawnSync(pythonBin, [scriptPath], { encoding: "utf8" });
  if (child.status !== 0) {
    console.error("Backup E2E Test stderr:", child.stderr);
    console.log("Backup E2E Test stdout:", child.stdout);
  }
  assert.equal(child.status, 0, "test_backup_e2e.py must exit with code 0");
  assert.match(child.stdout, /All Backup E2E Tests Passed Successfully/);
});

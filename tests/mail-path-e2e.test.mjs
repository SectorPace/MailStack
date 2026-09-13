import assert from "node:assert/strict";
import test from "node:test";
import { pythonBin } from "./_source.mjs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

test("Mail Delivery Path E2E verification test suite passes", () => {
  const scriptPath = path.join(rootDir, "scripts", "test_mail_path_e2e.py");
  const child = spawnSync(pythonBin, [scriptPath], { encoding: "utf8" });
  if (child.status !== 0) {
    console.error("Mail Path E2E Test stderr:", child.stderr);
    console.log("Mail Path E2E Test stdout:", child.stdout);
  }
  assert.equal(child.status, 0, "test_mail_path_e2e.py must exit with code 0");
  assert.match(child.stdout, /All Mail Path E2E Tests Passed Successfully/);
});

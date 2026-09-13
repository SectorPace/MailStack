import assert from "node:assert/strict";
import test from "node:test";
import { pythonBin } from "./_source.mjs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

test("Release Version and Manifest Consistency across package.json, manifest, mailstackctl, changelog", () => {
  const scriptPath = path.join(rootDir, "scripts", "verify_release_consistency.py");
  const child = spawnSync(pythonBin, [scriptPath], { encoding: "utf8" });
  if (child.status !== 0) {
    console.error("Release Consistency Test stderr:", child.stderr);
    console.log("Release Consistency Test stdout:", child.stdout);
  }
  assert.equal(child.status, 0, "verify_release_consistency.py must exit with code 0");
  assert.match(child.stdout, /All Release Version References Are 100% Consistent/);
});

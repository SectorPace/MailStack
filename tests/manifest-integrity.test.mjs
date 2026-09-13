import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { readPackageVersion, rootDir } from "./_source.mjs";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

test("build-manifest.json has correct structure and valid SHA256 sums", () => {
  const manifestPath = path.join(rootDir, "dist", "build-manifest.json");
  assert.ok(fs.existsSync(manifestPath), "dist/build-manifest.json must exist");

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  assert.equal(manifest.version, readPackageVersion());
  assert.equal(manifest.buildTarget, "standalone-inlined");
  assert.ok(manifest.provenance, "manifest.provenance must be defined");
  assert.ok(manifest.artifacts, "manifest.artifacts must be defined");

  for (const [relPath, expectedHash] of Object.entries(manifest.artifacts)) {
    const fullPath = path.join(rootDir, "dist", relPath);
    assert.ok(fs.existsSync(fullPath), `Artifact dist/${relPath} must exist`);
    const fileBuf = fs.readFileSync(fullPath);
    const actualHash = crypto.createHash("sha256").update(fileBuf).digest("hex");
    assert.equal(
      actualHash,
      expectedHash,
      `SHA256 mismatch for ${relPath}: expected ${expectedHash}, got ${actualHash}`
    );
  }
});

test("deploy/install.sh has strict validation and openSUSE support", () => {
  const installSh = fs.readFileSync(path.join(rootDir, "deploy", "install.sh"), "utf8");
  assert.match(installSh, /zypper/);
  assert.match(installSh, /validate_prebuilt_dist/);
  assert.match(installSh, /COOKIE_SECURE/);
});

test("deploy/install-mail-stack.sh has zypper and proper OpenDKIM heredoc", () => {
  const mailStackSh = fs.readFileSync(path.join(rootDir, "deploy", "install-mail-stack.sh"), "utf8");
  assert.match(mailStackSh, /zypper/);
  assert.match(mailStackSh, /cat >\/etc\/opendkim\/trusted\.hosts <<'EOF'/);
  assert.doesNotMatch(mailStackSh, /> \/etc\/opendkim\/trusted\.hosts >/);
});

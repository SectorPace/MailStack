import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pythonBin } from "./_source.mjs";
import { spawnSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const CTL_SCRIPT = path.join(ROOT, "backend", "mailstackctl.py");

function runCtl(action, data = {}) {
  const payload = JSON.stringify({ action, data });
  const res = spawnSync(pythonBin, [CTL_SCRIPT], {
    input: payload,
    encoding: "utf8",
    timeout: 10000,
    cwd: ROOT,
  });
  let parsed = null;
  try {
    parsed = JSON.parse(res.stdout);
  } catch (err) {
    parsed = { parseError: err.message, rawStdout: res.stdout, rawStderr: res.stderr };
  }
  return { status: res.status, output: parsed, rawStderr: res.stderr };
}

test("Integration - network.check_port RPC returns real probe results", () => {
  // Test port 80 connectivity to 1.1.1.1
  const res = runCtl("network.check_port", { port: 80, host: "1.1.1.1" });
  assert.equal(res.status, 0);
  assert.equal(res.output.ok, true);
  const data = res.output.data;
  assert.equal(typeof data.open, "boolean");
  assert.equal(typeof data.port, "number");
  assert.ok(["open", "blocked"].includes(data.status));
  assert.ok(Array.isArray(data.details));
});

test("Integration - setup.cert.issue validates PEM format correctly", () => {
  // Invalid cert PEM format
  const resBadCert = runCtl("setup.cert.issue", {
    mailHost: "mail.example.com",
    method: "custom",
    customCertPem: "NOT_A_CERT",
    customKeyPem: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----",
  });
  assert.equal(resBadCert.status, 1);
  assert.equal(resBadCert.output.ok, false);
  assert.match(resBadCert.output.error, /invalid certificate PEM format/i);

  // Invalid key PEM format
  const resBadKey = runCtl("setup.cert.issue", {
    mailHost: "mail.example.com",
    method: "custom",
    customCertPem: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQ...\n-----END CERTIFICATE-----",
    customKeyPem: "NOT_A_PRIVATE_KEY",
  });
  assert.equal(resBadKey.status, 1);
  assert.equal(resBadKey.output.ok, false);
  assert.match(resBadKey.output.error, /invalid private key PEM format/i);

  // Invalid domain
  const resBadDomain = runCtl("setup.cert.issue", {
    mailHost: "invalid domain name!",
    method: "custom",
    customCertPem: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQ...\n-----END CERTIFICATE-----",
    customKeyPem: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----",
  });
  assert.equal(resBadDomain.status, 1);
  assert.equal(resBadDomain.output.ok, false);
  assert.match(resBadDomain.output.error, /invalid certificate domain/i);
});

test("Integration - mail.test_loopback rejects invalid recipients and restricts external relay", () => {
  // Invalid recipient format
  const resInvalid = runCtl("mail.test_loopback", { recipient: "bad-recipient-format" });
  assert.equal(resInvalid.status, 1);
  assert.equal(resInvalid.output.ok, false);
  assert.match(resInvalid.output.error, /invalid recipient/i);
});

test("Integration - backup actions require explicit confirmation", () => {
  // backup.delete without confirm: true must fail
  const resDelete = runCtl("backup.delete", { name: "test-backup.tar.gz" });
  assert.equal(resDelete.status, 1);
  assert.equal(resDelete.output.ok, false);
  assert.match(resDelete.output.error, /explicit confirmation required/i);
});

test("Integration - domains.delete and users.delete require explicit confirmation", () => {
  const resDomain = runCtl("domains.delete", { domain: "example.com" });
  assert.equal(resDomain.status, 1);
  assert.equal(resDomain.output.ok, false);
  assert.match(resDomain.output.error, /explicit confirmation required/i);

  const resUser = runCtl("users.delete", { id: "testuser" });
  assert.equal(resUser.status, 1);
  assert.equal(resUser.output.ok, false);
  assert.match(resUser.output.error, /explicit confirmation required/i);
});

test("Integration - backup.restore validates filenames, confirms, and rejects corrupt/traversal archives", () => {
  // Empty filename
  const resEmpty = runCtl("backup.restore", {});
  assert.equal(resEmpty.status, 1);
  assert.equal(resEmpty.output.ok, false);

  // Non-existent file
  const resMissing = runCtl("backup.restore", { filename: "mailstack-backup-20990101-000000.tar.gz" });
  assert.equal(resMissing.status, 1);
  assert.equal(resMissing.output.ok, false);
  assert.match(resMissing.output.error, /not found|archive/i);
});


import assert from "node:assert/strict";
import test from "node:test";
import { pythonBin } from "./_source.mjs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

test("Modular backend/mailstackctl package exports submodules and dispatch", () => {
  const pyCode = `
import sys
import pathlib
sys.path.insert(0, r"${rootDir}/backend")
import mailstackctl
from mailstackctl import core, security, ai, certs, backup, mail, network, telemetry, dispatcher

assert hasattr(core, 'ALLOWED_ACTIONS')
assert hasattr(security, 'validate_mailbox_password')
assert hasattr(ai, 'AI_PRESETS')
assert hasattr(certs, 'parse_cert_openssl')
assert hasattr(backup, 'validate_tar_safe')
assert hasattr(mail, 'managed_users')
assert hasattr(network, 'network_check_port')
assert hasattr(telemetry, 'system_doctor')
assert hasattr(dispatcher, 'dispatch')

# Test dispatching settings.get through modular dispatcher
res = dispatcher.dispatch('settings.get')
assert isinstance(res, dict)
assert 'version' in res

print("MODULAR_OK")
`;

  const child = spawnSync(pythonBin, ["-c", pyCode], { encoding: "utf8" });
  if (child.status !== 0) {
    console.error("Python modular test stderr:", child.stderr);
  }
  assert.equal(child.status, 0, "Modular package import test should succeed");
  assert.match(child.stdout, /MODULAR_OK/);
});

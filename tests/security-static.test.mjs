import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readMailstackctl } from "./_source.mjs";

import { pythonBin } from "./_source.mjs";

// The privileged helper is a package, not a single file. Read all of it or these
// assertions silently stop guarding anything.
const py = readMailstackctl();
test("password validation", () =>
  assert.match(py, /validate_mailbox_password/));
test("canonical mailboxes", () => assert.match(py, /managed-mailboxes\.json/));
test("SASL 0600", () => assert.match(py, /0o600/));
test("Zhipu BigModel GLM-4 and Multi-Provider AI Hub", () => {
  assert.match(py, /glm-4/);
  assert.match(py, /AI_PRESETS/);
  assert.match(py, /ai_request/);
});
test("AI TLS strict default verification and SSRF defense", () => {
  assert.match(py, /validate_ai_endpoint/);
  assert.match(py, /get_ai_ssl_context/);
  assert.match(py, /ipaddress\.ip_address/);
  assert.match(py, /is_private/);
});

test("Backup secret protection and partial failure handling", () => {
  assert.match(py, /include_secrets/);
  assert.match(py, /--exclude=\/etc\/postfix\/sasl_passwd/);
  assert.match(py, /--exclude=\/etc\/mailstack\/ai\.json/);
  assert.match(py, /allow_partial/);
});

test("Backup restore SHA256 integrity and single-pass safe extraction", () => {
  assert.match(py, /safe_extract_tar/);
  assert.match(py, /validate_tar_safe/);
  assert.match(py, /expected_sha/);
  assert.match(py, /allowed_prefixes/);
});

test("Outbound SSRF validation for AI and SMTP Relay", () => {
  assert.match(py, /validate_outbound_ip/);
  assert.match(py, /validate_relay/);
  assert.match(py, /allow_private/);
});

test("Strict loopback test recipient restriction", () => {
  assert.match(py, /rec_domain/);
  assert.match(py, /managed_mailboxes/);
});

test("Dovecot socket permissions, Postfix master.cf, and access modes", () => {
  const installSh = fs.readFileSync(new URL("../deploy/install.sh", import.meta.url), "utf8");
  const installMailStackSh = fs.readFileSync(new URL("../deploy/install-mail-stack.sh", import.meta.url), "utf8");
  assert.match(installSh, /mode = 0660/);
  assert.match(installSh, /user = mailstack-webmail/);
  assert.match(installSh, /User=mailstack-webmail/);
  assert.doesNotMatch(installSh, /mailstack-webmail ALL=/);
  assert.match(installSh, /--access-mode/);
  assert.match(installSh, /caddy/);
  assert.match(installMailStackSh, /smtpd_tls_auth_only = yes/);
  assert.match(installMailStackSh, /submission inet/);
  assert.match(installMailStackSh, /smtps {5}inet/);
  assert.match(installMailStackSh, /universe/);
});

test("Server session hard cap and login attempt sliding window", () => {
  const srv = fs.readFileSync(new URL("../backend/server.production.ts", import.meta.url), "utf8");
  assert.match(srv, /MAX_ATTEMPT_KEYS/);
  assert.match(srv, /900000/);
  assert.match(srv, /MAX_SESSIONS/);
  assert.match(srv, /oldestKey/);
});

test("Password policy is defined once and enforced at every call site", () => {
  // The bounds used to be spelled out inline in core.py, network.py and security.py,
  // and only one of the three rejected control characters. Assert on the single
  // definition plus the fact that no module rolls its own length check.
  assert.match(py, /MIN_PASSWORD_LENGTH = 12/);
  assert.match(py, /MAX_PASSWORD_LENGTH = 256/);
  assert.match(py, /def validate_mailbox_password/);
  assert.doesNotMatch(py, /12 <= len\(password\) <= 256/);
  assert.doesNotMatch(py, /len\(password\) < 12 or len\(password\) > 256/);
});

test("Password policy rejects short, long and control-character passwords", () => {
  const pyPath = new URL("../backend/mailstackctl/", import.meta.url);
  const check = JSON.stringify([
    "", "short", "x".repeat(11), "x".repeat(256), "x".repeat(257),
    "abcdef\r\ngh", "abcdefg\u0000hij",
    "a1b" + "c3d6f9h2j5".repeat(25), // 253-char compliant password, must pass
  ]);
  const script = [
    "import json,sys",
    "sys.path.insert(0, sys.argv[1])",
    "from mailstackctl.core import validate_mailbox_password as v",
    "out=[]",
    "for c in json.loads(sys.argv[2]):",
    "    try:",
    "        v(c)",
    "        out.append(True)",
    "    except ValueError:",
    "        out.append(False)",
    "print(json.dumps(out))",
  ].join("\n");
  const r = spawnSync(pythonBin, ["-c", script, fileURLToPath(pyPath).replace(/mailstackctl[\\/]$/, ""), check], {
    encoding: "utf8",
  });
  assert.equal(r.status, 0, `policy probe failed: ${r.stderr}`);
  const accepted = JSON.parse(r.stdout.trim());
  // x-only passwords are rejected by the rc.5 composition rules (letters+digits,
  // no 3+ equal/sequential run); only the compliant probe may pass.
  assert.deepEqual(accepted, [false, false, false, false, false, false, false, true], "only a compliant password may pass");
});

test("Package build scripts ensure standalone zero-external bundling", () => {
  const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.doesNotMatch(pkg.scripts["build:server"], /--external/);
  assert.doesNotMatch(pkg.scripts["build:webmail"], /--external/);
});

test("Distro matrix test script ensures non-zero exit on failure", () => {
  const matrixPy = fs.readFileSync(new URL("../scripts/test_distro_matrix.py", import.meta.url), "utf8");
  assert.match(matrixPy, /sys\.exit\(1\)/);
  assert.match(matrixPy, /test_native_linux/);
});

test("Release hygiene - no debug passwords or host machine absolute paths in source and deployment scripts", () => {
  // deploy/mailstack-cli 是死文件，rc.3 已从发布包移除（verify-release-scripts.sh
  // 会对其存在报错）。这里继续按存在读取导致该测试在 rc.3 上必然失败——
  // 两道门禁互相矛盾，删掉这个引用。
  const filesToCheck = [
    "../deploy/install.sh",
    "../deploy/install-mail-stack.sh",
    "../mailstack.sh",
    "../backend/mailstackctl.py",
    "../backend/server.production.ts",
    "../webmail/server.mjs",
  ];

  for (const rel of filesToCheck) {
    const content = fs.readFileSync(new URL(rel, import.meta.url), "utf8");
    assert.doesNotMatch(content, /Admin@123/, `Debug password Admin@123 must not exist in ${rel}`);
    assert.doesNotMatch(content, /\/mnt\/e\b/, `Host-specific path /mnt/e must not exist in ${rel}`);
  }
  // Same rules apply to every module inside the helper package.
  const pkgDir = new URL("../backend/mailstackctl/", import.meta.url);
  const modules = fs.readdirSync(pkgDir).filter((n) => n.endsWith(".py"));
  assert.ok(modules.length > 0, "helper package must contain python modules");
  for (const name of modules) {
    const content = fs.readFileSync(new URL(name, pkgDir), "utf8");
    assert.doesNotMatch(content, /Admin@123/, `Debug password Admin@123 must not exist in backend/mailstackctl/${name}`);
    assert.doesNotMatch(content, /\/mnt\/e\b/, `Host-specific path /mnt/e must not exist in backend/mailstackctl/${name}`);
  }
});

test("Release hygiene - packaging script excludes pycache, pyc, and source maps", () => {
  const pkgPy = fs.readFileSync(new URL("../scripts/package.py", import.meta.url), "utf8");
  assert.match(pkgPy, /__pycache__/);
  assert.match(pkgPy, /\.pyc/);
});

test("A2+B1/T-PEER-2: rw actions always take the sudo wrapper; the ro channel never falls back to sudo in public mode", () => {
  // The B1 dual-socket split re-scoped the invariant this gate enforces.
  // ctl() now routes by action kind:
  //   rw -> ctlViaSudo unconditionally (public AND local): the sudoers-gated
  //         wrapper IS the change surface; the rw socket (helper.sock, 0600
  //         root:root) is root-only and Node cannot connect to it.
  //   ro -> ctlViaSocket (helper-ro.sock); only a transport-level failure may
  //         fall back to the one-shot sudo path, and ONLY in local mode.
  //         Public mode keeps the A2 invariant scoped to the ro channel: no
  //         sudo spawn at all when the read-only socket is down.
  const srv = fs.readFileSync(new URL("../backend/server.production.ts", import.meta.url), "utf8");
  const guard = "if (PUBLIC_MODE) throw err;";
  const fallback = "return ctlViaSudo(action, data);";
  const rwPrimary = 'if (effectiveKind === "rw") {';
  const transportFilter = "if (err.message !== HELPER_UNAVAILABLE) throw err;";
  const guardIdx = srv.indexOf(guard);
  const firstFallbackIdx = srv.indexOf(fallback);
  const rwPrimaryIdx = srv.indexOf(rwPrimary);
  const roFallbackIdx = srv.indexOf(fallback, guardIdx);
  assert.ok(guardIdx !== -1, "public-mode guard `if (PUBLIC_MODE) throw err;` must exist in ctl()'s ro branch");
  assert.ok(firstFallbackIdx !== -1, "the sudo transport call must still exist");
  assert.ok(rwPrimaryIdx !== -1, "ctl() must branch on effectiveKind for the B1 split");
  // The rw branch hosts the PRIMARY sudo transport and is unconditional: its
  // body is a bare ctlViaSudo return, not gated by PUBLIC_MODE, so mutating
  // actions reach the sudoers-gated wrapper on public deployments too.
  const rwBranchBody = srv.slice(rwPrimaryIdx, srv.indexOf("}", rwPrimaryIdx));
  assert.match(rwBranchBody, /return ctlViaSudo\(action, data\);/, "the rw branch body must call ctlViaSudo directly");
  assert.ok(!rwBranchBody.includes("PUBLIC_MODE"), "the rw primary transport must not be gated by PUBLIC_MODE");
  assert.ok(rwPrimaryIdx < guardIdx, "the rw primary transport must be defined before (and independent of) the ro PUBLIC_MODE guard");
  // The ro-channel fallback: the PUBLIC_MODE guard must short-circuit it in
  // public mode (guard precedes the fallback inside the catch)...
  assert.ok(roFallbackIdx !== -1, "the ro-channel sudo fallback must still exist for local non-systemd hosts");
  assert.ok(guardIdx < roFallbackIdx, "the PUBLIC_MODE guard must precede the ro-channel ctlViaSudo fallback so it is unreachable in public mode");
  // ...and only transport-level failures may take it.
  assert.ok(
    srv.indexOf(transportFilter) < guardIdx,
    "the PUBLIC_MODE guard must follow the HELPER_UNAVAILABLE transport filter",
  );
  // B1: kind is optional now; when omitted, routing derives from RW_ACTIONS.
  assert.match(srv, /function ctl\([^)]*kind\?: 'ro' \| 'rw'/);
  // B1: the ro channel goes through the read-only socket transport.
  assert.match(srv, /return ctlViaSocket\(action, data\)\.catch/);
  // B1: Node connects to the READ-ONLY socket only (helper-ro.sock).
  assert.match(srv, /MAILSTACK_HELPER_RO_SOCKET/);
  assert.match(srv, /\/run\/mailstack\/helper-ro\.sock/);
});

test("A2: helper daemon gates peers with SO_PEERCRED and audits denials", () => {
  // The unix-socket daemon must verify the peer credentials (pid/uid/gid) after
  // accept and deny any uid that is neither root nor the mailstack-admin service
  // account, recording a peer_denied audit entry.
  assert.match(py, /SO_PEERCRED/);
  assert.match(py, /peer_denied/);
  assert.match(py, /getpwnam\('mailstack-admin'\)/);
});

test("B1: RW_ACTIONS mirrors core.py ALLOWED_ACTIONS_RW item-for-item (no drift)", () => {
  // The B1 routing table is declared twice -- python side
  // (ALLOWED_ACTIONS_RO / ALLOWED_ACTIONS_RW) and Node side (RW_ACTIONS) -- and
  // a single drift would silently route a mutating action onto the read-only
  // socket (where the daemon refuses it) or waste sudo forks on read-only
  // actions. Parse both definitions and compare item-for-item.
  const corePy = fs.readFileSync(new URL("../backend/mailstackctl/core.py", import.meta.url), "utf8");
  const srv = fs.readFileSync(new URL("../backend/server.production.ts", import.meta.url), "utf8");

  const pySet = (varName) => {
    const start = corePy.indexOf(`${varName} = {`);
    assert.ok(start !== -1, `${varName} must exist in core.py`);
    const end = corePy.indexOf("\n}", start);
    const items = [...corePy.slice(start, end).matchAll(/['"]([a-z0-9_.]+)['"]/g)].map((m) => m[1]);
    assert.ok(items.length > 0, `${varName} must not be empty`);
    return new Set(items);
  };
  const tsSet = (constName) => {
    const start = srv.indexOf(`const ${constName} = new Set<string>([`);
    assert.ok(start !== -1, `const ${constName} must exist in server.production.ts`);
    const end = srv.indexOf("]);", start);
    const items = [...srv.slice(start, end).matchAll(/"([a-z0-9_.]+)"/g)].map((m) => m[1]);
    assert.ok(items.length > 0, `${constName} must not be empty`);
    return new Set(items);
  };

  const pyRo = pySet("ALLOWED_ACTIONS_RO");
  const pyRw = pySet("ALLOWED_ACTIONS_RW");
  const tsRw = tsSet("RW_ACTIONS");

  // Every python RW action must be routed through the sudo wrapper in Node...
  const missingInTs = [...pyRw].filter((a) => !tsRw.has(a));
  assert.deepEqual(missingInTs, [], "ALLOWED_ACTIONS_RW items missing from RW_ACTIONS would be sent to the read-only socket");
  // ...and Node must not mark anything rw that python does not.
  const extraInTs = [...tsRw].filter((a) => !pyRw.has(a));
  assert.deepEqual(extraInTs, [], "RW_ACTIONS items outside ALLOWED_ACTIONS_RW would bypass the read-only socket");
  // The two python channels must partition cleanly (no action on both).
  const both = [...pyRo].filter((a) => pyRw.has(a));
  assert.deepEqual(both, [], "an action may belong to only one channel (RO xor RW)");
  // Both sides must remain non-trivial partitions of the full allowlist.
  assert.ok(pyRo.size >= 10, "ALLOWED_ACTIONS_RO must stay a real read-only surface");
  assert.ok(pyRw.size >= 30, "ALLOWED_ACTIONS_RW must stay a real change surface");
});

test("B1/T-SOCK: daemon binds a dual socket surface (ro 0660 admin, rw 0600 root-only) and audits ro violations", () => {
  // Static half of T-SOCK-1/T-SOCK-2 (the behavioural half lives in
  // scripts/test_actions_unit.py's DualSocket class): the change surface must
  // be root-only (0600 root:root) so the admin console cannot connect to it
  // without sudo (T-SOCK-1), and the read-only surface must refuse mutating
  // actions with a dedicated ro_channel_violation audit entry (T-SOCK-2).
  // Sudoers stays a single rule: the one-shot wrapper is the only sanctioned
  // root channel.
  const daemonPy = fs.readFileSync(new URL("../backend/mailstackctl/daemon.py", import.meta.url), "utf8");
  const installSh = fs.readFileSync(new URL("../deploy/install.sh", import.meta.url), "utf8");

  // Two sockets: ro (Node-facing, group-writable by mailstack-admin) + rw (root-only).
  assert.match(daemonPy, /helper-ro\.sock/);
  assert.match(daemonPy, /RO_SOCKET_PATH/);
  // Per-channel peer gate: ro accepts root+mailstack-admin, rw accepts root only.
  assert.match(daemonPy, /def _allowed_uids/);
  assert.match(daemonPy, /if channel == 'ro'/);
  // rw socket: 0600 root:root (Node cannot connect -> T-SOCK-1 fails closed).
  assert.match(daemonPy, /mode=0o600, group=None/);
  assert.match(daemonPy, /os\.chown\(self\._socket_path, 0, 0\)/);
  // ro socket: 0660 root:mailstack-admin, serving ALLOWED_ACTIONS_RO only.
  assert.match(daemonPy, /mode=0o660, group='mailstack-admin'/);
  assert.match(daemonPy, /allowed_actions=ALLOWED_ACTIONS_RO/);
  // T-SOCK-2: a mutating action on the ro channel is refused + audited.
  assert.match(daemonPy, /ro_channel_violation/);
  assert.match(daemonPy, /action in ALLOWED_ACTIONS_RW/);
  // Baseline: sudoers stays exactly one rule, and the legacy second rule
  // (mailstack-web-ctl) is actively cleaned up on every install.
  assert.match(installSh, /mailstack-admin ALL=\(root\) NOPASSWD: \/usr\/local\/libexec\/mailstack-privileged/);
  assert.match(installSh, /rm -f \/etc\/sudoers\.d\/mailstack-web-ctl/);
});

/**
 * Slice one branch body out of install.sh's `case "$ACCESS_MODE" in ... esac`.
 * Branch labels are 2-space indented (`  caddy)`); bodies are 4-space indented,
 * so the lookahead only stops at the next branch label, never at a body line.
 */
function sliceAccessModeBranch(src, mode) {
  const caseStart = src.indexOf('case "$ACCESS_MODE" in');
  if (caseStart === -1) return null;
  const caseEnd = src.indexOf("\nesac", caseStart);
  const block = src.slice(caseStart, caseEnd === -1 ? undefined : caseEnd);
  const re = new RegExp(`\\n {2}${mode}\\)\\n([\\s\\S]*?)(?=\\n {2}\\S+\\)|$)`);
  const m = re.exec(block);
  return m ? m[1] : null;
}

test("A5: public systemd unit template pins HOST=127.0.0.1 and COOKIE_SECURE=1", () => {
  const installSh = fs.readFileSync(new URL("../deploy/install.sh", import.meta.url), "utf8");
  // The generated mailstack-web unit writes HOST from ADMIN_HOST and the cookie
  // Secure flag from COOKIE_SECURE_VAL -- the two knobs A5 hardens for public mode.
  assert.match(installSh, /Environment=HOST=\$\{ADMIN_HOST\}/);
  assert.match(installSh, /Environment=COOKIE_SECURE=\$\{COOKIE_SECURE_VAL\}/);
  // HTTPS deployments (caddy/direct) force the Secure cookie flag; the default is 0.
  assert.match(installSh, /COOKIE_SECURE_VAL=0/);
  assert.match(installSh, /if \[\[ \$HTTPS_MODE -eq 1 \]\]; then\s*\n\s*COOKIE_SECURE_VAL=1/);
  // Both public branches keep the admin panel on loopback with HTTPS_MODE=1, so
  // HOST resolves to 127.0.0.1 and COOKIE_SECURE resolves to 1 on a public install.
  for (const mode of ["caddy", "direct"]) {
    const branch = sliceAccessModeBranch(installSh, mode);
    assert.ok(branch, `${mode}) branch not found in install.sh ACCESS_MODE case`);
    assert.match(branch, /ADMIN_HOST="127\.0\.0\.1"/, `${mode} must bind the admin panel to loopback`);
    assert.match(branch, /HTTPS_MODE=1/, `${mode} must enable HTTPS (=> COOKIE_SECURE=1)`);
  }
  // A5 hard gate: direct refuses to install without TLS evidence.
  const direct = sliceAccessModeBranch(installSh, "direct");
  assert.match(direct, /_direct_tls_present/, "direct must probe for TLS evidence");
  assert.match(direct, /fail /, "direct must fail when no TLS evidence is present");
});

test("A5: server.production.ts hard-closes production escape hatches before listen", () => {
  const srv = fs.readFileSync(new URL("../backend/server.production.ts", import.meta.url), "utf8");
  assert.match(srv, /function assertNoEscapeHatches\(\)/);
  // All four escape-hatch switches are refused in public mode.
  assert.match(srv, /process\.env\.COOKIE_SECURE === "0"/);
  assert.match(srv, /HOST === "0\.0\.0\.0"/);
  assert.match(srv, /process\.env\.MAILSTACK_AUDIT_FAILOPEN === "1"/);
  assert.match(srv, /process\.env\.MAILSTACK_ALLOW_UNSAFE_GIT === "1"/);
  // The only exemption is MAILSTACK_I_AM_A_DEVELOPER=1 AND access-mode local.
  assert.match(srv, /MAILSTACK_I_AM_A_DEVELOPER === "1"/);
  assert.match(srv, /readAccessMode\(\) === "local"/);
  assert.match(srv, /process\.exit\(1\)/);
  // The assertion is invoked at startup and must run before the socket is bound.
  assert.match(srv, /assertNoEscapeHatches\(\);/);
  assert.ok(
    srv.indexOf("assertNoEscapeHatches();") < srv.indexOf("app.listen("),
    "escape-hatch assertion must run before app.listen()",
  );
});

test("A4/A5: mailstack.sh gates UNSAFE_GIT in public mode and refuses downgrade", () => {
  const sh = fs.readFileSync(new URL("../mailstack.sh", import.meta.url), "utf8");
  // A5 UNSAFE_GIT double gate: refused in public mode unless developer+local.
  assert.match(sh, /MAILSTACK_ALLOW_UNSAFE_GIT/);
  assert.match(sh, /MAILSTACK_I_AM_A_DEVELOPER/);
  assert.match(sh, /_installed_access_mode/);
  // A4 downgrade gate primitives.
  assert.match(sh, /_semver_lt\(\)/);
  assert.match(sh, /assert_no_downgrade\(\)/);
  assert.match(sh, /--allow-downgrade/);
  assert.match(sh, /downgrade_allowed/);
  // Source guard lets T-UP-1 exercise the pure functions without command dispatch.
  assert.match(sh, /BASH_SOURCE\[0\][^\n]*!=[^\n]*\$\{0\}/);
});

test("A5/T-ESC-1: doctor scans the web unit and process env for escape hatches", () => {
  assert.match(py, /def escape_hatch_scan/);
  assert.match(py, /MAILSTACK_ALLOW_UNSAFE_GIT/);
  assert.match(py, /MAILSTACK_AUDIT_FAILOPEN/);
  assert.match(py, /COOKIE_SECURE/);
  assert.match(py, /Environment=/);
  assert.match(py, /\/proc\/\{pid\}\/environ/);
});

// ---------------------------------------------------------------------------
// PR-B2..B5 gates
// ---------------------------------------------------------------------------

/**
 * Slice one generated systemd unit out of install.sh (`cat >unit <<EOF` ... `EOF`).
 * Directives sit at the start of a line while unit comments start with `#`,
 * so assertion regexes anchored with ^...$ /m cannot be fooled by prose.
 */
function sliceUnit(src, unitFile) {
  const start = src.indexOf(`cat >${unitFile} <<EOF`);
  if (start === -1) return null;
  const end = src.indexOf("\nEOF", start);
  return src.slice(start, end === -1 ? undefined : end);
}

test("B4/T-PERM-1: helper unit carries the full systemd hardening set", () => {
  const installSh = fs.readFileSync(new URL("../deploy/install.sh", import.meta.url), "utf8");
  const helper = sliceUnit(installSh, "/etc/systemd/system/mailstack-helper.service");
  assert.ok(helper, "install.sh must generate the mailstack-helper unit");
  // The privileged helper keeps exactly the /etc subtrees it must write via
  // ReadWritePaths; everything else about the unit is locked down. The last
  // three directives are the B4 additions on top of the A-series baseline.
  for (const directive of [
    "ProtectSystem=full",
    "ReadWritePaths=${HELPER_RW_PATHS}",
    "PrivateTmp=true",
    "NoNewPrivileges=true",
    "ProtectKernelTunables=true",
    "ProtectKernelModules=true",
    "ProtectControlGroups=true",
    "RestrictRealtime=true",
    "RestrictSUIDSGID=true",
    "LockPersonality=true",
    "SystemCallFilter=@system-service",
  ]) {
    assert.ok(helper.includes(directive), `helper unit must carry ${directive}`);
  }
});

test("B4/T-PERM-1: web unit is ProtectSystem=strict and cannot write /etc/mailstack", () => {
  const installSh = fs.readFileSync(new URL("../deploy/install.sh", import.meta.url), "utf8");
  const web = sliceUnit(installSh, "/etc/systemd/system/mailstack-web.service");
  assert.ok(web, "install.sh must generate the mailstack-web unit");
  // The whole filesystem is read-only for the admin console: every write to
  // /etc/mailstack (admin.json, settings.json, ...) goes through the helper
  // daemon's namespace via sudo mailstack-privileged + the rw socket.
  assert.match(web, /^ProtectSystem=strict$/m);
  assert.doesNotMatch(web, /^ReadWritePaths=/m,
    "web must not carve out any writable path; /etc/mailstack writes belong to the helper daemon");
  // Deliberate omissions: NoNewPrivileges/RestrictSUIDSGID would break the
  // sudo setuid escalation the rw channel depends on (see the unit's own
  // comment for the rationale) -- their absence is the design, not an oversight.
  assert.doesNotMatch(web, /^NoNewPrivileges=/m);
  assert.doesNotMatch(web, /^RestrictSUIDSGID=/m);
  assert.match(web, /^LockPersonality=true$/m);
});

test("B4: webmail unit keeps its strict baseline untouched", () => {
  const installSh = fs.readFileSync(new URL("../deploy/install.sh", import.meta.url), "utf8");
  const webmail = sliceUnit(installSh, "/etc/systemd/system/mailstack-webmail.service");
  assert.ok(webmail, "install.sh must generate the mailstack-webmail unit");
  assert.match(webmail, /^ProtectSystem=strict$/m);
  assert.match(webmail, /^ReadWritePaths=-\/home -\/var\/vmail$/m);
  assert.match(webmail, /^NoNewPrivileges=true$/m);
  assert.match(webmail, /^RestrictSUIDSGID=true$/m);
});

test("B4: sudo wrapper forwards over the rw socket with a direct-run fallback", () => {
  const privileged = fs.readFileSync(new URL("../deploy/mailstack-privileged", import.meta.url), "utf8");
  const cliPy = fs.readFileSync(new URL("../backend/mailstackctl.py", import.meta.url), "utf8");
  // No-argument invocation takes the forwarding mode; explicit arguments
  // (audit-verify) pass through unchanged.
  assert.match(privileged, /--rw-forward/);
  assert.match(cliPy, /'--rw-forward'/);
  assert.match(cliPy, /def rw_forward/);
  assert.match(cliPy, /def _forward_over_rw_socket/);
  // The forward timeout stays under the Node-side helper timeout (120s) so
  // the wrapper is never the component that hangs the longest.
  assert.match(cliPy, /FORWARD_TIMEOUT_SECONDS = 115/);
});

test("B2/T-BKP-1: backup.create refuses passphrase-less runs in public mode", () => {
  assert.match(py, /backup\.create requires a passphrase in public mode/);
  assert.match(py, /backup\.restore requires a passphrase in public mode/);
  assert.match(py, /def plaintext_backup_scan/);
});

test("B3/T-AUD-1: audit records chain via prev_hash and mirror to syslog AUTHPRIV", () => {
  assert.match(py, /AUDIT_GENESIS/);
  assert.match(py, /'prev_hash': prev_hash/);
  assert.match(py, /def audit_verify\b/);
  assert.match(py, /def audit_verify_cli/);
  assert.match(py, /audit head anchor mismatch/);
  assert.match(py, /LOG_AUTHPRIV/);
  // doctor re-uses the same verifier in-process instead of shelling out.
  assert.match(py, /audit_result = audit_verify\(\)/);
  // Remote syslog forwarding is a WARN-level probe, not a FAIL.
  assert.match(py, /def remote_syslog_scan/);
});

test("B5: AI outbound is opt-in in public mode and the crypto policy is pinned", () => {
  assert.match(py, /def ai_outbound_enabled/);
  assert.match(py, /AI_OUTBOUND_ACTIONS/);
  assert.match(py, /AI outbound actions are disabled in public mode/);
  // Algorithm inventory, pinned: PBKDF2-SHA256 at 310k iterations for
  // passwords, AES-256-GCM for the TOTP envelope, TLS left to Caddy/OpenSSL.
  assert.match(py, /PBKDF2_ITERATIONS = 310000/);
  assert.match(py, /pbkdf2_hmac\('sha256'/);
  assert.match(py, /from \.totp import AESGCM/);
  // Doctor self-checks the policy at runtime (tamper with the constant and
  // the panel lights up a FAIL).
  assert.match(py, /PBKDF2_ITERATIONS == 310000 and AESGCM is not None/);
  // Key material permissions are FAIL-level checks, not soft warnings.
  assert.match(py, /def key_permission_scan/);
});

test("B5: session cookie is HttpOnly; SameSite=Strict with Secure on HTTPS", () => {
  const srv = fs.readFileSync(new URL("../backend/server.production.ts", import.meta.url), "utf8");
  // HttpOnly + SameSite=Strict are hard-coded into every Set-Cookie header
  // (issue and clear paths alike); Secure is conditionally appended and A5's
  // escape-hatch gate already refuses COOKIE_SECURE=0 in public mode.
  assert.match(srv, /HttpOnly; SameSite=Strict/);
  assert.match(srv, /secureCookie \? "; Secure" : ""/);
});

test("B3: `ms audit-verify` is exposed through the shell wrapper", () => {
  const sh = fs.readFileSync(new URL("../mailstack.sh", import.meta.url), "utf8");
  assert.match(sh, /audit-verify/);
});




/**
 * T-DOCK-1: Docker admin-port gate (MailStack 冲98 checklist A6).
 *
 * docker/entrypoint.sh defaults the admin panel to loopback (LISTEN_HOST
 * 127.0.0.1). Publishing it to a non-loopback address (so `docker -p` can reach
 * it through the container's eth0) requires BOTH explicit flags:
 *
 *   MAILSTACK_LISTEN_HOST=<non-loopback>  AND  MAILSTACK_I_PUBLISH_ADMIN=1
 *
 * gate_listen_host() runs first thing in main(), before any seed/init/process
 * spawn, and exits 1 when a non-loopback LISTEN_HOST is missing either flag. So
 * a bare `docker run -p 8787:8787` (no flags) never comes up.
 *
 * MAILSTACK_ENTRYPOINT_DRYRUN=1 lets the passing cases stop right after the gate
 * (exit 0) without starting the 6 real processes, so this test never launches
 * postfix/dovecot/node. The rejecting cases exit 1 at the gate itself.
 *
 * Cross-platform bash: on Linux/CI `bash` is native; on Windows we prefer WSL
 * bash (System32) and translate the repo path to its /mnt/<drive>/... form, with
 * Git-Bash and plain POSIX forms as fallbacks. If no bash is reachable the test
 * is skipped with an explicit reason (record it and re-run under WSL).
 */
import assert from "node:assert/strict";
import test from "node:test";
import { resolveBash, bashRepoCandidates, runBashStdin } from "./_source.mjs";

const bashExe = resolveBash();
const candList = bashRepoCandidates();

const driver = `
set -uo pipefail
REPO=''
for cand in ${candList}; do
  if [[ -f "$cand/docker/entrypoint.sh" ]]; then REPO="$cand"; break; fi
done
if [[ -z "$REPO" ]]; then echo "RESULT NO_SCRIPT"; exit 98; fi
cd "$REPO" || { echo "RESULT CD_FAIL"; exit 98; }
EP=docker/entrypoint.sh

emit(){ printf 'RESULT %s %s\\n' "$1" "$2"; }
has(){ case "$2" in *"$3"*) emit "$1" 1;; *) emit "$1" 0;; esac; }

# 1) Default (no MAILSTACK_LISTEN_HOST): loopback, gate passes, DRYRUN exits 0.
out=$(MAILSTACK_ENTRYPOINT_DRYRUN=1 bash "$EP" 2>&1); rc=$?
emit default_rc "$rc"
has default_loopback "$out" 'LISTEN_HOST=127.0.0.1'

# 2) T-DOCK-1 core: non-loopback WITHOUT the publish flag -> gate exits 1.
out=$(MAILSTACK_ENTRYPOINT_DRYRUN=1 MAILSTACK_LISTEN_HOST=0.0.0.0 bash "$EP" 2>&1); rc=$?
emit noflag_rc "$rc"
has noflag_msg "$out" 'MAILSTACK_I_PUBLISH_ADMIN'

# 3) Non-loopback WITH both flags -> gate passes, DRYRUN exits 0.
out=$(MAILSTACK_ENTRYPOINT_DRYRUN=1 MAILSTACK_LISTEN_HOST=0.0.0.0 MAILSTACK_I_PUBLISH_ADMIN=1 bash "$EP" 2>&1); rc=$?
emit bothflags_rc "$rc"
has bothflags_publish "$out" 'LISTEN_HOST=0.0.0.0'

# 4) No flag and NO dryrun: the gate still runs before any process spawn, so the
#    bare-publish path exits 1 and never reaches the 6-process orchestration.
out=$(MAILSTACK_LISTEN_HOST=0.0.0.0 bash "$EP" 2>&1); rc=$?
emit noflag_nodry_rc "$rc"
`;

function runDriver() {
  return runBashStdin(bashExe, driver);
}

function parseResults(stdout) {
  const out = {};
  for (const line of (stdout || "").split("\n")) {
    const m = /^RESULT\s+(\S+)\s*(\S*)\s*$/.exec(line.trim());
    if (m) out[m[1]] = m[2];
  }
  return out;
}

test("T-DOCK-1: entrypoint refuses a non-loopback admin port without both publish flags", (t) => {
  if (!bashExe) {
    t.skip("no bash reachable (WSL/Git-Bash absent); re-run this test under WSL");
    return;
  }
  const res = runDriver();
  const results = parseResults(res.stdout);
  if ("NO_SCRIPT" in results || "CD_FAIL" in results) {
    t.skip(`bash could not locate docker/entrypoint.sh in repo (candidates exhausted): ${res.stdout}`);
    return;
  }

  const expect = {
    default_rc: "0", // loopback default passes the gate, DRYRUN exits 0
    default_loopback: "1", // announced LISTEN_HOST=127.0.0.1
    noflag_rc: "1", // 0.0.0.0 without MAILSTACK_I_PUBLISH_ADMIN -> refused
    noflag_msg: "1", // refusal names the missing publish flag
    bothflags_rc: "0", // both flags -> gate passes, DRYRUN exits 0
    bothflags_publish: "1", // announced LISTEN_HOST=0.0.0.0
    noflag_nodry_rc: "1", // gate runs before process spawn even without DRYRUN
  };
  for (const [name, want] of Object.entries(expect)) {
    assert.equal(
      results[name],
      want,
      `${name}: expected ${want}, got ${JSON.stringify(results[name])}\nfull output:\n${res.stdout}\nstderr:\n${res.stderr}`,
    );
  }
});

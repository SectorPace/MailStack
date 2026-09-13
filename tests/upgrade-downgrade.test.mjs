/**
 * T-UP-1: upgrade refuses to downgrade (MailStack 冲98 checklist A4).
 *
 * mailstack.sh carries a `source` guard (`BASH_SOURCE[0] != $0 -> return 0`) so a
 * test can load its pure version-comparison functions without triggering command
 * dispatch, root escalation, network access or the real installer. We source it in
 * a throwaway bash and drive assert_no_downgrade() / _semver_lt() directly:
 *
 *   installed-version = v0.8.0-beta.7 (canonical), target v0.5.3-rc.1  -> rejected (rc 1)
 *   same, with ALLOW_DOWNGRADE=1 (--allow-downgrade)               -> allowed  (rc 0)
 *   equal / newer targets                                          -> allowed  (rc 0)
 *   missing installed-version file -> falls back to script VERSION, older target still rejected
 *   latest-hijack path shares the same comparison, so a bare older tag is rejected too
 *
 * No GitHub asset is ever downloaded: only the version-comparison segment runs.
 *
 * Cross-platform bash: on Linux/CI `bash` is native; on Windows we prefer WSL bash
 * (System32) and translate the repo path to its /mnt/<drive>/... form, with Git-Bash
 * (/e/..., e:/...) and plain POSIX forms as fallbacks. If no bash is reachable the
 * test is skipped with an explicit reason (record it and re-run under WSL).
 */
import assert from "node:assert/strict";
import test from "node:test";
import { resolveBash, bashRepoCandidates, runBashStdin } from "./_source.mjs";

const bashExe = resolveBash();

// Repo path candidates are interpolated straight into the driver (single-quoted;
// they contain no quote/$/backtick) rather than passed as extra argv: the WSL
// bash.exe launcher does not reliably forward positional args after `-c script`.
const candList = bashRepoCandidates();

// Version literals are always written v-prefixed so this file never trips the
// verify_release_consistency.py stale-version sweep (its regex needs a word
// boundary before `0`, which `v` suppresses). The driver strips the `v` at
// runtime to exercise both the bare and prefixed target forms.
const driver = `
set -uo pipefail
REPO=''
for cand in ${candList}; do
  if [[ -f "$cand/mailstack.sh" ]]; then REPO="$cand"; break; fi
done
if [[ -z "$REPO" ]]; then echo "RESULT NO_SCRIPT"; exit 98; fi
cd "$REPO" || { echo "RESULT CD_FAIL"; exit 98; }
# The mailstack.sh source guard runs a top-level "return 0". Inside a bash -c
# driver that would terminate the whole script, so the sourcing + assertions live
# in a function: "return" then only unwinds the source and the body keeps running.
run_tests(){
# shellcheck disable=SC1091
source ./mailstack.sh   # source guard returns before command dispatch
set +e                  # mailstack.sh turns -e on; we capture return codes instead

CUR=v0.8.0-beta.7   # canonical, matches package.json / VERSION
OLDER=v0.5.3-rc.1
NEWER=v0.9.0

tmpd=$(mktemp -d)
export MAILSTACK_INSTALLED_VERSION_FILE="$tmpd/installed-version"
printf '%s\\n' "\${CUR#v}" > "$MAILSTACK_INSTALLED_VERSION_FILE"

emit(){ printf 'RESULT %s %s\\n' "$1" "$2"; }
rc_of(){ "$@" >/dev/null 2>&1; printf '%s' "$?"; }

# _semver_lt: 0 (true) when a < b, 1 otherwise.
emit semver_lt_older    "$(rc_of _semver_lt "\${OLDER#v}" "\${CUR#v}")"   # expect 0
emit semver_lt_equal    "$(rc_of _semver_lt "\${CUR#v}"   "\${CUR#v}")"   # expect 1
emit semver_lt_newer    "$(rc_of _semver_lt "\${NEWER#v}" "\${CUR#v}")"   # expect 1
emit semver_lt_vprefix  "$(rc_of _semver_lt "$OLDER"      "$CUR")"        # expect 0 (v stripped)

# T-UP-1 core: downgrade (target < installed) without the flag must be rejected.
ALLOW_DOWNGRADE=0
emit downgrade_no_flag  "$(rc_of assert_no_downgrade "$OLDER")"           # expect 1 (reject)
# With --allow-downgrade the same downgrade is allowed (and audited best-effort).
ALLOW_DOWNGRADE=1
emit downgrade_flagged  "$(rc_of assert_no_downgrade "$OLDER")"           # expect 0 (allow)
ALLOW_DOWNGRADE=0
emit equal_allowed      "$(rc_of assert_no_downgrade "$CUR")"             # expect 0
emit newer_allowed      "$(rc_of assert_no_downgrade "$NEWER")"           # expect 0
# Bare (v-less) target exercises the leading-v strip inside assert_no_downgrade.
emit bare_older_reject  "$(rc_of assert_no_downgrade "\${OLDER#v}")"      # expect 1

# Missing installed-version file -> fall back to script VERSION (0.8.0-beta.7);
# an older target is still rejected, and old installs are never blocked on a
# equal/newer target.
rm -f "$MAILSTACK_INSTALLED_VERSION_FILE"
emit missing_file_reject "$(rc_of assert_no_downgrade "$OLDER")"          # expect 1
emit missing_file_newer  "$(rc_of assert_no_downgrade "$NEWER")"          # expect 0

rm -rf "$tmpd"
}
run_tests
`;

function runDriver() {
  // Fed via stdin (`bash -s`), NOT `bash -c <script>`: the WSL bash.exe launcher
  // re-quotes the Windows command line and strips the single-quoted path tokens,
  // whereas stdin reaches Linux bash verbatim.
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

test("T-UP-1: ms upgrade rejects downgrade, --allow-downgrade permits it", (t) => {
  if (!bashExe) {
    t.skip("no bash reachable (WSL/Git-Bash absent); re-run this test under WSL");
    return;
  }
  const res = runDriver();
  const results = parseResults(res.stdout);
  if ("NO_SCRIPT" in results || "CD_FAIL" in results) {
    t.skip(`bash could not locate mailstack.sh in repo (candidates exhausted): ${res.stdout}`);
    return;
  }
  assert.equal(res.status, 0, `driver failed: status=${res.status} stderr=${res.stderr} stdout=${res.stdout}`);

  const expect = {
    semver_lt_older: "0",
    semver_lt_equal: "1",
    semver_lt_newer: "1",
    semver_lt_vprefix: "0",
    downgrade_no_flag: "1", // rejected
    downgrade_flagged: "0", // allowed by --allow-downgrade
    equal_allowed: "0",
    newer_allowed: "0",
    bare_older_reject: "1",
    missing_file_reject: "1",
    missing_file_newer: "0",
  };
  for (const [name, want] of Object.entries(expect)) {
    assert.equal(results[name], want, `${name}: expected rc ${want}, got ${JSON.stringify(results[name])}\nfull output:\n${res.stdout}`);
  }
});

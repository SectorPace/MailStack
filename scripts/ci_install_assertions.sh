#!/usr/bin/env bash
# CI install-matrix assertions (runs as root inside a clean distro container,
# source tree mounted read-only at /src, AFTER deploy/install.sh succeeded).
set -Eeuo pipefail

fail() { echo "CI-INSTALL: $*" >&2; exit 1; }

echo "--- health assertions ---"
curl -fsS http://127.0.0.1:8787/api/health | grep -q '"status":"ok"' || fail "admin health check FAILED"
curl -fsS http://127.0.0.1:18788/api/webmail/health | grep -q '"status":"ok"' || fail "webmail health check FAILED"

echo "--- privilege model assertions ---"
[ "$(stat -c %U /opt/mailstack)" = root ] || fail "/opt/mailstack must be owned by root"
[ "$(stat -c %U /opt/mailstack/backend/mailstackctl.py)" = root ] || fail "helper must be owned by root"
# Local privilege escalation probe: the service account must not be able to
# replace the root-executed helper tree (NOPASSWD sudoers would make that root).
if su -s /bin/sh mailstack-admin -c "touch /opt/mailstack/backend/write-probe" 2>/dev/null; then
  rm -f /opt/mailstack/backend/write-probe
  fail "PRIVILEGE ESCALATION: mailstack-admin can write /opt/mailstack/backend"
fi

echo "--- sudoers: exactly one MailStack rule, pointing at the wrapper only ---"
[ -f /etc/sudoers.d/mailstack-web ] || fail "sudoers rule missing"
[ ! -e /etc/sudoers.d/mailstack-web-ctl ] || fail "second sudoers rule must not exist"
# 用 glob 数组计数（替代 ls | grep，规避 SC2010，且对任意文件名安全）
shopt -s nullglob
_mailstack_sudoers=(/etc/sudoers.d/mailstack*)
shopt -u nullglob
count=${#_mailstack_sudoers[@]}
[ "$count" = "1" ] || { ls -la /etc/sudoers.d/; fail "unexpected extra mailstack sudoers files ($count)"; }
grep -q 'NOPASSWD: /usr/local/libexec/mailstack-privileged' /etc/sudoers.d/mailstack-web \
  || fail "sudoers must point at the wrapper only"
if grep -q 'mailstackctl\.py' /etc/sudoers.d/mailstack-web; then
  fail "sudoers must not reference the python entrypoint"
fi

echo "--- fail2ban jail configuration present ---"
[ -f /etc/fail2ban/jail.d/mailstack.conf ] || fail "fail2ban jail config missing"
grep -q 'postfix-sasl' /etc/fail2ban/jail.d/mailstack.conf || fail "postfix-sasl jail missing"
grep -q 'dovecot' /etc/fail2ban/jail.d/mailstack.conf || fail "dovecot jail missing"

echo "--- release signing trust anchor installed ---"
[ -f /etc/mailstack/release-allowed-signers ] || fail "release allowed_signers missing"

echo "--- loopback mail path (behavioural: must actually deliver) ---"
python3 - <<'PYEOF'
import json, subprocess, sys

def ctl(action, data=None):
    p = subprocess.run(
        ["python3", "/opt/mailstack/backend/mailstackctl.py"],
        input=json.dumps({"action": action, "data": data or {}}).encode(),
        stdout=subprocess.PIPE,
    )
    try:
        return json.loads(p.stdout.decode())
    except Exception:
        print(f"CI-INSTALL: helper returned non-JSON for {action}: {p.stdout!r}", file=sys.stderr)
        sys.exit(1)

r = ctl("domains.add", {"name": "ci.local"})
assert r.get("ok"), f"domain add failed: {r}"
# Probe password must clear validate_mailbox_password (>=12 chars, letters +
# digits, no 3-char equal/ascending/descending run, no identity tokens).
r = ctl("users.add", {"email": "ci@ci.local", "password": "ci-mailbox-probe-7Kw"})
assert r.get("ok"), f"mailbox add failed: {r}"
r = ctl("mail.test_loopback", {"recipient": "ci@ci.local"})
assert r.get("ok"), f"loopback test failed: {r}"
print("  loopback mail path OK:", r["data"].get("recipient"))
PYEOF

echo "CI-INSTALL: all checks passed"

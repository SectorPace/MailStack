#!/usr/bin/env bash
# CI gate (runs as root inside a clean distro container, source mounted at /src).
#
# The Caddyfile is written from operator-supplied --domain/--email strings.
# A value containing a newline used to be able to inject arbitrary Caddy
# directives (e.g. an extra reverse_proxy to an attacker address). The
# installer must reject such values before ANY side effect -- package
# installation included -- and must never write a Caddyfile containing them.
set -Eeuo pipefail

fail() { echo "CI-DOMAIN-INJECTION: $*" >&2; exit 1; }

# 探针口令自身必须满足 rc.5 新密码策略（12-256 位、含字母与数字、无三连、
# 不含 admin 身份 token；已用 validate_mailbox_password(context='admin') 实测通过），
# 以免安装被口令校验而非域名/邮箱校验拒绝，掩盖注入漏洞。
CI_ADMIN_PASS='ci-msctl-root-9Kw7Qp'

evil_domain=$'evil.com {\n reverse_proxy 1.1.1.1\n}'
if bash ${SRC:-/src}/deploy/install.sh --non-interactive --access-mode caddy \
     --domain "$evil_domain" --email ops@example.com \
     --admin-password-stdin <<< "$CI_ADMIN_PASS" >/dev/null 2>&1; then
  fail "malicious domain was ACCEPTED"
fi
if [ -f /etc/caddy/Caddyfile ] && grep -q '1\.1\.1\.1' /etc/caddy/Caddyfile; then
  fail "injected reverse_proxy directive found in Caddyfile"
fi
echo "  ok: newline-injected domain rejected before any side effect"

evil_email=$'ops@example.com\n}\n\nattacker.example {\n reverse_proxy 2.2.2.2\n}'
if bash ${SRC:-/src}/deploy/install.sh --non-interactive --access-mode caddy \
     --domain mail.example.com --email "$evil_email" \
     --admin-password-stdin <<< "$CI_ADMIN_PASS" >/dev/null 2>&1; then
  fail "malicious ACME email was ACCEPTED"
fi
echo "  ok: newline-injected email rejected"

# Sanity: a legitimate domain must pass the same validator (would fail later
# at the privilege check, not at validation). We stop it right after arg
# parsing by feeding an invalid access mode together with the valid domain.
out=$(bash ${SRC:-/src}/deploy/install.sh --non-interactive --access-mode bogus \
   --domain mail.example.com --admin-password-stdin <<< "$CI_ADMIN_PASS" 2>&1 || true)
case "$out" in
  *不支持的访问模式*) echo "  ok: legitimate domain passes validation (fails only on bogus mode)";;
  *非法*) fail "legitimate domain was rejected by the validator";;
  *) fail "unexpected installer output: $out";;
esac
echo "CI-DOMAIN-INJECTION: all checks passed"

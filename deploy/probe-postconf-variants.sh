#!/usr/bin/env bash
# 探测 postconf 各变体的语义差异，为「快照/回滚需要知道是否显式设置」找到正确读法。
set -uo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

echo "=== A) postconf -h <key>：有效值（含默认）==="
for k in smtp_sasl_security_options relayhost smtp_tls_security_level; do
  printf '  %-28s [%s]\n' "$k" "$(postconf -h "$k" 2>/dev/null || true)"
done

echo
echo "=== B) postconf -n <key>：仅非默认（即显式设置）==="
for k in smtp_sasl_security_options relayhost smtp_tls_security_level; do
  out="$(postconf -n "$k" 2>&1 || true)"
  printf '  %-28s [%s]\n' "$k" "$out"
done

echo
echo "=== C) postconf -n 对已知未显式设置的键 ==="
# mynetworks 通常有默认值且常被显式设置；用 smtp_tls_wrappermode（默认 no、通常不写）
for k in smtp_tls_wrappermode smtp_sasl_password_maps; do
  printf '  %-28s -h=[%s]  -n=[%s]\n' "$k" \
    "$(postconf -h "$k" 2>/dev/null || true)" \
    "$(postconf -n "$k" 2>&1 || true)"
done

echo
echo "=== D) main.cf 中是否显式含这些键 ==="
for k in smtp_sasl_security_options relayhost smtp_tls_security_level smtp_tls_wrappermode; do
  n=$(grep -cE "^[[:space:]]*${k}[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null || true)
  printf '  %-28s in_main.cf=%s\n' "$k" "${n:-0}"
done
#!/usr/bin/env bash
# 复现「写入 noanonymous 后 -n 读回空值」的怪现象。
set -uo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

K=smtp_sasl_security_options
echo "=== 0) 初始 ==="
printf '  -n: [%s]\n' "$(postconf -n $K 2>/dev/null)"
printf '  -h: [%s]\n' "$(postconf -h $K 2>/dev/null)"

echo
echo "=== 1) postconf -e $K=noanonymous ==="
postconf -e "$K=noanonymous"
echo "  exit=$?"
printf '  -n 原始输出: [%s]\n' "$(postconf -n $K 2>/dev/null)"
printf '  -h: [%s]\n' "$(postconf -h $K 2>/dev/null)"
echo "  main.cf 中的行:"
grep -nE "^[[:space:]]*$K[[:space:]]*=" /etc/postfix/main.cf | sed 's/^/    /'

echo
echo "=== 2) 换个键试试（smtp_tls_wrappermode）==="
postconf -e "smtp_tls_wrappermode=yes"
printf '  -n: [%s]\n' "$(postconf -n smtp_tls_wrappermode 2>/dev/null)"
grep -nE '^[[:space:]]*smtp_tls_wrappermode[[:space:]]*=' /etc/postfix/main.cf | sed 's/^/    /'

echo
echo "=== 3) 用 relayhost 试试 ==="
postconf -e "relayhost=[smtp.sendgrid.net]:587"
printf '  -n: [%s]\n' "$(postconf -n relayhost 2>/dev/null)"
grep -nE '^[[:space:]]*relayhost[[:space:]]*=' /etc/postfix/main.cf | sed 's/^/    /'

echo
echo "=== 4) 直接看 -n 全量输出里这几个键 ==="
postconf -n 2>/dev/null | grep -E "smtp_sasl_security_options|smtp_tls_wrappermode|relayhost" | cat -A | sed 's/^/    /'

echo
echo "=== 5) 清理 ==="
postconf -X smtp_tls_wrappermode 2>/dev/null || true
postconf -X relayhost 2>/dev/null || true
echo "  已移除测试键（$K 留待后续判断）"
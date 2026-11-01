#!/usr/bin/env bash
# 复现「写入 noanonymous 后 -n 读回空值」的怪现象。
#
# 探测全程在**隔离目录**里进行（`postconf -c <dir>`）：先把宿主的 main.cf 原样
# 拷进去作为基线，之后所有 postconf -e / -n / -h 都指向该副本 —— 宿主的真实
# /etc/postfix/main.cf 只被**只读**核对，绝不被写入。
#
# 早先版本直接 `postconf -e` 改宿主配置，结束时还刻意把
# smtp_sasl_security_options=noanonymous 留在原地 —— 那是真实的测试残留：
# noanonymous 会放开匿名认证（对内网中继即匿名投递），改变宿主 Postfix 的
# 安全行为。故整个探测改为 -c 隔离，不再触碰、也不再需要清理宿主配置。
set -uo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

MAIN=/etc/postfix/main.cf
[ -f "$MAIN" ] || {
  echo "ERROR: $MAIN 不存在（宿主未装 Postfix？本脚本探测的正是 postconf 的行为）" >&2
  exit 1
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/mailstack-postconf-probe.XXXXXXXX") || {
  echo "ERROR: 无法创建临时目录" >&2
  exit 1
}
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"
# 基线：隔离副本与宿主完全一致，-n/-h 的读回结果因此与真实场景同构
# （副本目录 0700 且退出即删，不引入额外的暴露面）。
cp -a "$MAIN" "$WORK/main.cf"

K=smtp_sasl_security_options
echo "=== 0) 初始（宿主只读核对 + 隔离副本读回，两者应一致）==="
printf '  宿主 -n: [%s]\n' "$(postconf -n "$K" 2>/dev/null)"
printf '  宿主 -h: [%s]\n' "$(postconf -h "$K" 2>/dev/null)"
printf '  副本 -n: [%s]\n' "$(postconf -c "$WORK" -n "$K" 2>/dev/null)"
printf '  副本 -h: [%s]\n' "$(postconf -c "$WORK" -h "$K" 2>/dev/null)"

echo
echo "=== 1) postconf -c \$WORK -e $K=noanonymous（只写隔离副本）==="
postconf -c "$WORK" -e "$K=noanonymous"
echo "  exit=$?"
printf '  副本 -n 原始输出: [%s]\n' "$(postconf -c "$WORK" -n "$K" 2>/dev/null)"
printf '  副本 -h: [%s]\n' "$(postconf -c "$WORK" -h "$K" 2>/dev/null)"
echo "  副本 main.cf 中的行:"
grep -nE "^[[:space:]]*$K[[:space:]]*=" "$WORK/main.cf" | sed 's/^/    /'

echo
echo "=== 2) 换个键试试（smtp_tls_wrappermode）==="
postconf -c "$WORK" -e "smtp_tls_wrappermode=yes"
printf '  副本 -n: [%s]\n' "$(postconf -c "$WORK" -n smtp_tls_wrappermode 2>/dev/null)"
grep -nE '^[[:space:]]*smtp_tls_wrappermode[[:space:]]*=' "$WORK/main.cf" | sed 's/^/    /'

echo
echo "=== 3) 用 relayhost 试试 ==="
postconf -c "$WORK" -e "relayhost=[smtp.sendgrid.net]:587"
printf '  副本 -n: [%s]\n' "$(postconf -c "$WORK" -n relayhost 2>/dev/null)"
grep -nE '^[[:space:]]*relayhost[[:space:]]*=' "$WORK/main.cf" | sed 's/^/    /'

echo
echo "=== 4) 直接看副本 -n 全量输出里这几个键 ==="
postconf -c "$WORK" -n 2>/dev/null | grep -E "smtp_sasl_security_options|smtp_tls_wrappermode|relayhost" | cat -A | sed 's/^/    /'

echo
echo "=== 5) 收尾 ==="
echo "  隔离副本 $WORK 将在退出时删除；宿主 $MAIN 全程未被写入，无需清理。"
echo "  宿主这些键的当前值（只读核对，应与步骤 0 一致）："
for key in smtp_sasl_security_options smtp_tls_wrappermode relayhost; do
  printf '  %-28s [%s]\n' "$key" "$(postconf -h "$key" 2>/dev/null)"
done

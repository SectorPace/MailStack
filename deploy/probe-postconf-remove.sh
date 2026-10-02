#!/usr/bin/env bash
# 探测 postconf -X（移除参数）是否可用，以及 -e key=（设为空）与「从未设置」的差异。
set -u
export PATH="/usr/sbin:/sbin:$PATH"

WORK=/tmp/pfx-test.cf
cp /etc/postfix/main.cf "$WORK"
echo "=== 用临时配置文件独立试验（不碰 main.cf）==="

# postconf 支持 -c 指定 config_directory
TMPDIR_TEST=/tmp/pfx-conf
mkdir -p "$TMPDIR_TEST"
cp /etc/postfix/main.cf "$TMPDIR_TEST/main.cf"
chmod 644 "$TMPDIR_TEST/main.cf"

pc() { postconf -c "$TMPDIR_TEST" "$@"; }

echo
echo "=== 1) 初始：smtp_tls_wrappermode 是否显式设置 ==="
printf '  -n: [%s]\n' "$(pc -n smtp_tls_wrappermode 2>&1 || true)"
printf '  -h: [%s]\n' "$(pc -h smtp_tls_wrappermode 2>&1 || true)"

echo
echo "=== 2) postconf -X 移除一个从未设置的键（应无害）==="
pc -X smtp_tls_wrappermode 2>&1 || echo "  -X 失败"
printf '  after -X: -n=[%s]\n' "$(pc -n smtp_tls_wrappermode 2>&1 || true)"

echo
echo "=== 3) postconf -e key=yes 设置，然后 -X 移除 ==="
pc -e smtp_tls_wrappermode=yes 2>&1 || echo "  -e 失败"
printf '  after -e: -n=[%s]  -h=[%s]\n' \
  "$(pc -n smtp_tls_wrappermode 2>&1 || true)" \
  "$(pc -h smtp_tls_wrappermode 2>&1 || true)"
grep -cE '^[[:space:]]*smtp_tls_wrappermode[[:space:]]*=' "$TMPDIR_TEST/main.cf" | sed 's/^/  in_main.cf=/'

pc -X smtp_tls_wrappermode 2>&1 || echo "  -X 失败"
printf '  after -X: -n=[%s]  -h=[%s]\n' \
  "$(pc -n smtp_tls_wrappermode 2>&1 || true)" \
  "$(pc -h smtp_tls_wrappermode 2>&1 || true)"
grep -cE '^[[:space:]]*smtp_tls_wrappermode[[:space:]]*=' "$TMPDIR_TEST/main.cf" | sed 's/^/  in_main.cf=/'

echo
echo "=== 4) smtp_sasl_security_options 的行为差异（安全相关）==="
printf '  默认(-d):        [%s]\n' "$(pc -d smtp_sasl_security_options 2>&1 | sed 's/^[^=]*= *//' || true)"
printf '  当前(-h):        [%s]\n' "$(pc -h smtp_sasl_security_options 2>&1 || true)"

pc -X smtp_sasl_security_options 2>&1 || echo "  -X 失败"
printf '  移除后 -h:       [%s]   <- 应回到默认 noplaintext\n' "$(pc -h smtp_sasl_security_options 2>&1 || true)"

pc -e smtp_sasl_security_options= 2>&1 || echo "  -e 空值失败"
printf '  设为空后 -h:     [%s]   <- 若为空则说明覆盖掉了默认的保护\n' "$(pc -h smtp_sasl_security_options 2>&1 || true)"

echo
echo "=== 5) 恢复临时目录 ==="
rm -rf "$TMPDIR_TEST" "$WORK"
echo "  done（main.cf 未被本次试验修改）"
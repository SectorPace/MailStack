#!/usr/bin/env bash
# 核实集成测试是否把宿主（WSL）的真实 postfix 配置还原干净。
set -euo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

echo "=== 测试涉及的键当前值 ==="
for k in relayhost smtp_sasl_security_options smtp_tls_wrappermode smtp_sasl_auth_enable smtp_tls_security_level; do
  v="$(postconf -h "$k" 2>/dev/null || true)"
  printf '%-28s = [%s]\n' "$k" "$v"
done

echo
echo "=== main.cf 是否残留测试用值 ==="
if grep -nE 'sendgrid|old\.example\.com|wrong\.example\.com|SG\.integration' /etc/postfix/main.cf 2>/dev/null; then
  echo "!! 发现残留"
else
  echo "无残留"
fi

echo
echo "=== main.cf 及其临时/备份文件 ==="
ls -la /etc/postfix/main.cf* 2>/dev/null || echo "(none)"

echo
echo "=== sasl_passwd 是否被测试创建过 ==="
for f in /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db; do
  if [ -e "$f" ]; then echo "存在: $f"; else echo "不存在: $f"; fi
done

echo
echo "=== postfix 服务状态 ==="
pgrep -a master 2>/dev/null | head -3 || echo "master 未运行"
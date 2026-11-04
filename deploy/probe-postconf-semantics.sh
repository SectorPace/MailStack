set -uo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

echo "=== main.cf 中显式设置的行 ==="
grep -nE '^[a-z_]+ *=' /etc/postfix/main.cf 2>/dev/null || echo "(无)"
echo
echo "=== main.cf 总行数 ==="
wc -l < /etc/postfix/main.cf

echo
echo "=== 对比：显式设置 vs 默认 ==="
for k in smtp_sasl_security_options relayhost smtp_tls_security_level spam_threshold; do
  eff="$(postconf -h "$k" 2>/dev/null || true)"      # 有效值（含默认）
  dflt="$(postconf -d "$k" 2>/dev/null || true)"     # 仅默认值
  explicit=$(grep -cE "^[[:space:]]*${k}[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null || echo 0)
  printf '%-28s effective=[%s]  default=[%s]  in_main.cf=%s\n' "$k" "$eff" "$dflt" "$explicit"
done

echo
echo "=== 结论要点 ==="
echo "若 effective 在「main.cf 未显式设置」时等于 default 且非空，"
echo "则 read_key 无法区分「未设置」与「显式设为默认值」。"

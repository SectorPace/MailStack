set -euo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

MAIN=/etc/postfix/main.cf
BACKUP="${MAIN}.before-mailstack-cleanup"

echo "=== 清理前 ==="
for k in smtp_sasl_security_options relayhost smtp_tls_wrappermode smtp_sasl_auth_enable smtp_sasl_password_maps; do
  n=$(grep -cE "^[[:space:]]*${k}[[:space:]]*=" "$MAIN" 2>/dev/null || true)
  printf '  %-28s in_main.cf=%s  effective=[%s]\n' "$k" "${n:-0}" "$(postconf -h "$k" 2>/dev/null || true)"
done

echo
echo "=== 备份到 $BACKUP ==="
if [ -e "$BACKUP" ]; then
  echo "  已存在，保留首次运行时的原始状态（不覆盖）"
else
  cp -a "$MAIN" "$BACKUP"
  echo "  done"
fi

echo
echo "=== 移除测试写入的键（仅当其值等于测试所写内容时才移除，避免误删运维配置）==="
cur_relay=$(postconf -n relayhost 2>/dev/null | sed -E 's/^[^=]*= *//')
if [ "$cur_relay" = "[smtp.sendgrid.net]:587" ] || [ "$cur_relay" = "" ]; then
  postconf -X relayhost && echo "  已移除 relayhost（值: '$cur_relay'）"
else
  echo "  保留 relayhost（当前值: '$cur_relay'，非测试所写）"
fi

cur_sasl=$(postconf -n smtp_sasl_security_options 2>/dev/null | sed -E 's/^[^=]*= *//')
case "$cur_sasl" in
  "noplaintext, noanonymous"|"noanonymous"|"")
    postconf -X smtp_sasl_security_options && echo "  已移除 smtp_sasl_security_options（值: '$cur_sasl'）"
    ;;
  *)
    echo "  保留 smtp_sasl_security_options（当前值: '$cur_sasl'，非测试所写）"
    ;;
esac

for k in smtp_tls_wrappermode smtp_sasl_auth_enable smtp_sasl_password_maps; do
  cur=$(postconf -n "$k" 2>/dev/null | sed -E 's/^[^=]*= *//')
  case "$cur" in
    "yes"|"no"|"")
      if ! grep -qE "^[[:space:]]*${k}[[:space:]]*=" "$BACKUP" 2>/dev/null; then
        postconf -X "$k" && echo "  已移除 $k（测试新增，值: '$cur'）"
      else
        echo "  保留 $k（备份中已存在）"
      fi
      ;;
    *)
      echo "  保留 $k（当前值: '$cur'）"
      ;;
  esac
done

echo
echo "=== 清理后 ==="
for k in smtp_sasl_security_options relayhost smtp_tls_wrappermode smtp_sasl_auth_enable smtp_sasl_password_maps; do
  n=$(grep -cE "^[[:space:]]*${k}[[:space:]]*=" "$MAIN" 2>/dev/null || true)
  printf '  %-28s in_main.cf=%s  effective=[%s]\n' "$k" "${n:-0}" "$(postconf -h "$k" 2>/dev/null || true)"
done

echo
echo "备份保留在 $BACKUP（如需回滚：cp -a $BACKUP $MAIN）"

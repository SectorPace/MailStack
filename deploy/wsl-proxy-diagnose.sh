set -uo pipefail

for target in "proxy7890|http://127.0.0.1:7890" "proxy7897|http://127.0.0.1:7897" "direct|"; do
  label="${target%%|*}"
  proxy="${target#*|}"
  echo "=== $label ==="
  for url in "https://crates.io/api/v1/crates/mail-auth" "https://static.crates.io/config.json"; do
    if [ -n "$proxy" ]; then
      code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 -x "$proxy" "$url" 2>/dev/null)
    else
      code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "$url" 2>/dev/null)
    fi
    echo "  $url -> HTTP $code (curl rc=$?)"
  done
  echo "  DNS: $(getent hosts crates.io | head -1)"
done

echo "=== 监听端口 ==="
ss -ltn 2>/dev/null | grep -E '7890|7897' || echo "  (7890/7897 未在监听)"

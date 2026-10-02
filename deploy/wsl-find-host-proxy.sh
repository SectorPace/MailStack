#!/usr/bin/env bash
# 找出 WSL 到 Windows 宿主代理（Clash 混合端口 7890）的可达路径。
# Windows 侧实测：127.0.0.1:7890 -> 200（7897 虽监听但不可用）。
set -u

echo "=== resolv.conf nameserver (WSL2 NAT 下通常就是宿主 IP) ==="
NS=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)
echo "nameserver=${NS:-none}"

echo
echo "=== default route ==="
ip route show default 2>/dev/null

echo
echo "=== candidate host IPs ==="
CANDIDATES=()
[ -n "${NS:-}" ] && CANDIDATES+=("$NS")
GW=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1)
[ -n "${GW:-}" ] && CANDIDATES+=("$GW")
CANDIDATES+=("127.0.0.1")

# 去掉重复
UNIQ=()
for c in "${CANDIDATES[@]}"; do
  dup=0
  for u in "${UNIQ[@]:-}"; do [ "$u" = "$c" ] && dup=1; done
  [ $dup -eq 0 ] && UNIQ+=("$c")
done

echo "trying: ${UNIQ[*]}"
echo
for host in "${UNIQ[@]}"; do
  for port in 7890 7897; do
    code=$(curl -sS -m 8 -x "http://${host}:${port}" -o /dev/null -w '%{http_code}' \
             https://static.rust-lang.org/ 2>/dev/null || echo ERR)
    printf 'proxy %-16s:%-5s -> %s\n' "$host" "$port" "$code"
  done
done

echo
echo "=== also try http (not https) CONNECT via 7890 ==="
for host in "${UNIQ[@]}"; do
  code=$(curl -sS -m 8 -x "http://${host}:7890" -o /dev/null -w '%{http_code}' \
           http://index.crates.io/ 2>/dev/null || echo ERR)
  printf 'plain http %-16s:7890 -> %s\n' "$host" "$code"
done
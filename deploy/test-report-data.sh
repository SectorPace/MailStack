#!/usr/bin/env bash
# 汇总测试规模与不变量覆盖，产出 TEST_REPORT.md 所需的事实数据。
set -u
cd /mnt/e/MailStack/mailstack-rust || exit 1

echo "### 每 crate 测试数"
total=0
for c in mailstack-core mailstack-priv mailstack-web; do
  out=$(bash deploy/wsl-cargo.sh test -p "$c" 2>/dev/null)
  n=$(printf '%s\n' "$out" | grep -oE 'running [0-9]+ tests' | head -1 | grep -oE '[0-9]+')
  n=${n:-0}
  src=$(find "crates/${c#mailstack-}" -name '*.rs' -exec cat {} + 2>/dev/null | wc -l)
  printf '%-18s %4s tests   %6s 行\n' "$c" "$n" "$src"
  total=$((total + n))
done
echo "TOTAL=$total"

echo
echo "### 不变量覆盖（INV → 测试函数）"
grep -rhoE 'fn [a-z0-9_]+' crates/*/src/*.rs \
  | sed 's/^fn //' | sort -u > /tmp/all_fns.txt
grep -rhE 'INV-[0-9]+' crates/*/src/*.rs | grep -oE 'INV-[0-9]+' | sort -u -V | tr '\n' ' '
echo

echo
echo "### 每个 INV 的引用次数"
for i in $(grep -rhoE 'INV-[0-9]+' crates/*/src/*.rs | sort -u -V); do
  c=$(grep -rc "$i" crates/*/src/*.rs 2>/dev/null | awk -F: '{s+=$2} END {print s}')
  printf '%s=%s ' "$i" "$c"
done
echo

echo
echo "### 测试函数总数"
grep -rhoE '#\[tokio::test\]|#\[test\]' crates/*/src/*.rs | wc -l
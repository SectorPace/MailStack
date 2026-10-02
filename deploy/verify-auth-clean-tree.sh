#!/usr/bin/env bash
# 用受限特性引入 mail-auth 后，验证依赖树里没有 C 依赖链（规格书 §3.4 硬约束）。
set -u

SRC_DIR="/mnt/e/MailStack/mailstack-rust"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$HOME/.cache/mailstack-target"
export HTTP_PROXY="http://127.0.0.1:7890"
export HTTPS_PROXY="$HTTP_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTP_PROXY"
export NO_PROXY="localhost,127.0.0.1,::1"
export no_proxy="$NO_PROXY"

cd "$SRC_DIR" || exit 1

echo "=== cargo fetch（重试） ==="
for attempt in 1 2 3 4 5; do
  if cargo fetch 2>&1 | tail -5; then
    if cargo fetch 2>/dev/null; then
      echo "FETCH_OK"
      break
    fi
  fi
  sleep 3
done

echo
echo "=== 解析结果 ==="
cargo tree -p mailstack-auth --depth 1 2>&1 | head -20

echo
echo "=== C 依赖链排查（应为空） ==="
FOUND=0
for c in zstd-sys zstd-safe zstd xz2 liblzma-sys bzip2-sys bzip2 aws-lc-rs aws-lc-sys cmake nasm; do
  if cargo tree -p mailstack-auth -i "$c" >/dev/null 2>&1; then
    echo "  [!!] 命中 $c"
    cargo tree -p mailstack-auth -i "$c" 2>/dev/null | head -5
    FOUND=1
  fi
done
[ "$FOUND" -eq 0 ] && echo "  未发现任何 C 依赖链"

echo
echo "=== flate2 的后端 ==="
cargo tree -p mailstack-auth -e features 2>/dev/null | grep -E 'flate2 feature' | head -5

echo
echo "=== 全部依赖总数 ==="
cargo tree -p mailstack-auth --prefix none 2>/dev/null | sort -u | wc -l

echo
echo "=== 磁盘 ==="
df -h / | tail -1

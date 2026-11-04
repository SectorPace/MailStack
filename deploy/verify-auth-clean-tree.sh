set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$HOME/.cache/mailstack-target"
export HTTP_PROXY="${MAILSTACK_PROXY:-http://127.0.0.1:7890}"
export HTTPS_PROXY="$HTTP_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTP_PROXY"
export NO_PROXY="localhost,127.0.0.1,::1"
export no_proxy="$NO_PROXY"

cd "$SRC_DIR" || exit 1

echo "=== cargo fetch（最多重试 5 次；最终失败即退出非零） ==="
FETCH_OK=0
for attempt in 1 2 3 4 5; do
  if cargo fetch 2>&1 | tail -5; then
    echo "FETCH_OK"
    FETCH_OK=1
    break
  fi
  if [ "$attempt" -lt 5 ]; then
    sleep 3
  fi
done
if [ "$FETCH_OK" -ne 1 ]; then
  echo "ERROR: cargo fetch 连续 5 次尝试均失败" >&2
  exit 1
fi

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

if [ "$FOUND" -ne 0 ]; then
  echo "C_DEPENDENCY_GATE_FAIL: 发现 C 依赖链，违反了「纯 Rust 构建」约束" >&2
  exit 1
fi
echo "C_DEPENDENCY_GATE_OK"

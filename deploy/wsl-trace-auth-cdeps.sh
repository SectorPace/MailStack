set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$HOME/.cache/mailstack-target"
cd "$SRC_DIR" || exit 1

echo "=== 反向依赖：zstd-sys ==="
cargo tree -i zstd-sys -p mailstack-auth 2>&1 | head -20
echo
echo "=== 反向依赖：xz2 ==="
cargo tree -i xz2 -p mailstack-auth 2>&1 | head -20
echo
echo "=== 反向依赖：zip ==="
cargo tree -i zip -p mailstack-auth 2>&1 | head -20
echo
echo "=== 反向依赖：hickory-resolver ==="
cargo tree -i hickory-resolver -p mailstack-auth 2>&1 | head -20
echo
echo "=== mail-auth 自身的 features ==="
cargo tree -p mailstack-auth -e features 2>&1 | head -30

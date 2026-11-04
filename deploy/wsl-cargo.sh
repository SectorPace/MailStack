set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT"
NATIVE_TARGET="${HOME}/.cache/mailstack-target"

export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$NATIVE_TARGET"

if [ "${MAILSTACK_FULL_DEBUG:-0}" != "1" ]; then
  export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-line-tables-only}"
fi

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

if [ "${MAILSTACK_USE_PROXY:-0}" = "1" ]; then
  export HTTP_PROXY="${MAILSTACK_PROXY:-http://127.0.0.1:7890}"
  export HTTPS_PROXY="$HTTP_PROXY"
  export http_proxy="$HTTP_PROXY"
  export https_proxy="$HTTP_PROXY"
  export NO_PROXY="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.local"
  export no_proxy="$NO_PROXY"
fi

if [ ! -d "$SRC_DIR" ]; then
  echo "源码目录不存在: $SRC_DIR" >&2
  exit 1
fi

mkdir -p "$NATIVE_TARGET"
cd "$SRC_DIR"

if [ "$#" -eq 0 ]; then
  echo "用法: $0 <cargo 子命令> [参数...]" >&2
  exit 2
fi

echo "[wsl-cargo] cwd=$SRC_DIR target=$CARGO_TARGET_DIR proxy=${MAILSTACK_USE_PROXY:-0}"
exec cargo "$@"

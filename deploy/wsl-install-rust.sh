set -euo pipefail

PROXY="${MAILSTACK_PROXY:-http://127.0.0.1:7890}"
RUST_VERSION="1.98.1"

export HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY" http_proxy="$PROXY" https_proxy="$PROXY"
export NO_PROXY="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.local"
export no_proxy="$NO_PROXY"

echo "=== 0) 代理连通性 ==="
code=$(curl -sS -m 12 -o /dev/null -w '%{http_code}' https://static.rust-lang.org/ || echo ERR)
echo "static.rust-lang.org -> $code"
if [ "$code" != "200" ]; then
  echo "代理不可用，终止。" >&2
  exit 1
fi

echo
echo "=== 1) 构建基础（cc/make，链接 Rust 产物必需） ==="
if command -v cc >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
  echo "已安装: $(cc --version | head -1)"
else
  apt-get -o Acquire::http::Proxy="$PROXY" -o Acquire::https::Proxy="$PROXY" \
          update -qq 2>&1 | tail -3
  DEBIAN_FRONTEND=noninteractive apt-get \
    -o Acquire::http::Proxy="$PROXY" -o Acquire::https::Proxy="$PROXY" \
    install -y -qq build-essential pkg-config 2>&1 | tail -5
  echo "安装后: $(cc --version | head -1)"
fi

echo
echo "=== 2) 安装 rustup + ${RUST_VERSION} ==="
if [ -x "$HOME/.cargo/bin/cargo" ]; then
  echo "已存在 cargo: $($HOME/.cargo/bin/cargo --version)"
else
  workdir=$(mktemp -d "${TMPDIR:-/tmp}/mailstack-rustup.XXXXXXXX") || {
    echo "无法创建临时目录" >&2; exit 1
  }
  trap 'rm -rf "$workdir"' EXIT
  chmod 700 "$workdir"

  curl -sSf --proto '=https' --tlsv1.2 \
    https://sh.rustup.rs -o "$workdir/rustup-init.sh"

  require_sha256="${MAILSTACK_REQUIRE_SHA256:-0}"
  expected="${MAILSTACK_RUSTUP_SHA256:-}"
  if [ -n "$expected" ]; then
    actual=$(sha256sum "$workdir/rustup-init.sh" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
      echo "rustup-init.sh 的 SHA256 与钉住的值不符" >&2
      echo "  expected: $expected" >&2
      echo "  actual:   $actual" >&2
      exit 1
    fi
    echo "已用 MAILSTACK_RUSTUP_SHA256 校验安装脚本"
  elif [ "$require_sha256" = "1" ]; then
    echo "MAILSTACK_REQUIRE_SHA256=1 但未设置 MAILSTACK_RUSTUP_SHA256：拒绝在无钉扎的情况下执行安装脚本" >&2
    exit 1
  else
    echo "⚠️  未设置 MAILSTACK_RUSTUP_SHA256：仅依赖 HTTPS 传输完整性，未做独立哈希钉扎" >&2
    echo "    生产构建建议先离线核对 sha256 再显式传入该变量；" >&2
    echo "    强制钉扎可设 MAILSTACK_REQUIRE_SHA256=1（未钉扎即失败）。" >&2
  fi

  sh "$workdir/rustup-init.sh" -y --no-modify-path --profile minimal \
     --default-toolchain "$RUST_VERSION"
fi

export PATH="$HOME/.cargo/bin:$PATH"

echo
echo "=== 3) 校验 ==="
rustc --version
cargo --version
echo "targets:"
rustup target list --installed

echo
echo "=== 4) 确保 Linux 目标可用 ==="
rustup target add x86_64-unknown-linux-gnu 2>&1 | tail -2 || true

echo
echo "WSL_RUST_READY"

#!/usr/bin/env bash
# 在 WSL Ubuntu 24.04 内装配 Rust 工具链（规格书 §7：构建在 WSL Ubuntu 24.04 环境）。
#
# 本机网络要点：WSL 通过 Clash 混合端口出网。实测 **7897 会接受 TCP 连接但不能代理**
# （/etc/profile.d/99-clash-proxy.sh 恰好优先探测 7897，且它探测成功 → 于是导出了一个
# 不可用的代理），真正可用的是 **7890**。故本脚本显式使用 7890。
set -u

PROXY="http://127.0.0.1:7890"
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
  curl -sSf --proto '=https' --tlsv1.2 https://sh.rustup.rs -o /tmp/rustup-init.sh
  sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
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
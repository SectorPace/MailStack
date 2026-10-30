#!/usr/bin/env bash
# 在 WSL Ubuntu 中构建/测试 MailStack（生产目标平台即 Linux）。
#
# 用法：
#   deploy/wsl-cargo.sh test  -p mailstack-core
#   deploy/wsl-cargo.sh clippy --all-targets -- -D warnings
#   deploy/wsl-cargo.sh check --target x86_64-unknown-linux-gnu
#
# 设计要点：
#   * 源码留在 /mnt/e（Windows 侧唯一真相源），避免双份源码漂移；
#   * 但 CARGO_TARGET_DIR 指向 WSL 原生文件系统 —— /mnt/e 走 9p 协议，
#     把 target/ 放在上面会让每次增量构建慢一个数量级；
#   * 代理：本机 WSL 必须走 Clash 混合端口 7890（7897 会接受连接但不可代理）。
#     仅在需要访问网络时导出，且 NO_PROXY 覆盖本地，避免本地回环请求被劫持。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT"
NATIVE_TARGET="${HOME}/.cache/mailstack-target"

export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$NATIVE_TARGET"

# WSL 根分区只有 9.8G（`df -h /` 可见），而本工作区的测试目标有 10 个。
# 完整 debuginfo 会把 target/debug 撑到 4.5G 以上，直接导致链接器
# `ld terminated with signal 7 [Bus error]`（写盘失败），表现为莫名其妙的
# 「链接失败」而不是「磁盘满」。
#
# 默认降到 line-tables-only：**保留回溯里的文件与行号**，只丢掉变量/类型信息。
# 需要完整调试信息时设 MAILSTACK_FULL_DEBUG=1（记得先确认剩余空间）。
# release profile 不受影响（deploy/build.sh 走 --release，且已 strip）。
if [ "${MAILSTACK_FULL_DEBUG:-0}" != "1" ]; then
  export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-line-tables-only}"
fi

# 仅当显式需要网络时启用代理（vendor 构建/离线场景不应依赖它）。
if [ "${MAILSTACK_USE_PROXY:-0}" = "1" ]; then
  # 6.7：代理不再写死开发机地址，默认值可被 MAILSTACK_PROXY 覆盖。
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
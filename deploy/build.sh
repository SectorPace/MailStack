#!/usr/bin/env bash
# MailStack 构建脚本（规格书 §7 供应链要求）。
#
# 必须在 Linux 上运行（生产目标 x86_64-unknown-linux-gnu）。
#   * 依赖锁定：一律 `cargo build --locked`
#   * 离线可复现：`--offline` 配合 `cargo vendor` 产出的 vendor/
#   * 产物：单一二进制 + SHA256SUMS + SBOM
#
# 用法：
#   deploy/build.sh                 # release 构建 + 校验和
#   deploy/build.sh --offline       # 使用已 vendor 的依赖离线构建
#   deploy/build.sh --vendor        # 先 cargo vendor 再离线构建
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
EXPECTED_RUST_PREFIX="1.98.1"
DIST_DIR="$REPO_ROOT/dist"
OFFLINE=0
DO_VENDOR=0

for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
    --vendor)  DO_VENDOR=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "未知参数: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$1"; }
die()  { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

step "0/6 环境断言"
command -v cargo >/dev/null || die "未找到 cargo"
command -v cc    >/dev/null || die "未找到 C 编译器（链接 Rust 产物必需）"

RUSTC_VERSION="$(rustc --version)"
echo "rustc: $RUSTC_VERSION"
# 工具链在 CI 与本脚本两处固定；此处断言防止误用其它版本产出不可复现的二进制。
case "$RUSTC_VERSION" in
  "rustc $EXPECTED_RUST_PREFIX"*) ;;
  *) die "工具链版本不匹配：期望 $EXPECTED_RUST_PREFIX.x，实际 $RUSTC_VERSION" ;;
esac

case "$(uname -s)" in
  Linux) ;;
  *) die "本脚本必须在 Linux 上运行（当前 $(uname -s)）；Windows 开发机请用 WSL" ;;
esac

step "1/6 版本一致性"
CARGO_VERSION="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
[ "$CARGO_VERSION" = "$VERSION" ] \
  || die "Cargo.toml 的 version($CARGO_VERSION) 与 VERSION 文件($VERSION) 不一致"
echo "version: $VERSION"

if [ "$DO_VENDOR" -eq 1 ]; then
  step "2/6 cargo vendor（产出离线依赖目录）"
  cargo vendor --versioned-dirs vendor
  echo "vendor/ 已生成；请在 .cargo/config.toml 中启用 vendored-sources 后使用 --offline"
else
  step "2/6 跳过 vendor"
fi

CARGO_ARGS=(build --release --locked)
[ "$OFFLINE" -eq 1 ] && CARGO_ARGS+=(--offline)

step "3/6 构建（${CARGO_ARGS[*]}）"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"   # 可复现构建锚点
export MAILSTACK_BUILT_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
cargo "${CARGO_ARGS[@]}"

step "4/6 收集产物"
mkdir -p "$DIST_DIR"
# 6.6：原先这里漏了 `mailstack-web`，而它明确是 workspace 的一个 bin（`bin/mailstack-web`，
# 包名 `mailstack-web-bin`、产物名 `mailstack-web`）。后果不只是「少复制一个文件」：
# 产物清单、`SHA256SUMS`、SBOM 会随之缺项，而发布包看起来仍然「构建成功」。
BINS=(target/release/mailstackd target/release/mailstackctl target/release/mailstack-web)
FOUND=0
MISSING=()
for bin in "${BINS[@]}"; do
  if [ -f "$bin" ]; then
    cp -f "$bin" "$DIST_DIR/"
    echo "已收集 $(basename "$bin") ($(stat -c%s "$bin") 字节)"
    FOUND=$((FOUND + 1))
  else
    echo "未构建：$bin" >&2
    MISSING+=("$bin")
  fi
done
# 6.6：原来的判定是 `FOUND -gt 0` —— 只要**任意一个**产物存在就算通过，
# 于是漏掉一个 bin 也能「构建成功」。交付物清单必须逐个齐全。
if [ "${#MISSING[@]}" -ne 0 ]; then
  die "产物不齐，缺少：${MISSING[*]}（workspace 的每个 bin 都必须产出）"
fi
[ "$FOUND" -eq "${#BINS[@]}" ] || die "产物数量不符"

step "5/6 SHA256SUMS"
( cd "$DIST_DIR" && sha256sum ./* > SHA256SUMS )
cat "$DIST_DIR/SHA256SUMS"

step "6/6 SBOM"
if command -v cargo >/dev/null && cargo sbom --version >/dev/null 2>&1; then
  cargo sbom --output-format spdx_json_2_3 > "$DIST_DIR/sbom.spdx.json"
  echo "已生成 sbom.spdx.json"
else
  # 退化路径：至少给出完整依赖清单，避免 SBOM 缺失导致发布流程中断。
  { echo "# MailStack $VERSION dependency inventory (cargo metadata)"; \
    cargo metadata --format-version 1 --locked \
      | tr ',' '\n' | grep -oE '"name":"[^"]+","version":"[^"]+"' | sort -u; } \
    > "$DIST_DIR/dependency-inventory.txt"
  echo "cargo-sbom 不可用，已退化为 dependency-inventory.txt"
  echo "（正式发布前请安装 cargo-sbom 以产出 SPDX/CycloneDX）"
fi

printf '\n构建完成：%s\n' "$DIST_DIR"
echo "版本：$VERSION"
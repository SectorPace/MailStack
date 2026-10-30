#!/usr/bin/env bash
# MailStack 构建脚本（规格书 §7 供应链要求）。
#
# 必须在 Linux 上运行（生产目标 x86_64-unknown-linux-gnu）。
#   * 依赖锁定：一律 `cargo build --locked`
#   * 离线可复现：`--offline` 配合 `cargo vendor` 产出的 vendor/
#   * 产物：二进制 + SHA256SUMS + SBOM
#
# libc 兼容性（2026-10-30 实测，见 docs/DEPLOYMENT.md §6）：
#   * 默认产物是**动态链接 glibc**，实测下限 **glibc >= 2.39**
#     （低版本报 `GLIBC_2.39 not found`，例如 Oracle Linux 9 / Rocky Linux 9 的 2.34）。
#   * `--musl` 额外产出 `*-musl` **全静态**二进制，不依赖 glibc，
#     实测可在 glibc 2.34、Alpine(musl) 上运行 —— 这是安装矩阵里
#     「Rocky Linux 9 / Alpine」唯一可用的产物形态。
#
# 用法：
#   deploy/build.sh                 # glibc 动态构建（默认）
#   deploy/build.sh --musl          # 额外产出 musl 全静态二进制
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
DO_MUSL=0
MUSL_TARGET="x86_64-unknown-linux-musl"

for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
    --vendor)  DO_VENDOR=1 ;;
    --musl)    DO_MUSL=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
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

# ── 可选：musl 全静态产物 ──
#
# 为什么需要它：默认产物动态链接 glibc，实测下限是 **glibc 2.39**。
# 而本项目声明支持的两个目标平台达不到：
#   * Rocky Linux 9 / Oracle Linux 9 = glibc 2.34
#   * Alpine = musl，根本没有 glibc
# 2026-10-30 实测：glibc 版在这两者上直接 `GLIBC_2.39 not found` / not found，
# musl 全静态版在两者上都能跑（见 docs/DEPLOYMENT.md §6 的兼容性矩阵）。
if [ "$DO_MUSL" -eq 1 ]; then
  step "4b/6 musl 全静态产物（${MUSL_TARGET}）"
  command -v musl-gcc >/dev/null \
    || die "缺少 musl-gcc（apt install musl-tools / dnf install musl-gcc 后重试）"
  rustup target list --installed 2>/dev/null | grep -qx "$MUSL_TARGET" \
    || rustup target add "$MUSL_TARGET"
  cargo build --release --locked --target "$MUSL_TARGET"
  for name in mailstackd mailstackctl mailstack-web; do
    src="target/$MUSL_TARGET/release/$name"
    [ -f "$src" ] || die "musl 产物缺失：$src"
    cp -f "$src" "$DIST_DIR/$name-musl"
    echo "已收集 $name-musl ($(stat -c%s "$src") 字节，全静态)"
  done
fi

step "5/6 SHA256SUMS"
( cd "$DIST_DIR" && sha256sum ./* > SHA256SUMS )
cat "$DIST_DIR/SHA256SUMS"

step "6/6 SBOM"
if command -v cargo >/dev/null && cargo sbom --version >/dev/null 2>&1; then
  cargo sbom --output-format spdx_json_2_3 > "$DIST_DIR/sbom.spdx.json"
  echo "已生成 sbom.spdx.json"
else
  # 退化路径：至少给出完整依赖清单，避免 SBOM 缺失导致发布流程中断。
  #
  # ⚠️ 这里原先有一个**真 bug**（2026-10-30 实测发现）：
  #   `cargo metadata ... | tr ',' '\n' | grep -oE '"name":"[^"]+","version":"[^"]+"'`
  # `cargo metadata` 输出的是 `"name":"x","version":"y"`，先按逗号切成两行后，
  # `"name":"x"` 与 `"version":"y"` 再也不会同时出现在一行里 —— grep 永远不匹配，
  # 于是 `dependency-inventory.txt` **只剩表头一行**。
  # 也就是说：没装 cargo-sbom 时，所谓「退化路径」产出的是空清单，
  # 而发布流程会以为 SBOM 已经生成了。
  #
  # 改用 python3 解析 JSON（本仓库的构建环境本身就需要 python3 做门禁校验）。
  { echo "# MailStack $VERSION dependency inventory (cargo metadata)"
    cargo metadata --format-version 1 --locked \
      | python3 -c '
import json, sys
doc = json.load(sys.stdin)
rows = sorted(
    (p["name"], p["version"], p.get("license") or "-")
    for p in doc["packages"]
    if p.get("source")  # 只列外部依赖，不列本仓库的 workspace 成员
)
for name, version, license in rows:
    print(f"{name} {version} {license}")
'
  } > "$DIST_DIR/dependency-inventory.txt"
  entries=$(grep -cv '^#' "$DIST_DIR/dependency-inventory.txt" 2>/dev/null || echo 0)
  echo "cargo-sbom 不可用，已退化为 dependency-inventory.txt（$entries 条外部依赖）"
  echo "（正式发布前请安装 cargo-sbom 以产出 SPDX/CycloneDX）"
  [ "$entries" -gt 0 ] || die "依赖清单为空：退化路径失效，SBOM 不可用"
fi

printf '\n构建完成：%s\n' "$DIST_DIR"
echo "版本：$VERSION"
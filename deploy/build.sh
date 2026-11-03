#!/usr/bin/env bash
# MailStack 构建脚本（规格书 §7 供应链要求）。
#
# 必须在 Linux 上运行（生产目标 x86_64-unknown-linux-gnu）。
#   * 依赖锁定：一律 `cargo build --locked`
#   * 离线可复现：`--offline` 配合 `cargo vendor` 产出的 vendor/
#   * 产物：二进制 + 发布 tarball + SHA256SUMS + SBOM
#
# libc 兼容性（2026-10-30 实测，见 docs/DEPLOYMENT.md §6）：
#   * 默认产物是**动态链接 glibc**，实测下限 **glibc >= 2.39**
#     （低版本报 `GLIBC_2.39 not found`，例如 Oracle Linux 9 / Rocky Linux 9 的 2.34）。
#   * `--musl` 额外产出 `*-musl` **全静态**二进制，不依赖 glibc，
#     实测可在 glibc 2.34、Alpine(musl) 上运行 —— 这是安装矩阵里
#     「Rocky Linux 9 / Alpine」唯一可用的产物形态。
#     带 `--musl` 时还会额外打一个 `...-x86_64-unknown-linux-musl.tar.gz`，
#     供 prebuilt 安装（`deploy/install.sh --archive <tarball>`）使用。
#
# 产物清单（R7-003：不再硬编码白名单）：
#   二进制集合从 `cargo build --message-format=json` 的
#   `compiler-artifact.executable` **动态收集**，再用 workspace 的 bin 目标集合做
#   相等断言 —— 新增/删除 bin 时构建会跟着变，漏收集会在这里失败，而不是静默
#   生成一个「看起来构建成功」的发布包。
#
# 发布 tarball 布局（install.sh 按此读取）：
#   mailstack-v<ver>-x86_64-unknown-linux-gnu/
#     bin/{mailstackd,mailstackctl,mailstack-web,mailstack-imap,mailstack-webmail}
#     deploy/install.sh
#     deploy/uninstall.sh
#     deploy/systemd/*.service.in
#     webui-dist/                      （仅当 webui/dist 存在）
#     README.md README_EN.md LICENSE CHANGELOG.md （仅当存在）
#
# 用法：
#   deploy/build.sh                 # glibc 动态构建（默认）
#   deploy/build.sh --musl          # 额外产出 musl 全静态二进制 + musl 发布包
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
GNU_TARGET="x86_64-unknown-linux-gnu"
# workspace 必须产出的 5 个 bin（R7-003：第 5 个是 mailstack-webmail）。
# 动态集合与它做「必须全部包含」断言；多出来的 bin 会被自动收集。
EXPECTED_BINS=(mailstackd mailstackctl mailstack-web mailstack-imap mailstack-webmail)
# 发布包必须包含的模板文件（产物不齐必须 die，不允许「构建成功但发布包缺件」）。
REQUIRED_UNIT_TEMPLATES=(mailstackd mailstack-web mailstack-imap mailstack-webmail)
OPTIONAL_DOCS=(README.md README_EN.md LICENSE CHANGELOG.md)
TARBALLS=()

usage() {
  cat <<'EOF'
MailStack 构建脚本

用法: deploy/build.sh [选项]
  (默认)           release 构建（glibc 动态）+ 发布 tarball + SHA256SUMS + SBOM
  --musl           额外产出 musl 全静态二进制 + musl 发布 tarball
  --offline        使用已 vendor 的依赖离线构建
  --vendor         先执行 cargo vendor（--locked），再离线构建
  -h, --help       显示本帮助
EOF
}

for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
    --vendor)  DO_VENDOR=1 ;;
    --musl)    DO_MUSL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$1"; }
die()  { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

BUILD_JSON=""
MUSL_JSON=""
PKG_STAGE=""
cleanup() {
  [ -n "$BUILD_JSON" ] && rm -f -- "$BUILD_JSON"
  [ -n "$MUSL_JSON" ] && rm -f -- "$MUSL_JSON"
  [ -n "$PKG_STAGE" ] && rm -rf -- "$PKG_STAGE"
  return 0
}
trap cleanup EXIT

step "0/7 环境断言"
command -v cargo >/dev/null || die "未找到 cargo"
command -v cc    >/dev/null || die "未找到 C 编译器（链接 Rust 产物必需）"
command -v tar   >/dev/null || die "未找到 tar（发布包打包必需）"
command -v sha256sum >/dev/null || die "未找到 sha256sum（校验和必需）"

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

step "1/7 版本一致性"
CARGO_VERSION="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
[ "$CARGO_VERSION" = "$VERSION" ] \
  || die "Cargo.toml 的 version($CARGO_VERSION) 与 VERSION 文件($VERSION) 不一致"
echo "version: $VERSION"

# 发布包里必须有的「发布层文件」先做存在性断言：等打包到最后一步才发现缺
# install.sh，会在 dist/ 里留下半套产物，而构建脚本已经打印成功。
[ -f deploy/install.sh ]   || die "缺少 deploy/install.sh（发布包不完整）"
[ -f deploy/uninstall.sh ] || die "缺少 deploy/uninstall.sh（发布包不完整）"
for unit in "${REQUIRED_UNIT_TEMPLATES[@]}"; do
  [ -f "deploy/systemd/${unit}.service.in" ] \
    || die "缺少 unit 模板 deploy/systemd/${unit}.service.in（发布包不完整）"
done
echo "发布层文件: deploy/install.sh, deploy/uninstall.sh, deploy/systemd/*.service.in"

if [ "$DO_VENDOR" -eq 1 ]; then
  step "2/7 cargo vendor（产出离线依赖目录）"
  # 必须 --locked：否则 vendor 过程可能改写 Cargo.lock，与「锁定构建」矛盾。
  cargo vendor --locked --versioned-dirs vendor
  echo "vendor/ 已生成；请在 .cargo/config.toml 中启用 vendored-sources 后使用 --offline"
else
  step "2/7 跳过 vendor"
fi

CARGO_ARGS=(build --release --locked)
[ "$OFFLINE" -eq 1 ] && CARGO_ARGS+=(--offline)

# 构建前先清空 dist：上一轮留下的旧产物若不清，会连同本轮产物一起被收进
# SHA256SUMS，发布包里混入陈旧文件而校验和「看起来」仍然有效。
# 只删本脚本自己的输出目录，且删除前双重守卫：变量必须非空，且不得是 / 或仓库根。
: "${DIST_DIR:?DIST_DIR 未设置}"
case "$DIST_DIR" in
  /|"$REPO_ROOT"|"$REPO_ROOT"/) die "DIST_DIR 指向危险位置（$DIST_DIR），拒绝 rm -rf" ;;
esac
rm -rf -- "$DIST_DIR"

step "3/7 构建（${CARGO_ARGS[*]}）"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"   # 可复现构建锚点
export MAILSTACK_BUILT_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
BUILD_JSON="$(mktemp)"
# stdout 只放 JSON（供收集 executable），编译进度/告警都在 stderr，终端照常可见。
cargo "${CARGO_ARGS[@]}" --message-format=json > "$BUILD_JSON"

# ── 从构建事件动态收集可执行产物（R7-003） ──
#
# 之前是硬编码 `BINS=(...4 个...)`：workspace 增加 mailstack-webmail 后，dist/
# 与 SHA256SUMS 都会静默缺第 5 个二进制，而脚本仍然打印「构建完成」。
# 现在由 cargo 自己报告「哪些可执行文件被产出」，脚本只负责断言与收集。
parse_executables() {
  local json="$1"
  grep -oE '"executable":"[^"]+"' "$json" 2>/dev/null \
    | sed -E 's/^"executable":"//; s/"$//' \
    | sort -u
}

declare -A BUILT_BIN=()
while IFS= read -r exe; do
  [ -n "$exe" ] || continue
  BUILT_BIN["$(basename "$exe")"]="$exe"
done < <(parse_executables "$BUILD_JSON")

if [ "${#BUILT_BIN[@]}" -eq 0 ]; then
  die "没有从 cargo 构建事件里收集到任何可执行产物（构建失败？）"
fi

# 期望的 5 个 bin 必须全部出现（逐个点名，缺一个就失败）。
missing=()
for name in "${EXPECTED_BINS[@]}"; do
  if [ -z "${BUILT_BIN[$name]:-}" ]; then missing+=("$name"); fi
done
[ "${#missing[@]}" -eq 0 ] || die "产物不齐，缺少：${missing[*]}（workspace 的每个 bin 都必须产出）"

# 与 workspace 的 bin 目标集合做严格相等断言（新增 bin 被漏收集时会红）。
# python3 缺失时退化为「期望的 5 个必须齐全」+ 警告，避免把「没有 python3」误报成构建失败。
if command -v python3 >/dev/null 2>&1; then
  mapfile -t WORKSPACE_BINS < <(
    cargo metadata --format-version 1 --no-deps --locked \
      | python3 -c 'import json,sys
doc = json.load(sys.stdin)
names = sorted({t["name"] for p in doc["packages"] for t in p["targets"] if "bin" in t["kind"]})
print("\n".join(names))'
  )
  mapfile -t BUILT_BINS_SORTED < <(printf '%s\n' "${!BUILT_BIN[@]}" | sort)
  if [ "${#WORKSPACE_BINS[@]}" -ne "${#BUILT_BINS_SORTED[@]}" ] \
     || ! diff -u <(printf '%s\n' "${WORKSPACE_BINS[@]}") <(printf '%s\n' "${BUILT_BINS_SORTED[@]}") >/dev/null; then
    echo "workspace bin 目标: ${WORKSPACE_BINS[*]}" >&2
    echo "构建产出可执行文件: ${BUILT_BINS_SORTED[*]}" >&2
    die "workspace bin 集合与构建产物集合不一致（构建脚本漏收集/多收集）"
  fi
  echo "workspace bin 集合 == 构建产物集合：${WORKSPACE_BINS[*]}"
else
  echo "WARN: 未安装 python3，跳过 workspace bin 集合的严格比对（期望 ${#EXPECTED_BINS[@]} 个已齐全）" >&2
fi

step "4/7 收集产物"
mkdir -p "$DIST_DIR"
COLLECTED=0
for name in "${!BUILT_BIN[@]}"; do
  src="${BUILT_BIN[$name]}"
  [ -f "$src" ] || die "构建事件声称产出 $name，但文件不存在：$src"
  cp -f "$src" "$DIST_DIR/$name"
  echo "已收集 $name ($(stat -c%s "$src") 字节)"
  COLLECTED=$((COLLECTED + 1))
done
[ "$COLLECTED" -ge "${#EXPECTED_BINS[@]}" ] || die "收集到的产物数量不符（$COLLECTED）"

# ── 可选：musl 全静态产物 ──
#
# 为什么需要它：默认产物动态链接 glibc，实测下限是 **glibc 2.39**。
# 而本项目声明支持的两个目标平台达不到：
#   * Rocky Linux 9 / Oracle Linux 9 = glibc 2.34
#   * Alpine = musl，根本没有 glibc
# 2026-10-30 实测：glibc 版在这两者上直接 `GLIBC_2.39 not found` / not found，
# musl 全静态版在两者上都能跑（见 docs/DEPLOYMENT.md §6 的兼容性矩阵）。
declare -A MUSL_BIN=()
if [ "$DO_MUSL" -eq 1 ]; then
  step "4b/7 musl 全静态产物（${MUSL_TARGET}）"
  command -v musl-gcc >/dev/null \
    || die "缺少 musl-gcc（apt install musl-tools / dnf install musl-gcc 后重试）"
  rustup target list --installed 2>/dev/null | grep -qx "$MUSL_TARGET" \
    || rustup target add "$MUSL_TARGET"
  # --offline 必须透传给 musl 构建（此前漏传：断网机器上 musl 构建会去联网）。
  MUSL_JSON="$(mktemp)"
  cargo "${CARGO_ARGS[@]}" --target "$MUSL_TARGET" --message-format=json > "$MUSL_JSON"
  while IFS= read -r exe; do
    [ -n "$exe" ] || continue
    MUSL_BIN["$(basename "$exe")"]="$exe"
  done < <(parse_executables "$MUSL_JSON")
  for name in "${EXPECTED_BINS[@]}"; do
    [ -n "${MUSL_BIN[$name]:-}" ] || die "musl 产物缺失：$name"
    src="${MUSL_BIN[$name]}"
    [ -f "$src" ] || die "musl 产物缺失：$src"
    cp -f "$src" "$DIST_DIR/$name-musl"
    echo "已收集 $name-musl ($(stat -c%s "$src") 字节，全静态)"
  done
fi

step "5/7 SBOM"
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
  # `grep -c` 在「零命中」时会**既打印 0 又以退出码 1 结束**，原先的 `|| echo 0`
  # 于是又追加一行 0 —— entries 变成 "0\n0"，`[ ... -gt 0 ]` 报
  # "integer expression expected"，把一个合法的空清单误判成脚本故障。
  # 现在命令替换只取输出（`|| true` 保住 set -e 下赋值语句的退出码），
  # 空输出回落为 0，再按数字校验兜底。
  entries=$(grep -cv '^#' "$DIST_DIR/dependency-inventory.txt" 2>/dev/null || true)
  entries=${entries:-0}
  case "$entries" in
    ''|*[!0-9]*) die "依赖清单条数不是数字：$entries" ;;
  esac
  echo "cargo-sbom 不可用，已退化为 dependency-inventory.txt（$entries 条外部依赖）"
  echo "（正式发布前请安装 cargo-sbom 以产出 SPDX/CycloneDX）"
  [ "$entries" -gt 0 ] || die "依赖清单为空：退化路径失效，SBOM 不可用"
fi

# ── 发布 tarball ──
#
# 为什么必须由构建脚本产出：GitHub Release 上传的「一套产物」应该就是
# SHA256SUMS 覆盖的那一套。tarball 里放 install.sh/uninstall.sh/systemd 模板，
# 是为了让 `deploy/install.sh --archive <tarball>` 在离线机器上也能完成安装
# （否则安装器只能自己去网上捞模板，离线场景直接失效）。
package_tarball() {
  local tarball_suffix="$1"      # x86_64-unknown-linux-gnu / x86_64-unknown-linux-musl
  local source_suffix="$2"       # "" / "-musl"
  local pkg_name="mailstack-v${VERSION}-${tarball_suffix}"
  local tarball="$DIST_DIR/${pkg_name}.tar.gz"

  PKG_STAGE="$(mktemp -d)"
  local root="$PKG_STAGE/$pkg_name"
  mkdir -p "$root/bin" "$root/deploy/systemd"

  local name src found=0
  for name in "${EXPECTED_BINS[@]}"; do
    src="$DIST_DIR/${name}${source_suffix}"
    [ -f "$src" ] || die "打包失败：缺少 $src"
    cp -p "$src" "$root/bin/$name"
    chmod 0755 "$root/bin/$name"
    found=$((found + 1))
  done
  [ "$found" -eq "${#EXPECTED_BINS[@]}" ] || die "打包失败：二进制数量不符（$found）"

  cp -p deploy/install.sh   "$root/deploy/install.sh"
  cp -p deploy/uninstall.sh "$root/deploy/uninstall.sh"
  chmod 0755 "$root/deploy/install.sh" "$root/deploy/uninstall.sh"
  local unit
  for unit in "${REQUIRED_UNIT_TEMPLATES[@]}"; do
    cp -p "deploy/systemd/${unit}.service.in" "$root/deploy/systemd/${unit}.service.in"
  done

  if [ -d webui/dist ]; then
    cp -a webui/dist "$root/webui-dist"
    echo "已打包前端产物：webui-dist/"
  else
    echo "WARN: webui/dist 不存在，发布包不含前端产物（管理台/Webmail 页面将 503）" >&2
  fi
  local doc
  for doc in "${OPTIONAL_DOCS[@]}"; do
    [ -f "$doc" ] && cp -p "$doc" "$root/$doc"
  done
  if [ ! -f "$root/README.md" ] || [ ! -f "$root/LICENSE" ]; then
    echo "WARN: 发布包缺少 README.md 或 LICENSE（发布前应补齐）" >&2
  fi

  # 可复现：固定文件顺序/时间戳/属主（GNU tar 参数；BSD tar 上会失败，项目只支持 Linux）。
  tar --sort=name \
      --mtime="@${SOURCE_DATE_EPOCH}" \
      --owner=0 --group=0 --numeric-owner \
      -C "$PKG_STAGE" -czf "$tarball" "$pkg_name"

  # 打包后自检：5 个二进制 + install.sh 必须真的在包里（防止 cp/tar 静默漏件）。
  local listing entry
  listing="$(tar -tzf "$tarball")"
  printf '%s\n' "$listing" | grep -q "/deploy/install.sh\$" \
    || die "发布包自检失败：缺 deploy/install.sh"
  for name in "${EXPECTED_BINS[@]}"; do
    printf '%s\n' "$listing" | grep -q "/bin/${name}\$" \
      || die "发布包自检失败：缺 bin/${name}"
  done

  rm -rf -- "$PKG_STAGE"
  PKG_STAGE=""
  TARBALLS+=("$tarball")
  echo "已生成发布包：$(basename "$tarball") ($(stat -c%s "$tarball") 字节)"
}

step "6/7 发布包（release tarball）"
package_tarball "$GNU_TARGET" ""
if [ "$DO_MUSL" -eq 1 ]; then
  package_tarball "$MUSL_TARGET" "-musl"
fi

step "7/7 SHA256SUMS"
( cd "$DIST_DIR" && sha256sum ./* > SHA256SUMS )
cat "$DIST_DIR/SHA256SUMS"
for tarball in "${TARBALLS[@]}"; do
  # `sha256sum ./*` 生成的行是 `<hash>  ./<name>`；这里必须容忍可选的 `./`
  # 前缀，否则自检会把「刚刚写进去的条目」判成缺失（实测踩过：
  # tarball 已生成、SHA256SUMS 也有对应行，但 `grep " name$"` 匹配不到）。
  # 转义文件名里的 `.`；`--` 防止以 `-` 开头的名字被当成选项。
  pattern="$(printf '%s' "$(basename "$tarball")" | sed 's/[.[\*^$]/\\&/g')"
  grep -qE "(\./| )${pattern}\$" "$DIST_DIR/SHA256SUMS" \
    || die "SHA256SUMS 缺少发布包条目：$(basename "$tarball")"
done

printf '\n构建完成：%s\n' "$DIST_DIR"
echo "版本：$VERSION"
echo "发布包："
for tarball in "${TARBALLS[@]}"; do
  echo "  $(basename "$tarball")"
done

#!/usr/bin/env bash
# CI gate: deploy/install.sh 的「脱离源码树一行式自举」链路（引导段本身）。
#
# 为什么需要单独门禁：install-matrix 走的是源码树安装（$BASE 下 install-mail-stack.sh
# 存在，引导段根本不会进入），release.yml 只断言资产可复现、布局合规、四件套齐备，
# 二者都不执行引导代码。而一行式安装恰好是 README「快速开始」主推的形态，它的信任
# 模型（分离签名 → 校验和 → 解压 → 转交）一旦被改坏，用户侧就是「下载完直接执行了
# 未验签内容」——最不能出错的一段却完全没有覆盖。
#
# 不访问网络：用临时 ed25519 密钥签一份本地伪造 Release，三个基址环境变量全部指向
# file://，再以 README 主推的进程替换形态（bash <(curl -fsSL …)）执行真实的
# deploy/install.sh。资产内装的是 stub 安装器（只回显 handoff 现场），所以这里只覆盖
# 引导段，不会在 CI 机器上真装一套邮件栈。
#
# 失败路径逐条断言：签名缺失 / 签名不匹配 / 校验和被篡改 / 资产布局异常，都必须在
# 「铺开任何源码之前」非零退出，且不得写入 $STAGED。
set -Eeuo pipefail
# 与 install.sh 第 11 行保持同一套 PATH：本门禁在 CI 里经 sudo 启动，sudo 的
# secure_path 会换掉调用者的 PATH，固定下来就不必假设调用环境。
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_URL="file://$ROOT/deploy/install.sh"
TAG='v0.0.0-smoke'
ASSET="MailStack-$TAG.tar.gz"
# 引导段把解压目标硬编码为这个路径；门禁要断言「失败即不落盘」，必须盯同一个位置。
STAGED=/opt/mailstack-source

fail(){ echo "CI-BOOTSTRAP: $*" >&2; exit 1; }
for c in curl tar find sha256sum ssh-keygen mktemp; do
  command -v "$c" >/dev/null 2>&1 || fail "缺少依赖 $c"
done
[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "必须以 root 运行（引导段会写 $STAGED）：sudo bash $0"
# 本门禁会 rm -rf $STAGED。宁可拒绝运行，也不要把一台真机上已有的源码树顺手删掉。
[[ ! -e "$STAGED" ]] || fail "$STAGED 已存在（本门禁会覆盖它）。请先移走再运行：mv $STAGED /tmp/staged.bak"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK" "$STAGED"' EXIT

# 引导段的三个基址全部改指本地伪 Release（file:// 由 curl 直接读取，全程不出网）。
export MAILSTACK_RELEASE_API="file://$WORK/rel"
export MAILSTACK_RELEASE_BASE="file://$WORK/dl"
export MAILSTACK_RAW_BASE="file://$WORK/raw"
mkdir -p "$WORK/rel/releases" "$WORK/dl/$TAG" "$WORK/raw/deploy"
printf '{"tag_name":"%s"}\n' "$TAG" > "$WORK/rel/releases/latest"

# 临时发布密钥 + 与仓内信任锚同格式的 allowed_signers（identity 必须是
# mailstack-release —— 引导段的 ssh-keygen -Y verify 用的是这个 principal）。
ssh-keygen -q -t ed25519 -N '' -C smoke -f "$WORK/key" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C smoke-wrong -f "$WORK/key.wrong" >/dev/null

# 资产内的 stub「安装器」：只回显 handoff 现场，用来证明引导段确实把控制权交给了
# 解压出来的那棵树，且参数原样透传。
mkdir -p "$WORK/tree/MailStack-$TAG/deploy"
cat > "$WORK/tree/MailStack-$TAG/deploy/install.sh" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'SMOKE-HANDOFF-REACHED staged=%s args=%s\n' "$0" "$*"
STUB
chmod +x "$WORK/tree/MailStack-$TAG/deploy/install.sh"

write_trust_anchor(){
  awk '{print "mailstack-release "$1" "$2}' "$WORK/key.pub" \
    > "$WORK/raw/deploy/mailstack-release.allowed_signers"
}

# 用指定密钥签 SHA256SUMS。
# 必须先删掉旧签名：ssh-keygen -Y sign 在 <file>.sig 已存在时会问「Overwrite (y/n)?」，
# 非交互环境读到 EOF 就按「不覆盖」处理，而且**退出码仍是 0** —— 于是旧签名被静静地
# 留在原地，签名用例会假通过（scripts/package.py 的 sign_checksum_manifest 同样是
# 先 unlink 再签，原因相同）。
sign_sums(){
  rm -f "$1.sig"
  ssh-keygen -Y sign -f "$2" -n file "$1" >/dev/null 2>&1 || fail "ssh-keygen 签名失败：$1"
  [[ -s "$1.sig" ]] || fail "ssh-keygen 未产出签名文件：$1.sig"
}

# 打归档 → 写 SHA256SUMS → 用可信密钥签名。用例之间一律经这个函数回到干净状态。
# 用法: build_assets [额外顶层条目…]（额外条目用于构造「顶层多于一个」的异常资产）
build_assets(){
  rm -f "$WORK/dl/$TAG/$ASSET" "$WORK/dl/$TAG/SHA256SUMS" "$WORK/dl/$TAG/SHA256SUMS.sig"
  tar -C "$WORK/tree" -czf "$WORK/dl/$TAG/$ASSET" "MailStack-$TAG" "$@"
  (cd "$WORK/dl/$TAG" && sha256sum "$ASSET" > SHA256SUMS)
  sign_sums "$WORK/dl/$TAG/SHA256SUMS" "$WORK/key"
  write_trust_anchor
}

# 以 README 主推的进程替换形态执行真实安装器：bash <(curl -fsSL <install.sh>) [args…]
# --non-interactive 是必须的：无控制终端时引导段会跳过 /dev/tty 回接，否则它会走
# 「无可用 /dev/tty」这条同样正确、但与本门禁无关的失败路径。
run_installer(){
  set +e
  OUT=$(bash <(curl -fsSL "$INSTALL_URL") "$@" 2>&1)
  RC=$?
  set -e
}

expect_fail(){
  local needle=$1 desc=$2
  shift 2
  rm -rf "$STAGED"
  run_installer "$@"
  (( RC != 0 )) || fail "$desc：预期非零退出，实际 rc=0。输出：$OUT"
  case "$OUT" in
    *"$needle"*) ;;
    *) fail "$desc：输出未包含「$needle」。实际输出：$OUT" ;;
  esac
  [[ ! -e "$STAGED/deploy/install.sh" ]] \
    || fail "$desc：失败路径竟把源码铺到了 $STAGED（必须在解压/铺开之前中止）"
  echo "  ok: $desc"
}

echo "==> 1/7 --help 必须离线可用（不下载任何 Release 资产）"
rm -rf "$STAGED"
set +e
OUT=$(MAILSTACK_RELEASE_API="file://$WORK/absent" \
      MAILSTACK_RELEASE_BASE="file://$WORK/absent" \
      MAILSTACK_RAW_BASE="file://$WORK/absent" \
      bash <(curl -fsSL "$INSTALL_URL") --help 2>&1)
RC=$?
set -e
(( RC == 0 )) || fail "--help 在无源码树时应离线打印用法并以 0 退出，实际 rc=$RC。输出：$OUT"
case "$OUT" in
  *'用法:'*) ;;
  *) fail "--help 输出缺少用法文本（三个基址都不可达，一旦回落到引导段就会失败）：$OUT" ;;
esac
echo "  ok: --help 离线可用，未触发引导段"

build_assets

echo "==> 2/7 缺少 SHA256SUMS.sig 必须拒绝（升级端同款门禁：无签名不安装）"
rm -f "$WORK/dl/$TAG/SHA256SUMS.sig"
expect_fail '拒绝继续' 'Release 缺少签名时拒绝安装' --non-interactive

echo "==> 3/7 签名与信任锚不匹配必须拒绝（防篡改控制落在这里）"
build_assets
sign_sums "$WORK/dl/$TAG/SHA256SUMS" "$WORK/key.wrong"
expect_fail '签名验证失败' 'SHA256SUMS 由非发布密钥签名时拒绝安装' --non-interactive

echo "==> 4/7 归档被篡改必须拒绝（签名只覆盖 SHA256SUMS，归档由校验和兜底）"
build_assets
printf 'tamper' >> "$WORK/dl/$TAG/$ASSET"
expect_fail 'SHA256 校验失败' '归档字节被改动时拒绝安装' --non-interactive

echo "==> 5/7 资产顶层条目多于一个必须拒绝（与 ms upgrade 同门禁）"
mkdir -p "$WORK/tree/extra"
build_assets extra
expect_fail '资产结构异常' '资产含多个顶层条目时拒绝安装' --non-interactive
rmdir "$WORK/tree/extra"

echo "==> 6/7 资产缺少 deploy/install.sh 必须拒绝（转交前必须能自证是安装包）"
mv "$WORK/tree/MailStack-$TAG/deploy/install.sh" "$WORK/hold.stub"
build_assets
expect_fail '缺少核心部署文件' '资产缺少 deploy/install.sh 时拒绝安装' --non-interactive
mv "$WORK/hold.stub" "$WORK/tree/MailStack-$TAG/deploy/install.sh"

echo "==> 7/7 合法资产：验签 → 校验和 → 解压 → 铺开 → 转交安装器"
build_assets
rm -rf "$STAGED"
run_installer --non-interactive
(( RC == 0 )) || fail "合法资产应完成引导并转交安装器，实际 rc=$RC。输出：$OUT"
for needle in '签名验证通过' '校验和验证通过' 'SMOKE-HANDOFF-REACHED' \
              "staged=$STAGED/deploy/install.sh" 'args=--non-interactive'; do
  case "$OUT" in
    *"$needle"*) ;;
    *) fail "成功路径输出缺少「$needle」（引导链可能在某一步静默降级）。实际输出：$OUT" ;;
  esac
done
echo "  ok: 引导段完整走通，stub 安装器在 $STAGED 接手，参数原样透传"

echo "CI-BOOTSTRAP: all checks passed"
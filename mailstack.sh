#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  if command -v bash >/dev/null 2>&1; then
    exec bash "$0" "$@"
  else
    echo "Error: bash is required to run mailstack.sh" >&2
    exit 1
  fi
fi
set -Eeuo pipefail
VERSION="v0.8.0-beta.10"
REPO_URL="${MAILSTACK_REPO_URL:-https://github.com/SectorPace/MailStack.git}"
INSTALL_DIR="/opt/mailstack-source"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
cyan(){ printf '\033[36m%s\033[0m\n' "$*"; }
need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || exec sudo -- "$SELF" "$@"; }
usage(){ cat <<EOF
MailStack ${VERSION} 运维管理工具

常用命令：
  ms doctor              # 执行系统全栈健康体检 (配置、服务、端口、DNS、TLS、AI)
  ms audit-verify       # 校验审计日志哈希链完整性 (截尾/篡改 → 非零退出)
  ms test-mail [邮箱]     # 执行邮件闭环投递验证 (Roundtrip Loopback)
  ms backup [create|list] # 备份配置 (支持 --include-mails) 或查看历史备份
  ms restore <备份文件>   # 安全还原历史配置备份 (自动生成回滚快照)
  ms status              # 查看核心服务运行状态
  ms logs [admin|webmail] # 实时查看系统与服务日志
  ms upgrade [版本]      # 从官方签名 Release 资产安全升级 (验签失败即中止；可指定版本标签钉扎)
                         #   拒绝降级到低于当前已安装版本；确需降级加 --allow-downgrade (会记审计)
  ms rollback            # 快速回滚至上次备份状态
  ms uninstall [--purge] # 安全卸载 (默认完整保留用户邮件数据)
  ms version             # 查看当前安装版本

高级用法：
  sudo bash mailstack.sh install [安装选项]
  sudo bash mailstack.sh uninstall --dry-run
EOF
}
copy_source(){
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  tar -C "$(dirname "$SELF")" \
    --exclude=.git --exclude=node_modules \
    -cf - . | tar -C "$INSTALL_DIR" -xf -
  chmod +x "$INSTALL_DIR/mailstack.sh" "$INSTALL_DIR/deploy/"*.sh "$INSTALL_DIR/backend/mailstackctl.py" 2>/dev/null || true
  chmod +x "$INSTALL_DIR/scripts/"*.sh 2>/dev/null || true
}
install_cmd(){
  need_root install "$@"
  copy_source
  green "正在运行 MailStack 安装器..."
  bash "$INSTALL_DIR/deploy/install.sh" "$@"
  green "安装完成。以后在命令行直接运行：ms"
}
# 透传初次安装时持久化的参数，保证升级后访问模式/域名/HTTPS 行为与原部署一致。
# 两个升级来源（签名 Release / 开发者 git）共用同一段安装逻辑。
run_staged_install(){
  local staged=$1; shift
  local extra_args=()
  if [[ -r /etc/mailstack/install-args.conf ]]; then
    # shellcheck disable=SC1091
    source /etc/mailstack/install-args.conf
    extra_args+=(--access-mode "$ACCESS_MODE" --admin-port "$ADMIN_PORT" --webmail-port "$WEBMAIL_PORT" --admin-host "$ADMIN_HOST" --webmail-host "$WEBMAIL_HOST")
    [[ -n ${MAIL_DOMAIN:-} ]] && extra_args+=(--domain "$MAIL_DOMAIN")
    [[ -n ${WEBMAIL_DOMAIN:-} ]] && extra_args+=(--webmail-domain "$WEBMAIL_DOMAIN")
    [[ -n ${ADMIN_EMAIL:-} ]] && extra_args+=(--email "$ADMIN_EMAIL")
    [[ ${HTTPS_MODE:-0} == 1 ]] && extra_args+=(--https)
    # plain 模式在非交互安装下必须显式确认（初次安装时用户已确认过一次）
    [[ ${ACCESS_MODE:-} == plain ]] && extra_args+=(--i-understand-plain-http)
  else
    yellow "未找到 /etc/mailstack/install-args.conf，升级将回退到 local 访问模式。"
  fi
  # ${extra_args[@]+...} 守卫：bash < 4.4 的 set -u 下空数组展开会误报 unbound variable
  bash "$staged/deploy/install.sh" --reuse-admin ${extra_args[@]+"${extra_args[@]}"} "$@"
  rm -rf "$INSTALL_DIR"
  mv "$staged" "$INSTALL_DIR"
  green "MailStack 更新完成。"
}

# --- A4：升级拒绝降级 -------------------------------------------------------
# ALLOW_DOWNGRADE 由 update_cmd 解析到的 --allow-downgrade 旗标置位；默认 0（拒绝降级）。
ALLOW_DOWNGRADE=0

# 版本比较：a < b 时返回 0（真），相等或 a > b 返回 1。用 sort -V 处理，先剥离 v 前缀。
# 任一为空按“不降级”处理（返回 1），避免缺信息时误拦。
_semver_lt(){
  local a=${1#v} b=${2#v}
  [[ -n "$a" && -n "$b" ]] || return 1
  [[ "$a" == "$b" ]] && return 1
  local first
  first=$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)
  [[ "$first" == "$a" ]]
}

# 读取当前已安装版本。/etc/mailstack/installed-version 不存在（老装机）时，
# 回退到本脚本自带的 VERSION，绝不因缺文件而阻塞升级。MAILSTACK_INSTALLED_VERSION_FILE
# 仅供测试注入，生产走默认绝对路径。
_read_installed_version(){
  local f=${MAILSTACK_INSTALLED_VERSION_FILE:-/etc/mailstack/installed-version}
  if [[ -r "$f" ]]; then
    local v
    v=$(head -n1 "$f" | tr -d '[:space:]')
    if [[ -n "$v" ]]; then printf '%s\n' "${v#v}"; return 0; fi
  fi
  printf '%s\n' "${VERSION#v}"
}

# 读取已安装侧的访问模式（install-args.conf 由 install.sh 用 %q 写入，值不含特殊字符）。
# 文件缺失时回退 local。MAILSTACK_INSTALL_ARGS_CONF 仅供测试注入。
_installed_access_mode(){
  local f=${MAILSTACK_INSTALL_ARGS_CONF:-/etc/mailstack/install-args.conf}
  if [[ -r "$f" ]]; then
    local line val
    line=$(grep -m1 '^[[:space:]]*ACCESS_MODE=' "$f" 2>/dev/null || true)
    if [[ -n "$line" ]]; then
      val=${line#*=}
      val=$(printf '%s' "$val" | tr -d '[:space:]' | sed -e "s/^['\"]//" -e "s/['\"]$//")
      if [[ -n "$val" ]]; then printf '%s\n' "$val"; return 0; fi
    fi
  fi
  printf '%s\n' local
}

# --allow-downgrade 放行时写审计（动作名 downgrade_allowed）。复用 helper 的 audit()，
# 与 RPC 审计同一格式/同一日志/同一 0600 权限。best-effort：找不到后端时告警但不阻塞
# 已显式授权的降级。
_audit_downgrade_allowed(){
  local target=$1 backend rc
  for backend in /opt/mailstack/backend "$(dirname "$SELF")/backend"; do
    [[ -d "$backend/mailstackctl" ]] || continue
    rc=0
    python3 - "$backend" "$target" >/dev/null 2>&1 <<'PY' || rc=$?
import sys
sys.path.insert(0, sys.argv[1])
from mailstackctl.core import audit
audit('downgrade_allowed', True, '', {'filename': sys.argv[2]})
PY
    [[ $rc -eq 0 ]] && return 0
  done
  yellow "无法写入 downgrade_allowed 审计（未找到 helper 后端），降级仍按 --allow-downgrade 放行。"
  return 0
}

# 降级门：目标版本 < 已安装版本时拒绝（返回非零），除非 ALLOW_DOWNGRADE=1。
# 独立可调（T-UP-1 直接 source 本脚本后测此函数）。latest 与显式 tag 共用同一比较，
# 故 GitHub latest 被劫持到旧签名包时同样在此被拦下。
assert_no_downgrade(){
  local target=${1#v} current
  current=$(_read_installed_version)
  if _semver_lt "$target" "$current"; then
    if [[ "$ALLOW_DOWNGRADE" == "1" ]]; then
      yellow "⚠️  --allow-downgrade：目标 $target 低于已安装 $current，已按显式旗标放行并记审计。"
      _audit_downgrade_allowed "$target"
      return 0
    fi
    red "拒绝降级：目标版本 $target 低于当前已安装版本 $current。"
    red "升级只接受等于或高于当前版本的签名 Release；确需降级请显式追加 --allow-downgrade（将写入审计）。"
    return 1
  fi
  return 0
}

# 默认且唯一的在线升级通道：GitHub Release 签名资产。
# 只接受「tar.gz + SHA256SUMS + ssh-keygen 分离签名」三件套，
# 验签或校验和失败即退出，绝不执行来历不明的 install.sh。
# 打印 commit SHA 不是签名；git clone HEAD 更不是。
update_from_signed_release(){
  local ref=$1; shift
  local api_base=${MAILSTACK_RELEASE_API:-https://api.github.com/repos/SectorPace/MailStack}
  local dl_base=${MAILSTACK_RELEASE_BASE:-https://github.com/SectorPace/MailStack/releases/download}
  command -v curl >/dev/null || { red "缺少 curl，无法下载 Release 资产"; exit 1; }
  command -v ssh-keygen >/dev/null || { red "缺少 ssh-keygen (需要 OpenSSH >= 8.0)，无法验证 Release 签名"; exit 1; }

  local tag=$ref
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  if [[ -z "$tag" ]]; then
    green "正在查询最新 Release..."
    tag=$(curl -fsSL "$api_base/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    [[ "$tag" =~ ^v[0-9][A-Za-z0-9.+-]{0,63}$ ]] || { red "无法解析最新 Release 标签"; exit 1; }
  else
    [[ "$tag" == v* ]] || tag="v$tag"
    [[ "$tag" =~ ^v[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$ ]] || { red "非法版本标签: $tag"; exit 1; }
  fi

  local asset="MailStack-${tag}.tar.gz"
  green "正在下载 Release 资产 $tag ..."
  curl -fsSL "$dl_base/$tag/SHA256SUMS" -o "$tmp/SHA256SUMS" || { red "下载 SHA256SUMS 失败（该 Release 可能没有发布校验文件）"; exit 1; }
  curl -fsSL "$dl_base/$tag/SHA256SUMS.sig" -o "$tmp/SHA256SUMS.sig" || { red "下载 SHA256SUMS.sig 失败（该 Release 未携带签名，拒绝继续）"; exit 1; }
  curl -fsSL "$dl_base/$tag/$asset" -o "$tmp/$asset" || { red "下载 $asset 失败"; exit 1; }

  # 签名信任锚：安装时落到 /etc/mailstack 的 allowed_signers；
  # 源码树内直接运行时回退到仓库自带的同一文件。
  local signers=/etc/mailstack/release-allowed-signers
  [[ -r "$signers" ]] || signers="$(dirname "$SELF")/deploy/mailstack-release.allowed_signers"
  [[ -r "$signers" ]] || { red "找不到 Release 签名信任锚 (allowed_signers)"; exit 1; }
  green "正在验证 SHA256SUMS 的 ssh-keygen 签名..."
  if ! ssh-keygen -Y verify -f "$signers" -I mailstack-release -n file -s "$tmp/SHA256SUMS.sig" < "$tmp/SHA256SUMS" >/dev/null 2>&1; then
    red "Release 签名验证失败！可能是资产被篡改或信任锚过旧。已中止升级，未执行任何安装脚本。"
    exit 1
  fi
  green "签名验证通过 (identity: mailstack-release, namespace: file)"

  (cd "$tmp" && grep -- " $asset\$" SHA256SUMS > .check && sha256sum -c .check >/dev/null) || { red "$asset 的 SHA256 校验失败，已中止升级"; exit 1; }
  green "校验和验证通过"

  # A4：降级门。验签 + 校验和都通过后、执行任何安装动作前比对版本。latest 与显式 tag
  # 都汇聚到同一 $tag，故 GitHub latest 被劫持到旧签名包（旧包签名有效，只有版本比较能
  # 识别）的场景同样在此被拦下。
  if ! assert_no_downgrade "$tag"; then
    exit 1
  fi

  mkdir -p "$tmp/extract"
  tar -xzf "$tmp/$asset" -C "$tmp/extract" || { red "解压 Release 资产失败"; exit 1; }
  # 资产内有且只有一个顶层目录 (MailStack-<tag>/)；多顶层条目属于异常资产。
  local top_count top_dir
  top_count=$(find "$tmp/extract" -mindepth 1 -maxdepth 1 | wc -l)
  [[ "$top_count" == "1" ]] || { red "Release 资产结构异常（顶层条目数: $top_count）"; exit 1; }
  top_dir=$(find "$tmp/extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
  if [[ ! -s "$top_dir/deploy/install.sh" ]]; then
    red "获取更新失败：Release 资产缺少核心部署文件"
    exit 1
  fi
  green "正在执行热更新与构建校验（已验签资产 $tag）..."
  rm -rf /opt/mailstack-source.new
  mkdir -p /opt/mailstack-source.new
  tar -C "$top_dir" --exclude=.git --exclude=node_modules -cf - . | tar -C /opt/mailstack-source.new -xf -
  run_staged_install /opt/mailstack-source.new "$@"
}

# 开发者专用遗留通道。生产环境禁止：MAILSTACK_REPO_URL 可以指向任意 git
# 远端，clone HEAD 后以 root 执行其中的 install.sh 等于把主机交给远端。
# 必须显式设置 MAILSTACK_ALLOW_UNSAFE_GIT=1 才会走到这里。
update_from_unsafe_git(){
  local ref=$1; shift
  yellow "⚠️  MAILSTACK_ALLOW_UNSAFE_GIT=1：正在使用不安全的 git clone 升级通道（仅限开发者）"
  command -v git >/dev/null || { red "缺少 git，正在尝试自动安装..."; (command -v apt-get >/dev/null && apt-get install -y git) || (command -v dnf >/dev/null && dnf install -y git) || (command -v yum >/dev/null && yum install -y git) || (command -v zypper >/dev/null && zypper -n in git) || (command -v pacman >/dev/null && pacman -Sy --noconfirm git) || (command -v apk >/dev/null && apk add git) || { red "无法安装 git"; exit 1; }; }
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  green "正在从 GitHub 获取${ref:+ $ref}最新代码..."
  local clone_args=(--depth 1)
  [[ -n "$ref" ]] && clone_args+=(--branch "$ref")
  git clone "${clone_args[@]}" "$REPO_URL" "$tmp/repo"
  if [[ ! -s "$tmp/repo/deploy/install.sh" ]]; then
    red "获取更新失败：更新仓库缺少核心部署文件"
    exit 1
  fi
  green "更新来源: $REPO_URL @ $(git -C "$tmp/repo" rev-parse HEAD)"
  green "正在执行热更新与构建校验..."
  rm -rf /opt/mailstack-source.new
  mkdir -p /opt/mailstack-source.new
  tar -C "$tmp/repo" --exclude=.git --exclude=node_modules -cf - . | tar -C /opt/mailstack-source.new -xf -
  run_staged_install /opt/mailstack-source.new "$@"
}

update_cmd(){
  need_root update "$@"
  # 首个非选项参数视为目标版本标签（钉扎在已知 Release 上，而不是无条件
  # 跟进 latest）；--allow-downgrade 是 A4 降级放行旗标；其余参数透传给安装器，
  # 可覆盖 install-args.conf 持久化的部署参数（此前参数被静默丢弃）。
  local ref=''
  local passthrough=()
  ALLOW_DOWNGRADE=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --allow-downgrade) ALLOW_DOWNGRADE=1; shift;;
      -*) passthrough+=("$1"); shift;;
      *) if [[ -z "$ref" ]]; then ref=$1; else passthrough+=("$1"); fi; shift;;
    esac
  done
  if [[ "${MAILSTACK_ALLOW_UNSAFE_GIT:-0}" == "1" ]]; then
    # A5：公网逃生门硬关。MAILSTACK_ALLOW_UNSAFE_GIT 是开发者专用的不安全 git clone
    # 升级逃生门；公网（access-mode=caddy/direct，或 SECURITY_PROFILE=high）下即便置 1
    # 也拒绝 upgrade。唯一豁免：MAILSTACK_I_AM_A_DEVELOPER=1 且 access-mode=local。
    local mode profile
    mode=$(_installed_access_mode)
    profile=$(printf '%s' "${MAILSTACK_SECURITY_PROFILE:-}" | tr '[:upper:]' '[:lower:]')
    if [[ "$mode" == "caddy" || "$mode" == "direct" || "$profile" == "high" ]]; then
      if ! { [[ "${MAILSTACK_I_AM_A_DEVELOPER:-0}" == "1" && "$mode" == "local" ]]; }; then
        red "拒绝：MAILSTACK_ALLOW_UNSAFE_GIT=1 是不安全的 git clone 升级逃生门，公网模式（当前 access-mode=$mode）下禁止使用。"
        red "公网升级只接受官方签名 Release 资产：去掉 MAILSTACK_ALLOW_UNSAFE_GIT 即走签名通道。"
        red "唯一豁免：MAILSTACK_I_AM_A_DEVELOPER=1 且 access-mode=local（见冲98清单 A5 逃生门语义）。"
        exit 1
      fi
    fi
    update_from_unsafe_git "$ref" ${passthrough[@]+"${passthrough[@]}"}
  else
    if [[ -n "${MAILSTACK_REPO_URL:-}" && "${MAILSTACK_REPO_URL}" != "https://github.com/SectorPace/MailStack.git" ]]; then
      red "MAILSTACK_REPO_URL 指向非官方 git 源，已拒绝。升级只接受官方签名 Release 资产；开发者请显式设置 MAILSTACK_ALLOW_UNSAFE_GIT=1。"
      exit 1
    fi
    update_from_signed_release "$ref" ${passthrough[@]+"${passthrough[@]}"}
  fi
}
doctor_cmd(){
  need_root doctor "$@"
  cyan "=== [MailStack 全栈系统健康体检] ==="
  python3 - <<'PY'
import json, subprocess, sys
# need_root 已保证以 root 运行：直接调用特权助手，不再依赖 sudo 存在
try:
    p = subprocess.run(['/usr/local/libexec/mailstack-privileged'], input=json.dumps({'action':'system.doctor','data':{}}).encode(), stdout=subprocess.PIPE)
except FileNotFoundError:
    print("未找到特权助手 /usr/local/libexec/mailstack-privileged，请先运行 ms install")
    sys.exit(1)
if p.returncode != 0:
    print(f"体检执行失败 (退出码 {p.returncode})，请检查 journalctl 中的 helper 崩溃原因")
    sys.exit(1)
res = json.loads(p.stdout.decode())
if not res.get('ok'):
    print(f"体检错误: {res.get('error')}")
    sys.exit(1)
data = res.get('data', {})
overall = data.get('overall', 'UNKNOWN')
colors = {'HEALTHY': '\033[32m', 'WARNING': '\033[33m', 'CRITICAL': '\033[31m'}
reset = '\033[0m'
print(f"总体状态: {colors.get(overall, '')}{overall}{reset} ({data.get('summary')})\n")
print(f"{'类别':<10} {'检查项':<24} {'状态':<6} {'详情与建议'}")
print("-" * 75)
for c in data.get('checks', []):
    st = c.get('status', 'INFO')
    st_color = '\033[32m' if st == 'PASS' else ('\033[33m' if st == 'WARN' else ('\033[31m' if st == 'FAIL' else ''))
    msg = c.get('message', '')
    if c.get('fixSuggestion'):
        msg += f" -> \033[36m建议: {c.get('fixSuggestion')}\033[0m"
    print(f"{c.get('category',''):<10} {c.get('name',''):<24} {st_color}{st:<6}{reset} {msg}")
print("-" * 75)
PY
}
audit_verify_cmd(){
  need_root audit-verify "$@"
  cyan "=== [MailStack 审计日志哈希链校验] ==="
  if [[ ! -x /usr/local/libexec/mailstack-privileged ]]; then
    red "未找到特权助手 /usr/local/libexec/mailstack-privileged，请先运行 ms install"
    exit 1
  fi
  # B3：audit-verify 是 CLI 子命令（非 RPC action），经包装器参数透传直达
  # mailstackctl.py；退出码透传（截尾/篡改非零）。日志 0600 root:root，须 root 读。
  /usr/local/libexec/mailstack-privileged audit-verify
}
test_mail_cmd(){
  need_root test-mail "$@"
  local recipient="${1:-}"
  cyan "=== [MailStack 邮件链路闭环投递验证] ==="
  python3 - "$recipient" <<'PY'
import json, subprocess, sys
rec = sys.argv[1]
data = {'recipient': rec} if rec else {}
try:
    p = subprocess.run(['/usr/local/libexec/mailstack-privileged'], input=json.dumps({'action':'mail.test_loopback','data':data}).encode(), stdout=subprocess.PIPE)
except FileNotFoundError:
    print("未找到特权助手 /usr/local/libexec/mailstack-privileged，请先运行 ms install")
    sys.exit(1)
if p.returncode != 0:
    print(f"投递验证执行失败 (退出码 {p.returncode})")
    sys.exit(1)
res = json.loads(p.stdout.decode())
if not res.get('ok'):
    print(f"\033[31m投递验证失败: {res.get('error')}\033[0m")
    sys.exit(1)
d = res.get('data', {})
print(f"\033[32m✓ 投递验证成功！\033[0m")
print(f"  发件人: {d.get('sender')}")
print(f"  收件人: {d.get('recipient')}")
print(f"  跟踪令牌: {d.get('token')}")
print(f"  往返延迟: {d.get('deliveryTimeMs')} ms")
print(f"  Maildir 写入确认: {'是 (已验证本地邮箱目录落地)' if d.get('maildirDelivered') else '否 (已进入中继/外部队列)'}")
PY
}
backup_cmd(){
  need_root backup "$@"
  local sub="${1:-list}"
  shift || true
  if [[ "$sub" == "create" ]]; then
    local inc_mail=false encrypt=0
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --include-mails) inc_mail=true;;
        --encrypt) encrypt=1;;
      esac
      shift || true
    done
    if ((encrypt)) && [[ -z "${MAILSTACK_BACKUP_PASSPHRASE:-}" ]]; then
      # 口令只走 read -s（/dev/tty）→ 环境变量 → helper 的 stdin JSON，
      # 绝不进入任何进程的 argv（rc.5 铁律）。
      local pp1 pp2
      read -rs -p "请输入备份加密口令（不回显）: " pp1 </dev/tty; echo
      read -rs -p "请再次输入以确认: " pp2 </dev/tty; echo
      if [[ "$pp1" != "$pp2" ]]; then red "两次输入的口令不一致，已取消"; exit 1; fi
      if [[ -z "$pp1" ]]; then red "加密口令不能为空，已取消"; exit 1; fi
      export MAILSTACK_BACKUP_PASSPHRASE="$pp1"
    fi
    if ((encrypt)); then
      cyan "正在创建加密配置备份..."
    else
      cyan "正在创建配置备份..."
    fi
    python3 - "$inc_mail" "$encrypt" <<'PY'
import json, os, subprocess, sys
inc = sys.argv[1] == 'true'
enc = sys.argv[2] == '1'
data = {'includeMails': inc}
if enc:
    data['passphrase'] = os.environ.get('MAILSTACK_BACKUP_PASSPHRASE', '')
try:
    p = subprocess.run(['/usr/local/libexec/mailstack-privileged'], input=json.dumps({'action':'backup.create','data':data}).encode(), stdout=subprocess.PIPE)
except FileNotFoundError:
    print("未找到特权助手 /usr/local/libexec/mailstack-privileged，请先运行 ms install")
    sys.exit(1)
if p.returncode != 0:
    print(f"备份执行失败 (退出码 {p.returncode})")
    sys.exit(1)
res = json.loads(p.stdout.decode())
if not res.get('ok'):
    print(f"\033[31m备份失败: {res.get('error')}\033[0m")
    sys.exit(1)
b = res['data']['backup']
print(f"\033[32m✓ 备份创建成功:\033[0m {b.get('name')}")
print(f"  路径: {b.get('path')} (大小: {b.get('size')} 字节)")
print(f"  SHA256: {b.get('sha256')}")
if b.get('encrypted'):
    print("  \033[32m加密: 已启用 (还原时需要口令)\033[0m")
PY
    unset MAILSTACK_BACKUP_PASSPHRASE
  else
    cyan "=== [历史配置备份列表] ==="
    python3 - <<'PY'
import json, subprocess, sys
try:
    p = subprocess.run(['/usr/local/libexec/mailstack-privileged'], input=json.dumps({'action':'backup.list','data':{}}).encode(), stdout=subprocess.PIPE)
except FileNotFoundError:
    print("未找到特权助手 /usr/local/libexec/mailstack-privileged，请先运行 ms install")
    sys.exit(1)
if p.returncode != 0:
    print(f"备份列表查询失败 (退出码 {p.returncode})")
    sys.exit(1)
res = json.loads(p.stdout.decode())
backups = res.get('data', [])
if not backups:
    print("暂无备份记录。运行 'ms backup create' 创建新备份。")
else:
    for b in backups:
        lock = ' | 加密: 是' if b.get('encrypted') else ''
        print(f"  • {b.get('name')} | {b.get('createdAt')} | {b.get('size')} 字节 | 邮件数据: {'包含' if b.get('includeMails') else '排除'}{lock}")
PY
  fi
}
restore_cmd(){
  need_root restore "$@"
  local file="${1:-}"
  if [[ -z "$file" ]]; then
    red "用法: ms restore <备份文件名或路径>"
    exit 1
  fi
  yellow "警告: 还原备份将覆盖现有的 Postfix/Dovecot/OpenDKIM 及 MailStack 配置！"
  read -r -p "确认还原备份 $file 吗？[y/N] " confirm
  if [[ ! "$confirm" =~ ^[yY]$ ]]; then
    echo "已取消还原。"
    exit 0
  fi
  # 目标备份元数据标记 encrypted 时，先索要口令（绝不进入 argv）。
  if [[ -z "${MAILSTACK_BACKUP_PASSPHRASE:-}" ]]; then
    local is_enc
    is_enc=$(python3 - "$file" <<'PY'
import json, subprocess, sys
fn = sys.argv[1]
try:
    p = subprocess.run(['/usr/local/libexec/mailstack-privileged'], input=json.dumps({'action':'backup.list','data':{}}).encode(), stdout=subprocess.PIPE)
    res = json.loads(p.stdout.decode())
    for b in res.get('data', []):
        if b.get('name') == fn or b.get('filename') == fn:
            print('1' if b.get('encrypted') else '0')
            break
    else:
        print('0')
except Exception:
    print('0')
PY
)
    if [[ "$is_enc" == "1" ]]; then
      local pp
      read -rs -p "该备份已加密，请输入解密口令（不回显）: " pp </dev/tty; echo
      export MAILSTACK_BACKUP_PASSPHRASE="$pp"
    fi
  fi
  python3 - "$file" <<'PY'
import json, os, subprocess, sys
fn = sys.argv[1]
data = {'filename': fn, 'confirm': True}
pp = os.environ.get('MAILSTACK_BACKUP_PASSPHRASE', '')
if pp:
    data['passphrase'] = pp
def call(payload):
    try:
        return subprocess.run(['/usr/local/libexec/mailstack-privileged'], input=json.dumps(payload).encode(), stdout=subprocess.PIPE)
    except FileNotFoundError:
        print("未找到特权助手 /usr/local/libexec/mailstack-privileged，请先运行 ms install")
        sys.exit(1)
p = call({'action':'backup.restore','data':data})
if p.returncode != 0:
    print(f"还原执行失败 (退出码 {p.returncode})")
    sys.exit(1)
res = json.loads(p.stdout.decode())
if not res.get('ok') and not pp and 'passphrase' in str(res.get('error', '')).lower():
    # 服务端要求口令时的兜底：交互索要后重试一次。
    import getpass
    pp = getpass.getpass("该备份需要口令才能还原，请输入解密口令（不回显）: ")
    data['passphrase'] = pp
    p = call({'action':'backup.restore','data':data})
    if p.returncode != 0:
        print(f"还原执行失败 (退出码 {p.returncode})")
        sys.exit(1)
    res = json.loads(p.stdout.decode())
if not res.get('ok'):
    print(f"\033[31m还原失败: {res.get('error')}\033[0m")
    sys.exit(1)
print(f"\033[32m✓ 备份已成功还原！服务已重新加载。\033[0m")
snap = res['data'].get('preRestoreSnapshot') or res['data'].get('snapshot')
if snap:
    print(f"  (已自动生成还原前回滚快照: {snap})")
snapwarn = res['data'].get('preRestoreSnapshotWarning')
if snapwarn:
    print(f"  \033[33m(回滚快照未生成: {snapwarn})\033[0m")
PY
  unset MAILSTACK_BACKUP_PASSPHRASE
}
rollback_cmd(){
  need_root rollback "$@"
  yellow "正在查找最近生成的安全回滚快照..."
  python3 - <<'PY'
import json, subprocess, sys, pathlib
base = pathlib.Path('/var/backups/mailstack')
# 快照由 backup_restore 生成，命名遵循 mailstack-backup-*-pre-restore.tar.gz
# （须匹配 helper 的 BACKUP_FILENAME_RE 且按 basename 传递，否则会被拒绝）。
snaps = sorted(base.glob('mailstack-backup-*-pre-restore.tar.gz'), key=lambda x: x.stat().st_mtime, reverse=True)
if not snaps:
    print("\033[31m未找到任何可回滚快照（先执行一次 ms restore 才会生成）。\033[0m")
    sys.exit(1)
latest = snaps[0]
print(f"发现最近快照: {latest.name}")
try:
    p = subprocess.run(['/usr/local/libexec/mailstack-privileged'], input=json.dumps({'action':'backup.restore','data':{'filename':latest.name,'confirm':True}}).encode(), stdout=subprocess.PIPE)
except FileNotFoundError:
    print("未找到特权助手 /usr/local/libexec/mailstack-privileged，请先运行 ms install")
    sys.exit(1)
if p.returncode != 0:
    print(f"回滚执行失败 (退出码 {p.returncode})")
    sys.exit(1)
res = json.loads(p.stdout.decode())
if not res.get('ok'):
    print(f"\033[31m回滚失败: {res.get('error')}\033[0m")
    sys.exit(1)
print(f"\033[32m✓ 成功回滚至快照: {latest.name}\033[0m")
PY
}
uninstall_cmd(){
  need_root uninstall "$@"
  local purge=0
  local dry_run=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge) purge=1;;
      --dry-run) dry_run=1;;
    esac
    shift || true
  done
  if ((dry_run)); then
    cyan "=== [卸载 Dry-Run 预检] ==="
    echo "将停止并注销的服务: mailstack-web, mailstack-webmail, mailstack-helper"
    echo "将删除的二进制与服务单元: /etc/systemd/system/mailstack-*.service, /usr/local/bin/ms, /usr/local/libexec/mailstack-privileged, /opt/mailstack, /run/mailstack"
    echo "将删除的 sudoers 规则: /etc/sudoers.d/mailstack-web（另清理历史遗留的 mailstack-web-ctl）"
    echo "将删除的 MailStack 组件配置: /etc/dovecot/conf.d/99-mailstack*.conf, /etc/logrotate.d/mailstack"
    echo "将备份后移除: /etc/caddy/Caddyfile (仅当文件含 MailStack 管理标记时，备份为 Caddyfile.mailstack-backup)"
    if ((purge)); then
      echo "将删除的配置文件: /etc/mailstack"
    else
      echo "将保留的配置文件: /etc/mailstack"
    fi
    echo "用户邮箱数据 (/home/*/Maildir 与 /var/vmail): 完整保留 (绝不删除)"
    exit 0
  fi
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now mailstack-web mailstack-webmail mailstack-helper 2>/dev/null || true
  elif [[ -x /etc/init.d/mailstack-web ]]; then
    /etc/init.d/mailstack-web stop 2>/dev/null || true
  fi
  rm -f /etc/systemd/system/mailstack-web.service /etc/systemd/system/mailstack-webmail.service /etc/systemd/system/mailstack-helper.service /etc/init.d/mailstack-web /etc/sudoers.d/mailstack-web /etc/sudoers.d/mailstack-web-ctl /usr/local/libexec/mailstack-privileged /usr/local/bin/ms /usr/local/bin/mailstack
  # 清理 MailStack 写入的组件级配置（与 dry-run 清单一致）
  rm -f /etc/dovecot/conf.d/99-mailstack-webmail.conf /etc/dovecot/conf.d/99-mailstack.conf /etc/logrotate.d/mailstack
  if [[ -f /etc/caddy/Caddyfile ]] && grep -q 'Managed automatically by MailStack' /etc/caddy/Caddyfile; then
    cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.mailstack-backup 2>/dev/null || true
    rm -f /etc/caddy/Caddyfile
  fi
  [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
  # dovecot 配置已移除，重启使其回到发行版默认行为
  command -v systemctl >/dev/null 2>&1 && systemctl restart dovecot 2>/dev/null || service dovecot restart 2>/dev/null || true
  rm -rf /opt/mailstack /opt/mailstack-source /opt/mailstack-source.new /run/mailstack
  if ((purge)); then
    rm -rf /etc/mailstack
    green "MailStack 程序、Webmail 及管理配置已彻底删除。Postfix、Dovecot 与邮件数据未自动删除。"
  else
    green "MailStack 程序与 Webmail 已删除，/etc/mailstack 管理配置及邮箱数据已完整保留。"
  fi
}
# 被 source 时（如 T-UP-1 提取纯函数测试）到此即返回，不执行命令分派。
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then return 0; fi
cmd=${1:-help}; shift || true
case "$cmd" in
  install) install_cmd "$@";;
  update|upgrade) update_cmd "$@";;
  doctor|diag|check) doctor_cmd "$@";;
  audit-verify) audit_verify_cmd "$@";;
  test-mail|mail-test) test_mail_cmd "$@";;
  backup) backup_cmd "$@";;
  restore) restore_cmd "$@";;
  rollback) rollback_cmd "$@";;
  uninstall) uninstall_cmd "$@";;
  status)
    if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
      echo "=== [MailStack 管理控制台服务 (mailstack-web)] ==="
      systemctl --no-pager status mailstack-web || true
      echo ""
      echo "=== [MailStack Webmail 邮箱服务 (mailstack-webmail)] ==="
      systemctl --no-pager status mailstack-webmail || true
      echo ""
      echo "=== [MailStack 特权助手服务 (mailstack-helper)] ==="
      systemctl --no-pager status mailstack-helper || true
    elif [[ -x /etc/init.d/mailstack-web ]]; then
      /etc/init.d/mailstack-web status || true
    fi
    ;;
  logs)
    svc="${1:-all}"
    if [[ -d /run/systemd/system ]] && command -v journalctl >/dev/null 2>&1; then
      if [[ "$svc" == "webmail" ]]; then
        journalctl -u mailstack-webmail -n 100 -f
      elif [[ "$svc" == "admin" || "$svc" == "web" ]]; then
        journalctl -u mailstack-web -n 100 -f
      elif [[ "$svc" == "helper" ]]; then
        journalctl -u mailstack-helper -n 100 -f
      else
        journalctl -u mailstack-web -u mailstack-webmail -u mailstack-helper -n 100 -f
      fi
    elif [[ -f /var/log/mailstack-web.log ]]; then
      tail -n 100 -f /var/log/mailstack-web.log /var/log/mailstack-webmail.log 2>/dev/null || tail -n 100 -f /var/log/mailstack-web.log
    fi
    ;;
  version|-v|--version) echo "$VERSION";;
  help|-h|--help) usage;;
  *) red "未知命令：$cmd"; usage; exit 1;;
esac

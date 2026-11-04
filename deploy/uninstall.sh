
set -Eeuo pipefail
umask 022

MAILSTACK_VERSION="1.0.0"

BIN_NAMES=(mailstackd mailstackctl mailstack-web mailstack-imap mailstack-webmail)
UNIT_NAMES=(mailstackd mailstack-web mailstack-imap mailstack-webmail)
WRAPPER_NAME="mailstack-privileged"
SUDOERS_NAME="mailstack-admin"

PREFIX="/"
PREFIX_NORM=""
PURGE=0
NON_INTERACTIVE=0

ETC_DIR=""
VAR_LIB_DIR=""
BACKUP_DIR=""
RUN_DIR=""
BIN_DIR=""
LIBEXEC_DIR=""
DIST_DIR=""
UNIT_DIR=""

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""

say()  { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

cleanup() { return 0; }
on_err() {
  local rc=$?
  printf '\nERROR: 卸载在第 %s 行失败（退出码 %s）\n' "${BASH_LINENO[0]}" "$rc" >&2
  exit "$rc"
}
trap cleanup EXIT
trap on_err ERR

usage() {
  cat <<'EOF'
MailStack v1.0.0 卸载脚本

用法:
  sudo bash deploy/uninstall.sh [选项]

选项:
  --prefix DIR        只卸载 DIR 下的 staging 安装（默认 /）
  --purge             连 /etc/mailstack、/var/lib/mailstack、/var/backups/mailstack 一起删除
  --non-interactive   不交互确认
  -h, --help          显示本帮助
  --version           显示版本

默认保留（--purge 才删除）:
  /etc/mailstack          配置、管理员凭证、身份（setup.json）
  /var/lib/mailstack      队列、注册表、封禁
  /var/backups/mailstack  备份

说明:
  * curl|bash 安装时可执行 `curl .../deploy/uninstall.sh | sudo bash -s --`；
    已安装的主机也可直接 `sudo bash /usr/local/libexec/mailstack-uninstall`。
  * 系统账号 mailstack-admin、组 mailstack-admin / mailstack-webmail / opendkim
    默认保留（并存的旧部署可能共用）；如需删除请手工 userdel/groupdel。
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --prefix)      [ "$#" -ge 2 ] || die "--prefix 需要一个目录参数"; PREFIX="$2"; shift 2 ;;
      --prefix=*)    PREFIX="${1#*=}"; shift ;;
      --purge)       PURGE=1; shift ;;
      --non-interactive) NON_INTERACTIVE=1; shift ;;
      -h|--help)     usage; exit 0 ;;
      --version)     printf 'MailStack uninstaller %s\n' "$MAILSTACK_VERSION"; exit 0 ;;
      *) die "未知参数：$1（用 -h 查看用法）" ;;
    esac
  done
}

normalize_prefix() {
  [ -n "$PREFIX" ] || PREFIX="/"
  case "$PREFIX" in
    /*) : ;;
    *) die "--prefix 必须是绝对路径（实际：$PREFIX）" ;;
  esac
  while [ "$PREFIX" != "/" ] && [ "${PREFIX%/}" != "$PREFIX" ]; do
    PREFIX="${PREFIX%/}"
  done
  if [ "$PREFIX" = "/" ]; then
    PREFIX_NORM=""
  else
    if ! printf '%s' "$PREFIX" | grep -Eq '^/[A-Za-z0-9._/-]+$'; then
      die "--prefix 只允许字母/数字/_/./-//（实际：$PREFIX）"
    fi
    case "$PREFIX" in
      /etc|/usr|/var|/bin|/sbin|/lib|/lib64|/boot|/home|/root|/opt|/srv|/mnt|/media|/run|/tmp|/dev|/proc|/sys)
        die "拒绝把 --prefix 指向系统目录：$PREFIX" ;;
    esac
    PREFIX_NORM="$PREFIX"
  fi
}

prefix_path() { printf '%s%s' "$PREFIX_NORM" "$1"; }

derive_paths() {
  ETC_DIR="$(prefix_path /etc/mailstack)"
  VAR_LIB_DIR="$(prefix_path /var/lib/mailstack)"
  BACKUP_DIR="$(prefix_path /var/backups/mailstack)"
  RUN_DIR="$(prefix_path /run/mailstack)"
  BIN_DIR="$(prefix_path /usr/local/bin)"
  LIBEXEC_DIR="$(prefix_path /usr/local/libexec)"
  DIST_DIR="$(prefix_path /usr/share/mailstack/admin)"
  UNIT_DIR="$(prefix_path /etc/systemd/system)"
}

safe_rm_rf() {
  local target="$1"
  [ -n "$target" ] || return 0
  case "$target" in /*) : ;; *) die "safe_rm_rf: 必须是绝对路径（$target）" ;; esac
  local real
  real="$(realpath -m -- "$target")" || die "safe_rm_rf: realpath 失败（$target）"
  case "$real" in
    /|/etc|/usr|/var|/bin|/sbin|/lib|/lib64|/boot|/home|/root|/opt|/srv|/mnt|/media|/run|/tmp|/dev|/proc|/sys)
      die "safe_rm_rf: 拒绝删除系统目录（$real）" ;;
  esac
  if [ -n "$PREFIX_NORM" ]; then
    local preal
    preal="$(realpath -m -- "$PREFIX_NORM")"
    case "$real" in
      "$preal"/*) : ;;
      *) die "safe_rm_rf: $real 不在卸载前缀 $preal 之下，拒绝删除" ;;
    esac
  fi
  if [ -e "$real" ] || [ -L "$real" ]; then
    rm -rf -- "$real"
    info "已删除：$real"
  fi
}

rm_file() {
  local f="$1"
  if [ -e "$f" ] || [ -L "$f" ]; then
    rm -f -- "$f"
    info "已删除：$f"
  fi
}

has_systemd() {
  [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

check_environment() {
  [ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo bash $0 ...）"
  command -v realpath >/dev/null 2>&1 || die "缺少 realpath（coreutils）"
  command -v stat >/dev/null 2>&1 || die "缺少 stat（coreutils）"
}

verify_staging_prefix() {
  [ -n "$PREFIX_NORM" ] || return 0
  local marker="$ETC_DIR/.mailstack-installed"
  local binary="$BIN_DIR/mailstackd"
  if [ -e "$marker" ] || [ -e "$binary" ] || [ -e "$LIBEXEC_DIR/$WRAPPER_NAME" ]; then
    info "staging 前缀校验通过：$PREFIX_NORM（存在 MailStack 安装痕迹）"
    return 0
  fi
  die "拒绝卸载：$PREFIX_NORM 下找不到 MailStack 安装痕迹（缺 $marker / $binary）。
      --prefix 只用于卸载 install.sh 装出来的 staging 安装；真实安装在 /（不给 --prefix）。"
}

confirm_or_abort() {
  [ "$NON_INTERACTIVE" -eq 1 ] && return 0
  [ -t 0 ] || return 0
  local answer=""
  printf '确认卸载 MailStack（前缀 %s）？[y/N] ' "${PREFIX_NORM:-/}" >&2
  IFS= read -r answer || answer=""
  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    y|yes) return 0 ;;
    *) die "已取消" ;;
  esac
}

stop_services() {
  say "停止并禁用 systemd unit"
  if [ -n "$PREFIX_NORM" ]; then
    info "staging 前缀：跳过宿主 systemd 操作（unit 文件在下一步直接删除）"
    return 0
  fi
  if ! has_systemd; then
    warn "未检测到运行中的 systemd：跳过 systemctl（可能存在手工启动的进程，注意检查）"
    return 0
  fi
  local unit
  for unit in "${UNIT_NAMES[@]}"; do
    systemctl stop "$unit" >/dev/null 2>&1 && info "已停止：$unit" || true
    systemctl disable "$unit" >/dev/null 2>&1 && info "已禁用：$unit" || true
  done
  systemctl daemon-reload >/dev/null 2>&1 || warn "systemctl daemon-reload 失败（unit 文件将删除，可稍后手工重跑）"
}

remove_install_files() {
  say "删除安装文件"
  local name unit
  for unit in "${UNIT_NAMES[@]}"; do
    rm_file "$UNIT_DIR/${unit}.service"
  done
  for name in "${BIN_NAMES[@]}"; do
    rm_file "$BIN_DIR/$name"
  done
  rm_file "$LIBEXEC_DIR/$WRAPPER_NAME"
  rm_file "$LIBEXEC_DIR/mailstack-uninstall"
  rm_file "$ETC_DIR/sudoers.d/$SUDOERS_NAME"
  if [ -d "$DIST_DIR" ]; then
    safe_rm_rf "$DIST_DIR"
  fi
  local share_dir
  share_dir="$(prefix_path /usr/share/mailstack)"
  if [ -d "$share_dir" ] && [ -z "$(ls -A "$share_dir" 2>/dev/null)" ]; then
    safe_rm_rf "$share_dir"
  fi
  if [ -d "$RUN_DIR" ]; then
    safe_rm_rf "$RUN_DIR"
  fi
  rm_file "$ETC_DIR/.mailstack-installed"
}

keep_or_purge_data() {
  if [ "$PURGE" -eq 1 ]; then
    say "删除配置与数据（--purge）"
    if [ -d "$ETC_DIR" ]; then
      safe_rm_rf "$ETC_DIR"
    fi
    if [ -d "$VAR_LIB_DIR" ]; then
      safe_rm_rf "$VAR_LIB_DIR"
    fi
    if [ -d "$BACKUP_DIR" ]; then
      safe_rm_rf "$BACKUP_DIR"
    fi
    info "配置与数据已删除（管理员凭证、身份、队列、备份不可恢复）"
    return 0
  fi

  say "保留配置与数据（默认；--purge 才删除）"
  local kept=0 p
  for p in "$ETC_DIR" "$VAR_LIB_DIR" "$BACKUP_DIR"; do
    if [ -d "$p" ]; then
      stat -c '    %a %U:%G %n' "$p"
      kept=$((kept + 1))
    fi
  done
  if [ "$kept" -eq 0 ]; then
    info "（以上目录不存在，无需保留）"
  else
    info "以上 ${kept} 个目录已保留。确认不再需要后可用 --purge 删除。"
    info "手工删除命令（危险）：rm -rf $ETC_DIR $VAR_LIB_DIR $BACKUP_DIR"
  fi
}

report_accounts() {
  say "系统账号与组（默认保留）"
  local u g found=0
  for u in mailstack-admin; do
    if getent passwd "$u" >/dev/null 2>&1; then
      info "保留用户：$u"
      found=$((found + 1))
    fi
  done
  for g in mailstack-admin mailstack-webmail opendkim; do
    if getent group "$g" >/dev/null 2>&1; then
      info "保留组：$g"
      found=$((found + 1))
    fi
  done
  if [ "$found" -eq 0 ]; then
    info "（未发现 MailStack 账号/组）"
  else
    info "如需彻底清理：userdel mailstack-admin; groupdel mailstack-webmail; groupdel mailstack-admin; groupdel opendkim"
  fi
}

check_leftover_processes() {
  if command -v pgrep >/dev/null 2>&1; then
    local left
    left="$(pgrep -af "${BIN_DIR}/(mailstackd|mailstack-web|mailstack-imap|mailstack-webmail)" 2>/dev/null || true)"
    if [ -n "$left" ]; then
      warn "仍有 MailStack 进程在运行（可能是手工启动的）："
      printf '%s\n' "$left" | sed 's/^/    /'
      warn "需要的话手工 kill 后再确认端口/数据不再被占用。"
    fi
  fi
}

print_summary() {
  say "卸载完成（MailStack v${MAILSTACK_VERSION}）"
  printf '    已移除: unit / 特权包装器 / sudoers 规则 / 5 个二进制 / 前端产物 / 运行时目录（前缀 %s）\n' "${PREFIX_NORM:-/}"
  if [ "$PURGE" -eq 1 ]; then
    printf '    数据:   已按 --purge 删除\n'
  else
    printf '    数据:   已保留（%s、%s、%s）\n' "$ETC_DIR" "$VAR_LIB_DIR" "$BACKUP_DIR"
  fi
  printf '    重装:   sudo bash deploy/install.sh（会复用保留的配置与数据）\n'
}

main() {
  if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
  fi

  parse_args "$@"
  normalize_prefix
  derive_paths
  check_environment
  verify_staging_prefix
  confirm_or_abort

  stop_services
  remove_install_files
  keep_or_purge_data
  report_accounts
  check_leftover_processes
  print_summary
}

main "$@"

#!/usr/bin/env bash
# MailStack uninstaller.
#
#   sudo bash deploy/uninstall.sh [--prefix DIR] [--purge] [--yes]
#
# Default: stop/disable units, remove binaries/wrapper/sudoers/units/frontend/
# manage script and generated access configs; keep /etc/mailstack, /var/lib/mailstack
# and /var/backups/mailstack. --purge also deletes those directories.
# Staging prefixes must look like a MailStack install before anything is removed.

set -Eeuo pipefail
umask 022

VERSION="1.0.0"
BIN_NAMES=(mailstackd mailstackctl mailstack-web mailstack-imap mailstack-webmail)
UNIT_NAMES=(mailstackd mailstack-web mailstack-imap mailstack-webmail)
WRAPPER_NAME="mailstack-privileged"
SUDOERS_NAME="mailstack-admin"
MANAGE_NAME="mailstack-manage"

PREFIX="/"
PREFIX_NORM=""
PURGE=0
ASSUME_YES=0

ETC_DIR=""
VAR_LIB_DIR=""
BACKUP_DIR=""
RUN_DIR=""
BIN_DIR=""
LIBEXEC_DIR=""
DIST_DIR=""
UNIT_DIR=""
SUDOERS_DIR=""

C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""

setup_colors() {
  if [ -z "${NO_COLOR:-}" ] && [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
  fi
}

say()  { printf '\n%s==> %s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%sWARN: %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
die()  { printf '\n%sERROR: %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }

on_err() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 141 ]; then
    printf '\n%sERROR: 卸载失败（第 %s 行，退出码 %s）%s\n' "$C_RED" "${BASH_LINENO[0]:-?}" "$rc" "$C_RESET" >&2
  fi
  exit "$rc"
}
trap on_err ERR

usage() {
  cat <<EOF
MailStack v${VERSION} 卸载脚本

用法:
  sudo bash deploy/uninstall.sh [选项]

选项:
  --prefix DIR      只卸载 DIR 下的 staging 安装（默认 /）
  --purge           连 /etc/mailstack、/var/lib/mailstack、/var/backups/mailstack 一起删除
  --yes/-y          不交互确认
  -h, --help        帮助
  --version         版本

默认保留: /etc/mailstack（配置/管理员/身份/DKIM/证书）、/var/lib/mailstack（队列/注册表）、
          /var/backups/mailstack（备份）；邮件数据在用户家目录，始终不在卸载范围。
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --prefix)  [ "$#" -ge 2 ] || die "--prefix 需要目录"; PREFIX="$2"; shift 2 ;;
      --prefix=*) PREFIX="${1#*=}"; shift ;;
      --purge)   PURGE=1; shift ;;
      --yes|-y|--non-interactive) ASSUME_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --version) printf 'MailStack uninstaller %s\n' "$VERSION"; exit 0 ;;
      *) die "未知参数：$1（-h 查看用法）" ;;
    esac
  done
}

normalize_prefix() {
  [ -n "$PREFIX" ] || PREFIX="/"
  case "$PREFIX" in /*) : ;; *) die "--prefix 必须是绝对路径：$PREFIX" ;; esac
  while [ "$PREFIX" != "/" ] && [ "${PREFIX%/}" != "$PREFIX" ]; do PREFIX="${PREFIX%/}"; done
  if [ "$PREFIX" = "/" ]; then PREFIX_NORM=""; return 0; fi
  printf '%s' "$PREFIX" | grep -Eq '^/[A-Za-z0-9._/-]+$' || die "前缀字符不合法：$PREFIX"
  case "${PREFIX#/}" in */*) : ;; *) die "前缀至少两级：$PREFIX" ;; esac
  PREFIX_NORM="$PREFIX"
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
  SUDOERS_DIR="$(prefix_path /etc/sudoers.d)"
}

safe_rm_rf() {
  local target="$1" real preal
  [ -n "$target" ] || return 0
  case "$target" in /*) : ;; *) die "safe_rm_rf: 必须绝对路径" ;; esac
  real="$(realpath -m -- "$target")"
  case "$real" in
    /|/etc|/usr|/var|/bin|/sbin|/lib|/lib64|/boot|/home|/root|/opt|/srv|/mnt|/media|/run|/tmp|/dev|/proc|/sys)
      die "拒绝删除系统目录：$real" ;;
  esac
  if [ -n "$PREFIX_NORM" ]; then
    preal="$(realpath -m -- "$PREFIX_NORM")"
    case "$real" in "$preal"/*) : ;; *) die "路径不在前缀内：$real" ;; esac
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

systemd_live() { [ -z "$PREFIX_NORM" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

verify_staging_prefix() {
  [ -n "$PREFIX_NORM" ] || return 0
  local marker="$ETC_DIR/.mailstack-installed"
  if [ -e "$marker" ] || [ -e "$BIN_DIR/mailstackd" ] || [ -e "$LIBEXEC_DIR/$WRAPPER_NAME" ]; then
    info "staging 前缀校验通过：$PREFIX_NORM"
    return 0
  fi
  die "拒绝卸载：$PREFIX_NORM 下没有 MailStack 安装痕迹"
}

confirm_or_abort() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  [ -t 0 ] || return 0
  local answer=""
  printf '确认卸载 MailStack（前缀 %s%s）？[y/N] ' "${PREFIX_NORM:-/}" \
    "$([ "$PURGE" -eq 1 ] && echo '，删除配置与数据' || echo '，保留配置与数据')" >&2
  IFS= read -r answer || answer=""
  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    y|yes) return 0 ;;
    *) die "已取消" ;;
  esac
}

stop_services() {
  say "停止并禁用 systemd unit"
  if ! systemd_live; then
    info "staging/无 systemd：跳过 systemctl"
    return 0
  fi
  local unit
  for unit in "${UNIT_NAMES[@]}" mailstack-cloudflared; do
    systemctl stop "$unit" >/dev/null 2>&1 && info "已停止：$unit" || true
    systemctl disable "$unit" >/dev/null 2>&1 && info "已禁用：$unit" || true
  done
  systemctl daemon-reload >/dev/null 2>&1 || warn "daemon-reload 失败"
  return 0
}

remove_generated_proxy_files() {
  local f
  for f in "$(prefix_path /etc/caddy/mailstack.caddy)" \
           "$(prefix_path /etc/nginx/conf.d/mailstack-panel.conf)"; do
    if [ -f "$f" ] && grep -qF '由 mailstack-manage 生成' "$f" 2>/dev/null; then
      rm_file "$f"
    fi
  done
  local main
  main="$(prefix_path /etc/caddy/Caddyfile)"
  if [ -f "$main" ] && grep -qF 'import /etc/caddy/mailstack.caddy' "$main"; then
    sed -i '/import \/etc\/caddy\/mailstack.caddy/d' "$main" 2>/dev/null || true
    info "已从 $main 移除 mailstack import"
  fi
}

remove_install_files() {
  say "删除安装文件"
  local name unit
  for unit in "${UNIT_NAMES[@]}"; do
    rm_file "$UNIT_DIR/${unit}.service"
  done
  rm_file "$UNIT_DIR/mailstack-cloudflared.service"
  for name in "${BIN_NAMES[@]}" "$MANAGE_NAME"; do
    rm_file "$BIN_DIR/$name"
  done
  rm_file "$LIBEXEC_DIR/$WRAPPER_NAME"
  rm_file "$LIBEXEC_DIR/mailstack-uninstall"
  rm_file "$SUDOERS_DIR/$SUDOERS_NAME"
  remove_generated_proxy_files
  if [ -d "$DIST_DIR" ]; then safe_rm_rf "$DIST_DIR"; fi
  local share_dir
  share_dir="$(prefix_path /usr/share/mailstack)"
  if [ -d "$share_dir" ] && [ -z "$(ls -A "$share_dir" 2>/dev/null)" ]; then
    safe_rm_rf "$share_dir"
  fi
  [ -d "$RUN_DIR" ] && safe_rm_rf "$RUN_DIR"
  rm_file "$ETC_DIR/install.json"
  rm_file "$ETC_DIR/.mailstack-installed"
}

keep_or_purge_data() {
  if [ "$PURGE" -eq 1 ]; then
    say "删除配置与数据（--purge）"
    [ -d "$ETC_DIR" ] && safe_rm_rf "$ETC_DIR"
    [ -d "$VAR_LIB_DIR" ] && safe_rm_rf "$VAR_LIB_DIR"
    [ -d "$BACKUP_DIR" ] && safe_rm_rf "$BACKUP_DIR"
    info "配置与数据已删除（不可恢复）"
    return 0
  fi
  say "保留配置与数据（默认；--purge 才删除）"
  local kept=0 p
  for p in "$ETC_DIR" "$VAR_LIB_DIR" "$BACKUP_DIR"; do
    if [ -d "$p" ]; then
      stat -c '    %a %U:%G %n' "$p" 2>/dev/null || printf '    %s\n' "$p"
      kept=$((kept + 1))
    fi
  done
  [ "$kept" -gt 0 ] && info "以上目录已保留；确认不再需要后可用 --purge 删除"
  return 0
}

report_accounts() {
  say "系统账号与组（默认保留）"
  local u g found=0
  for u in mailstack-admin; do
    if getent passwd "$u" >/dev/null 2>&1; then info "保留用户：$u"; found=$((found + 1)); fi
  done
  for g in mailstack-admin mailstack-webmail opendkim; do
    if getent group "$g" >/dev/null 2>&1; then info "保留组：$g"; found=$((found + 1)); fi
  done
  [ "$found" -gt 0 ] && info "彻底清理：userdel mailstack-admin; groupdel mailstack-webmail; groupdel mailstack-admin; groupdel opendkim"
  return 0
}

check_leftover_processes() {
  command -v pgrep >/dev/null 2>&1 || return 0
  local left
  left="$(pgrep -af "${BIN_DIR}/(mailstackd|mailstack-web|mailstack-imap|mailstack-webmail)" 2>/dev/null || true)"
  if [ -n "$left" ]; then
    warn "仍有 MailStack 进程在运行（手工启动的？）："
    printf '%s\n' "$left" | sed 's/^/    /'
  fi
}

print_summary() {
  say "卸载完成（MailStack v${VERSION}）"
  printf '    前缀:   %s\n' "${PREFIX_NORM:-/}"
  printf '    已移除: unit / 特权包装器 / sudoers / 6 个二进制（含 manage）/ 前端产物 / 运行时目录\n'
  if [ "$PURGE" -eq 1 ]; then
    printf '    数据:   已按 --purge 删除\n'
  else
    printf '    数据:   已保留 %s、%s、%s\n' "$ETC_DIR" "$VAR_LIB_DIR" "$BACKUP_DIR"
  fi
  printf '    重装:   sudo bash deploy/install.sh（复用保留的配置与数据）\n'
}

main() {
  setup_colors
  parse_args "$@"
  normalize_prefix
  derive_paths
  [ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo bash $0 ...）"
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

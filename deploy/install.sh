#!/usr/bin/env bash
# MailStack installer (panel-style one-liner).
#
#   curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh \
#     | sudo bash -s -- --domain example.com --mail-host mail.example.com \
#         --admin-user admin --admin-password 'Passw0rd-9' \
#         --access-mode caddy --panel-host panel.example.com --acme-email ops@example.com
#
# Without arguments on a TTY it runs an interactive wizard. Non-interactive flags
# cover the whole install. Deployment state:
#   /etc/mailstack/install-args.conf  (mode.rs reads ACCESS_MODE)
#   /etc/mailstack/install.json       (installer metadata)
# Log: /var/log/mailstack-install.log (staging: <prefix>/var/log/...).

set -Eeuo pipefail
umask 022

VERSION="1.0.0"
REPO_SLUG="SectorPace/MailStack"
REPO_URL="https://github.com/${REPO_SLUG}"
RAW_BRANCH="main"
TARGET_TRIPLE="x86_64-unknown-linux-gnu"
TARBALL_NAME="mailstack-v${VERSION}-${TARGET_TRIPLE}.tar.gz"
RELEASE_BASE="${MAILSTACK_RELEASE_BASE_URL:-${REPO_URL}/releases/download/v${VERSION}}"
SOURCE_TARBALL_URL="${REPO_URL}/archive/refs/tags/v${VERSION}.tar.gz"
API_RELEASE_URL="https://api.github.com/repos/${REPO_SLUG}/releases/tags/v${VERSION}"
EXPECTED_RUST="1.98.1"

BIN_NAMES=(mailstackd mailstackctl mailstack-web mailstack-imap mailstack-webmail)
UNIT_NAMES=(mailstackd mailstack-web mailstack-imap mailstack-webmail)
WRAPPER_NAME="mailstack-privileged"
SUDOERS_NAME="mailstack-admin"
MANAGE_NAME="mailstack-manage"
ACCESS_MODES=(ssh caddy nginx ip-acme panel-domain cloudflared)
MAIL_PORTS=(25 465 587 143 993 110 995 4190)
WEB_PORTS=(80 443)

MODE="release"
ARCHIVE=""
BINARY_DIR=""
MIRROR=""
PREFIX="/"
DOMAIN=""
MAIL_HOST=""
ADMIN_USER="admin"
ADMIN_PASSWORD=""
ADMIN_PASSWORD_STDIN=0
ADMIN_PASSWORD_ARGV=0
ADMIN_PORT="8443"
WEBMAIL_PORT="8444"
PANEL_HOST=""
WEBMAIL_HOST=""
ACME_EMAIL=""
SERVER_IP=""
IMAP_ENABLE=1
NON_INTERACTIVE=0
NO_SYSTEMD=0
NO_ACCESS_PROVISION=0
NO_FIREWALL=0
ALLOW_UNSIGNED=0
ACCESS_MODE=""
ACCESS_MODE_GIVEN=0
ACTION="fresh"
ASSUME_YES=0
DRY_RUN=0
INTERACTIVE=0
UNINSTALL=0
PURGE=0

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
CHECKOUT_ROOT=""
PREFIX_NORM=""
TMP_DIRS=()
LOCK_DIR=""
LOG_FILE=""
SUDO_CMD=""
STDIN_IS_SCRIPT=0
PW_STDIN_MISSING=0
ADMIN_STATE="unknown"
IDENTITY_STATE="not-requested"
ACCESS_STATE="not-requested"
FIREWALL_STATE="skipped"

ETC_DIR=""
ACCESS_DIR=""
VAR_LIB_DIR=""
BACKUP_DIR=""
ROLLBACK_DIR=""
RUN_DIR=""
BIN_DIR=""
LIBEXEC_DIR=""
DIST_DIR=""
UNIT_DIR=""
SUDOERS_DIR=""
CONFIG_ARG=""
INSTALL_UNITS=()
BIN_SRC=""
UNIT_SRC=""
DIST_SRC=""
UNINSTALL_SRC=""
MANAGE_SRC=""

C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""

# ---------------------------------------------------------------------------
# output / logging
# ---------------------------------------------------------------------------

setup_colors() {
  if [ -z "${NO_COLOR:-}" ] && [ -t 2 ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_BOLD=$'\033[1m'
  fi
}

log_line() {
  local level="$1"; shift
  [ -n "$LOG_FILE" ] || return 0
  printf '%s %-5s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$*" >> "$LOG_FILE" 2>/dev/null || true
  return 0
}

say()  { log_line INFO "$*"; printf '\n%s==> %s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
info() { log_line INFO "$*"; printf '    %s\n' "$*"; }
warn() { log_line WARN "$*"; printf '%sWARN: %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
die()  { log_line ERROR "$*"; printf '\n%sERROR: %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }

cleanup() {
  local d
  for d in ${TMP_DIRS[@]+"${TMP_DIRS[@]}"}; do
    [ -n "$d" ] && rm -rf -- "$d"
  done
  if [ -n "$LOCK_DIR" ] && [ -d "$LOCK_DIR" ]; then
    rm -rf -- "$LOCK_DIR"
  fi
  return 0
}

on_err() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 141 ]; then
    log_line ERROR "install failed at line ${BASH_LINENO[0]:-?} (rc=$rc)"
    printf '\n%sERROR: 安装失败（第 %s 行，退出码 %s）%s\n' "$C_RED" "${BASH_LINENO[0]:-?}" "$rc" "$C_RESET" >&2
    [ -n "$LOG_FILE" ] && printf '    日志：%s\n' "$LOG_FILE" >&2
  fi
  exit "$rc"
}

trap cleanup EXIT
trap on_err ERR

need_cmd() { command -v "$1" >/dev/null 2>&1; }

new_tmp() {
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/mailstack-install.XXXXXXXX")" || die "无法创建临时目录"
  TMP_DIRS+=("$d")
  printf '%s' "$d"
}

is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/}"; s="${s//$'\r'/}"; s="${s//$'\t'/}"
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------

usage() {
  cat <<EOF
MailStack v${VERSION} 安装脚本（$TARGET_TRIPLE）

一行安装:
  curl -fsSL https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/install.sh \\
    | sudo bash -s -- --domain example.com --admin-user admin \\
        --admin-password 'Passw0rd-9' --access-mode caddy \\
        --panel-host panel.example.com --acme-email ops@example.com

无参数 + TTY 进入交互安装向导；全部选项均可非交互提供。

安装来源:
  (默认)                 GitHub Release tarball + SHA256SUMS 校验
  --archive FILE|URL     指定发布包（离线/镜像）
  --binary-dir DIR       预编译二进制目录（测试/离线旁路）
  --from-source          用 checkout 或源码包调用 deploy/build.sh 构建
  --mirror URL           发布包镜像根（也可用 MAILSTACK_RELEASE_MIRROR）

身份与端口:
  --domain DOMAIN        邮件主域名（写入 setup.json/域名表/状态）
  --mail-host HOST       邮件主机名（默认 mail.<domain>）
  --admin-user NAME      管理员用户名（默认 admin）
  --admin-password PW    管理员口令（argv 可见；优先 --admin-password-stdin）
  --admin-password-stdin 从 stdin 读一行口令
  --admin-port PORT      管理台端口（默认 8443，仅回环）
  --webmail-port PORT    Webmail 端口（默认 8444，仅回环）
  --imap yes|no          IMAP/POP3/ManageSieve unit（默认 yes）
  --server-ip IP         服务器 IP（缺省自动探测）
  --panel-host HOST      面板主机名（默认 panel.<domain>，不得与邮件主机同名）
  --webmail-host HOST    Webmail 主机名（默认 webmail.<domain>）
  --acme-email EMAIL     ACME 账户邮箱

访问模式（默认 ssh；旧值 local/caddy/direct 也接受）:
  ssh caddy nginx ip-acme panel-domain cloudflared
  --no-access-provision  只写状态，不生成反代/Tunnel 文件

运行控制:
  --prefix DIR           安装到 DIR 下（staging；不操作宿主 systemd）
  --upgrade              升级：保留状态/数据，替换程序文件，健康检查失败自动回滚
  --repair               修复：只替换程序文件
  --uninstall [--purge]  转交 uninstall.sh（--purge 删除配置/数据）
  --non-interactive      不交互
  --yes / --force        自动确认（防火墙、升级/卸载确认）
  --no-systemd           只写 unit 不 enable/start（容器）
  --no-firewall          不改防火墙
  --allow-unsigned       无 SHA256SUMS 时允许安装（默认拒绝）
  --dry-run              只校验并打印计划，不改系统
  -h, --help             帮助
  --version              安装器版本

安装后:
  sudo mailstack-manage                 # 面板式管理菜单
  sudo mailstack-manage status          # 或 status --json
EOF
}

# ---------------------------------------------------------------------------
# access mode helpers
# ---------------------------------------------------------------------------

normalize_access_mode() {
  local m
  m="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$m" in
    ssh|local|loopback)             printf 'ssh' ;;
    caddy)                          printf 'caddy' ;;
    nginx)                          printf 'nginx' ;;
    ip-acme|ip_acme|ipacme|direct)  printf 'ip-acme' ;;
    panel-domain|panel_domain)      printf 'panel-domain' ;;
    cloudflared|cloudflare)         printf 'cloudflared' ;;
    *) return 1 ;;
  esac
}

canonical_access_mode() {
  case "$1" in
    ssh)                                  printf 'local' ;;
    caddy|nginx|panel-domain|cloudflared) printf 'caddy' ;;
    ip-acme)                              printf 'direct' ;;
    local)                                printf 'local' ;;
    caddy)                                printf 'caddy' ;;
    direct)                               printf 'direct' ;;
    *)                                    printf 'local' ;;
  esac
}

mode_from_state() {
  local conf="$ETC_DIR/install-args.conf"
  local detail=""
  local canonical=""
  [ -s "$conf" ] || return 0
  detail="$(state_get "$conf" ACCESS_MODE_DETAIL || true)"
  if [ -n "$detail" ]; then
    normalize_access_mode "$detail" && return 0
  fi
  canonical="$(state_get "$conf" ACCESS_MODE || true)"
  case "$canonical" in
    local|"") printf 'ssh' ;;
    caddy)    printf 'caddy' ;;
    direct)   printf 'ip-acme' ;;
  esac
}

state_get() {
  local conf="$1"
  local key="$2"
  local raw=""
  raw="$(sed -n "s/^${key}=//p" "$conf" 2>/dev/null | head -1)"
  [ -n "$raw" ] || return 1
  case "$raw" in
    \'*\') raw="${raw#\'}"; raw="${raw%\'}" ;;
    \"*\") raw="${raw#\"}"; raw="${raw%\"}" ;;
  esac
  printf '%s' "$raw"
}

valid_hostname() {
  printf '%s' "${1:-}" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
}

valid_ipv4() {
  printf '%s' "${1:-}" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
  local IFS='.' octet
  for octet in $1; do
    [ "$octet" -ge 0 ] 2>/dev/null && [ "$octet" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

valid_email() {
  printf '%s' "${1:-}" | grep -Eq '^[A-Za-z0-9._%+-]+@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
}

detect_server_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null \
      | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}' || true)"
  fi
  if [ -z "$ip" ]; then
    ip="$(hostname -I 2>/dev/null \
      | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit }}' || true)"
  fi
  printf '%s' "$ip"
  return 0
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

read_password_stdin() {
  if [ "$STDIN_IS_SCRIPT" -eq 1 ]; then
    [ -n "${MAILSTACK_ADMIN_PASSWORD:-}" ] || PW_STDIN_MISSING=1
    ADMIN_PASSWORD="${MAILSTACK_ADMIN_PASSWORD:-}"
    return 0
  fi
  local value=""
  IFS= read -r value || value=""
  value="${value%$'\r'}"
  [ -n "$value" ] || value="${MAILSTACK_ADMIN_PASSWORD:-}"
  [ -n "$value" ] || die "未能从 stdin 读到口令（--admin-password-stdin）；可用 MAILSTACK_ADMIN_PASSWORD"
  ADMIN_PASSWORD="$value"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --from-source)          MODE="source"; shift ;;
      --archive)              [ "$#" -ge 2 ] || die "--archive 需要参数"; MODE="archive"; ARCHIVE="$2"; shift 2 ;;
      --archive=*)            MODE="archive"; ARCHIVE="${1#*=}"; shift ;;
      --binary-dir)           [ "$#" -ge 2 ] || die "--binary-dir 需要目录"; MODE="binary-dir"; BINARY_DIR="$2"; shift 2 ;;
      --binary-dir=*)         MODE="binary-dir"; BINARY_DIR="${1#*=}"; shift ;;
      --mirror)               [ "$#" -ge 2 ] || die "--mirror 需要 URL"; MIRROR="$2"; shift 2 ;;
      --mirror=*)             MIRROR="${1#*=}"; shift ;;
      --prefix)               [ "$#" -ge 2 ] || die "--prefix 需要目录"; PREFIX="$2"; shift 2 ;;
      --prefix=*)             PREFIX="${1#*=}"; shift ;;
      --domain)               [ "$#" -ge 2 ] || die "--domain 需要参数"; DOMAIN="$2"; shift 2 ;;
      --domain=*)             DOMAIN="${1#*=}"; shift ;;
      --mail-host)            [ "$#" -ge 2 ] || die "--mail-host 需要参数"; MAIL_HOST="$2"; shift 2 ;;
      --mail-host=*)          MAIL_HOST="${1#*=}"; shift ;;
      --admin-user)           [ "$#" -ge 2 ] || die "--admin-user 需要参数"; ADMIN_USER="$2"; shift 2 ;;
      --admin-user=*)         ADMIN_USER="${1#*=}"; shift ;;
      --admin-password)       [ "$#" -ge 2 ] || die "--admin-password 需要参数"; ADMIN_PASSWORD="$2"; ADMIN_PASSWORD_ARGV=1; shift 2 ;;
      --admin-password=*)     ADMIN_PASSWORD="${1#*=}"; ADMIN_PASSWORD_ARGV=1; shift ;;
      --admin-password-stdin) ADMIN_PASSWORD_STDIN=1; read_password_stdin; shift ;;
      --admin-port)           [ "$#" -ge 2 ] || die "--admin-port 需要参数"; ADMIN_PORT="$2"; shift 2 ;;
      --admin-port=*)         ADMIN_PORT="${1#*=}"; shift ;;
      --webmail-port)         [ "$#" -ge 2 ] || die "--webmail-port 需要参数"; WEBMAIL_PORT="$2"; shift 2 ;;
      --webmail-port=*)       WEBMAIL_PORT="${1#*=}"; shift ;;
      --panel-host)           [ "$#" -ge 2 ] || die "--panel-host 需要参数"; PANEL_HOST="$2"; shift 2 ;;
      --panel-host=*)         PANEL_HOST="${1#*=}"; shift ;;
      --webmail-host)         [ "$#" -ge 2 ] || die "--webmail-host 需要参数"; WEBMAIL_HOST="$2"; shift 2 ;;
      --webmail-host=*)       WEBMAIL_HOST="${1#*=}"; shift ;;
      --acme-email)           [ "$#" -ge 2 ] || die "--acme-email 需要参数"; ACME_EMAIL="$2"; shift 2 ;;
      --acme-email=*)         ACME_EMAIL="${1#*=}"; shift ;;
      --server-ip)            [ "$#" -ge 2 ] || die "--server-ip 需要参数"; SERVER_IP="$2"; shift 2 ;;
      --server-ip=*)          SERVER_IP="${1#*=}"; shift ;;
      --imap)
        [ "$#" -ge 2 ] || die "--imap 需要 yes|no"
        case "$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')" in
          yes|true|1|enable|on)   IMAP_ENABLE=1 ;;
          no|false|0|disable|off) IMAP_ENABLE=0 ;;
          *) die "--imap 只接受 yes|no（实际：$2）" ;;
        esac
        shift 2 ;;
      --imap=*)
        case "$(printf '%s' "${1#*=}" | tr '[:upper:]' '[:lower:]')" in
          yes|true|1|enable|on)   IMAP_ENABLE=1 ;;
          no|false|0|disable|off) IMAP_ENABLE=0 ;;
          *) die "--imap 只接受 yes|no（实际：${1#*=}）" ;;
        esac
        shift ;;
      --access-mode)          [ "$#" -ge 2 ] || die "--access-mode 需要模式"; ACCESS_MODE="$2"; ACCESS_MODE_GIVEN=1; shift 2 ;;
      --access-mode=*)        ACCESS_MODE="${1#*=}"; ACCESS_MODE_GIVEN=1; shift ;;
      --no-access-provision)  NO_ACCESS_PROVISION=1; shift ;;
      --no-firewall)          NO_FIREWALL=1; shift ;;
      --allow-unsigned)       ALLOW_UNSIGNED=1; shift ;;
      --interactive)          INTERACTIVE=1; shift ;;
      --upgrade)              ACTION="upgrade"; shift ;;
      --repair)               ACTION="repair"; shift ;;
      --dry-run)              DRY_RUN=1; shift ;;
      --non-interactive)      NON_INTERACTIVE=1; shift ;;
      --yes|-y|--force)       ASSUME_YES=1; shift ;;
      --no-systemd)           NO_SYSTEMD=1; shift ;;
      --uninstall)            UNINSTALL=1; shift ;;
      --purge)                PURGE=1; shift ;;
      -h|--help)              usage; exit 0 ;;
      --version)              printf 'MailStack installer %s (target %s)\n' "$VERSION" "$TARGET_TRIPLE"; exit 0 ;;
      *) die "未知参数：$1（-h 查看用法）" ;;
    esac
  done
}

validate_options() {
  if [ "$PW_STDIN_MISSING" -eq 1 ]; then
    die "curl|bash 管道下 stdin 是脚本本身，不能 --admin-password-stdin；改用 --admin-password 或 MAILSTACK_ADMIN_PASSWORD"
  fi
  [ "$ADMIN_PASSWORD_STDIN" -eq 1 ] && [ "$ADMIN_PASSWORD_ARGV" -eq 1 ] \
    && die "--admin-password 与 --admin-password-stdin 只能选一个"
  if [ -z "$ADMIN_PASSWORD" ] && [ -n "${MAILSTACK_ADMIN_PASSWORD:-}" ]; then
    ADMIN_PASSWORD="$MAILSTACK_ADMIN_PASSWORD"
  fi
  [ "$ADMIN_PASSWORD_ARGV" -eq 1 ] && warn "--admin-password 会经 argv 暴露；生产建议 --admin-password-stdin"

  [ -n "$ARCHIVE" ] && [ -n "$BINARY_DIR" ] && die "--archive 与 --binary-dir 只能选一个"
  [ "$UNINSTALL" -eq 0 ] && [ "$PURGE" -eq 1 ] && die "--purge 只能与 --uninstall 一起使用"
  [ "$ACTION" != "fresh" ] && [ "$UNINSTALL" -eq 1 ] && die "--uninstall 不能与 --upgrade/--repair 同时使用"
  [ -n "$MIRROR" ] && printf '%s' "$MIRROR" | grep -Eq '^https?://' || [ -z "$MIRROR" ] \
    || die "--mirror 需要 http(s) URL：$MIRROR"

  is_uint "$ADMIN_PORT" || die "--admin-port 必须是整数：$ADMIN_PORT"
  is_uint "$WEBMAIL_PORT" || die "--webmail-port 必须是整数：$WEBMAIL_PORT"
  [ "$ADMIN_PORT" -ge 1 ] && [ "$ADMIN_PORT" -le 65535 ] || die "--admin-port 越界：$ADMIN_PORT"
  [ "$WEBMAIL_PORT" -ge 1 ] && [ "$WEBMAIL_PORT" -le 65535 ] || die "--webmail-port 越界：$WEBMAIL_PORT"
  [ "$ADMIN_PORT" != "$WEBMAIL_PORT" ] || die "管理台端口与 Webmail 端口不能相同"

  printf '%s' "$ADMIN_USER" | grep -Eq '^[A-Za-z][A-Za-z0-9_.-]{2,31}$' \
    || die "管理员用户名非法（3-32 字符，字母开头）：$ADMIN_USER"

  if [ -n "$DOMAIN" ]; then
    valid_hostname "$DOMAIN" || die "域名非法：$DOMAIN"
    [ -n "$MAIL_HOST" ] || MAIL_HOST="mail.$DOMAIN"
  fi
  [ -n "$MAIL_HOST" ] && { valid_hostname "$MAIL_HOST" || die "邮件主机名非法：$MAIL_HOST"; }
  [ -n "$PANEL_HOST" ] && { valid_hostname "$PANEL_HOST" || die "面板主机名非法：$PANEL_HOST"; }
  [ -n "$WEBMAIL_HOST" ] && { valid_hostname "$WEBMAIL_HOST" || die "Webmail 主机名非法：$WEBMAIL_HOST"; }
  [ -n "$ACME_EMAIL" ] && { valid_email "$ACME_EMAIL" || die "ACME 邮箱非法：$ACME_EMAIL"; }
  [ -n "$SERVER_IP" ] && { valid_ipv4 "$SERVER_IP" || die "服务器 IP 非法：$SERVER_IP"; }

  if [ "$ACCESS_MODE_GIVEN" -eq 1 ]; then
    local requested="$ACCESS_MODE"
    ACCESS_MODE="$(normalize_access_mode "$requested")" || die "未知访问模式：$requested"
  else
    ACCESS_MODE="$(mode_from_state)"
    [ -n "$ACCESS_MODE" ] || ACCESS_MODE="ssh"
  fi

  if [ "$ACCESS_MODE" != "ssh" ]; then
    if [ -z "$PANEL_HOST" ]; then
      [ -n "$DOMAIN" ] || die "访问模式 $ACCESS_MODE 需要 --panel-host（或 --domain）"
      PANEL_HOST="panel.$DOMAIN"
    fi
    if [ -z "$WEBMAIL_HOST" ]; then
      [ -n "$DOMAIN" ] || die "访问模式 $ACCESS_MODE 需要 --webmail-host（或 --domain）"
      WEBMAIL_HOST="webmail.$DOMAIN"
    fi
    local h
    for h in "$DOMAIN" "$MAIL_HOST" "mail.$DOMAIN" "imap.$DOMAIN" "smtp.$DOMAIN" "pop.$DOMAIN"; do
      [ -n "$h" ] || continue
      [ "$PANEL_HOST" != "$h" ] || die "面板主机不能与邮件主机同名：$PANEL_HOST"
      [ "$WEBMAIL_HOST" != "$h" ] || die "Webmail 主机不能与邮件主机同名：$WEBMAIL_HOST"
    done
    [ "$PANEL_HOST" != "$WEBMAIL_HOST" ] || die "面板主机与 Webmail 主机不能相同"
  fi

  if [ -n "$ADMIN_PASSWORD" ]; then
    printf '%s' "$ADMIN_PASSWORD" | LC_ALL=C grep -q '[[:cntrl:]]' && die "口令不得包含控制字符"
    local plen=${#ADMIN_PASSWORD}
    [ "$plen" -ge 12 ] && [ "$plen" -le 256 ] || die "口令长度必须 12-256（实际 $plen）"
    printf '%s' "$ADMIN_PASSWORD" | grep -q '[A-Za-z]' || die "口令必须包含字母"
    printf '%s' "$ADMIN_PASSWORD" | grep -q '[0-9]' || die "口令必须包含数字"
    local lowered passlower
    lowered="$(printf '%s' "$ADMIN_USER" | tr '[:upper:]' '[:lower:]')"
    passlower="$(printf '%s' "$ADMIN_PASSWORD" | tr '[:upper:]' '[:lower:]')"
    case "$passlower" in *"$lowered"*) die "口令不得包含用户名" ;; esac
  fi
}

# ---------------------------------------------------------------------------
# interactive wizard
# ---------------------------------------------------------------------------

wizard_prompt() {
  local prompt="$1"
  local default="${2:-}"
  local value=""
  printf '%s' "$prompt" >&2
  IFS= read -r value || value=""
  [ -n "$value" ] || value="$default"
  printf '%s' "$value"
}

wizard_confirm() {
  local prompt="$1"
  local answer=""
  printf '%s [Y/n] ' "$prompt" >&2
  IFS= read -r answer || answer=""
  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    ""|y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

interactive_wizard() {
  [ -t 0 ] || die "交互向导需要 TTY；非交互安装请传 --domain/--admin-password 等参数"
  echo
  printf '%sMailStack v%s 安装向导%s\n' "$C_BOLD" "$VERSION" "$C_RESET"
  echo '  Ctrl-C 随时退出（清理临时文件）'
  echo

  echo '安装来源:'
  echo '  1) GitHub Release（默认，SHA256 校验）'
  echo '  2) 本地/URL 发布包（--archive）'
  echo '  3) 预编译二进制目录（--binary-dir）'
  echo '  4) 源码构建（--from-source，需要 Rust 工具链）'
  local source_choice
  source_choice="$(wizard_prompt '选择 [1]: ' 1)"
  case "$source_choice" in
    1) MODE="release" ;;
    2) MODE="archive"; ARCHIVE="$(wizard_prompt '发布包路径或 URL: ')"; [ -n "$ARCHIVE" ] || die "发布包不能为空" ;;
    3) MODE="binary-dir"; BINARY_DIR="$(wizard_prompt '二进制目录: ')"; [ -n "$BINARY_DIR" ] || die "目录不能为空" ;;
    4) MODE="source" ;;
    *) die "无效选择：$source_choice" ;;
  esac

  while :; do
    DOMAIN="$(wizard_prompt '邮件主域名（例 example.com，必填）: ' "$DOMAIN")"
    if [ -n "$DOMAIN" ] && valid_hostname "$DOMAIN"; then break; fi
    warn "域名非法：${DOMAIN:-<空>}"
  done
  MAIL_HOST="$(wizard_prompt "邮件主机名 [mail.$DOMAIN]: " "${MAIL_HOST:-mail.$DOMAIN}")"
  valid_hostname "$MAIL_HOST" || die "邮件主机名非法：$MAIL_HOST"

  ADMIN_USER="$(wizard_prompt "管理员用户名 [admin]: " "$ADMIN_USER")"
  while :; do
    if valid_ok_admin_user "$ADMIN_USER"; then break; fi
    warn "用户名非法（3-32 字符，字母开头）"
    ADMIN_USER="$(wizard_prompt '管理员用户名: ' admin)"
  done

  while :; do
    local pw1=""
    local pw2=""
    printf '管理员口令（12-256 位，含字母与数字）: ' >&2
    IFS= read -r -s pw1 || pw1=""
    printf '\n再次输入: ' >&2
    IFS= read -r -s pw2 || pw2=""
    printf '\n' >&2
    [ "$pw1" = "$pw2" ] || { warn "两次输入不一致"; continue; }
    ADMIN_PASSWORD="$pw1"
    ADMIN_PASSWORD_ARGV=0
    if password_policy_ok "$ADMIN_PASSWORD" "$ADMIN_USER"; then break; fi
    warn "口令不满足策略，请重试"
  done

  ADMIN_PORT="$(wizard_prompt "管理台端口 [8443]: " "$ADMIN_PORT")"
  WEBMAIL_PORT="$(wizard_prompt "Webmail 端口 [8444]: " "$WEBMAIL_PORT")"
  local imap_answer
  imap_answer="$(wizard_prompt '安装 IMAP/POP3/ManageSieve? [Y/n]: ' y)"
  case "$(printf '%s' "$imap_answer" | tr '[:upper:]' '[:lower:]')" in
    n|no) IMAP_ENABLE=0 ;;
    *)    IMAP_ENABLE=1 ;;
  esac

  echo
  echo '访问模式:'
  printf '  1) ssh（默认，回环+SSH 隧道）\n  2) caddy（自动 HTTPS）\n  3) nginx\n'
  printf '  4) ip-acme（公网 IP + ACME）\n  5) panel-domain（独立面板域名）\n  6) cloudflared\n'
  local mode_choice mode_name
  mode_choice="$(wizard_prompt '选择 [1]: ' 1)"
  case "$mode_choice" in
    1) mode_name="ssh" ;;
    2) mode_name="caddy" ;;
    3) mode_name="nginx" ;;
    4) mode_name="ip-acme" ;;
    5) mode_name="panel-domain" ;;
    6) mode_name="cloudflared" ;;
    *) die "无效选择：$mode_choice" ;;
  esac
  ACCESS_MODE="$mode_name"
  ACCESS_MODE_GIVEN=1
  if [ "$mode_name" != "ssh" ]; then
    PANEL_HOST="$(wizard_prompt "面板主机名 [panel.$DOMAIN]: " "panel.$DOMAIN")"
    WEBMAIL_HOST="$(wizard_prompt "Webmail 主机名 [webmail.$DOMAIN]: " "webmail.$DOMAIN")"
    ACME_EMAIL="$(wizard_prompt 'ACME 账户邮箱（可留空）: ' "$ACME_EMAIL")"
    SERVER_IP="$(wizard_prompt '服务器公网 IP（留空自动探测）: ' "$SERVER_IP")"
  fi
  if ! wizard_confirm '配置防火墙（ufw/firewalld）放行邮件与 Web 端口?'; then
    NO_FIREWALL=1
  fi

  echo
  echo '安装摘要:'
  printf '  来源:     %s\n  域名:     %s\n  邮件主机: %s\n  管理员:   %s\n' "$MODE" "$DOMAIN" "$MAIL_HOST" "$ADMIN_USER"
  printf '  端口:     管理台 %s / Webmail %s / IMAP %s\n' "$ADMIN_PORT" "$WEBMAIL_PORT" "$([ "$IMAP_ENABLE" -eq 1 ] && echo yes || echo no)"
  printf '  访问模式: %s%s\n' "$ACCESS_MODE" "${PANEL_HOST:+（面板 $PANEL_HOST）}"
  printf '  前缀:     %s\n' "${PREFIX:-/}"
  wizard_confirm '开始安装?' || die "已取消"
  NON_INTERACTIVE=1
}

password_policy_ok() {
  local password="$1"
  local user="$2"
  local plen=${#password}
  [ "$plen" -ge 12 ] && [ "$plen" -le 256 ] || return 1
  printf '%s' "$password" | grep -q '[A-Za-z]' || return 1
  printf '%s' "$password" | grep -q '[0-9]' || return 1
  printf '%s' "$password" | LC_ALL=C grep -q '[[:cntrl:]]' && return 1
  case "$(printf '%s' "$password" | tr '[:upper:]' '[:lower:]')" in
    *"$(printf '%s' "$user" | tr '[:upper:]' '[:lower:]')"*) return 1 ;;
  esac
  return 0
}

valid_ok_admin_user() { printf '%s' "${1:-}" | grep -Eq '^[A-Za-z][A-Za-z0-9_.-]{2,31}$'; }

# ---------------------------------------------------------------------------
# prefix / paths / lock / logging
# ---------------------------------------------------------------------------

normalize_prefix() {
  [ -n "$PREFIX" ] || PREFIX="/"
  case "$PREFIX" in /*) : ;; *) die "--prefix 必须是绝对路径：$PREFIX" ;; esac
  while [ "$PREFIX" != "/" ] && [ "${PREFIX%/}" != "$PREFIX" ]; do PREFIX="${PREFIX%/}"; done
  if [ "$PREFIX" = "/" ]; then
    PREFIX_NORM=""
    return 0
  fi
  printf '%s' "$PREFIX" | grep -Eq '^/[A-Za-z0-9._/-]+$' || die "--prefix 字符不合法：$PREFIX"
  case "/$PREFIX/" in *"/../"*) die "--prefix 不得包含 .. 段：$PREFIX" ;; esac
  PREFIX="$(realpath -m -- "$PREFIX")" || die "--prefix 规范化失败：$PREFIX"
  case "$PREFIX" in
    /|/etc|/usr|/var|/bin|/sbin|/lib|/lib64|/boot|/home|/root|/opt|/srv|/mnt|/media|/run|/tmp|/dev|/proc|/sys)
      die "拒绝把 --prefix 指向系统目录：$PREFIX" ;;
  esac
  case "${PREFIX#/}" in
    */*) : ;;
    *) die "--prefix 至少两级（例 /tmp/mailstack-stage）" ;;
  esac
  PREFIX_NORM="$PREFIX"
}

prefix_path() { printf '%s%s' "$PREFIX_NORM" "$1"; }

derive_paths() {
  ETC_DIR="$(prefix_path /etc/mailstack)"
  ACCESS_DIR="$ETC_DIR/access"
  VAR_LIB_DIR="$(prefix_path /var/lib/mailstack)"
  BACKUP_DIR="$(prefix_path /var/backups/mailstack)"
  ROLLBACK_DIR="$ETC_DIR/rollback"
  RUN_DIR="$(prefix_path /run/mailstack)"
  BIN_DIR="$(prefix_path /usr/local/bin)"
  LIBEXEC_DIR="$(prefix_path /usr/local/libexec)"
  DIST_DIR="$(prefix_path /usr/share/mailstack/admin)"
  UNIT_DIR="$(prefix_path /etc/systemd/system)"
  SUDOERS_DIR="$(prefix_path /etc/sudoers.d)"
  [ -n "$PREFIX_NORM" ] && CONFIG_ARG=" --config-dir ${PREFIX_NORM}" || CONFIG_ARG=""
  LOG_FILE="$(prefix_path /var/log/mailstack-install.log)"
  LOCK_DIR="$(prefix_path /run/lock)/mailstack-install.lock"
  INSTALL_UNITS=(mailstackd mailstack-web mailstack-webmail)
  [ "$IMAP_ENABLE" -eq 1 ] && INSTALL_UNITS+=(mailstack-imap)
  return 0
}

init_logging() {
  mkdir -p "$(dirname -- "$LOG_FILE")" 2>/dev/null || true
  : >> "$LOG_FILE" 2>/dev/null || warn "无法写日志：$LOG_FILE"
  chmod 0600 "$LOG_FILE" 2>/dev/null || true
  log_line INFO "installer start (version=$VERSION mode=$MODE action=$ACTION prefix=${PREFIX_NORM:-/})"
}

acquire_lock() {
  mkdir -p "$(dirname -- "$LOCK_DIR")" 2>/dev/null || true
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    die "另一个 MailStack 安装正在进行（锁：$LOCK_DIR）；确认无进程后可删除该目录"
  fi
  log_line INFO "lock acquired: $LOCK_DIR"
}

# ---------------------------------------------------------------------------
# OS detection / dependencies
# ---------------------------------------------------------------------------

OS_FAMILY=""
OS_PRETTY=""
PKG_MANAGER=""

detect_os() {
  OS_PRETTY="unknown"
  local saved_version="$VERSION"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_PRETTY="${PRETTY_NAME:-${NAME:-unknown}}"
    case "${ID:-}${ID_LIKE:-}" in
      *debian*|*ubuntu*) OS_FAMILY="debian"; PKG_MANAGER="apt-get" ;;
      *rhel*|*fedora*|*centos*|*rocky*|*alma*|*ol*) OS_FAMILY="rhel"; PKG_MANAGER="$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)" ;;
      *arch*|*manjaro*) OS_FAMILY="arch"; PKG_MANAGER="pacman" ;;
      *alpine*) OS_FAMILY="alpine"; PKG_MANAGER="apk" ;;
      *) OS_FAMILY="unknown"; PKG_MANAGER="" ;;
    esac
  fi
  VERSION="$saved_version"
  TARBALL_NAME="mailstack-v${VERSION}-${TARGET_TRIPLE}.tar.gz"
  info "系统：$OS_PRETTY（$OS_FAMILY）"
}

install_packages() {
  local packages=("$@")
  [ "${#packages[@]}" -gt 0 ] || return 0
  [ -n "$PKG_MANAGER" ] && command -v "$PKG_MANAGER" >/dev/null 2>&1 \
    || die "缺少依赖：${packages[*]}，且未识别的包管理器；请手工安装后重跑"
  if [ "$INTERACTIVE" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ]; then
    wizard_confirm "安装缺少的依赖 ${packages[*]}?" || die "缺少依赖：${packages[*]}"
  fi
  say "安装依赖：${packages[*]}"
  export DEBIAN_FRONTEND=noninteractive
  local rc=0
  case "$OS_FAMILY" in
    debian)
      timeout 600 env DEBIAN_FRONTEND=noninteractive "$PKG_MANAGER" update -qq || rc=$?
      if [ "$rc" -eq 0 ]; then
        timeout 600 env DEBIAN_FRONTEND=noninteractive "$PKG_MANAGER" install -y "${packages[@]}" || rc=$?
      fi
      ;;
    rhel)   timeout 600 "$PKG_MANAGER" install -y "${packages[@]}" || rc=$? ;;
    arch)   timeout 600 "$PKG_MANAGER" -Sy --noconfirm "${packages[@]}" || rc=$? ;;
    alpine) timeout 600 "$PKG_MANAGER" add --no-cache "${packages[@]}" || rc=$? ;;
    *) die "不支持的发行版，无法自动安装依赖：${packages[*]}" ;;
  esac
  [ "$rc" -eq 0 ] || die "依赖安装失败或超时（可手工安装：${packages[*]}）"
}

PKG_FOR_CMD() {
  case "$1" in
    visudo) printf 'sudo' ;;
    getent) printf 'libc-bin' ;;
    sha256sum) printf 'coreutils' ;;
    *) printf '%s' "$1" ;;
  esac
}

SUDOERS_VALIDATE=0

ensure_dependencies() {
  local required=(install tar sha256sum mktemp realpath tr sed awk grep groupadd useradd getent)
  if [ "$MODE" = "release" ] || { [ "$MODE" = "archive" ] && printf '%s' "$ARCHIVE" | grep -Eq '^https?://'; }; then
    required+=(curl)
  fi
  local missing_cmds=() missing_pkgs=() c p
  for c in "${required[@]}"; do
    need_cmd "$c" || missing_cmds+=("$c")
  done
  if [ -z "$PREFIX_NORM" ]; then
    if ! need_cmd sudo; then missing_cmds+=(sudo); fi
    if ! need_cmd visudo; then missing_cmds+=(visudo); fi
  fi
  for c in "${missing_cmds[@]}"; do
    missing_pkgs+=("$(PKG_FOR_CMD "$c")")
  done
  if [ "${#missing_pkgs[@]}" -gt 0 ] && [ -n "$PREFIX_NORM" ]; then
    warn "staging 前缀：跳过依赖自动安装（缺少：${missing_cmds[*]}；staging 测试允许 sudo/visudo 缺失）"
  fi
  if [ "${#missing_pkgs[@]}" -gt 0 ] && [ -z "$PREFIX_NORM" ]; then
    local uniq=() pkg seen
    for pkg in "${missing_pkgs[@]}"; do
      seen=0
      for c in ${uniq[@]+"${uniq[@]}"}; do [ "$c" = "$pkg" ] && seen=1; done
      [ "$seen" -eq 0 ] && uniq+=("$pkg")
    done
    install_packages "${uniq[@]}"
  fi
  for c in "${missing_cmds[@]}"; do
    need_cmd "$c" || die "依赖仍缺失：$c（请手工安装后重跑）"
  done

  SUDO_CMD="$(command -v sudo || true)"
  if need_cmd visudo; then
    SUDOERS_VALIDATE=1
  else
    SUDOERS_VALIDATE=0
  fi
  if ! need_cmd systemctl && [ -z "$PREFIX_NORM" ] && [ "$NO_SYSTEMD" -eq 0 ]; then
    warn "未检测到 systemctl：容器内安装请加 --no-systemd"
  fi
}

check_environment() {
  [ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo bash $0 ...）"
  [ "$(uname -s)" = "Linux" ] || die "只支持 Linux（当前 $(uname -s)）"
  local arch
  arch="$(uname -m)"
  if [ "$MODE" != "binary-dir" ] && [ "$arch" != "x86_64" ]; then
    die "官方产物只覆盖 x86_64（当前 $arch）；请用 --binary-dir"
  fi
  detect_os
  ensure_dependencies
  if [ -n "$CHECKOUT_ROOT" ] && [ -f "$CHECKOUT_ROOT/VERSION" ]; then
    local repo_version
    repo_version="$(tr -d '[:space:]' < "$CHECKOUT_ROOT/VERSION")"
    [ "$repo_version" = "$VERSION" ] || warn "安装器 $VERSION 与 checkout $repo_version 版本不一致"
  fi
}

# ---------------------------------------------------------------------------
# download / artifact acquisition
# ---------------------------------------------------------------------------

download() {
  local url="$1"
  local dest="$2"
  info "下载 $url"
  if need_cmd curl; then
    curl -fSL --retry 3 --retry-delay 2 --connect-timeout 20 -o "$dest" "$url" \
      || die "下载失败：$url"
  else
    wget -q -O "$dest" "$url" || die "下载失败：$url"
  fi
}

api_asset_url() {
  local name="$1"
  local body=""
  need_cmd curl || return 1
  body="$(curl -fsSL --connect-timeout 15 "$API_RELEASE_URL" 2>/dev/null || true)"
  [ -n "$body" ] || return 1
  printf '%s' "$body" \
    | grep -o '"browser_download_url":[[:space:]]*"[^"]*"' \
    | sed 's/.*"\(https[^"]*\)"/\1/' \
    | grep -F "/$name" | head -1
}

download_release_asset() {
  local name="$1" dest="$2" bases=() base url
  if [ -n "$MIRROR" ]; then
    bases+=("${MIRROR%/}/releases/download/v${VERSION}")
    bases+=("${MIRROR%/}/v${VERSION}")
    bases+=("${MIRROR%/}")
  fi
  bases+=("$RELEASE_BASE")
  for base in "${bases[@]}"; do
    url="${base%/}/$name"
    if need_cmd curl; then
      curl -fSL --retry 2 --connect-timeout 20 -o "$dest" "$url" >/dev/null 2>&1 && { info "下载 $url"; return 0; }
    elif wget -q -O "$dest" "$url" >/dev/null 2>&1; then
      info "下载 $url"
      return 0
    fi
    warn "镜像不可用：$url"
  done
  url="$(api_asset_url "$name" || true)"
  if [ -n "$url" ]; then
    info "GitHub API 定位：$url"
    download "$url" "$dest" && return 0
  fi
  return 1
}

verify_sha256() {
  local dir="$1"
  local file="$2"
  local sums="$3"
  [ -s "$sums" ] || die "SHA256SUMS 不存在或为空：$sums"
  local base expected
  base="$(basename -- "$file")"
  expected="$(awk -v want="$base" '
    { name = $2; sub(/^\*/, "", name); sub(/^\.\//, "", name); if (name == want) { print $1; exit } }' "$sums")"
  [ -n "$expected" ] || die "SHA256SUMS 中没有 $base（拒绝安装未校验的包）"
  ( cd "$dir" && printf '%s  %s\n' "$expected" "$base" | sha256sum -c - >/dev/null ) \
    || die "SHA256 校验失败：$base"
  info "SHA256 校验通过：$base"
}

extract_tarball() {
  local tarball="$1"
  local dest="$2"
  mkdir -p "$dest"
  tar -xzf "$tarball" -C "$dest" || die "解包失败：$tarball"
  local roots=() entry
  for entry in "$dest"/*; do [ -e "$entry" ] && roots+=("$entry"); done
  if [ "${#roots[@]}" -eq 1 ] && [ -d "${roots[0]}" ]; then
    printf '%s' "${roots[0]}"
  else
    printf '%s' "$dest"
  fi
}

resolve_package() {
  local pkg="$1"
  [ -n "$pkg" ] && [ -d "$pkg" ] || die "发布包目录不存在：$pkg"
  if [ -d "$pkg/bin" ] && [ -f "$pkg/bin/mailstackd" ]; then
    BIN_SRC="$pkg/bin"
  elif [ -f "$pkg/mailstackd" ]; then
    BIN_SRC="$pkg"
  else
    die "发布包结构不符合预期（缺 bin/mailstackd）"
  fi
  [ -d "$pkg/deploy/systemd" ] && UNIT_SRC="$pkg/deploy/systemd"
  if [ -d "$pkg/webui-dist" ]; then DIST_SRC="$pkg/webui-dist"
  elif [ -d "$pkg/webui/dist" ]; then DIST_SRC="$pkg/webui/dist"; fi
  [ -f "$pkg/deploy/uninstall.sh" ] && UNINSTALL_SRC="$pkg/deploy/uninstall.sh"
  [ -f "$pkg/deploy/mailstack-manage.sh" ] && MANAGE_SRC="$pkg/deploy/mailstack-manage.sh"
  return 0
}

locate_checkout_assets() {
  local base="${CHECKOUT_ROOT:-}"
  if [ -n "$base" ]; then
    [ -d "$base/deploy/systemd" ] && UNIT_SRC="$base/deploy/systemd"
    if [ -d "$base/webui/dist" ]; then DIST_SRC="$base/webui/dist"
    elif [ -d "$base/dist/webui-dist" ]; then DIST_SRC="$base/dist/webui-dist"; fi
    [ -f "$base/deploy/uninstall.sh" ] && UNINSTALL_SRC="$base/deploy/uninstall.sh"
    [ -f "$base/deploy/mailstack-manage.sh" ] && MANAGE_SRC="$base/deploy/mailstack-manage.sh"
  fi
  if [ -z "$UNIT_SRC" ] && [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/systemd" ]; then
    UNIT_SRC="$SCRIPT_DIR/systemd"
  fi
  [ -z "$UNINSTALL_SRC" ] && [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/uninstall.sh" ] \
    && UNINSTALL_SRC="$SCRIPT_DIR/uninstall.sh"
  [ -z "$MANAGE_SRC" ] && [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/mailstack-manage.sh" ] \
    && MANAGE_SRC="$SCRIPT_DIR/mailstack-manage.sh"
  return 0
}

acquire_release() {
  say "获取官方发布包（v${VERSION}，${TARGET_TRIPLE}）"
  local dl extract pkg
  dl="$(new_tmp)"
  download_release_asset "$TARBALL_NAME" "$dl/$TARBALL_NAME" || die "无法下载 $TARBALL_NAME（镜像/GitHub 均失败）"
  if download_release_asset "SHA256SUMS" "$dl/SHA256SUMS"; then
    verify_sha256 "$dl" "$TARBALL_NAME" "$dl/SHA256SUMS"
  elif [ "$ALLOW_UNSIGNED" -eq 1 ]; then
    warn "无法下载 SHA256SUMS：--allow-unsigned 已显式放行，跳过完整性校验"
  else
    die "无法下载 SHA256SUMS：拒绝安装未校验的发布包（可用 --mirror/--archive，或显式 --allow-unsigned）"
  fi
  extract="$(new_tmp)"
  pkg="$(extract_tarball "$dl/$TARBALL_NAME" "$extract")"
  resolve_package "$pkg"
}

acquire_archive() {
  say "使用指定发布包：$ARCHIVE"
  local file dl sums sums_dir
  case "$ARCHIVE" in
    http://*|https://*)
      dl="$(new_tmp)"
      file="$dl/$(basename "${ARCHIVE%%\?*}")"
      download "$ARCHIVE" "$file" ;;
    *)
      file="$ARCHIVE"
      [ -f "$file" ] || die "发布包不存在：$file"
      file="$(realpath -- "$file")" ;;
  esac
  sums_dir="$(dirname "$file")"
  sums="$sums_dir/SHA256SUMS"
  if [ -s "$sums" ]; then
    verify_sha256 "$sums_dir" "$(basename "$file")" "$sums"
  elif [ "$ALLOW_UNSIGNED" -eq 1 ]; then
    warn "发布包旁没有 SHA256SUMS：--allow-unsigned 已显式放行，跳过完整性校验"
  else
    die "发布包旁没有 SHA256SUMS：拒绝安装未校验的发布包（或显式 --allow-unsigned）"
  fi
  local extract pkg
  extract="$(new_tmp)"
  pkg="$(extract_tarball "$file" "$extract")"
  resolve_package "$pkg"
}

acquire_binary_dir() {
  say "使用预编译二进制目录：$BINARY_DIR"
  local dir="$BINARY_DIR"
  [ -d "$dir" ] || die "--binary-dir 不存在：$dir"
  dir="$(realpath -- "$dir")"
  if [ -d "$dir/bin" ] && [ -f "$dir/bin/mailstackd" ]; then BIN_SRC="$dir/bin"
  elif [ -f "$dir/mailstackd" ]; then BIN_SRC="$dir"
  else die "--binary-dir 下找不到 mailstackd"; fi
  locate_checkout_assets
  [ -n "$UNIT_SRC" ] || die "找不到 systemd unit 模板（请在 checkout 中运行）"
  return 0
}

check_source_toolchain() {
  need_cmd cargo || die "源码构建需要 cargo（Rust $EXPECTED_RUST）"
  need_cmd rustc || die "源码构建需要 rustc"
  local version
  version="$(rustc --version 2>/dev/null || true)"
  case "$version" in
    "rustc $EXPECTED_RUST"*) info "rustc: $version" ;;
    *) die "工具链版本不匹配：期望 rustc $EXPECTED_RUST.x，实际 ${version:-unknown}" ;;
  esac
  { need_cmd cc || need_cmd gcc; } || die "源码构建需要 C 编译器"
  return 0
}

acquire_source() {
  say "从源码构建（deploy/build.sh）"
  local src
  if [ -n "$CHECKOUT_ROOT" ] && [ -f "$CHECKOUT_ROOT/Cargo.toml" ] && [ -f "$CHECKOUT_ROOT/deploy/build.sh" ]; then
    src="$CHECKOUT_ROOT"
    info "使用当前 checkout：$src"
  else
    local dl extract pkg
    dl="$(new_tmp)"
    download "$SOURCE_TARBALL_URL" "$dl/source.tar.gz"
    extract="$(new_tmp)"
    pkg="$(extract_tarball "$dl/source.tar.gz" "$extract")"
    [ -f "$pkg/Cargo.toml" ] || die "源码包结构不符合预期"
    src="$pkg"
  fi
  check_source_toolchain
  if [ ! -d "$src/webui/dist" ] && [ -d "$src/webui" ] && need_cmd npm && need_cmd node; then
    say "构建前端产物"
    ( cd "$src/webui" && npm ci --no-audit --no-fund && npm run build ) \
      || warn "前端构建失败（页面 503，API 可用）"
  fi
  say "调用 deploy/build.sh"
  ( cd "$src" && bash deploy/build.sh ) || die "deploy/build.sh 失败"
  BIN_SRC="$src/dist"
  UNIT_SRC="$src/deploy/systemd"
  [ -d "$src/webui/dist" ] && DIST_SRC="$src/webui/dist"
  [ -f "$src/deploy/uninstall.sh" ] && UNINSTALL_SRC="$src/deploy/uninstall.sh"
  [ -f "$src/deploy/mailstack-manage.sh" ] && MANAGE_SRC="$src/deploy/mailstack-manage.sh"
  [ -d "$BIN_SRC" ] || die "构建产物目录不存在：$BIN_SRC"
  return 0
}

acquire_manage_script() {
  [ -n "$MANAGE_SRC" ] && [ -f "$MANAGE_SRC" ] && return 0
  if [ -n "$CHECKOUT_ROOT" ] && [ -f "$CHECKOUT_ROOT/deploy/mailstack-manage.sh" ]; then
    MANAGE_SRC="$CHECKOUT_ROOT/deploy/mailstack-manage.sh"; return 0
  fi
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/mailstack-manage.sh" ]; then
    MANAGE_SRC="$SCRIPT_DIR/mailstack-manage.sh"; return 0
  fi
  { need_cmd curl || need_cmd wget; } || die "发布包缺 mailstack-manage.sh，且无 curl/wget"
  local dl
  dl="$(new_tmp)"
  say "发布包未携带管理脚本：从 ${RAW_BRANCH} 下载"
  download "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/mailstack-manage.sh" \
    "$dl/mailstack-manage.sh"
  bash -n "$dl/mailstack-manage.sh" || die "下载的管理脚本语法校验失败"
  MANAGE_SRC="$dl/mailstack-manage.sh"
}

validate_artifacts() {
  [ -n "$BIN_SRC" ] && [ -d "$BIN_SRC" ] || die "内部错误：未定位二进制目录"
  local name path missing=()
  for name in "${BIN_NAMES[@]}"; do
    path="$BIN_SRC/$name"
    if [ ! -f "$path" ]; then missing+=("$name"); continue; fi
    [ -x "$path" ] || die "二进制不可执行：$path"
    if [ "$MODE" != "binary-dir" ]; then
      "$path" --version >/dev/null 2>&1 || die "二进制无法执行：$path（架构/glibc 不匹配？）"
    fi
  done
  [ "${#missing[@]}" -eq 0 ] || die "产物不齐，缺少：${missing[*]}"
  [ -n "$UNIT_SRC" ] && [ -d "$UNIT_SRC" ] || die "找不到 unit 模板目录"
  local unit
  for unit in "${UNIT_NAMES[@]}"; do
    [ -f "$UNIT_SRC/$unit.service.in" ] || die "缺少 unit 模板：$unit"
  done
  if [ -z "$DIST_SRC" ] || [ ! -d "$DIST_SRC" ]; then
    warn "未找到前端产物（页面 503，API 可用）"; DIST_SRC=""
  else
    [ -f "$DIST_SRC/index.html" ] || warn "前端产物缺 index.html"
    [ -f "$DIST_SRC/mail.html" ] || warn "前端产物缺 mail.html"
  fi
  [ -n "$MANAGE_SRC" ] && [ -f "$MANAGE_SRC" ] || die "缺少 mailstack-manage.sh"
  bash -n "$MANAGE_SRC" || die "mailstack-manage.sh 语法校验失败"
  [ -n "$UNINSTALL_SRC" ] && { bash -n "$UNINSTALL_SRC" || die "uninstall.sh 语法校验失败"; }
  return 0
}

# ---------------------------------------------------------------------------
# users / directories / files
# ---------------------------------------------------------------------------

group_exists() {
  if need_cmd getent; then getent group "$1" >/dev/null 2>&1
  else grep -qE "^$1:" /etc/group 2>/dev/null; fi
}

user_exists() {
  if need_cmd getent; then getent passwd "$1" >/dev/null 2>&1
  else grep -qE "^$1:" /etc/passwd 2>/dev/null; fi
}

nologin_shell() {
  local c
  for c in /usr/sbin/nologin /sbin/nologin /bin/false; do
    [ -x "$c" ] && { printf '%s' "$c"; return 0; }
  done
  printf '/bin/false'
}

ensure_users_and_groups() {
  say "创建运行账号与用户组"
  if group_exists mailstack-admin; then info "组已存在：mailstack-admin"; else
    groupadd --system mailstack-admin || die "创建组 mailstack-admin 失败"; info "已创建组：mailstack-admin"; fi
  if user_exists mailstack-admin; then info "用户已存在：mailstack-admin"; else
    useradd --system --gid mailstack-admin --no-create-home --home-dir /nonexistent \
      --shell "$(nologin_shell)" mailstack-admin || die "创建用户 mailstack-admin 失败"
    info "已创建用户：mailstack-admin"; fi
  if group_exists mailstack-webmail; then info "组已存在：mailstack-webmail"; else
    groupadd --system mailstack-webmail || die "创建组 mailstack-webmail 失败"; info "已创建组：mailstack-webmail"; fi
  if group_exists opendkim; then info "组已存在：opendkim"; else
    groupadd --system opendkim || die "创建组 opendkim 失败"; info "已创建组：opendkim"; fi
  return 0
}

install_dir() {
  local dir="$1"
  local mode="$2"
  local owner="$3"
  local group="$4"
  [ -n "$dir" ] || die "install_dir: 空路径"
  install -d -m "$mode" "$dir" || die "创建目录失败：$dir"
  chown "$owner:$group" "$dir" 2>/dev/null || die "设置属主失败：$dir"
  chmod "$mode" "$dir" || die "设置权限失败：$dir"
  return 0
}

put_file() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  local owner="$4"
  local group="$5"
  local tmp="${dst}.new.$$"
  install -m "$mode" "$src" "$tmp" || die "写入失败：$tmp"
  chown "$owner:$group" "$tmp" 2>/dev/null || { rm -f -- "$tmp"; die "设置属主失败：$dst"; }
  mv -f -- "$tmp" "$dst" || die "替换失败：$dst"
  return 0
}

safe_rm_rf() {
  local target="$1" real preal
  [ -n "$target" ] || die "safe_rm_rf: 空路径"
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
  rm -rf -- "$real"
}

create_directories() {
  say "创建目录与权限"
  install_dir "$ETC_DIR" 0750 root mailstack-admin
  install_dir "$ACCESS_DIR" 0750 root root
  install_dir "$VAR_LIB_DIR" 0750 root mailstack-webmail
  install_dir "$BACKUP_DIR" 0700 root root
  install_dir "$ROLLBACK_DIR" 0700 root root
  install_dir "$RUN_DIR" 0750 root mailstack-admin
  install_dir "$LIBEXEC_DIR" 0755 root root
  install_dir "$BIN_DIR" 0755 root root
  install_dir "$(prefix_path /usr/share/mailstack)" 0755 root root
  install_dir "$(prefix_path /etc/opendkim)" 0750 root opendkim
  install_dir "$(prefix_path /etc/opendkim/keys)" 0750 root opendkim
  install_dir "$SUDOERS_DIR" 0750 root root
  [ -d "$(prefix_path /etc/postfix)" ] || install -d -m 0755 "$(prefix_path /etc/postfix)"
  return 0
}

install_binaries() {
  say "安装二进制到 $BIN_DIR"
  local name
  for name in "${BIN_NAMES[@]}"; do
    put_file "$BIN_SRC/$name" "$BIN_DIR/$name" 0755 root root
    info "已安装：$BIN_DIR/$name"
  done
}

install_manage_script() {
  say "安装管理脚本"
  put_file "$MANAGE_SRC" "$BIN_DIR/$MANAGE_NAME" 0755 root root
  bash -n "$BIN_DIR/$MANAGE_NAME" || die "管理脚本语法校验失败"
  info "已安装：$BIN_DIR/$MANAGE_NAME"
}

wrapper_config_arg() {
  [ -n "$PREFIX_NORM" ] && printf ' --config-dir %s' "$PREFIX_NORM"
  return 0
}

install_wrapper() {
  say "安装特权包装器与 sudoers"
  local wrapper="$LIBEXEC_DIR/$WRAPPER_NAME" src sudoers src_sudoers
  src="$(new_tmp)/$WRAPPER_NAME"
  cat > "$src" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
exec $BIN_DIR/mailstackctl --privileged-stdin$(wrapper_config_arg)
EOF
  chmod 0755 "$src"
  put_file "$src" "$wrapper" 0750 root root
  grep -q -- '--privileged-stdin' "$wrapper" || die "包装器自检失败：缺少 --privileged-stdin"
  grep -qF '"$@"' "$wrapper" && die "包装器自检失败：不允许转发 \"\$@\""
  info "已安装：$wrapper（0750 root:root）"

  sudoers="$SUDOERS_DIR/$SUDOERS_NAME"
  src_sudoers="$(new_tmp)/sudoers"
  cat > "$src_sudoers" <<EOF
# MailStack：唯一特权入口。
mailstack-admin ALL=(root) NOPASSWD: $wrapper
EOF
  chmod 0440 "$src_sudoers"
  if [ "$SUDOERS_VALIDATE" -eq 1 ] && need_cmd visudo; then
    visudo -cf "$src_sudoers" >/dev/null 2>&1 || die "sudoers 语法校验失败（visudo -cf）"
    info "sudoers 校验通过（visudo -cf）"
  elif [ -z "$PREFIX_NORM" ]; then
    die "缺少 visudo，无法校验 sudoers"
  else
    warn "staging：跳过 sudoers 语法校验"
  fi
  put_file "$src_sudoers" "$sudoers" 0440 root root
  info "已安装：$sudoers"
  return 0
}

install_dist() {
  say "安装前端产物"
  if [ -z "$DIST_SRC" ]; then warn "无前端产物：跳过"; return 0; fi
  local staging="${DIST_DIR}.new.$$"
  rm -rf -- "$staging"
  mkdir -p "$(dirname "$DIST_DIR")"
  cp -a "$DIST_SRC/." "$staging/" || die "复制前端产物失败"
  chmod -R a+rX "$staging"; chmod -R go-w "$staging"; chmod 0755 "$staging"
  chown -R root:root "$staging" 2>/dev/null || warn "前端产物 chown 失败"
  safe_rm_rf "$DIST_DIR"
  mv -- "$staging" "$DIST_DIR" || die "替换前端产物失败"
  info "已安装：$DIST_DIR"
}

render_unit() {
  local template="$1"
  local dest="$2"
  local imap_cert_args=""
  local imap_condition=""
  local server_name="mailstack"
  if [ -n "$MAIL_HOST" ]; then
    server_name="$MAIL_HOST"
    local cert_dir="$ETC_DIR/tls/$MAIL_HOST"
    imap_cert_args=" --cert $cert_dir/fullchain.pem --key $cert_dir/privkey.pem"
    imap_condition="ConditionPathExists=$cert_dir/fullchain.pem"
  else
    imap_condition="# 未配置邮件主机：本 unit 不启用"
  fi
  sed -e "s|@BIN_DIR@|$BIN_DIR|g" -e "s|@ETC_DIR@|$ETC_DIR|g" -e "s|@DIST_DIR@|$DIST_DIR|g" \
      -e "s|@ADMIN_PORT@|$ADMIN_PORT|g" -e "s|@WEBMAIL_PORT@|$WEBMAIL_PORT|g" \
      -e "s|@CONFIG_ARG@|$CONFIG_ARG|g" -e "s|@MAIL_HOST@|$server_name|g" \
      -e "s|@IMAP_CERT_ARGS@|$imap_cert_args|g" -e "s|@IMAP_CONDITION_LINE@|$imap_condition|g" \
      "$template" > "$dest" || die "渲染 unit 失败：$template"
  chmod 0644 "$dest"
}

install_units() {
  say "安装 systemd unit"
  mkdir -p "$UNIT_DIR"
  local unit
  for unit in "${INSTALL_UNITS[@]}"; do
    local tmp="$UNIT_DIR/${unit}.service.new.$$"
    render_unit "$UNIT_SRC/${unit}.service.in" "$tmp"
    mv -f -- "$tmp" "$UNIT_DIR/${unit}.service" || die "安装 unit 失败：$unit"
    info "已安装：$UNIT_DIR/${unit}.service"
  done
  if [ "$IMAP_ENABLE" -eq 0 ] && [ -f "$UNIT_DIR/mailstack-imap.service" ]; then
    rm -f -- "$UNIT_DIR/mailstack-imap.service"
    warn "已按 --imap no 移除 mailstack-imap.service"
  fi
}

adopt_uninstaller() {
  if [ -n "$UNINSTALL_SRC" ] && [ -f "$UNINSTALL_SRC" ]; then
    put_file "$UNINSTALL_SRC" "$LIBEXEC_DIR/mailstack-uninstall" 0755 root root
    info "已安装卸载脚本：$LIBEXEC_DIR/mailstack-uninstall"
  fi
}

# ---------------------------------------------------------------------------
# state files
# ---------------------------------------------------------------------------

write_deployment_state() {
  say "写入部署状态"
  local conf="$ETC_DIR/install-args.conf"
  if [ -z "$DOMAIN" ]; then DOMAIN="$(state_get "$conf" DOMAIN || true)"; fi
  if [ -z "$MAIL_HOST" ]; then MAIL_HOST="$(state_get "$conf" MAIL_HOST || true)"; fi
  if [ -z "$PANEL_HOST" ]; then PANEL_HOST="$(state_get "$conf" PANEL_HOST || true)"; fi
  if [ -z "$WEBMAIL_HOST" ]; then WEBMAIL_HOST="$(state_get "$conf" WEBMAIL_HOST || true)"; fi
  if [ -z "$ACME_EMAIL" ]; then ACME_EMAIL="$(state_get "$conf" ACME_EMAIL || true)"; fi
  if [ -z "$SERVER_IP" ]; then SERVER_IP="$(state_get "$conf" SERVER_IP || true)"; fi

  local canonical panel_url="" webmail_url=""
  canonical="$(canonical_access_mode "$ACCESS_MODE")"
  case "$ACCESS_MODE" in
    ssh) panel_url="http://127.0.0.1:${ADMIN_PORT}/"; webmail_url="http://127.0.0.1:${WEBMAIL_PORT}/" ;;
    *) [ -n "$PANEL_HOST" ] && panel_url="https://$PANEL_HOST/"
       [ -n "$WEBMAIL_HOST" ] && webmail_url="https://$WEBMAIL_HOST/" ;;
  esac

  local tmp="$conf.tmp.$$"
  {
    printf '# 由 deploy/install.sh / deploy/mailstack-manage.sh 维护；mode.rs 只读 ACCESS_MODE。\n'
    printf 'ACCESS_MODE=%s\n' "$canonical"
    printf 'ACCESS_MODE_DETAIL=%s\n' "$ACCESS_MODE"
    printf 'MAILSTACK_VERSION=%s\n' "$VERSION"
    printf 'INSTALLED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'DOMAIN=%s\n' "$DOMAIN"
    printf 'MAIL_HOST=%s\n' "$MAIL_HOST"
    printf 'ADMIN_USER=%s\n' "$ADMIN_USER"
    printf 'ADMIN_PORT=%s\n' "$ADMIN_PORT"
    printf 'WEBMAIL_PORT=%s\n' "$WEBMAIL_PORT"
    printf 'PANEL_HOST=%s\n' "$PANEL_HOST"
    printf 'WEBMAIL_HOST=%s\n' "$WEBMAIL_HOST"
    printf 'PANEL_URL=%s\n' "$panel_url"
    printf 'WEBMAIL_URL=%s\n' "$webmail_url"
    printf 'ACME_EMAIL=%s\n' "$ACME_EMAIL"
    printf 'SERVER_IP=%s\n' "$SERVER_IP"
    printf 'IMAP_ENABLE=%s\n' "$IMAP_ENABLE"
  } > "$tmp"
  chmod 0600 "$tmp"; chown root:root "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$conf" || die "写入 $conf 失败"
  info "ACCESS_MODE=$canonical（DETAIL=$ACCESS_MODE）"
}

write_install_json() {
  local file="$ETC_DIR/install.json"
  local tmp="$file.tmp.$$"
  local source_label="$MODE"
  [ "$MODE" = "release" ] && source_label="release:v${VERSION}"
  {
    printf '{\n'
    printf '  "installerVersion": "%s",\n' "$(json_escape "$VERSION")"
    printf '  "source": "%s",\n' "$(json_escape "$source_label")"
    printf '  "installedAt": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "prefix": "%s",\n' "$(json_escape "${PREFIX_NORM:-/}")"
    printf '  "action": "%s",\n' "$(json_escape "$ACTION")"
    printf '  "domain": "%s",\n' "$(json_escape "$DOMAIN")"
    printf '  "mailHost": "%s",\n' "$(json_escape "$MAIL_HOST")"
    printf '  "accessMode": "%s",\n' "$(json_escape "$(canonical_access_mode "$ACCESS_MODE")")"
    printf '  "accessModeDetail": "%s",\n' "$(json_escape "$ACCESS_MODE")"
  printf '  "paths": {\n'
    printf '    "etc": "%s",\n' "$(json_escape "$ETC_DIR")"
    printf '    "varLib": "%s",\n' "$(json_escape "$VAR_LIB_DIR")"
    printf '    "bin": "%s",\n' "$(json_escape "$BIN_DIR")"
    printf '    "libexec": "%s",\n' "$(json_escape "$LIBEXEC_DIR")"
    printf '    "units": "%s",\n' "$(json_escape "$UNIT_DIR")"
    printf '    "dist": "%s"\n' "$(json_escape "$DIST_DIR")"
    printf '  }\n'
    printf '}\n'
  } > "$tmp"
  chmod 0600 "$tmp"; chown root:root "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$file" || die "写入 $file 失败"
  info "已写入：$file"
}

write_install_marker() {
  local marker="$ETC_DIR/.mailstack-installed"
  {
    printf 'MAILSTACK_VERSION=%s\n' "$VERSION"
    printf 'INSTALLED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'PREFIX=%s\n' "${PREFIX_NORM:-/}"
  } > "$marker.tmp.$$"
  chmod 0644 "$marker.tmp.$$"
  mv -f -- "$marker.tmp.$$" "$marker" || die "写入安装标记失败"
  return 0
}

# ---------------------------------------------------------------------------
# privileged calls
# ---------------------------------------------------------------------------

call_privileged() {
  local action="$1" data="$2" out rc=0
  out="$(printf '{"action":"%s","data":%s}' "$(json_escape "$action")" "$data" \
    | "$LIBEXEC_DIR/$WRAPPER_NAME" 2>&1)" || rc=$?
  printf '%s' "$out"
  return "$rc"
}

response_ok()    { case "$1" in *'"ok":true'*) return 0 ;; *) return 1 ;; esac; }
response_error() { printf '%s' "$1" | sed -n 's/.*"error":"\([^"]*\)".*/\1/p' | head -1; }

bootstrap_admin() {
  say "管理员凭证引导"
  local cfg="$ETC_DIR/admin.json" out payload
  if [ -s "$cfg" ]; then
    info "管理员凭证已存在（幂等，不重置）"
    ADMIN_STATE="kept"
    return 0
  fi
  if [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_STATE="skipped"
    warn "未提供管理员口令：跳过引导"
    info "手工创建：printf '%s' '{\"action\":\"admin.set\",\"data\":{\"username\":\"$ADMIN_USER\",\"password\":\"<口令>\"}}' | sudo $LIBEXEC_DIR/$WRAPPER_NAME"
    return 0
  fi
  payload="$(printf '{"username":"%s","password":"%s"}' \
    "$(json_escape "$ADMIN_USER")" "$(json_escape "$ADMIN_PASSWORD")")"
  out="$(call_privileged admin.set "$payload")" || true
  ADMIN_PASSWORD=""
  if response_ok "$out" || [ -s "$cfg" ]; then
    ADMIN_STATE="ok"
    info "管理员已创建：$cfg"
  else
    ADMIN_STATE="failed"
    warn "管理员引导失败：$(response_error "$out")"
    [ -z "$PREFIX_NORM" ] && die "管理员引导失败，安装中止"
  fi
}

apply_identity() {
  if [ -z "$DOMAIN" ]; then
    IDENTITY_STATE="not-requested"
    info "未提供 --domain：跳过邮件身份"
    return 0
  fi
  say "应用邮件身份：$DOMAIN"
  local ip="${SERVER_IP:-}"
  [ -n "$ip" ] || ip="$(detect_server_ip)"
  if [ -z "$ip" ]; then
    IDENTITY_STATE="failed"
    warn "无法确定服务器 IP：跳过身份应用（用 domain set --server-ip 补）"
    return 0
  fi
  SERVER_IP="$ip"
  local payload out
  payload="$(printf '{"domain":"%s","mailHost":"%s","serverIp":"%s","dkimSelector":"mail"}' \
    "$(json_escape "$DOMAIN")" "$(json_escape "${MAIL_HOST:-mail.$DOMAIN}")" "$(json_escape "$ip")")"
  out="$(call_privileged setup.identity.apply "$payload")" || true
  if ! response_ok "$out"; then
    IDENTITY_STATE="failed"
    warn "setup.identity.apply 失败：$(response_error "$out")"
    [ -z "$PREFIX_NORM" ] && die "邮件身份应用失败，安装中止"
    return 0
  fi
  IDENTITY_STATE="ok"
  info "身份已写入：$ETC_DIR/setup.json（DKIM 已生成）"
  if call_privileged domains.add "$(printf '{"name":"%s"}' "$(json_escape "$DOMAIN")")" >/dev/null 2>&1; then
    info "域名表已登记"
  else
    warn "domains.add 失败（可用 mailstack-manage domain add 重试）"
  fi
}

run_manage() {
  if [ -n "$PREFIX_NORM" ]; then
    MAILSTACK_PREFIX="$PREFIX_NORM" "$BIN_DIR/$MANAGE_NAME" "$@"
  else
    "$BIN_DIR/$MANAGE_NAME" "$@"
  fi
}

provision_access() {
  if [ "$NO_ACCESS_PROVISION" -eq 1 ]; then
    ACCESS_STATE="skipped"
    info "--no-access-provision：跳过访问层"
    return 0
  fi
  say "应用访问模式：$ACCESS_MODE"
  local -a args=(access set "$ACCESS_MODE" --no-reload)
  [ -n "$PANEL_HOST" ] && args+=(--panel-host "$PANEL_HOST")
  [ -n "$WEBMAIL_HOST" ] && args+=(--webmail-host "$WEBMAIL_HOST")
  [ -n "$ACME_EMAIL" ] && args+=(--acme-email "$ACME_EMAIL")
  [ -n "$SERVER_IP" ] && args+=(--server-ip "$SERVER_IP")
  if run_manage "${args[@]}"; then
    ACCESS_STATE="ok"
  else
    ACCESS_STATE="failed"
    warn "访问层应用失败（sudo mailstack-manage access set $ACCESS_MODE 重试）"
    [ -z "$PREFIX_NORM" ] && die "访问模式应用失败，安装中止"
  fi
}

# ---------------------------------------------------------------------------
# firewall
# ---------------------------------------------------------------------------

firewall_ports() {
  local ports=("${WEB_PORTS[@]}")
  [ "$IMAP_ENABLE" -eq 1 ] && ports+=("${MAIL_PORTS[@]}")
  [ "$ACCESS_MODE" = "caddy" ] || [ "$ACCESS_MODE" = "nginx" ] || [ "$ACCESS_MODE" = "ip-acme" ] \
    || [ "$ACCESS_MODE" = "panel-domain" ] && ports+=(80 443)
  printf '%s\n' "${ports[@]}" | awk '!seen[$0]++'
}

apply_firewall() {
  FIREWALL_STATE="skipped"
  [ "$NO_FIREWALL" -eq 1 ] && { info "--no-firewall：跳过防火墙"; return 0; }
  [ -n "$PREFIX_NORM" ] && { info "staging：跳过防火墙"; return 0; }
  local tool=""
  local ports=()
  mapfile -t ports < <(firewall_ports)
  if need_cmd ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
    tool="ufw"
  elif need_cmd firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    tool="firewalld"
  else
    info "未检测到活动的 ufw/firewalld：跳过（如启用请手工放行：${ports[*]}）"
    return 0
  fi
  if [ "$INTERACTIVE" -eq 1 ] && [ "$NON_INTERACTIVE" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ]; then
    wizard_confirm "通过 $tool 放行端口 ${ports[*]}?" || { info "跳过防火墙"; return 0; }
  fi
  say "配置防火墙（$tool）"
  local p
  case "$tool" in
    ufw)
      for p in "${ports[@]}"; do ufw allow "$p/tcp" >/dev/null 2>&1 && info "ufw allow $p/tcp"; done
      ;;
    firewalld)
      for p in "${ports[@]}"; do
        firewall-cmd --add-port="$p/tcp" --permanent >/dev/null 2>&1 && info "firewalld allow $p/tcp"
      done
      firewall-cmd --reload >/dev/null 2>&1 || warn "firewall-cmd --reload 失败"
      ;;
  esac
  FIREWALL_STATE="ok"
}

# ---------------------------------------------------------------------------
# services / health / rollback
# ---------------------------------------------------------------------------

print_manual_start_commands() {
  say "手工启动命令"
  printf '    systemctl daemon-reload\n'
  printf '    systemctl enable --now %s\n' "${INSTALL_UNITS[*]}"
}

services_start() {
  say "systemd 服务"
  if [ "$NO_SYSTEMD" -eq 1 ]; then
    info "--no-systemd：unit 已写入，未 enable/start"
    print_manual_start_commands
    return 0
  fi
  if [ -n "$PREFIX_NORM" ]; then
    warn "staging 前缀：unit 写入 $UNIT_DIR，不操作宿主 systemd"
    print_manual_start_commands
    return 0
  fi
  if [ ! -d /run/systemd/system ] || ! need_cmd systemctl; then
    warn "未检测到运行中的 systemd：跳过 enable/start"
    print_manual_start_commands
    return 0
  fi
  systemctl daemon-reload || die "systemctl daemon-reload 失败"
  local unit
  for unit in "${INSTALL_UNITS[@]}"; do
    systemctl enable "$unit" >/dev/null 2>&1 && info "已 enable：$unit" || warn "enable $unit 失败"
  done
  for unit in "${INSTALL_UNITS[@]}"; do
    systemctl restart "$unit" >/dev/null 2>&1 && info "已重启：$unit" || warn "restart $unit 失败"
  done
  for unit in "${INSTALL_UNITS[@]}"; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      info "状态：$unit = active"
    elif [ "$unit" = "mailstackd" ] && [ ! -s "$ETC_DIR/setup.json" ]; then
      info "状态：$unit = inactive（预期：邮件身份未配置）"
    elif [ "$unit" = "mailstack-imap" ] && [ ! -s "$ETC_DIR/tls/${MAIL_HOST:-_}/fullchain.pem" ]; then
      info "状态：$unit = inactive（预期：证书未就绪）"
    else
      warn "状态：$unit = inactive（journalctl -u $unit 查看）"
    fi
  done
}

health_check() {
  systemd_live() { [ -z "$PREFIX_NORM" ] && [ -d /run/systemd/system ] && need_cmd systemctl; }
  if ! systemd_live; then
    info "staging/无 systemd：跳过健康检查"
    return 0
  fi
  local unit failed=0
  for unit in mailstack-web mailstack-webmail; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      info "健康：$unit active"
    else
      warn "健康检查失败：$unit 不是 active"
      failed=1
    fi
  done
  if [ -f "$ETC_DIR/setup.json" ]; then
    if systemctl is-active --quiet mailstackd 2>/dev/null; then
      info "健康：mailstackd active"
    else
      warn "健康检查失败：mailstackd 不是 active"
      failed=1
    fi
  fi
  return "$failed"
}

backup_current_files() {
  local ts dir
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  dir="$ROLLBACK_DIR/$ts"
  mkdir -p "$dir"
  local name
  for name in "${BIN_NAMES[@]}" "$MANAGE_NAME"; do
    [ -f "$BIN_DIR/$name" ] && cp -a "$BIN_DIR/$name" "$dir/" 2>/dev/null || true
  done
  [ -d "$UNIT_DIR" ] && mkdir -p "$dir/units" && cp -a "$UNIT_DIR"/mailstack*.service "$dir/units/" 2>/dev/null || true
  printf '%s\n' "$dir"
}

rollback_files() {
  local dir="$1" name
  warn "回滚程序文件：$dir"
  for name in "${BIN_NAMES[@]}" "$MANAGE_NAME"; do
    [ -f "$dir/$name" ] && cp -a "$dir/$name" "$BIN_DIR/$name" 2>/dev/null || true
  done
  if [ -d "$dir/units" ] && need_cmd systemctl; then
    cp -a "$dir/units"/*.service "$UNIT_DIR/" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    for name in "${INSTALL_UNITS[@]}"; do
      systemctl restart "$name" >/dev/null 2>&1 || true
    done
  fi
}

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

print_summary() {
  say "安装完成（MailStack v${VERSION}）"
  printf '    %s前缀%s:       %s\n' "$C_BOLD" "$C_RESET" "${PREFIX_NORM:-/}"
  printf '    %s二进制%s:     %s（含 mailstack-manage）\n' "$C_BOLD" "$C_RESET" "$BIN_DIR"
  printf '    %s管理台%s:     %s（内部 127.0.0.1:%s）\n' "$C_BOLD" "$C_RESET" \
    "$([ "$ACCESS_MODE" = "ssh" ] && printf 'http://127.0.0.1:%s/?login=1' "$ADMIN_PORT" || printf 'https://%s/' "${PANEL_HOST:-?}")" "$ADMIN_PORT"
  printf '    %sWebmail%s:    %s（内部 127.0.0.1:%s）\n' "$C_BOLD" "$C_RESET" \
    "$([ "$ACCESS_MODE" = "ssh" ] && printf 'http://127.0.0.1:%s/' "$WEBMAIL_PORT" || printf 'https://%s/' "${WEBMAIL_HOST:-?}")" "$WEBMAIL_PORT"
  printf '    %s访问模式%s:   %s（ACCESS_MODE=%s）\n' "$C_BOLD" "$C_RESET" "$ACCESS_MODE" "$(canonical_access_mode "$ACCESS_MODE")"
  printf '    %s配置目录%s:   %s\n' "$C_BOLD" "$C_RESET" "$ETC_DIR"
  printf '    %s数据目录%s:   %s\n' "$C_BOLD" "$C_RESET" "$VAR_LIB_DIR"
  printf '    %s日志%s:       %s\n' "$C_BOLD" "$C_RESET" "$LOG_FILE"
  case "$ADMIN_STATE" in
    ok)      printf '    管理员:     %s（已写入 admin.json）\n' "$ADMIN_USER" ;;
    kept)    printf '    管理员:     %s（既有凭证保留）\n' "$ADMIN_USER" ;;
    skipped) printf '    管理员:     未引导（重跑安装或手工 admin.set）\n' ;;
    failed)  printf '    管理员:     引导失败\n' ;;
  esac
  case "$IDENTITY_STATE" in
    ok)            printf '    邮件身份:   %s @ %s（DKIM 已生成）\n' "$DOMAIN" "$MAIL_HOST" ;;
    failed)        printf '    邮件身份:   未应用（sudo mailstack-manage domain set %s --server-ip <ip>）\n' "${DOMAIN:-<domain>}" ;;
    not-requested) printf '    邮件身份:   未配置（sudo mailstack-manage domain set <domain>）\n' ;;
  esac
  case "$ACCESS_STATE" in
    ok)      printf '    访问层:     已生成（%s）\n' "$ACCESS_MODE" ;;
    skipped) printf '    访问层:     未生成（--no-access-provision）\n' ;;
    failed)  printf '    访问层:     生成失败\n' ;;
  esac
  printf '    防火墙:     %s\n' "$(case "$FIREWALL_STATE" in ok) echo "已放行所需端口" ;; skipped) echo "未修改" ;; *) echo "$FIREWALL_STATE" ;; esac)"
  echo
  echo '    下一步:'
  echo "      1) sudo mailstack-manage status"
  echo "      2) 登录管理台：$([ "$ACCESS_MODE" = "ssh" ] && printf 'SSH 隧道后 http://127.0.0.1:%s/?login=1' "$ADMIN_PORT" || printf 'https://%s/' "${PANEL_HOST:-<panel-host>}")"
  echo '      3) 添加邮箱：sudo mailstack-manage account add alice@example.com --password-stdin'
  echo '      4) 证书：sudo mailstack-manage tls issue <host> --email <邮箱>'
  echo
  echo '    一行安装（复用示例）:'
  echo "      curl -fsSL https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/install.sh \\"
  echo "        | sudo bash -s -- --domain example.com --mail-host mail.example.com \\"
  echo "            --admin-user $ADMIN_USER --admin-password '<口令>' --access-mode caddy \\"
  echo '            --panel-host panel.example.com --acme-email ops@example.com'
  echo
  echo "    卸载: sudo bash $LIBEXEC_DIR/mailstack-uninstall${PREFIX_NORM:+ --prefix $PREFIX_NORM}"
}

run_uninstaller() {
  local args=(--non-interactive)
  [ -n "$PREFIX_NORM" ] && args+=(--prefix "$PREFIX_NORM")
  [ "$PURGE" -eq 1 ] && args+=(--purge)
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/uninstall.sh" ]; then
    say "转交卸载脚本"
    exec bash "$SCRIPT_DIR/uninstall.sh" "${args[@]}"
  fi
  if [ -n "$CHECKOUT_ROOT" ] && [ -f "$CHECKOUT_ROOT/deploy/uninstall.sh" ]; then
    exec bash "$CHECKOUT_ROOT/deploy/uninstall.sh" "${args[@]}"
  fi
  local dl
  dl="$(new_tmp)"
  download "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/uninstall.sh" "$dl/uninstall.sh"
  exec bash "$dl/uninstall.sh" "${args[@]}"
}

# ---------------------------------------------------------------------------
# upgrade / repair
# ---------------------------------------------------------------------------

require_existing_install() {
  [ -s "$ETC_DIR/install-args.conf" ] \
    || die "未找到既有安装（$ETC_DIR/install-args.conf）；$ACTION 前请先完成一次全新安装"
  return 0
}

run_upgrade_or_repair() {
  require_existing_install
  say "$([ "$ACTION" = "upgrade" ] && echo 升级 || echo 修复)（保留配置与数据）"
  local old_domain old_mail
  old_domain="$(state_get "$ETC_DIR/install-args.conf" DOMAIN || true)"
  old_mail="$(state_get "$ETC_DIR/install-args.conf" MAIL_HOST || true)"
  ACCESS_MODE="$(mode_from_state)"
  [ -n "$ACCESS_MODE" ] || ACCESS_MODE="ssh"
  [ -z "$DOMAIN" ] && DOMAIN="$old_domain"
  [ -z "$MAIL_HOST" ] && MAIL_HOST="$old_mail"

  local rollback=""
  if [ "$ACTION" = "upgrade" ]; then
    rollback="$(backup_current_files)"
    info "程序文件已备份：$rollback"
  fi

  ensure_users_and_groups
  create_directories
  install_binaries
  install_manage_script
  install_wrapper
  install_dist
  install_units
  adopt_uninstaller

  if [ "$NO_SYSTEMD" -eq 0 ] && [ -z "$PREFIX_NORM" ] && [ -d /run/systemd/system ] && need_cmd systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || warn "daemon-reload 失败"
    local unit
    for unit in "${INSTALL_UNITS[@]}"; do
      systemctl restart "$unit" >/dev/null 2>&1 || warn "restart $unit 失败"
    done
  else
    info "staging/无 systemd：跳过服务重启"
  fi

  if [ "$ACTION" = "upgrade" ]; then
    if ! health_check; then
      warn "健康检查失败：自动回滚"
      rollback_files "$rollback"
      die "升级失败，已回滚（日志：$LOG_FILE）"
    fi
    # 刷新访问层产物（幂等）
    if [ "$NO_ACCESS_PROVISION" -eq 0 ] && [ -x "$BIN_DIR/$MANAGE_NAME" ] && [ "$ACCESS_MODE" != "ssh" ]; then
      run_manage access set "$ACCESS_MODE" --no-reload >/dev/null 2>&1 || warn "访问层刷新失败"
    fi
  fi
  write_install_json
  print_summary
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

main() {
  setup_colors
  if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
    if [ -f "$SCRIPT_DIR/../Cargo.toml" ] && [ -d "$SCRIPT_DIR/../deploy" ]; then
      CHECKOUT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    fi
  else
    STDIN_IS_SCRIPT=1
  fi
  if [ "$#" -eq 0 ] && [ "$STDIN_IS_SCRIPT" -eq 0 ] && [ ! -t 0 ]; then
    usage >&2
    exit 2
  fi
  [ "$#" -eq 0 ] && [ "$STDIN_IS_SCRIPT" -eq 0 ] && [ -t 0 ] && INTERACTIVE=1

  parse_args "$@"
  normalize_prefix
  derive_paths
  [ "$INTERACTIVE" -eq 1 ] && interactive_wizard
  validate_options
  derive_paths
  init_logging

  if [ "$UNINSTALL" -eq 1 ]; then
    run_uninstaller
  fi

  acquire_lock
  check_environment

  case "$MODE" in
    release)    acquire_release ;;
    archive)    acquire_archive ;;
    binary-dir) acquire_binary_dir ;;
    source)     acquire_source ;;
    *) die "内部错误：未知安装模式 $MODE" ;;
  esac
  acquire_manage_script
  validate_artifacts

  if [ "$DRY_RUN" -eq 1 ]; then
    say "--dry-run：校验通过，未修改系统"
    info "来源：$MODE  身份：${DOMAIN:-<未配置>}  访问模式：$ACCESS_MODE  前缀：${PREFIX_NORM:-/}"
    exit 0
  fi

  if [ "$ACTION" = "upgrade" ] || [ "$ACTION" = "repair" ]; then
    run_upgrade_or_repair
    return 0
  fi

  ensure_users_and_groups
  create_directories
  install_binaries
  install_manage_script
  install_wrapper
  install_dist
  install_units
  adopt_uninstaller
  write_deployment_state
  write_install_json
  write_install_marker
  bootstrap_admin
  apply_identity
  provision_access
  apply_firewall
  services_start
  print_summary
  log_line INFO "install finished successfully"
}

main "$@"

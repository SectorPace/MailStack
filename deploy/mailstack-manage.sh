#!/usr/bin/env bash
# MailStack panel-style server management CLI + TUI.
#
#   sudo mailstack-manage                      # TUI menu
#   sudo mailstack-manage status [--json]
#   sudo mailstack-manage access set caddy
#   sudo mailstack-manage domain set example.com --mail-host mail.example.com
#   sudo mailstack-manage account add alice@example.com --password-stdin
#   sudo mailstack-manage tls issue mail.example.com --email ops@example.com
#   sudo mailstack-manage backup create --include-secrets
#   sudo mailstack-manage service restart mailstackd
#   sudo mailstack-manage doctor
#
# Privileged actions run through the installed wrapper
# (/usr/local/libexec/mailstack-privileged, stdin JSON). This script orchestrates
# deployment only: state in /etc/mailstack/install-args.conf, access artifacts in
# /etc/mailstack/access/. 8443/8444 stay on loopback.
#
# Env: MAILSTACK_PREFIX  staged install root (tests; default /)
# Log: /var/log/mailstack-manage.log (0600; staging: <prefix>/var/log/...)
# Exit: 0 ok, 1 runtime failure, 2 usage error

set -Eeuo pipefail
umask 022

VERSION="1.0.0"
REPO_SLUG="SectorPace/MailStack"
RAW_BRANCH="main"
UNITS=(mailstackd mailstack-web mailstack-imap mailstack-webmail)
ACCESS_MODES=(ssh caddy nginx ip-acme panel-domain cloudflared)
MAIL_PORTS=(25 465 587 143 993 110 995 4190)
WEB_PORTS=(80 443)

PREFIX="${MAILSTACK_PREFIX:-/}"
PREFIX_NORM=""
ETC_DIR=""
ACCESS_DIR=""
TLS_DIR=""
RUN_DIR=""
BIN_DIR=""
LIBEXEC_DIR=""
UNIT_DIR=""
BACKUP_DIR=""
DOMAINS_TABLE=""
MANUAL_BANS=""
STATE_FILE=""
INSTALL_JSON=""
LOG_FILE=""

ACCESS_MODE=""
ACCESS_MODE_DETAIL=""
DOMAIN=""
MAIL_HOST=""
ADMIN_USER="admin"
ADMIN_PORT="8443"
WEBMAIL_PORT="8444"
PANEL_HOST=""
WEBMAIL_HOST=""
PANEL_URL=""
WEBMAIL_URL=""
ACME_EMAIL=""
SERVER_IP=""
ACME_WEBROOT="/var/www/mailstack-acme"
IMAP_ENABLE="1"
MAILSTACK_VERSION="$VERSION"
STATE_LOADED=0
CHANGED=0
LAST_ERROR=""
ASSUME_YES=0
JSON_OUT=0

C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""

# ---------------------------------------------------------------------------
# output / audit log
# ---------------------------------------------------------------------------

setup_colors() {
  if [ -z "${NO_COLOR:-}" ] && [ -t 1 ]; then
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

audit() {
  local action="$1"
  local detail="${2:-}"
  log_line AUDIT "user=${SUDO_USER:-$(id -un)} action=$action detail=$detail"
}

say()  { printf '\n%s==> %s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%sWARN: %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
err()  { printf '%sERROR: %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; }
die()  { err "$*"; exit 1; }
die_usage() { err "$*"; printf '    用法见：mailstack-manage --help\n' >&2; exit 2; }

on_err() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 141 ]; then
    printf '%sERROR: mailstack-manage 第 %s 行失败（退出码 %s）%s\n' "$C_RED" "${BASH_LINENO[0]:-?}" "$rc" "$C_RESET" >&2
  fi
  exit "$rc"
}
trap on_err ERR

# ---------------------------------------------------------------------------
# paths / state
# ---------------------------------------------------------------------------

normalize_prefix() {
  [ -n "$PREFIX" ] || PREFIX="/"
  case "$PREFIX" in /*) : ;; *) die_usage "--prefix 必须是绝对路径：$PREFIX" ;; esac
  while [ "$PREFIX" != "/" ] && [ "${PREFIX%/}" != "$PREFIX" ]; do PREFIX="${PREFIX%/}"; done
  if [ "$PREFIX" = "/" ]; then PREFIX_NORM=""; return 0; fi
  printf '%s' "$PREFIX" | grep -Eq '^/[A-Za-z0-9._/-]+$' || die_usage "前缀字符不合法：$PREFIX"
  case "/$PREFIX/" in *"/../"*) die_usage "前缀不得包含 .. 段：$PREFIX" ;; esac
  PREFIX="$(realpath -m -- "$PREFIX")" || die_usage "前缀规范化失败：$PREFIX"
  case "${PREFIX#/}" in */*) : ;; *) die_usage "前缀至少两级：$PREFIX" ;; esac
  PREFIX_NORM="$PREFIX"
}

prefix_path() { printf '%s%s' "$PREFIX_NORM" "$1"; }

derive_paths() {
  ETC_DIR="$(prefix_path /etc/mailstack)"
  ACCESS_DIR="$ETC_DIR/access"
  TLS_DIR="$ETC_DIR/tls"
  RUN_DIR="$(prefix_path /run/mailstack)"
  BIN_DIR="$(prefix_path /usr/local/bin)"
  LIBEXEC_DIR="$(prefix_path /usr/local/libexec)"
  UNIT_DIR="$(prefix_path /etc/systemd/system)"
  BACKUP_DIR="$(prefix_path /var/backups/mailstack)"
  DOMAINS_TABLE="$(prefix_path /etc/postfix)/mailstack_domains"
  MANUAL_BANS="$(prefix_path /var/lib/mailstack)/manual-bans.json"
  STATE_FILE="$ETC_DIR/install-args.conf"
  INSTALL_JSON="$ETC_DIR/install.json"
  LOG_FILE="$(prefix_path /var/log/mailstack-manage.log)"
}

init_logging() {
  mkdir -p "$(dirname -- "$LOG_FILE")" 2>/dev/null || true
  : >> "$LOG_FILE" 2>/dev/null || true
  chmod 0600 "$LOG_FILE" 2>/dev/null || true
  return 0
}

load_state() {
  ACCESS_MODE=""
  ACCESS_MODE_DETAIL=""
  DOMAIN=""
  MAIL_HOST=""
  ADMIN_USER="admin"
  ADMIN_PORT="8443"
  WEBMAIL_PORT="8444"
  PANEL_HOST=""
  WEBMAIL_HOST=""
  PANEL_URL=""
  WEBMAIL_URL=""
  ACME_EMAIL=""
  SERVER_IP=""
  IMAP_ENABLE="1"
  MAILSTACK_VERSION="$VERSION"
  STATE_LOADED=0
  if [ -f "$STATE_FILE" ]; then
    local line key value
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%$'\r'}"
      case "$line" in ''|'#'*) continue ;; esac
      key="${line%%=*}"
      value="${line#*=}"
      value="${value%\'}"
      value="${value#\'}"
      case "$value" in
        *$'\n'*|*$'\r'*|*'$('*|*'`'*|*';'*|*'|'*|*'&'*) warn "忽略状态文件中的可疑 $key 值"; continue ;;
      esac
      case "$key" in
        ACCESS_MODE)
          case "$value" in local|direct|caddy) : ;; *) warn "状态文件 ACCESS_MODE 非法：$value"; continue ;; esac ;;
        ACCESS_MODE_DETAIL)
          case "$value" in ssh|caddy|nginx|ip-acme|panel-domain|cloudflared) : ;; *) warn "状态文件 ACCESS_MODE_DETAIL 非法：$value"; continue ;; esac ;;
        DOMAIN|MAIL_HOST|PANEL_HOST|WEBMAIL_HOST)
          valid_hostname "$value" || { warn "状态文件 $key 非主机名：$value"; continue; } ;;
        ADMIN_USER)
          printf '%s' "$value" | grep -Eq '^[A-Za-z][A-Za-z0-9_.-]{2,31}$' || { warn "状态文件 ADMIN_USER 非法"; continue; } ;;
        ADMIN_PORT|WEBMAIL_PORT)
          case "$value" in ''|*[!0-9]*) warn "状态文件 $key 非法：$value"; continue ;; esac
          [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || { warn "状态文件 $key 越界"; continue; } ;;
        SERVER_IP)
          [ -n "$value" ] && valid_ipv4 "$value" || { warn "状态文件 SERVER_IP 非法"; continue; } ;;
        ACME_EMAIL)
          [ -n "$value" ] && valid_email "$value" || { warn "状态文件 ACME_EMAIL 非法"; continue; } ;;
        PANEL_URL|WEBMAIL_URL)
          printf '%s' "$value" | grep -Eq '^https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+$' || { warn "状态文件 $key 非法"; continue; } ;;
        IMAP_ENABLE)
          case "$value" in 0|1) : ;; *) warn "状态文件 IMAP_ENABLE 非法"; continue ;; esac ;;
        MAILSTACK_VERSION)
          printf '%s' "$value" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+-]+)?$' || { warn "状态文件 MAILSTACK_VERSION 非法"; continue; } ;;
      esac
      printf -v "$key" '%s' "$value"
    done < "$STATE_FILE"
    STATE_LOADED=1
  fi
  [ -n "${ADMIN_PORT:-}" ] || ADMIN_PORT="8443"
  [ -n "${WEBMAIL_PORT:-}" ] || WEBMAIL_PORT="8444"
  [ -n "${ADMIN_USER:-}" ] || ADMIN_USER="admin"
  [ -n "${MAILSTACK_VERSION:-}" ] || MAILSTACK_VERSION="$VERSION"
  return 0
}

write_state() {
  local canonical detail
  detail="$(current_detail)"
  canonical="$(canonical_mode "$detail")"
  mkdir -p "$ETC_DIR"
  local tmp="$STATE_FILE.tmp.$$"
  {
    printf '# 由 deploy/install.sh / deploy/mailstack-manage.sh 维护；mode.rs 只读 ACCESS_MODE。\n'
    printf 'ACCESS_MODE=%q\n' "$canonical"
    printf 'ACCESS_MODE_DETAIL=%q\n' "$detail"
    printf 'MAILSTACK_VERSION=%q\n' "$MAILSTACK_VERSION"
    printf 'INSTALLED_AT=%q\n' "${INSTALLED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
    printf 'UPDATED_AT=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'DOMAIN=%q\n' "$DOMAIN"
    printf 'MAIL_HOST=%q\n' "$MAIL_HOST"
    printf 'ADMIN_USER=%q\n' "$ADMIN_USER"
    printf 'ADMIN_PORT=%q\n' "$ADMIN_PORT"
    printf 'WEBMAIL_PORT=%q\n' "$WEBMAIL_PORT"
    printf 'PANEL_HOST=%q\n' "$PANEL_HOST"
    printf 'WEBMAIL_HOST=%q\n' "$WEBMAIL_HOST"
    printf 'PANEL_URL=%q\n' "$PANEL_URL"
    printf 'WEBMAIL_URL=%q\n' "$WEBMAIL_URL"
    printf 'ACME_EMAIL=%q\n' "$ACME_EMAIL"
    printf 'SERVER_IP=%q\n' "$SERVER_IP"
    printf 'IMAP_ENABLE=%q\n' "$IMAP_ENABLE"
  } > "$tmp"
  chmod 0600 "$tmp"; chown root:root "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$STATE_FILE"
  ACCESS_MODE="$canonical"
  ACCESS_MODE_DETAIL="$detail"
}

write_access_state() {
  local detail
  detail="$(current_detail)"
  mkdir -p "$ACCESS_DIR"
  chmod 0750 "$ACCESS_DIR" 2>/dev/null || true
  printf '%s\n' "$detail" > "$ACCESS_DIR/mode.tmp.$$"
  mv -f -- "$ACCESS_DIR/mode.tmp.$$" "$ACCESS_DIR/mode"
  {
    printf 'ACCESS_MODE=%s\nACCESS_MODE_DETAIL=%s\n' "$(canonical_mode "$detail")" "$detail"
    printf 'PANEL_HOST=%s\nWEBMAIL_HOST=%s\n' "$PANEL_HOST" "$WEBMAIL_HOST"
    printf 'PANEL_URL=%s\nWEBMAIL_URL=%s\n' "$PANEL_URL" "$WEBMAIL_URL"
    printf 'ADMIN_PORT=%s\nWEBMAIL_PORT=%s\n' "$ADMIN_PORT" "$WEBMAIL_PORT"
    printf 'ACME_EMAIL=%s\nSERVER_IP=%s\n' "$ACME_EMAIL" "$SERVER_IP"
  } > "$ACCESS_DIR/access.env.tmp.$$"
  chmod 0640 "$ACCESS_DIR/access.env.tmp.$$"
  mv -f -- "$ACCESS_DIR/access.env.tmp.$$" "$ACCESS_DIR/access.env"
}

# ---------------------------------------------------------------------------
# access mode mapping
# ---------------------------------------------------------------------------

normalize_mode() {
  local m
  m="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$m" in
    ssh|local|loopback)            printf 'ssh' ;;
    caddy)                         printf 'caddy' ;;
    nginx)                         printf 'nginx' ;;
    ip-acme|ip_acme|ipacme|direct) printf 'ip-acme' ;;
    panel-domain|panel_domain)     printf 'panel-domain' ;;
    cloudflared|cloudflare)        printf 'cloudflared' ;;
    *) return 1 ;;
  esac
}

canonical_mode() {
  case "$1" in
    ssh)                                  printf 'local' ;;
    caddy|nginx|panel-domain|cloudflared) printf 'caddy' ;;
    ip-acme)                              printf 'direct' ;;
    *)                                    printf 'local' ;;
  esac
}

current_detail() {
  if [ -n "${ACCESS_MODE_DETAIL:-}" ]; then
    case "$ACCESS_MODE_DETAIL" in
      ssh|caddy|nginx|ip-acme|panel-domain|cloudflared) printf '%s' "$ACCESS_MODE_DETAIL"; return 0 ;;
    esac
  fi
  case "${ACCESS_MODE:-local}" in
    local|"") printf 'ssh' ;;
    caddy)    printf 'caddy' ;;
    direct)   printf 'ip-acme' ;;
    *)        printf 'ssh' ;;
  esac
}

default_panel_host() { printf 'panel.%s' "$DOMAIN"; }
default_webmail_host() { printf 'webmail.%s' "$DOMAIN"; }

panel_url_for() {
  case "$1" in ssh) printf 'http://127.0.0.1:%s/' "$ADMIN_PORT" ;; *) [ -n "$2" ] && printf 'https://%s/' "$2" ;; esac
  return 0
}
webmail_url_for() {
  case "$1" in ssh) printf 'http://127.0.0.1:%s/' "$WEBMAIL_PORT" ;; *) [ -n "$2" ] && printf 'https://%s/' "$2" ;; esac
  return 0
}

# ---------------------------------------------------------------------------
# validation / misc helpers
# ---------------------------------------------------------------------------

require_root() { [ "$(id -u)" -eq 0 ] || die "需要 root 权限（sudo mailstack-manage ...）"; }
have_python3() { command -v python3 >/dev/null 2>&1; }
systemd_live() { [ -z "$PREFIX_NORM" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

json_quote() {
  local s="${1:-}"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/ }"; s="${s//$'\r'/ }"; s="${s//$'\t'/ }"
  printf '"%s"' "$s"
}

json_ok()    { case "$1" in *'"ok":true'*) return 0 ;; *) return 1 ;; esac; }
json_error() { printf '%s' "$1" | sed -n 's/.*"error":"\([^"]*\)".*/\1/p' | head -1; }

json_pretty() {
  local raw="${1:-}"
  if have_python3 && [ -n "$raw" ]; then
    printf '%s' "$raw" | python3 -c '
import json, sys
text = sys.stdin.read()
try:
    print(json.dumps(json.loads(text), ensure_ascii=False, indent=2))
except Exception:
    sys.stdout.write(text)' 2>/dev/null && return 0
  fi
  printf '%s\n' "$raw"
}

json_data() {
  local raw="${1:-}"
  if have_python3 && [ -n "$raw" ]; then
    printf '%s' "$raw" | python3 -c '
import json, sys
try:
    print(json.dumps(json.load(sys.stdin).get("data"), ensure_ascii=False, indent=2))
except Exception:
    pass' 2>/dev/null && return 0
  fi
  printf '%s\n' "$raw"
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

valid_port() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
  return 0
}

detect_server_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}' \
    || true
  return 0
}

setup_json_value() {
  local key="$1"
  [ -s "$ETC_DIR/setup.json" ] || return 1
  sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC_DIR/setup.json" | head -1
}

write_if_changed() {
  local path="$1"
  local mode="$2"
  local content="$3"
  mkdir -p "$(dirname -- "$path")"
  if [ -f "$path" ] && [ "$(cat -- "$path")" = "$content" ]; then
    info "未变化：$path"
    return 0
  fi
  local tmp="$path.tmp.$$"
  printf '%s\n' "$content" > "$tmp"
  chmod "$mode" "$tmp"; chown root:root "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$path"
  CHANGED=1
  info "已写入：$path"
}

confirm_or_die() {
  local prompt="$1"
  [ "$ASSUME_YES" -eq 1 ] && return 0
  [ -t 0 ] || die "非交互模式需要 --yes/--confirm：$prompt"
  local answer=""
  printf '%s [y/N] ' "$prompt" >&2
  IFS= read -r answer || answer=""
  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    y|yes) return 0 ;;
    *) die "已取消" ;;
  esac
}

# ---------------------------------------------------------------------------
# privileged calls
# ---------------------------------------------------------------------------

priv_endpoint() {
  if [ -x "$LIBEXEC_DIR/mailstack-privileged" ]; then
    printf '%s' "$LIBEXEC_DIR/mailstack-privileged"
  elif [ -x "$BIN_DIR/mailstackctl" ]; then
    printf '%s' "$BIN_DIR/mailstackctl"
  else
    die "找不到特权入口：$LIBEXEC_DIR/mailstack-privileged（先运行 deploy/install.sh）"
  fi
}

priv_call() {
  local action="$1" data="${2:-{\}}" endpoint out rc=0
  endpoint="$(priv_endpoint)"
  local -a argv=("$endpoint")
  if [ ! -x "$LIBEXEC_DIR/mailstack-privileged" ] && [ -n "$PREFIX_NORM" ]; then
    argv+=(--privileged-stdin --config-dir "$PREFIX_NORM")
  fi
  out="$(printf '{"action":%s,"data":%s}' "$(json_quote "$action")" "$data" \
    | "${argv[@]}" 2>&1)" || rc=$?
  LAST_ERROR=""
  if [ "$rc" -ne 0 ]; then
    LAST_ERROR="特权入口退出码 $rc：$(printf '%s' "$out" | head -1)"
    err "动作 $action 失败：$LAST_ERROR"
    return 1
  fi
  if ! json_ok "$out"; then
    LAST_ERROR="$(json_error "$out")"
    [ -n "$LAST_ERROR" ] || LAST_ERROR="$out"
    err "动作 $action 失败：$LAST_ERROR"
    return 1
  fi
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# systemd / services
# ---------------------------------------------------------------------------

unit_file() { printf '%s/%s.service' "$UNIT_DIR" "$1"; }

restart_units() {
  local units=("$@")
  [ "${#units[@]}" -gt 0 ] || units=("${UNITS[@]}")
  if ! systemd_live; then
    info "未检测到 systemd（staging/容器）：跳过重启"
    local u
    for u in "${units[@]}"; do printf '    systemctl restart %s\n' "$u"; done
    return 0
  fi
  systemctl daemon-reload >/dev/null 2>&1 || warn "daemon-reload 失败"
  local u
  for u in "${units[@]}"; do
    if systemctl restart "$u" >/dev/null 2>&1; then info "已重启：$u"; else warn "restart $u 失败"; fi
  done
}

service_control() {
  local verb="$1"
  local unit="${2:-}"
  local -a targets=()
  if [ -n "$unit" ]; then
    printf '%s\n' "${UNITS[@]}" | grep -qx "$unit" || die_usage "未知 unit：$unit（可选 ${UNITS[*]}）"
    targets=("$unit")
  else
    targets=("${UNITS[@]}")
  fi
  if ! systemd_live; then
    info "staging/无 systemd：跳过 service $verb"
    local u
    for u in "${targets[@]}"; do printf '    systemctl %s %s\n' "$verb" "$u"; done
    return 0
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  local u
  for u in "${targets[@]}"; do
    if systemctl "$verb" "$u" >/dev/null 2>&1; then
      info "$verb $u: ok"
    else
      warn "$verb $u 失败（journalctl -u $u）"
    fi
  done
}

assert_loopback_only() {
  local f
  for f in "$UNIT_DIR/mailstack-web.service" "$UNIT_DIR/mailstack-webmail.service"; do
    [ -f "$f" ] || continue
    if grep -Eq -- '--bind[= ][^ ]*0\.0\.0\.0' "$f"; then
      warn "$f 把 --bind 指向 0.0.0.0；8443/8444 只允许 127.0.0.1"
    fi
  done
  if command -v ss >/dev/null 2>&1; then
    local line
    if line="$(ss -lntp 2>/dev/null | grep -E ':(8443|8444)\b' | grep -v '127\.0\.0\.1' || true)" && [ -n "$line" ]; then
      warn "检测到非回环监听：$line"
    fi
  fi
}

# ---------------------------------------------------------------------------
# access artifacts
# ---------------------------------------------------------------------------

gen_caddyfile() {
  local panel="$1"
  local webmail="$2"
  local email="$3"
  local email_line='	# email 未设置：可用 --acme-email 指定 ACME 账户邮箱'
  [ -n "$email" ] && email_line="	email $email"
  cat <<EOF
# 由 mailstack-manage 生成；刷新：sudo mailstack-manage access set caddy
{
$email_line
}

$panel {
	encode zstd gzip
	reverse_proxy 127.0.0.1:${ADMIN_PORT} {
		header_up Host {host}
		header_up X-Forwarded-Proto {scheme}
	}
}

$webmail {
	encode zstd gzip
	reverse_proxy 127.0.0.1:${WEBMAIL_PORT} {
		header_up Host {host}
		header_up X-Forwarded-Proto {scheme}
	}
}
EOF
}

gen_nginx_http() {
  local panel="$1"
  local webmail="$2"
  cat <<EOF
# 由 mailstack-manage 生成；TLS 用 certbot/acme.sh 补
#   sudo apt install -y certbot python3-certbot-nginx
#   sudo certbot --nginx -d $panel -d $webmail
#   sudo /root/.acme.sh/acme.sh --issue -d $panel -d $webmail --nginx

server {
    listen 80;
    listen [::]:80;
    server_name $panel;
    client_max_body_size 40m;
    location / {
        proxy_pass http://127.0.0.1:${ADMIN_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name $webmail;
    client_max_body_size 40m;
    location / {
        proxy_pass http://127.0.0.1:${WEBMAIL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
    }
}
EOF
}

gen_nginx_tls() {
  local panel="$1"
  local webmail="$2"
  cat <<EOF
# 由 mailstack-manage 生成；证书来自 mailstackctl setup.cert.issue
#   sudo mailstack-manage tls issue $panel --email <邮箱>
#   sudo mailstack-manage tls issue $webmail --email <邮箱>

server {
    listen 80;
    listen [::]:80;
    server_name $panel $webmail;
    location /.well-known/acme-challenge/ { root $ACME_WEBROOT; default_type text/plain; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $panel;
    ssl_certificate     $TLS_DIR/$panel/fullchain.pem;
    ssl_certificate_key $TLS_DIR/$panel/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 40m;
    location / {
        proxy_pass http://127.0.0.1:${ADMIN_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $webmail;
    ssl_certificate     $TLS_DIR/$webmail/fullchain.pem;
    ssl_certificate_key $TLS_DIR/$webmail/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 40m;
    location / {
        proxy_pass http://127.0.0.1:${WEBMAIL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
    }
}
EOF
}

gen_cloudflared_config() {
  local panel="$1"
  local webmail="$2"
  local tunnel="${CLOUDFLARE_TUNNEL:-REPLACE_WITH_TUNNEL_UUID}"
  cat <<EOF
# 由 mailstack-manage 生成；Tunnel 指向回环，公网 TLS 由 Cloudflare 终止
# 1) sudo cloudflared tunnel login && sudo cloudflared tunnel create mailstack
# 2) sudo CLOUDFLARE_TUNNEL=<id> mailstack-manage access set cloudflared
# 3) CNAME：$panel / $webmail → <id>.cfargotunnel.com
tunnel: $tunnel
credentials-file: /etc/cloudflared/$tunnel.json
no-autoupdate: true

ingress:
  - hostname: $panel
    service: http://127.0.0.1:${ADMIN_PORT}
    originRequest: { httpHostHeader: $panel }
  - hostname: $webmail
    service: http://127.0.0.1:${WEBMAIL_PORT}
    originRequest: { httpHostHeader: $webmail }
  - service: http_status:404
EOF
}

gen_cloudflared_unit() {
  local bin
  bin="$(command -v cloudflared 2>/dev/null || printf '/usr/bin/cloudflared')"
  cat <<EOF
[Unit]
Description=MailStack Cloudflare Tunnel (panel/webmail access)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart=$bin --no-autoupdate --config $ACCESS_DIR/cloudflared/config.yml tunnel run
Restart=on-failure
RestartSec=5s
User=root
Group=root
ProtectSystem=strict
ReadWritePaths=$ACCESS_DIR/cloudflared /etc/cloudflared
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
}

gen_ssh_files() {
  local tunnel="ssh -N -L ${ADMIN_PORT}:127.0.0.1:${ADMIN_PORT} -L ${WEBMAIL_PORT}:127.0.0.1:${WEBMAIL_PORT} <user>@<server>"
  write_if_changed "$ACCESS_DIR/ssh/README.txt" 0644 "$(cat <<EOF
MailStack 访问模式 = ssh（默认）
隧道：$tunnel
管理台：http://127.0.0.1:${ADMIN_PORT}/?login=1
Webmail：http://127.0.0.1:${WEBMAIL_PORT}/
切换公网访问：sudo mailstack-manage access set caddy|nginx|panel-domain|ip-acme|cloudflared
EOF
)"
  write_if_changed "$ACCESS_DIR/ssh/tunnel.sh" 0755 "$(cat <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
target="\${1:-<user>@<server>}"
exec ssh -N -o ExitOnForwardFailure=yes \\
  -L ${ADMIN_PORT}:127.0.0.1:${ADMIN_PORT} -L ${WEBMAIL_PORT}:127.0.0.1:${WEBMAIL_PORT} "\$target"
EOF
)"
}

sync_caddy_live() {
  local canonical="$ACCESS_DIR/caddy/Caddyfile"
  local live="$(prefix_path /etc/caddy/mailstack.caddy)"
  local main="$(prefix_path /etc/caddy/Caddyfile)"
  if ! command -v caddy >/dev/null 2>&1; then
    info "未安装 caddy：配置在 $canonical（安装后重跑本命令）"
    return 0
  fi
  write_if_changed "$live" 0644 "$(cat -- "$canonical")"
  if [ -f "$main" ] && grep -qF 'import /etc/caddy/mailstack.caddy' "$main"; then
    :
  else
    mkdir -p "$(dirname -- "$main")"
    if [ -f "$main" ]; then
      cp -a -- "$main" "$main.mailstack.bak"
      printf '\nimport /etc/caddy/mailstack.caddy\n' >> "$main"
      info "已向 $main 追加 import（备份 .mailstack.bak）"
    else
      printf 'import /etc/caddy/mailstack.caddy\n' > "$main"
    fi
    CHANGED=1
  fi
  if caddy validate --config "$main" --adapter caddyfile >/dev/null 2>&1; then
    info "caddy validate 通过"
    if systemd_live; then
      systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 \
        || warn "caddy reload/restart 失败"
      info "已 reload caddy"
    fi
  else
    warn "caddy validate 失败（未 reload）"
  fi
}

sync_nginx_live() {
  local variant="$1"
  local canonical="$ACCESS_DIR/nginx/mailstack-panel.conf"
  local live="$(prefix_path /etc/nginx/conf.d/mailstack-panel.conf)"
  if ! command -v nginx >/dev/null 2>&1; then
    info "未安装 nginx：配置在 $canonical（安装后重跑本命令）"
    return 0
  fi
  if [ "$variant" = "tls" ]; then
    local h
    for h in "$PANEL_HOST" "$WEBMAIL_HOST"; do
      [ -n "$h" ] || continue
      if [ ! -f "$TLS_DIR/$h/fullchain.pem" ] || [ ! -f "$TLS_DIR/$h/privkey.pem" ]; then
        warn "证书未就绪：$TLS_DIR/$h（先 tls issue，再重跑本命令）"
        return 0
      fi
    done
  fi
  write_if_changed "$live" 0644 "$(cat -- "$canonical")"
  if nginx -t >/dev/null 2>&1; then
    info "nginx -t 通过"
    if systemd_live; then
      systemctl reload nginx >/dev/null 2>&1 && info "已 reload nginx" || warn "nginx reload 失败"
    fi
  else
    warn "nginx -t 失败（未 reload）"
  fi
}

sync_cloudflared_live() {
  local cfg="$ACCESS_DIR/cloudflared/config.yml" tunnel
  write_if_changed "$ACCESS_DIR/cloudflared/mailstack-cloudflared.service" 0644 "$(gen_cloudflared_unit)"
  write_if_changed "$UNIT_DIR/mailstack-cloudflared.service" 0644 "$(cat -- "$ACCESS_DIR/cloudflared/mailstack-cloudflared.service")"
  tunnel="$(sed -n 's/^tunnel:[[:space:]]*//p' "$cfg" 2>/dev/null | head -1)"
  if [ -z "$tunnel" ] || [ "${tunnel#REPLACE_WITH_TUNNEL_UUID}" != "$tunnel" ]; then
    warn "cloudflared 配置仍是占位符：$cfg"
    info "  完成云侧配置后：sudo CLOUDFLARE_TUNNEL=<id> mailstack-manage access set cloudflared"
    return 0
  fi
  command -v cloudflared >/dev/null 2>&1 || { info "未安装 cloudflared（安装后启动 mailstack-cloudflared）"; return 0; }
  if systemd_live; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now mailstack-cloudflared >/dev/null 2>&1 \
      && info "已 enable --now mailstack-cloudflared" || warn "mailstack-cloudflared 启动失败"
  fi
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

print_services_line() {
  local u state
  for u in "${UNITS[@]}"; do
    if [ ! -f "$(unit_file "$u")" ]; then
      printf '    %-22s %s\n' "$u" '未安装'
    elif systemd_live; then
      state="$(systemctl is-active "$u" 2>/dev/null || true)"
      printf '    %-22s %s\n' "$u" "${state:-unknown}"
    else
      printf '    %-22s %s\n' "$u" '（staging/无 systemd）'
    fi
  done
}

print_certs_line() {
  local found=0 d host end
  if [ -d "$TLS_DIR" ]; then
    for d in "$TLS_DIR"/*/; do
      [ -d "$d" ] && [ -f "$d/fullchain.pem" ] || continue
      host="$(basename -- "$d")"
      end=""
      command -v openssl >/dev/null 2>&1 && end="$(openssl x509 -in "$d/fullchain.pem" -noout -enddate 2>/dev/null | sed -n 's/^notAfter=//p')"
      printf '    %-32s %s\n' "$host" "${end:-（无法解析）}"
      found=$((found + 1))
    done
  fi
  [ "$found" -gt 0 ] || info "（无证书：sudo mailstack-manage tls issue <host> --email <邮箱>）"
  return 0
}

print_domains_line() {
  local list=""
  [ -f "$DOMAINS_TABLE" ] && list="$(awk 'NF { print $1 }' "$DOMAINS_TABLE" 2>/dev/null || true)"
  if [ -n "$list" ]; then printf '%s\n' "$list" | sed 's/^/    - /'
  else info "（域名表为空：sudo mailstack-manage domain set example.com）"; fi
}

print_disk_line() {
  if command -v df >/dev/null 2>&1; then
    df -Pk "$(prefix_path /var/lib)" 2>/dev/null | awk 'NR==2 { printf "    %s 可用 %.1f GiB（使用 %s%%）\n", $6, $4/1048576, $5 }' || true
  fi
}

status_json() {
  local svc_json="{" first=1 u state cert_json="[" cfirst=1 d host end admin_conf=false wizard=false
  for u in "${UNITS[@]}"; do
    if [ -f "$(unit_file "$u")" ] && systemd_live; then state="$(systemctl is-active "$u" 2>/dev/null || true)"; else state="unknown"; fi
    [ "$first" -eq 1 ] || svc_json="$svc_json,"
    first=0
    svc_json="$svc_json$(printf '"%s":"%s"' "$u" "${state:-unknown}")"
  done
  svc_json="$svc_json}"
  if [ -d "$TLS_DIR" ]; then
    for d in "$TLS_DIR"/*/; do
      [ -d "$d" ] && [ -f "$d/fullchain.pem" ] || continue
      host="$(basename -- "$d")"; end=""
      command -v openssl >/dev/null 2>&1 && end="$(openssl x509 -in "$d/fullchain.pem" -noout -enddate 2>/dev/null | sed -n 's/^notAfter=//p')"
      [ "$cfirst" -eq 1 ] || cert_json="$cert_json,"
      cfirst=0
      cert_json="$cert_json$(printf '{"host":"%s","notAfter":"%s"}' "$(json_escape_local "$host")" "$(json_escape_local "$end")")"
    done
  fi
  cert_json="$cert_json]"
  [ -s "$ETC_DIR/admin.json" ] && admin_conf=true
  grep -Eq '"wizardCompleted"[[:space:]]*:[[:space:]]*true' "$ETC_DIR/setup.json" 2>/dev/null && wizard=true
  cat <<EOF
{
  "version": "$(json_escape_local "$MAILSTACK_VERSION")",
  "stateLoaded": $([ "$STATE_LOADED" -eq 1 ] && echo true || echo false),
  "prefix": "$(json_escape_local "${PREFIX_NORM:-/}")",
  "domain": "$(json_escape_local "$DOMAIN")",
  "mailHost": "$(json_escape_local "$MAIL_HOST")",
  "serverIp": "$(json_escape_local "$SERVER_IP")",
  "accessMode": "$(json_escape_local "$(canonical_mode "$(current_detail)")")",
  "accessModeDetail": "$(json_escape_local "$(current_detail)")",
  "panelUrl": "$(json_escape_local "$PANEL_URL")",
  "webmailUrl": "$(json_escape_local "$WEBMAIL_URL")",
  "adminUser": "$(json_escape_local "$ADMIN_USER")",
  "adminConfigured": $admin_conf,
  "identityConfigured": $([ -s "$ETC_DIR/setup.json" ] && echo true || echo false),
  "wizardCompleted": $wizard,
  "services": $svc_json,
  "certificates": $cert_json
}
EOF
}

json_escape_local() {
  local s="${1:-}"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/ }"; s="${s//$'\r'/ }"
  printf '%s' "$s"
}

cmd_status() {
  require_root
  load_state
  if [ "$JSON_OUT" -eq 1 ]; then
    status_json
    return 0
  fi
  local detail
  detail="$(current_detail)"
  say "MailStack 状态"
  info "版本：$MAILSTACK_VERSION    前缀：${PREFIX_NORM:-/}"
  info "部署状态：$STATE_FILE"
  [ "$STATE_LOADED" -eq 1 ] || warn "未找到部署状态（尚未安装？可用 MAILSTACK_PREFIX）"
  info "邮件域名：${DOMAIN:-（未设置）}    邮件主机：${MAIL_HOST:-（未设置）}"
  info "服务器 IP：${SERVER_IP:-（未设置）}"
  info "访问模式：$detail（ACCESS_MODE=$(canonical_mode "$detail")）"
  info "管理员：$ADMIN_USER（凭证：$([ -s "$ETC_DIR/admin.json" ] && echo 已配置 || echo 未配置)）"
  info "管理台：${PANEL_URL:-（未配置）}    内部 127.0.0.1:${ADMIN_PORT}"
  info "Webmail：${WEBMAIL_URL:-（未配置）}    内部 127.0.0.1:${WEBMAIL_PORT}"
  if [ -s "$ETC_DIR/setup.json" ]; then
    local wizard="未完成"
    grep -Eq '"wizardCompleted"[[:space:]]*:[[:space:]]*true' "$ETC_DIR/setup.json" 2>/dev/null && wizard="已完成"
    info "身份：setup.json 已配置（向导 $wizard）"
  else
    info "身份：未配置（sudo mailstack-manage domain set <domain>）"
  fi
  echo
  echo '    邮件域名:'
  print_domains_line
  echo
  echo '    服务:'
  print_services_line
  echo
  echo '    TLS 证书:'
  print_certs_line
  echo
  echo '    磁盘:'
  print_disk_line
  echo
  echo '    访问层:'
  case "$detail" in
    ssh) info "SSH 隧道（$ACCESS_DIR/ssh/README.txt）" ;;
    caddy) info "Caddy（$ACCESS_DIR/caddy/Caddyfile）" ;;
    nginx) info "nginx（$ACCESS_DIR/nginx/mailstack-panel.conf）" ;;
    ip-acme) info "nginx TLS + ACME（$ACCESS_DIR/nginx/mailstack-panel.conf）" ;;
    panel-domain) info "独立面板域名反代（$ACCESS_DIR）" ;;
    cloudflared) info "Cloudflare Tunnel（$ACCESS_DIR/cloudflared/config.yml）" ;;
  esac
  assert_loopback_only
}

# ---------------------------------------------------------------------------
# access show / set
# ---------------------------------------------------------------------------

usage_access_set() {
  cat <<EOF
用法: mailstack-manage access set <模式> [选项]

模式: ${ACCESS_MODES[*]}（旧值 local/caddy/direct 也接受）
选项:
  --panel-host HOST --webmail-host HOST --acme-email EMAIL
  --server-ip IP --acme-webroot DIR --no-reload
EOF
}

cmd_access_show() {
  require_root
  load_state
  local detail
  detail="$(current_detail)"
  say "访问模式"
  info "模式：$detail（ACCESS_MODE=$(canonical_mode "$detail")）"
  info "管理台：${PANEL_URL:-（未配置）} 内部 127.0.0.1:${ADMIN_PORT}"
  info "Webmail：${WEBMAIL_URL:-（未配置）} 内部 127.0.0.1:${WEBMAIL_PORT}"
  info "面板主机：${PANEL_HOST:-（无，ssh 模式）}    Webmail 主机：${WEBMAIL_HOST:-（无）}"
  info "ACME 邮箱：${ACME_EMAIL:-（未设置）}    服务器 IP：${SERVER_IP:-（未设置）}"
  echo
  echo '    模式矩阵:'
  printf '    %-13s %-34s %s\n' '模式' '入口' 'TLS'
  printf '    %-13s %-34s %s\n' 'ssh' '回环 + SSH 隧道' '不需要'
  printf '    %-13s %-34s %s\n' 'caddy' 'Caddy 反代 panel/webmail' 'Caddy 自动 ACME'
  printf '    %-13s %-34s %s\n' 'nginx' 'nginx 反代（80）' 'certbot/acme.sh'
  printf '    %-13s %-34s %s\n' 'ip-acme' 'nginx 443 反代' 'mailstackctl ACME'
  printf '    %-13s %-34s %s\n' 'panel-domain' '独立面板域名反代' 'Caddy 或 nginx+ACME'
  printf '    %-13s %-34s %s\n' 'cloudflared' 'Cloudflare Tunnel → 回环' 'Cloudflare 边缘'
  echo
  if [ -d "$ACCESS_DIR" ]; then
    echo '    已生成文件:'
    find "$ACCESS_DIR" -maxdepth 2 -type f -printf '    %p\n' 2>/dev/null | sort
  else
    info "（无：sudo mailstack-manage access set <mode>）"
  fi
  assert_loopback_only
}

apply_access_artifacts() {
  local mode="$1"
  case "$mode" in
    ssh) gen_ssh_files ;;
    caddy)
      write_if_changed "$ACCESS_DIR/caddy/Caddyfile" 0644 "$(gen_caddyfile "$PANEL_HOST" "$WEBMAIL_HOST" "$ACME_EMAIL")"
      sync_caddy_live ;;
    nginx)
      write_if_changed "$ACCESS_DIR/nginx/mailstack-panel.conf" 0644 "$(gen_nginx_http "$PANEL_HOST" "$WEBMAIL_HOST")"
      write_if_changed "$ACCESS_DIR/nginx/README.txt" 0644 "$(cat <<EOF
访问模式 = nginx
配置：$ACCESS_DIR/nginx/mailstack-panel.conf
加 TLS：certbot --nginx -d $PANEL_HOST -d $WEBMAIL_HOST
     或 /root/.acme.sh/acme.sh --issue -d $PANEL_HOST -d $WEBMAIL_HOST --nginx
EOF
)"
      sync_nginx_live http ;;
    ip-acme|panel-domain)
      if [ "$mode" = "panel-domain" ] && command -v caddy >/dev/null 2>&1; then
        write_if_changed "$ACCESS_DIR/caddy/Caddyfile" 0644 "$(gen_caddyfile "$PANEL_HOST" "$WEBMAIL_HOST" "$ACME_EMAIL")"
        sync_caddy_live
      else
        write_if_changed "$ACCESS_DIR/nginx/mailstack-panel.conf" 0644 "$(gen_nginx_tls "$PANEL_HOST" "$WEBMAIL_HOST")"
        sync_nginx_live tls
      fi
      write_if_changed "$ACCESS_DIR/$mode/DNS-REQUIREMENTS.txt" 0644 "$(cat <<EOF
访问模式 = $mode
A     $PANEL_HOST  → ${SERVER_IP:-<公网 IP>}
A     $WEBMAIL_HOST → ${SERVER_IP:-<公网 IP>}
80/tcp 对 Let's Encrypt 可达；证书：
  sudo mailstack-manage tls issue $PANEL_HOST --email ${ACME_EMAIL:-<邮箱>}
  sudo mailstack-manage tls issue $WEBMAIL_HOST --email ${ACME_EMAIL:-<邮箱>}
落点：$TLS_DIR/<host>/{fullchain,privkey}.pem
EOF
)" ;;
    cloudflared)
      local cfg="$ACCESS_DIR/cloudflared/config.yml"
      if [ ! -f "$cfg" ] || [ -n "${CLOUDFLARE_TUNNEL:-}" ]; then
        write_if_changed "$cfg" 0640 "$(gen_cloudflared_config "$PANEL_HOST" "$WEBMAIL_HOST")"
      else
        info "保留既有 cloudflared 配置：$cfg"
      fi
      write_if_changed "$ACCESS_DIR/cloudflared/README.txt" 0644 "$(cat <<EOF
访问模式 = cloudflared
1) sudo cloudflared tunnel login && sudo cloudflared tunnel create mailstack
2) sudo CLOUDFLARE_TUNNEL=<id> mailstack-manage access set cloudflared
3) CNAME：$PANEL_HOST / $WEBMAIL_HOST → <id>.cfargotunnel.com
4) sudo systemctl enable --now mailstack-cloudflared
EOF
)"
      sync_cloudflared_live ;;
  esac
}

cmd_access_set() {
  require_root
  load_state
  local requested="${1:-}"
  [ -n "$requested" ] || die_usage "access set 需要模式：${ACCESS_MODES[*]}"
  shift
  local mode
  mode="$(normalize_mode "$requested")" || die_usage "未知访问模式：$requested"
  local opt_panel=""
  local opt_webmail=""
  local opt_email=""
  local opt_ip=""
  local opt_webroot=""
  local no_reload=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --panel-host)     [ "$#" -ge 2 ] || die_usage "--panel-host 需要参数"; opt_panel="$2"; shift 2 ;;
      --panel-host=*)   opt_panel="${1#*=}"; shift ;;
      --webmail-host)   [ "$#" -ge 2 ] || die_usage "--webmail-host 需要参数"; opt_webmail="$2"; shift 2 ;;
      --webmail-host=*) opt_webmail="${1#*=}"; shift ;;
      --acme-email)     [ "$#" -ge 2 ] || die_usage "--acme-email 需要参数"; opt_email="$2"; shift 2 ;;
      --acme-email=*)   opt_email="${1#*=}"; shift ;;
      --server-ip)      [ "$#" -ge 2 ] || die_usage "--server-ip 需要参数"; opt_ip="$2"; shift 2 ;;
      --server-ip=*)    opt_ip="${1#*=}"; shift ;;
      --acme-webroot)   [ "$#" -ge 2 ] || die_usage "--acme-webroot 需要参数"; opt_webroot="$2"; shift 2 ;;
      --acme-webroot=*) opt_webroot="${1#*=}"; shift ;;
      --no-reload)      no_reload=1; shift ;;
      -h|--help)        usage_access_set; return 0 ;;
      *) die_usage "access set 未知参数：$1" ;;
    esac
  done
  if [ -n "$opt_panel" ] && ! valid_hostname "$opt_panel"; then die_usage "面板主机名非法：$opt_panel"; fi
  if [ -n "$opt_webmail" ] && ! valid_hostname "$opt_webmail"; then die_usage "Webmail 主机名非法：$opt_webmail"; fi
  if [ -n "$opt_email" ] && ! valid_email "$opt_email"; then die_usage "ACME 邮箱非法：$opt_email"; fi
  if [ -n "$opt_ip" ] && ! valid_ipv4 "$opt_ip"; then die_usage "服务器 IP 非法：$opt_ip"; fi

  [ -n "$opt_panel" ] && PANEL_HOST="$opt_panel"
  [ -n "$opt_webmail" ] && WEBMAIL_HOST="$opt_webmail"
  [ -n "$opt_email" ] && ACME_EMAIL="$opt_email"
  [ -n "$opt_ip" ] && SERVER_IP="$opt_ip"
  [ -n "$opt_webroot" ] && ACME_WEBROOT="$opt_webroot"

  if [ "$mode" = "ssh" ]; then
    PANEL_HOST=""; WEBMAIL_HOST=""
  else
    [ -n "$DOMAIN" ] || die "模式 $mode 需要先配置域名（domain set）"
    [ -n "$PANEL_HOST" ] || PANEL_HOST="$(default_panel_host)"
    [ -n "$WEBMAIL_HOST" ] || WEBMAIL_HOST="$(default_webmail_host)"
    valid_hostname "$PANEL_HOST" || die_usage "面板主机名非法：$PANEL_HOST"
    valid_hostname "$WEBMAIL_HOST" || die_usage "Webmail 主机名非法：$WEBMAIL_HOST"
    local h
    for h in "$DOMAIN" "$MAIL_HOST" "mail.$DOMAIN" "imap.$DOMAIN" "smtp.$DOMAIN" "pop.$DOMAIN"; do
      [ -n "$h" ] || continue
      [ "$PANEL_HOST" != "$h" ] || die "面板主机不能与邮件主机同名：$PANEL_HOST"
      [ "$WEBMAIL_HOST" != "$h" ] || die "Webmail 主机不能与邮件主机同名：$WEBMAIL_HOST"
    done
    [ "$PANEL_HOST" != "$WEBMAIL_HOST" ] || die "面板主机与 Webmail 主机不能相同"
  fi

  ACCESS_MODE_DETAIL="$mode"
  ACCESS_MODE="$(canonical_mode "$mode")"
  PANEL_URL="$(panel_url_for "$mode" "$PANEL_HOST")"
  WEBMAIL_URL="$(webmail_url_for "$mode" "$WEBMAIL_HOST")"
  write_state
  write_access_state
  say "应用访问模式：$mode"
  apply_access_artifacts "$mode"
  assert_loopback_only
  audit "access-set" "$mode panel=${PANEL_HOST:-none}"
  if [ "$mode" = "ip-acme" ] || [ "$mode" = "panel-domain" ]; then
    info "证书下一步：sudo mailstack-manage tls issue ${PANEL_HOST} --email ${ACME_EMAIL:-<邮箱>}"
  fi
  [ "$CHANGED" -eq 0 ] && info "配置无变化（幂等）"
  [ "$no_reload" -eq 1 ] && info "--no-reload：仅写文件"
  return 0
}

# ---------------------------------------------------------------------------
# domain commands
# ---------------------------------------------------------------------------

print_dns_hints() {
  local domain="$1"
  local mail_host="$2"
  local ip="$3"
  local selector="$4"
  echo
  echo '    DNS 记录:'
  printf '    %-5s %-42s %s\n' 'A' "$mail_host" "→ ${ip:-<公网 IP>}"
  printf '    %-5s %-42s %s\n' 'MX' "$domain" "→ $mail_host（优先级 10）"
  printf '    %-5s %-42s %s\n' 'TXT' "$domain" '"v=spf1 mx -all"'
  printf '    %-5s %-42s %s\n' 'TXT' "$selector._domainkey.$domain" '"v=DKIM1; k=rsa; p=<dkimPublicKey>"'
  printf '    %-5s %-42s %s\n' 'TXT' "_dmarc.$domain" "\"v=DMARC1; p=quarantine; rua=mailto:postmaster@$domain\""
}

usage_domain_set() {
  cat <<'EOF'
用法: mailstack-manage domain set <domain> [选项]
  --mail-host HOST --server-ip IP --dkim-selector S --complete --no-restart --skip-domain-table
EOF
}

cmd_domain_set() {
  require_root
  load_state
  local domain=""
  local mail_host=""
  local server_ip=""
  local selector=""
  local complete=0
  local restart=1
  local skip_table=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --mail-host)         [ "$#" -ge 2 ] || die_usage "--mail-host 需要参数"; mail_host="$2"; shift 2 ;;
      --mail-host=*)       mail_host="${1#*=}"; shift ;;
      --server-ip)         [ "$#" -ge 2 ] || die_usage "--server-ip 需要参数"; server_ip="$2"; shift 2 ;;
      --server-ip=*)       server_ip="${1#*=}"; shift ;;
      --dkim-selector)     [ "$#" -ge 2 ] || die_usage "--dkim-selector 需要参数"; selector="$2"; shift 2 ;;
      --dkim-selector=*)   selector="${1#*=}"; shift ;;
      --complete)          complete=1; shift ;;
      --no-restart)        restart=0; shift ;;
      --skip-domain-table) skip_table=1; shift ;;
      -h|--help)           usage_domain_set; return 0 ;;
      -*)                  die_usage "domain set 未知参数：$1" ;;
      *)                   [ -z "$domain" ] || die_usage "domain set 只接受一个域名"; domain="$1"; shift ;;
    esac
  done
  [ -n "$domain" ] || die_usage "domain set 需要域名（例 example.com）"
  valid_hostname "$domain" || die_usage "域名非法：$domain"
  if [ -z "$mail_host" ]; then
    if [ -n "${MAIL_HOST:-}" ] && printf '%s' "$MAIL_HOST" | grep -Eq "\.${domain//./\\.}$"; then
      mail_host="$MAIL_HOST"
    else
      mail_host="mail.$domain"
    fi
  fi
  valid_hostname "$mail_host" || die_usage "邮件主机名非法：$mail_host"
  [ -n "$server_ip" ] || server_ip="$(setup_json_value serverIp || true)"
  [ -n "$server_ip" ] || server_ip="$(detect_server_ip)"
  [ -n "$server_ip" ] || die "无法确定服务器 IP：加 --server-ip <ip>"
  valid_ipv4 "$server_ip" || die_usage "服务器 IP 非法：$server_ip"
  [ -n "$selector" ] || selector="$(setup_json_value dkimSelector || true)"
  [ -n "$selector" ] || selector="mail"

  say "更新邮件身份：$domain"
  local payload out
  payload="$(printf '{"domain":%s,"mailHost":%s,"serverIp":%s,"dkimSelector":%s}' \
    "$(json_quote "$domain")" "$(json_quote "$mail_host")" "$(json_quote "$server_ip")" "$(json_quote "$selector")")"
  out="$(priv_call setup.identity.apply "$payload")" || die "setup.identity.apply 失败：${LAST_ERROR:-未知错误}"
  info "身份已写入：$ETC_DIR/setup.json"
  json_data "$out" | sed 's/^/    /'

  if [ "$skip_table" -eq 0 ]; then
    if priv_call domains.add "$(printf '{"name":%s}' "$(json_quote "$domain")")" >/dev/null 2>&1; then
      info "域名表已登记：$DOMAINS_TABLE"
    else
      warn "domains.add 失败：${LAST_ERROR:-未知错误}"
    fi
  fi

  DOMAIN="$domain"; MAIL_HOST="$mail_host"; SERVER_IP="$server_ip"
  if [ -n "$PANEL_HOST" ] && printf '%s' "$PANEL_HOST" | grep -Eq '^panel\.'; then PANEL_HOST="$(default_panel_host)"; fi
  if [ -n "$WEBMAIL_HOST" ] && printf '%s' "$WEBMAIL_HOST" | grep -Eq '^webmail\.'; then WEBMAIL_HOST="$(default_webmail_host)"; fi
  PANEL_URL="$(panel_url_for "$(current_detail)" "$PANEL_HOST")"
  WEBMAIL_URL="$(webmail_url_for "$(current_detail)" "$WEBMAIL_HOST")"
  write_state
  write_access_state
  CHANGED=0
  if [ "$(current_detail)" != "ssh" ] && [ -f "$ACCESS_DIR/mode" ] \
     && [ "$(cat -- "$ACCESS_DIR/mode")" = "$(current_detail)" ]; then
    apply_access_artifacts "$(current_detail)"
  fi
  if [ "$complete" -eq 1 ]; then
    priv_call setup.wizard.complete '{}' >/dev/null 2>&1 && info "已置位向导完成标记" || warn "setup.wizard.complete 失败"
  fi
  print_dns_hints "$domain" "$mail_host" "$server_ip" "$selector"
  if [ "$restart" -eq 1 ]; then
    restart_units mailstackd
    if [ -f "$TLS_DIR/$mail_host/fullchain.pem" ]; then
      restart_units mailstack-imap
    else
      info "IMAP 证书未就绪，mailstack-imap 保持原状"
    fi
  fi
  audit "domain-set" "$domain mailHost=$mail_host"
}

cmd_domain_list() {
  require_root
  load_state
  say "受管邮件域名"
  local out
  out="$(priv_call domains.list '{}')" || die "domains.list 失败：${LAST_ERROR:-未知错误}"
  if have_python3; then
    printf '%s' "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin).get("data")
rows = data.get("domains") if isinstance(data, dict) else data
for item in rows or []:
    name = item if isinstance(item, str) else (item.get("name") or item.get("domain") or "")
    if name: print(f"    - {name}")' || warn "解析 domains.list 失败"
  else
    printf '%s\n' "$out"
  fi
  echo
  info "身份域：${DOMAIN:-（未设置）}  邮件主机：${MAIL_HOST:-（未设置）}"
}

cmd_domain_add() {
  require_root
  load_state
  local domain="${1:-}"
  [ -n "$domain" ] || die_usage "domain add 需要域名"
  valid_hostname "$domain" || die_usage "域名非法：$domain"
  say "添加邮件域名：$domain"
  priv_call domains.add "$(printf '{"name":%s}' "$(json_quote "$domain")")" >/dev/null \
    || die "domains.add 失败：${LAST_ERROR:-未知错误}"
  info "已登记：$DOMAINS_TABLE"
  audit "domain-add" "$domain"
}

cmd_domain_delete() {
  require_root
  load_state
  local domain=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm|-y|--yes) ASSUME_YES=1; shift ;;
      -h|--help) die_usage "domain delete <domain> [--confirm]" ;;
      -*) die_usage "domain delete 未知参数：$1" ;;
      *) [ -z "$domain" ] || die_usage "domain delete 只接受一个域名"; domain="$1"; shift ;;
    esac
  done
  [ -n "$domain" ] || die_usage "domain delete 需要域名"
  valid_hostname "$domain" || die_usage "域名非法：$domain"
  confirm_or_die "确认删除域名 $domain（同时删除该域别名）？"
  say "删除邮件域名：$domain"
  priv_call domains.delete "$(printf '{"id":%s,"confirm":true}' "$(json_quote "$domain")")" >/dev/null \
    || die "domains.delete 失败：${LAST_ERROR:-未知错误}"
  info "已删除：$domain"
  audit "domain-delete" "$domain"
}

# ---------------------------------------------------------------------------
# account commands
# ---------------------------------------------------------------------------

account_usage() {
  cat <<'EOF'
用法:
  mailstack-manage account add <email> [--password-stdin | --password <pw>] [--name 显示名]
  mailstack-manage account list
  mailstack-manage account passwd <email> [--password-stdin | --password <pw>]
  mailstack-manage account delete <email> [--confirm]
EOF
}

read_account_password() {
  local value="$1"
  local stdin_flag="$2"
  if [ "$stdin_flag" -eq 1 ]; then
    [ -z "$value" ] || die_usage "--password 与 --password-stdin 只能选一个"
    local line=""
    IFS= read -r line || line=""
    line="${line%$'\r'}"
    [ -n "$line" ] || die "stdin 未读到口令"
    printf '%s' "$line"
    return 0
  fi
  if [ -n "$value" ]; then
    warn "--password 会经 argv 暴露；建议 --password-stdin"
    printf '%s' "$value"
    return 0
  fi
  if [ -n "${MAILSTACK_ADMIN_PASSWORD:-}" ]; then
    printf '%s' "$MAILSTACK_ADMIN_PASSWORD"
    return 0
  fi
  [ -t 0 ] || die "未提供口令：用 --password-stdin（推荐）或 --password"
  local first=""
  local second=""
  printf '邮箱口令（8-256 位，含字母与数字）: ' >&2
  IFS= read -r -s first || first=""
  printf '\n再次输入: ' >&2
  IFS= read -r -s second || second=""
  printf '\n' >&2
  [ "$first" = "$second" ] || die "两次输入不一致"
  printf '%s' "$first"
}

precheck_password() {
  local password="$1"
  local email="$2"
  local plen=${#password}
  printf '%s' "$password" | LC_ALL=C grep -q '[[:cntrl:]]' && die "口令不得包含控制字符"
  [ "$plen" -ge 8 ] && [ "$plen" -le 256 ] || die "口令长度必须 8-256（实际 $plen）"
  printf '%s' "$password" | grep -q '[A-Za-z]' || die "口令必须包含字母"
  printf '%s' "$password" | grep -q '[0-9]' || die "口令必须包含数字"
  local localpart="${email%%@*}"
  case "$(printf '%s' "$password" | tr '[:upper:]' '[:lower:]')" in
    *"$(printf '%s' "$localpart" | tr '[:upper:]' '[:lower:]')"*) die "口令不得包含邮箱用户名" ;;
  esac
}

cmd_account_add() {
  require_root
  load_state
  local email=""
  local name=""
  local password_arg=""
  local stdin_flag=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --password)       [ "$#" -ge 2 ] || die_usage "--password 需要参数"; password_arg="$2"; shift 2 ;;
      --password=*)     password_arg="${1#*=}"; shift ;;
      --password-stdin) stdin_flag=1; shift ;;
      --name)           [ "$#" -ge 2 ] || die_usage "--name 需要参数"; name="$2"; shift 2 ;;
      --name=*)         name="${1#*=}"; shift ;;
      -h|--help)        account_usage; return 0 ;;
      -*)               die_usage "account add 未知参数：$1" ;;
      *)                [ -z "$email" ] || die_usage "account add 只接受一个邮箱"; email="$1"; shift ;;
    esac
  done
  [ -n "$email" ] || die_usage "account add 需要邮箱地址"
  valid_email "$email" || die_usage "邮箱地址非法：$email"
  local password payload
  password="$(read_account_password "$password_arg" "$stdin_flag")"
  precheck_password "$password" "$email"
  payload="$(printf '{"email":%s,"password":%s' "$(json_quote "$email")" "$(json_quote "$password")")"
  [ -n "$name" ] && payload="$payload$(printf ',"name":%s' "$(json_quote "$name")")"
  payload="$payload}"
  password=""
  say "创建邮箱：$email"
  priv_call users.add "$payload" >/dev/null || die "users.add 失败：${LAST_ERROR:-未知错误}"
  info "已创建：$email（unix 账号：${email%%@*}）"
  audit "account-add" "$email"
}

cmd_account_list() {
  require_root
  load_state
  say "受管邮箱账号"
  local out
  out="$(priv_call users.list '{}')" || die "users.list 失败：${LAST_ERROR:-未知错误}"
  if have_python3; then
    printf '%s' "$out" | python3 -c '
import json, sys
rows = json.load(sys.stdin).get("data")
rows = rows if isinstance(rows, list) else []
print("    %-38s %-22s %s" % ("邮箱", "显示名", "状态"))
for row in rows:
    print("    %-38s %-22s %s" % (row.get("address", ""), row.get("name", ""),
                                  "enabled" if row.get("active") else "disabled"))' || warn "解析 users.list 失败"
  else
    json_data "$out"
  fi
}

cmd_account_passwd() {
  require_root
  load_state
  local email=""
  local password_arg=""
  local stdin_flag=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --password)       [ "$#" -ge 2 ] || die_usage "--password 需要参数"; password_arg="$2"; shift 2 ;;
      --password=*)     password_arg="${1#*=}"; shift ;;
      --password-stdin) stdin_flag=1; shift ;;
      -h|--help)        account_usage; return 0 ;;
      -*)               die_usage "account passwd 未知参数：$1" ;;
      *)                [ -z "$email" ] || die_usage "account passwd 只接受一个邮箱"; email="$1"; shift ;;
    esac
  done
  [ -n "$email" ] || die_usage "account passwd 需要邮箱地址"
  valid_email "$email" || die_usage "邮箱地址非法：$email"
  local password
  password="$(read_account_password "$password_arg" "$stdin_flag")"
  precheck_password "$password" "$email"
  say "重设邮箱口令：$email"
  priv_call users.password "$(printf '{"email":%s,"password":%s}' \
    "$(json_quote "$email")" "$(json_quote "$password")")" >/dev/null \
    || die "users.password 失败：${LAST_ERROR:-未知错误}"
  password=""
  info "口令已更新（IMAP/POP3/提交/Webmail 同时生效）"
  audit "account-passwd" "$email"
}

cmd_account_delete() {
  require_root
  load_state
  local email=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm|-y|--yes) ASSUME_YES=1; shift ;;
      -h|--help) account_usage; return 0 ;;
      -*) die_usage "account delete 未知参数：$1" ;;
      *) [ -z "$email" ] || die_usage "account delete 只接受一个邮箱"; email="$1"; shift ;;
    esac
  done
  [ -n "$email" ] || die_usage "account delete 需要邮箱地址"
  valid_email "$email" || die_usage "邮箱地址非法：$email"
  confirm_or_die "确认删除邮箱 $email（系统账号与 Maildir 一并删除）？"
  say "删除邮箱：$email"
  priv_call users.delete "$(printf '{"email":%s,"confirm":true}' "$(json_quote "$email")")" >/dev/null \
    || die "users.delete 失败：${LAST_ERROR:-未知错误}"
  info "已删除：$email"
  audit "account-delete" "$email"
}

# ---------------------------------------------------------------------------
# tls commands
# ---------------------------------------------------------------------------

print_tls_hints() {
  local host="$1"
  echo
  echo '    DNS/网络前置条件（HTTP-01）:'
  printf '    %-5s %-42s %s\n' 'A' "$host" "→ ${SERVER_IP:-<公网 IP>}"
  printf '    %-5s %-42s %s\n' 'P80' "$host" '80/tcp 对公网可达'
  echo "    证书落点：$TLS_DIR/$host/{fullchain,privkey}.pem"
}

cmd_tls_issue() {
  require_root
  load_state
  local host=""
  local email=""
  local method="standalone"
  local webroot=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --email)       [ "$#" -ge 2 ] || die_usage "--email 需要参数"; email="$2"; shift 2 ;;
      --email=*)     email="${1#*=}"; shift ;;
      --method)      [ "$#" -ge 2 ] || die_usage "--method 需要参数"; method="$2"; shift 2 ;;
      --method=*)    method="${1#*=}"; shift ;;
      --webroot)     [ "$#" -ge 2 ] || die_usage "--webroot 需要参数"; webroot="$2"; shift 2 ;;
      --webroot=*)   webroot="${1#*=}"; shift ;;
      --server-ip)   [ "$#" -ge 2 ] || die_usage "--server-ip 需要参数"; SERVER_IP="$2"; shift 2 ;;
      --server-ip=*) SERVER_IP="${1#*=}"; shift ;;
      -h|--help)     die_usage "tls issue <host> [--email E] [--method standalone|webroot] [--webroot DIR]" ;;
      -*)            die_usage "tls issue 未知参数：$1" ;;
      *)             [ -z "$host" ] || die_usage "tls issue 只接受一个主机名"; host="$1"; shift ;;
    esac
  done
  [ -n "$host" ] || die_usage "tls issue 需要主机名"
  valid_hostname "$host" || die_usage "主机名非法：$host"
  [ -n "$email" ] || email="${ACME_EMAIL:-}"
  [ -n "$email" ] || die "缺少 ACME 邮箱：加 --email ops@example.com"
  valid_email "$email" || die_usage "ACME 邮箱非法：$email"
  [ -n "${SERVER_IP:-}" ] || SERVER_IP="$(detect_server_ip)"
  case "$method" in
    standalone) : ;;
    webroot)
      [ -n "$webroot" ] || die_usage "--method webroot 需要 --webroot <目录>"
      [ -d "$webroot" ] || die_usage "--webroot 目录不存在：$webroot" ;;
    *) die_usage "--method 只支持 standalone|webroot" ;;
  esac
  ACME_EMAIL="$email"
  write_state
  say "签发 TLS 证书：$host（$method）"
  local payload out
  payload="$(printf '{"domain":%s,"email":%s,"method":%s' \
    "$(json_quote "$host")" "$(json_quote "$email")" "$(json_quote "$method")")"
  [ -n "$webroot" ] && payload="$payload$(printf ',"webroot":%s' "$(json_quote "$webroot")")"
  payload="$payload}"
  out="$(priv_call setup.cert.issue "$payload")" \
    || { print_tls_hints "$host"; die "setup.cert.issue 失败：${LAST_ERROR:-未知错误}"; }
  json_data "$out" | sed 's/^/    /'
  info "证书：$TLS_DIR/$host/"
  print_tls_hints "$host"
  audit "tls-issue" "$host"
  local detail
  detail="$(current_detail)"
  case "$detail" in
    nginx|ip-acme|panel-domain) info "刷新反向代理：sudo mailstack-manage access set $detail" ;;
  esac
}

cmd_tls_renew() {
  require_root
  load_state
  local host=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --all) shift ;;
      -h|--help) die_usage "tls renew [<host>|--all]" ;;
      -*) die_usage "tls renew 未知参数：$1" ;;
      *) [ -z "$host" ] || die_usage "tls renew 只接受一个主机名"; host="$1"; shift ;;
    esac
  done
  local hosts=() d
  if [ -n "$host" ]; then
    valid_hostname "$host" || die_usage "主机名非法：$host"
    hosts=("$host")
  elif [ -d "$TLS_DIR" ]; then
    for d in "$TLS_DIR"/*/; do
      [ -d "$d" ] && [ -f "$d/fullchain.pem" ] && hosts+=("$(basename -- "$d")")
    done
  fi
  if [ "${#hosts[@]}" -eq 0 ]; then
    info "没有已签发证书（先 tls issue <host>）"
    return 0
  fi
  say "续期证书"
  local h failures=0
  for h in "${hosts[@]}"; do
    if priv_call certs.renew "$(printf '{"domain":%s}' "$(json_quote "$h")")" >/dev/null; then
      info "完成：$h"
    else
      warn "失败：$h（${LAST_ERROR:-未知错误}）"
      failures=$((failures + 1))
    fi
  done
  audit "tls-renew" "${hosts[*]}"
  [ "$failures" -eq 0 ] || die "$failures 个域名续期失败"
  return 0
}

# ---------------------------------------------------------------------------
# backup
# ---------------------------------------------------------------------------

backup_usage() {
  cat <<'EOF'
用法:
  mailstack-manage backup create [--include-mails] [--include-secrets] [--passphrase-stdin]
  mailstack-manage backup list
  mailstack-manage backup restore <filename> [--dry-run] [--passphrase-stdin] [--confirm]
  mailstack-manage backup delete <filename> [--confirm]
EOF
}

read_secret_line() {
  local prompt="$1"
  local value=""
  if [ -n "${MAILSTACK_BACKUP_PASSPHRASE:-}" ]; then
    printf '%s' "$MAILSTACK_BACKUP_PASSPHRASE"
    return 0
  fi
  [ -t 0 ] || return 1
  printf '%s' "$prompt" >&2
  IFS= read -r -s value || value=""
  printf '\n' >&2
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

cmd_backup() {
  require_root
  load_state
  local sub="${1:-}"; [ "$#" -gt 0 ] && shift
  case "$sub" in
    create)
      local include_mails=0
      local include_secrets=0
      local passphrase_stdin=0
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --include-mails) include_mails=1; shift ;;
          --include-secrets) include_secrets=1; shift ;;
          --passphrase-stdin) passphrase_stdin=1; shift ;;
          -h|--help) backup_usage; return 0 ;;
          *) die_usage "backup create 未知参数：$1" ;;
        esac
      done
      local passphrase="" payload out
      if [ "$passphrase_stdin" -eq 1 ]; then
        IFS= read -r passphrase || passphrase=""
        passphrase="${passphrase%$'\r'}"
      elif ! passphrase="$(read_secret_line '备份口令（公网模式必填，留空跳过）: ' 2>/dev/null)"; then
        passphrase=""
      fi
      payload="$(printf '{"includeMails":%s,"includeSecrets":%s' \
        "$([ "$include_mails" -eq 1 ] && echo true || echo false)" \
        "$([ "$include_secrets" -eq 1 ] && echo true || echo false)")"
      [ -n "$passphrase" ] && payload="$payload$(printf ',"passphrase":%s' "$(json_quote "$passphrase")")"
      payload="$payload}"
      passphrase=""
      say "创建备份"
      out="$(priv_call backup.create "$payload")" || die "backup.create 失败：${LAST_ERROR:-未知错误}"
      json_data "$out" | sed 's/^/    /'
      audit "backup-create" "mails=$include_mails secrets=$include_secrets"
      ;;
    list)
      say "备份列表"
      local out
      out="$(priv_call backup.list '{}')" || die "backup.list 失败：${LAST_ERROR:-未知错误}"
      if have_python3; then
        printf '%s' "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin).get("data")
rows = data if isinstance(data, list) else []
if not rows:
    print("    （无备份）")
else:
    print("    %-52s %-12s %s" % ("文件", "大小", "时间"))
    for row in rows:
        size = row.get("size", 0) or 0
        print("    %-52s %-12s %s" % (row.get("filename", ""), f"{size/1048576:.1f}MiB", row.get("createdAt", "")))' \
          || warn "解析 backup.list 失败"
      else
        json_data "$out"
      fi
      ;;
    restore)
      local filename=""
      local dry=0
      local passphrase_stdin=0
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --dry-run) dry=1; shift ;;
          --passphrase-stdin) passphrase_stdin=1; shift ;;
          --confirm|-y|--yes) ASSUME_YES=1; shift ;;
          -h|--help) backup_usage; return 0 ;;
          -*) die_usage "backup restore 未知参数：$1" ;;
          *) [ -z "$filename" ] || die_usage "backup restore 只接受一个文件名"; filename="$1"; shift ;;
        esac
      done
      [ -n "$filename" ] || die_usage "backup restore 需要文件名（先 backup list）"
      local passphrase="" payload out
      if [ "$passphrase_stdin" -eq 1 ]; then
        IFS= read -r passphrase || passphrase=""
        passphrase="${passphrase%$'\r'}"
      elif ! passphrase="$(read_secret_line '备份口令（公网模式必填，留空跳过）: ' 2>/dev/null)"; then
        passphrase=""
      fi
      [ "$dry" -eq 1 ] && info "dry-run：只预演，不落盘" || confirm_or_die "确认从备份 $filename 恢复（覆盖当前配置/数据）？"
      payload="$(printf '{"filename":%s,"confirm":%s' "$(json_quote "$filename")" "$([ "$dry" -eq 1 ] && echo false || echo true)")"
      [ "$dry" -eq 1 ] && payload="$payload,\"dryRun\":true"
      [ -n "$passphrase" ] && payload="$payload$(printf ',"passphrase":%s' "$(json_quote "$passphrase")")"
      payload="$payload}"
      passphrase=""
      say "恢复备份：$filename"
      out="$(priv_call backup.restore "$payload")" || die "backup.restore 失败：${LAST_ERROR:-未知错误}"
      json_data "$out" | sed 's/^/    /'
      audit "backup-restore" "$filename dry=$dry"
      ;;
    delete)
      local filename=""
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --confirm|-y|--yes) ASSUME_YES=1; shift ;;
          -h|--help) backup_usage; return 0 ;;
          -*) die_usage "backup delete 未知参数：$1" ;;
          *) [ -z "$filename" ] || die_usage "backup delete 只接受一个文件名"; filename="$1"; shift ;;
        esac
      done
      [ -n "$filename" ] || die_usage "backup delete 需要文件名"
      confirm_or_die "确认删除备份 $filename？"
      say "删除备份：$filename"
      priv_call backup.delete "$(printf '{"filename":%s,"confirm":true}' "$(json_quote "$filename")")" >/dev/null \
        || die "backup.delete 失败：${LAST_ERROR:-未知错误}"
      info "已删除：$filename"
      audit "backup-delete" "$filename"
      ;;
    -h|--help|"") backup_usage ;;
    *) die_usage "backup 未知子命令：$sub（create|list|restore|delete）" ;;
  esac
}

# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

latest_release_tag() {
  local api="https://api.github.com/repos/${REPO_SLUG}/releases/latest"
  local body=""
  command -v curl >/dev/null 2>&1 || return 1
  body="$(curl -fsSL --connect-timeout 15 "$api" 2>/dev/null || true)"
  [ -n "$body" ] || return 1
  printf '%s' "$body" | sed -n 's/.*"tag_name":[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -1
}

cmd_update() {
  require_root
  load_state
  local sub="${1:-check}"; [ "$#" -gt 0 ] && shift
  case "$sub" in
    check)
      say "检查更新（当前 v$MAILSTACK_VERSION）"
      local latest
      if ! latest="$(latest_release_tag)"; then
        warn "无法访问 GitHub API（网络/代理）；可手动下载安装器后 --upgrade"
        return 0
      fi
      info "最新版本：v$latest"
      if [ "$latest" = "$MAILSTACK_VERSION" ]; then
        info "已是最新"
      else
        info "可升级：sudo mailstack-manage update apply"
      fi
      ;;
    apply)
      confirm_or_die "下载并运行最新安装器执行升级（程序文件会替换，配置保留）？"
      local dl
      dl="$(mktemp -d "${TMPDIR:-/tmp}/mailstack-update.XXXXXXXX")"
      say "备份配置"
      if priv_call backup.create '{"includeSecrets":true}' >/dev/null 2>&1; then
        info "已创建配置备份"
      else
        warn "配置备份失败（继续升级；可用 backup create 手工备份）"
      fi
      say "下载安装器"
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 2 --connect-timeout 20 \
          "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/install.sh" \
          -o "$dl/install.sh" || die "下载安装器失败"
      elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dl/install.sh" \
          "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/install.sh" \
          || die "下载安装器失败"
      else
        die "需要 curl 或 wget"
      fi
      bash -n "$dl/install.sh" || die "下载的安装器语法校验失败（拒绝执行）"
      say "执行升级"
      local -a args=(--upgrade --yes)
      [ -n "$PREFIX_NORM" ] && args+=(--prefix "$PREFIX_NORM")
      if bash "$dl/install.sh" "${args[@]}"; then
        audit "update-apply" "upgraded"
        info "升级完成"
      else
        rm -rf -- "$dl"
        die "升级失败（安装器已尝试自动回滚；看上面的输出）"
      fi
      rm -rf -- "$dl"
      ;;
    -h|--help|"") die_usage "update <check|apply>" ;;
    *) die_usage "update 未知子命令：$sub（check|apply）" ;;
  esac
}

# ---------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------

firewall_tool() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    printf 'ufw'
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    printf 'firewalld'
  fi
}

security_usage() {
  cat <<'EOF'
用法:
  mailstack-manage security status
  mailstack-manage security passwd [--password-stdin | --password <pw>]
  mailstack-manage security 2fa
  mailstack-manage security bans
  mailstack-manage security unban <ip>
  mailstack-manage security firewall status
  mailstack-manage security firewall open [ports...]
  mailstack-manage security firewall close [ports...]
  mailstack-manage security scan [--json]
EOF
}

cmd_security() {
  require_root
  load_state
  local sub="${1:-status}"; [ "$#" -gt 0 ] && shift
  case "$sub" in
    status)
      say "安全状态"
      local out
      out="$(priv_call admin.get '{}')" || true
      [ -n "$out" ] && info "admin：$(json_data "$out" | tr -d '\n ' | head -c 200)"
      out="$(priv_call security.scan '{}' 2>/dev/null || true)"
      if [ -n "$out" ] && have_python3; then
        printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin).get("data") or {}
summary = d.get("summary") or {}
print("    安全扫描：high=%s medium=%s info=%s" % (summary.get("high"), summary.get("medium"), summary.get("info")))
for f in (d.get("findings") or [])[:10]:
    print("      - %s %s: %s" % (f.get("severity"), f.get("issue"), f.get("path")))' || true
      fi
      local tool
      tool="$(firewall_tool || true)"
      info "防火墙：${tool:-未启用}"
      ;;
    passwd)
      local password_arg=""
      local stdin_flag=0
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --password)       [ "$#" -ge 2 ] || die_usage "--password 需要参数"; password_arg="$2"; shift 2 ;;
          --password=*)     password_arg="${1#*=}"; shift ;;
          --password-stdin) stdin_flag=1; shift ;;
          -h|--help) security_usage; return 0 ;;
          *) die_usage "security passwd 未知参数：$1" ;;
        esac
      done
      local pass
      pass="$(read_account_password "$password_arg" "$stdin_flag")"
      local plen=${#pass}
      [ "$plen" -ge 8 ] && [ "$plen" -le 256 ] || die "口令长度必须 8-256"
      printf '%s' "$pass" | grep -q '[A-Za-z]' && printf '%s' "$pass" | grep -q '[0-9]' \
        || die "口令必须同时包含字母与数字"
      say "重设管理员口令"
      priv_call admin.set "$(printf '{"username":%s,"password":%s}' \
        "$(json_quote "$ADMIN_USER")" "$(json_quote "$pass")")" >/dev/null \
        || die "admin.set 失败：${LAST_ERROR:-未知错误}"
      pass=""
      info "管理员口令已更新"
      audit "security-admin-passwd" "$ADMIN_USER"
      ;;
    2fa)
      say "2FA 状态"
      json_data "$(priv_call admin.get '{}')" | sed 's/^/    /' ;;
    bans)
      say "手工封禁（manual-bans.json）"
      if [ -f "$MANUAL_BANS" ]; then
        json_pretty "$(cat -- "$MANUAL_BANS")"
      else
        info "无封禁记录"
      fi ;;
    unban)
      local ip="${1:-}"
      [ -n "$ip" ] || die_usage "security unban 需要 IP"
      valid_ipv4 "$ip" || die_usage "IP 非法：$ip"
      say "解封：$ip"
      priv_call security.unban "$(printf '{"ip":%s}' "$(json_quote "$ip")")" >/dev/null \
        || die "security.unban 失败：${LAST_ERROR:-未知错误}"
      info "已解封：$ip"
      audit "security-unban" "$ip" ;;
    scan)
      local out
      out="$(priv_call security.scan '{}')" || die "security.scan 失败：${LAST_ERROR:-未知错误}"
      if [ "$JSON_OUT" -eq 1 ]; then json_data "$out"; else json_data "$out"; fi ;;
    firewall)
      local verb="${1:-status}"; [ "$#" -gt 0 ] && shift
      local tool ports=()
      tool="$(firewall_tool || true)"
      case "$verb" in
        status)
          say "防火墙"
          if [ -n "$tool" ]; then
            info "工具：$tool"
            case "$tool" in
              ufw) ufw status numbered 2>/dev/null | sed 's/^/    /' ;;
              firewalld) firewall-cmd --list-all 2>/dev/null | sed 's/^/    /' ;;
            esac
          else
            info "未检测到活动的 ufw/firewalld"
          fi ;;
        open|close)
          [ -n "$tool" ] || die "未检测到活动的 ufw/firewalld"
          if [ "$#" -gt 0 ]; then ports=("$@"); else
            [ "$IMAP_ENABLE" = "1" ] && ports=("${MAIL_PORTS[@]}")
            ports+=("${WEB_PORTS[@]}")
          fi
          local p
          for p in "${ports[@]}"; do
            valid_port "$p" || die_usage "端口非法：$p"
          done
          if [ "$verb" = "open" ]; then confirm_or_die "放行端口 ${ports[*]}？"; else confirm_or_die "关闭端口 ${ports[*]}？"; fi
          for p in "${ports[@]}"; do
            case "$tool" in
              ufw)
                if [ "$verb" = "open" ]; then
                  ufw allow "$p/tcp" >/dev/null 2>&1 || warn "ufw allow $p/tcp 失败"
                else
                  ufw delete allow "$p/tcp" >/dev/null 2>&1 || warn "ufw delete allow $p/tcp 失败"
                fi
                info "ufw $verb $p/tcp" ;;
              firewalld)
                if [ "$verb" = "open" ]; then
                  firewall-cmd --add-port="$p/tcp" --permanent >/dev/null 2>&1 || warn "firewalld 放行 $p 失败"
                else
                  firewall-cmd --remove-port="$p/tcp" --permanent >/dev/null 2>&1 || warn "firewalld 关闭 $p 失败"
                fi
                info "firewalld $verb $p/tcp" ;;
            esac
          done
          [ "$tool" = "firewalld" ] && firewall-cmd --reload >/dev/null 2>&1 || true
          audit "security-firewall" "$verb ${ports[*]}" ;;
        -h|--help) security_usage ;;
        *) die_usage "security firewall 未知子命令：$verb" ;;
      esac ;;
    -h|--help|"") security_usage ;;
    *) die_usage "security 未知子命令：$sub" ;;
  esac
}

# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

DOCTOR_FAIL=0
DOCTOR_WARN=0

doctor_ok()   { printf '    %sPASS%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
doctor_warn() { printf '    %sWARN%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; DOCTOR_WARN=$((DOCTOR_WARN + 1)); }
doctor_fail() { printf '    %sFAIL%s %s\n' "$C_RED" "$C_RESET" "$1"; DOCTOR_FAIL=$((DOCTOR_FAIL + 1)); }

cmd_doctor() {
  require_root
  load_state
  DOCTOR_FAIL=0; DOCTOR_WARN=0
  say "MailStack 体检"
  if [ "$STATE_LOADED" -eq 1 ]; then doctor_ok "部署状态存在：$STATE_FILE"; else doctor_fail "缺少部署状态：$STATE_FILE"; fi
  if [ -f "$STATE_FILE" ]; then
    local n
    n="$(grep -c '^ACCESS_MODE=' "$STATE_FILE" 2>/dev/null || true)"
    if [ "$n" = "1" ]; then doctor_ok "ACCESS_MODE 单行"; else doctor_fail "ACCESS_MODE 行数=$n（应为 1）"; fi
  fi
  if [ -x "$LIBEXEC_DIR/mailstack-privileged" ]; then
    if grep -q -- '--privileged-stdin' "$LIBEXEC_DIR/mailstack-privileged"; then
      doctor_ok "特权包装器使用 --privileged-stdin"
    else
      doctor_fail "特权包装器未使用 --privileged-stdin"
    fi
  else
    doctor_fail "缺少特权包装器：$LIBEXEC_DIR/mailstack-privileged"
  fi
  local sudoers
  sudoers="$(prefix_path /etc/sudoers.d)/mailstack-admin"
  if [ -f "$sudoers" ]; then doctor_ok "sudoers 规则存在：$sudoers"; else
    if [ -z "$PREFIX_NORM" ]; then doctor_fail "缺少 sudoers 规则：$sudoers"; else doctor_warn "staging 无 sudoers：$sudoers"; fi
  fi
  local unit missing=0
  for unit in "${UNITS[@]}"; do
    if [ -f "$(unit_file "$unit")" ]; then
      if systemd_live && systemctl is-active --quiet "$unit" 2>/dev/null; then
        doctor_ok "unit $unit active"
      elif systemd_live; then
        doctor_warn "unit $unit 未运行（journalctl -u $unit）"
      else
        doctor_ok "unit $unit 已安装（staging/无 systemd）"
      fi
    else
      missing=1; doctor_fail "缺少 unit $unit"
    fi
  done
  assert_loopback_only
  if systemd_live; then
    local f line
    for f in "$UNIT_DIR/mailstack-web.service" "$UNIT_DIR/mailstack-webmail.service"; do
      [ -f "$f" ] || continue
      if grep -Eq -- '--bind[= ][^ ]*0\.0\.0\.0' "$f"; then doctor_fail "$f 绑定了 0.0.0.0"; else doctor_ok "$f 绑定回环"; fi
    done
  fi
  if command -v openssl >/dev/null 2>&1 && [ -d "$TLS_DIR" ]; then
    local d host end epoch now warn_after days
    now="$(date +%s)"
    for d in "$TLS_DIR"/*/; do
      [ -d "$d" ] && [ -f "$d/fullchain.pem" ] || continue
      host="$(basename -- "$d")"
      end="$(openssl x509 -in "$d/fullchain.pem" -noout -enddate 2>/dev/null | sed -n 's/^notAfter=//p')"
      if [ -n "$end" ]; then
        epoch="$(date -d "$end" +%s 2>/dev/null || echo 0)"
        days=$(( (epoch - now) / 86400 ))
        if [ "$epoch" -gt 0 ] && [ "$days" -lt 0 ]; then doctor_fail "证书已过期：$host（$end）"
        elif [ "$epoch" -gt 0 ] && [ "$days" -lt 14 ]; then doctor_warn "证书即将到期：$host（${days} 天）"
        else doctor_ok "证书：$host（$end）"; fi
      else
        doctor_warn "无法解析证书：$host"
      fi
    done
  fi
  if command -v df >/dev/null 2>&1; then
    local avail
    avail="$(df -Pk "$(prefix_path /var/lib)" 2>/dev/null | awk 'NR==2 { print $4 }')"
    if [ -n "$avail" ] && [ "$avail" -lt 1048576 ]; then doctor_warn "磁盘可用 <1GiB（${avail}KB）"; else doctor_ok "磁盘可用充足（${avail}KB）"; fi
  fi
  local perms
  perms="$(stat -c '%a' "$ETC_DIR" 2>/dev/null || true)"
  if [ -n "$perms" ]; then
    if printf '%s' "$perms" | grep -Eq '^(7[0-5]0|750)$'; then doctor_ok "/etc/mailstack 权限 $perms"; else doctor_warn "/etc/mailstack 权限 $perms（期望 750）"; fi
  else
    doctor_fail "$ETC_DIR 不存在"
  fi
  local ver
  ver="$("$BIN_DIR/mailstackctl" --version 2>/dev/null | awk '{print $2}')"
  if [ -n "$ver" ] && [ "$ver" = "$MAILSTACK_VERSION" ]; then doctor_ok "版本一致：$ver"
  elif [ -n "$ver" ]; then doctor_warn "二进制版本 $ver 与状态 $MAILSTACK_VERSION 不一致"
  else doctor_fail "无法执行 $BIN_DIR/mailstackctl --version"; fi
  if [ -n "$(current_detail)" ] && [ "$(current_detail)" != "ssh" ]; then
    if [ -f "$ACCESS_DIR/mode" ]; then doctor_ok "访问层模式标记：$(cat -- "$ACCESS_DIR/mode")"; else doctor_warn "缺少访问层模式标记"; fi
  fi
  if priv_call queue.list '{}' >/dev/null 2>&1; then
    doctor_ok "特权通道可用（queue.list）"
  else
    doctor_warn "特权通道不可用（daemon/包装器未就绪？）"
  fi
  echo
  if [ "$DOCTOR_FAIL" -gt 0 ]; then
    warn "体检完成：$DOCTOR_FAIL 项失败，$DOCTOR_WARN 项警告"
    return 1
  fi
  info "体检完成：$DOCTOR_WARN 项警告"
}

# ---------------------------------------------------------------------------
# repair / uninstall
# ---------------------------------------------------------------------------

cmd_repair() {
  require_root
  load_state
  confirm_or_die "重新安装程序文件（保留配置与数据）？"
  local dl
  dl="$(mktemp -d "${TMPDIR:-/tmp}/mailstack-repair.XXXXXXXX")"
  say "下载安装器"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 2 --connect-timeout 20 \
      "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/install.sh" \
      -o "$dl/install.sh" || { rm -rf -- "$dl"; die "下载安装器失败"; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$dl/install.sh" \
      "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/install.sh" \
      || { rm -rf -- "$dl"; die "下载安装器失败"; }
  else
    rm -rf -- "$dl"
    die "需要 curl 或 wget"
  fi
  bash -n "$dl/install.sh" || { rm -rf -- "$dl"; die "安装器语法校验失败"; }
  local -a args=(--repair --yes)
  [ -n "$PREFIX_NORM" ] && args+=(--prefix "$PREFIX_NORM")
  if bash "$dl/install.sh" "${args[@]}"; then
    audit "repair" "ok"
    rm -rf -- "$dl"
    info "修复完成"
  else
    rm -rf -- "$dl"
    die "修复失败"
  fi
}

cmd_uninstall() {
  require_root
  load_state
  local purge=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --purge) purge=1; shift ;;
      --confirm|-y|--yes) ASSUME_YES=1; shift ;;
      -h|--help) die_usage "uninstall [--purge] [--confirm]" ;;
      *) die_usage "uninstall 未知参数：$1" ;;
    esac
  done
  if [ "$purge" -eq 1 ]; then
    confirm_or_die "卸载 MailStack 并删除配置/数据（不可恢复）？"
  else
    confirm_or_die "卸载 MailStack（保留 /etc/mailstack 与 /var/lib/mailstack）？"
  fi
  local candidate=""
  if [ -x "$LIBEXEC_DIR/mailstack-uninstall" ]; then candidate="$LIBEXEC_DIR/mailstack-uninstall"; fi
  if [ -z "$candidate" ]; then
    local dl
    dl="$(mktemp -d "${TMPDIR:-/tmp}/mailstack-uninstall.XXXXXXXX")"
    say "下载卸载脚本"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/uninstall.sh" \
        -o "$dl/uninstall.sh" || { rm -rf -- "$dl"; die "下载卸载脚本失败"; }
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O "$dl/uninstall.sh" \
        "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/uninstall.sh" \
        || { rm -rf -- "$dl"; die "下载卸载脚本失败"; }
    else
      rm -rf -- "$dl"
      die "需要 curl 或 wget"
    fi
    candidate="$dl/uninstall.sh"
  fi
  local -a args=(--non-interactive --yes)
  [ -n "$PREFIX_NORM" ] && args+=(--prefix "$PREFIX_NORM")
  [ "$purge" -eq 1 ] && args+=(--purge)
  audit "uninstall" "purge=$purge"
  bash "$candidate" "${args[@]}"
}

# ---------------------------------------------------------------------------
# service / logs
# ---------------------------------------------------------------------------

cmd_service() {
  require_root
  load_state
  local verb="${1:-status}"; [ "$#" -gt 0 ] && shift
  case "$verb" in
    start|stop|restart|reload) service_control "$verb" "${1:-}"; audit "service-$verb" "${1:-all}" ;;
    status)
      say "服务状态"
      print_services_line ;;
    logs)
      cmd_logs "$@" ;;
    -h|--help) die_usage "service <start|stop|restart|status|logs> [unit]" ;;
    *) die_usage "service 未知子命令：$verb" ;;
  esac
}

cmd_logs() {
  require_root
  load_state
  local unit="mailstackd"
  local lines=100
  local follow=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --lines|-n) [ "$#" -ge 2 ] || die_usage "--lines 需要参数"; lines="$2"; shift 2 ;;
      --lines=*) lines="${1#*=}"; shift ;;
      -f|--follow) follow=1; shift ;;
      -h|--help) die_usage "logs [unit] [--lines N] [-f]" ;;
      -*) die_usage "logs 未知参数：$1" ;;
      *) unit="$1"; shift ;;
    esac
  done
  printf '%s\n' "${UNITS[@]}" | grep -qx "$unit" || die_usage "未知 unit：$unit"
  if systemd_live; then
    local -a argv=(-u "$unit" -n "$lines" --no-pager)
    [ "$follow" -eq 1 ] && argv+=(-f)
    exec journalctl "${argv[@]}"
  fi
  info "未检测到 systemd：journald 不可用"
}

# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------

tui_header() {
  local detail services host
  detail="$(current_detail)"
  host="$(hostname 2>/dev/null || echo unknown)"
  printf '%s' "$C_CYAN$C_BOLD"
  echo '┌──────────────────────────────────────────────────────────────┐'
  printf '│  MailStack 管理面板  v%-10s  %-28s│\n' "$MAILSTACK_VERSION" "$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
  echo '└──────────────────────────────────────────────────────────────┘'
  printf '%s' "$C_RESET"
  printf '  主机: %-32s 前缀: %s\n' "$host" "${PREFIX_NORM:-/}"
  printf '  域名: %-32s 邮件主机: %s\n' "${DOMAIN:-（未配置）}" "${MAIL_HOST:-（未配置）}"
  printf '  访问: %-32s 管理台: %s\n' "$detail" "${PANEL_URL:-（未配置）}"
  printf '  身份: %s   管理员: %s（%s）\n' \
    "$([ -s "$ETC_DIR/setup.json" ] && echo 已配置 || echo 未配置)" \
    "$ADMIN_USER" "$([ -s "$ETC_DIR/admin.json" ] && echo 已配置 || echo 未配置)"
  return 0
}

tui_menu() {
  cat <<'EOF'

  1) 状态总览            2) 域名管理            3) 邮箱账号
  4) 访问与 TLS          5) 服务管理            6) 备份与恢复
  7) 更新/升级           8) 安全                9) 修复/卸载
  i) 初始化向导（首次配置域名/DKIM/域名表）          0) 退出
EOF
}

tui_domain() {
  local sub
  echo '  a) 列表   b) 添加   c) 删除   d) 设置身份/DKIM' >&2
  sub="$(menu_read '选择: ')"
  case "$sub" in
    a) menu_run cmd_domain_list ;;
    b) local d; d="$(menu_read '要添加的域名: ')"; [ -n "$d" ] && menu_run cmd_domain_add "$d" ;;
    c) local d2; d2="$(menu_read '要删除的域名: ')"; [ -n "$d2" ] && menu_run cmd_domain_delete "$d2" ;;
    d)
      local domain mh ip
      domain="$(menu_read '邮件域名（例 example.com）: ')"
      [ -n "$domain" ] || return 0
      mh="$(menu_read '邮件主机（留空 mail.<domain>）: ')"
      ip="$(menu_read '服务器 IP（留空自动探测）: ')"
      local -a args=("$domain" --complete)
      [ -n "$mh" ] && args+=(--mail-host "$mh")
      [ -n "$ip" ] && args+=(--server-ip "$ip")
      menu_run cmd_domain_set "${args[@]}" ;;
    *) warn "无效选择" ;;
  esac
}

tui_account() {
  local sub
  echo '  a) 列表   b) 添加   c) 重设口令   d) 删除' >&2
  sub="$(menu_read '选择: ')"
  case "$sub" in
    a) menu_run cmd_account_list ;;
    b) local mail pwd; mail="$(menu_read '邮箱地址: ')"; [ -n "$mail" ] || return 0
       pwd="$(menu_read '口令（留空用 MAILSTACK_ADMIN_PASSWORD）: ')"
       if [ -n "$pwd" ]; then menu_run cmd_account_add "$mail" --password "$pwd"; else menu_run cmd_account_add "$mail"; fi ;;
    c) local mail2; mail2="$(menu_read '邮箱地址: ')"; [ -n "$mail2" ] && menu_run cmd_account_passwd "$mail2" ;;
    d) local mail3; mail3="$(menu_read '邮箱地址: ')"; [ -n "$mail3" ] && menu_run cmd_account_delete "$mail3" ;;
    *) warn "无效选择" ;;
  esac
}

tui_access() {
  local sub
  echo '  a) 当前访问模式   b) 切换访问模式   c) 签发证书   d) 续期证书' >&2
  sub="$(menu_read '选择: ')"
  case "$sub" in
    a) menu_run cmd_access_show ;;
    b) local mode panel
       mode="$(menu_read "模式（${ACCESS_MODES[*]}）: ")"
       [ -n "$mode" ] || return 0
       if [ "$mode" != "ssh" ]; then panel="$(menu_read '面板主机（留空 panel.<domain>）: ')"; fi
       if [ -n "${panel:-}" ]; then menu_run cmd_access_set "$mode" --panel-host "$panel"; else menu_run cmd_access_set "$mode"; fi ;;
    c) local h; h="$(menu_read '证书主机名: ')"; [ -n "$h" ] && menu_run cmd_tls_issue "$h" ;;
    d) menu_run cmd_tls_renew ;;
    *) warn "无效选择" ;;
  esac
}

tui_service() {
  local sub
  echo '  a) 状态   b) 重启   c) 启动   d) 停止   e) 日志' >&2
  sub="$(menu_read '选择: ')"
  case "$sub" in
    a) menu_run cmd_service status ;;
    b) local u; u="$(menu_read "unit（留空全部）: ")"; menu_run cmd_service restart "$u" ;;
    c) local u2; u2="$(menu_read "unit（留空全部）: ")"; menu_run cmd_service start "$u2" ;;
    d) local u3; u3="$(menu_read "unit（留空全部）: ")"; menu_run cmd_service stop "$u3" ;;
    e) local u4; u4="$(menu_read 'unit（默认 mailstackd）: ' mailstackd)"; menu_run cmd_logs "$u4" ;;
    *) warn "无效选择" ;;
  esac
}

tui_backup() {
  local sub
  echo '  a) 创建   b) 列表   c) 恢复   d) 删除' >&2
  sub="$(menu_read '选择: ')"
  case "$sub" in
    a) local mails secrets
       mails="$(menu_read '包含邮件? [y/N]: ' n)"; secrets="$(menu_read '包含机密? [y/N]: ' n)"
       local -a args=(create)
       [ "$mails" = "y" ] || [ "$mails" = "Y" ] && args+=(--include-mails)
       [ "$secrets" = "y" ] || [ "$secrets" = "Y" ] && args+=(--include-secrets)
       menu_run cmd_backup "${args[@]}" ;;
    b) menu_run cmd_backup list ;;
    c) local fn; fn="$(menu_read '备份文件名: ')"; [ -n "$fn" ] && menu_run cmd_backup restore "$fn" ;;
    d) local fn2; fn2="$(menu_read '备份文件名: ')"; [ -n "$fn2" ] && menu_run cmd_backup delete "$fn2" ;;
    *) warn "无效选择" ;;
  esac
}

tui_security() {
  local sub
  echo '  a) 安全状态   b) 扫描   c) 重设管理员口令   d) 封禁列表   e) 解封   f) 防火墙状态' >&2
  sub="$(menu_read '选择: ')"
  case "$sub" in
    a) menu_run cmd_security status ;;
    b) menu_run cmd_security scan ;;
    c) menu_run cmd_security passwd ;;
    d) menu_run cmd_security bans ;;
    e) local ip; ip="$(menu_read '要解封的 IP: ')"; [ -n "$ip" ] && menu_run cmd_security unban "$ip" ;;
    f) menu_run cmd_security firewall status ;;
    *) warn "无效选择" ;;
  esac
}

tui_update() {
  local sub
  echo '  a) 检查更新   b) 执行升级' >&2
  sub="$(menu_read '选择: ')"
  case "$sub" in
    a) menu_run cmd_update check ;;
    b) menu_run cmd_update apply ;;
    *) warn "无效选择" ;;
  esac
}

tui_repair_uninstall() {
  local sub
  echo '  a) 修复文件   b) 卸载（保留数据）   c) 卸载（删除数据）' >&2
  sub="$(menu_read '选择: ')"
  case "$sub" in
    a) menu_run cmd_repair ;;
    b) menu_run cmd_uninstall ;;
    c) menu_run cmd_uninstall --purge ;;
    *) warn "无效选择" ;;
  esac
}

menu_read() {
  local prompt="$1"
  local default="${2:-}"
  local value=""
  printf '%s' "$prompt" >&2
  IFS= read -r value || value=""
  [ -n "$value" ] || value="$default"
  printf '%s' "$value"
}

menu_run() {
  local rc=0
  "$@" || rc=$?
  [ "$rc" -ne 0 ] && warn "命令失败（退出码 $rc），返回菜单"
  return 0
}

tui_init() {
  if [ -s "$ETC_DIR/setup.json" ]; then
    warn "邮件身份已配置；如需修改请用 2) 域名管理 → d) 设置身份/DKIM"
    return 0
  fi
  echo '  首次初始化：填写邮件域名，脚本会写入 setup.json、生成 DKIM 并登记域名表。'
  local domain mail_host ip
  domain="$(menu_read '邮件主域名（例 example.com）: ')"
  [ -n "$domain" ] || return 0
  if ! valid_hostname "$domain"; then
    warn "域名不合法：$domain"
    return 0
  fi
  mail_host="$(menu_read "邮件主机名 [mail.$domain]: " "mail.$domain")"
  ip="$(menu_read '服务器公网 IP（留空自动探测）: ')"
  local -a args=("$domain" --complete --mail-host "$mail_host")
  [ -n "$ip" ] && args+=(--server-ip "$ip")
  menu_run cmd_domain_set "${args[@]}"
}

tui_loop() {
  [ -t 0 ] || { usage; exit 2; }
  require_root
  derive_paths
  init_logging
  load_state
  while true; do
    [ -t 1 ] && printf '\033[2J\033[H'
    tui_header
    tui_menu
    local choice=""
    printf '选择: '
    IFS= read -r choice || break
    case "$choice" in
      1) menu_run cmd_status ;;
      2) tui_domain ;;
      3) tui_account ;;
      4) tui_access ;;
      5) tui_service ;;
      6) tui_backup ;;
      7) tui_update ;;
      8) tui_security ;;
      9) tui_repair_uninstall ;;
      i|init) tui_init ;;
      0|q|quit|exit) break ;;
      *) warn "无效选择：$choice" ;;
    esac
  done
  printf '\n再见。\n'
}

# ---------------------------------------------------------------------------
# usage / dispatch
# ---------------------------------------------------------------------------

usage() {
  cat <<EOF
MailStack 管理脚本（mailstack-manage）v$VERSION

用法:
  sudo mailstack-manage [--prefix DIR] [--json] <命令> [参数...]
  无参数 + TTY → 面板式交互菜单。

监控:
  status [--json]                状态总览（服务/端口/队列/TLS/磁盘/访问模式/管理员）
  doctor                         体检并返回非零（有 FAIL 时）
  info                           同 status

域名:
  domain list | add <domain> | delete <domain> | set <domain> [选项]
       set 选项: --mail-host --server-ip --dkim-selector --complete --no-restart --skip-domain-table

邮箱:
  account list | add <email> [--password-stdin|--password|--name] | passwd <email> | delete <email>

访问与 TLS:
  access show
  access set <${ACCESS_MODES[*]}> [--panel-host --webmail-host --acme-email
              --server-ip --acme-webroot --no-reload]
  tls issue <host> [--email E] [--method standalone|webroot] [--webroot DIR]
  tls renew [<host>|--all]

服务:
  service start|stop|restart|reload|status [unit]
  service logs [unit] [--lines N] [-f]
  restart [unit ...]

备份:
  backup create [--include-mails] [--include-secrets] [--passphrase-stdin]
  backup list
  backup restore <filename> [--dry-run] [--passphrase-stdin] [--confirm]
  backup delete <filename> [--confirm]

更新/修复/卸载:
  update check | update apply
  repair
  uninstall [--purge]

安全:
  security status | scan | 2fa | bans | unban <ip> | passwd [--password-stdin]
  security firewall status|open [ports...]|close [ports...]

全局:
  --prefix DIR        staging 前缀（MAILSTACK_PREFIX）
  --json              status/scan 输出 JSON
  --yes/--confirm     自动确认破坏性操作
  -h, --help          帮助
  --version           版本

访问模式: ssh（默认）、caddy、nginx、ip-acme、panel-domain、cloudflared；
旧值 local/caddy/direct 也接受。8443/8444 恒为回环监听。
日志：$LOG_FILE（0600，记录管理操作审计）
EOF
}

dispatch() {
  if [ "$#" -eq 0 ]; then
    tui_loop
    return 0
  fi
  local command="$1"
  shift
  case "$command" in
    -h|--help|help) usage; return 0 ;;
    --version|version) printf 'mailstack-manage %s\n' "$VERSION"; return 0 ;;
  esac
  require_root
  derive_paths
  init_logging
  case "$command" in
    status|info) cmd_status ;;
    doctor) cmd_doctor ;;
    access)
      local sub="${1:-show}"; [ "$#" -gt 0 ] && shift
      case "$sub" in
        show|list) cmd_access_show ;;
        set) cmd_access_set "$@" ;;
        -h|--help) usage ;;
        *) die_usage "access 未知子命令：$sub（show|set）" ;;
      esac ;;
    domain)
      local sub="${1:-list}"; [ "$#" -gt 0 ] && shift
      case "$sub" in
        set) cmd_domain_set "$@" ;;
        list) cmd_domain_list ;;
        add) cmd_domain_add "$@" ;;
        delete|del|rm) cmd_domain_delete "$@" ;;
        -h|--help) usage ;;
        *) die_usage "domain 未知子命令：$sub（list|add|delete|set）" ;;
      esac ;;
    account)
      local sub="${1:-list}"; [ "$#" -gt 0 ] && shift
      case "$sub" in
        add) cmd_account_add "$@" ;;
        list) cmd_account_list ;;
        passwd|password) cmd_account_passwd "$@" ;;
        delete|del|rm) cmd_account_delete "$@" ;;
        -h|--help) usage ;;
        *) die_usage "account 未知子命令：$sub（list|add|passwd|delete）" ;;
      esac ;;
    tls)
      local sub="${1:-}"; [ "$#" -gt 0 ] && shift
      case "$sub" in
        issue) cmd_tls_issue "$@" ;;
        renew) cmd_tls_renew "$@" ;;
        -h|--help) usage ;;
        *) die_usage "tls 未知子命令：$sub（issue|renew）" ;;
      esac ;;
    backup) cmd_backup "$@" ;;
    update|upgrade) cmd_update "$@" ;;
    security) cmd_security "$@" ;;
    service) cmd_service "$@" ;;
    restart) require_root; load_state; restart_units "$@" ;;
    logs) cmd_logs "$@" ;;
    repair) cmd_repair ;;
    uninstall) cmd_uninstall ;;
    *) die_usage "未知命令：$command" ;;
  esac
}

main() {
  setup_colors
  local -a rest=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --prefix) [ "$#" -ge 2 ] || die_usage "--prefix 需要目录"; PREFIX="$2"; shift 2 ;;
      --prefix=*) PREFIX="${1#*=}"; shift ;;
      --json) JSON_OUT=1; shift ;;
      --yes|--confirm|--force) ASSUME_YES=1; shift ;;
      *) rest+=("$1"); shift ;;
    esac
  done
  normalize_prefix
  dispatch ${rest[@]+"${rest[@]}"}
  # dispatch 里的子函数需要路径/状态；未派生时补一次（用于无命令菜单路径）
}

main "$@"

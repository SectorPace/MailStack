
set -Eeuo pipefail
umask 022

readonly SCRIPT_VERSION="1.0.0"
readonly MAILSTACK_VERSION_FALLBACK="1.0.0"

readonly UNITS_ALL=(mailstackd mailstack-web mailstack-imap mailstack-webmail)
readonly ACCESS_MODES_ALL=(ssh caddy nginx ip-acme panel-domain cloudflared)

say()  { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }

die() {
  err "$*"
  exit 1
}
die_usage() {
  err "$*"
  printf '    （用法见：mailstack-manage --help）\n' >&2
  exit 2
}

on_err() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 141 ]; then
    printf 'ERROR: mailstack-manage 在第 %s 行失败（退出码 %s）\n' "${BASH_LINENO[0]:-?}" "$rc" >&2
  fi
  exit "$rc"
}
trap on_err ERR

PREFIX="${MAILSTACK_PREFIX:-/}"
PREFIX_NORM=""
ETC_DIR=""
VAR_LIB_DIR=""
RUN_DIR=""
BIN_DIR=""
LIBEXEC_DIR=""
UNIT_DIR=""
TLS_DIR=""
ACCESS_DIR=""
DOMAINS_TABLE=""
STATE_FILE=""

ACCESS_MODE="local"
ACCESS_MODE_DETAIL=""
DOMAIN=""
MAIL_HOST=""
ADMIN_USER="admin"
ADMIN_PORT="8443"
WEBMAIL_PORT="8444"
PANEL_HOST=""
PANEL_HOST_AUTO="0"
WEBMAIL_HOST=""
WEBMAIL_HOST_AUTO="0"
PANEL_URL=""
WEBMAIL_URL=""
ACME_EMAIL=""
SERVER_IP=""
IMAP_ENABLE="1"
MAILSTACK_VERSION="$MAILSTACK_VERSION_FALLBACK"
INSTALLED_AT=""
STATE_LOADED=0
CHANGED=0
PRIV_LAST_OUT=""

normalize_prefix() {
  [ -n "$PREFIX" ] || PREFIX="/"
  case "$PREFIX" in
    /*) : ;;
    *) die_usage "MAILSTACK_PREFIX/--prefix 必须是绝对路径（实际：$PREFIX）" ;;
  esac
  while [ "$PREFIX" != "/" ] && [ "${PREFIX%/}" != "$PREFIX" ]; do
    PREFIX="${PREFIX%/}"
  done
  if [ "$PREFIX" = "/" ]; then
    PREFIX_NORM=""
  else
    printf '%s' "$PREFIX" | grep -Eq '^/[A-Za-z0-9._/-]+$' \
      || die_usage "前缀只允许字母/数字/_/./-//（实际：$PREFIX）"
    case "$PREFIX" in
      /etc|/usr|/var|/bin|/sbin|/lib|/lib64|/boot|/home|/root|/opt|/srv|/mnt|/media|/run|/tmp|/dev|/proc|/sys)
        die_usage "拒绝把前缀指向系统目录：$PREFIX" ;;
    esac
    case "${PREFIX#/}" in
      */*) : ;;
      *) die_usage "前缀至少要有两级（例：/tmp/mailstack-stage），实际：$PREFIX" ;;
    esac
    PREFIX_NORM="$PREFIX"
  fi
}

prefix_path() { printf '%s%s' "$PREFIX_NORM" "$1"; }

derive_paths() {
  ETC_DIR="$(prefix_path /etc/mailstack)"
  VAR_LIB_DIR="$(prefix_path /var/lib/mailstack)"
  RUN_DIR="$(prefix_path /run/mailstack)"
  BIN_DIR="$(prefix_path /usr/local/bin)"
  LIBEXEC_DIR="$(prefix_path /usr/local/libexec)"
  UNIT_DIR="$(prefix_path /etc/systemd/system)"
  TLS_DIR="$ETC_DIR/tls"
  ACCESS_DIR="$ETC_DIR/access"
  DOMAINS_TABLE="$(prefix_path /etc/postfix/mailstack_domains)"
  STATE_FILE="$ETC_DIR/install-args.conf"
}

load_state() {
  ACCESS_MODE="local"
  ACCESS_MODE_DETAIL=""
  DOMAIN=""
  MAIL_HOST=""
  ADMIN_USER="admin"
  ADMIN_PORT="8443"
  WEBMAIL_PORT="8444"
  PANEL_HOST=""
  PANEL_HOST_AUTO="0"
  WEBMAIL_HOST=""
  WEBMAIL_HOST_AUTO="0"
  PANEL_URL=""
  WEBMAIL_URL=""
  ACME_EMAIL=""
  SERVER_IP=""
  IMAP_ENABLE="1"
  MAILSTACK_VERSION="$MAILSTACK_VERSION_FALLBACK"
  INSTALLED_AT=""
  STATE_LOADED=0

  if [ -f "$STATE_FILE" ]; then
    if [ ! -r "$STATE_FILE" ]; then
      die "无法读取部署状态 $STATE_FILE（权限不足？请用 root）"
    fi
    if ! . "$STATE_FILE"; then
      die "部署状态文件内容不可解析：$STATE_FILE（删掉它并重跑 install.sh 可重建）"
    fi
    STATE_LOADED=1
  fi

  [ -n "${ADMIN_PORT:-}" ] || ADMIN_PORT="8443"
  [ -n "${WEBMAIL_PORT:-}" ] || WEBMAIL_PORT="8444"
  [ -n "${ADMIN_USER:-}" ] || ADMIN_USER="admin"
  [ -n "${MAILSTACK_VERSION:-}" ] || MAILSTACK_VERSION="$MAILSTACK_VERSION_FALLBACK"
}

canonical_access_mode() {
  case "$1" in
    ssh|local)                     printf 'local' ;;
    caddy|nginx|panel-domain|cloudflared) printf 'caddy' ;;
    ip-acme|direct)                printf 'direct' ;;
    *) return 1 ;;
  esac
}

normalize_access_mode() {
  local raw lowered
  raw="${1:-}"
  [ -n "$raw" ] || return 1
  lowered="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  case "$lowered" in
    ssh|local|loopback|tunnel)   printf 'ssh' ;;
    caddy)                       printf 'caddy' ;;
    nginx)                       printf 'nginx' ;;
    ip-acme|ip_acme|ipacme|ip)   printf 'ip-acme' ;;
    panel-domain|panel_domain|panel) printf 'panel-domain' ;;
    cloudflared|cloudflare|cf-tunnel) printf 'cloudflared' ;;
    direct)                      printf 'ip-acme' ;;      # 旧值 direct → 公网直连档
    *) return 1 ;;
  esac
}

is_known_access_mode() {
  normalize_access_mode "$1" >/dev/null 2>&1
}

current_access_detail() {
  if [ -n "${ACCESS_MODE_DETAIL:-}" ]; then
    printf '%s' "$ACCESS_MODE_DETAIL"
    return 0
  fi
  case "${ACCESS_MODE:-local}" in
    local) printf 'ssh' ;;
    caddy) printf 'caddy' ;;
    direct) printf 'ip-acme' ;;
    *) printf '%s' "${ACCESS_MODE:-local}" ;;
  esac
}

default_panel_host_for_mode() {
  local mode="$1" domain="${DOMAIN:-}"
  case "$mode" in
    ssh) return 0 ;;
    ip-acme) printf '%s' "${MAIL_HOST:-$domain}" ;;
    *) [ -n "$domain" ] && printf 'panel.%s' "$domain" ;;
  esac
}

default_webmail_host_for_mode() {
  local mode="$1" domain="${DOMAIN:-}"
  case "$mode" in
    ssh) return 0 ;;
    ip-acme) [ -n "$domain" ] && printf 'webmail.%s' "$domain" ;;
    *) [ -n "$domain" ] && printf 'webmail.%s' "$domain" ;;
  esac
}

panel_url_for() {
  local mode="$1" host="$2"
  case "$mode" in
    ssh) printf 'http://127.0.0.1:%s/' "$ADMIN_PORT" ;;
    *) [ -n "$host" ] && printf 'https://%s/' "$host" ;;
  esac
}

webmail_url_for() {
  local mode="$1" host="$2"
  case "$mode" in
    ssh) printf 'http://127.0.0.1:%s/' "$WEBMAIL_PORT" ;;
    *) [ -n "$host" ] && printf 'https://%s/' "$host" ;;
  esac
}

write_state() {
  local canonical
  canonical="$(canonical_access_mode "$(current_access_detail)" 2>/dev/null || printf '%s' "${ACCESS_MODE:-local}")"
  mkdir -p "$ETC_DIR"
  local tmp="$STATE_FILE.tmp.$$"
  {
    printf '# 由 deploy/install.sh / deploy/mailstack-manage.sh 写入；crates/core/src/mode.rs 读取 ACCESS_MODE 判定公网档\n'
    printf '# 合法 ACCESS_MODE：local | caddy | direct（缺失=local；非法/多值按 direct 从严处理）\n'
    printf '# 详细访问模式（ssh/caddy/nginx/ip-acme/panel-domain/cloudflared）见 ACCESS_MODE_DETAIL；\n'
    printf '# 机器可读副本在 <etc>/access/access.env。不要手工插入第二行 ACCESS_MODE=。\n'
    printf 'ACCESS_MODE=%q\n' "$canonical"
    printf 'ACCESS_MODE_DETAIL=%q\n' "$(current_access_detail)"
    printf 'MAILSTACK_VERSION=%q\n' "$MAILSTACK_VERSION"
    printf 'INSTALLED_AT=%q\n' "${INSTALLED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
    printf 'UPDATED_AT=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'DOMAIN=%q\n' "$DOMAIN"
    printf 'MAIL_HOST=%q\n' "$MAIL_HOST"
    printf 'ADMIN_USER=%q\n' "$ADMIN_USER"
    printf 'ADMIN_PORT=%q\n' "$ADMIN_PORT"
    printf 'WEBMAIL_PORT=%q\n' "$WEBMAIL_PORT"
    printf 'PANEL_HOST=%q\n' "$PANEL_HOST"
    printf 'PANEL_HOST_AUTO=%q\n' "$PANEL_HOST_AUTO"
    printf 'WEBMAIL_HOST=%q\n' "$WEBMAIL_HOST"
    printf 'WEBMAIL_HOST_AUTO=%q\n' "$WEBMAIL_HOST_AUTO"
    printf 'PANEL_URL=%q\n' "$PANEL_URL"
    printf 'WEBMAIL_URL=%q\n' "$WEBMAIL_URL"
    printf 'ACME_EMAIL=%q\n' "$ACME_EMAIL"
    printf 'SERVER_IP=%q\n' "$SERVER_IP"
    printf 'IMAP_ENABLE=%q\n' "$IMAP_ENABLE"
  } > "$tmp"
  chmod 0600 "$tmp"
  chown root:root "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$STATE_FILE"
  ACCESS_MODE="$canonical"
}

write_access_state_files() {
  local mode
  mode="$(current_access_detail)"
  mkdir -p "$ACCESS_DIR"
  chmod 0750 "$ACCESS_DIR" 2>/dev/null || true
  printf '%s\n' "$mode" > "$ACCESS_DIR/mode.tmp.$$"
  chmod 0644 "$ACCESS_DIR/mode.tmp.$$"
  chown root:root "$ACCESS_DIR/mode.tmp.$$" 2>/dev/null || true
  mv -f -- "$ACCESS_DIR/mode.tmp.$$" "$ACCESS_DIR/mode"

  local tmp="$ACCESS_DIR/access.env.tmp.$$"
  {
    printf '# 由 mailstack-manage 生成（机器可读）；修改请用 mailstack-manage access set\n'
    printf 'ACCESS_MODE=%s\n' "$(canonical_access_mode "$mode" 2>/dev/null || printf '%s' "${ACCESS_MODE:-local}")"
    printf 'ACCESS_MODE_DETAIL=%s\n' "$mode"
    printf 'PANEL_HOST=%s\n' "$PANEL_HOST"
    printf 'WEBMAIL_HOST=%s\n' "$WEBMAIL_HOST"
    printf 'PANEL_URL=%s\n' "$PANEL_URL"
    printf 'WEBMAIL_URL=%s\n' "$WEBMAIL_URL"
    printf 'ADMIN_PORT=%s\n' "$ADMIN_PORT"
    printf 'WEBMAIL_PORT=%s\n' "$WEBMAIL_PORT"
    printf 'ACME_EMAIL=%s\n' "$ACME_EMAIL"
    printf 'SERVER_IP=%s\n' "$SERVER_IP"
    printf 'GENERATED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$tmp"
  chmod 0640 "$tmp"
  chown root:root "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$ACCESS_DIR/access.env"
}

is_root() { [ "$(id -u)" -eq 0 ]; }

require_root() {
  is_root || die "需要 root 权限运行（sudo mailstack-manage ...）"
}

have_python3() { command -v python3 >/dev/null 2>&1; }

json_quote() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/ }"
  s="${s//$'\r'/ }"
  s="${s//$'\t'/ }"
  printf '"%s"' "$s"
}

json_error_of() {
  printf '%s' "$1" | sed -n 's/.*"error":"\([^"]*\)".*/\1/p' | head -1
}

json_is_ok() {
  case "$1" in *'"ok":true'*) return 0 ;; *) return 1 ;; esac
}

json_print() {
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

json_data_of() {
  local raw="${1:-}"
  if have_python3 && [ -n "$raw" ]; then
    printf '%s' "$raw" | python3 -c \
      'import json,sys
v=json.load(sys.stdin)
print(json.dumps(v.get("data"), ensure_ascii=False, indent=2))' 2>/dev/null && return 0
  fi
  printf '%s\n' "$raw"
}

valid_domain() {
  printf '%s' "${1:-}" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
}

valid_hostname() { valid_domain "${1:-}"; }

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

systemd_live() {
  [ -z "$PREFIX_NORM" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

prefix_notice() {
  if [ -n "$PREFIX_NORM" ]; then
    info "staging 前缀：$PREFIX_NORM（不操作宿主 systemd）"
  fi
}

write_if_changed() {
  local path="$1" mode="$2" content="$3"
  mkdir -p "$(dirname -- "$path")"
  if [ -f "$path" ] && [ "$(cat -- "$path")" = "$content" ]; then
    info "未变化：$path"
    return 0
  fi
  local tmp="$path.tmp.$$"
  printf '%s\n' "$content" > "$tmp"
  chmod "$mode" "$tmp"
  chown root:root "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$path"
  CHANGED=1
  info "已写入：$path"
}

backup_file() {
  local src="$1"
  [ -f "$src" ] || return 0
  local dir="$ACCESS_DIR/backups"
  mkdir -p "$dir"
  local dest="$dir/$(basename -- "$src").$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a -- "$src" "$dest" 2>/dev/null || { warn "备份失败（继续）：$src"; return 0; }
  info "已备份：$src → $dest"
  local keep
  keep="$(ls -1t "$dir"/"$(basename -- "$src")".* 2>/dev/null | tail -n +21 || true)"
  [ -n "$keep" ] && printf '%s\n' "$keep" | xargs -r rm -f -- 2>/dev/null || true
  return 0
}

detect_local_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{for (i=1; i<=NF; i++) if ($i=="src") { print $(i+1); exit }}' \
    || true
}

setup_json_value() {
  local key="$1"
  [ -s "$ETC_DIR/setup.json" ] || return 1
  sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC_DIR/setup.json" | head -1
}

priv_call() {
  local action="$1" data="${2:-'{}'}" out rc=0
  [ -n "$action" ] || die "内部错误：priv_call 缺少动作名"

  local ctl wrapper_arg config_arg
  if [ -n "$PREFIX_NORM" ]; then
    ctl="$BIN_DIR/mailstackctl"
    config_arg="$PREFIX_NORM"
  else
    ctl="$LIBEXEC_DIR/mailstack-privileged"
    config_arg=""
    [ -x "$ctl" ] || ctl="$BIN_DIR/mailstackctl"
  fi
  [ -x "$ctl" ] || die "找不到特权调用入口：$ctl（先运行 deploy/install.sh）"

  local req
  req="$(printf '{"action":%s,"data":%s}' "$(json_quote "$action")" "$data")"

  if [ -n "$config_arg" ]; then
    out="$(printf '%s' "$req" | "$BIN_DIR/mailstackctl" --privileged-stdin --config-dir "$config_arg" 2>&1)" || rc=$?
  else
    out="$(printf '%s' "$req" | "$ctl" 2>&1)" || rc=$?
  fi

  PRIV_LAST_OUT="$out"
  if [ "$rc" -ne 0 ]; then
    err "特权调用失败：$action（入口 $ctl 退出码 $rc）"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
    return 1
  fi
  if ! json_is_ok "$out"; then
    local message
    message="$(json_error_of "$out")"
    [ -n "$message" ] || message="$out"
    err "动作 $action 失败：$message"
    return 1
  fi
  printf '%s' "$out"
  return 0
}

priv_call_show() {
  local action="$1" data="${2:-'{}'}" out
  out="$(priv_call "$action" "$data")" || return 1
  json_data_of "$out"
}

unit_file_of() { printf '%s/%s.service' "$UNIT_DIR" "$1"; }

restart_units() {
  local units=("$@")
  if [ "${#units[@]}" -eq 0 ]; then
    units=("${UNITS_ALL[@]}")
  fi
  local unit
  if ! systemd_live; then
    info "未检测到运行中的 systemd（staging 前缀或容器）：跳过 restart，手工命令："
    for unit in "${units[@]}"; do
      printf '    systemctl restart %s\n' "$unit"
    done
    return 0
  fi
  systemctl daemon-reload >/dev/null 2>&1 || warn "systemctl daemon-reload 失败"
  for unit in "${units[@]}"; do
    if systemctl restart "$unit" >/dev/null 2>&1; then
      info "已重启：$unit"
    else
      warn "systemctl restart $unit 失败（journalctl -u $unit 查看；unit 不存在时属正常）"
    fi
  done
}

proxy_header_comment() {
  printf '# 由 mailstack-manage 生成（access set %s）。不要手改：重新运行\n#   sudo mailstack-manage access set %s\n# 即可刷新本文件；手工改动会在下次刷新时丢失。' "$1" "$1"
}

assert_loopback_bindings() {
  local f bad=0
  for f in "$UNIT_DIR/mailstack-web.service" "$UNIT_DIR/mailstack-webmail.service"; do
    [ -f "$f" ] || continue
    if grep -Eq -- '--bind[= ][^ ]*0\.0\.0\.0' "$f"; then
      warn "发现 $f 把 --bind 指向 0.0.0.0：8443/8444 只允许绑 127.0.0.1（公网入口必须经反向代理/隧道）"
      bad=1
    fi
  done
  return 0
}

generate_caddyfile() {
  local panel="$1" webmail="$2"
  local email_line=""
  if [ -n "$ACME_EMAIL" ]; then
    email_line="	email $ACME_EMAIL"
  else
    email_line="	# email 未设置：可运行 access set caddy --acme-email ops@example.com 指定 ACME 账户邮箱"
  fi
  cat <<EOF
$(proxy_header_comment "caddy")
#
# Caddy 自动申请/续期 Let's Encrypt 证书（HTTP-01/TLS-ALPN-01），并自动做
# HTTP→HTTPS 跳转。前置条件：$panel / $webmail 的 A/AAAA 记录指向本机，
# 80/443 对公网可达。
{
	$email_line
}

# 管理台（mailstack-web 只监听 127.0.0.1:${ADMIN_PORT}，TLS 在这里终止）
$panel {
	encode zstd gzip
	reverse_proxy 127.0.0.1:${ADMIN_PORT} {
		header_up Host {host}
		header_up X-Real-IP {remote_host}
		header_up X-Forwarded-For {remote_host}
		header_up X-Forwarded-Proto {scheme}
	}
}

# Webmail（mailstack-webmail 只监听 127.0.0.1:${WEBMAIL_PORT}）
$webmail {
	encode zstd gzip
	reverse_proxy 127.0.0.1:${WEBMAIL_PORT} {
		header_up Host {host}
		header_up X-Real-IP {remote_host}
		header_up X-Forwarded-For {remote_host}
		header_up X-Forwarded-Proto {scheme}
	}
}
EOF
}

generate_nginx_http_conf() {
  local panel="$1" webmail="$2"
  cat <<EOF
$(proxy_header_comment "nginx")
#
# 先在 80 端口跑通反向代理；TLS 用下面任一方式补上（推荐第一种）：
#   sudo apt install -y certbot python3-certbot-nginx
#   sudo certbot --nginx -d $panel -d $webmail
#   # 或 acme.sh：
#   sudo /root/.acme.sh/acme.sh --issue -d $panel -d $webmail --nginx
#
# 管理台/Webmail 进程只监听 127.0.0.1:${ADMIN_PORT}/${WEBMAIL_PORT}，这里是唯一公网入口。
# 上游若改 bind 到 0.0.0.0 属于安全违规（访问层不会这样做）。

server {
    listen 80;
    listen [::]:80;
    server_name $panel;

    client_max_body_size 40m;   # Webmail 附件上限 32MiB + 余量

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

acme_webroot() { printf '%s' "${ACME_WEBROOT:-/var/www/mailstack-acme}"; }

generate_nginx_tls_conf() {
  local panel="$1" webmail="$2"
  local panel_cert="$TLS_DIR/$panel/fullchain.pem"
  local panel_key="$TLS_DIR/$panel/privkey.pem"
  local webmail_cert="$TLS_DIR/$webmail/fullchain.pem"
  local webmail_key="$TLS_DIR/$webmail/privkey.pem"
  local webroot
  webroot="$(acme_webroot)"
  cat <<EOF
$(proxy_header_comment "$(current_access_detail)")
#
# TLS 证书来源：mailstackctl setup.cert.issue / certs.renew，落点
#   $TLS_DIR/<host>/{fullchain,privkey}.pem
# 签发前 DNS 必须就绪（A 记录指向本机公网 IP，80 端口对 Let's Encrypt 可达）：
#   sudo mailstack-manage tls issue $panel --email ops@example.com
#   sudo mailstack-manage tls issue $webmail --email ops@example.com
#
# 管理台/Webmail 进程只监听 127.0.0.1:${ADMIN_PORT}/${WEBMAIL_PORT}，TLS 在这里终止。

server {
    listen 80;
    listen [::]:80;
    server_name $panel $webmail;

    # ACME HTTP-01 校验目录（acme.sh webroot 模式用；standalone 模式可忽略）
    location /.well-known/acme-challenge/ {
        root $webroot;
        default_type text/plain;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $panel;

    ssl_certificate     $panel_cert;
    ssl_certificate_key $panel_key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:MailStackTLS:10m;
    ssl_session_timeout 1d;

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

    ssl_certificate     $webmail_cert;
    ssl_certificate_key $webmail_key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:MailStackTLS:10m;
    ssl_session_timeout 1d;

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

generate_cloudflared_config() {
  local panel="$1" webmail="$2" tunnel="${CLOUDFLARE_TUNNEL:-REPLACE_WITH_TUNNEL_UUID}"
  cat <<EOF
$(proxy_header_comment "cloudflared")
#
# Cloudflare Tunnel：本机不需要开放 8443/8444，也不需要本地 TLS 证书。
# tunnel 指到本机回环即可（Cloudflare 边缘负责公网 TLS）。
#
# 首次配置步骤（只需一次）：
#   1) 安装 cloudflared（Debian/Ubuntu）：
#        sudo mkdir -p --mode=0755 /usr/share/keyrings
#        curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
#        echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
#        sudo apt update && sudo apt install -y cloudflared
#   2) 登录并创建 tunnel：
#        sudo cloudflared tunnel login
#        sudo cloudflared tunnel create mailstack
#      记下 Tunnel ID，把下面 tunnel/credentials-file 改成真实值（或设 CLOUDFLARE_TUNNEL=<id> 后重跑 access set cloudflared）。
#   3) 在 Cloudflare DNS 里创建 CNAME：$panel → <TunnelID>.cfargotunnel.com
#                                    $webmail → <TunnelID>.cfargotunnel.com
#   4) 启动：sudo systemctl enable --now mailstack-cloudflared

tunnel: $tunnel
credentials-file: /etc/cloudflared/$tunnel.json
# 远端配置以本地 ingress 为准（不要同时在 Dashboard 配 public hostname 的 service，
# 否则以 Dashboard 为准且会覆盖这里；二选一，推荐本地 ingress）。
no-autoupdate: true

ingress:
  - hostname: $panel
    service: http://127.0.0.1:${ADMIN_PORT}
    originRequest:
      httpHostHeader: $panel
  - hostname: $webmail
    service: http://127.0.0.1:${WEBMAIL_PORT}
    originRequest:
      httpHostHeader: $webmail
  # 兜底规则：不匹配的请求直接 404
  - service: http_status:404
EOF
}

generate_cloudflared_unit() {
  local access_dir="$ACCESS_DIR/cloudflared"
  local bin
  bin="$(command -v cloudflared 2>/dev/null || printf '/usr/bin/cloudflared')"
  cat <<EOF
[Unit]
Description=MailStack Cloudflare Tunnel (panel/webmail access)
Documentation=https://github.com/SectorPace/MailStack
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 隧道目标恒为回环：本机 8443/8444 不对外暴露，公网 TLS 由 Cloudflare 边缘终止。
ExecStart=$bin --no-autoupdate --config $access_dir/config.yml tunnel run
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
User=root
Group=root
# cloudflared 只需要读配置与凭据，不需要写系统任何位置。
ProtectSystem=strict
ReadWritePaths=$access_dir /etc/cloudflared
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
}

generate_ssh_files() {
  local ssh_dir="$ACCESS_DIR/ssh"
  local panel_line webmail_line
  panel_line="  ssh -N -L ${ADMIN_PORT}:127.0.0.1:${ADMIN_PORT} -L ${WEBMAIL_PORT}:127.0.0.1:${WEBMAIL_PORT} <user>@<server>"
  cat <<EOF
# MailStack 访问模式：ssh（默认，最安全）
#
# 管理台与 Webmail 都只监听回环地址，不安装反向代理、不对外开 8443/8444。
# 从本机或跳板机建立 SSH 隧道后，用 http://127.0.0.1 访问：
#
#   隧道：
$panel_line
#
#   浏览器：
#     管理台  http://127.0.0.1:${ADMIN_PORT}/?login=1
#     Webmail http://127.0.0.1:${WEBMAIL_PORT}/
#
# 建议把 SSH 放在 VPN / bastion 之后，并只允许密钥登录。切换公网访问模式：
#   sudo mailstack-manage access set caddy|nginx|panel-domain|ip-acme|cloudflared
EOF
  write_if_changed "$ssh_dir/README.txt" 0644 "$(cat <<EOF
MailStack 访问模式 = ssh
隧道命令：
$panel_line
然后访问：http://127.0.0.1:${ADMIN_PORT}/?login=1（管理台） / http://127.0.0.1:${WEBMAIL_PORT}/（Webmail）
本文件由 mailstack-manage 生成。
EOF
)"
  write_if_changed "$ssh_dir/tunnel.sh" 0755 "$(cat <<EOF
#!/usr/bin/env bash
# 由 mailstack-manage 生成：建立到 MailStack 管理台/Webmail 的 SSH 隧道。
# 用法：sudo -u <你的运维账号> ./tunnel.sh [ssh 目标，例如 admin@mail.example.com]
set -Eeuo pipefail
target="\${1:-<user>@<server>}"
exec ssh -N -o ExitOnForwardFailure=yes \\
  -L ${ADMIN_PORT}:127.0.0.1:${ADMIN_PORT} \\
  -L ${WEBMAIL_PORT}:127.0.0.1:${WEBMAIL_PORT} \\
  "\$target"
EOF
)"
}

cmd_access_show() {
  require_root
  load_state
  local detail canonical
  detail="$(current_access_detail)"
  canonical="$(canonical_access_mode "$detail" 2>/dev/null || printf '%s' "${ACCESS_MODE:-local}")"

  say "访问模式（access）"
  info "详细模式:      $detail（归一后：$canonical；mode.rs 读 ACCESS_MODE）"
  info "状态文件:      $STATE_FILE（$([ "$STATE_LOADED" -eq 1 ] && echo 已加载 || echo 缺失)）"
  info "模式标记:      $ACCESS_DIR/mode（$([ -f "$ACCESS_DIR/mode" ] && cat "$ACCESS_DIR/mode" || echo 缺失)）"
  info "管理台:        ${PANEL_URL:-（未配置）}（内部 127.0.0.1:${ADMIN_PORT}）"
  info "Webmail:       ${WEBMAIL_URL:-（未配置）}（内部 127.0.0.1:${WEBMAIL_PORT}）"
  info "面板主机:      ${PANEL_HOST:-（无 —— ssh 模式只走回环）}"
  info "Webmail 主机:  ${WEBMAIL_HOST:-（无）}"
  info "ACME 邮箱:     ${ACME_EMAIL:-（未设置）}"
  info "服务器 IP:     ${SERVER_IP:-（未设置）}"

  echo
  echo '    访问模式行为矩阵:'
  printf '      %-13s %-28s %s\n' '模式' '入口' 'TLS/证书'
  printf '      %-13s %-28s %s\n' 'ssh' '回环 + SSH 隧道' '不需要（不对外）'
  printf '      %-13s %-28s %s\n' 'caddy' 'Caddy 反代 panel/webmail' 'Caddy 自动 ACME'
  printf '      %-13s %-28s %s\n' 'nginx' 'nginx 反代（80 → certbot）' 'certbot --nginx 补 TLS'
  printf '      %-13s %-28s %s\n' 'ip-acme' 'nginx 443 反代（公网 IP 路径）' 'mailstackctl ACME → tls 目录'
  printf '      %-13s %-28s %s\n' 'panel-domain' '独立 panel 主机名反代' 'Caddy 或 nginx+ACME'
  printf '      %-13s %-28s %s\n' 'cloudflared' 'Cloudflare Tunnel → 回环' 'Cloudflare 边缘 TLS'

  echo
  echo '    已生成文件:'
  if [ -d "$ACCESS_DIR" ]; then
    find "$ACCESS_DIR" -maxdepth 3 -type f -printf '      %-80p\n' 2>/dev/null | sort || true
  else
    echo '      （无：运行 mailstack-manage access set <mode>）'
  fi

  echo
  echo '    宿主配置同步:'
  local f marker='由 mailstack-manage 生成'
  for f in "$(prefix_path /etc/caddy/mailstack.caddy)" \
           "$(prefix_path /etc/nginx/conf.d/mailstack-panel.conf)" \
           "$UNIT_DIR/mailstack-cloudflared.service"; do
    if [ ! -f "$f" ]; then
      printf '      %-70s 未安装\n' "$f"
    elif grep -qF "$marker" "$f" 2>/dev/null; then
      printf '      %-70s 已安装（本工具生成）\n' "$f"
    else
      printf '      %-70s 已存在（非本工具生成，未覆盖）\n' "$f"
    fi
  done
  assert_loopback_bindings
}

sync_caddy_live() {
  local canonical="$ACCESS_DIR/caddy/Caddyfile"
  local live="$(prefix_path /etc/caddy/mailstack.caddy)"
  local main="$(prefix_path /etc/caddy/Caddyfile)"
  local marker='import /etc/caddy/mailstack.caddy'

  if ! command -v caddy >/dev/null 2>&1; then
    info "未安装 caddy：已生成 $canonical"
    info "  安装：sudo apt install -y caddy（或见 https://caddyserver.com/docs/install）"
    info "  然后：sudo mailstack-manage access set caddy（会写入 $live 并在 $main 里 import）"
    return 0
  fi

  write_if_changed "$live" 0644 "$(cat -- "$canonical")"
  if [ -f "$main" ] && grep -qF -- "$marker" "$main"; then
    info "已存在 import 指令：$main"
  else
    if [ -f "$main" ]; then
      backup_file "$main"
      printf '\n# >>> mailstack-manage（由 deploy/mailstack-manage.sh 管理） >>>\n%s\n# <<< mailstack-manage <<<\n' "$marker" >> "$main"
      info "已把 import 指令追加到既有 $main（原文件已备份）"
    else
      mkdir -p "$(dirname -- "$main")"
      printf '%s\n' "$marker" > "$main"
      chmod 0644 "$main"
      info "已创建 $main"
    fi
    CHANGED=1
  fi

  # 语法校验：caddy validate 需要能定位 caddyfile adapter；失败时不动服务。
  if ! caddy validate --config "$main" --adapter caddyfile >/dev/null 2>&1; then
    warn "caddy validate 失败：$main（配置已写入但未 reload；修正后重跑）"
    return 0
  fi
  info "caddy validate 通过"
  if systemd_live; then
    if systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1; then
      info "已 reload caddy"
    else
      warn "caddy 服务 reload/restart 失败（systemctl status caddy 查看）"
    fi
  else
    info "未检测到运行中的 systemd：跳过 caddy reload"
  fi
  return 0
}

sync_nginx_live() {
  local variant="$1"   # http | tls
  local canonical="$ACCESS_DIR/nginx/mailstack-panel.conf"
  local live="$(prefix_path /etc/nginx/conf.d/mailstack-panel.conf)"

  if ! command -v nginx >/dev/null 2>&1; then
    info "未安装 nginx：已生成 $canonical"
    info "  安装：sudo apt install -y nginx（RHEL 系：sudo dnf install -y nginx）"
    info "  然后：sudo mailstack-manage access set $(current_access_detail)（会写入 $live）"
    return 0
  fi

  if [ "$variant" = "tls" ]; then
    local h missing=0
    for h in "$PANEL_HOST" "$WEBMAIL_HOST"; do
      [ -n "$h" ] || continue
      [ -f "$TLS_DIR/$h/fullchain.pem" ] && [ -f "$TLS_DIR/$h/privkey.pem" ] || missing=1
    done
    if [ "$missing" -eq 1 ]; then
      warn "TLS 证书尚未就绪：跳过写入 $live（先运行 mailstack-manage tls issue <host>）"
      info "  已生成模板：$canonical"
      return 0
    fi
  fi

  write_if_changed "$live" 0644 "$(cat -- "$canonical")"
  if ! nginx -t >/dev/null 2>&1; then
    warn "nginx -t 失败：$live 已写入但未 reload（nginx -t 查看原因）"
    return 0
  fi
  info "nginx -t 通过"
  if systemd_live; then
    if systemctl reload nginx >/dev/null 2>&1; then
      info "已 reload nginx"
    else
      warn "nginx reload 失败（systemctl status nginx 查看）"
    fi
  else
    info "未检测到运行中的 systemd：跳过 nginx reload"
  fi
  return 0
}

sync_cloudflared_live() {
  local access_dir="$ACCESS_DIR/cloudflared"
  local config="$access_dir/config.yml"
  local unit_src="$access_dir/mailstack-cloudflared.service"
  local unit_dst="$UNIT_DIR/mailstack-cloudflared.service"

  write_if_changed "$unit_src" 0644 "$(generate_cloudflared_unit)"
  write_if_changed "$unit_dst" 0644 "$(cat -- "$unit_src")"

  local tunnel_line
  tunnel_line="$(sed -n 's/^tunnel:[[:space:]]*//p' "$config" 2>/dev/null | head -1)"
  if [ -z "$tunnel_line" ] || [ "${tunnel_line#REPLACE_WITH_TUNNEL_UUID}" != "$tunnel_line" ]; then
    warn "cloudflared 配置仍是占位符：$config"
    info "  完成 Cloudflare 侧配置（cloudflared tunnel login/create）后重跑："
    info "    sudo CLOUDFLARE_TUNNEL=<tunnel-id> mailstack-manage access set cloudflared"
    info "  或手工改 tunnel/credentials-file 后：sudo systemctl enable --now mailstack-cloudflared"
    if systemd_live; then
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    return 0
  fi

  if ! command -v cloudflared >/dev/null 2>&1; then
    warn "未安装 cloudflared（配置与 unit 已生成；安装后启动）"
    info "  安装步骤见：$config 文件头注释"
    return 0
  fi
  if systemd_live; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl enable --now mailstack-cloudflared >/dev/null 2>&1; then
      info "已 enable --now mailstack-cloudflared"
    else
      warn "systemctl enable --now mailstack-cloudflared 失败（journalctl -u mailstack-cloudflared 查看）"
    fi
  else
    info "未检测到运行中的 systemd：跳过 cloudflared 启动"
  fi
  return 0
}

write_access_mode_files() {
  local mode="$1" panel="$2" webmail="$3"

  mkdir -p "$ACCESS_DIR"
  case "$mode" in
    ssh)
      generate_ssh_files
      ;;
    caddy)
      [ -n "$panel" ] || die "caddy 模式需要面板主机名（--panel-host，或提供 --domain）"
      [ -n "$webmail" ] || die "caddy 模式需要 Webmail 主机名（--webmail-host，或提供 --domain）"
      write_if_changed "$ACCESS_DIR/caddy/Caddyfile" 0644 "$(generate_caddyfile "$panel" "$webmail")"
      sync_caddy_live
      ;;
    nginx)
      [ -n "$panel" ] || die "nginx 模式需要面板主机名（--panel-host，或提供 --domain）"
      [ -n "$webmail" ] || die "nginx 模式需要 Webmail 主机名（--webmail-host，或提供 --domain）"
      write_if_changed "$ACCESS_DIR/nginx/mailstack-panel.conf" 0644 "$(generate_nginx_http_conf "$panel" "$webmail")"
      write_if_changed "$ACCESS_DIR/nginx/README.txt" 0644 "$(cat <<EOF
MailStack 访问模式 = nginx
1) 已写入 $ACCESS_DIR/nginx/mailstack-panel.conf（80 端口反向代理）；
2) 给它加 TLS（二者其一）：
     sudo apt install -y certbot python3-certbot-nginx
     sudo certbot --nginx -d $panel -d $webmail
   或 acme.sh：
     sudo /root/.acme.sh/acme.sh --issue -d $panel -d $webmail --nginx
3) 检查：sudo nginx -t && sudo systemctl reload nginx
本文件由 mailstack-manage 生成。
EOF
)"
      sync_nginx_live http
      ;;
    ip-acme|panel-domain)
      [ -n "$panel" ] || die "${mode} 模式需要面板主机名（--panel-host，或提供 --domain）"
      [ -n "$webmail" ] || die "${mode} 模式需要 Webmail 主机名（--webmail-host，或提供 --domain）"
      local variant="tls" chosen="nginx"
      if [ "$mode" = "panel-domain" ] && command -v caddy >/dev/null 2>&1; then
        chosen="caddy"
      fi
      if [ "$chosen" = "caddy" ]; then
        write_if_changed "$ACCESS_DIR/caddy/Caddyfile" 0644 "$(generate_caddyfile "$panel" "$webmail")"
        sync_caddy_live
      else
        write_if_changed "$ACCESS_DIR/nginx/mailstack-panel.conf" 0644 "$(generate_nginx_tls_conf "$panel" "$webmail")"
        write_if_changed "$ACCESS_DIR/nginx/README.txt" 0644 "$(cat <<EOF
MailStack 访问模式 = $mode（nginx TLS 变体）
证书落点：$TLS_DIR/<host>/{fullchain,privkey}.pem（由 mailstackctl setup.cert.issue 签发）
签发命令（先确认 DNS）：
  sudo mailstack-manage tls issue $panel --email ${ACME_EMAIL:-<你的邮箱>}
  sudo mailstack-manage tls issue $webmail --email ${ACME_EMAIL:-<你的邮箱>}
签发完成后重跑本命令把 nginx TLS 站点装上：
  sudo mailstack-manage access set $mode
DNS 要求：
  A 记录 $panel → ${SERVER_IP:-<本机公网 IP>}
  A 记录 $webmail → ${SERVER_IP:-<本机公网 IP>}
  80/tcp 对 Let's Encrypt 可达（HTTP-01）；不要让 CNAME 指到别的名字。
本文件由 mailstack-manage 生成。
EOF
)"
        sync_nginx_live "$variant"
      fi
      write_if_changed "$ACCESS_DIR/$mode/DNS-REQUIREMENTS.txt" 0644 "$(cat <<EOF
MailStack 访问模式 = $mode —— DNS / 网络前置条件
1) 面板主机 $panel 的 A/AAAA 记录必须指向本机公网 IP（${SERVER_IP:-<未记录>}）。
2) Webmail 主机 $webmail 同上；两者都**不要**与 mail./imap./smtp. 混用。
3) 80/tcp 必须对 Let's Encrypt 可达（HTTP-01）。若 80 被云厂商封禁，
   改用 DNS-01 或直接使用 Cloudflare Tunnel（access set cloudflared）。
4) 证书由 mailstackctl 调本机 acme.sh 签发：
     /root/.acme.sh/acme.sh（缺失时先安装 acme.sh）
   落点：$TLS_DIR/<host>/{fullchain,privkey}.pem。
5) 本层不在 8443/8444 上直接对外提供 TLS；两个 Rust 进程始终只绑 127.0.0.1。
本文件由 mailstack-manage 生成。
EOF
)"
      ;;
    cloudflared)
      [ -n "$panel" ] || die "cloudflared 模式需要面板主机名（--panel-host，或提供 --domain）"
      [ -n "$webmail" ] || die "cloudflared 模式需要 Webmail 主机名（--webmail-host，或提供 --domain）"
      local cfg="$ACCESS_DIR/cloudflared/config.yml"
      if [ ! -f "$cfg" ] || [ "${CLOUDFLARE_TUNNEL:-}" != "" ]; then
        write_if_changed "$cfg" 0640 "$(generate_cloudflared_config "$panel" "$webmail")"
      else
        info "保留既有 cloudflared 配置（不要被占位符覆盖）：$cfg"
      fi
      write_if_changed "$ACCESS_DIR/cloudflared/README.txt" 0644 "$(cat <<EOF
MailStack 访问模式 = cloudflared
入口：Cloudflare Tunnel → http://127.0.0.1:${ADMIN_PORT} / http://127.0.0.1:${WEBMAIL_PORT}
本机不需要公网 IP、不需要开放 8443/8444、不需要本地证书。
必须完成（一次性）：
  sudo cloudflared tunnel login
  sudo cloudflared tunnel create mailstack
  # 记下 Tunnel ID；然后
  sudo CLOUDFLARE_TUNNEL=<tunnel-id> mailstack-manage access set cloudflared
Cloudflare DNS（在 Zero Trust / DNS 面板）：
  $panel  CNAME  <tunnel-id>.cfargotunnel.com
  $webmail CNAME  <tunnel-id>.cfargotunnel.com
启动：sudo systemctl enable --now mailstack-cloudflared
注意：不能同时在 Dashboard 与本地 config.yml 配置同一个 hostname 的 service（二选一）。
本文件由 mailstack-manage 生成。
EOF
)"
      sync_cloudflared_live
      ;;
    *)
      die "内部错误：未知访问模式 $mode"
      ;;
  esac
}

cmd_access_set() {
  require_root
  load_state

  local requested="${1:-}"
  [ -n "$requested" ] || die_usage "access set 需要模式：${ACCESS_MODES_ALL[*]}"
  shift || true

  local mode
  mode="$(normalize_access_mode "$requested")" \
    || die_usage "未知访问模式：$requested（可选：${ACCESS_MODES_ALL[*]}；旧值 local/caddy/direct 仍接受）"

  local opt_panel="" opt_webmail="" opt_email="" opt_ip="" opt_webroot="" no_reload=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --panel-host)    [ "$#" -ge 2 ] || die_usage "--panel-host 需要参数"; opt_panel="$2"; shift 2 ;;
      --panel-host=*)  opt_panel="${1#*=}"; shift ;;
      --webmail-host)  [ "$#" -ge 2 ] || die_usage "--webmail-host 需要参数"; opt_webmail="$2"; shift 2 ;;
      --webmail-host=*) opt_webmail="${1#*=}"; shift ;;
      --acme-email)    [ "$#" -ge 2 ] || die_usage "--acme-email 需要参数"; opt_email="$2"; shift 2 ;;
      --acme-email=*)  opt_email="${1#*=}"; shift ;;
      --server-ip)     [ "$#" -ge 2 ] || die_usage "--server-ip 需要参数"; opt_ip="$2"; shift 2 ;;
      --server-ip=*)   opt_ip="${1#*=}"; shift ;;
      --acme-webroot)  [ "$#" -ge 2 ] || die_usage "--acme-webroot 需要参数"; opt_webroot="$2"; shift 2 ;;
      --acme-webroot=*) opt_webroot="${1#*=}"; shift ;;
      --no-reload)     no_reload=1; shift ;;
      -h|--help)       usage_access; return 0 ;;
      *) die_usage "access set 未知参数：$1" ;;
    esac
  done

  # 输入校验（拒绝污染状态文件的可疑值）。
  if [ -n "$opt_panel" ] && ! valid_hostname "$opt_panel"; then
    die_usage "面板主机名不合法：$opt_panel（例：panel.example.com）"
  fi
  if [ -n "$opt_webmail" ] && ! valid_hostname "$opt_webmail"; then
    die_usage "Webmail 主机名不合法：$opt_webmail"
  fi
  if [ -n "$opt_email" ] && ! valid_email "$opt_email"; then
    die_usage "ACME 邮箱不合法：$opt_email"
  fi
  if [ -n "$opt_ip" ] && ! valid_ipv4 "$opt_ip"; then
    die_usage "服务器公网 IP 不合法：$opt_ip"
  fi

  # 显式给了就覆盖；否则沿用状态里的值并标记为「自动推导」。
  if [ -n "$opt_panel" ]; then
    PANEL_HOST="$opt_panel"; PANEL_HOST_AUTO="0"
  elif [ -z "${PANEL_HOST:-}" ] || [ "${PANEL_HOST_AUTO:-0}" = "1" ]; then
    PANEL_HOST="$(default_panel_host_for_mode "$mode")"; PANEL_HOST_AUTO="1"
  fi
  if [ -n "$opt_webmail" ]; then
    WEBMAIL_HOST="$opt_webmail"; WEBMAIL_HOST_AUTO="0"
  elif [ -z "${WEBMAIL_HOST:-}" ] || [ "${WEBMAIL_HOST_AUTO:-0}" = "1" ]; then
    WEBMAIL_HOST="$(default_webmail_host_for_mode "$mode")"; WEBMAIL_HOST_AUTO="1"
  fi
  [ -n "$opt_email" ] && ACME_EMAIL="$opt_email"
  [ -n "$opt_ip" ] && SERVER_IP="$opt_ip"
  [ -n "$opt_webroot" ] && ACME_WEBROOT="$opt_webroot"

  # 公网模式必须有真实主机名；ssh 模式允许没有域名（纯回环）。
  case "$mode" in
    ssh) : ;;
    *)
      [ -n "$PANEL_HOST" ] || die "模式 $mode 需要面板主机名：加 --panel-host <host>，或先 domain set 配置域名"
      [ -n "$WEBMAIL_HOST" ] || die "模式 $mode 需要 Webmail 主机名：加 --webmail-host <host>"
      ;;
  esac

  # panel-domain 的硬约束：面板主机名必须与邮件主机名分开。
  if [ "$mode" = "panel-domain" ]; then
    local h
    for h in "$DOMAIN" "$MAIL_HOST" "mail.$DOMAIN" "imap.$DOMAIN" "smtp.$DOMAIN" "pop.$DOMAIN"; do
      [ -n "$h" ] || continue
      if [ "$PANEL_HOST" = "$h" ]; then
        die "panel-domain 要求独立面板主机名：$PANEL_HOST 与邮件主机 $h 冲突。请改用 --panel-host panel.<domain>，或选择 caddy 模式复用邮件主机名"
      fi
    done
    [ "$PANEL_HOST" != "$WEBMAIL_HOST" ] || die "面板主机与 Webmail 主机不能相同：$PANEL_HOST"
  fi

  # 计算 URL 并落状态（先落状态再生成文件：失败时运维至少能看到尝试的模式）。
  ACCESS_MODE_DETAIL="$mode"
  PANEL_URL="$(panel_url_for "$mode" "$PANEL_HOST")"
  WEBMAIL_URL="$(webmail_url_for "$mode" "$WEBMAIL_HOST")"
  ACCESS_MODE="$(canonical_access_mode "$mode")"
  write_state
  write_access_state_files

  say "应用访问模式：$mode（ACCESS_MODE=$ACCESS_MODE）"
  info "管理台入口：${PANEL_URL:-<未配置>}（内部 127.0.0.1:${ADMIN_PORT}）"
  info "Webmail入口：${WEBMAIL_URL:-<未配置>}（内部 127.0.0.1:${WEBMAIL_PORT}）"
  write_access_mode_files "$mode" "$PANEL_HOST" "$WEBMAIL_HOST"

  if [ "$mode" = "ip-acme" ] || [ "$mode" = "panel-domain" ]; then
    echo
    info "证书与 DNS 下一步："
    info "  sudo mailstack-manage tls issue ${PANEL_HOST} --email ${ACME_EMAIL:-<邮箱>}"
    info "  sudo mailstack-manage tls issue ${WEBMAIL_HOST} --email ${ACME_EMAIL:-<邮箱>}"
    info "  DNS 要求见：$ACCESS_DIR/$mode/DNS-REQUIREMENTS.txt"
  fi
  if [ "$mode" = "cloudflared" ]; then
    echo
    info "Cloudflare Tunnel 下一步见：$ACCESS_DIR/cloudflared/config.yml 与 README.txt"
  fi
  if [ "$mode" = "nginx" ]; then
    echo
    info "nginx TLS 下一步见：$ACCESS_DIR/nginx/README.txt"
  fi

  assert_loopback_bindings

  if [ "$no_reload" -eq 1 ]; then
    info "--no-reload：未触发服务 reload"
  elif [ "$CHANGED" -eq 0 ]; then
    info "配置无变化：未触发服务 reload（幂等）"
  else
    info "配置已更新：相关服务 reload 见上"
  fi
}

# ─────────────────────────── domain 子命令 ───────────────────────────

print_dns_hints() {
  local domain="$1" mail_host="$2" server_ip="$3" selector="$4"
  [ -n "$domain" ] || return 0
  mail_host="${mail_host:-mail.$domain}"
  echo
  echo '    DNS 记录（把 <公网 IP> 换成实际值；这里给出的是本栈要求的最小集合）:'
  if [ -n "$server_ip" ]; then
    printf '      %-6s %-46s %s\n' 'A' "$mail_host" "→ $server_ip"
    printf '      %-6s %-46s %s\n' 'A' "$domain" "→ $server_ip（可选：域根网页/A 记录）"
  else
    printf '      %-6s %-46s %s\n' 'A' "$mail_host" '→ <公网 IP>'
  fi
  printf '      %-6s %-46s %s\n' 'MX' "$domain" "→ $mail_host（优先级 10）"
  printf '      %-6s %-46s %s\n' 'TXT' "$domain" '"v=spf1 mx -all"'
  printf '      %-6s %-46s %s\n' 'TXT' "$selector._domainkey.$domain" '"v=DKIM1; k=rsa; p=<setup.identity.apply 响应中的 dkimPublicKey>"'
  printf '      %-6s %-46s %s\n' 'TXT' "_dmarc.$domain" "\"v=DMARC1; p=quarantine; rua=mailto:postmaster@$domain\""
  echo '    用管理台「初始化向导 → DNS 校验」或 mailstackctl setup.dns.verify 复核。'
}

cmd_domain_set() {
  require_root
  load_state

  local domain="" mail_host="" server_ip="" selector="" complete=0 restart=1 skip_table=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --mail-host)     [ "$#" -ge 2 ] || die_usage "--mail-host 需要参数"; mail_host="$2"; shift 2 ;;
      --mail-host=*)   mail_host="${1#*=}"; shift ;;
      --server-ip)     [ "$#" -ge 2 ] || die_usage "--server-ip 需要参数"; server_ip="$2"; shift 2 ;;
      --server-ip=*)   server_ip="${1#*=}"; shift ;;
      --dkim-selector) [ "$#" -ge 2 ] || die_usage "--dkim-selector 需要参数"; selector="$2"; shift 2 ;;
      --dkim-selector=*) selector="${1#*=}"; shift ;;
      --complete)      complete=1; shift ;;
      --no-restart)    restart=0; shift ;;
      --skip-domain-table) skip_table=1; shift ;;
      -h|--help)       usage_domain; return 0 ;;
      -*)              die_usage "domain set 未知参数：$1" ;;
      *)               [ -z "$domain" ] || die_usage "domain set 只接受一个域名"; domain="$1"; shift ;;
    esac
  done
  [ -n "$domain" ] || die_usage "domain set 需要邮件域名（例：example.com）"
  valid_domain "$domain" || die_usage "域名不合法：$domain"

  if [ -z "$mail_host" ]; then
    # 新域名的默认邮件主机；若旧 MAIL_HOST 属于旧域名，别把旧主机名带过来。
    if [ -n "${MAIL_HOST:-}" ] && { [ "$MAIL_HOST" = "$domain" ] || printf '%s' "$MAIL_HOST" | grep -qE "\.${domain//./\\.}$"; }; then
      mail_host="$MAIL_HOST"
    else
      mail_host="mail.$domain"
    fi
  fi
  valid_hostname "$mail_host" || die_usage "邮件主机名不合法：$mail_host"

  # serverIp 是 setup.identity.apply 的必填字段（它会写进 setup.json 并用于 DNS 提示）。
  if [ -z "$server_ip" ]; then
    server_ip="$(setup_json_value serverIp || true)"
  fi
  if [ -z "$server_ip" ]; then
    server_ip="$(detect_local_ip)"
  fi
  if [ -z "$server_ip" ]; then
    die "无法自动确定服务器公网 IP：请加 --server-ip <ip>（该值写入 setup.json 并用于 DNS 提示）"
  fi
  valid_ipv4 "$server_ip" || die_usage "服务器 IP 不合法：$server_ip"

  if [ -z "$selector" ]; then
    selector="$(setup_json_value dkimSelector || true)"
  fi
  [ -n "$selector" ] || selector="mail"
  printf '%s' "$selector" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$' \
    || die_usage "DKIM selector 不合法：$selector"

  say "更新邮件身份：$domain（mail-host $mail_host，server-ip $server_ip，dkim $selector）"
  info "经特权面执行 setup.identity.apply（校验 → 原生生成 DKIM → 写 setup.json）"
  local payload out
  payload="$(printf '{"domain":%s,"mailHost":%s,"serverIp":%s,"dkimSelector":%s}' \
    "$(json_quote "$domain")" "$(json_quote "$mail_host")" "$(json_quote "$server_ip")" "$(json_quote "$selector")")"
  out="$(priv_call setup.identity.apply "$payload")" \
    || die "setup.identity.apply 失败（域名/主机/selector 未通过 Rust 侧校验，或特权面不可用）"

  info "身份已写入：$ETC_DIR/setup.json"
  json_data_of "$out" | sed 's/^/    /'

  if [ "$skip_table" -eq 0 ]; then
    if priv_call domains.add "$(printf '{"name":%s}' "$(json_quote "$domain")")" >/dev/null 2>&1; then
      info "域名表已登记：$DOMAINS_TABLE"
    else
      warn "domains.add 失败（域名表可能已存在该域名或 postmap 不可用）；用 domain list 复核"
    fi
  fi

  # 状态：身份是权威，状态文件跟随；PANEL/WEBMAIL 主机若原先是自动推导，随域名刷新。
  local old_domain="$DOMAIN"
  DOMAIN="$domain"
  MAIL_HOST="$mail_host"
  SERVER_IP="$server_ip"
  if [ "${PANEL_HOST_AUTO:-0}" = "1" ]; then
    PANEL_HOST="$(default_panel_host_for_mode "$(current_access_detail)")"
  fi
  if [ "${WEBMAIL_HOST_AUTO:-0}" = "1" ]; then
    WEBMAIL_HOST="$(default_webmail_host_for_mode "$(current_access_detail)")"
  fi
  if [ -n "$PANEL_HOST" ]; then
    PANEL_URL="$(panel_url_for "$(current_access_detail)" "$PANEL_HOST")"
  fi
  if [ -n "$WEBMAIL_HOST" ]; then
    WEBMAIL_URL="$(webmail_url_for "$(current_access_detail)" "$WEBMAIL_HOST")"
  fi
  write_state

  if [ "$complete" -eq 1 ]; then
    if priv_call setup.wizard.complete '{}' >/dev/null 2>&1; then
      info "已置位向导完成标记（setup.wizard.complete）"
    else
      warn "setup.wizard.complete 失败（身份已写；可在管理台向导里收尾）"
    fi
  fi

  # 刷新访问层文件（主机名可能变）：ssh 模式无文件依赖主机名。
  local detail
  detail="$(current_access_detail)"
  if [ "$detail" != "ssh" ]; then
    info "访问层主机名可能变化：建议重跑 mailstack-manage access set $detail"
    # 若 access 产物已存在，直接按当前状态刷新，避免面板主机名与状态不一致。
    if [ -d "$ACCESS_DIR" ] && [ -f "$ACCESS_DIR/mode" ]; then
      if [ "$(cat "$ACCESS_DIR/mode" 2>/dev/null || true)" = "$detail" ]; then
        write_access_mode_files "$detail" "$PANEL_HOST" "$WEBMAIL_HOST"
      fi
    fi
  fi

  print_dns_hints "$domain" "$mail_host" "$server_ip" "$selector"

  if [ "$restart" -eq 1 ]; then
    echo
    say "重启服务以加载新身份"
    restart_units mailstackd
    if [ -f "$TLS_DIR/$mail_host/fullchain.pem" ]; then
      restart_units mailstack-imap
    else
      info "IMAP 证书尚未就绪（$TLS_DIR/$mail_host/fullchain.pem），mailstack-imap 保持原状"
    fi
  fi
  if [ -n "$old_domain" ] && [ "$old_domain" != "$domain" ]; then
    warn "域名已从 $old_domain 变更为 $domain：旧域名表项仍在，用 domain delete $old_domain --confirm 清理（确认不需要后再删）"
  fi
}

cmd_domain_list() {
  require_root
  load_state
  say "受管邮件域名"
  local out="" list=""
  if out="$(priv_call domains.list '{}' 2>/dev/null)"; then
    if have_python3; then
      # 后端当前返回 [{"name":"example.com","target":"OK"}]（旧版本可能是字符串数组），
      # 两种形状都接受，取域名本身展示。
      list="$(printf '%s' "$out" | python3 -c \
        'import json,sys
d=json.load(sys.stdin)
data=d.get("data")
doms = data.get("domains") if isinstance(data,dict) else data
names=[]
for item in doms or []:
    if isinstance(item,str):
        names.append(item)
    elif isinstance(item,dict):
        n=item.get("name") or item.get("domain") or item.get("id")
        if n: names.append(n)
print("\n".join(names))' 2>/dev/null || true)"
    else
      # 无 python3：兼容 "domains":["a"] 与 "domains":[{"name":"a",...}] 两种紧凑形状。
      list="$(printf '%s' "$out" \
        | sed -n 's/.*"domains":\[\([^]]*\)\].*/\1/p' \
        | tr ',' '\n' \
        | sed -n -e 's/^"\([^"]*\)"$/\1/p' -e 's/.*"name":"\([^"]*\)".*/\1/p' \
        | grep -v -E '^(target|OK)$' || true)"
    fi
  fi
  if [ -z "$list" ] && [ -f "$DOMAINS_TABLE" ]; then
    list="$(awk 'NF { print $1 }' "$DOMAINS_TABLE" 2>/dev/null || true)"
    [ -n "$list" ] && info "（domains.list 不可用，回退读取 $DOMAINS_TABLE）"
  fi
  if [ -z "$list" ]; then
    info "（暂无受管域名：运行 mailstack-manage domain set example.com）"
  else
    printf '%s\n' "$list" | sed 's/^/    - /'
  fi
  echo
  info "身份域: ${DOMAIN:-（未设置）}   邮件主机: ${MAIL_HOST:-（未设置）}"
}

cmd_domain_add() {
  require_root
  load_state
  local domain="${1:-}"
  [ -n "$domain" ] || die_usage "domain add 需要域名"
  valid_domain "$domain" || die_usage "域名不合法：$domain"
  say "添加邮件域名：$domain"
  priv_call domains.add "$(printf '{"name":%s}' "$(json_quote "$domain")")" >/dev/null \
    || die "domains.add 失败"
  info "已登记到域名表（$DOMAINS_TABLE）"
  info "提示：单加域名不会创建邮箱；用 account add 建号。"
}

cmd_domain_delete() {
  require_root
  load_state
  local domain="" confirm=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm|-y|--yes) confirm=1; shift ;;
      -h|--help) usage_domain; return 0 ;;
      -*) die_usage "domain delete 未知参数：$1" ;;
      *) [ -z "$domain" ] || die_usage "domain delete 只接受一个域名"; domain="$1"; shift ;;
    esac
  done
  [ -n "$domain" ] || die_usage "domain delete 需要域名"
  valid_domain "$domain" || die_usage "域名不合法：$domain"

  if [ "$confirm" -eq 0 ]; then
    if [ -t 0 ]; then
      local answer=""
      printf '确认删除域名 %s（会同时删除该域别名；邮箱账号不会自动删除）？[y/N] ' "$domain" >&2
      IFS= read -r answer || answer=""
      case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
        y|yes) : ;;
        *) die "已取消" ;;
      esac
    else
      die_usage "非交互模式删除域名需要 --confirm"
    fi
  fi

  say "删除邮件域名：$domain"
  # domains.delete 是破坏性动作：载荷必须携带布尔 confirm:true（ActionGate INV-2）。
  priv_call domains.delete "$(printf '{"id":%s,"confirm":true}' "$(json_quote "$domain")")" >/dev/null \
    || die "domains.delete 失败"
  info "已从域名表删除：$domain"
  if [ "$domain" = "$DOMAIN" ]; then
    warn "注意：$domain 仍是 setup.json 里的身份域；如要换域，请运行 mailstack-manage domain set <新域名>"
  fi
}

# ─────────────────────────── account 子命令 ───────────────────────────

read_password_line() {
  local value="${1:-}"
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return 0
  fi
  if [ -n "${MAILSTACK_ADMIN_PASSWORD:-}" ]; then
    printf '%s' "$MAILSTACK_ADMIN_PASSWORD"
    return 0
  fi
  if [ -t 0 ]; then
    local first="" second=""
    printf '邮箱口令（12-256 位，含字母与数字；输入不回显）: ' >&2
    IFS= read -r -s first || first=""
    printf '\n' >&2
    printf '再次输入以确认: ' >&2
    IFS= read -r -s second || second=""
    printf '\n' >&2
    [ "$first" = "$second" ] || die "两次输入的口令不一致"
    printf '%s' "$first"
    return 0
  fi
  die "未提供口令：用 --password-stdin（推荐，stdin 传一行）或 --password <口令>（会留在 shell 历史/进程列表）"
}

# 本地快速预检（权威校验仍在 Rust 侧，这里只避免明显无效口令打穿到特权面）。
precheck_password() {
  local password="$1" email="$2"
  local plen=${#password}
  if printf '%s' "$password" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    die "口令不得包含控制字符（换行/制表符等）"
  fi
  [ "$plen" -ge 12 ] && [ "$plen" -le 256 ] \
    || die "口令长度必须 12-256 字符（实际 $plen；后端 validate_mailbox_password 同一策略）"
  printf '%s' "$password" | grep -q '[A-Za-z]' || die "口令必须包含字母"
  printf '%s' "$password" | grep -q '[0-9]' || die "口令必须包含数字"
  local localpart="${email%%@*}"
  case "$(printf '%s' "$password" | tr '[:upper:]' '[:lower:]')" in
    *"$(printf '%s' "$localpart" | tr '[:upper:]' '[:lower:]')"*) die "口令不得包含邮箱用户名（$localpart）" ;;
  esac
}

parse_account_password_args() {
  # 解析 --password / --password-stdin，结果放 ACCOUNT_PASSWORD_SOURCE/
  # ACCOUNT_PASSWORD_VALUE；其他参数保留在 REMAINING_ARGS。
  ACCOUNT_PASSWORD_VALUE=""
  ACCOUNT_PASSWORD_STDIN=0
  REMAINING_ARGS=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --password)       [ "$#" -ge 2 ] || die_usage "--password 需要参数"; ACCOUNT_PASSWORD_VALUE="$2"; shift 2 ;;
      --password=*)     ACCOUNT_PASSWORD_VALUE="${1#*=}"; shift ;;
      --password-stdin) ACCOUNT_PASSWORD_STDIN=1; shift ;;
      *)                REMAINING_ARGS+=("$1"); shift ;;
    esac
  done
}

cmd_account_add() {
  require_root
  load_state
  parse_account_password_args "$@"
  local email="" name=""
  local -a rest=("${REMAINING_ARGS[@]}")
  while [ "${#rest[@]}" -gt 0 ]; do
    case "${rest[0]}" in
      --name|--display-name)
        [ "${#rest[@]}" -ge 2 ] || die_usage "--name 需要参数"
        name="${rest[1]}"; rest=("${rest[@]:2}") ;;
      --name=*) name="${rest[0]#*=}"; rest=("${rest[@]:1}") ;;
      -h|--help) usage_account; return 0 ;;
      -*) die_usage "account add 未知参数：${rest[0]}" ;;
      *) [ -z "$email" ] || die_usage "account add 只接受一个邮箱地址"; email="${rest[0]}"; rest=("${rest[@]:1}") ;;
    esac
  done
  [ -n "$email" ] || die_usage "account add 需要邮箱地址（例：alice@example.com）"
  valid_email "$email" || die_usage "邮箱地址不合法：$email"

  local password
  if [ "$ACCOUNT_PASSWORD_STDIN" -eq 1 ] && [ -n "$ACCOUNT_PASSWORD_VALUE" ]; then
    die_usage "--password 与 --password-stdin 只能选一个"
  fi
  if [ -n "$ACCOUNT_PASSWORD_VALUE" ]; then
    warn "--password 会经 argv/进程列表暴露，建议改用 --password-stdin 或 MAILSTACK_ADMIN_PASSWORD"
    password="$ACCOUNT_PASSWORD_VALUE"
  elif [ "$ACCOUNT_PASSWORD_STDIN" -eq 1 ]; then
    IFS= read -r password || password=""
    password="${password%$'\r'}"
    [ -n "$password" ] || die "stdin 未读到口令（--password-stdin 需要一行口令）"
  else
    password="$(read_password_line "")"
  fi
  precheck_password "$password" "$email"

  local payload
  payload="$(printf '{"email":%s,"password":%s' "$(json_quote "$email")" "$(json_quote "$password")")"
  if [ -n "$name" ]; then
    payload="$payload$(printf ',"name":%s' "$(json_quote "$name")")"
  fi
  payload="$payload}"
  password=""

  say "创建邮箱账号：$email"
  info "经特权面执行 users.add（建系统账号 + 系统口令 + mailbox-passwords 记录 + Maildir）"
  priv_call users.add "$payload" >/dev/null || die "users.add 失败（域名是否已 domain add？口令是否被后端策略拒绝？）"
  info "已创建：$email（unix 账号：${email%%@*}）"
  info "客户端可用完整地址或本地部分登录 IMAP/POP3/提交端口（同一份 mailbox-passwords 记录）。"
}

cmd_account_list() {
  require_root
  load_state
  say "受管邮箱账号"
  local out=""
  if ! out="$(priv_call users.list '{}')"; then
    warn "users.list 不可用（daemon/特权面未就绪？）"
    return 1
  fi
  if have_python3; then
    printf '%s' "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin).get("data")
rows = data if isinstance(data, list) else []
if not rows:
    print("    （暂无受管邮箱：mailstack-manage account add <email> --password-stdin）")
else:
    print("    %-38s %-22s %s" % ("邮箱地址", "显示名", "状态"))
    for row in rows:
        active = "enabled" if row.get("active") else "disabled"
        print("    %-38s %-22s %s" % (row.get("address", ""), row.get("name", ""), active))
' || { warn "解析 users.list 响应失败；原始响应："; json_print "$out"; }
  else
    info "（无 python3，展示原始 JSON）"
    json_data_of "$out"
  fi
}

cmd_account_passwd() {
  require_root
  load_state
  parse_account_password_args "$@"
  local email=""
  local -a rest=("${REMAINING_ARGS[@]}")
  while [ "${#rest[@]}" -gt 0 ]; do
    case "${rest[0]}" in
      -h|--help) usage_account; return 0 ;;
      -*) die_usage "account passwd 未知参数：${rest[0]}" ;;
      *) [ -z "$email" ] || die_usage "account passwd 只接受一个邮箱地址"; email="${rest[0]}"; rest=("${rest[@]:1}") ;;
    esac
  done
  [ -n "$email" ] || die_usage "account passwd 需要邮箱地址"
  valid_email "$email" || die_usage "邮箱地址不合法：$email"

  local password
  if [ "$ACCOUNT_PASSWORD_STDIN" -eq 1 ] && [ -n "$ACCOUNT_PASSWORD_VALUE" ]; then
    die_usage "--password 与 --password-stdin 只能选一个"
  fi
  if [ -n "$ACCOUNT_PASSWORD_VALUE" ]; then
    warn "--password 会经 argv/进程列表暴露，建议改用 --password-stdin"
    password="$ACCOUNT_PASSWORD_VALUE"
  elif [ "$ACCOUNT_PASSWORD_STDIN" -eq 1 ]; then
    IFS= read -r password || password=""
    password="${password%$'\r'}"
    [ -n "$password" ] || die "stdin 未读到口令"
  else
    password="$(read_password_line "")"
  fi
  precheck_password "$password" "$email"

  say "重设邮箱口令：$email"
  # users.password 同时写 mailbox-passwords 记录与系统口令，并 bump webmail 会话纪元。
  priv_call users.password "$(printf '{"email":%s,"password":%s}' "$(json_quote "$email")" "$(json_quote "$password")")" >/dev/null \
    || die "users.password 失败"
  password=""
  info "口令已更新（IMAP/POP3/提交端口/Webmail 同时生效；已登录的 Webmail 会话会失效）"
}

cmd_account_delete() {
  require_root
  load_state
  local email="" confirm=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm|-y|--yes) confirm=1; shift ;;
      -h|--help) usage_account; return 0 ;;
      -*) die_usage "account delete 未知参数：$1" ;;
      *) [ -z "$email" ] || die_usage "account delete 只接受一个邮箱地址"; email="$1"; shift ;;
    esac
  done
  [ -n "$email" ] || die_usage "account delete 需要邮箱地址"
  valid_email "$email" || die_usage "邮箱地址不合法：$email"

  if [ "$confirm" -eq 0 ]; then
    if [ -t 0 ]; then
      local answer=""
      printf '确认删除邮箱 %s（系统账号与 Maildir 一并删除，不可恢复）？[y/N] ' "$email" >&2
      IFS= read -r answer || answer=""
      case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
        y|yes) : ;;
        *) die "已取消" ;;
      esac
    else
      die_usage "非交互模式删除邮箱需要 --confirm"
    fi
  fi

  say "删除邮箱账号：$email"
  # users.delete 是破坏性动作：载荷必须携带布尔 confirm:true（ActionGate INV-2）。
  priv_call users.delete "$(printf '{"email":%s,"confirm":true}' "$(json_quote "$email")")" >/dev/null \
    || die "users.delete 失败（账号受保护或不在受管注册表？）"
  info "已删除：$email（系统账号 + 两份注册表 + 口令记录）"
}

# ─────────────────────────── tls 子命令 ───────────────────────────

print_tls_dns_hints() {
  local host="$1"
  echo
  echo '    DNS/网络前置条件（ACME HTTP-01）:'
  printf '      %-6s %-46s %s\n' 'A' "$host" "→ ${SERVER_IP:-<本机公网 IP>}"
  printf '      %-6s %-46s %s\n' 'P80' "$host" '80/tcp 对公网可达（Let'"'"'s Encrypt 回连）'
  printf '      %-6s %-46s %s\n' '注意' '' '不要用 CNAME 指到别的名字（会按 CNAME 目标校验主机名）'
  echo '    证书落点：'"$TLS_DIR/$host"'/{fullchain,privkey}.pem（acme.sh 签发后由本栈安装）'
}

cmd_tls_issue() {
  require_root
  load_state
  local host="" email="" method="standalone" webroot=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --email)        [ "$#" -ge 2 ] || die_usage "--email 需要参数"; email="$2"; shift 2 ;;
      --email=*)      email="${1#*=}"; shift ;;
      --method)       [ "$#" -ge 2 ] || die_usage "--method 需要参数"; method="$2"; shift 2 ;;
      --method=*)     method="${1#*=}"; shift ;;
      --webroot)      [ "$#" -ge 2 ] || die_usage "--webroot 需要参数"; webroot="$2"; shift 2 ;;
      --webroot=*)    webroot="${1#*=}"; shift ;;
      --server-ip)    [ "$#" -ge 2 ] || die_usage "--server-ip 需要参数"; SERVER_IP="$2"; shift 2 ;;
      --server-ip=*)  SERVER_IP="${1#*=}"; shift ;;
      -h|--help)      usage_tls; return 0 ;;
      -*)             die_usage "tls issue 未知参数：$1" ;;
      *)              [ -z "$host" ] || die_usage "tls issue 只接受一个主机名"; host="$1"; shift ;;
    esac
  done
  [ -n "$host" ] || die_usage "tls issue 需要主机名（例：mail.example.com）"
  valid_hostname "$host" || die_usage "主机名不合法：$host"
  [ -n "$email" ] || email="${ACME_EMAIL:-}"
  [ -n "$email" ] || die "缺少 ACME 账户邮箱：加 --email ops@example.com，或先 access set <mode> --acme-email ops@example.com"
  valid_email "$email" || die_usage "ACME 邮箱不合法：$email"
  [ -n "${SERVER_IP:-}" ] || SERVER_IP="$(detect_local_ip || true)"

  case "$method" in
    standalone) : ;;
    webroot)
      [ -n "$webroot" ] || die_usage "--method webroot 需要 --webroot <目录>"
      [ -d "$webroot" ] || die_usage "--webroot 目录不存在：$webroot"
      ;;
    *) die_usage "--method 只支持 standalone|webroot（实际：$method）" ;;
  esac

  # 记住邮箱，后续 renew 不必重复传。
  ACME_EMAIL="$email"
  write_state

  say "签发 TLS 证书：$host（method=$method）"
  info "经特权面执行 setup.cert.issue（调用本机 /root/.acme.sh/acme.sh）"
  local payload
  payload="$(printf '{"domain":%s,"email":%s,"method":%s}' \
    "$(json_quote "$host")" "$(json_quote "$email")" "$(json_quote "$method")")"
  if [ "$method" = "webroot" ]; then
    payload="${payload%\}},\"webroot\":$(json_quote "$webroot")}"
  fi
  local out
  out="$(priv_call setup.cert.issue "$payload")" || {
    print_tls_dns_hints "$host"
    die "setup.cert.issue 失败（多半是 DNS 未就绪 / 80 端口不可达 / acme.sh 未安装；看上面的错误与 DNS 要求）"
  }
  json_data_of "$out" | sed 's/^/    /'
  info "证书已安装到：$TLS_DIR/$host/"
  print_tls_dns_hints "$host"
  echo
  info "下一步："
  info "  1) 若访问模式为 nginx/ip-acme/panel-domain，重跑 access set 让反代加载新证书："
  info "       sudo mailstack-manage access set $(current_access_detail)"
  info "  2) 若 mailstack-imap 使用该主机名，重启它：sudo systemctl restart mailstack-imap"
}

cmd_tls_renew() {
  require_root
  load_state
  local host="" all=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --all) all=1; shift ;;
      -h|--help) usage_tls; return 0 ;;
      -*) die_usage "tls renew 未知参数：$1" ;;
      *) [ -z "$host" ] || die_usage "tls renew 只接受一个主机名（--all 续期全部）"; host="$1"; shift ;;
    esac
  done

  local hosts=()
  if [ -n "$host" ]; then
    valid_hostname "$host" || die_usage "主机名不合法：$host"
    hosts=("$host")
  else
    if [ -d "$TLS_DIR" ]; then
      local d
      for d in "$TLS_DIR"/*/; do
        [ -d "$d" ] || continue
        [ -f "$d/fullchain.pem" ] || continue
        hosts+=("$(basename -- "$d")")
      done
    fi
  fi
  if [ "${#hosts[@]}" -eq 0 ]; then
    info "没有已签发的证书可续期（先 mailstack-manage tls issue <host>）"
    return 0
  fi

  say "续期证书（certs.renew → /root/.acme.sh/acme.sh --renew）"
  local h failed=0
  for h in "${hosts[@]}"; do
    info "续期：$h"
    if priv_call certs.renew "$(printf '{"domain":%s}' "$(json_quote "$h")")" >/dev/null; then
      info "  完成：$h"
    else
      warn "  续期失败：$h（acme.sh 未安装 / DNS 变化 / 速率限制；看上面的错误）"
      failed=$((failed + 1))
    fi
  done
  if [ "$failed" -gt 0 ]; then
    warn "$failed 个域名续期失败"
    return 1
  fi
  info "全部续期完成；反代（nginx/caddy）通常无需动作，邮件服务按需重启。"
}

# ─────────────────────────── restart / logs / status ───────────────────────────

cmd_restart() {
  require_root
  load_state
  local units=("$@")
  if [ "${#units[@]}" -eq 0 ]; then
    units=("${UNITS_ALL[@]}")
  fi
  say "重启 MailStack 服务"
  restart_units "${units[@]}"
}

cmd_logs() {
  require_root
  load_state
  local unit="mailstackd" lines=100 follow=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --lines|-n) [ "$#" -ge 2 ] || die_usage "--lines 需要参数"; lines="$2"; shift 2 ;;
      --lines=*)  lines="${1#*=}"; shift ;;
      -f|--follow) follow=1; shift ;;
      -h|--help) usage_logs; return 0 ;;
      -*) die_usage "logs 未知参数：$1" ;;
      *) unit="$1"; shift ;;
    esac
  done
  case "$unit" in
    mailstackd|mailstack-web|mailstack-imap|mailstack-webmail) : ;;
    *) die_usage "logs 只支持 ${UNITS_ALL[*]}（实际：$unit）" ;;
  esac
  if systemd_live; then
    local args=(-u "$unit" -n "$lines" --no-pager)
    [ "$follow" -eq 1 ] && args+=(-f)
    exec journalctl "${args[@]}"
  fi
  info "未检测到运行中的 systemd：journald 不可用。"
  info "前台排查：sudo $BIN_DIR/$unit --help（或按安装摘要里的前台命令启动）"
  if [ -d "$VAR_LIB_DIR" ]; then
    info "数据目录：$VAR_LIB_DIR"
  fi
}

print_services_status() {
  if ! systemd_live; then
    info "systemd: 不可用（staging 前缀 / 容器）—— 不查询宿主服务状态"
    return 0
  fi
  local unit state
  for unit in "${UNITS_ALL[@]}"; do
    if [ ! -f "$(unit_file_of "$unit")" ]; then
      printf '    %-22s %s\n' "$unit" 'unit 未安装'
      continue
    fi
    if state="$(systemctl is-active "$unit" 2>/dev/null)"; then :; else state="inactive"; fi
    printf '    %-22s %s\n' "$unit" "$state"
  done
}

print_certs_status() {
  local found=0 d host end
  if [ -d "$TLS_DIR" ]; then
    for d in "$TLS_DIR"/*/; do
      [ -d "$d" ] || continue
      [ -f "$d/fullchain.pem" ] || continue
      host="$(basename -- "$d")"
      end=""
      if command -v openssl >/dev/null 2>&1; then
        end="$(openssl x509 -in "$d/fullchain.pem" -noout -enddate 2>/dev/null | sed -n 's/^notAfter=//p' || true)"
      fi
      printf '    %-34s %s\n' "$host" "${end:+到期 $end}${end:-（无法解析证书）}"
      found=$((found + 1))
    done
  fi
  if [ "$found" -eq 0 ]; then
    info "（尚无 TLS 证书：sudo mailstack-manage tls issue <host> --email <邮箱>）"
  fi
}

print_domains_status() {
  local list=""
  if [ -f "$DOMAINS_TABLE" ]; then
    list="$(awk 'NF { print $1 }' "$DOMAINS_TABLE" 2>/dev/null || true)"
  fi
  if [ -n "$list" ]; then
    printf '%s\n' "$list" | sed 's/^/    - /'
  else
    info "（域名表为空：sudo mailstack-manage domain set example.com）"
  fi
}

cmd_status() {
  require_root
  load_state
  local detail canonical
  detail="$(current_access_detail)"
  canonical="$(canonical_access_mode "$detail" 2>/dev/null || printf '%s' "${ACCESS_MODE:-local}")"

  say "MailStack 状态（v${MAILSTACK_VERSION}）"
  info "安装前缀:     ${PREFIX_NORM:-/}"
  info "部署状态:     $STATE_FILE"
  if [ "$STATE_LOADED" -eq 0 ]; then
    warn "未找到部署状态文件：尚未 install.sh，或前缀不对（可用 MAILSTACK_PREFIX/--prefix 指定）"
  fi
  info "邮件域名:     ${DOMAIN:-（未设置）}"
  info "邮件主机:     ${MAIL_HOST:-（未设置）}"
  info "服务器 IP:    ${SERVER_IP:-（未设置；domain set --server-ip 或自动探测）}"
  info "部署模式:     $detail（ACCESS_MODE=$canonical）"
  info "管理员:       $ADMIN_USER（凭证：$([ -s "$ETC_DIR/admin.json" ] && echo 已配置 || echo 未配置)）"
  info "管理台:       ${PANEL_URL:-（未配置公网入口）}  内部 127.0.0.1:${ADMIN_PORT}"
  info "Webmail:      ${WEBMAIL_URL:-（未配置公网入口）}  内部 127.0.0.1:${WEBMAIL_PORT}"
  if [ -s "$ETC_DIR/setup.json" ]; then
    local wizard="未完成"
    if grep -Eq '"wizardCompleted"[[:space:]]*:[[:space:]]*true' "$ETC_DIR/setup.json" 2>/dev/null; then
      wizard="已完成"
    fi
    info "身份状态:     setup.json 已配置（向导：$wizard）"
  else
    info "身份状态:     未配置（sudo mailstack-manage domain set <domain>，或管理台向导）"
  fi

  echo
  echo '    邮件域名（域名表）:'
  print_domains_status

  echo
  echo '    服务:'
  print_services_status

  echo
  echo '    TLS 证书:'
  print_certs_status

  echo
  echo '    访问层:'
  case "$detail" in
    ssh) info "SSH 隧道模式（无反向代理）；隧道说明：$ACCESS_DIR/ssh/README.txt" ;;
    caddy) info "Caddy 反代（自动 HTTPS）；Caddyfile：$ACCESS_DIR/caddy/Caddyfile" ;;
    nginx) info "nginx 反代（80 → certbot）；配置：$ACCESS_DIR/nginx/mailstack-panel.conf" ;;
    ip-acme) info "nginx TLS 反代（ACME 证书来自 $TLS_DIR）；配置：$ACCESS_DIR/nginx/mailstack-panel.conf" ;;
    panel-domain) info "独立 panel 域名反代；配置：$ACCESS_DIR/{caddy/Caddyfile|nginx/mailstack-panel.conf}" ;;
    cloudflared) info "Cloudflare Tunnel；配置：$ACCESS_DIR/cloudflared/config.yml，unit：$UNIT_DIR/mailstack-cloudflared.service" ;;
    *) info "未知模式：$detail（运行 mailstack-manage access show 查看）" ;;
  esac

  echo
  echo '    数据/配置目录:'
  local p
  for p in "$ETC_DIR" "$VAR_LIB_DIR" "$(prefix_path /var/backups/mailstack)"; do
    if [ -d "$p" ]; then
      stat -c '      %a %U:%G %n' "$p" 2>/dev/null || printf '      %s\n' "$p"
    else
      printf '      (missing) %s\n' "$p"
    fi
  done
  assert_loopback_bindings
}

# ─────────────────────────── 交互菜单 ───────────────────────────

menu_try() {
  local rc=0
  "$@" || rc=$?
  if [ "$rc" -ne 0 ]; then
    warn "命令失败（退出码 $rc），已返回菜单"
  fi
  return 0
}

prompt_read() {
  local prompt="$1" default="${2:-}" value=""
  printf '%s' "$prompt" >&2
  IFS= read -r value || value=""
  [ -n "$value" ] || value="$default"
  printf '%s' "$value"
}

menu_loop() {
  if [ ! -t 0 ]; then
    usage
    exit 2
  fi
  require_root
  load_state
  while true; do
    cat <<'EOF'

+--------------------------------------------------------------+
|            MailStack 服务器管理（mailstack-manage）          |
+--------------------------------------------------------------+
|  1) 状态总览                     2) 访问模式详情             |
|  3) 设置访问模式                 4) 设置邮件域名/身份        |
|  5) 域名列表                     6) 添加域名                 |
|  7) 删除域名                     8) 添加邮箱账号             |
|  9) 邮箱列表                    10) 重设邮箱口令             |
| 11) 删除邮箱账号                12) 签发 TLS 证书            |
| 13) 续期 TLS 证书               14) 重启服务                 |
| 15) 查看日志                     0) 退出                     |
+--------------------------------------------------------------+
EOF
    printf '请选择: '
    local choice=""
    IFS= read -r choice || break
    case "$choice" in
      1) menu_try cmd_status ;;
      2) menu_try cmd_access_show ;;
      3)
        echo "可选访问模式: ${ACCESS_MODES_ALL[*]}（旧值 local/caddy/direct 仍接受）" >&2
        local mode
        mode="$(prompt_read '访问模式: ')"
        [ -n "$mode" ] || { warn "未输入，已返回菜单"; continue; }
        local panel=""
        if [ "$mode" != "ssh" ]; then
          panel="$(prompt_read '面板主机名（留空自动推导 panel.<domain>）: ')"
        fi
        if [ -n "$panel" ]; then
          menu_try cmd_access_set "$mode" --panel-host "$panel"
        else
          menu_try cmd_access_set "$mode"
        fi ;;
      4)
        local domain mail_host server_ip
        domain="$(prompt_read '邮件域名（例 example.com）: ')"
        [ -n "$domain" ] || { warn "未输入，已返回菜单"; continue; }
        mail_host="$(prompt_read '邮件主机名（留空自动推导 mail.<domain>）: ')"
        server_ip="$(prompt_read '服务器公网 IP（留空自动探测）: ')"
        local -a args=("$domain")
        [ -n "$mail_host" ] && args+=(--mail-host "$mail_host")
        [ -n "$server_ip" ] && args+=(--server-ip "$server_ip")
        menu_try cmd_domain_set "${args[@]}" --complete ;;
      5) menu_try cmd_domain_list ;;
      6)
        local d; d="$(prompt_read '要添加的域名: ')"
        [ -n "$d" ] && menu_try cmd_domain_add "$d" || warn "未输入，已返回菜单" ;;
      7)
        local d2; d2="$(prompt_read '要删除的域名: ')"
        [ -n "$d2" ] && menu_try cmd_domain_delete "$d2" || warn "未输入，已返回菜单" ;;
      8)
        local mail pw
        mail="$(prompt_read '邮箱地址（例 alice@example.com）: ')"
        [ -n "$mail" ] || { warn "未输入，已返回菜单"; continue; }
        pw="$(prompt_read '口令（12-256 位，含字母与数字；留空则使用 MAILSTACK_ADMIN_PASSWORD）: ')"
        if [ -n "$pw" ]; then
          menu_try cmd_account_add "$mail" --password "$pw"
        else
          menu_try cmd_account_add "$mail"
        fi ;;
      9) menu_try cmd_account_list ;;
      10)
        local mail2; mail2="$(prompt_read '要重设口令的邮箱: ')"
        [ -n "$mail2" ] && menu_try cmd_account_passwd "$mail2" || warn "未输入，已返回菜单" ;;
      11)
        local mail3; mail3="$(prompt_read '要删除的邮箱: ')"
        [ -n "$mail3" ] && menu_try cmd_account_delete "$mail3" || warn "未输入，已返回菜单" ;;
      12)
        local host; host="$(prompt_read '证书主机名（例 mail.example.com）: ')"
        [ -n "$host" ] && menu_try cmd_tls_issue "$host" || warn "未输入，已返回菜单" ;;
      13) menu_try cmd_tls_renew ;;
      14) menu_try cmd_restart ;;
      15)
        local unit; unit="$(prompt_read '服务名（mailstackd/mailstack-web/mailstack-imap/mailstack-webmail，默认 mailstackd）: ' 'mailstackd')"
        menu_try cmd_logs "$unit" ;;
      0|q|quit|exit) break ;;
      *) warn "无效选择：$choice" ;;
    esac
  done
  printf '\n再见。\n'
}

# ─────────────────────────── 帮助 ───────────────────────────

usage_common_tail() {
  cat <<'EOF'

通用选项（放在任意位置均可）:
  --prefix DIR           指定安装前缀（默认 /，staging 测试用；等价 MAILSTACK_PREFIX）
  -h, --help             显示帮助
  --version              显示版本

访问模式（access set <mode>）:
  ssh            默认。管理台/Webmail 只绑回环，经 SSH 隧道访问；不安装反向代理、不对外开端口。
  caddy          用 Caddy 反代 panel/webmail 主机名，自动 ACME HTTPS（需 caddy 已安装）。
  nginx          用 nginx 反代（80），TLS 由 certbot --nginx / acme.sh 补；给出完整命令。
  ip-acme        公网 IP 路径：nginx 终止 TLS，证书由 mailstackctl setup.cert.issue 签发到
                 /etc/mailstack/tls/<host>/；需 A 记录指向本机且 80 端口可达。
  panel-domain   独立面板主机名（默认 panel.<domain>，禁止与 mail./imap./smtp. 冲突）反代 TLS；
                 有 caddy 用 Caddy（自动 HTTPS），否则用 nginx + ACME 证书。
  cloudflared    Cloudflare Tunnel：生成 config.yml + systemd unit，隧道指向 127.0.0.1:8443/8444，
                 公网 TLS 由 Cloudflare 边缘终止；本机不开放端口。
  旧值 local / caddy / direct 仍被接受（local→ssh，direct→ip-acme）。

安全约束:
  * mailstack-web / mailstack-webmail 永远只绑 127.0.0.1:8443/8444；反向代理/Tunnel 是本脚本
    唯一支持的对外入口（脚本会检查 unit 并告警）。
  * 所有变更动作经 mailstackctl 特权面执行，本脚本不复制 Rust 侧校验逻辑。
EOF
}

usage() {
  cat <<'EOF'
MailStack 服务器管理脚本（mailstack-manage）

用法:
  sudo mailstack-manage [--prefix DIR] <命令> [参数...]
  sudo mailstack-manage                # 无参数 → 交互菜单（需要 TTY）

命令:
  status                       显示域名 / 管理员 / 访问模式 / 服务 / TLS 证书 / 面板地址
  access show                  当前访问模式与生成的反代/Tunnel 文件
  access set <mode> [选项]     切换访问模式（幂等；写入 install-args.conf 与 access/）
      选项: --panel-host H --webmail-host H --acme-email E --server-ip IP
            --acme-webroot DIR --no-reload
  domain set <domain> [选项]   更新邮件身份（setup.identity.apply + DKIM + 域名表 + 重启）
      选项: --mail-host H --server-ip IP --dkim-selector S --complete --no-restart
            --skip-domain-table
  domain list                  列出受管邮件域名（mailstackctl domains.list）
  domain add <domain>          添加邮件域名（domains.add）
  domain delete <domain>       删除邮件域名（domains.delete；非交互需 --confirm）
  account add <email> [选项]   创建邮箱（users.add）
      选项: --password-stdin | --password <pw> | --name <显示名>
  account list                 列出受管邮箱（users.list）
  account passwd <email>       重设邮箱口令（users.password；同时更新 IMAP/POP3/Webmail）
      选项: --password-stdin | --password <pw>
  account delete <email>       删除邮箱（users.delete；非交互需 --confirm）
  tls issue <host> [选项]      签发 TLS 证书（setup.cert.issue；打印精确 DNS 提示）
      选项: --email E --method standalone|webroot --webroot DIR
  tls renew [<host>|--all]     续期证书（certs.renew；缺省续期 tls 目录下全部）
  restart [unit ...]           重启服务（缺省 4 个 unit）
  logs [unit] [--lines N] [-f] 查看服务日志（journalctl；仅生产 systemd 环境）
  menu                         交互菜单（等同无参数执行）
EOF
  usage_common_tail
}

usage_access() { usage; }
usage_domain() { usage; }
usage_account() { usage; }
usage_tls() { usage; }
usage_logs() { usage; }

# ─────────────────────────── 入口 ───────────────────────────

dispatch() {
  if [ "$#" -eq 0 ]; then
    menu_loop
    return 0
  fi
  local command="$1"
  shift || true
  case "$command" in
    -h|--help|help) usage; return 0 ;;
    --version|version) printf 'mailstack-manage %s (MailStack %s)\n' "$SCRIPT_VERSION" "$MAILSTACK_VERSION_FALLBACK"; return 0 ;;
  esac
  require_root
  derive_paths
  case "$command" in
    status)  cmd_status ;;
    menu)    menu_loop ;;
    access)
      local sub="${1:-show}"; [ "$#" -gt 0 ] && shift || true
      case "$sub" in
        show|list) cmd_access_show ;;
        set)       cmd_access_set "$@" ;;
        -h|--help) usage_access ;;
        *) die_usage "access 未知子命令：$sub（show|set）" ;;
      esac ;;
    domain)
      local sub="${1:-list}"; [ "$#" -gt 0 ] && shift || true
      case "$sub" in
        set)    cmd_domain_set "$@" ;;
        list)   cmd_domain_list ;;
        add)    cmd_domain_add "$@" ;;
        delete|del|rm) cmd_domain_delete "$@" ;;
        -h|--help) usage_domain ;;
        *) die_usage "domain 未知子命令：$sub（set|list|add|delete）" ;;
      esac ;;
    account)
      local sub="${1:-list}"; [ "$#" -gt 0 ] && shift || true
      case "$sub" in
        add)    cmd_account_add "$@" ;;
        list)   cmd_account_list ;;
        passwd|password|pass) cmd_account_passwd "$@" ;;
        delete|del|rm) cmd_account_delete "$@" ;;
        -h|--help) usage_account ;;
        *) die_usage "account 未知子命令：$sub（add|list|passwd|delete）" ;;
      esac ;;
    tls)
      local sub="${1:-}"; [ "$#" -gt 0 ] && shift || true
      case "$sub" in
        issue) cmd_tls_issue "$@" ;;
        renew) cmd_tls_renew "$@" ;;
        list)  cmd_status ;;
        -h|--help) usage_tls ;;
        *) die_usage "tls 未知子命令：$sub（issue|renew）" ;;
      esac ;;
    restart) cmd_restart "$@" ;;
    logs)    cmd_logs "$@" ;;
    *) die_usage "未知命令：$command" ;;
  esac
}

main() {
  # --prefix 允许出现在任意位置；先摘出来，其余参数原样交给命令。
  local -a remainder=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --prefix)   [ "$#" -ge 2 ] || die_usage "--prefix 需要目录参数"; PREFIX="$2"; shift 2 ;;
      --prefix=*) PREFIX="${1#*=}"; shift ;;
      *)          remainder+=("$1"); shift ;;
    esac
  done
  normalize_prefix
  dispatch ${remainder[@]+"${remainder[@]}"}
}

main "$@"

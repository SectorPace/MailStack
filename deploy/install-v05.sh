#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root'; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ADMIN_PORT=${ADMIN_PORT:-8787}
WEBMAIL_PORT=${WEBMAIL_PORT:-18788}
ADMIN_HOST=${ADMIN_HOST:-127.0.0.1}
WEBMAIL_HOST=${WEBMAIL_HOST:-127.0.0.1}
ACCESS_MODE=${ACCESS_MODE:-local}

# 10# 前缀强制十进制：带前导零的端口（如 0877）会被算术展开按八进制解析而报错
valid_port(){ [[ $1 =~ ^[0-9]+$ ]] && (( 10#$1 >= 1024 && 10#$1 <= 65535 )); }
valid_port "$ADMIN_PORT" || { echo 'Invalid ADMIN_PORT (1024-65535 required)' >&2; exit 2; }
valid_port "$WEBMAIL_PORT" || { echo 'Invalid WEBMAIL_PORT (1024-65535 required)' >&2; exit 2; }
[[ $ADMIN_PORT != "$WEBMAIL_PORT" ]] || { echo 'Admin and Webmail ports must differ' >&2; exit 2; }

args=(
  --access-mode "$ACCESS_MODE"
  --admin-port "$ADMIN_PORT"
  --admin-host "$ADMIN_HOST"
  --webmail-port "$WEBMAIL_PORT"
  --webmail-host "$WEBMAIL_HOST"
)
[[ -n ${MAIL_DOMAIN:-} ]] && args+=(--domain "$MAIL_DOMAIN")
[[ -n ${WEBMAIL_DOMAIN:-} ]] && args+=(--webmail-domain "$WEBMAIL_DOMAIN")
[[ -n ${ADMIN_EMAIL:-} ]] && args+=(--email "$ADMIN_EMAIL")
[[ ${NONINTERACTIVE:-0} == 1 ]] && args+=(--non-interactive)
[[ ${COOKIE_SECURE:-} == 1 ]] && args+=(--https)

exec bash "$ROOT/deploy/install.sh" "${args[@]}" "$@"

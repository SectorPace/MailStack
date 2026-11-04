
set -Eeuo pipefail
umask 022

MAILSTACK_VERSION="1.0.0"
REPO_SLUG="SectorPace/MailStack"
REPO_URL="https://github.com/${REPO_SLUG}"
RAW_BRANCH="main"
TARGET_TRIPLE="x86_64-unknown-linux-gnu"
TARBALL_NAME="mailstack-v${MAILSTACK_VERSION}-${TARGET_TRIPLE}.tar.gz"
RELEASE_BASE="${MAILSTACK_RELEASE_BASE_URL:-${REPO_URL}/releases/download/v${MAILSTACK_VERSION}}"
SOURCE_TARBALL_URL="${REPO_URL}/archive/refs/tags/v${MAILSTACK_VERSION}.tar.gz"
EXPECTED_RUST="1.98.1"

BIN_NAMES=(mailstackd mailstackctl mailstack-web mailstack-imap mailstack-webmail)
UNIT_NAMES=(mailstackd mailstack-web mailstack-imap mailstack-webmail)
WRAPPER_NAME="mailstack-privileged"
SUDOERS_NAME="mailstack-admin"
MANAGE_NAME="mailstack-manage"
ACCESS_MODES_ALL=(ssh caddy nginx ip-acme panel-domain cloudflared)

MODE="release"            # release | source | archive | binary-dir
ARCHIVE=""
BINARY_DIR=""
PREFIX="/"
DOMAIN=""
MAIL_HOST=""
MAIL_HOST_GIVEN=0
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
ACCESS_MODE=""            # 归一后的「详细访问模式」（ssh/caddy/nginx/ip-acme/panel-domain/cloudflared）
ACCESS_MODE_GIVEN=0
UNINSTALL=0
PURGE=0

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
CHECKOUT_ROOT=""
PREFIX_NORM=""            # "" 表示 /；否则形如 /tmp/mailstack-stage（无尾斜杠）
TMP_DIRS=()
WORK_DIR=""
SUDO_CMD=""
ADMIN_BOOTSTRAP="unknown" # ok | kept | skipped | unverified
IDENTITY_APPLIED="not-requested" # ok | failed | not-requested
ACCESS_PROVISIONED="not-requested" # ok | failed | skipped
STDIN_IS_SCRIPT=0
ADMIN_PW_PIPE_MISSING=0

ETC_DIR=""
ACCESS_DIR=""
VAR_LIB_DIR=""
BACKUP_DIR=""
RUN_DIR=""
BIN_DIR=""
LIBEXEC_DIR=""
DIST_DIR=""
UNIT_DIR=""
CONFIG_ROOT_ARG=""
INSTALL_UNITS=()
RUN_UNITS=()

BIN_SRC_DIR=""
UNIT_SRC_DIR=""
DIST_SRC_DIR=""
PKG_ROOT=""
PKG_DOC_DIR=""
INSTALL_UNINSTALL_SRC=""
MANAGE_SRC=""
MANAGE_DOWNLOADED=0
STATE_REL_PATH="etc/mailstack/install-args.conf"

say()  { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  local d
  for d in ${TMP_DIRS[@]+"${TMP_DIRS[@]}"}; do
    [ -n "$d" ] && rm -rf -- "$d"
  done
  return 0
}

on_err() {
  local rc=$?
  printf '\nERROR: 安装在第 %s 行失败（退出码 %s）\n' "${BASH_LINENO[0]}" "$rc" >&2
  exit "$rc"
}

trap cleanup EXIT
trap on_err ERR

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令 $1（安装前置依赖）"
}

new_tmp() {
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/mailstack-install.XXXXXXXX")" || die "无法创建临时目录"
  TMP_DIRS+=("$d")
  printf '%s' "$d"
}

is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

usage() {
  cat <<'EOF'
MailStack v1.0.0 安装脚本

推荐用法（一条命令，非交互；安装完成后可直接用 sudo mailstack-manage 管理）:
  curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh \
    | sudo bash -s -- --domain mail.example.com --admin-user admin \
        --admin-password '<口令>' --access-mode <模式> [--mail-host mail.example.com]

等价用法:
  bash deploy/install.sh [选项]
  sudo bash deploy/install.sh --from-source [选项]

安装来源（四选一，默认从 GitHub Release 下载）:
  (默认)                 下载 mailstack-v1.0.0-x86_64-unknown-linux-gnu.tar.gz，
                         并用同目录 SHA256SUMS 校验
  --from-source          用当前 checkout（或下载 tag v1.0.0 源码包）调 deploy/build.sh 构建
  --archive FILE|URL     使用指定的发布包（本地文件或 URL；离线/内网镜像）
  --binary-dir DIR       直接使用预编译二进制目录（测试/离线；不校验二进制内容）

目标位置:
  --prefix DIR           把全部路径安装到 DIR 下（默认 /；staging 测试用）

身份与端口:
  --domain DOMAIN        邮件主域名（写入 setup.json / 域名表 / 部署状态）
  --mail-host HOST       对外邮件主机名（默认 mail.<domain>；MX 目标）
  --admin-port PORT      管理台监听端口（默认 8443，只绑 127.0.0.1）
  --webmail-port PORT    Webmail 监听端口（默认 8444，只绑 127.0.0.1）
  --imap yes|no          安装并启用 IMAP/POP3/ManageSieve unit（默认 yes）
  --server-ip IP         setup.json 里的服务器 IP（默认自动探测；仅写 DNS 提示用）
  --panel-host HOST      面板主机名（默认按访问模式推导；可省略）
  --webmail-host HOST    Webmail 主机名（默认 webmail.<domain>；可省略）
  --acme-email EMAIL     ACME 证书账户邮箱（ip-acme/panel-domain/caddy 用）

访问模式（--access-mode，默认 ssh；旧值 local/caddy/direct 仍接受）:
  ssh            管理台/Webmail 只绑回环 + SSH 隧道；不安装反向代理（默认，最安全）
  caddy          Caddy 反代 panel/webmail 主机名，自动 ACME HTTPS
  nginx          nginx 反代（80），TLS 由 certbot --nginx / acme.sh 补
  ip-acme        公网 IP 路径：nginx 终止 TLS，证书由 mailstackctl setup.cert.issue 签发
  panel-domain   独立面板域名（禁止与 mail./imap./smtp. 冲突）反代 TLS
  cloudflared    Cloudflare Tunnel → 127.0.0.1:8443/8444（本机不开放端口）
  旧值：local→ssh，caddy→caddy，direct→ip-acme（install-args.conf 里仍写这三个旧值之一，
       详细模式写在 ACCESS_MODE_DETAIL，保证老读方 crates/core/src/mode.rs 可读）。
  --no-access-provision  只写部署状态，不调用 mailstack-manage 生成反代/Tunnel 文件

管理员引导:
  --admin-user NAME      管理员用户名（默认 admin）
  --admin-password PW    直接给管理员口令（会经 argv 暴露，仅建议 curl 一行安装时用；
                         更安全的方式是 --admin-password-stdin）
  --admin-password-stdin 从标准输入读一行作为管理员口令（不落 argv）。
                         注意：curl|bash 管道模式下 stdin 是脚本本身，**不能**再读，
                         此时口令接受 --admin-password 或环境变量 MAILSTACK_ADMIN_PASSWORD。

运行方式:
  --non-interactive      不交互（不会提示任何输入；缺省口令时跳过引导并打印手工命令）
  --no-systemd           只写 unit 文件，不 systemctl enable/start（容器/staging）
  --uninstall            执行卸载（转交 deploy/uninstall.sh；可加 --purge）
  --purge                仅配合 --uninstall：连 /etc/mailstack 与 /var/lib/mailstack 一起删除
  -h, --help             显示本帮助
  --version              显示安装器版本

安装器做的事情（顺序）:
  1) root/平台/依赖检查（不满足即失败，不做部分安装）
  2) 获取二进制（Release+SHA256 / --from-source / --archive / --binary-dir）
  3) 建系统用户/组、目录与权限
  4) 装 5 个二进制 + 特权包装器（--privileged-stdin）+ sudoers（visudo -cf 校验）
  5) 装前端产物 + systemd unit + 卸载脚本
  6) 装 /usr/local/bin/mailstack-manage（服务器管理脚本）
  7) 写部署状态（domain/admin/ports/access mode/panel host… 到 install-args.conf）
  8) 管理员凭证引导（admin.set，经特权包装器；已存在则跳过）
  9) 应用邮件身份（有 --domain 时：setup.identity.apply，原生 DKIM）
 10) 应用访问模式（mailstack-manage access set：Caddyfile/nginx/cloudflared/ssh 文件）
 11) enable/start systemd unit，打印摘要与一行安装用法

示例:
  # ① 一条命令完整安装（推荐；口令走 argv，注意 shell 历史）
  curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh \
    | sudo bash -s -- --domain mail.example.com --admin-user admin \
        --admin-password 'My-Admin-Pass-9' --access-mode caddy

  # ② 先落盘再执行（口令可以走 stdin，不留在 argv/历史）
  curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh \
    -o /tmp/mailstack-install.sh
  sudo bash /tmp/mailstack-install.sh --domain example.com --admin-password-stdin <<< 'My-Admin-Pass-9'

  # ③ 管道 + 环境变量（stdin 已被脚本占用时）
  curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh \
    | MAILSTACK_ADMIN_PASSWORD='My-Admin-Pass-9' sudo -E bash -s -- \
        --domain example.com --admin-password-stdin

  # ④ staging 安装（不碰 systemd、不联网；测试用）
  sudo bash deploy/install.sh --binary-dir ./dist --prefix /tmp/mailstack-stage \
    --non-interactive --no-systemd --domain example.com \
    --admin-password-stdin --access-mode ssh <<< 'Bootstrap-Pass-9'

  # ⑤ 从当前 checkout 源码构建后安装
  sudo bash deploy/install.sh --from-source --domain example.com --admin-password-stdin

  # ⑥ 卸载（默认保留 /etc/mailstack 与 /var/lib/mailstack；--purge 才删）
  sudo bash deploy/uninstall.sh

安装后管理（3x-ui 风格 CLI + 交互菜单）:
  sudo mailstack-manage                  # 交互菜单
  sudo mailstack-manage status
  sudo mailstack-manage access set caddy
  sudo mailstack-manage domain set example.com --mail-host mail.example.com
  sudo mailstack-manage account add alice@example.com --password-stdin
  sudo mailstack-manage tls issue mail.example.com --email ops@example.com
EOF
}

read_admin_password_stdin() {
  if [ "$STDIN_IS_SCRIPT" -eq 1 ]; then
    if [ -n "${MAILSTACK_ADMIN_PASSWORD:-}" ]; then
      ADMIN_PASSWORD="$MAILSTACK_ADMIN_PASSWORD"
    else
      ADMIN_PW_PIPE_MISSING=1
    fi
    return 0
  fi
  local value=""
  if IFS= read -r value; then :; fi
  value="${value%$'\r'}"
  if [ -z "$value" ] && [ -n "${MAILSTACK_ADMIN_PASSWORD:-}" ]; then
    value="$MAILSTACK_ADMIN_PASSWORD"
  fi
  [ -n "$value" ] || die "未能从 stdin 读到管理员口令（--admin-password-stdin）；可用环境变量 MAILSTACK_ADMIN_PASSWORD='...' 传入"
  ADMIN_PASSWORD="$value"
}

normalize_access_mode_detail() {
  local lowered
  lowered="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$lowered" in
    ssh|local|loopback|tunnel)      printf 'ssh' ;;
    caddy)                          printf 'caddy' ;;
    nginx)                          printf 'nginx' ;;
    ip-acme|ip_acme|ipacme|ip)      printf 'ip-acme' ;;
    panel-domain|panel_domain|panel) printf 'panel-domain' ;;
    cloudflared|cloudflare|cf-tunnel) printf 'cloudflared' ;;
    direct)                         printf 'ip-acme' ;;   # 旧值 direct → 公网直连档
    *) return 1 ;;
  esac
}

canonical_access_mode() {
  case "$1" in
    ssh)                            printf 'local' ;;
    caddy|nginx|panel-domain|cloudflared) printf 'caddy' ;;
    ip-acme)                        printf 'direct' ;;
    local)                          printf 'local' ;;
    direct)                         printf 'direct' ;;
    *)                              printf 'local' ;;
  esac
}

detail_mode_from_state() {
  local conf="$ETC_DIR/install-args.conf" detail="" canonical=""
  [ -s "$conf" ] || return 0
  detail="$(state_get "$conf" ACCESS_MODE_DETAIL)"
  if [ -n "$detail" ]; then
    normalize_access_mode_detail "$detail" && return 0
  fi
  canonical="$(state_get "$conf" ACCESS_MODE)"
  case "$canonical" in
    local|"") printf 'ssh' ;;
    caddy)    printf 'caddy' ;;
    direct)   printf 'ip-acme' ;;
    *)        : ;;
  esac
}

state_get() {
  local conf="$1" key="$2" raw=""
  raw="$(sed -n "s/^${key}=//p" "$conf" 2>/dev/null | head -1)"
  [ -n "$raw" ] || return 1
  case "$raw" in
    \'*\') raw="${raw#\'}"; raw="${raw%\'}" ;;
    \"*\") raw="${raw#\"}"; raw="${raw%\"}" ;;
  esac
  printf '%s' "$raw"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --from-source) MODE="source"; shift ;;
      --archive)     [ "$#" -ge 2 ] || die "--archive 需要一个参数（文件或 URL）"; MODE="archive"; ARCHIVE="$2"; shift 2 ;;
      --archive=*)   MODE="archive"; ARCHIVE="${1#*=}"; shift ;;
      --binary-dir)  [ "$#" -ge 2 ] || die "--binary-dir 需要一个目录参数"; MODE="binary-dir"; BINARY_DIR="$2"; shift 2 ;;
      --binary-dir=*) MODE="binary-dir"; BINARY_DIR="${1#*=}"; shift ;;
      --prefix)      [ "$#" -ge 2 ] || die "--prefix 需要一个目录参数"; PREFIX="$2"; shift 2 ;;
      --prefix=*)    PREFIX="${1#*=}"; shift ;;
      --domain)      [ "$#" -ge 2 ] || die "--domain 需要一个参数"; DOMAIN="$2"; shift 2 ;;
      --domain=*)    DOMAIN="${1#*=}"; shift ;;
      --mail-host)   [ "$#" -ge 2 ] || die "--mail-host 需要一个参数"; MAIL_HOST="$2"; MAIL_HOST_GIVEN=1; shift 2 ;;
      --mail-host=*) MAIL_HOST="${1#*=}"; MAIL_HOST_GIVEN=1; shift ;;
      --admin-user)  [ "$#" -ge 2 ] || die "--admin-user 需要一个参数"; ADMIN_USER="$2"; shift 2 ;;
      --admin-user=*) ADMIN_USER="${1#*=}"; shift ;;
      --admin-password)
        [ "$#" -ge 2 ] || die "--admin-password 需要一个参数（口令本身；建议改用 --admin-password-stdin）"
        ADMIN_PASSWORD="$2"; ADMIN_PASSWORD_ARGV=1; shift 2 ;;
      --admin-password=*) ADMIN_PASSWORD="${1#*=}"; ADMIN_PASSWORD_ARGV=1; shift ;;
      --admin-password-stdin) ADMIN_PASSWORD_STDIN=1; read_admin_password_stdin; shift ;;
      --admin-port)  [ "$#" -ge 2 ] || die "--admin-port 需要一个参数"; ADMIN_PORT="$2"; shift 2 ;;
      --admin-port=*) ADMIN_PORT="${1#*=}"; shift ;;
      --webmail-port) [ "$#" -ge 2 ] || die "--webmail-port 需要一个参数"; WEBMAIL_PORT="$2"; shift 2 ;;
      --webmail-port=*) WEBMAIL_PORT="${1#*=}"; shift ;;
      --panel-host)  [ "$#" -ge 2 ] || die "--panel-host 需要一个参数"; PANEL_HOST="$2"; shift 2 ;;
      --panel-host=*) PANEL_HOST="${1#*=}"; shift ;;
      --webmail-host) [ "$#" -ge 2 ] || die "--webmail-host 需要一个参数"; WEBMAIL_HOST="$2"; shift 2 ;;
      --webmail-host=*) WEBMAIL_HOST="${1#*=}"; shift ;;
      --acme-email)  [ "$#" -ge 2 ] || die "--acme-email 需要一个参数"; ACME_EMAIL="$2"; shift 2 ;;
      --acme-email=*) ACME_EMAIL="${1#*=}"; shift ;;
      --server-ip)   [ "$#" -ge 2 ] || die "--server-ip 需要一个参数"; SERVER_IP="$2"; shift 2 ;;
      --server-ip=*) SERVER_IP="${1#*=}"; shift ;;
      --imap)
        [ "$#" -ge 2 ] || die "--imap 需要 yes|no"
        case "$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')" in
          yes|true|1|enable|on)  IMAP_ENABLE=1 ;;
          no|false|0|disable|off) IMAP_ENABLE=0 ;;
          *) die "--imap 只接受 yes|no（实际：$2）" ;;
        esac
        shift 2 ;;
      --imap=*)      # 兼容 --imap=yes 写法
        case "$(printf '%s' "${1#*=}" | tr '[:upper:]' '[:lower:]')" in
          yes|true|1|enable|on)  IMAP_ENABLE=1 ;;
          no|false|0|disable|off) IMAP_ENABLE=0 ;;
          *) die "--imap 只接受 yes|no（实际：${1#*=}）" ;;
        esac
        shift ;;
      --access-mode)
        [ "$#" -ge 2 ] || die "--access-mode 需要模式（${ACCESS_MODES_ALL[*]}；旧值 local/caddy/direct 仍接受）"
        ACCESS_MODE="$2"; ACCESS_MODE_GIVEN=1; shift 2 ;;
      --access-mode=*) ACCESS_MODE="${1#*=}"; ACCESS_MODE_GIVEN=1; shift ;;
      --no-access-provision) NO_ACCESS_PROVISION=1; shift ;;
      --non-interactive) NON_INTERACTIVE=1; shift ;;
      --no-systemd)  NO_SYSTEMD=1; shift ;;
      --uninstall)   UNINSTALL=1; shift ;;
      --purge)       PURGE=1; shift ;;
      -h|--help)     usage; exit 0 ;;
      --version)     printf 'MailStack installer %s (target %s)\n' "$MAILSTACK_VERSION" "$TARGET_TRIPLE"; exit 0 ;;
      *) die "未知参数：$1（用 -h 查看用法）" ;;
    esac
  done
}

validate_options() {
  if [ "$ADMIN_PW_PIPE_MISSING" -eq 1 ]; then
    die "curl|bash 管道模式无法从 stdin 读口令（stdin 就是脚本本身）。两种写法：
  ① 先落盘再执行：curl -fsSL .../deploy/install.sh -o /tmp/i.sh && sudo bash /tmp/i.sh --admin-password-stdin <<< '口令'
  ② 管道 + 环境变量：curl -fsSL .../deploy/install.sh | MAILSTACK_ADMIN_PASSWORD='口令' sudo -E bash -s -- --admin-password-stdin
  ③ 或直接用 --admin-password '<口令>'（会经 argv 暴露，见 --help 的安全提示）"
  fi

  if [ -z "$ADMIN_PASSWORD" ] && [ -n "${MAILSTACK_ADMIN_PASSWORD:-}" ]; then
    ADMIN_PASSWORD="$MAILSTACK_ADMIN_PASSWORD"
  fi
  if [ "$ADMIN_PASSWORD_ARGV" -eq 1 ]; then
    warn "--admin-password 会经 argv/进程列表暴露（curl 一行安装的便利写法）；更安全的是 --admin-password-stdin"
  fi

  if [ -n "$ARCHIVE" ] && [ -n "$BINARY_DIR" ]; then
    die "--archive 与 --binary-dir 只能选一个"
  fi
  if [ "$UNINSTALL" -eq 0 ] && [ "$PURGE" -eq 1 ]; then
    die "--purge 只能与 --uninstall 一起使用"
  fi

  is_uint "$ADMIN_PORT" || die "--admin-port 必须是整数（实际：$ADMIN_PORT）"
  is_uint "$WEBMAIL_PORT" || die "--webmail-port 必须是整数（实际：$WEBMAIL_PORT）"
  [ "$ADMIN_PORT" -ge 1 ] && [ "$ADMIN_PORT" -le 65535 ] || die "--admin-port 越界：$ADMIN_PORT"
  [ "$WEBMAIL_PORT" -ge 1 ] && [ "$WEBMAIL_PORT" -le 65535 ] || die "--webmail-port 越界：$WEBMAIL_PORT"
  [ "$ADMIN_PORT" != "$WEBMAIL_PORT" ] || die "--admin-port 与 --webmail-port 不能相同（$ADMIN_PORT）"

  case "$ADMIN_USER" in
    [A-Za-z]*) : ;;
    *) die "管理员用户名必须以字母开头（实际：$ADMIN_USER）" ;;
  esac
  if ! printf '%s' "$ADMIN_USER" | grep -Eq '^[A-Za-z][A-Za-z0-9_.-]{2,31}$'; then
    die "管理员用户名不合法（要求 3-32 字符，字母开头，允许字母/数字/_.-，实际：$ADMIN_USER）"
  fi

  if [ -n "$DOMAIN" ] && ! printf '%s' "$DOMAIN" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'; then
    die "域名不合法：$DOMAIN（例：example.com）"
  fi
  if [ -z "$MAIL_HOST" ] && [ -n "$DOMAIN" ]; then
    MAIL_HOST="mail.$DOMAIN"
  fi
  if [ -n "$MAIL_HOST" ] && ! printf '%s' "$MAIL_HOST" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'; then
    die "邮件主机名不合法：$MAIL_HOST"
  fi
  if [ -n "$MAIL_HOST" ] && [ -z "$DOMAIN" ]; then
    info "只给出 --mail-host（$MAIL_HOST）：域名身份留给 mailstack-manage domain set / 管理台向导"
  fi

  if [ -n "$PANEL_HOST" ] && ! printf '%s' "$PANEL_HOST" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'; then
    die "面板主机名不合法：$PANEL_HOST"
  fi
  if [ -n "$WEBMAIL_HOST" ] && ! printf '%s' "$WEBMAIL_HOST" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'; then
    die "Webmail 主机名不合法：$WEBMAIL_HOST"
  fi
  if [ -n "$ACME_EMAIL" ] && ! printf '%s' "$ACME_EMAIL" | grep -Eq '^[A-Za-z0-9._%+-]+@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'; then
    die "--acme-email 不合法：$ACME_EMAIL"
  fi
  if [ -n "$SERVER_IP" ] && ! printf '%s' "$SERVER_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    die "--server-ip 不是合法 IPv4：$SERVER_IP"
  fi

  if [ "$ACCESS_MODE_GIVEN" -eq 1 ]; then
    local requested_mode="$ACCESS_MODE"
    ACCESS_MODE="$(normalize_access_mode_detail "$requested_mode")" \
      || die "--access-mode 只有 ${ACCESS_MODES_ALL[*]}（旧值 local/caddy/direct 也接受）（实际：$requested_mode）"
  else
    ACCESS_MODE="$(detail_mode_from_state)"
  fi
  if [ -z "$ACCESS_MODE" ]; then
    ACCESS_MODE="ssh"
  fi

  if [ "$ACCESS_MODE" != "ssh" ]; then
    if [ -z "$PANEL_HOST" ]; then
      if [ -n "$DOMAIN" ]; then
        case "$ACCESS_MODE" in
          ip-acme) PANEL_HOST="${MAIL_HOST:-$DOMAIN}" ;;
          *)       PANEL_HOST="panel.$DOMAIN" ;;
        esac
      else
        die "访问模式 $ACCESS_MODE 需要面板主机名：加 --panel-host <host>（或先给 --domain）"
      fi
    fi
    if [ -z "$WEBMAIL_HOST" ]; then
      if [ -n "$DOMAIN" ]; then
        WEBMAIL_HOST="webmail.$DOMAIN"
      else
        die "访问模式 $ACCESS_MODE 需要 Webmail 主机名：加 --webmail-host <host>（或先给 --domain）"
      fi
    fi
  fi
  if [ "$ACCESS_MODE" = "panel-domain" ]; then
    local h
    for h in "$DOMAIN" "$MAIL_HOST" "mail.$DOMAIN" "imap.$DOMAIN" "smtp.$DOMAIN" "pop.$DOMAIN"; do
      [ -n "$h" ] || continue
      if [ "$PANEL_HOST" = "$h" ]; then
        die "panel-domain 要求独立面板主机名：$PANEL_HOST 与邮件主机 $h 冲突（改用 --panel-host panel.<domain> 或 --access-mode caddy）"
      fi
    done
    [ "$PANEL_HOST" != "$WEBMAIL_HOST" ] || die "--panel-host 与 --webmail-host 不能相同"
  fi

  if [ -n "$ADMIN_PASSWORD" ]; then
    if printf '%s' "$ADMIN_PASSWORD" | LC_ALL=C grep -q '[[:cntrl:]]'; then
      die "管理员口令不得包含控制字符（换行/制表符等）"
    fi
    local plen=${#ADMIN_PASSWORD}
    [ "$plen" -ge 12 ] && [ "$plen" -le 256 ] \
      || die "管理员口令长度必须 12-256 字符（实际 $plen）"
    printf '%s' "$ADMIN_PASSWORD" | grep -q '[A-Za-z]' || die "管理员口令必须同时包含字母与数字"
    printf '%s' "$ADMIN_PASSWORD" | grep -q '[0-9]'    || die "管理员口令必须同时包含字母与数字"
    local lowered passlower
    lowered="$(printf '%s' "$ADMIN_USER" | tr '[:upper:]' '[:lower:]')"
    passlower="$(printf '%s' "$ADMIN_PASSWORD" | tr '[:upper:]' '[:lower:]')"
    case "$passlower" in
      *"$lowered"*) die "管理员口令不得包含用户名（后端会拒绝，与上下文校验保持一致）" ;;
    esac
  fi
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
    case "${PREFIX#/}" in
      */*) : ;;
      *) die "--prefix 至少要有两级（例：/tmp/mailstack-stage），实际：$PREFIX" ;;
    esac
    PREFIX_NORM="$PREFIX"
  fi
}

prefix_path() { printf '%s%s' "$PREFIX_NORM" "$1"; }

derive_paths() {
  ETC_DIR="$(prefix_path /etc/mailstack)"
  ACCESS_DIR="$ETC_DIR/access"
  VAR_LIB_DIR="$(prefix_path /var/lib/mailstack)"
  BACKUP_DIR="$(prefix_path /var/backups/mailstack)"
  RUN_DIR="$(prefix_path /run/mailstack)"
  BIN_DIR="$(prefix_path /usr/local/bin)"
  LIBEXEC_DIR="$(prefix_path /usr/local/libexec)"
  DIST_DIR="$(prefix_path /usr/share/mailstack/admin)"
  UNIT_DIR="$(prefix_path /etc/systemd/system)"
  if [ -n "$PREFIX_NORM" ]; then
    CONFIG_ROOT_ARG=" --config-dir ${PREFIX_NORM}"
  else
    CONFIG_ROOT_ARG=""
  fi
  INSTALL_UNITS=(mailstackd mailstack-web mailstack-webmail)
  [ "$IMAP_ENABLE" -eq 1 ] && INSTALL_UNITS+=(mailstack-imap)
  RUN_UNITS=("${INSTALL_UNITS[@]}")
}

install_dir() {
  local dir="$1" mode="$2" owner="$3" group="$4"
  [ -n "$dir" ] || die "install_dir: 空路径"
  install -d -m "$mode" "$dir" || die "无法创建目录 $dir"
  chown "$owner:$group" "$dir" 2>/dev/null || die "无法设置 $dir 属主 $owner:$group"
  chmod "$mode" "$dir" || die "无法设置 $dir 权限 $mode"
}

put_file() {
  local src="$1" dst="$2" mode="$3" owner="$4" group="$5"
  local tmp="${dst}.new.$$"
  install -m "$mode" "$src" "$tmp" || die "无法写入 $tmp"
  chown "$owner:$group" "$tmp" 2>/dev/null || { rm -f -- "$tmp"; die "无法设置 $dst 属主 $owner:$group"; }
  mv -f -- "$tmp" "$dst" || die "无法替换 $dst"
}

safe_rm_rf() {
  local target="$1"
  [ -n "$target" ] || die "safe_rm_rf: 空路径"
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
      *) die "safe_rm_rf: $real 不在安装前缀 $preal 之下，拒绝删除" ;;
    esac
  fi
  rm -rf -- "$real"
}

check_environment() {
  [ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo bash $0 ...）"
  case "$(uname -s)" in
    Linux) : ;;
    *) die "本脚本只支持 Linux（当前 $(uname -s)）" ;;
  esac
  local arch
  arch="$(uname -m)"
  if [ "$MODE" != "binary-dir" ] && [ "$arch" != "x86_64" ]; then
    die "官方发布产物只覆盖 x86_64（当前 $arch）。请改用 --binary-dir 提供本机架构的预编译二进制。"
  fi
  [ "$arch" = "x86_64" ] || warn "当前架构 $arch 非 x86_64：仅 --binary-dir 模式可用"

  need_cmd install
  need_cmd tar
  need_cmd sha256sum
  need_cmd mktemp
  need_cmd realpath
  need_cmd tr
  need_cmd sed
  if command -v getent >/dev/null 2>&1; then :; else need_cmd grep; fi
  need_cmd groupadd
  need_cmd useradd

  if command -v sudo >/dev/null 2>&1; then
    SUDO_CMD="$(command -v sudo)"
  else
    SUDO_CMD=""
    if [ -n "$PREFIX_NORM" ]; then
      warn "未找到 sudo：staging 前缀模式继续（引导阶段由 root 直接执行包装器）"
    else
      die "未找到 sudo：MailStack 的变更动作恒经 sudo 包装器（R2-001）。请先安装 sudo（apt install sudo）后重跑。"
    fi
  fi

  if command -v visudo >/dev/null 2>&1; then
    SUDOERS_VALIDATE=1
  else
    SUDOERS_VALIDATE=0
    if [ -n "$PREFIX_NORM" ]; then
      warn "未找到 visudo：staging 前缀模式跳过 sudoers 语法校验（真实安装必须安装 sudo 包）"
    else
      die "未找到 visudo：无法校验 /etc/sudoers.d 语法（缺 sudo 包）。请安装 sudo 后重跑。"
    fi
  fi

  if [ "$MODE" = "release" ] || { [ "$MODE" = "archive" ] && printf '%s' "$ARCHIVE" | grep -Eq '^https?://'; }; then
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
      die "下载发布包需要 curl 或 wget"
    fi
  fi

  if [ -n "$CHECKOUT_ROOT" ] && [ -f "$CHECKOUT_ROOT/VERSION" ]; then
    local repo_version
    repo_version="$(tr -d '[:space:]' < "$CHECKOUT_ROOT/VERSION")"
    [ "$repo_version" = "$MAILSTACK_VERSION" ] \
      || warn "安装器版本 $MAILSTACK_VERSION 与 checkout 版本 $repo_version 不一致"
  fi
}

download() {
  local url="$1" dest="$2"
  info "下载 $url"
  if command -v curl >/dev/null 2>&1; then
    curl -fSL --retry 3 --retry-delay 2 --connect-timeout 20 -o "$dest" "$url" \
      || die "下载失败：$url（如需代理请设置 HTTPS_PROXY）"
  else
    wget -q -O "$dest" "$url" || die "下载失败：$url（如需代理请设置 HTTPS_PROXY）"
  fi
}

verify_sha256() {
  local dir="$1" file="$2" sums="$3"
  [ -s "$sums" ] || die "SHA256SUMS 不存在或为空：$sums"
  local base expected
  base="$(basename -- "$file")"
  expected="$(awk -v want="$base" '
    {
      name = $2
      sub(/^\*/, "", name)
      sub(/^\.\//, "", name)
      if (name == want) { print $1; exit }
    }
  ' "$sums")"
  [ -n "$expected" ] || die "SHA256SUMS 中没有 $base 的条目（拒绝安装未校验的包）"
  ( cd "$dir" && printf '%s  %s\n' "$expected" "$base" | sha256sum -c - >/dev/null ) \
    || die "SHA256 校验失败：$base（发布包损坏或被篡改）"
  info "SHA256 校验通过：$base"
}

extract_tarball() {
  local tarball="$1" dest="$2"
  mkdir -p "$dest"
  tar -xzf "$tarball" -C "$dest" || die "解包失败：$tarball"
  local roots=()
  local entry
  for entry in "$dest"/*; do
    [ -e "$entry" ] && roots+=("$entry")
  done
  if [ "${#roots[@]}" -eq 1 ] && [ -d "${roots[0]}" ]; then
    printf '%s' "${roots[0]}"
  else
    printf '%s' "$dest"
  fi
}

resolve_package() {
  local pkg="$1"
  [ -n "$pkg" ] && [ -d "$pkg" ] || die "发布包目录不存在：$pkg"
  PKG_ROOT="$pkg"
  PKG_DOC_DIR="$pkg"

  if [ -d "$pkg/bin" ] && [ -f "$pkg/bin/mailstackd" ]; then
    BIN_SRC_DIR="$pkg/bin"
  elif [ -f "$pkg/mailstackd" ]; then
    BIN_SRC_DIR="$pkg"
  else
    die "发布包结构不符合预期：既没有 bin/mailstackd，也没有顶层 mailstackd（$pkg）"
  fi

  if [ -d "$pkg/deploy/systemd" ]; then
    UNIT_SRC_DIR="$pkg/deploy/systemd"
  fi

  if [ -d "$pkg/webui-dist" ]; then
    DIST_SRC_DIR="$pkg/webui-dist"
  elif [ -d "$pkg/webui/dist" ]; then
    DIST_SRC_DIR="$pkg/webui/dist"
  fi

  if [ -f "$pkg/deploy/uninstall.sh" ]; then
    INSTALL_UNINSTALL_SRC="$pkg/deploy/uninstall.sh"
  fi
  if [ -f "$pkg/deploy/mailstack-manage.sh" ]; then
    MANAGE_SRC="$pkg/deploy/mailstack-manage.sh"
  fi
}

locate_checkout_assets() {
  local base="${CHECKOUT_ROOT:-}"
  if [ -n "$base" ]; then
    [ -d "$base/deploy/systemd" ] && UNIT_SRC_DIR="$base/deploy/systemd"
    if [ -d "$base/webui/dist" ]; then
      DIST_SRC_DIR="$base/webui/dist"
    elif [ -d "$base/dist/webui-dist" ]; then
      DIST_SRC_DIR="$base/dist/webui-dist"
    fi
    [ -f "$base/deploy/uninstall.sh" ] && INSTALL_UNINSTALL_SRC="$base/deploy/uninstall.sh"
    [ -f "$base/deploy/mailstack-manage.sh" ] && MANAGE_SRC="$base/deploy/mailstack-manage.sh"
  fi
  if [ -z "$UNIT_SRC_DIR" ] && [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/systemd" ]; then
    UNIT_SRC_DIR="$SCRIPT_DIR/systemd"
  fi
  if [ -z "$INSTALL_UNINSTALL_SRC" ] && [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/uninstall.sh" ]; then
    INSTALL_UNINSTALL_SRC="$SCRIPT_DIR/uninstall.sh"
  fi
  if [ -z "$MANAGE_SRC" ] && [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/mailstack-manage.sh" ]; then
    MANAGE_SRC="$SCRIPT_DIR/mailstack-manage.sh"
  fi
}

acquire_release() {
  say "获取官方发布包（Release v${MAILSTACK_VERSION}，${TARGET_TRIPLE}）"
  local dl
  dl="$(new_tmp)"
  download "${RELEASE_BASE}/${TARBALL_NAME}" "$dl/$TARBALL_NAME"
  download "${RELEASE_BASE}/SHA256SUMS" "$dl/SHA256SUMS"
  verify_sha256 "$dl" "$TARBALL_NAME" "$dl/SHA256SUMS"
  local extract
  extract="$(new_tmp)"
  local pkg
  pkg="$(extract_tarball "$dl/$TARBALL_NAME" "$extract")"
  resolve_package "$pkg"
}

acquire_archive() {
  say "使用显式发布包：$ARCHIVE"
  local file=""
  local dl=""
  case "$ARCHIVE" in
    http://*|https://*)
      dl="$(new_tmp)"
      file="$dl/$(basename "${ARCHIVE%%\?*}")"
      download "$ARCHIVE" "$file" ;;
    *)
      file="$ARCHIVE"
      [ -f "$file" ] || die "发布包文件不存在：$file"
      file="$(realpath -- "$file")" ;;
  esac
  local sums_dir sums
  sums_dir="$(dirname "$file")"
  sums="$sums_dir/SHA256SUMS"
  if [ -s "$sums" ]; then
    verify_sha256 "$sums_dir" "$(basename "$file")" "$sums"
  else
    warn "发布包旁边没有 SHA256SUMS：跳过完整性校验（--archive 的调用方需自行担保来源）"
  fi
  local extract
  extract="$(new_tmp)"
  local pkg
  pkg="$(extract_tarball "$file" "$extract")"
  resolve_package "$pkg"
}

acquire_binary_dir() {
  say "使用预编译二进制目录：$BINARY_DIR"
  local dir="$BINARY_DIR"
  [ -d "$dir" ] || die "--binary-dir 目录不存在：$dir"
  dir="$(realpath -- "$dir")"
  if [ -d "$dir/bin" ] && [ -f "$dir/bin/mailstackd" ]; then
    BIN_SRC_DIR="$dir/bin"
  elif [ -f "$dir/mailstackd" ]; then
    BIN_SRC_DIR="$dir"
  else
    die "--binary-dir 下找不到 mailstackd（期望 $dir/bin/mailstackd 或 $dir/mailstackd）"
  fi
  locate_checkout_assets
  if [ -z "$UNIT_SRC_DIR" ]; then
    die "找不到 systemd unit 模板：请在仓库 checkout 中运行，或使用 --archive/默认 Release 模式（发布包内含 deploy/systemd/）"
  fi
}

check_toolchain_for_source() {
  command -v cargo >/dev/null 2>&1 || die "源码构建需要 cargo（rustup 安装 Rust $EXPECTED_RUST）"
  command -v rustc >/dev/null 2>&1 || die "源码构建需要 rustc"
  local version
  version="$(rustc --version 2>/dev/null || true)"
  case "$version" in
    "rustc $EXPECTED_RUST"*) info "rustc: $version" ;;
    *) die "工具链版本不匹配：期望 rustc $EXPECTED_RUST.x，实际 ${version:-unknown}（见 TOOLCHAIN.md）" ;;
  esac
  if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    die "源码构建需要 C 编译器（cc/gcc；ring 的汇编构建也用它）"
  fi
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    info "node/npm 可用：将尝试构建前端产物（可选）"
  else
    info "node/npm 不可用：跳过前端构建（若 checkout 已有 webui/dist 则直接使用）"
  fi
}

acquire_source() {
  say "从源码构建（deploy/build.sh）"
  local src=""
  if [ -n "$CHECKOUT_ROOT" ] && [ -f "$CHECKOUT_ROOT/Cargo.toml" ] && [ -f "$CHECKOUT_ROOT/deploy/build.sh" ]; then
    src="$CHECKOUT_ROOT"
    info "使用当前 checkout：$src"
  else
    info "当前不是仓库 checkout：下载 v${MAILSTACK_VERSION} 源码包"
    local dl extract pkg
    dl="$(new_tmp)"
    download "$SOURCE_TARBALL_URL" "$dl/source.tar.gz"
    extract="$(new_tmp)"
    pkg="$(extract_tarball "$dl/source.tar.gz" "$extract")"
    [ -f "$pkg/Cargo.toml" ] || die "源码包结构不符合预期（缺 Cargo.toml）：$pkg"
    src="$pkg"
  fi

  check_toolchain_for_source

  if [ ! -d "$src/webui/dist" ] && [ -d "$src/webui" ] \
     && command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    say "构建前端产物（webui：npm ci + npm run build）"
    if ( cd "$src/webui" && npm ci --no-audit --no-fund && npm run build ); then
      info "前端构建完成：$src/webui/dist"
    else
      warn "前端构建失败：管理台/Webmail 页面将不可用（API 仍可用）。可手工构建后重跑。"
    fi
  fi

  say "调用 deploy/build.sh（release 构建 + SHA256SUMS + SBOM）"
  ( cd "$src" && bash deploy/build.sh ) || die "deploy/build.sh 构建失败"

  BIN_SRC_DIR="$src/dist"
  UNIT_SRC_DIR="$src/deploy/systemd"
  PKG_DOC_DIR="$src"
  if [ -d "$src/webui/dist" ]; then
    DIST_SRC_DIR="$src/webui/dist"
  fi
  [ -f "$src/deploy/uninstall.sh" ] && INSTALL_UNINSTALL_SRC="$src/deploy/uninstall.sh"
  [ -f "$src/deploy/mailstack-manage.sh" ] && MANAGE_SRC="$src/deploy/mailstack-manage.sh"
  [ -f "$src/deploy/install.sh" ] && [ -z "$INSTALL_UNINSTALL_SRC" ] && INSTALL_UNINSTALL_SRC=""
  resolve_bin_dir_only "$BIN_SRC_DIR"
}

acquire_manage_script() {
  [ -n "$MANAGE_SRC" ] && [ -f "$MANAGE_SRC" ] && return 0
  if [ -n "$CHECKOUT_ROOT" ] && [ -f "$CHECKOUT_ROOT/deploy/mailstack-manage.sh" ]; then
    MANAGE_SRC="$CHECKOUT_ROOT/deploy/mailstack-manage.sh"
    return 0
  fi
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/mailstack-manage.sh" ]; then
    MANAGE_SRC="$SCRIPT_DIR/mailstack-manage.sh"
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "发布包里没有 deploy/mailstack-manage.sh，且本机没有 curl/wget 可下载。请改用仓库 checkout 安装，或升级到包含该脚本的发布包"
  fi
  local dl
  dl="$(new_tmp)"
  say "发布包未携带管理脚本：从 ${RAW_BRANCH} 分支下载 mailstack-manage.sh"
  download "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/mailstack-manage.sh" "$dl/mailstack-manage.sh"
  bash -n "$dl/mailstack-manage.sh" || die "下载的 mailstack-manage.sh 语法校验失败（拒绝安装）"
  MANAGE_SRC="$dl/mailstack-manage.sh"
  MANAGE_DOWNLOADED=1
}

resolve_bin_dir_only() {
  local dir="$1"
  [ -d "$dir" ] || die "构建产物目录不存在：$dir"
  BIN_SRC_DIR="$dir"
}

validate_artifacts() {
  [ -n "$BIN_SRC_DIR" ] && [ -d "$BIN_SRC_DIR" ] || die "内部错误：未定位到二进制目录"
  local name path missing=()
  for name in "${BIN_NAMES[@]}"; do
    path="$BIN_SRC_DIR/$name"
    if [ ! -f "$path" ]; then
      missing+=("$name")
      continue
    fi
    [ -x "$path" ] || die "二进制不可执行：$path（权限应含 x）"
    if [ "$MODE" != "binary-dir" ]; then
      if ! "$path" --version >/dev/null 2>&1; then
        die "二进制无法执行：$path（架构/glibc 不匹配？或文件损坏）"
      fi
    fi
  done
  if [ "${#missing[@]}" -ne 0 ]; then
    die "产物不齐，缺少：${missing[*]}（期望 5 个：${BIN_NAMES[*]}）"
  fi
  info "二进制齐全（${#BIN_NAMES[@]} 个）：${BIN_NAMES[*]}"

  [ -n "$UNIT_SRC_DIR" ] && [ -d "$UNIT_SRC_DIR" ] || die "找不到 systemd unit 模板目录"
  local unit
  for unit in "${UNIT_NAMES[@]}"; do
    [ -f "$UNIT_SRC_DIR/${unit}.service.in" ] || die "缺少 unit 模板：$UNIT_SRC_DIR/${unit}.service.in"
  done
  info "unit 模板齐全：$UNIT_SRC_DIR"

  if [ -z "$DIST_SRC_DIR" ] || [ ! -d "$DIST_SRC_DIR" ]; then
    warn "未找到前端产物（webui dist）：管理台/Webmail 页面将返回 503，API 仍可用"
    DIST_SRC_DIR=""
  else
    [ -f "$DIST_SRC_DIR/index.html" ] || warn "前端产物缺 index.html：管理台页面可能不可用"
    [ -f "$DIST_SRC_DIR/mail.html" ] || warn "前端产物缺 mail.html：Webmail 页面可能不可用"
    info "前端产物：$DIST_SRC_DIR"
  fi
}

group_exists() {
  if command -v getent >/dev/null 2>&1; then
    getent group "$1" >/dev/null 2>&1
  else
    grep -qE "^$1:" /etc/group 2>/dev/null
  fi
}

user_exists() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd "$1" >/dev/null 2>&1
  else
    grep -qE "^$1:" /etc/passwd 2>/dev/null
  fi
}

nologin_shell() {
  local candidate
  for candidate in /usr/sbin/nologin /sbin/nologin /bin/false; do
    [ -x "$candidate" ] && { printf '%s' "$candidate"; return 0; }
  done
  printf '/bin/false'
}

ensure_users_and_groups() {
  say "创建运行账号与用户组"

  if group_exists mailstack-admin; then
    info "组已存在：mailstack-admin"
  else
    groupadd --system mailstack-admin || die "创建组 mailstack-admin 失败"
    info "已创建组：mailstack-admin"
  fi
  if user_exists mailstack-admin; then
    info "用户已存在：mailstack-admin"
  else
    useradd --system --gid mailstack-admin --no-create-home \
      --home-dir /nonexistent --shell "$(nologin_shell)" mailstack-admin \
      || die "创建用户 mailstack-admin 失败"
    info "已创建用户：mailstack-admin（nologin，无家目录）"
  fi
  user_exists mailstack-admin || die "mailstack-admin 用户创建后校验失败"

  if group_exists mailstack-webmail; then
    info "组已存在：mailstack-webmail"
  else
    groupadd --system mailstack-webmail || die "创建组 mailstack-webmail 失败"
    info "已创建组：mailstack-webmail"
  fi

  if group_exists opendkim; then
    info "组已存在：opendkim"
  else
    groupadd --system opendkim || die "创建组 opendkim 失败"
    info "已创建组：opendkim"
  fi
}

create_directories() {
  say "创建目录与权限（幂等收敛）"
  install_dir "$ETC_DIR" 0750 root mailstack-admin
  install_dir "$ACCESS_DIR" 0750 root root
  install_dir "$VAR_LIB_DIR" 0750 root mailstack-webmail
  install_dir "$BACKUP_DIR" 0700 root root
  install_dir "$RUN_DIR" 0750 root mailstack-admin
  install_dir "$LIBEXEC_DIR" 0755 root root
  install_dir "$BIN_DIR" 0755 root root
  install_dir "$(prefix_path /usr/share/mailstack)" 0755 root root
  install_dir "$(prefix_path /etc/opendkim)" 0750 root opendkim
  install_dir "$(prefix_path /etc/opendkim/keys)" 0750 root opendkim
  if [ ! -d "$(prefix_path /etc/postfix)" ]; then
    install -d -m 0755 "$(prefix_path /etc/postfix)" || die "无法创建 $(prefix_path /etc/postfix)"
  fi
}

install_binaries() {
  say "安装 5 个二进制到 $BIN_DIR"
  local name
  for name in "${BIN_NAMES[@]}"; do
    put_file "$BIN_SRC_DIR/$name" "$BIN_DIR/$name" 0755 root root
    info "已安装：$BIN_DIR/$name"
  done
}

install_wrapper() {
  say "安装特权包装器与 sudoers 规则"
  local wrapper="$LIBEXEC_DIR/$WRAPPER_NAME"
  local wrapper_src
  wrapper_src="$(new_tmp)/$WRAPPER_NAME"
  local cfg_arg=""
  if [ -n "$PREFIX_NORM" ]; then
    cfg_arg=" --config-dir $PREFIX_NORM"
  fi
  cat > "$wrapper_src" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
exec $BIN_DIR/mailstackctl --privileged-stdin$cfg_arg
EOF
  chmod 0755 "$wrapper_src"
  put_file "$wrapper_src" "$wrapper" 0750 root root
  info "已安装：$wrapper（0750 root:root，--privileged-stdin，无 argv 转发）"

  grep -q -- 'exec .*mailstackctl --privileged-stdin' "$wrapper" \
    || die "包装器内容自检失败：没有 --privileged-stdin"
  if grep -qF -- 'exec' "$wrapper" && grep -qF '"$@"' "$wrapper"; then
    die "包装器内容自检失败：不允许转发 \"\$@\"（参数注入面 / 动作名缺失）"
  fi

  local sudoers="$ETC_DIR/sudoers.d/$SUDOERS_NAME"
  mkdir -p "$ETC_DIR/sudoers.d"
  chmod 0750 "$ETC_DIR/sudoers.d"
  local sudoers_src
  sudoers_src="$(new_tmp)/sudoers"
  cat > "$sudoers_src" <<EOF
# MailStack：唯一特权入口。只放行包装器本身（不接受参数通配符）。
# 由 deploy/install.sh 生成；修改后必须 visudo -cf 校验。
mailstack-admin ALL=(root) NOPASSWD: $wrapper
EOF
  chmod 0440 "$sudoers_src"
  if [ "$SUDOERS_VALIDATE" -eq 1 ]; then
    visudo -cf "$sudoers_src" >/dev/null 2>&1 || die "sudoers 语法校验失败（visudo -cf）：$sudoers_src"
    info "sudoers 语法校验通过（visudo -cf）"
  fi
  put_file "$sudoers_src" "$sudoers" 0440 root root
  info "已安装：$sudoers"

  if [ -n "$PREFIX_NORM" ]; then
    warn "staging 前缀模式：sudoers 写入 $sudoers，不会影响宿主 /etc/sudoers.d"
  fi
}

install_dist() {
  say "安装前端产物到 $DIST_DIR"
  if [ -z "$DIST_SRC_DIR" ]; then
    warn "没有可安装的前端产物：跳过（管理台/Webmail 页面 503，API 可用）"
    return 0
  fi
  local staging="${DIST_DIR}.new.$$"
  rm -rf -- "$staging"
  mkdir -p "$(dirname "$DIST_DIR")"
  cp -a "$DIST_SRC_DIR/." "$staging/" || die "复制前端产物失败：$DIST_SRC_DIR"
  chmod -R a+rX "$staging"
  chmod -R go-w "$staging"
  chmod 0755 "$staging"
  chown -R root:root "$staging" 2>/dev/null || warn "无法把前端产物 chown 到 root:root"
  safe_rm_rf "$DIST_DIR"
  mv -- "$staging" "$DIST_DIR" || die "替换前端产物目录失败：$DIST_DIR"
  info "已安装：$DIST_DIR（index.html=管理台，mail.html=Webmail，同一份 dist）"
}

render_unit() {
  local template="$1" dest="$2"
  local imap_cert_args="" imap_condition="" server_name="mailstack"
  if [ -n "$MAIL_HOST" ]; then
    server_name="$MAIL_HOST"
    local cert_dir="$ETC_DIR/tls/$MAIL_HOST"
    imap_cert_args=" --cert $cert_dir/fullchain.pem --key $cert_dir/privkey.pem"
    imap_condition="ConditionPathExists=$cert_dir/fullchain.pem"
  else
    imap_condition="# （未提供 --domain/--mail-host：证书路径未固化，本次不启用本 unit；请重跑 install.sh --domain <mail-host>）"
  fi
  sed -e "s|@BIN_DIR@|$BIN_DIR|g" \
      -e "s|@ETC_DIR@|$ETC_DIR|g" \
      -e "s|@DIST_DIR@|$DIST_DIR|g" \
      -e "s|@ADMIN_PORT@|$ADMIN_PORT|g" \
      -e "s|@WEBMAIL_PORT@|$WEBMAIL_PORT|g" \
      -e "s|@CONFIG_ARG@|$CONFIG_ROOT_ARG|g" \
      -e "s|@MAIL_HOST@|$server_name|g" \
      -e "s|@IMAP_CERT_ARGS@|$imap_cert_args|g" \
      -e "s|@IMAP_CONDITION_LINE@|$imap_condition|g" \
      "$template" > "$dest" || die "渲染 unit 失败：$template"
  chmod 0644 "$dest"
}

install_units() {
  say "渲染并安装 systemd unit 到 $UNIT_DIR"
  mkdir -p "$UNIT_DIR"
  local unit
  for unit in "${INSTALL_UNITS[@]}"; do
    local src="$UNIT_SRC_DIR/${unit}.service.in"
    local dst_tmp="$UNIT_DIR/${unit}.service.new.$$"
    render_unit "$src" "$dst_tmp"
    mv -f -- "$dst_tmp" "$UNIT_DIR/${unit}.service" || die "安装 unit 失败：$unit"
    info "已安装：$UNIT_DIR/${unit}.service"
  done

  if [ "$IMAP_ENABLE" -eq 0 ] && [ -f "$UNIT_DIR/mailstack-imap.service" ]; then
    if [ "$NO_SYSTEMD" -eq 0 ] && [ -z "$PREFIX_NORM" ] && [ -d /run/systemd/system ] \
       && command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now mailstack-imap >/dev/null 2>&1 || true
    fi
    rm -f -- "$UNIT_DIR/mailstack-imap.service"
    warn "已按要求移除 mailstack-imap.service（--imap no）"
  fi
}

install_manage_script() {
  say "安装服务器管理脚本：$BIN_DIR/$MANAGE_NAME"
  acquire_manage_script
  install_dir "$BIN_DIR" 0755 root root
  put_file "$MANAGE_SRC" "$BIN_DIR/$MANAGE_NAME" 0755 root root
  info "已安装：$BIN_DIR/$MANAGE_NAME（sudo $MANAGE_NAME 进入交互菜单）"
}

apply_identity() {
  IDENTITY_APPLIED=not-requested
  if [ -z "$DOMAIN" ]; then
    info "未提供 --domain：邮件身份留给管理台向导或 mailstack-manage domain set"
    return 0
  fi
  local mail_host="${MAIL_HOST:-mail.$DOMAIN}"
  say "应用邮件身份与 DKIM（$DOMAIN / $mail_host）"
  local ctl="$BIN_DIR/mailstackctl"
  local cfg=()
  [ -n "$PREFIX_NORM" ] && cfg=(--config-dir "$PREFIX_NORM")
  [ -x "$ctl" ] || { IDENTITY_APPLIED=failed; warn "mailstackctl 不可执行，跳过身份应用"; return 0; }

  if [ -z "${SERVER_IP:-}" ] && command -v ip >/dev/null 2>&1; then
    SERVER_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)"
  fi
  if [ -z "${SERVER_IP:-}" ]; then
    SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  if [ -z "${SERVER_IP:-}" ]; then
    IDENTITY_APPLIED=failed
    warn "无法自动探测服务器 IP：稍后 sudo mailstack-manage domain set $DOMAIN --server-ip <IP>"
    return 0
  fi
  local ip_part=",\"serverIp\":\"$SERVER_IP\""
  local payload
  payload="{\"action\":\"setup.identity.apply\",\"data\":{\"domain\":\"$DOMAIN\",\"mailHost\":\"$mail_host\",\"dkimSelector\":\"mail\"$ip_part}}"
  local out rc
  out="$(printf '%s' "$payload" | "$ctl" --privileged-stdin "${cfg[@]}" 2>&1)"
  rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q '"ok":true'; then
    IDENTITY_APPLIED=ok
    info "身份已写入：$ETC_DIR/setup.json（DKIM selector=mail）"
  else
    IDENTITY_APPLIED=failed
    warn "身份应用失败（可稍后 sudo mailstack-manage domain set $DOMAIN）：$out"
    return 0
  fi

  local domain_payload
  domain_payload="{\"action\":\"domains.add\",\"data\":{\"domain\":\"$DOMAIN\"}}"
  out="$(printf '%s' "$domain_payload" | "$ctl" --privileged-stdin "${cfg[@]}" 2>&1)"
  if printf '%s' "$out" | grep -q '"ok":true'; then
    info "邮件域名已写入域名表：$DOMAIN"
  else
    warn "域名表写入失败（可稍后 sudo mailstack-manage domain add $DOMAIN）：$out"
  fi
}

provision_access() {
  if [ "$NO_ACCESS_PROVISION" -eq 1 ]; then
    ACCESS_PROVISIONED=skipped
    info "按 --no-access-provision 跳过访问模式应用（之后可 sudo $MANAGE_NAME access set <mode>）"
    return 0
  fi

  local mode="${ACCESS_MODE:-ssh}"
  case "$mode" in
    local|loopback|tunnel) mode="ssh" ;;
    direct) mode="ip-acme" ;;
    caddy|nginx|ip-acme|panel-domain|cloudflared|ssh) : ;;
    *) mode="ssh" ;;
  esac

  say "应用访问模式：$mode"
  local mgr="$BIN_DIR/$MANAGE_NAME"
  if [ ! -x "$mgr" ]; then
    ACCESS_PROVISIONED=failed
    warn "管理脚本不可执行：$mgr（跳过访问模式应用）"
    return 0
  fi

  local args=(access set "$mode")
  [ -n "${PANEL_HOST:-}" ] && args+=(--panel-host "$PANEL_HOST")
  [ -n "${WEBMAIL_HOST:-}" ] && args+=(--webmail-host "$WEBMAIL_HOST")
  [ -n "${ACME_EMAIL:-}" ] && args+=(--acme-email "$ACME_EMAIL")
  [ -n "${SERVER_IP:-}" ] && args+=(--server-ip "$SERVER_IP")

  if MAILSTACK_PREFIX="$PREFIX_NORM" bash "$mgr" "${args[@]}"; then
    ACCESS_PROVISIONED=ok
    info "访问模式已应用：$mode"
  else
    ACCESS_PROVISIONED=failed
    warn "访问模式应用失败（可重跑：sudo $MANAGE_NAME access set $mode）"
  fi
}

write_deployment_state() {
  say "写入部署状态（$STATE_REL_PATH）"
  local conf="$ETC_DIR/install-args.conf"

  if [ -z "$DOMAIN" ]; then DOMAIN="$(state_get "$conf" DOMAIN || true)"; fi
  if [ -z "$MAIL_HOST" ]; then MAIL_HOST="$(state_get "$conf" MAIL_HOST || true)"; fi
  if [ -z "$PANEL_HOST" ]; then PANEL_HOST="$(state_get "$conf" PANEL_HOST || true)"; fi
  if [ -z "$WEBMAIL_HOST" ]; then WEBMAIL_HOST="$(state_get "$conf" WEBMAIL_HOST || true)"; fi
  if [ -z "$ACME_EMAIL" ]; then ACME_EMAIL="$(state_get "$conf" ACME_EMAIL || true)"; fi
  if [ -z "$SERVER_IP" ]; then SERVER_IP="$(state_get "$conf" SERVER_IP || true)"; fi
  if [ -z "$MAIL_HOST" ] && [ -n "$DOMAIN" ]; then MAIL_HOST="mail.$DOMAIN"; fi

  local detail="$ACCESS_MODE"
  local canonical
  canonical="$(canonical_access_mode "$detail")"
  if [ -z "$detail" ]; then
    detail="$(detail_mode_from_state)"
    [ -n "$detail" ] || detail="ssh"
    canonical="$(canonical_access_mode "$detail")"
  fi
  ACCESS_MODE="$detail"

  local panel_url="" webmail_url=""
  case "$detail" in
    ssh)
      panel_url="http://127.0.0.1:${ADMIN_PORT}/"
      webmail_url="http://127.0.0.1:${WEBMAIL_PORT}/"
      ;;
    *)
      [ -n "$PANEL_HOST" ] && panel_url="https://$PANEL_HOST/"
      [ -n "$WEBMAIL_HOST" ] && webmail_url="https://$WEBMAIL_HOST/"
      ;;
  esac

  mkdir -p "$ETC_DIR"
  local tmp="$conf.tmp.$$"
  {
    printf '# 由 deploy/install.sh / deploy/mailstack-manage.sh 写入；crates/core/src/mode.rs 读取 ACCESS_MODE 判定公网档\n'
    printf '# 合法 ACCESS_MODE：local | caddy | direct（缺失=local；非法/多值按 direct 从严处理）\n'
    printf '# 详细访问模式见 ACCESS_MODE_DETAIL；机器可读副本在 <etc>/access/access.env。\n'
    printf 'ACCESS_MODE=%q\n' "$canonical"
    printf 'ACCESS_MODE_DETAIL=%q\n' "$detail"
    printf 'MAILSTACK_VERSION=%q\n' "$MAILSTACK_VERSION"
    printf 'INSTALLED_AT=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'DOMAIN=%q\n' "${DOMAIN:-}"
    printf 'MAIL_HOST=%q\n' "${MAIL_HOST:-}"
    printf 'ADMIN_USER=%q\n' "$ADMIN_USER"
    printf 'ADMIN_PORT=%q\n' "$ADMIN_PORT"
    printf 'WEBMAIL_PORT=%q\n' "$WEBMAIL_PORT"
    printf 'PANEL_HOST=%q\n' "${PANEL_HOST:-}"
    printf 'PANEL_HOST_AUTO=%q\n' "$([ -n "$PANEL_HOST" ] && printf 0 || printf 1)"
    printf 'WEBMAIL_HOST=%q\n' "${WEBMAIL_HOST:-}"
    printf 'WEBMAIL_HOST_AUTO=%q\n' "$([ -n "$WEBMAIL_HOST" ] && printf 0 || printf 1)"
    printf 'PANEL_URL=%q\n' "$panel_url"
    printf 'WEBMAIL_URL=%q\n' "$webmail_url"
    printf 'ACME_EMAIL=%q\n' "${ACME_EMAIL:-}"
    printf 'SERVER_IP=%q\n' "${SERVER_IP:-}"
    printf 'IMAP_ENABLE=%q\n' "$IMAP_ENABLE"
  } > "$tmp"
  chmod 0600 "$tmp"
  chown root:root "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$conf" || die "写入 $conf 失败"
  info "ACCESS_MODE=$canonical（DETAIL=$detail；$conf，0600 root:root）"
  if [ -n "${PANEL_HOST:-}" ]; then
    info "面板主机：$PANEL_HOST → ${panel_url:-（未计算）}"
  fi
}

write_install_marker() {
  local marker="$ETC_DIR/.mailstack-installed"
  {
    printf 'MAILSTACK_VERSION=%s\n' "$MAILSTACK_VERSION"
    printf 'INSTALLED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'PREFIX=%s\n' "${PREFIX_NORM:-/}"
  } > "$marker.tmp.$$"
  chmod 0644 "$marker.tmp.$$"
  mv -f -- "$marker.tmp.$$" "$marker" || die "写入安装标记失败：$marker"
}

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

prompt_admin_password() {
  local first="" second=""
  printf '管理员口令（12-256 位，含字母与数字；留空则跳过引导）: ' >&2
  IFS= read -r -s first || first=""
  printf '\n' >&2
  if [ -z "$first" ]; then
    ADMIN_PASSWORD=""
    return 0
  fi
  printf '再次输入以确认: ' >&2
  IFS= read -r -s second || second=""
  printf '\n' >&2
  [ "$first" = "$second" ] || die "两次输入的管理员口令不一致"
  ADMIN_PASSWORD="$first"
  validate_options
}

bootstrap_admin() {
  say "管理员引导（经特权包装器，stdin JSON）"
  local cfg="$ETC_DIR/admin.json"
  local wrapper="$LIBEXEC_DIR/$WRAPPER_NAME"

  if [ -s "$cfg" ]; then
    info "管理员凭证已存在：$cfg —— 跳过引导（幂等，不重置既有凭证）"
    ADMIN_BOOTSTRAP="kept"
    return 0
  fi

  if [ -z "$ADMIN_PASSWORD" ] && [ "$NON_INTERACTIVE" -eq 0 ] && [ -t 0 ]; then
    prompt_admin_password
  fi
  if [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_BOOTSTRAP="skipped"
    warn "未提供管理员口令：跳过引导（安装完成后手工创建，命令见下）"
    info "  printf '%s' '{\"action\":\"admin.set\",\"data\":{\"username\":\"$ADMIN_USER\",\"password\":\"<口令>\"}}' | sudo $wrapper"
    info "  或直接打开管理台完成向导：http://127.0.0.1:${ADMIN_PORT}/?login=1"
    return 0
  fi

  local json
  json="$(printf '{"action":"admin.set","data":{"username":"%s","password":"%s"}}' \
    "$(json_escape "$ADMIN_USER")" "$(json_escape "$ADMIN_PASSWORD")")"

  local out="" rc=0
  if [ -n "$SUDO_CMD" ]; then
    out="$(printf '%s' "$json" | "$SUDO_CMD" "$wrapper" 2>&1)" || rc=$?
  else
    out="$(printf '%s' "$json" | "$wrapper" 2>&1)" || rc=$?
  fi
  json=""  # 尽快丢弃含口令的中间量
  ADMIN_PASSWORD=""

  if [ "$rc" -ne 0 ]; then
    if [ -n "$PREFIX_NORM" ]; then
      warn "staging 前缀：包装器调用返回 $rc（stub/旁路二进制属预期）；响应：$(printf '%s' "$out" | head -3)"
      ADMIN_BOOTSTRAP="unverified"
      return 0
    fi
    die "管理员引导失败（包装器退出码 $rc）：$(printf '%s' "$out" | head -5)"
  fi

  case "$out" in
    *'"ok":true'*|*'"ok": true'*)
      ADMIN_BOOTSTRAP="ok"
      info "管理员已创建：$cfg（0640 root:mailstack-admin，口令不落盘明文）" ;;
    *)
      if [ -s "$cfg" ]; then
        ADMIN_BOOTSTRAP="ok"
        info "管理员凭证已落盘：$cfg"
      elif [ -n "$PREFIX_NORM" ]; then
        ADMIN_BOOTSTRAP="unverified"
        warn "staging 前缀：无法从响应确认 ok:true（stub/旁路二进制属预期）：$(printf '%s' "$out" | head -3)"
      else
        die "管理员引导失败：包装器响应既不是 ok:true，也没有生成 $cfg。响应：$(printf '%s' "$out" | head -5)"
      fi ;;
  esac
}

print_manual_start_commands() {
  say "手工启动命令"
  local units="${INSTALL_UNITS[*]}"
  printf '    systemctl daemon-reload\n'
  printf '    systemctl enable --now %s\n' "$units"
  printf '    systemctl status %s\n' "$units"
  printf '    # 前台排查示例：%s/mailstackd --port 25 --port 465 --port 587\n' "$BIN_DIR"
}

services_start() {
  say "systemd 服务"
  if [ "$NO_SYSTEMD" -eq 1 ]; then
    info "--no-systemd：unit 已写入，未 enable/start"
    print_manual_start_commands
    return 0
  fi
  if [ -n "$PREFIX_NORM" ]; then
    warn "非根前缀：unit 写入 $UNIT_DIR，但不会操作宿主 systemd"
    print_manual_start_commands
    return 0
  fi
  if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
    warn "未检测到运行中的 systemd：跳过 enable/start（unit 已写入）"
    print_manual_start_commands
    return 0
  fi

  systemctl daemon-reload || die "systemctl daemon-reload 失败"
  local unit
  for unit in "${INSTALL_UNITS[@]}"; do
    if systemctl enable "$unit" >/dev/null 2>&1; then
      info "已 enable：$unit"
    else
      warn "systemctl enable $unit 失败（稍后手工处理）"
    fi
  done

  for unit in mailstackd mailstack-web mailstack-webmail; do
    if systemctl restart "$unit" >/dev/null 2>&1; then
      info "已重启：$unit"
    else
      warn "systemctl restart $unit 失败（journalctl -u $unit 查看）"
    fi
  done
  if [ "$IMAP_ENABLE" -eq 1 ]; then
    if [ -z "$MAIL_HOST" ]; then
      warn "IMAP unit 已写入但未启用：缺少 --domain/--mail-host，证书路径无法确定"
    else
      systemctl restart mailstack-imap >/dev/null 2>&1 || warn "systemctl restart mailstack-imap 失败（journalctl -u mailstack-imap 查看）"
      info "已尝试启动：mailstack-imap（证书未就绪时会被 ConditionPathExists 跳过）"
    fi
  fi

  for unit in "${INSTALL_UNITS[@]}"; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      info "状态：$unit = active"
    else
      if [ "$unit" = "mailstackd" ] && [ ! -s "$ETC_DIR/setup.json" ]; then
        info "状态：$unit = inactive（预期：尚未完成身份向导；向导完成后: systemctl restart mailstackd）"
      elif [ "$unit" = "mailstack-imap" ] && [ ! -s "$ETC_DIR/tls/${MAIL_HOST:-_}/fullchain.pem" ] 2>/dev/null; then
        info "状态：$unit = inactive（预期：证书尚未就绪；就绪后: systemctl start mailstack-imap）"
      else
        warn "状态：$unit = inactive（journalctl -u $unit 查看原因）"
      fi
    fi
  done
}

adopt_uninstaller() {
  if [ -n "$INSTALL_UNINSTALL_SRC" ] && [ -f "$INSTALL_UNINSTALL_SRC" ]; then
    put_file "$INSTALL_UNINSTALL_SRC" "$LIBEXEC_DIR/mailstack-uninstall" 0755 root root
    info "已安装卸载脚本：$LIBEXEC_DIR/mailstack-uninstall"
  else
    info "发布包内没有卸载脚本：卸载请使用仓库的 deploy/uninstall.sh"
  fi
}

print_summary() {
  say "安装完成（MailStack v${MAILSTACK_VERSION}）"
  printf '    版本:        %s（target %s）\n' "$MAILSTACK_VERSION" "$TARGET_TRIPLE"
  printf '    安装前缀:    %s\n' "${PREFIX_NORM:-/}"
  printf '    二进制:      %s/mailstackd, mailstackctl, mailstack-web, mailstack-imap, mailstack-webmail\n' "$BIN_DIR"
  printf '    管理台:      http://127.0.0.1:%s/?login=1\n' "$ADMIN_PORT"
  printf '    Webmail:     http://127.0.0.1:%s/\n' "$WEBMAIL_PORT"
  printf '    配置目录:    %s\n' "$ETC_DIR"
  printf '    数据目录:    %s\n' "$VAR_LIB_DIR"
  printf '    部署模式:    ACCESS_MODE=%s\n' "${ACCESS_MODE:-local}"
  case "$ADMIN_BOOTSTRAP" in
    ok)         printf '    管理员:      %s（凭证已写入 %s/admin.json）\n' "$ADMIN_USER" "$ETC_DIR" ;;
    kept)       printf '    管理员:      既有凭证保留（%s/admin.json）\n' "$ETC_DIR" ;;
    skipped)    printf '    管理员:      未引导（安装后手工创建或走管理台向导）\n' ;;
    unverified) printf '    管理员:      staging 模式未验证写入（stub 二进制属预期）\n' ;;
  esac
  echo
  echo '    后续步骤:'
  echo "      1) 浏览器打开 http://127.0.0.1:${ADMIN_PORT}/?login=1 登录管理台；"
  echo '         若管理员尚未引导，请用上面打印的 admin.set 命令创建（或重跑本脚本加 --admin-password-stdin）。'
  echo '      2) 在管理台初始化向导中填写域名 / DKIM / DNS（本脚本不猜身份）。'
  echo "      3) 向导完成后: systemctl restart mailstackd（首次安装时 daemon 会等待 setup.json）。"
  echo "      4) IMAP 证书就绪后: systemctl start mailstack-imap。"
  echo
  echo '    安装结果核对（mode owner:group path）:'
  local f
  for f in "$BIN_DIR/mailstackd" "$LIBEXEC_DIR/$WRAPPER_NAME" "$ETC_DIR/sudoers.d/$SUDOERS_NAME" \
           "$ETC_DIR" "$VAR_LIB_DIR" "$BACKUP_DIR" "$DIST_DIR"; do
    if [ -e "$f" ]; then
      stat -c '    %a %U:%G %n' "$f"
    else
      printf '    (missing) %s\n' "$f"
    fi
  done
  local unit
  for unit in "${INSTALL_UNITS[@]}"; do
    if [ -f "$UNIT_DIR/${unit}.service" ]; then
      stat -c '    %a %U:%G %n' "$UNIT_DIR/${unit}.service"
    fi
  done
  echo
  echo "    卸载: bash deploy/uninstall.sh${PREFIX_NORM:+ --prefix $PREFIX_NORM}"
  echo "          默认保留 $ETC_DIR 与 $VAR_LIB_DIR（--purge 才删除）。"
}

run_uninstaller() {
  local args=(--non-interactive)
  [ -n "$PREFIX_NORM" ] && args+=(--prefix "$PREFIX_NORM")
  [ "$PURGE" -eq 1 ] && args+=(--purge)

  local candidate=""
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/uninstall.sh" ]; then
    candidate="$SCRIPT_DIR/uninstall.sh"
  elif [ -n "$CHECKOUT_ROOT" ] && [ -f "$CHECKOUT_ROOT/deploy/uninstall.sh" ]; then
    candidate="$CHECKOUT_ROOT/deploy/uninstall.sh"
  fi

  if [ -n "$candidate" ]; then
    say "转交卸载脚本：$candidate"
    exec bash "$candidate" "${args[@]}"
  fi

  local dl
  dl="$(new_tmp)"
  download "https://raw.githubusercontent.com/${REPO_SLUG}/${RAW_BRANCH}/deploy/uninstall.sh" "$dl/uninstall.sh"
  say "转交下载的卸载脚本（${RAW_BRANCH} 分支）"
  exec bash "$dl/uninstall.sh" "${args[@]}"
}

main() {
  if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
    if [ -f "$SCRIPT_DIR/../Cargo.toml" ] && [ -d "$SCRIPT_DIR/../deploy" ]; then
      CHECKOUT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    fi
  fi

  if [ -z "$SCRIPT_PATH" ] || [ ! -f "$SCRIPT_PATH" ]; then
    STDIN_IS_SCRIPT=1
  fi

  parse_args "$@"
  normalize_prefix
  validate_options
  derive_paths

  if [ "$UNINSTALL" -eq 1 ]; then
    run_uninstaller   # exec 后不会返回
  fi

  check_environment

  case "$MODE" in
    release)    acquire_release ;;
    archive)    acquire_archive ;;
    binary-dir) acquire_binary_dir ;;
    source)     acquire_source ;;
    *) die "内部错误：未知安装模式 $MODE" ;;
  esac

  validate_artifacts

  ensure_users_and_groups
  create_directories
  install_binaries
  install_wrapper
  install_manage_script
  install_dist
  write_deployment_state
  write_install_marker
  install_units
  adopt_uninstaller
  bootstrap_admin
  apply_identity
  provision_access
  services_start
  print_summary
}

main "$@"

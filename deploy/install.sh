#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  if command -v bash >/dev/null 2>&1; then
    exec bash "$0" "$@"
  else
    echo "Error: bash is required to run install.sh" >&2
    exit 1
  fi
fi
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo '请使用 root 运行'; exit 1; }
BASE=$(cd "$(dirname "$0")/.." && pwd)
ADMIN_USER='admin'; ADMIN_PASS=''; ADMIN_PORT='8787'; ADMIN_HOST='127.0.0.1'; WEBMAIL_PORT='18788'; WEBMAIL_HOST='127.0.0.1'; NONINTERACTIVE=0; REUSE_ADMIN=0
ACCESS_MODE=''
MAIL_DOMAIN=''
WEBMAIL_DOMAIN=''
ADMIN_EMAIL=''
I_UNDERSTAND_PLAIN_HTTP=0
I_HAVE_EXTERNAL_TLS=0
HTTPS_MODE=0
MIN_NODE_MAJOR=20
MAX_NODE_MAJOR=24

# 辅助函数必须先于参数解析定义：--admin-password-stdin 在解析阶段就可能调用
# fail()，此前定义在使用之后，EOF 错误路径会以 "fail: command not found" 崩溃
# 而不是给出设计好的报错（rc.3 审计发现，与当年 warn() 未定义是同一类缺陷）。
say(){ printf '\n==> %s\n' "$*"; }
fail(){ printf '\n安装失败: %s\n日志: /var/log/mailstack-install.log\n' "$*" >&2; exit 1; }
warn(){ printf '\n⚠️  %s\n' "$*" >&2; }
# ERR trap 用命名函数实现：内联字符串中 `rc=$?` 的赋值不被 shellcheck 追踪，
# 会误报 SC2154（变量未赋值）；函数写法语义等价且通过 shellcheck -S warning。
_on_err(){ local rc=$?; echo "安装失败于第 ${BASH_LINENO[1]} 行，退出码 $rc"; }
trap _on_err ERR

# 跨脚本降级汇总：install-mail-stack.sh 以子进程运行（下方 bash 调用），其降级项经
# MAILSTACK_DEGRADED_LOG 临时文件回传，由本脚本结尾统一输出「降级组件清单」（子脚本
# 检测到该变量已设时会抑制自身重复打印）。set -e 安全：写入以 || true 兜底，EXIT trap 清理。
MAILSTACK_DEGRADED_LOG=$(mktemp "${TMPDIR:-/tmp}/mailstack-degraded.XXXXXX")
export MAILSTACK_DEGRADED_LOG
DEGRADED_ITEMS=()
mark_degraded(){ DEGRADED_ITEMS+=("$*"); }
_cleanup_degraded(){ rm -f "$MAILSTACK_DEGRADED_LOG" 2>/dev/null || true; }
trap _cleanup_degraded EXIT
print_degradation_summary(){
  local _items=() _line _n=0
  # 先汇入子脚本（install-mail-stack.sh）经临时文件回传的降级项（发生在前）
  if [[ -s $MAILSTACK_DEGRADED_LOG ]]; then
    while IFS= read -r _line; do
      if [[ -n $_line ]]; then _items+=("$_line"); fi
    done <"$MAILSTACK_DEGRADED_LOG"
  fi
  # 再并入本脚本自身登记的降级项（Node/Caddy 层）
  if ((${#DEGRADED_ITEMS[@]})); then _items+=("${DEGRADED_ITEMS[@]}"); fi
  say '降级组件清单'
  if ((${#_items[@]} == 0)); then
    echo '  无降级，全部组件就位。'
    return 0
  fi
  for _line in "${_items[@]}"; do _n=$((_n+1)); printf '  %d) %s\n' "$_n" "$_line"; done
  echo '  （以上为安装期按设计降级的组件；核心邮件收发不受影响，ms doctor 会持续报告其状态）'
}

# 新口令密码策略（rc.5）：12-256 位，且必须同时含字母与数字。
# 完整策略（禁 3+ 相同/连续字符、禁含用户名/邮箱等身份 token、禁控制字符）
# 由 backend/mailstackctl/core.py 的 validate_mailbox_password 权威执行；
# shell 侧仅做长度与字符类前置检查，尽早给用户清晰报错。
# --reuse-admin 复用既有凭证，不经此校验（新规只约束新设置的口令）。
validate_admin_password(){
  local pass=$1
  [[ ${#pass} -ge 12 && ${#pass} -le 256 ]] || return 1
  [[ $pass =~ [A-Za-z] ]] || return 1
  [[ $pass =~ [0-9] ]] || return 1
  return 0
}

usage(){ cat <<EOF
用法: $0 [选项]
  --access-mode local|caddy|direct|plain  访问模式 (推荐 caddy 或 local)
  --domain DOMAIN                        管理后台/主邮件域名 (如 mail.example.com)
  --webmail-domain DOMAIN                Webmail 域名 (如 webmail.example.com)
  --email EMAIL                          管理员证书通知邮箱 (如 ops@example.com)
  --i-understand-plain-http              非交互模式下确认使用明文公网 HTTP (仅 plain 模式必填)
  --i-have-external-tls                  direct 模式确认 TLS 由本机尚未就绪的外部反代/另一主机终结 (跳过证书证据探测)
  --admin-user NAME                      管理员用户名 (默认 admin)
  --admin-port PORT                      管理后台内部端口 (默认 8787)
  --admin-host HOST                      管理后台监听地址 (默认 127.0.0.1)
  --webmail-port PORT                    Webmail 内部端口 (默认 18788)
  --webmail-host HOST                    Webmail 监听地址 (默认 127.0.0.1)
  --admin-password-stdin                 通过标准输入读取管理员密码
  --non-interactive                      非交互静默安装
  --reuse-admin                          复用已有管理员凭证
  --https                                强制安全 Cookie 标记
EOF
}

while (($#)); do case $1 in
  --access-mode) ACCESS_MODE=$2;shift 2;;
  --domain) MAIL_DOMAIN=$2;shift 2;;
  --webmail-domain) WEBMAIL_DOMAIN=$2;shift 2;;
  --email) ADMIN_EMAIL=$2;shift 2;;
  --i-understand-plain-http) I_UNDERSTAND_PLAIN_HTTP=1;shift;;
  --i-have-external-tls) I_HAVE_EXTERNAL_TLS=1;shift;;
  --admin-user) ADMIN_USER=$2;shift 2;;
  --admin-port) ADMIN_PORT=$2;shift 2;;
  --admin-host) ADMIN_HOST=$2;shift 2;;
  --webmail-port) WEBMAIL_PORT=$2;shift 2;;
  --webmail-host) WEBMAIL_HOST=$2;shift 2;;
  --admin-password-stdin) IFS= read -r ADMIN_PASS || fail '未能从标准输入读取管理员密码 (--admin-password-stdin)';shift;;
  --non-interactive) NONINTERACTIVE=1;shift;;
  --reuse-admin) REUSE_ADMIN=1;NONINTERACTIVE=1;shift;;
  --https) HTTPS_MODE=1;shift;;
  -h|--help) usage;exit 0;;
  *) echo "未知参数: $1";usage;exit 1;;
esac; done

# 注入面校验：域名与证书邮箱最终会被原样写入 Caddyfile（caddy 以其为准签发
# 证书并反代到内部端口）。一个带换行的「域名」可以向 Caddyfile 注入任意指令块
# （如 reverse_proxy 到攻击者地址），所以校验必须早于任何副作用（装包、写文件）。
# bash =~ 的 ERE 语义与后端 Python 的 DOMAIN_RE 保持一致。
DOMAIN_RE='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
EMAIL_RE='^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$'
if [[ -n "$MAIL_DOMAIN" && ! "$MAIL_DOMAIN" =~ $DOMAIN_RE ]]; then
  fail "非法域名: '${MAIL_DOMAIN}'"
fi
if [[ -n "$WEBMAIL_DOMAIN" && ! "$WEBMAIL_DOMAIN" =~ $DOMAIN_RE ]]; then
  fail "非法 Webmail 域名: '${WEBMAIL_DOMAIN}'"
fi
if [[ -n "$ADMIN_EMAIL" && ! "$ADMIN_EMAIL" =~ $EMAIL_RE ]]; then
  fail "非法证书通知邮箱: '${ADMIN_EMAIL}'"
fi


say '安装和验证完整邮件基础栈'
bash "$BASE/deploy/install-mail-stack.sh"

# Python ≥3.10 硬门槛：后端 mailstackctl 广泛使用 PEP 604 联合类型（X | None），
# 低于 3.10 时特权 helper 在 import 阶段即崩，全部 RPC 静默失败（rc.5 OracleLinux 9
# 默认 python3=3.9 实测）。install-mail-stack.sh 已在 dnf 分支尽力升级；仍不达标时
# 明确失败，避免装出一个管理接口看似健康、提权通道全坏的栈。
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
  fail "Python 版本不满足要求：需 >=3.10（当前 $(python3 -V 2>&1 || echo 未安装)），后端使用 PEP 604 语法"
fi

# 供应链硬门：安装器以 root 运行，绝不执行任何「下载即跑」的第三方脚本。
# 规则：要么用发行版包管理器（自带签名校验），要么下载后与钉死的
# SHA256 / GPG 指纹比对，对不上即失败。把哈希打进日志再 bash 是取证，不是控制。
verify_sha256(){
  # $1=文件 $2=期望哈希(小写hex)。比对失败返回非零。
  local got
  got=$(sha256sum "$1" | awk '{print $1}')
  [[ "$got" == "$2" ]]
}

say '检查 Node.js 运行时 (要求 Node 20-24 LTS)'
is_node_valid(){
  command -v node >/dev/null 2>&1 || return 1
  local major
  major=$(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)
  (( major >= MIN_NODE_MAJOR && major <= MAX_NODE_MAJOR ))
}

# Node 22 LTS 官方预编译包（nodejs.org 发布，哈希钉死；版本不可变，永不漂移）。
NODE_PINNED_VERSION='22.20.0'
NODE_SHA256_X64='00bbd05e306ea68b6e13e17360d0e2f680b493ef95f2fea1c4296ff7437530bc'
NODE_SHA256_ARM64='06907b9c088ce62305bc1530e5c1ae1510245114645768f7750c349c5b6fe667'
# musl 系统（Alpine 等）兜底：nodejs.org 官方构建链接 glibc，在 musl 上无法运行。
# musl 变体来自 Node 官方 unofficial-builds 渠道（https://unofficial-builds.nodejs.org），
# 哈希取自该渠道同版本目录下的 SHASUMS256.txt（v22.20.0 x64-musl；该渠道目前不提供
# arm64-musl 构建，musl+arm64 只能依赖发行版仓库包）。
NODE_SHA256_X64_MUSL='119817f0a2cb86e9b8f058a9fc0a9fcb1b56a8a6da7c6ebef64398328ee52d82'

detect_libc(){
  # musl 判定：ldd 自报 musl，或存在 /lib/ld-musl-* 动态链接器（Alpine 上
  # busybox 的 ldd 不一定输出版本信息，两条都查）。
  if ldd --version 2>&1 | grep -qi musl; then
    echo musl
  elif ls /lib/ld-musl-* >/dev/null 2>&1; then
    echo musl
  else
    echo glibc
  fi
}

install_node_pinned_tarball(){
  local arch tarball url expected tmp libc
  libc=$(detect_libc)
  case "$(uname -m)" in
    x86_64|amd64)
      arch='x64'
      if [[ "$libc" == "musl" ]]; then expected="$NODE_SHA256_X64_MUSL"; else expected="$NODE_SHA256_X64"; fi
      ;;
    aarch64|arm64) arch='arm64'; expected="$NODE_SHA256_ARM64";;
    *) return 1;;
  esac
  if [[ "$libc" == "musl" ]]; then
    if [[ "$arch" != "x64" ]]; then
      warn "musl 系统暂无钉死的 ${arch} Node 构建（unofficial-builds 仅提供 x64-musl），请改用发行版仓库安装 nodejs"
      return 1
    fi
    tarball="node-v${NODE_PINNED_VERSION}-linux-x64-musl.tar.xz"
    url="https://unofficial-builds.nodejs.org/download/release/v${NODE_PINNED_VERSION}/${tarball}"
    # unofficial-builds 的 musl 构建在 Alpine 上运行需要 libstdc++（基础镜像默认不装）
    command -v apk >/dev/null 2>&1 && apk add --no-cache libstdc++ 2>/dev/null || true
  else
    tarball="node-v${NODE_PINNED_VERSION}-linux-${arch}.tar.xz"
    url="https://nodejs.org/dist/v${NODE_PINNED_VERSION}/${tarball}"
  fi
  # 官方包为 .tar.xz：精简镜像（如 Debian 13 最小安装）常缺 xz 解码器，
  # 缺它时 tar -xJ 直接失败。按包管理器从发行版仓库补齐（签名由仓库校验）。
  if ! command -v xz >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y xz-utils 2>/dev/null || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y xz 2>/dev/null || true
    elif command -v yum >/dev/null 2>&1; then
      yum install -y xz 2>/dev/null || true
    elif command -v zypper >/dev/null 2>&1; then
      zypper --non-interactive install -y xz 2>/dev/null || true
    elif command -v pacman >/dev/null 2>&1; then
      pacman -Sy --noconfirm --needed xz 2>/dev/null || true
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache xz 2>/dev/null || true
    fi
  fi
  if ! command -v xz >/dev/null 2>&1; then
    warn '缺少 xz 解码器且自动安装失败，无法解压 Node.js 官方包 (.tar.xz)'
    return 1
  fi
  tmp=$(mktemp /tmp/mailstack-node.XXXXXX)
  say "下载 Node.js v${NODE_PINNED_VERSION} (${libc}, ${arch}) 官方包并校验 SHA256..."
  if ! curl -fsSL "$url" -o "$tmp"; then
    rm -f "$tmp"; return 1
  fi
  if ! verify_sha256 "$tmp" "$expected"; then
    warn "Node.js 官方包 SHA256 校验失败（期望 $expected，实际 $(sha256sum "$tmp" | awk '{print $1}')），拒绝安装"
    rm -f "$tmp"; return 1
  fi
  rm -rf "/opt/node-v${NODE_PINNED_VERSION}"
  mkdir -p "/opt/node-v${NODE_PINNED_VERSION}"
  if ! tar -xJf "$tmp" -C "/opt/node-v${NODE_PINNED_VERSION}" --strip-components=1; then
    rm -f "$tmp"; return 1
  fi
  rm -f "$tmp"
  ln -sfn "/opt/node-v${NODE_PINNED_VERSION}/bin/node" /usr/local/bin/node
  ln -sfn "/opt/node-v${NODE_PINNED_VERSION}/bin/npm" /usr/local/bin/npm
  ln -sfn "/opt/node-v${NODE_PINNED_VERSION}/bin/npx" /usr/local/bin/npx
  is_node_valid
}

install_node(){
  # 优先发行版包（自带仓库签名）；版本不够时退回钉死哈希的官方包。
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y nodejs npm 2>/dev/null || apt-get install -y nodejs 2>/dev/null || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nodejs npm 2>/dev/null || dnf install -y nodejs 2>/dev/null || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y nodejs npm 2>/dev/null || yum install -y nodejs 2>/dev/null || true
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install -y nodejs22 npm22 2>/dev/null || zypper --non-interactive install -y nodejs20 npm20 2>/dev/null || zypper --non-interactive install -y nodejs npm 2>/dev/null || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed --overwrite '*' nodejs npm 2>/dev/null || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache nodejs npm 2>/dev/null || true
  fi
  is_node_valid && return 0
  install_node_pinned_tarball
}

if ! is_node_valid; then
  say '当前环境缺少匹配的 Node.js (需要 Node.js 20-24)，正在安装...'
  install_node || true
  is_node_valid || fail "Node.js 版本不符合要求 (需要 Node.js 20-24 LTS，当前版本: $(node -v 2>/dev/null || echo '未安装'))"
fi

for c in node python3 sudo rsync tar; do command -v "$c" >/dev/null || fail "缺少核心命令: $c"; done

# 访问模式交互式选择与校验
if [[ -z "$ACCESS_MODE" ]]; then
  if ((NONINTERACTIVE)); then
    if [[ -n "$MAIL_DOMAIN" ]]; then ACCESS_MODE="caddy"; else ACCESS_MODE="local"; fi
  else
    echo ""
    echo "================================================================"
    echo "  MailStack 访问与安全网络架构选择 (Access & Network Topology)  "
    echo "================================================================"
    echo "  [1] local  - 本地回环安全模式 (127.0.0.1, 通过 SSH 隧道或 VPN 访问, 推荐安全基线)"
    echo "  [2] caddy  - Caddy 自动反向代理与 HTTPS 证书 (推荐公网生产部署)"
    echo "  [3] direct - 主机直通模式 (127.0.0.1 + 已有反代/ACME 证书)"
    echo "  [4] plain  - 公网明文 HTTP (0.0.0.0 裸监听, 极高风险, 仅限内网隔离测试)"
    echo "================================================================"
    read -r -p "请选择访问模式 [1-4, 默认 1]: " mode_choice
    case "${mode_choice:-1}" in
      1|local) ACCESS_MODE="local" ;;
      2|caddy) ACCESS_MODE="caddy" ;;
      3|direct) ACCESS_MODE="direct" ;;
      4|plain) ACCESS_MODE="plain" ;;
      *) ACCESS_MODE="local" ;;
    esac
  fi
fi

# direct 模式的 TLS 证据探测：显式外部终结旗标、已有 ACME 证书、或 443 上的反代监听，
# 任一即算“已有证书”。供 A5「禁止 direct + 无证书」硬门调用。
_direct_tls_present(){
  [[ "${I_HAVE_EXTERNAL_TLS:-0}" == "1" ]] && return 0
  local c
  for c in /etc/letsencrypt/live/*/fullchain.pem; do
    [[ -f "$c" ]] && return 0
  done
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -qE ':443[[:space:]]' && return 0
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | grep -qE ':443[[:space:]]' && return 0
  fi
  return 1
}

case "$ACCESS_MODE" in
  local)
    ADMIN_HOST="127.0.0.1"
    WEBMAIL_HOST="127.0.0.1"
    ADMIN_PORT="${ADMIN_PORT:-8787}"
    HTTPS_MODE=0
    ;;
  caddy)
    ADMIN_HOST="127.0.0.1"
    WEBMAIL_HOST="127.0.0.1"
    ADMIN_PORT="${ADMIN_PORT:-8787}"
    HTTPS_MODE=1
    if [[ -z "$MAIL_DOMAIN" && $NONINTERACTIVE -eq 0 ]]; then
      read -r -p "请输入管理后台域名 (如 mail.example.com): " MAIL_DOMAIN
      read -r -p "请输入 Webmail 域名 (如 webmail.example.com, 回车同主域名): " WEBMAIL_DOMAIN
      WEBMAIL_DOMAIN=${WEBMAIL_DOMAIN:-$MAIL_DOMAIN}
      read -r -p "请输入 Let's Encrypt 证书申请邮箱 (如 admin@example.com): " ADMIN_EMAIL
    fi
    [[ -n "$MAIL_DOMAIN" ]] || fail 'caddy 模式必须提供 --domain <域名>'
    WEBMAIL_DOMAIN=${WEBMAIL_DOMAIN:-$MAIL_DOMAIN}
    ;;
  direct)
    ADMIN_HOST="127.0.0.1"
    WEBMAIL_HOST="127.0.0.1"
    ADMIN_PORT="${ADMIN_PORT:-8787}"
    HTTPS_MODE=1
    # A5：禁止「direct + 无证书」。direct 语义是面板绑 127.0.0.1，由前置反代/ACME 证书
    # 终结 TLS 后对外。若本机检测不到任何 TLS 证据（443 监听或 letsencrypt 证书）且未显式
    # 声明外部终结，则拒绝安装——否则 COOKIE_SECURE=1 却没有 HTTPS，等于自欺（plain 本就该死，
    # direct 无证书同样不该活）。
    if ! _direct_tls_present; then
      fail 'direct 模式要求本机已有 TLS 终结（前置反代监听 443，或 /etc/letsencrypt 下的 ACME 证书）。未检测到任何证书证据，已拒绝安装（禁止 direct + 无证书）。若 TLS 由安装时尚未就绪的外部反代/另一主机终结，请显式追加 --i-have-external-tls 确认。'
    fi
    ;;
  plain)
    ADMIN_HOST="0.0.0.0"
    WEBMAIL_HOST="0.0.0.0"
    ADMIN_PORT="${ADMIN_PORT:-8787}"
    HTTPS_MODE=0
    if ((NONINTERACTIVE)) && ((I_UNDERSTAND_PLAIN_HTTP == 0)); then
      fail '公网明文 plain 模式具有严重会话窃听风险。在非交互模式下必须显式传入 --i-understand-plain-http 参数确认'
    fi
    if [[ $NONINTERACTIVE -eq 0 ]]; then
      echo ""
      echo "⚠️  [严重安全警告] 你已选择 plain (0.0.0.0 公网明文) 模式！"
      echo "   管理员密码、会话 Cookie 及邮件通信将以明文在公网传输，极易遭中间人监听或重放劫持。"
      read -r -p "你确定要以明文公网模式继续吗？(输入 yes 确认): " confirm_plain
      [[ "$confirm_plain" == "yes" ]] || fail '用户已取消非安全的明文模式安装'
    fi
    ;;
  *)
    fail "不支持的访问模式: $ACCESS_MODE (可选: local, caddy, direct, plain)"
    ;;
esac

# 交互式补录的域名/邮箱同样过白名单（命令行传入的已在参数解析后校验）。
if [[ "$ACCESS_MODE" == "caddy" ]]; then
  [[ "$MAIL_DOMAIN" =~ $DOMAIN_RE ]] || fail "非法管理后台域名: '${MAIL_DOMAIN}'"
  [[ "$WEBMAIL_DOMAIN" =~ $DOMAIN_RE ]] || fail "非法 Webmail 域名: '${WEBMAIL_DOMAIN}'"
  if [[ -n "$ADMIN_EMAIL" ]]; then
    [[ "$ADMIN_EMAIL" =~ $EMAIL_RE ]] || fail "非法证书通知邮箱: '${ADMIN_EMAIL}'"
  fi
fi

if ((REUSE_ADMIN)); then
 [[ -s /etc/mailstack/admin.json ]] || fail '没有可复用的管理员配置'
 if [[ -f /etc/systemd/system/mailstack-web.service ]]; then
  ADMIN_PORT=$(sed -n 's/^Environment=PORT=//p' /etc/systemd/system/mailstack-web.service | tail -n1); ADMIN_PORT=${ADMIN_PORT:-8787}
  ADMIN_HOST=$(sed -n 's/^Environment=HOST=//p' /etc/systemd/system/mailstack-web.service | tail -n1); ADMIN_HOST=${ADMIN_HOST:-127.0.0.1}
 fi
else
  if [[ -z $ADMIN_PASS && $NONINTERACTIVE -eq 0 ]]; then
   read -r -p "管理员用户名 [$ADMIN_USER]: " x; ADMIN_USER=${x:-$ADMIN_USER}
   read -r -p "管理内部端口 [$ADMIN_PORT]: " x; ADMIN_PORT=${x:-$ADMIN_PORT}
   while :; do
    read -r -s -p '管理员密码（12-256 位，须同时含字母与数字）: ' ADMIN_PASS; echo
    read -r -s -p '再次输入密码: ' p2; echo
    [[ $ADMIN_PASS == "$p2" ]] && validate_admin_password "$ADMIN_PASS" && break
    echo '密码不一致，或不满足策略（12-256 位，须同时含字母与数字）。'
   done
  fi
  # 交互与 --admin-password-stdin 两条路径共用同一校验；失败即退出。
  validate_admin_password "$ADMIN_PASS" || fail '管理员密码不满足策略：须为 12-256 位且同时包含字母与数字（完整策略由后端 validate_mailbox_password 权威执行）'
fi
[[ $ADMIN_USER =~ ^[A-Za-z][A-Za-z0-9_.-]{2,31}$ ]] || fail '管理员用户名格式不正确'
# 10# 前缀强制十进制：带前导零的端口（如 0877）会被算术展开按八进制解析而报错
[[ $ADMIN_PORT =~ ^[0-9]+$ ]] && ((10#$ADMIN_PORT>=1024&&10#$ADMIN_PORT<=65535)) || fail '管理端口必须为 1024-65535'
[[ $WEBMAIL_PORT =~ ^[0-9]+$ ]] && ((10#$WEBMAIL_PORT>=1024&&10#$WEBMAIL_PORT<=65535)) || fail 'Webmail 端口必须为 1024-65535'
[[ $WEBMAIL_PORT != "$ADMIN_PORT" ]] || fail '管理端口与 Webmail 端口不能相同'

say '部署 MailStack 管理与 Web 控制台'
install -d -m 0755 /opt/mailstack/ui /opt/mailstack/backend /opt/mailstack-source
if [[ "$BASE" != "/opt/mailstack-source" ]]; then
  rm -rf /opt/mailstack-source/*
  tar -C "$BASE" --exclude=.git --exclude=node_modules -cf - . | tar -C /opt/mailstack-source -xf -
fi
rm -rf /opt/mailstack/ui/*
# scripts/deploy/mailstack.sh/VERSION 必须随源码进 ui 树：源码构建路径的
# build:manifest（generate_manifest.mjs）按 criticalFiles 清单逐个读取并哈希
# 这些文件（含 VERSION 的版本一致性校验），缺任何一个都会 MODULE_NOT_FOUND /
# "critical source file is missing" 而安装失败。干净 checkout（无预构建 dist/）
# 必走此路径——发布归档带 dist/ 时走不到，容易漏测。
for item in src lib backend webmail public dist index.html package.json package-lock.json vite.config.ts tsconfig.json scripts deploy mailstack.sh VERSION; do [[ -e "$BASE/$item" ]] && cp -a "$BASE/$item" /opt/mailstack/ui/; done
rm -rf /opt/mailstack/backend/mailstackctl
cp -a "$BASE/backend/mailstackctl" /opt/mailstack/backend/mailstackctl
cp "$BASE/backend/mailstackctl.py" /opt/mailstack/backend/mailstackctl.py
chmod 0755 /opt/mailstack/backend/mailstackctl.py
chmod -R a+rX /opt/mailstack/backend/mailstackctl

# Strict prebuilt manifest and SHA256 integrity check
validate_prebuilt_dist(){
  local dist=$1
  [[ -s "$dist/index.html" && -s "$dist/server.cjs" && -s "$dist/webmail.cjs" && -d "$dist/assets" && -d "$dist/webmail-public" && -s "$dist/build-manifest.json" ]] || return 1
  
  # Run strict Python/Node SHA256 checksum comparison against manifest
  python3 - "$dist" <<'PY'
import sys, json, hashlib, pathlib
dist = pathlib.Path(sys.argv[1])
manifest_path = dist / 'build-manifest.json'
if not manifest_path.exists():
    sys.exit(1)
manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
artifacts = manifest.get('artifacts', {})
if not artifacts:
    sys.exit(1)
for rel, expected_hash in artifacts.items():
    p = dist / rel
    if not p.exists() or not p.is_file():
        sys.exit(1)
    actual_hash = hashlib.sha256(p.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        sys.exit(1)
sys.exit(0)
PY
}

cd /opt/mailstack/ui
if [[ -d "$BASE/dist" ]] && validate_prebuilt_dist "$BASE/dist"; then
  say '使用已通过 SHA256 完整性校验的预构建产物 (Prebuilt Release)...'
  mkdir -p /opt/mailstack/ui/dist /opt/mailstack/webmail-public
  cp -a "$BASE/dist/"* /opt/mailstack/ui/dist/
  cp /opt/mailstack/ui/dist/server.cjs /opt/mailstack/server.cjs
  cp /opt/mailstack/ui/dist/webmail.cjs /opt/mailstack/webmail.cjs
  if [[ -d "$BASE/dist/webmail-public" ]]; then
    cp -a "$BASE/dist/webmail-public/"* /opt/mailstack/webmail-public/
  elif [[ -d "$BASE/webmail/public" ]]; then
    cp -a "$BASE/webmail/public/"* /opt/mailstack/webmail-public/
  fi
else
  say '正在从源码执行完整构建 (npm run build:all)...'
  (npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund) || fail 'Node.js 依赖安装失败'
  npm run build:all || fail '前端与服务构建失败 (npm run build:all)'
  mkdir -p /opt/mailstack/webmail-public
  cp dist/server.cjs /opt/mailstack/server.cjs
  cp dist/webmail.cjs /opt/mailstack/webmail.cjs
  if [[ -d dist/webmail-public ]]; then
    cp -a dist/webmail-public/* /opt/mailstack/webmail-public/
  elif [[ -d webmail/public ]]; then
    cp -a webmail/public/* /opt/mailstack/webmail-public/
  fi
fi

# Artifact Gate: 验证全套构建与静态产物就绪
[[ -s /opt/mailstack/ui/dist/index.html ]] || fail '前端控制台构建产物 (index.html) 不存在'
[[ -s /opt/mailstack/server.cjs ]] || fail '生产 API 服务构建产物 (server.cjs) 不存在'
[[ -s /opt/mailstack/webmail.cjs ]] || fail 'Webmail 服务构建产物 (webmail.cjs) 不存在'
[[ -s /opt/mailstack/webmail-public/index.html ]] || fail 'Webmail 前端静态入口不存在'

# 创建系统级运行账号与用户组
if ! getent group mailstack-admin >/dev/null 2>&1; then
  (groupadd --system mailstack-admin 2>/dev/null || addgroup -S mailstack-admin 2>/dev/null || groupadd mailstack-admin 2>/dev/null) || fail '创建 mailstack-admin 用户组失败'
fi
if ! id mailstack-admin >/dev/null 2>&1; then
  (useradd --system -g mailstack-admin -d /opt/mailstack -s /usr/sbin/nologin mailstack-admin 2>/dev/null || \
   adduser -S -D -H -h /opt/mailstack -s /sbin/nologin -G mailstack-admin mailstack-admin 2>/dev/null || \
   adduser -S -D -H -h /opt/mailstack -s /bin/false -G mailstack-admin mailstack-admin 2>/dev/null || \
   useradd -g mailstack-admin -d /opt/mailstack -s /bin/false mailstack-admin 2>/dev/null) || fail '创建 mailstack-admin 系统用户失败'
fi
id mailstack-admin >/dev/null 2>&1 || fail 'mailstack-admin 系统用户创建后校验失败'
# The admin web process uses the audited helper and never reads mailbox files directly.
command -v gpasswd >/dev/null 2>&1 && gpasswd -d mailstack-admin mail >/dev/null 2>&1 || true
command -v gpasswd >/dev/null 2>&1 && gpasswd -d mailstack-admin dovecot >/dev/null 2>&1 || true
if ! getent group mailstack-webmail >/dev/null 2>&1; then
  (groupadd --system mailstack-webmail 2>/dev/null || addgroup -S mailstack-webmail 2>/dev/null || groupadd mailstack-webmail 2>/dev/null) || fail '创建 mailstack-webmail 用户组失败'
fi
if ! id mailstack-webmail >/dev/null 2>&1; then
  (useradd --system -g mailstack-webmail -d /nonexistent -s /usr/sbin/nologin mailstack-webmail 2>/dev/null || \
   adduser -S -D -H -h /nonexistent -s /sbin/nologin -G mailstack-webmail mailstack-webmail 2>/dev/null || \
   adduser -S -D -H -h /nonexistent -s /bin/false -G mailstack-webmail mailstack-webmail 2>/dev/null || \
   useradd -g mailstack-webmail -d /nonexistent -s /bin/false mailstack-webmail 2>/dev/null) || fail '创建 mailstack-webmail 系统用户失败'
fi
id mailstack-webmail >/dev/null 2>&1 || fail 'mailstack-webmail 系统用户创建后校验失败'
usermod -a -G dovecot,mail mailstack-webmail 2>/dev/null || usermod -a -G mail mailstack-webmail 2>/dev/null || true

install -d -o root -g mailstack-admin -m 0750 /etc/mailstack 2>/dev/null || install -d -m 0750 /etc/mailstack
# /var/lib/mailstack 存放需要被 webmail 读取的非敏感状态（邮箱注册表、会话 epoch）：
# webmail 不在 mailstack-admin 组，/etc/mailstack 对它不可读（rc5 实测：注册表放
# 在 /etc/mailstack 会让所有 webmail 登录静默失败）。
install -d -o root -g root -m 0755 /var/lib/mailstack
# 迁移旧版位置（/etc/mailstack/managed-mailboxes.json → /var/lib/mailstack/）
if [[ -s /etc/mailstack/managed-mailboxes.json && ! -s /var/lib/mailstack/managed-mailboxes.json ]]; then
  install -o root -g mailstack-webmail -m 0640 /etc/mailstack/managed-mailboxes.json /var/lib/mailstack/managed-mailboxes.json
fi
# 新位置存在后，无论新旧内容都以新位置为准并保证 webmail 可读
if [[ -s /var/lib/mailstack/managed-mailboxes.json ]]; then
  chown root:mailstack-webmail /var/lib/mailstack/managed-mailboxes.json
  chmod 0640 /var/lib/mailstack/managed-mailboxes.json
fi
if ((REUSE_ADMIN==0)); then
# 密码经环境变量传递，避免出现在 python3 进程 argv（/proc/<pid>/cmdline 短暂可读）。
MAILSTACK_ADMIN_PASS="$ADMIN_PASS" python3 - "$ADMIN_USER" <<'PY'
import json,hashlib,secrets,sys,os
u=sys.argv[1]; p=os.environ['MAILSTACK_ADMIN_PASS']; os.unsetenv('MAILSTACK_ADMIN_PASS')
salt=secrets.token_bytes(16); it=310000; h=hashlib.pbkdf2_hmac('sha256',p.encode(),salt,it,32)
f='/etc/mailstack/admin.json'; open(f,'w').write(json.dumps({'username':u,'algorithm':'pbkdf2-sha256','iterations':it,'salt':salt.hex(),'hash':h.hex()},indent=2)+'\n'); os.chmod(f,0o640)
PY
chown root:mailstack-admin /etc/mailstack/admin.json 2>/dev/null || true
fi

say '配置 MailStack 系统服务用户与安全权限'
# 安全模型：/opt/mailstack 目录本身归 root 且不可被服务账号写入。
# 若父目录对 mailstack-admin 可写，服务账号可整体替换 backend/ 并借 NOPASSWD
# sudoers 规则以 root 执行伪造的 mailstackctl.py（本地提权）。
chown root:root /opt/mailstack
chmod 0755 /opt/mailstack
chown -R mailstack-admin:mailstack-admin /opt/mailstack/ui /opt/mailstack/server.cjs /opt/mailstack/webmail.cjs /opt/mailstack/webmail-public
chown -R root:root /opt/mailstack/backend
chmod 0755 /opt/mailstack/backend/mailstackctl.py
chmod -R a+rX /opt/mailstack/backend/mailstackctl
chown -R root:mailstack-admin /etc/mailstack
chmod 0750 /etc/mailstack
chmod 0640 /etc/mailstack/admin.json 2>/dev/null || true
# A3: TOTP 主密钥（AES-256-GCM 信封）。必须 root:root 0600，仅特权 helper（以 root
# 运行）可读；web 服务账号 mailstack-admin 读不到。故意放在上面的递归 chown 之后
# 单独创建/收敛，避免被 chown root:mailstack-admin 波及而泄露给服务账号。
# 已存在且非空则保持内容不动（升级绝不重置密钥，否则既有信封将无法解密），
# 仅收敛属主/权限；缺失或为空时写入 32 字节随机密钥。
if [[ -s /etc/mailstack/totp.key ]]; then
  chown root:root /etc/mailstack/totp.key 2>/dev/null || true
  chmod 0600 /etc/mailstack/totp.key
else
  install -o root -g root -m 0600 /dev/null /etc/mailstack/totp.key
  head -c 32 /dev/urandom > /etc/mailstack/totp.key
  chown root:root /etc/mailstack/totp.key 2>/dev/null || true
  chmod 0600 /etc/mailstack/totp.key
fi
ln -sfn /opt/mailstack/ui/dist /opt/mailstack/dist

# 唯一特权入口由 root 拥有且不可被服务账号修改；sudoers 不使用参数通配符。
# rc2: 确保目标目录存在（Ubuntu 默认没有 /usr/local/libexec）。
# rc5: sudoers 有且只有这一条。曾经额外放行 /opt/mailstack/backend/mailstackctl.py
# 「保底」——那是第二条 root 通道，与「唯一入口」的承诺直接矛盾；源码/dev 环境
# 没有 wrapper 时应视为部署未完成而失败，而不是悄悄换一条更宽的路。
mkdir -p /usr/local/libexec
install -o root -g root -m 0755 "$BASE/deploy/mailstack-privileged" /usr/local/libexec/mailstack-privileged
cat >/etc/sudoers.d/mailstack-web <<'EOF'
mailstack-admin ALL=(root) NOPASSWD: /usr/local/libexec/mailstack-privileged
EOF
# 清理历史版本遗留的第二条 sudoers 规则
rm -f /etc/sudoers.d/mailstack-web-ctl
chmod 0440 /etc/sudoers.d/mailstack-web
if command -v visudo >/dev/null 2>&1; then
  visudo -cf /etc/sudoers.d/mailstack-web >/dev/null || fail 'sudoers 规则校验失败'
fi

# Release 升级签名信任锚：ms upgrade 只接受由 mailstack-release 私钥
# (ssh-keygen, ed25519) 签名的 SHA256SUMS。公钥随源码分发，私钥永不落地服务器。
if [[ -s "$BASE/deploy/mailstack-release.allowed_signers" ]]; then
  install -o root -g root -m 0644 "$BASE/deploy/mailstack-release.allowed_signers" /etc/mailstack/release-allowed-signers
fi

# 配置 Dovecot Auth Socket 权限供 Webmail 鉴权
if [[ -d /etc/dovecot/conf.d ]]; then
  cat >/etc/dovecot/conf.d/99-mailstack-webmail.conf <<'EOF'
service auth {
  unix_listener auth-client {
    mode = 0660
    user = mailstack-webmail
    group = dovecot
  }
}
service stats {
  unix_listener stats-writer {
    mode = 0660
    user = mailstack-webmail
    group = dovecot
  }
}
EOF
  # 可选设置按 doveconf 输出探测逐个追加：doveconf 对未知键也返回 0，
  # 只能凭「输出是否回显该键」区分。新版 dovecot 已移除 mail_umask 等键，
  # 写一个未知键会让整个配置加载失败（auth-client socket 静默退回
  # 0600 dovecot:root，webmail 登录全部拒绝）——rc5 WSL 实测踩中。
  for opt in 'mail_access_groups = mail' 'mail_privileged_group = mail' 'mail_umask = 0007'; do
    key=${opt%% =*}
    if doveconf "$key" 2>/dev/null | grep -q "^${key} ="; then
      printf '%s\n' "$opt" >> /etc/dovecot/conf.d/99-mailstack-webmail.conf
    fi
  done
  chmod 0644 /etc/dovecot/conf.d/99-mailstack-webmail.conf
  python3 <<'PY'
import json, os, pathlib, pwd, re, stat
registry = pathlib.Path('/etc/mailstack/managed-mailboxes.json')
try:
    mailboxes = json.loads(registry.read_text(encoding='utf-8'))
except Exception:
    mailboxes = []
for mailbox in mailboxes if isinstance(mailboxes, list) else []:
    user = str(mailbox.get('unixUser', ''))
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user):
        continue
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        continue
    home = pathlib.Path(account.pw_dir)
    maildir = home / 'Maildir'
    if not maildir.is_dir() or maildir.is_symlink():
        continue
    os.chmod(home, 0o750)
    for root, dirs, files in os.walk(maildir, followlinks=False):
        root_path = pathlib.Path(root)
        if root_path.is_symlink():
            dirs[:] = []
            continue
        os.chown(root_path, account.pw_uid, account.pw_gid)
        os.chmod(root_path, 0o770)
        dirs[:] = [name for name in dirs if not (root_path / name).is_symlink()]
        for name in files:
            target = root_path / name
            try:
                info = target.lstat()
                if not stat.S_ISREG(info.st_mode):
                    continue
                os.chown(target, account.pw_uid, account.pw_gid)
                os.chmod(target, 0o660)
            except OSError:
                pass
PY
  systemctl restart dovecot 2>/dev/null || service dovecot restart 2>/dev/null || true
fi

# 配置日志自动轮转（单一来源：deploy/mailstack.logrotate，此处不再手写第二份）
if [[ -d /etc/logrotate.d && -f "$BASE/deploy/mailstack.logrotate" ]]; then
  cp "$BASE/deploy/mailstack.logrotate" /etc/logrotate.d/mailstack
  chmod 0644 /etc/logrotate.d/mailstack
fi

# Determine COOKIE_SECURE based on https mode
COOKIE_SECURE_VAL=0
if [[ $HTTPS_MODE -eq 1 ]]; then
  COOKIE_SECURE_VAL=1
fi

NODE_BIN=$(command -v node)
PY_BIN=$(command -v python3)
# helper（无论长驻还是一次性 sudo 调用）需要写这些 /etc 子树：
# postconf/sasl_passwd、dovecot 配置、opendkim 密钥表、mailstack 自身配置、caddy。
# 绝不放行整棵 /etc。
# 前缀 '-' 为可选路径语义：目录不存在时静默跳过而非失败——local 模式不装 caddy，
# /etc/caddy 缺席时若不加 '-'，systemd 挂载命名空间初始化以 226/NAMESPACE 失败。
HELPER_RW_PATHS='-/etc/postfix -/etc/dovecot -/etc/opendkim -/etc/mailstack -/etc/caddy'

# 孤儿监听清理（Wave1 实测）：安装被中断后重跑时，上一轮残留的 node 进程仍占用
# ${ADMIN_PORT}/${WEBMAIL_PORT}（默认 8787/18788），新服务启动即 EADDRINUSE，systemd/init.d
# 反复拉起进入 failed 崩溃循环。此处只杀实际占用这两个端口的进程，不扩大杀进程范围；
# 无进程占用或 fuser 缺席时静默通过，不阻断安装。
if command -v fuser >/dev/null 2>&1; then
  fuser -k "${ADMIN_PORT}/tcp" "${WEBMAIL_PORT}/tcp" 2>/dev/null || true
  sleep 1
else
  # fuser 缺席时的等效兜底：只匹配本服务自身的启动命令行（与 init.d stop 同范围）。
  pkill -f "${NODE_BIN} /opt/mailstack/server.cjs" 2>/dev/null || true
  pkill -f "${NODE_BIN} /opt/mailstack/webmail.cjs" 2>/dev/null || true
  sleep 1
fi

if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
  # 长驻特权 helper：单一 root 进程经 unix socket 服务 RPC，
  # 前端 5 秒的 logs.list 轮询不再每次付出 sudo+python 的 fork 成本。
  # B1 双 socket 拆分（降 Node RCE 爆炸半径）：同一进程绑两个 socket——
  #   /run/mailstack/helper-ro.sock  0660 root:mailstack-admin（只读面：Node 直连，
  #     仅放行 ALLOWED_ACTIONS_RO；收到变更 action 拒绝并审计 ro_channel_violation）
  #   /run/mailstack/helper.sock     0600 root:root（变更面：Node 连不上，变更动作恒经
  #     sudo mailstack-privileged 包装器下发，sudoers 保持单条不变）
  # 单元无须 RuntimeDirectory/ReadWritePaths 覆盖 /run/mailstack：
  # ProtectSystem=full 只对 /usr /boot /etc 生效，/run 不在保护集内，daemon
  # 自建 /run/mailstack（0750 root:mailstack-admin）并绑定两个 socket。
  # B4 rw-forward：sudo 包装器把请求经 helper.sock 转发给本 daemon——变更动作的
  # /etc 写权限只存在于本单元命名空间（ReadWritePaths）；mailstack-web 单元
  # 收窄为 ProtectSystem=strict 后不再需要自身命名空间可写 /etc。
  cat >/etc/systemd/system/mailstack-helper.service <<EOF
[Unit]
Description=MailStack Privileged Helper Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=${PY_BIN} /opt/mailstack/backend/mailstackctl.py --daemon
Restart=always
RestartSec=2
LimitNOFILE=4096
ProtectSystem=full
ReadWritePaths=${HELPER_RW_PATHS}
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/mailstack-web.service <<EOF
[Unit]
Description=MailStack Admin Console
After=network.target postfix.service dovecot.service opendkim.service mailstack-helper.service
Wants=postfix.service dovecot.service opendkim.service mailstack-helper.service

[Service]
Type=simple
User=mailstack-admin
Group=mailstack-admin
WorkingDirectory=/opt/mailstack
Environment=NODE_ENV=production
Environment=PORT=${ADMIN_PORT}
Environment=HOST=${ADMIN_HOST}
Environment=COOKIE_SECURE=${COOKIE_SECURE_VAL}
Environment=DIST_DIR=/opt/mailstack/ui/dist
ExecStart=${NODE_BIN} /opt/mailstack/server.cjs
Restart=always
RestartSec=3
LimitNOFILE=65535
# B4: strict = 整个文件系统只读（含 /etc/mailstack）——admin.json、settings.json
# 的一切写路径恒经 helper（sudo 包装器 → rw socket 转发 → daemon 命名空间）。
# web 自身无已知写需求；/tmp 由 PrivateTmp 的私有 tmpfs 提供可写，
# /run 上的 socket 连接不受只读 bind 影响（webmail 单元同款先例）。
ProtectSystem=strict
# B4: 此处不能有 NoNewPrivileges/RestrictSUIDSGID：变更面主通道是
# sudo mailstack-privileged（setuid 提权后才连得上 0600 root:root 的
# helper.sock），NoNewPrivileges 会让 sudo 拒绝提权、杀死全部 RW 动作。
# 边界由 sudoers 单条规则 + helper.sock 0600 + daemon 双通道 action 门禁承担。
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/mailstack-webmail.service <<EOF
[Unit]
Description=MailStack Webmail Service
After=network.target postfix.service dovecot.service
Wants=postfix.service dovecot.service

[Service]
Type=simple
User=mailstack-webmail
Group=mailstack-webmail
SupplementaryGroups=dovecot mail
WorkingDirectory=/opt/mailstack
Environment=NODE_ENV=production
Environment=WEBMAIL_PORT=${WEBMAIL_PORT}
Environment=WEBMAIL_HOST=${WEBMAIL_HOST}
Environment=WEBMAIL_PUBLIC_DIR=/opt/mailstack/webmail-public
Environment=COOKIE_SECURE=${COOKIE_SECURE_VAL}
ExecStart=${NODE_BIN} /opt/mailstack/webmail.cjs
Restart=always
RestartSec=3
LimitNOFILE=65535
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=-/home -/var/vmail
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

  chown -R root:mailstack-admin /etc/mailstack || fail '无法设置 /etc/mailstack 所有权'
  chmod 0750 /etc/mailstack || fail '无法设置 /etc/mailstack 目录权限'
  chmod 0640 /etc/mailstack/admin.json 2>/dev/null || true

  systemctl daemon-reload
  systemctl unmask mailstack-helper mailstack-web mailstack-webmail 2>/dev/null || true
  systemctl enable --now mailstack-helper || fail '无法启用或启动 mailstack-helper 特权助手服务'
  if ! systemctl is-active --quiet mailstack-helper; then
    journalctl -u mailstack-helper -n 30 --no-pager || true
    fail 'mailstack-helper 特权助手服务启动失败'
  fi
  systemctl enable --now mailstack-web mailstack-webmail || fail '无法启用或启动 mailstack-web 与 mailstack-webmail systemd 服务'
  if ! systemctl is-active --quiet mailstack-web; then
    journalctl -u mailstack-web -n 30 --no-pager || true
    fail 'mailstack-web 管理控制台服务启动失败'
  fi
  if ! systemctl is-active --quiet mailstack-webmail; then
    journalctl -u mailstack-webmail -n 30 --no-pager || true
    fail 'mailstack-webmail 邮箱服务启动失败'
  fi
else
  # Non-systemd OpenRC / Init script
  # 日志文件必须由 root 预创建并归属对应服务账号：init 脚本内的重定向以服务账号
  # 身份执行，而 /var/log 对非 root 不可写。缺少这一步时 sh 无法创建日志文件，
  # node 进程静默启动失败（rc.3 审计发现），安装最终以毫无线索的健康自检失败收场。
  install -o mailstack-admin -g mailstack-admin -m 0640 /dev/null /var/log/mailstack-web.log
  install -o mailstack-webmail -g mailstack-webmail -m 0640 /dev/null /var/log/mailstack-webmail.log
  # 会话脱离：用 setsid 起服务进程（Alpine/WSL 实测：裸 & 后台的进程留在登录会话的
  # 进程组/会话里，发起安装的会话结束后被 SIGHUP 收割，健康自检之后服务即死）。
  # setsid 不可用时退回裸启动（行为等同旧版）。
  SETSID_BIN=$(command -v setsid || true)
  # init.d 启动脚本模板抽为独立文件 deploy/init.d-mailstack.in.sh（纳入 shellcheck 扫描面，
  # CI 的 find deploy -name '*.sh' 会自动扫到）。安装期用 sed 把 @占位符@ 替换为运行参数；
  # 模板内 $0/$1/$network 等 init 运行期变量保持字面（不经 shell 展开）。不引入 envsubst
  # 等新依赖，sed 足够；占位符用 @...@ 形式，与替换值（路径/IP/端口/布尔）无分隔符冲突。
  SETSID_PREFIX="${SETSID_BIN:+$SETSID_BIN }"
  INITD_TEMPLATE="$BASE/deploy/init.d-mailstack.in.sh"
  [[ -f "$INITD_TEMPLATE" ]] || fail "缺少 init.d 模板文件: $INITD_TEMPLATE（发布包不完整）"
  # 精简容器镜像可能没有 /etc/init.d（rockylinux:9 minimal 未装 initscripts）；
  # 预建目录，否则下方 sed 重定向报 No such file or directory 中止安装。
  # 真实系统已存在该目录，幂等无副作用。
  install -d -m 0755 /etc/init.d
  sed -e "s|@SETSID_PREFIX@|${SETSID_PREFIX}|g" \
      -e "s|@ADMIN_PORT@|${ADMIN_PORT}|g" \
      -e "s|@ADMIN_HOST@|${ADMIN_HOST}|g" \
      -e "s|@COOKIE_SECURE_VAL@|${COOKIE_SECURE_VAL}|g" \
      -e "s|@NODE_BIN@|${NODE_BIN}|g" \
      -e "s|@WEBMAIL_PORT@|${WEBMAIL_PORT}|g" \
      -e "s|@WEBMAIL_HOST@|${WEBMAIL_HOST}|g" \
      "$INITD_TEMPLATE" >/etc/init.d/mailstack-web || fail '生成 /etc/init.d/mailstack-web 失败'
  chmod 0755 /etc/init.d/mailstack-web
  /etc/init.d/mailstack-web restart || true
fi

# 配置 Caddy 反向代理与自动 HTTPS 证书 (caddy 模式)
if [[ "$ACCESS_MODE" == "caddy" ]]; then
  say '配置 Caddy 自动反向代理与 HTTPS 证书'
  if ! command -v caddy >/dev/null 2>&1; then
    say '正在自动安装 Caddy 代理服务器...'
    if command -v apt-get >/dev/null 2>&1; then
      # 优先发行版仓库（Debian/Ubuntu 自带 caddy，仓库签名由 apt 校验）。
      apt-get update 2>/dev/null || true
      apt-get install -y caddy 2>/dev/null || true
    fi
    if ! command -v caddy >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
      # 兜底 Cloudsmith 官方源：先验 GPG 指纹（钉死常量）再信任该源。
      # 直接把 curl 输出灌进 apt 源等于把 root 交给 CDN；指纹不符即拒绝。
      CADDY_KEY_FPR='65760C51EDEA2017CEA2CA15155B6D79CA56EA34'
      caddy_key_tmp=$(mktemp /tmp/mailstack-caddy-key.XXXXXX)
      if curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' -o "$caddy_key_tmp" 2>/dev/null \
         && gpg --show-keys --with-colons "$caddy_key_tmp" 2>/dev/null | awk -F: '/^fpr:/ {print $10}' | grep -qx "$CADDY_KEY_FPR"; then
        gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg "$caddy_key_tmp" 2>/dev/null || true
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' -o /etc/apt/sources.list.d/caddy-stable.list 2>/dev/null || true
        apt-get update 2>/dev/null || true
        apt-get install -y caddy 2>/dev/null || true
      else
        warn 'Caddy Cloudsmith GPG 密钥指纹不匹配或下载失败，拒绝添加第三方源（可手动安装 caddy 后重试）'
      fi
      rm -f "$caddy_key_tmp"
    fi
    if ! command -v caddy >/dev/null 2>&1 && command -v dnf >/dev/null 2>&1; then
      dnf install -y 'dnf-command(copr)' 2>/dev/null || true
      dnf copr enable -y @caddy/caddy 2>/dev/null || true
      dnf install -y caddy 2>/dev/null || true
    fi
    if ! command -v caddy >/dev/null 2>&1 && command -v yum >/dev/null 2>&1; then
      yum install -y yum-plugin-copr 2>/dev/null || true
      yum copr enable -y @caddy/caddy 2>/dev/null || true
      yum install -y caddy 2>/dev/null || true
    fi
  fi

  if ! command -v caddy >/dev/null 2>&1; then
    warn '未检测到 caddy 可执行文件，Caddyfile 已生成但尚未自动启动代理。请手动安装 caddy 或检查网络连接。'
  fi
  
  install -d -m 0755 /etc/caddy
  cat >/etc/caddy/Caddyfile <<EOF
# MailStack Production Reverse Proxy Caddyfile
# Managed automatically by MailStack Installer

{
    admin off
$( [[ -n "$ADMIN_EMAIL" ]] && echo "    email ${ADMIN_EMAIL}" )
}

${MAIL_DOMAIN} {
    encode gzip zstd
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
    reverse_proxy 127.0.0.1:${ADMIN_PORT}
}

${WEBMAIL_DOMAIN} {
    encode gzip zstd
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
    reverse_proxy 127.0.0.1:${WEBMAIL_PORT}
}
EOF
  chmod 0644 /etc/caddy/Caddyfile

  CADDY_ACTIVE=0
  if command -v caddy >/dev/null 2>&1; then
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 || warn 'Caddyfile 语法校验提示警告，请检查配置'
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable caddy 2>/dev/null || true
    systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || true
    if systemctl is-active --quiet caddy 2>/dev/null; then
      CADDY_ACTIVE=1
    else
      warn 'Caddy 服务未能立即处于 active 状态，请检查 80/443 端口是否被其他 Web 服务 (如 Nginx/Apache) 占用。'
    fi
  elif command -v caddy >/dev/null 2>&1; then
    CADDY_ACTIVE=1
  fi

  EFFECTIVE_ACCESS_MODE="${ACCESS_MODE}"
  if [[ "$ACCESS_MODE" == "caddy" && $CADDY_ACTIVE -eq 0 ]]; then
    EFFECTIVE_ACCESS_MODE="local (Caddy 未激活自动安全降级)"
    mark_degraded "Caddy 反向代理：未就绪/未激活，已安全降级为 local 本地监听模式（127.0.0.1:${ADMIN_PORT}）；请排查 caddy 服务与 80/443 端口占用"
  fi
fi

# Link CLI
cat >/usr/local/bin/ms <<'EOF'
#!/usr/bin/env bash
exec /opt/mailstack-source/mailstack.sh "$@"
EOF
chmod 0755 /usr/local/bin/ms
ln -sf /usr/local/bin/ms /usr/local/bin/mailstack 2>/dev/null || true

say '执行安装后服务健康自检...'
python3 - "$ADMIN_PORT" "$WEBMAIL_PORT" <<'PY' || fail '安装后服务健康自检失败'
import sys, urllib.request, json, time
port, webmail_port = sys.argv[1:3]
def check(url, name):
    for _ in range(15):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'MailStack-Installer'})
            with urllib.request.urlopen(req, timeout=3) as res:
                if res.status == 200:
                    data = json.loads(res.read().decode('utf-8'))
                    if data.get('status') == 'ok' or data.get('ok') is True:
                        print(f"  ✓ {name} 健康自检通过 ({url})")
                        return True
        except Exception:
            time.sleep(1)
    print(f"  ✗ {name} 健康自检未通过 ({url})")
    return False

ok1 = check(f'http://127.0.0.1:{port}/api/health', 'MailStack Admin API')
ok2 = check(f'http://127.0.0.1:{webmail_port}/api/webmail/health', 'MailStack Webmail API')
if not (ok1 and ok2):
    sys.exit(1)
PY

# 持久化本次安装的有效参数，供 ms upgrade 原样透传（避免升级后监听/HTTPS 行为漂移）
# A4：版本源为源码树 VERSION 文件（绝不硬编码）。同时写入 install-args.conf 的
# INSTALLED_VERSION 与独立的 /etc/mailstack/installed-version（单行，0644），供 ms upgrade
# 的降级门比对；文件缺失时 ms 回退到脚本自带 VERSION，不阻塞老装机。
MAILSTACK_INSTALLED_VERSION=''
if [[ -r "$BASE/VERSION" ]]; then
  MAILSTACK_INSTALLED_VERSION=$(tr -d '[:space:]' <"$BASE/VERSION")
fi
{
  printf 'ACCESS_MODE=%q\n' "$ACCESS_MODE"
  printf 'MAIL_DOMAIN=%q\n' "$MAIL_DOMAIN"
  printf 'WEBMAIL_DOMAIN=%q\n' "$WEBMAIL_DOMAIN"
  printf 'ADMIN_EMAIL=%q\n' "$ADMIN_EMAIL"
  printf 'ADMIN_PORT=%q\n' "$ADMIN_PORT"
  printf 'WEBMAIL_PORT=%q\n' "$WEBMAIL_PORT"
  printf 'ADMIN_HOST=%q\n' "$ADMIN_HOST"
  printf 'WEBMAIL_HOST=%q\n' "$WEBMAIL_HOST"
  printf 'ADMIN_USER=%q\n' "$ADMIN_USER"
  printf 'HTTPS_MODE=%q\n' "$HTTPS_MODE"
  printf 'INSTALLED_VERSION=%q\n' "$MAILSTACK_INSTALLED_VERSION"
} >/etc/mailstack/install-args.conf
chown root:mailstack-admin /etc/mailstack/install-args.conf
chmod 0640 /etc/mailstack/install-args.conf
if [[ -n "$MAILSTACK_INSTALLED_VERSION" ]]; then
  printf '%s\n' "$MAILSTACK_INSTALLED_VERSION" >/etc/mailstack/installed-version
  chown root:mailstack-admin /etc/mailstack/installed-version
  chmod 0644 /etc/mailstack/installed-version
fi

say "=== MailStack 控制台部署成功 ==="
echo "设定访问模式: ${ACCESS_MODE}"
if [[ -n "${EFFECTIVE_ACCESS_MODE:-}" && "$EFFECTIVE_ACCESS_MODE" != "$ACCESS_MODE" ]]; then
  echo "当前有效模式: ${EFFECTIVE_ACCESS_MODE}"
fi
echo "管理员账号: ${ADMIN_USER}"
echo ""

if [[ "$ACCESS_MODE" == "caddy" ]]; then
  if ((CADDY_ACTIVE)); then
    echo "🚀 管理后台 (HTTPS): https://${MAIL_DOMAIN}"
    echo "📬 Webmail 客户端:   https://${WEBMAIL_DOMAIN}"
    echo "提示: 请确保 DNS A/AAAA 记录已正确指向本服务器公网 IP，Caddy 将全自动签发与续期 TLS 证书。"
  else
    echo "⚠️  [警告] Caddy 反向代理未就绪或未处于 active 状态！"
    echo "   已自动安全降级为 local 本地监听模式 (127.0.0.1:${ADMIN_PORT})。"
    echo "   目标 HTTPS 访问地址: https://${MAIL_DOMAIN}"
    echo "   当前暂无法直接通过公网 HTTPS 访问，请排查 Caddy 服务及 80/443 端口占用。"
    echo "   👉 安全连接指引 (本地 SSH 端口转发):"
    echo "      ssh -L ${ADMIN_PORT}:127.0.0.1:${ADMIN_PORT} -L ${WEBMAIL_PORT}:127.0.0.1:${WEBMAIL_PORT} root@<服务器IP>"
    echo "      然后在本地浏览器打开 http://127.0.0.1:${ADMIN_PORT} 即可安全访问。"
  fi
elif [[ "$ACCESS_MODE" == "local" ]]; then
  echo "🔒 本地监听地址: http://127.0.0.1:${ADMIN_PORT}"
  echo "📬 Webmail 本地:  http://127.0.0.1:${WEBMAIL_PORT}"
  echo ""
  echo "👉 安全连接指引 (本地 SSH 端口转发):"
  echo "   在你的客户端电脑执行："
  echo "   ssh -L ${ADMIN_PORT}:127.0.0.1:${ADMIN_PORT} -L ${WEBMAIL_PORT}:127.0.0.1:${WEBMAIL_PORT} root@<服务器IP>"
  echo "   然后在本地浏览器打开 http://127.0.0.1:${ADMIN_PORT} 即可安全访问。"
elif [[ "$ACCESS_MODE" == "direct" ]]; then
  echo "🌐 主机直连地址: https://${MAIL_DOMAIN:-127.0.0.1}:${ADMIN_PORT}"
  echo "提示: 请确保前端反向代理或 ACME 证书已正确配置。"
elif [[ "$ACCESS_MODE" == "plain" ]]; then
  echo "⚠️  公网明文地址: http://${ADMIN_HOST}:${ADMIN_PORT}"
  echo "⚠️  [安全警告] 生产环境切勿以纯 HTTP 裸奔传输管理员认证会话与密码！"
fi
echo ""
echo "常用运维命令: ms doctor | ms status | ms logs | ms test-mail"
print_degradation_summary

#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  if command -v bash >/dev/null 2>&1; then
    exec bash "$0" "$@"
  else
    echo "Error: bash is required to run install-mail-stack.sh" >&2
    exit 1
  fi
fi
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
LOG=/var/log/mailstack-install.log
BACKUP_ROOT=/var/backups/mailstack
exec > >(tee -a "$LOG") 2>&1

say(){ printf '\n==> %s\n' "$*"; }
die(){ printf '\nERROR: %s\n' "$*" >&2; exit 1; }
warn(){ printf '\n⚠️  %s\n' "$*" >&2; }
need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || die '请使用 root 或 sudo 运行'; }

# 降级登记：opendkim/fail2ban/EPEL/ACME 等可选组件在仓库缺包或校验失败时按设计降级，
# 过程只散落在 warn 日志里，运维装机后难以一眼看清「到底哪些能力缺席」。此处集中登记，
# main() 结尾统一输出「降级组件清单」。父脚本 install.sh 会以子进程方式调用本脚本并经
# MAILSTACK_DEGRADED_LOG 临时文件回收降级项做顶层汇总，届时本脚本抑制自身重复打印。
DEGRADED_ITEMS=()
mark_degraded(){
  DEGRADED_ITEMS+=("$*")
  if [[ -n ${MAILSTACK_DEGRADED_LOG:-} ]]; then
    printf '%s\n' "$*" >>"$MAILSTACK_DEGRADED_LOG" 2>/dev/null || true
  fi
}
print_degradation_summary(){
  # 被 install.sh 编排调用时（MAILSTACK_DEGRADED_LOG 已设），降级项已回传父脚本统一汇总，
  # 本脚本不再重复打印，避免同一份清单在安装日志里出现两次。
  if [[ -n ${MAILSTACK_DEGRADED_LOG:-} ]]; then return 0; fi
  say '降级组件清单'
  if ((${#DEGRADED_ITEMS[@]} == 0)); then
    echo '  无降级，全部组件就位。'
    return 0
  fi
  local _i _n=0
  for _i in "${DEGRADED_ITEMS[@]}"; do
    _n=$((_n+1))
    printf '  %d) %s\n' "$_n" "$_i"
  done
  echo '  （以上为安装期按设计降级的组件；核心邮件收发不受影响，ms doctor 会持续报告其状态）'
}

backup_path(){
  local p=$1
  [[ -e $p ]] || return 0
  install -d -m 0700 "$BACKUP_ROOT"
  local archive
  archive="$BACKUP_ROOT/preinstall-$(date +%Y%m%d-%H%M%S)-$(basename "$p").tar.gz"
  # 备份失败不再静默吞掉：随后的配置改写是破坏性的，没有回滚副本必须让运维
  # 在日志里看得见（tar 对运行中配置常见 "file changed as we read it" 也走这里）。
  if ! tar -C / -czf "$archive" "${p#/}"; then
    rm -f "$archive"
    warn "预安装备份失败: $p（安装将继续，但该路径当前没有可回滚副本）"
  fi
}

version_ge_24(){
  local v=${1%% *}
  local a=${v%%.*}
  local r=${v#*.}
  local b=${r%%.*}
  ((a>2 || (a==2 && b>=4)))
}

# 1. Platform & OS Detection
detect_os(){
  local os_id="unknown" os_ver=""
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    os_id=${ID:-"unknown"}
    os_ver=${VERSION_ID:-""}
  fi
  echo "$os_id $os_ver"
}

detect_pm(){
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"
  elif command -v yum >/dev/null 2>&1; then echo "yum"
  elif command -v zypper >/dev/null 2>&1; then echo "zypper"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman"
  elif command -v apk >/dev/null 2>&1; then echo "apk"
  else echo "unknown"
  fi
}

log_platform_tier(){
  read -r os_id os_ver <<<"$(detect_os)"
  say "检测到运行平台: ID=$os_id, Version=$os_ver, 包管理器=$(detect_pm)"
  case "$os_id" in
    ubuntu|debian)
      echo "[MailStack 平台支持分级] Tier 1: 正式完全支持平台 ($os_id $os_ver)"
      ;;
    rhel|rocky|almalinux|centos|fedora|ol|openeuler|opensuse*|suse|arch)
      echo "[MailStack 平台支持分级] Tier 2: 正式扩展支持平台 ($os_id $os_ver)"
      ;;
    alpine)
      echo "[MailStack 平台支持分级] Tier 3: 实验性轻量平台 (Alpine/OpenRC/musl)"
      ;;
    *)
      echo "[MailStack 平台支持分级] 通用兼容模式 ($os_id)"
      ;;
  esac
}

# fail2ban 兜底：openEuler 25.09（OS/everything/EPOL）等发行版仓库不提供 fail2ban
# 包（断言要求 jail 配置落盘）。PyPI 无同名项目，故从 GitHub 发行版 tarball
# 装（fail2ban 为纯 Python）。pip 安装不带 systemd unit，由 configure_fail2ban
# 补写。仅在发行版原生包安装失败时触发，不影响其他发行版既有路径。
#
# 供应链钉扎：fail2ban 1.1.0 上游 GitHub release 仅提供 GPG 分离签名（fail2ban-1.1.0.tar.gz.asc，
# RSA 8738559E26F671DF9E2C6D9E683BF1BEBD0A882C）与 .deb 资产，被签名的源码 tarball 本体
# 未作为 release 资产托管（releases/download/1.1.0/fail2ban-1.1.0.tar.gz 实测 404），
# fail2ban.org 同路径也 404，故无法在线验签。退而钉 GitHub 自动归档 tarball 的 SHA256：
# archive/refs/tags 与 codeload 双通道实测哈希一致（取值时间 2026-09-12）。
# tag tarball 存在上游重打包漂移风险，故改为「单次下载 → SHA256 校验 → 从已校验本地件
# pip 安装 + 铺配置」，校验不通过即 warn 降级跳过（与其他 fail2ban 兜底语义一致，绝不中断安装）。
install_fail2ban_via_pip(){
  command -v fail2ban-server >/dev/null 2>&1 && [[ -f /etc/fail2ban/fail2ban.conf ]] && return 0
  say 'fail2ban 系统包缺失，尝试 GitHub 发行版包兜底安装（纯 Python，钉 SHA256）'
  local _f2b_ver='1.1.0'
  # 取值时间 2026-09-12；渠道 github.com/fail2ban/fail2ban tag 1.1.0 自动归档 tarball
  # （archive/refs/tags/1.1.0.tar.gz 与 codeload 双通道一致）。
  local _f2b_sha256='474fcc25afdaf929c74329d1e4d24420caabeea1ef2e041a267ce19269570bae'
  local _f2b_url="https://github.com/fail2ban/fail2ban/archive/refs/tags/${_f2b_ver}.tar.gz"
  local _tmp _got
  if ! python3 -m pip --version >/dev/null 2>&1; then
    apt-get install -y python3-pip 2>/dev/null \
      || dnf install -y python3-pip 2>/dev/null \
      || yum install -y python3-pip 2>/dev/null \
      || zypper --non-interactive install -y python3-pip 2>/dev/null \
      || pacman -S --noconfirm --needed python-pip 2>/dev/null \
      || apk add --no-cache py3-pip 2>/dev/null \
      || python3 -m ensurepip --upgrade 2>/dev/null \
      || true
  fi
  python3 -m pip --version >/dev/null 2>&1 || return 1
  # 先下载到临时目录并校验，通过后才用本地件安装（避免 pip 二次联网下载绕过校验）。
  _tmp=$(mktemp -d)
  if ! curl -fsSL "$_f2b_url" -o "$_tmp/f2b.tar.gz" 2>/dev/null; then
    warn 'fail2ban tarball 下载失败（网络受限），跳过 pip 兜底（doctor 会报告爆破防护不可用）'
    rm -rf "$_tmp"; return 1
  fi
  _got=$(sha256sum "$_tmp/f2b.tar.gz" | awk '{print $1}')
  if [[ "$_got" != "$_f2b_sha256" ]]; then
    warn "fail2ban ${_f2b_ver} tarball SHA256 不匹配（期望 $_f2b_sha256，实际 $_got），拒绝安装（上游重打包漂移或传输损坏），跳过 pip 兜底"
    rm -rf "$_tmp"; return 1
  fi
  # 从已校验的本地 tarball 安装（目录名 fail2ban-${_f2b_ver} 内含 setup.py，pip 可当 sdist 处理）。
  python3 -m pip install --no-input --break-system-packages "$_tmp/f2b.tar.gz" 2>/dev/null \
    || python3 -m pip install --no-input "$_tmp/f2b.tar.gz" 2>/dev/null \
    || { warn 'fail2ban pip 安装失败（tarball 已通过 SHA256 校验），跳过兜底'; rm -rf "$_tmp"; return 1; }
  # pip 装的 data_files 落点不可靠（openEuler 25.09 实测：/etc/fail2ban 只有空壳），
  # 从同一已校验本地件展开基础配置（fail2ban.conf/jail.conf/paths-*/filter.d/action.d）
  # 铺到 /etc/fail2ban，否则 fail2ban-server 报 Found no accessible config files。
  if [[ ! -f /etc/fail2ban/fail2ban.conf ]]; then
    tar -xzf "$_tmp/f2b.tar.gz" -C "$_tmp" 2>/dev/null || true
    if [[ -d $_tmp/fail2ban-${_f2b_ver}/config ]]; then
      mkdir -p /etc/fail2ban
      cp -a "$_tmp"/fail2ban-${_f2b_ver}/config/. /etc/fail2ban/
    fi
  fi
  rm -rf "$_tmp"
  hash -r
  command -v fail2ban-server >/dev/null 2>&1 && [[ -f /etc/fail2ban/fail2ban.conf ]]
}

# Arch 部分升级自愈：仓库存在「postfix 拉入新版 icu，而 pacman 本体还链旧版」的
# 组合时（2025-03 旧镜像实测：装 postfix 升 icu→78 后 pacman 报
# libicuuc.so.76 缺失），用包缓存 / archive 把旧版库文件补回，救活 pacman。
# 只补 SONAME 缺失的库文件，不碰已升级的新版库，共存无害。
#
# icu 版本解析采用「已知表快速路径 + archive 列表页动态解析兜底」：
#   数据源① 本地包缓存 /var/cache/pacman/pkg（命中则零网络）；
#   数据源② archive.archlinux.org/packages/i/icu/（永久保留历史版本，按大版本
#            反查最新补丁版；SONAME 主号即 icu 大版本，libicuuc.so.76 ← icu 76.x）；
#   数据源③ 清华镜像（只滚动保留当前版，仅用于 libgcc 等「取最新即可」的动态链）。
# 不硬编码具体补丁号（icu-77 实测未入 archive），避免钉死表随上游发布而失效。
repair_pacman_icu(){
  command -v pacman >/dev/null 2>&1 && pacman -Q >/dev/null 2>&1 && return 0
  local _missing _soname
  _missing=$(ldd "$(command -v pacman)" 2>/dev/null | awk '/not found/{print $1}' | sort -u)
  [[ -n $_missing ]] || return 0
  warn "pacman 因部分升级的库缺失无法运行（$_missing），尝试从包缓存/归档/镜像自愈"
  local _mirror='https://mirrors.tuna.tsinghua.edu.cn/archlinux/core/os/x86_64'
  local _archive='https://archive.archlinux.org/packages/i/icu'
  local _icu_index='' _icu_index_fetched=0
  for _soname in $_missing; do
    # libgcc_s.so.1：gcc-libs 拆分后由 libgcc 独立包提供，取镜像当前版即可（无需历史版）。
    if [[ "$_soname" == 'libgcc_s.so.1' ]]; then
      local _lf
      _lf=$(curl -fsS -m 15 "$_mirror/" 2>/dev/null | grep -oE 'libgcc-[0-9][^"]*x86_64.pkg.tar.zst' | grep -v '%2B' | sort -V | tail -1 || true)
      if [[ -n $_lf ]] && curl -fsSL -o "/tmp/$_lf" "$_mirror/$_lf" 2>/dev/null; then
        tar -xf "/tmp/$_lf" -C / 2>/dev/null || true
      fi
      continue
    fi
    # 其余只处理 icu 的 SONAME（libicuuc.so.<maj> / libicui18n.so.<maj> 等），取尾部主版本号。
    case "$_soname" in
      libicu*.so.[0-9]*) : ;;
      *) continue ;;
    esac
    local _maj=${_soname##*.so.}
    [[ $_maj =~ ^[0-9]+$ ]] || continue
    local _hit='' _c _known=''
    # 快速路径①：本地包缓存已有任意 icu-<maj>.x 包（零网络）。
    for _c in /var/cache/pacman/pkg/icu-"${_maj}".*-x86_64.pkg.tar.zst; do
      [[ -f $_c ]] && { _hit=$_c; break; }
    done
    # 快速路径②：已知表给出确定文件名（2025-2026 实测过的 SONAME），直接试 archive
    # 下载，省去列表页往返；不中再走动态解析。
    if [[ -z $_hit ]]; then
      case "$_maj" in
        76) _known='icu-76.1-1-x86_64.pkg.tar.zst' ;;
        77) _known='icu-77.1-1-x86_64.pkg.tar.zst' ;;
        78) _known='icu-78.3-1-x86_64.pkg.tar.zst' ;;
      esac
      if [[ -n $_known ]] && command -v curl >/dev/null 2>&1 \
         && curl -fsSL -m 60 -o "/tmp/$_known" "$_archive/$_known" 2>/dev/null; then
        _hit="/tmp/$_known"
      fi
    fi
    # 通用兜底：抓 archive 列表页（整个函数只抓一次），按大版本反查最新补丁版。
    if [[ -z $_hit ]] && command -v curl >/dev/null 2>&1; then
      if (( ! _icu_index_fetched )); then
        _icu_index=$(curl -fsS -m 20 "$_archive/" 2>/dev/null || true)
        _icu_index_fetched=1
      fi
      local _name
      _name=$(printf '%s' "$_icu_index" | grep -oE "icu-${_maj}\.[0-9]+-[0-9]+-x86_64\.pkg\.tar\.zst" | sort -u -V | tail -1 || true)
      if [[ -n $_name ]] && curl -fsSL -m 60 -o "/tmp/$_name" "$_archive/$_name" 2>/dev/null; then
        _hit="/tmp/$_name"
      fi
    fi
    if [[ -n $_hit ]]; then
      tar -xf "$_hit" -C / 2>/dev/null || true
    else
      warn "无法解析 icu 大版本 ${_maj}（SONAME $_soname）的历史包：archive.archlinux.org 未收录或网络受限。手动修复：pacman -Syu 全量升级，或从 https://archive.archlinux.org/packages/i/icu/ 下载 icu-${_maj}.x 包后 tar -xf 到 /"
    fi
  done
  ldconfig 2>/dev/null || true
  if ! pacman -Q >/dev/null 2>&1; then return 1; fi
  # gcc-libs 拆分后（实测：2.44 时代拆出 libgcc 等 9 个独立包），-Syu 只升级本体不装
  # 新拆分依赖；救活后立刻补齐并登记进 pacman 数据库，避免后续依赖解析报错。
  pacman -S --noconfirm --needed libgcc libatomic libasan libgomp libgfortran libhwasan libitm liblsan libubsan libquadmath >/dev/null 2>&1 || true
  return 0
}

# OpenRC 环境兼容（Alpine/Tier 3，容器与 WSL 等非完整引导场景）：
# 1) OpenRC 未完成引导时缺 /run/openrc/softlevel，rc-service 会拒绝启动任何服务
#    （Alpine 3.24 WSL 实测：failed to acquire lock: Bad file descriptor）；
# 2) postfix/dovecot/opendkim/fail2ban 的 init 脚本 depend 需要 net，
#    /etc/network/interfaces 缺失时 networking 服务起不来（ifquery 解析失败），
#    连锁导致全部服务无法启动。
# 只补最小回环配置，不碰真实网卡（网络由 WSL/容器运行时管理，ifup lo 无害）。
prepare_openrc_env(){
  command -v rc-service >/dev/null 2>&1 || return 0
  mkdir -p /run/openrc 2>/dev/null || true
  [[ -f /run/openrc/softlevel ]] || touch /run/openrc/softlevel 2>/dev/null || true
  if [[ ! -s /etc/network/interfaces ]]; then
    mkdir -p /etc/network
    printf 'auto lo\niface lo inet loopback\n' >/etc/network/interfaces
  fi
}

# 2. Package Installation
install_packages(){
  local pm; pm=$(detect_pm)
  say "正在使用包管理器安装核心依赖: $pm"
  case "$pm" in
    apt)
      read -r cur_os_id _ <<<"$(detect_os)"
      if [[ "$cur_os_id" == "ubuntu" ]]; then
        if command -v add-apt-repository >/dev/null 2>&1; then
          add-apt-repository -y universe 2>/dev/null || true
        else
          apt-get update -y 2>/dev/null || true
          DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends software-properties-common 2>/dev/null || true
          command -v add-apt-repository >/dev/null 2>&1 && add-apt-repository -y universe 2>/dev/null || true
        fi
      fi
      echo "postfix postfix/mailname string localhost" | debconf-set-selections 2>/dev/null || true
      echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections 2>/dev/null || true
      local retry=0
      while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if ((retry >= 15)); then break; fi
        say "等待 APT 锁释放 ($retry/15)..."
        sleep 2
        retry=$((retry+1))
      done
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates cron curl dnsutils git gnupg openssl socat hostname \
        postfix postfix-pcre libsasl2-modules \
        dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-sieve dovecot-managesieved \
        opendkim opendkim-tools fail2ban \
        python3 rsync sudo tar
      # A3: TOTP 信封加密依赖 cryptography（仅发行版仓库，禁 pip/wheel）。装不上时
      # 2FA 功能 fail-closed，doctor 会如实报告；核心邮件收发不受影响，按降级处理。
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-cryptography 2>/dev/null \
        || { warn "python3-cryptography 安装失败：管理后台 2FA（TOTP）不可用（fail-closed，doctor 会报告）"; \
             mark_degraded 'python3-cryptography：未能安装，管理后台 2FA（TOTP 信封加密）不可用（fail-closed；doctor 报告）'; }
      ;;
    dnf|yum)
      # rockylinux/almalinux 容器基础镜像自带 curl-minimal（功能子集包），与完整
      # curl 二进制冲突，dnf 拒绝安装（"problem with installed package
      # curl-minimal"）→ 整个安装直接失败。先 remove 不行：curl-minimal 在
      # dnf 的受保护依赖链上（remove 会连带删 dnf 本体而被拒绝）。唯一解是给
      # install 传 --allowerasing，同一事务内用完整 curl 替换掉 curl-minimal
      # （dnf 4/5 均支持；老 yum 无此镜像场景，不加）。真实服务器无
      # curl-minimal，此分支为空操作；条件限定 curl-minimal 存在才加旗标，
      # 绝不在干净系统上放开 allowerasing 的擦除能力。
      local _dnf_flags=()
      if [[ "$pm" == "dnf" ]] && rpm -q curl-minimal >/dev/null 2>&1; then
        _dnf_flags=(--allowerasing)
      fi
      # EPEL 前置：标准 EL 发行版包名是 epel-release；Oracle Linux 的包名是
      # oracle-epel-release-el<N>（Oracle 官方文档确认 OL9 为 oracle-epel-release-el9，
      # 网络检索核实）。两者都失败只记录不中断：缺 EPEL 仅影响 opendkim/fail2ban
      # 等可选组件，核心邮件栈仍可从主仓库装齐。
      local _os_id _os_ver _el_major
      read -r _os_id _os_ver <<<"$(detect_os)"
      _el_major=${_os_ver%%.*}
      if ! "$pm" install -y epel-release 2>/dev/null; then
        "$pm" install -y "oracle-epel-release-el${_el_major}" 2>/dev/null \
          || { warn "EPEL 仓库未能启用（epel-release 与 oracle-epel-release-el${_el_major} 均不可用），opendkim 等 EPEL 包可能装不上（将按可选组件降级处理）"; \
               mark_degraded "EPEL 仓库：未能启用（epel-release / oracle-epel-release-el${_el_major} 均不可用），opendkim、fail2ban 等 EPEL 包可能缺失（核心邮件栈仍从主仓库装齐）"; }
      fi
      "$pm" install -y "${_dnf_flags[@]}" ca-certificates curl bind-utils git gnupg2 openssl hostname python3 rsync sudo tar
      "$pm" install -y cronie socat
      "$pm" install -y postfix cyrus-sasl cyrus-sasl-plain
      "$pm" install -y dovecot dovecot-pigeonhole
      # Python 版本保障：后端 mailstackctl 使用 PEP 604 联合类型（X | None），
      # 硬性要求 >=3.10；EL9 系（OracleLinux/Rocky/Alma 9）默认 python3=3.9，
      # 不升级会让特权 helper 在 import 阶段即崩（rc.5 OL9 实测）。从 AppStream 装
      # python3.11/3.12 并经 alternatives 切换 /usr/bin/python3（不触碰
      # dnf 依赖的 platform-python）。切不动仅告警，由 install.sh 硬门槛兜底。
      if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
        "$pm" install -y python3.11 2>/dev/null || "$pm" install -y python3.12 2>/dev/null || true
        local _py
        for _py in /usr/bin/python3.12 /usr/bin/python3.11; do
          if [[ -x $_py ]]; then
            alternatives --set python3 "$_py" 2>/dev/null \
              || { alternatives --install /usr/bin/python3 python3 "$_py" 40 2>/dev/null || true; \
                   alternatives --set python3 "$_py" 2>/dev/null || true; }
            break
          fi
        done
        python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null \
          || { warn "Python 版本仍低于 3.10，后端特权 helper 将无法运行（请手动安装 python3.11 及以上）"; \
               mark_degraded 'Python ≥ 3.10：尽力升级后仍不达标，后端特权 helper 将无法运行（install.sh 会在此后硬门槛失败；请手动安装 python3.11+）'; }
      fi
      # 旧版 site-packages 兼容路径（幂等）：EL 系发行版包（如 EPEL fail2ban）的纯
      # Python 模块按旧默认解释器（3.9）安装；/usr/bin/python3 切到 3.11+ 后它们不在
      # 新解释器搜索路径上（rc.5 OL9 实测：fail2ban-server 报 No module named
      # 'fail2ban'）。补一条 .pth 使其继续可导入；依赖 ABI 的 C 扩展（如 3.9 版
      # python3-systemd）自然失效，使用方自行降级（见 configure_fail2ban 探测）。
      local _legacy_sitelib _site_dir
      for _legacy_sitelib in /usr/lib/python3.9/site-packages /usr/lib/python3.8/site-packages; do
        [[ -d $_legacy_sitelib ]] || continue
        # 写入现有 site 目录才会被 site 模块加载：/usr/local 下的目录在 EL 系
        # 解释器里不处理 .pth（rc.5 实测），只接受 /usr/(lib|lib64) 下的目录。
        while IFS= read -r _site_dir; do
          [[ -n $_site_dir ]] || continue
          if [[ -d $_site_dir && $_site_dir != "$_legacy_sitelib" && $_site_dir != /usr/local/* ]]; then
            printf '%s\n' "$_legacy_sitelib" >"$_site_dir/mailstack-py-compat.pth"
            break
          fi
        done < <(python3 -c 'import site; [print(p) for p in site.getsitepackages()]' 2>/dev/null)
        break
      done
      # opendkim 为可选组件（仿照下方 fail2ban 的降级模式）：openEuler 25.09 主仓库
      # （OS/everything，网络检索包索引核实）不提供 opendkim；OracleLinux 9 依赖 EPEL。
      # 装不上时降级：DKIM 签名不可用但邮件仍可收发，安装不得中断。
      # EL9 系上 opendkim 的运行依赖（libmilter、libmemcached）只存在于 CRB/PowerTools
      # 仓库（rc.5 OL9 实测：仅开 EPEL 会报 nothing provides libmilter.so.1.0）。
      # 各发行版仓库 ID 不同，逐个尝试启用，全部失败不中断（opendkim 走既有降级）。
      local _repo
      for _repo in crb ol9_codeready_builder ol8_codeready_builder powertools codeready-builder-for-rhel-9-x86_64-rpms; do
        "$pm" config-manager --set-enabled "$_repo" 2>/dev/null || true
      done
      "$pm" install -y opendkim opendkim-tools 2>/dev/null \
        || "$pm" install -y opendkim 2>/dev/null \
        || warn "opendkim 安装失败：DKIM 签名不可用，邮件仍可收发；可后续手动安装 opendkim 后运行 dkim.rotate（doctor 会报告）"
      "$pm" install -y fail2ban 2>/dev/null || "$pm" install -y fail2ban-server 2>/dev/null \
        || install_fail2ban_via_pip \
        || warn "无法安装 fail2ban，爆破防护将不可用（doctor 会报告）"
      # A3: TOTP 信封加密依赖 cryptography（仅发行版仓库，禁 pip/wheel）。
      "$pm" install -y python3-cryptography 2>/dev/null \
        || { warn "python3-cryptography 安装失败：管理后台 2FA（TOTP）不可用（fail-closed，doctor 会报告）"; \
             mark_degraded 'python3-cryptography：未能安装，管理后台 2FA（TOTP 信封加密）不可用（fail-closed；doctor 报告）'; }
      ;;
    zypper)
      zypper --non-interactive refresh || true
      # openSUSE 容器默认预装 OpenSMTPD，与 postfix 硬冲突（rpm conflicts，
      # Tumbleweed 20260723 实测：zypper 直接退出码 4）；先卸冲突 MTA 再装。
      local _mta
      for _mta in OpenSMTPD opensmtpd exim; do
        rpm -q "$_mta" >/dev/null 2>&1 && zypper --non-interactive remove "$_mta" 2>/dev/null || true
      done
      zypper --non-interactive install -y ca-certificates curl bind-utils git gpg2 openssl hostname python3 rsync sudo tar cronie socat
      zypper --non-interactive install -y postfix cyrus-sasl cyrus-sasl-plain
      zypper --non-interactive install -y dovecot
      zypper --non-interactive install -y opendkim opendkim-utils 2>/dev/null || zypper --non-interactive install -y opendkim 2>/dev/null || true
      # Tumbleweed 实测：fail2ban 依赖 ed 但 zypper 不自动拉（Problem: requirement
      # cannot be provided）；先装依赖再装 fail2ban，失败再走 pip 兜底。
      zypper --non-interactive install -y ed 2>/dev/null || true
      zypper --non-interactive install -y fail2ban 2>/dev/null || install_fail2ban_via_pip || warn "无法安装 fail2ban，爆破防护将不可用（doctor 会报告）"
      # A3: TOTP 信封加密依赖 cryptography（仅发行版仓库，禁 pip/wheel）。
      zypper --non-interactive install -y python3-cryptography 2>/dev/null \
        || { warn "python3-cryptography 安装失败：管理后台 2FA（TOTP）不可用（fail-closed，doctor 会报告）"; \
             mark_degraded 'python3-cryptography：未能安装，管理后台 2FA（TOTP 信封加密）不可用（fail-closed；doctor 报告）'; }
      ;;
    pacman)
      # 旧快照（如 2025-03 镜像）可能处于部分升级的中间态（python 新版要新 glibc、
      # icu 新旧断层等）：先完整 -Syu 收敛，再装包；收敛失败不阻断（后续逐个装）。
      repair_pacman_icu
      pacman -Sy --noconfirm archlinux-keyring 2>/dev/null || true
      pacman-key --populate archlinux 2>/dev/null \
        || warn 'pacman-key --populate archlinux 失败；若后续装包报签名错误，请先执行: pacman -Syu archlinux-keyring'
      if ! pacman -Syu --noconfirm --overwrite '*' >/tmp/mailstack-syu.log 2>&1; then
        warn 'pacman -Syu 全量收敛未完全成功（见 /tmp/mailstack-syu.log），继续按需装包'
      fi
      repair_pacman_icu
      pacman -S --noconfirm --needed --overwrite '*' ca-certificates curl git gnupg openssl socat inetutils python rsync sudo tar
      pacman -S --noconfirm --needed --overwrite '*' cronie
      pacman -S --noconfirm --needed --overwrite '*' bind 2>/dev/null || pacman -S --noconfirm --needed --overwrite '*' bind-tools
      pacman -S --noconfirm --needed --overwrite '*' postfix
      # postfix 可能拉入新版 icu 并删除旧版库文件，导致后续 pacman 调用缺库；
      # 事务间补回旧版库文件（幂等，正常系统无操作）。
      repair_pacman_icu
      pacman -S --noconfirm --needed --overwrite '*' dovecot
      repair_pacman_icu
      pacman -S --noconfirm --needed --overwrite '*' pigeonhole 2>/dev/null || pacman -S --noconfirm --needed --overwrite '*' dovecot-pigeonhole 2>/dev/null || true
      pacman -S --noconfirm --needed --overwrite '*' opendkim
      pacman -S --noconfirm --needed --overwrite '*' fail2ban 2>/dev/null || install_fail2ban_via_pip || warn "无法安装 fail2ban，爆破防护将不可用（doctor 会报告）"
      # A3: TOTP 信封加密依赖 cryptography（Arch 包名 python-cryptography）。
      pacman -S --noconfirm --needed --overwrite '*' python-cryptography 2>/dev/null \
        || { warn "python-cryptography 安装失败：管理后台 2FA（TOTP）不可用（fail-closed，doctor 会报告）"; \
             mark_degraded 'python-cryptography：未能安装，管理后台 2FA（TOTP 信封加密）不可用（fail-closed；doctor 报告）'; }
      [[ -e /usr/bin/python3 ]] || ln -sf /usr/bin/python /usr/bin/python3 2>/dev/null || true
      ;;
    apk)
      apk update
      apk add --no-cache ca-certificates curl bind-tools git gnupg openssl socat python3 rsync sudo tar
      apk add --no-cache postfix postfix-pcre 2>/dev/null || apk add --no-cache postfix
      apk add --no-cache dovecot dovecot-pop3d dovecot-lmtpd dovecot-pigeonhole-plugin 2>/dev/null || apk add --no-cache dovecot
      apk add --no-cache opendkim opendkim-utils 2>/dev/null || apk add --no-cache opendkim
      apk add --no-cache cyrus-sasl
      apk add --no-cache fail2ban 2>/dev/null || install_fail2ban_via_pip || warn "无法安装 fail2ban，爆破防护将不可用（doctor 会报告）"
      # A3: TOTP 信封加密依赖 cryptography（Alpine 包名 py3-cryptography）。
      apk add --no-cache py3-cryptography 2>/dev/null \
        || { warn "py3-cryptography 安装失败：管理后台 2FA（TOTP）不可用（fail-closed，doctor 会报告）"; \
             mark_degraded 'py3-cryptography：未能安装，管理后台 2FA（TOTP 信封加密）不可用（fail-closed；doctor 报告）'; }
      ;;
    *)
      die "不支持的包管理器: $pm"
      ;;
  esac
}

# 3. Optional ACME Client
# acme.sh 以 root 运行且持有证书私钥，来源必须钉死：固定版本 tarball +
# SHA256 常量比对，对不上即跳过（自签证书仍可保障基础 TLS）。
ACME_VERSION='3.1.4'
ACME_SHA256='e5f8e187bbf5251e0cd8891f2622daab9850366bd17bea9f92c2fe2ee091fd32'
install_acme_client(){
  say "检查并配置 ACME (Let's Encrypt) 证书客户端 (acme.sh v${ACME_VERSION}, 钉哈希)"
  local src=/opt/mailstack-acme-src
  if [[ -x /root/.acme.sh/acme.sh ]]; then
    echo "[ACME] 已检测到 acme.sh 客户端"
  else
    local tmp
    tmp=$(mktemp /tmp/mailstack-acme.XXXXXX)
    if curl -fsSL "https://codeload.github.com/acmesh-official/acme.sh/tar.gz/refs/tags/${ACME_VERSION}" -o "$tmp" 2>/dev/null; then
      local got
      got=$(sha256sum "$tmp" | awk '{print $1}')
      if [[ "$got" == "$ACME_SHA256" ]]; then
        rm -rf "$src"
        mkdir -p "$src"
        if tar -xzf "$tmp" -C "$src" --strip-components=1 2>/dev/null; then
          (cd "$src" && ./acme.sh --install --home /root/.acme.sh --config-home /etc/mailstack/acme --cert-home /etc/mailstack/acme/certs) 2>/dev/null || true
          echo "[ACME] acme.sh v${ACME_VERSION} 安装成功 (SHA256 已校验)"
        else
          warn "[ACME] acme.sh 解压失败，跳过（不影响基础邮件收发与自签证书）"
          mark_degraded 'acme.sh：tarball 解压失败已跳过，Let'"'"'s Encrypt 自动签发不可用（退回自签证书保障基础 TLS）'
        fi
      else
        warn "[ACME] acme.sh tarball SHA256 不匹配 (期望 $ACME_SHA256，实际 $got)，拒绝安装"
        mark_degraded 'acme.sh：tarball SHA256 校验失败已拒绝安装，Let'"'"'s Encrypt 自动签发不可用（退回自签证书保障基础 TLS）'
      fi
    else
      echo "[ACME] 网络受限，跳过 acme.sh 下载（不影响基础邮件收发与自签证书）"
      mark_degraded 'acme.sh：网络受限跳过下载，Let'"'"'s Encrypt 自动签发不可用（退回自签证书保障基础 TLS）'
    fi
    rm -f "$tmp"
  fi
  systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
}

# 4. Transactional Postfix Configuration
configure_postfix_base(){
  say '配置 Postfix 安全基线与投递通道'
  backup_path /etc/postfix
  local MAILNAME
  MAILNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")
  echo "postfix postfix/mailname string $MAILNAME" | debconf-set-selections 2>/dev/null || true

  postconf -e 'inet_interfaces = all'
  postconf -e 'inet_protocols = all'
  postconf -e 'mydestination = $myhostname, localhost.$mydomain, localhost'
  postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
  postconf -e 'smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
  postconf -e 'smtpd_sasl_type = dovecot'
  postconf -e 'smtpd_sasl_path = private/auth'
  postconf -e 'smtpd_sasl_auth_enable = yes'
  postconf -e 'smtpd_tls_auth_only = yes'
  postconf -e 'smtpd_tls_security_level = may'
  postconf -e 'smtp_tls_security_level = may'
  postconf -e 'mailbox_command ='
  postconf -e 'home_mailbox = Maildir/'
  postconf -e 'virtual_alias_maps = hash:/etc/postfix/mailstack_aliases'
  postconf -e 'virtual_alias_domains = hash:/etc/postfix/mailstack_domains'
  install -o root -g root -m 0644 /dev/null /etc/postfix/mailstack_domains
  install -o root -g root -m 0644 /dev/null /etc/postfix/mailstack_aliases
  postmap /etc/postfix/mailstack_domains
  postmap /etc/postfix/mailstack_aliases

  # Configure master.cf for submission (587) and smtps (465)
  if [[ -f /etc/postfix/master.cf ]]; then
    if ! grep -q '^submission' /etc/postfix/master.cf; then
      cat >>/etc/postfix/master.cf <<'EOF'

submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
EOF
    fi
  fi

  # Verify configuration
  if command -v postfix >/dev/null 2>&1; then
    if ! postfix check; then
      die 'Postfix 配置校验失败 (postfix check failed)'
    fi
  fi
}

write_dovecot_23(){
  cat >/etc/dovecot/dovecot.conf <<'EOF'
protocols = imap pop3 lmtp
listen = *, ::
!include conf.d/*.conf
EOF
  cat >/etc/dovecot/conf.d/99-mailstack.conf <<'EOF'
mail_location = maildir:~/Maildir
disable_plaintext_auth = yes
auth_mechanisms = plain login
ssl = required
ssl_cert = </etc/dovecot/private/dovecot.pem
ssl_key = </etc/dovecot/private/dovecot.key
passdb {
  driver = pam
}
userdb {
  driver = passwd
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
protocol lmtp {
  postmaster_address = postmaster@localhost
}
EOF
}

write_dovecot_24(){
  local version=$1
  cat >/etc/dovecot/dovecot.conf <<EOF
dovecot_config_version = $version
dovecot_storage_version = $version
protocols = imap pop3 lmtp
listen = *, ::
mail_driver = maildir
mail_path = ~/Maildir
ssl = yes
ssl_server_cert_file = /etc/dovecot/private/dovecot.pem
ssl_server_key_file = /etc/dovecot/private/dovecot.key
auth_mechanisms = plain login
passdb pam {
}
userdb passwd {
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  # Webmail 登录经 auth-client socket 校验密码（密码不进任何进程 argv）。
  # 本文件在 mailstack-webmail 账号创建前写入，属主只能用已存在的 dovecot；
  # webmail 服务以 dovecot 为附加组，经组权限获得写访问。
  unix_listener auth-client {
    mode = 0660
    user = dovecot
    group = dovecot
  }
}
protocol lmtp {
  postmaster_address = postmaster@localhost
}
EOF
}

ensure_bootstrap_cert(){
  install -d -m 0750 /etc/dovecot/private
  if [[ ! -s /etc/dovecot/private/dovecot.pem || ! -s /etc/dovecot/private/dovecot.key ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
      -subj '/CN=mailstack-bootstrap.local' \
      -keyout /etc/dovecot/private/dovecot.key \
      -out /etc/dovecot/private/dovecot.pem
    chmod 0600 /etc/dovecot/private/dovecot.key
    chmod 0644 /etc/dovecot/private/dovecot.pem
  fi
  mkdir -p /etc/pki/dovecot/certs /etc/pki/dovecot/private 2>/dev/null || true
  cp -f /etc/dovecot/private/dovecot.pem /etc/pki/dovecot/certs/dovecot.pem 2>/dev/null || true
  cp -f /etc/dovecot/private/dovecot.key /etc/pki/dovecot/private/dovecot.key 2>/dev/null || true
}

# 5. Transactional Dovecot Configuration
configure_dovecot(){
  say '按主版本配置 Dovecot 认证与 Maildir 存储'
  systemctl disable --now dovecot.socket 2>/dev/null || true
  backup_path /etc/dovecot
  local version; version=$(dovecot --version | awk '{print $1}' | sed 's/-.*//')
  install -d -m 0755 /etc/dovecot/conf.d
  find /etc/dovecot/conf.d -maxdepth 1 -type f -name '99-mailstack*.conf' -delete
  sed -i -E 's|^ssl_cert = .*|#ssl_cert|;s|^ssl_key = .*|#ssl_key|' /etc/dovecot/conf.d/10-ssl.conf 2>/dev/null || true
  ensure_bootstrap_cert
  if version_ge_24 "$version"; then
    write_dovecot_24 "$version"
  else
    write_dovecot_23
  fi

  # Validate Dovecot configuration syntax
  if command -v doveconf >/dev/null 2>&1; then
    if ! doveconf -n >/dev/null 2>&1; then
      doveconf 2>&1 | head -n 30
      die 'Dovecot 配置语法校验失败 (doveconf failed)'
    fi
  fi
}

# 6. Transactional OpenDKIM Configuration (Fixed Heredoc)
configure_opendkim(){
  # opendkim 安装失败时（如 openEuler 25.09 仓库无此包）全部跳过：
  # 配置、服务启动都以「已安装」为前提，降级后不得再碰 opendkim 相关文件/服务。
  if ! command -v opendkim >/dev/null 2>&1; then
    warn 'opendkim 未安装，跳过 DKIM 配置（DKIM 签名不可用，邮件收发不受影响；可后续手动安装 opendkim 后运行 dkim.rotate）'
    mark_degraded 'opendkim：仓库无包或未安装，DKIM 签名不可用（邮件收发不受影响；可后续手动安装 opendkim 后运行 dkim.rotate）'
    return 0
  fi
  say '配置 OpenDKIM 签名与验签引擎'
  backup_path /etc/opendkim.conf
  mkdir -p /etc/opendkim/keys
  chmod 0750 /etc/opendkim /etc/opendkim/keys 2>/dev/null || true
  chown -R opendkim:opendkim /etc/opendkim 2>/dev/null || true
  cat >/etc/opendkim.conf <<'EOF'
Syslog                  yes
UMask                   007
Mode                    sv
Canonicalization        relaxed/simple
OversignHeaders         From
Socket                  inet:8891@127.0.0.1
PidFile                 /run/opendkim/opendkim.pid
UserID                  opendkim
KeyTable                refile:/etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
ExternalIgnoreList      refile:/etc/opendkim/trusted.hosts
InternalHosts           refile:/etc/opendkim/trusted.hosts
EOF
  cat >/etc/opendkim/trusted.hosts <<'EOF'
127.0.0.1
::1
localhost
EOF
  : >/etc/opendkim/key.table
  : >/etc/opendkim/signing.table
  chown -R opendkim:opendkim /etc/opendkim 2>/dev/null || true
  chmod 0640 /etc/opendkim/key.table /etc/opendkim/signing.table /etc/opendkim/trusted.hosts 2>/dev/null || true
  install -d -o opendkim -g opendkim -m 0750 /run/opendkim 2>/dev/null || true
  usermod -a -G opendkim postfix 2>/dev/null || true
  # openSUSE / Arch 的 systemd unit 读 /etc/opendkim/opendkim.conf（非 /etc/opendkim.conf），
  # 不同步会导致 opendkim 报配置错误直接 exit 78（openSUSE 为出厂模板缺
  # KeyFile/Selector；Arch 为文件不存在 error reading）。一律同步。
  if [[ ! -f /etc/opendkim/opendkim.conf ]] || ! cmp -s /etc/opendkim.conf /etc/opendkim/opendkim.conf; then
    [[ -f /etc/opendkim/opendkim.conf ]] && backup_path /etc/opendkim/opendkim.conf
    cp -a /etc/opendkim.conf /etc/opendkim/opendkim.conf
    chown opendkim:opendkim /etc/opendkim/opendkim.conf 2>/dev/null || true
  fi

  postconf -e 'milter_default_action = accept'
  postconf -e 'milter_protocol = 6'
  postconf -e 'smtpd_milters = inet:127.0.0.1:8891'
  postconf -e 'non_smtpd_milters = inet:127.0.0.1:8891'
}

# 6.5 Fail2ban 真拦截：jail + filter + logpath + maxretry 全部落盘。
# 仅安装 fail2ban 包而不写 jail 等于没有爆破防护（doctor 按 operational 断言，
# 「装了但没 jail」是 FAIL 而非黄灯）。logpath/backend 变量 (%(postfix_log)s 等)
# 来自 fail2ban 自带的 paths-common/paths-<distro>.conf，各发行版均有定义。
#
# backend 探测：jail 默认变量在 systemd 系上解析为 backend=systemd，需要
# python3-systemd 模块；EL9 系该模块只为默认 python3.9 构建，而 MailStack 已把
# /usr/bin/python3 切到 3.11+（后端要求），systemd 后端初始化必崩（rc.5 OL9 实测：
# Backend 'systemd' failed to initialize due to No module named 'systemd'）。
# 探测不到模块时改走文件日志后端：rsyslog 把 mail 设施写入 /var/log/maillog，
# jail 用 backend=polling 直读；观测能力不变，只是少了 journald 过滤。
fail2ban_backend_ok(){
  python3 -c 'import systemd.journal' 2>/dev/null
}

configure_fail2ban(){
  say '配置 Fail2ban 爆破防护 (postfix-sasl / dovecot jail)'
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    warn 'fail2ban 未安装，跳过 jail 配置（doctor 会将爆破防护报告为不可用）'
    mark_degraded 'fail2ban：仓库无包且 pip 兜底失败，爆破防护不可用（doctor 会报告；可后续手动安装发行版 fail2ban 包）'
    return 0
  fi
  local f2b_backend f2b_logpath
  f2b_backend='%(postfix_backend)s'
  f2b_logpath='%(postfix_log)s'
  if ! fail2ban_backend_ok; then
    f2b_backend='polling'
    f2b_logpath='/var/log/maillog'
    # EL9 系默认 mail 日志只进 journald；给 rsyslog 补一条 mail 设施落盘规则，
    # polling 后端才有文件可读。部分发行版（openEuler 25.09 实测）默认不装
    # rsyslog，先用当前包管理器装上；装不上时该后端自然无日志可追。
    if [[ ! -d /etc/rsyslog.d ]]; then
      if command -v dnf >/dev/null 2>&1; then dnf install -y rsyslog 2>/dev/null || true
      elif command -v yum >/dev/null 2>&1; then yum install -y rsyslog 2>/dev/null || true
      elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install -y rsyslog 2>/dev/null || true
      elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog 2>/dev/null || true
      elif command -v pacman >/dev/null 2>&1; then pacman -S --noconfirm --needed rsyslog 2>/dev/null || true
      fi
    fi
    if [[ -d /etc/rsyslog.d ]]; then
      if ! grep -rq 'mail\.\*.*maillog' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
        printf 'mail.*    -/var/log/maillog\n' >/etc/rsyslog.d/20-mailstack-mail.conf
      fi
      systemctl restart rsyslog 2>/dev/null || true
    fi
    # maillog 预创建：无 rsyslog 的发行版（Alpine 3.24 busybox syslog 实测不落该文件）
    # 上 jail 的 logpath 文件缺失会让 fail2ban v1.1.0 直接拒启（Have not found any
    # log file for dovecot jail）。预建文件保证 jail 起得来，日志补齐后自动生效。
    if [[ ! -f /var/log/maillog ]]; then
      touch /var/log/maillog
      chmod 0640 /var/log/maillog 2>/dev/null || true
    fi
  fi
  install -d -m 0755 /etc/fail2ban/jail.d
  cat >/etc/fail2ban/jail.d/mailstack.conf <<EOF
# Managed by MailStack. Brute-force protection for SMTP AUTH and IMAP/POP3.
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[postfix-sasl]
enabled = true
port    = smtp,465,submission
logpath = ${f2b_logpath}
backend = ${f2b_backend}
maxretry = 5

[dovecot]
enabled = true
port    = imap,imaps,pop3,pop3s
logpath = ${f2b_logpath}
backend = ${f2b_backend}
maxretry = 5
EOF
  chmod 0644 /etc/fail2ban/jail.d/mailstack.conf
  # pip 安装的 fail2ban 不带 systemd unit（发行版包才有），补写一个再启用。
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1 \
     && ! systemctl cat fail2ban >/dev/null 2>&1; then
    cat >/etc/systemd/system/fail2ban.service <<'UNIT'
[Unit]
Description=Fail2Ban Service (MailStack pip fallback)
After=network.target

[Service]
Type=exec
ExecStartPre=/bin/mkdir -p /run/fail2ban
ExecStart=/usr/bin/env fail2ban-server -xf start
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload 2>/dev/null || true
  fi
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl unmask fail2ban 2>/dev/null || true
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || systemctl start fail2ban 2>/dev/null || true
  elif command -v rc-service >/dev/null 2>&1; then
    prepare_openrc_env
    rc-update add fail2ban default 2>/dev/null || true
    rc-service fail2ban restart 2>/dev/null || rc-service fail2ban start 2>/dev/null || true
  else
    service fail2ban restart 2>/dev/null || service fail2ban start 2>/dev/null || true
  fi
}

# 7. Start & Verify Service Loop
start_and_verify(){
  say '启动并验证邮件服务'
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now dovecot.socket 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    for svc in opendkim postfix dovecot; do
      systemctl unmask "$svc" 2>/dev/null || true
      systemctl --no-ask-password enable "$svc" 2>/dev/null || true
      systemctl --no-ask-password restart "$svc" 2>/dev/null || systemctl --no-ask-password start "$svc" 2>/dev/null || service "$svc" restart 2>/dev/null || service "$svc" start 2>/dev/null || true
      if ! systemctl is-active --quiet "$svc" && ! service "$svc" status >/dev/null 2>&1; then
        journalctl -u "$svc" -n 30 --no-pager 2>/dev/null || true
        # Attempt direct binary fallback if daemon is not started
        if [[ "$svc" == "opendkim" ]]; then
          # opendkim 可能因仓库缺包被降级跳过（仅当已安装时才尝试直启）
          command -v opendkim >/dev/null 2>&1 && { /usr/sbin/opendkim -x /etc/opendkim.conf 2>/dev/null || true; }
        elif [[ "$svc" == "postfix" ]]; then
          postfix start 2>/dev/null || true
        elif [[ "$svc" == "dovecot" ]]; then
          dovecot 2>/dev/null || true
        fi
      fi
    done
  elif command -v rc-service >/dev/null 2>&1; then
    prepare_openrc_env
    for svc in opendkim postfix dovecot; do
      rc-update add "$svc" default 2>/dev/null || true
      rc-service "$svc" restart || rc-service "$svc" start || true
    done
  else
    if command -v opendkim >/dev/null 2>&1; then
      service opendkim restart 2>/dev/null || service opendkim start 2>/dev/null || /usr/sbin/opendkim -x /etc/opendkim.conf 2>/dev/null || true
    fi
    postfix stop 2>/dev/null || true
    postfix start 2>/dev/null || service postfix restart 2>/dev/null || service postfix start 2>/dev/null || true
    dovecot stop 2>/dev/null || true
    dovecot 2>/dev/null || service dovecot restart 2>/dev/null || service dovecot start 2>/dev/null || true
  fi

  # Port verification
  if command -v ss >/dev/null 2>&1; then
    # 原实现 `... || true` 永远不会失败，等于没有验证。改为：监听缺失时明确告警，
    # 但不中断安装（服务异步启动、ss 输出格式差异都可能造成误报，交给末尾健康自检兜底）。
    listeners=$(ss -lntp | grep -E ':(25|143|993|8891)\b' || true)
    if [[ -n "$listeners" ]]; then
      echo "$listeners"
    else
      warn '未检测到 25/143/993/8891 端口监听，邮件服务可能未正常启动，请检查服务状态与日志'
    fi
  fi
}

main(){
  need_root
  log_platform_tier
  install_packages
  install_acme_client
  configure_postfix_base
  configure_dovecot
  configure_opendkim
  configure_fail2ban
  start_and_verify
  if command -v opendkim >/dev/null 2>&1; then
    say '邮件基础栈 (Postfix + Dovecot + OpenDKIM) 安装与校验成功'
  else
    say '邮件基础栈 (Postfix + Dovecot) 安装与校验成功（OpenDKIM 缺失：DKIM 签名不可用，邮件收发不受影响）'
  fi
  print_degradation_summary
}
main "$@"

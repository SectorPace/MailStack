#!/usr/bin/env bash
# MailStack 容器入口脚本（无 systemd 进程编排）。
#
# 职责：
#   1. 首次启动时把构建期快照的配置种子回填到（可能为空的）数据卷；
#   2. 首次启动初始化管理员凭证（环境变量给口令，或生成随机口令并只打印一次）；
#   3. 顺序拉起 6 个关键进程（全部日志直通 stdout/stderr，即 docker logs）：
#        helper   python3 mailstackctl.py --daemon   (root, /run/mailstack/helper{,-ro}.sock)
#        postfix  postfix start-fg                   (25/465/587)
#        dovecot  dovecot -F                         (143/993/110/995)
#        opendkim opendkim -f                        (可选，装了才启动)
#        admin    node /opt/mailstack/server.cjs     (mailstack-admin, 8787)
#        webmail  node /opt/mailstack/webmail.cjs    (mailstack-webmail, 18788)
#   4. 监督循环：任一关键进程退出即整体非零退出，交由容器重启策略接管；
#      不引入 supervisor 类依赖（tini 作 PID1 负责信号转发与僵尸回收）。
#
# 与裸机安装的差异：安装器的 init-d 分支不会启动 helper，这里显式补上；
# systemd 单元在容器内不生效。管理口默认仍绑回环 127.0.0.1（A6）——与裸机
# 「面板回环 + 前置 TLS 反代」模型一致；确需把管理面板发布到容器网络外，必须
# 显式双旗标（MAILSTACK_LISTEN_HOST=<非回环> 且 MAILSTACK_I_PUBLISH_ADMIN=1），
# 否则 gate_listen_host 拒绝启动。裸 `docker run -p 8787:8787`（无双旗标）起不来。
set -Eeuo pipefail

SEED_DIR=/opt/mailstack-seed
ADMIN_PORT=${MAILSTACK_ADMIN_PORT:-8787}
WEBMAIL_PORT=${MAILSTACK_WEBMAIL_PORT:-18788}
# A6：管理口默认绑回环 127.0.0.1。容器内 0.0.0.0 会让 -p 映射把管理面板直接
# 暴露到宿主网卡，绕过裸机的「面板回环 + TLS 反代」模型。要发布到容器网络外，
# 必须显式同时给出 MAILSTACK_LISTEN_HOST=<非回环> 与 MAILSTACK_I_PUBLISH_ADMIN=1
# （见 gate_listen_host）；docker-compose.yml 已按此显式声明。
LISTEN_HOST=${MAILSTACK_LISTEN_HOST:-127.0.0.1}
COOKIE_SECURE=${MAILSTACK_COOKIE_SECURE:-0}
ADMIN_USER=${MAILSTACK_ADMIN_USER:-admin}
# 门控/DRYRUN 测试路径可能没有 node；用 || true 避免 set -e 在到达 gate 前中止。
NODE_BIN=$(command -v node || true)

log(){ printf '[mailstack-entrypoint] %s\n' "$*"; }

# A6 管理口发布门控：非回环监听（把面板暴露到容器网络外）必须同时满足
#   1) 显式设置 MAILSTACK_LISTEN_HOST=<非回环>（默认 127.0.0.1 时不触发本门），
#   2) 显式 MAILSTACK_I_PUBLISH_ADMIN=1（表明运维确知此举绕过回环+反代模型）。
# 任一缺失即打印拒绝原因并非零退出；DRYRUN 下门控通过后由 main 提前退出（T-DOCK-1）。
gate_listen_host(){
  case "$LISTEN_HOST" in
    127.0.0.1|::1|localhost)
      return 0
      ;;
  esac
  if [[ -z "${MAILSTACK_LISTEN_HOST:-}" ]]; then
    log "拒绝启动：LISTEN_HOST=$LISTEN_HOST 为非回环地址，但未显式设置 MAILSTACK_LISTEN_HOST。"
    log "  管理面板默认绑回环 127.0.0.1；确需发布到容器网络外，请显式设置 MAILSTACK_LISTEN_HOST=<地址> 且 MAILSTACK_I_PUBLISH_ADMIN=1。"
    exit 1
  fi
  if [[ "${MAILSTACK_I_PUBLISH_ADMIN:-0}" != "1" ]]; then
    log "拒绝启动：MAILSTACK_LISTEN_HOST=$LISTEN_HOST 为非回环地址，但缺少 MAILSTACK_I_PUBLISH_ADMIN=1。"
    log "  非回环管理口会把面板直接暴露到容器网络外（绕过裸机的回环+TLS 反代模型）。"
    log "  确需发布请同时设置 MAILSTACK_I_PUBLISH_ADMIN=1；否则请移除 MAILSTACK_LISTEN_HOST 回到默认 127.0.0.1。"
    exit 1
  fi
  log "已显式发布管理口：LISTEN_HOST=$LISTEN_HOST（MAILSTACK_I_PUBLISH_ADMIN=1）。请确保宿主侧 -p 绑定与 TLS 终结到位。"
}

# 目标目录为空（空的命名卷/绑定挂载）时用构建期快照回填。
# 非空目录绝不覆盖：数据卷里是既有部署的真实状态。
seed_if_empty(){
  local target=$1 seed=$2
  [[ -d "$seed" ]] || return 0
  [[ -d "$target" ]] || install -d "$target"
  if [[ -z "$(ls -A "$target" 2>/dev/null)" ]]; then
    log "首次启动：回填 $target <- $seed"
    cp -a "$seed"/. "$target"/
  fi
}

seed_state(){
  seed_if_empty /etc/mailstack        "$SEED_DIR/etc-mailstack"
  seed_if_empty /etc/postfix          "$SEED_DIR/etc-postfix"
  seed_if_empty /etc/dovecot          "$SEED_DIR/etc-dovecot"
  seed_if_empty /var/spool/postfix    "$SEED_DIR/var-spool-postfix"
  seed_if_empty /var/lib/mailstack    "$SEED_DIR/var-lib-mailstack"
  seed_if_empty /etc/opendkim         "$SEED_DIR/etc-opendkim"
  # opendkim.conf 是文件（不在 /etc/opendkim 目录内），单独处理
  if [[ -f "$SEED_DIR/etc-opendkim.conf" && ! -f /etc/opendkim.conf ]]; then
    cp -a "$SEED_DIR/etc-opendkim.conf" /etc/opendkim.conf
  fi
  install -d -m 0700 /var/backups/mailstack
  # /run 每次容器启动都是空的：opendkim 的 PidFile 目录需要重建
  if command -v opendkim >/dev/null 2>&1; then
    install -d -o opendkim -g opendkim -m 0750 /run/opendkim
  fi
}

# 管理员口令策略与安装器保持一致：12-256 位且同时含字母与数字；
# 完整策略（禁 3 相同/连续字符、禁身份 token）由后端权威执行。
validate_admin_password(){
  local pass=$1
  [[ ${#pass} -ge 12 && ${#pass} -le 256 ]] || return 1
  [[ $pass =~ [A-Za-z] ]] || return 1
  [[ $pass =~ [0-9] ]] || return 1
  return 0
}

init_admin(){
  if [[ -s /etc/mailstack/admin.json ]]; then
    log "管理员凭证已存在（/etc/mailstack/admin.json），跳过初始化"
    return 0
  fi
  local pass generated=0
  if [[ -n "${MAILSTACK_ADMIN_PASSWORD:-}" ]]; then
    pass="$MAILSTACK_ADMIN_PASSWORD"
  else
    # 前缀保证字母类，后缀保证数字类，随机段提供熵；口令从不写入镜像层。
    pass="MailStack-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)-7Kx"
    generated=1
  fi
  validate_admin_password "$pass" || {
    log '错误: MAILSTACK_ADMIN_PASSWORD 不满足策略（12-256 位，须同时含字母与数字）'
    exit 1
  }
  # 与 deploy/install.sh 完全相同的哈希方式（密码经环境变量传递，不进 argv）。
  MAILSTACK_ADMIN_PASS="$pass" python3 - "$ADMIN_USER" <<'PY'
import json,hashlib,secrets,sys,os
u=sys.argv[1]; p=os.environ['MAILSTACK_ADMIN_PASS']; os.unsetenv('MAILSTACK_ADMIN_PASS')
salt=secrets.token_bytes(16); it=310000; h=hashlib.pbkdf2_hmac('sha256',p.encode(),salt,it,32)
f='/etc/mailstack/admin.json'; open(f,'w').write(json.dumps({'username':u,'algorithm':'pbkdf2-sha256','iterations':it,'salt':salt.hex(),'hash':h.hex()},indent=2)+'\n'); os.chmod(f,0o640)
PY
  chown root:mailstack-admin /etc/mailstack/admin.json
  chmod 0640 /etc/mailstack/admin.json
  if ((generated)); then
    log '==============================================================='
    log '  首次启动：已生成随机管理员口令（仅本次打印，请立即妥善保存）'
    log "  用户名: $ADMIN_USER"
    log "  密  码: $pass"
    log '  下次启动可用环境变量 MAILSTACK_ADMIN_PASSWORD 指定（新卷时生效）'
    log '==============================================================='
  else
    log "管理员 $ADMIN_USER 凭证已按 MAILSTACK_ADMIN_PASSWORD 初始化"
  fi
  # A6：init_admin 完成后立即清除口令。后续进程编排不再需要 pass/MAILSTACK_ADMIN_PASSWORD，
  # 而 admin/webmail 子进程会继承环境变量——不 unset 则明文口令驻留在 PID1 环境里，
  # 经 /proc/1/environ 可被容器内任何进程读到。pass 为 local，unset 只影响本函数作用域。
  unset MAILSTACK_ADMIN_PASSWORD pass
}

declare -a PROC_NAMES=() PROC_PIDS=()

start_proc(){
  local name=$1; shift
  "$@" &
  PROC_NAMES+=("$name"); PROC_PIDS+=("$!")
  log "已启动 $name (pid $!)"
}

shutdown_all(){
  local i
  for i in "${!PROC_PIDS[@]}"; do
    kill -TERM "${PROC_PIDS[$i]}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}

on_signal(){
  log '收到终止信号，正在停止全部服务...'
  shutdown_all
  exit 0
}
trap on_signal TERM INT

main(){
  log "MailStack 容器启动（无 systemd 编排，tini + shell 监督）"
  gate_listen_host
  if [[ "${MAILSTACK_ENTRYPOINT_DRYRUN:-0}" == "1" ]]; then
    log "DRYRUN：管理口门控通过，LISTEN_HOST=$LISTEN_HOST，跳过种子回填/凭证初始化/进程编排。"
    exit 0
  fi
  seed_state
  init_admin

  # 1) 特权 helper：其余服务的控制面动作（域名/用户/证书等）经它的
  #    unix socket 走；必须先于管理面就绪。
  #    A2 的 SO_PEERCRED 对端凭据校验在容器内同样生效：即便 helper 与管理面
  #    都是 root（uid=0）也不跳过校验——peercred 是“确知对端 uid/pid”的强制
  #    门禁而非“只挡低权进程”，root 对 root 一样要过 socket 凭据核对。
  #    B1 双 socket：同一命令同进程绑 helper-ro.sock（0660 root:mailstack-admin，
  #    只读 action 面）与 helper.sock（0600 root:root，变更面）。admin 以
  #    mailstack-admin 运行，直连 ro 面取只读数据；变更动作仍经 sudo 包装器
  #    （镜像构建期 install.sh 已配好单条 sudoers）。ro 面收到变更 action 同样
  #    被拒绝并审计 ro_channel_violation——通道而非 uid 决定 action 子集。
  start_proc helper python3 /opt/mailstack/backend/mailstackctl.py --daemon

  # 2) 邮件基础栈（与安装器 start_and_verify 的无 systemd 分支一致，
  #    这里改用前台模式以便监督循环感知退出）。
  start_proc postfix postfix start-fg
  start_proc dovecot dovecot -F
  if command -v opendkim >/dev/null 2>&1; then
    start_proc opendkim /usr/sbin/opendkim -f -x /etc/opendkim.conf
  else
    log 'opendkim 未安装：DKIM 签名不可用（降级，与安装器行为一致）'
  fi

  # 3) 管理面与 Webmail（以服务账号运行，环境变量与安装器 systemd 单元对齐）。
  start_proc admin runuser -u mailstack-admin -- \
    env NODE_ENV=production PORT="$ADMIN_PORT" HOST="$LISTEN_HOST" \
        COOKIE_SECURE="$COOKIE_SECURE" DIST_DIR=/opt/mailstack/ui/dist \
    "$NODE_BIN" /opt/mailstack/server.cjs
  start_proc webmail runuser -u mailstack-webmail -- \
    env NODE_ENV=production WEBMAIL_PORT="$WEBMAIL_PORT" WEBMAIL_HOST="$LISTEN_HOST" \
        WEBMAIL_PUBLIC_DIR=/opt/mailstack/webmail-public COOKIE_SECURE="$COOKIE_SECURE" \
    "$NODE_BIN" /opt/mailstack/webmail.cjs

  log "全部进程已拉起：管理面 $LISTEN_HOST:$ADMIN_PORT / Webmail $LISTEN_HOST:$WEBMAIL_PORT"

  # 监督循环：任一关键进程消失 → 整体退出（非零），容器重启策略接管。
  while :; do
    wait -n "${PROC_PIDS[@]}" 2>/dev/null || true
    local i dead=''
    for i in "${!PROC_PIDS[@]}"; do
      if ! kill -0 "${PROC_PIDS[$i]}" 2>/dev/null; then
        dead="${PROC_NAMES[$i]}"
      fi
    done
    if [[ -n "$dead" ]]; then
      log "关键进程 [$dead] 已退出，终止其余进程并以非零码退出（交由重启策略拉起）"
      shutdown_all
      exit 1
    fi
  done
}

main "$@"

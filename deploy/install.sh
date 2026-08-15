#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo '请使用 root 运行'; exit 1; }
BASE=$(cd "$(dirname "$0")/.." && pwd)
ADMIN_USER='admin'; ADMIN_PASS=''; ADMIN_PORT='8787'; ADMIN_HOST='127.0.0.1'; NONINTERACTIVE=0; REUSE_ADMIN=0
usage(){ cat <<EOF
用法: $0 [选项]
  --admin-user NAME       Web 管理员用户名
  --admin-port PORT       管理端口，默认 8787
  --admin-host ADDRESS    127.0.0.1、::1 或 0.0.0.0
  --admin-password-stdin  从标准输入读取密码
  --non-interactive       非交互安装，必须通过 stdin 提供密码
EOF
}
while (($#)); do case $1 in --admin-user) ADMIN_USER=$2;shift 2;;--admin-port) ADMIN_PORT=$2;shift 2;;--admin-host) ADMIN_HOST=$2;shift 2;;--admin-password-stdin) IFS= read -r ADMIN_PASS;shift;;--non-interactive) NONINTERACTIVE=1;shift;;--reuse-admin) REUSE_ADMIN=1;NONINTERACTIVE=1;shift;;-h|--help) usage;exit;;*) echo "未知参数: $1";usage;exit 1;;esac;done
[[ $ADMIN_USER =~ ^[A-Za-z][A-Za-z0-9_.-]{2,31}$ ]] || { echo '管理员用户名格式不正确'; exit 1; }
[[ $ADMIN_PORT =~ ^[0-9]+$ ]] && ((ADMIN_PORT>=1024&&ADMIN_PORT<=65535)) || { echo '管理端口必须为 1024-65535'; exit 1; }
[[ $ADMIN_HOST == 127.0.0.1 || $ADMIN_HOST == ::1 || $ADMIN_HOST == 0.0.0.0 ]] || { echo '管理地址只允许 127.0.0.1、::1、0.0.0.0'; exit 1; }
if [[ -z $ADMIN_PASS && $NONINTERACTIVE -eq 0 ]]; then
 read -r -p "管理员用户名 [$ADMIN_USER]: " x; ADMIN_USER=${x:-$ADMIN_USER}
 read -r -p "管理端口 [$ADMIN_PORT]: " x; ADMIN_PORT=${x:-$ADMIN_PORT}
 read -r -p "监听地址 [$ADMIN_HOST]: " x; ADMIN_HOST=${x:-$ADMIN_HOST}
 while :; do read -r -s -p '管理员密码（至少 12 个字符）: ' ADMIN_PASS;echo;read -r -s -p '再次输入密码: ' p2;echo;[[ $ADMIN_PASS == "$p2" && ${#ADMIN_PASS} -ge 12 ]]&&break;echo '密码不一致或不足 12 个字符。';done
fi
if ((REUSE_ADMIN)); then [[ -s /etc/mailstack/admin.json ]] || { echo '没有可复用的管理员配置'; exit 1; }; else [[ ${#ADMIN_PASS} -ge 12 ]] || { echo '必须提供至少 12 个字符的密码'; exit 1; }; fi
if [[ $ADMIN_HOST == 0.0.0.0 && $NONINTERACTIVE -eq 0 ]]; then read -r -p '警告：公网监听必须额外配置 HTTPS 和防火墙。输入 PUBLIC 确认: ' x;[[ $x == PUBLIC ]]||exit 1;fi
for c in node npm python3 systemctl sudo;do command -v "$c" >/dev/null||{ echo "缺少命令: $c";exit 1;};done
install -d -m 0755 /opt/mailstack/ui /opt/mailstack/backend
cp -a "$BASE/src" "$BASE/index.html" "$BASE/package.json" "$BASE/vite.config.ts" "$BASE/tsconfig.json" /opt/mailstack/ui/
cp "$BASE/backend/mailstackctl.py" /opt/mailstack/backend/mailstackctl.py;chmod 0755 /opt/mailstack/backend/mailstackctl.py
cp "$BASE/deploy/mailstack-cli" /usr/local/bin/mailstack;chmod 0755 /usr/local/bin/mailstack
cd /opt/mailstack/ui;npm install --omit=optional;npm run build
npx esbuild "$BASE/backend/server.production.ts" --bundle --platform=node --format=cjs --packages=external --outfile=/opt/mailstack/server.cjs
getent group mailstack-admin >/dev/null||groupadd --system mailstack-admin
id mailstack-admin >/dev/null 2>&1||useradd --system -g mailstack-admin -d /nonexistent -s /usr/sbin/nologin mailstack-admin
install -d -o root -g mailstack-admin -m 0750 /etc/mailstack
if ((REUSE_ADMIN==0)); then
python3 - "$ADMIN_USER" "$ADMIN_PASS" <<'PY'
import json,hashlib,secrets,sys,os,grp
u,p=sys.argv[1:];salt=secrets.token_bytes(16);it=310000;h=hashlib.pbkdf2_hmac('sha256',p.encode(),salt,it,32)
f='/etc/mailstack/admin.json';open(f,'w').write(json.dumps({'username':u,'algorithm':'pbkdf2-sha256','iterations':it,'salt':salt.hex(),'hash':h.hex()},indent=2)+'\n');os.chmod(f,0o640);os.chown(f,0,grp.getgrnam('mailstack-admin').gr_gid)
PY
fi
cat >/etc/sudoers.d/mailstack-web <<'EOF'
mailstack-admin ALL=(root) NOPASSWD: /opt/mailstack/backend/mailstackctl.py
EOF
chmod 0440 /etc/sudoers.d/mailstack-web;visudo -cf /etc/sudoers.d/mailstack-web
cat >/etc/systemd/system/mailstack-web.service <<EOF
[Unit]
Description=MailStack Admin Console
After=network.target postfix.service dovecot.service
[Service]
User=mailstack-admin
Group=mailstack-admin
WorkingDirectory=/opt/mailstack
Environment=NODE_ENV=production
Environment=PORT=$ADMIN_PORT
Environment=HOST=$ADMIN_HOST
Environment=DIST_DIR=/opt/mailstack/ui/dist
ExecStart=/usr/bin/node /opt/mailstack/server.cjs
Restart=on-failure
PrivateTmp=true
ProtectHome=false
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload;systemctl enable --now mailstack-web
printf '\n安装完成。管理员: %s\n监听地址: %s:%s\n快捷命令: mailstack\n' "$ADMIN_USER" "$ADMIN_HOST" "$ADMIN_PORT"
[[ $ADMIN_HOST == 127.0.0.1 ]]&&echo "SSH 隧道: ssh -L $ADMIN_PORT:127.0.0.1:$ADMIN_PORT root@服务器IP"

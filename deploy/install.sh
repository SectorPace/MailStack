#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo '请使用 root 运行'; exit 1; }
BASE=$(cd "$(dirname "$0")/.." && pwd)
ADMIN_USER='admin'; ADMIN_PASS=''; ADMIN_PORT='8787'; ADMIN_HOST='0.0.0.0'; NONINTERACTIVE=0; REUSE_ADMIN=0
usage(){ cat <<EOF
用法: $0 [选项]
  --admin-user NAME       Web 管理员用户名
  --admin-port PORT       管理端口，默认 8787
  --admin-host ADDRESS    127.0.0.1、::1 或 0.0.0.0
  --admin-password-stdin  从标准输入读取密码
  --non-interactive       非交互安装，必须通过 stdin 提供密码
  --reuse-admin           更新时保留现有管理员配置
EOF
}
while (($#)); do case $1 in
 --admin-user) ADMIN_USER=$2;shift 2;; --admin-port) ADMIN_PORT=$2;shift 2;;
 --admin-host) ADMIN_HOST=$2;shift 2;; --admin-password-stdin) IFS= read -r ADMIN_PASS;shift;;
 --non-interactive) NONINTERACTIVE=1;shift;; --reuse-admin) REUSE_ADMIN=1;NONINTERACTIVE=1;shift;;
 -h|--help) usage;exit;; *) echo "未知参数: $1";usage;exit 1;; esac; done

install_dependencies(){
 if command -v apt-get >/dev/null 2>&1; then
   export DEBIAN_FRONTEND=noninteractive
   apt-get update
   apt-get install -y ca-certificates curl git gnupg python3 rsync sudo tar
   if ! command -v node >/dev/null 2>&1 || [[ $(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || echo 0) -lt 20 ]]; then
     curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
     apt-get install -y nodejs
   fi
 elif command -v dnf >/dev/null 2>&1; then
   dnf install -y ca-certificates curl git python3 rsync sudo tar nodejs npm
 elif command -v yum >/dev/null 2>&1; then
   yum install -y ca-certificates curl git python3 rsync sudo tar nodejs npm
 elif command -v zypper >/dev/null 2>&1; then
   zypper --non-interactive install ca-certificates curl git python3 rsync sudo tar nodejs npm
 elif command -v pacman >/dev/null 2>&1; then
   pacman -Sy --noconfirm ca-certificates curl git python rsync sudo tar nodejs npm
 else
   echo '无法识别包管理器，请手动安装 Node.js 20+、npm、Python 3、sudo、rsync、git 和 tar。' >&2
   exit 1
 fi
 for c in node npm python3 systemctl sudo rsync tar; do command -v "$c" >/dev/null || { echo "缺少命令: $c"; exit 1; }; done
 local major; major=$(node -p 'Number(process.versions.node.split(".")[0])')
 ((major>=20)) || { echo "Node.js 版本过低: $(node --version)，需要 20 或更高版本"; exit 1; }
}
install_dependencies

if ((REUSE_ADMIN)); then
 [[ -s /etc/mailstack/admin.json ]] || { echo '没有可复用的管理员配置'; exit 1; }
 if [[ -f /etc/systemd/system/mailstack-web.service ]]; then
   ADMIN_PORT=$(sed -n 's/^Environment=PORT=//p' /etc/systemd/system/mailstack-web.service | tail -n1); ADMIN_PORT=${ADMIN_PORT:-8787}
   ADMIN_HOST=$(sed -n 's/^Environment=HOST=//p' /etc/systemd/system/mailstack-web.service | tail -n1); ADMIN_HOST=${ADMIN_HOST:-127.0.0.1}
 fi
else
 if [[ -z $ADMIN_PASS && $NONINTERACTIVE -eq 0 ]]; then
   read -r -p "管理员用户名 [$ADMIN_USER]: " x; ADMIN_USER=${x:-$ADMIN_USER}
   read -r -p "管理端口 [$ADMIN_PORT]: " x; ADMIN_PORT=${x:-$ADMIN_PORT}
   read -r -p "监听地址 [$ADMIN_HOST]: " x; ADMIN_HOST=${x:-$ADMIN_HOST}
   while :; do
     read -r -s -p '管理员密码（至少 12 个字符）: ' ADMIN_PASS; echo
     read -r -s -p '再次输入密码: ' p2; echo
     [[ $ADMIN_PASS == "$p2" && ${#ADMIN_PASS} -ge 12 ]] && break
     echo '密码不一致或不足 12 个字符。'
   done
 fi
 [[ ${#ADMIN_PASS} -ge 12 ]] || { echo '必须提供至少 12 个字符的密码'; exit 1; }
fi
[[ $ADMIN_USER =~ ^[A-Za-z][A-Za-z0-9_.-]{2,31}$ ]] || { echo '管理员用户名格式不正确'; exit 1; }
[[ $ADMIN_PORT =~ ^[0-9]+$ ]] && ((ADMIN_PORT>=1024&&ADMIN_PORT<=65535)) || { echo '管理端口必须为 1024-65535'; exit 1; }
[[ $ADMIN_HOST == 127.0.0.1 || $ADMIN_HOST == ::1 || $ADMIN_HOST == 0.0.0.0 ]] || { echo '管理地址只允许 127.0.0.1、::1、0.0.0.0'; exit 1; }
if [[ $ADMIN_HOST == 0.0.0.0 ]]; then
 echo '提示：管理后台将监听公网地址，请配置云安全组、防火墙和 HTTPS。'
fi

install -d -m 0755 /opt/mailstack/ui /opt/mailstack/backend
rm -rf /opt/mailstack/ui/src /opt/mailstack/ui/dist /opt/mailstack/ui/node_modules
cp -a "$BASE/src" "$BASE/index.html" "$BASE/package.json" "$BASE/vite.config.ts" "$BASE/tsconfig.json" /opt/mailstack/ui/
cp "$BASE/backend/mailstackctl.py" /opt/mailstack/backend/mailstackctl.py
chmod 0755 /opt/mailstack/backend/mailstackctl.py
cp "$BASE/deploy/mailstack-cli" /usr/local/bin/ms
chmod 0755 /usr/local/bin/ms
ln -sfn /usr/local/bin/ms /usr/local/bin/mailstack

cd /opt/mailstack/ui
rm -f package-lock.json
npm install --include=optional
npm run build
# Build the authenticated production backend independently. It is bundled with Express,
# so runtime module resolution does not depend on /opt/mailstack/ui/node_modules.
npx --no-install esbuild "$BASE/backend/server.production.ts" \
  --bundle --platform=node --format=cjs --sourcemap \
  --outfile=/opt/mailstack/server.cjs
[[ -s /opt/mailstack/ui/dist/index.html ]] || { echo '前端构建失败：缺少 dist/index.html'; exit 1; }
[[ -s /opt/mailstack/server.cjs ]] || { echo '后端构建失败：缺少 server.cjs'; exit 1; }

getent group mailstack-admin >/dev/null || groupadd --system mailstack-admin
id mailstack-admin >/dev/null 2>&1 || useradd --system -g mailstack-admin -d /nonexistent -s /usr/sbin/nologin mailstack-admin
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
chmod 0440 /etc/sudoers.d/mailstack-web
visudo -cf /etc/sudoers.d/mailstack-web
cat >/etc/systemd/system/mailstack-web.service <<EOF
[Unit]
Description=MailStack Admin Console
After=network.target
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
RestartSec=3
PrivateTmp=true
ProtectHome=false
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now mailstack-web
sleep 2
systemctl is-active --quiet mailstack-web || { journalctl -u mailstack-web -n 80 --no-pager; exit 1; }
HEALTH_HOST='127.0.0.1'
[[ $ADMIN_HOST == '::1' ]] && HEALTH_HOST='[::1]'
curl -fsS "http://$HEALTH_HOST:$ADMIN_PORT/api/health" >/dev/null || { echo '后台健康检查失败'; journalctl -u mailstack-web -n 80 --no-pager; exit 1; }
printf '\n安装完成。管理员: %s\n监听地址: %s:%s\n快捷命令: ms（兼容命令: mailstack）\n' "$ADMIN_USER" "$ADMIN_HOST" "$ADMIN_PORT"
[[ $ADMIN_HOST == 127.0.0.1 ]] && echo "SSH 隧道: ssh -L $ADMIN_PORT:127.0.0.1:$ADMIN_PORT root@服务器IP"

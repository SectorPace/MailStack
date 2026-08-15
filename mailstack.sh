#!/usr/bin/env bash
set -Eeuo pipefail
VERSION="v0.1-beta1"
REPO_URL="${MAILSTACK_REPO_URL:-https://github.com/SectorPace/MailStack.git}"
INSTALL_DIR="/opt/mailstack-source"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || exec sudo -- "$SELF" "$@"; }
usage(){ cat <<EOF
MailStack ${VERSION}

用法：
  sudo bash mailstack.sh install [安装选项]
  sudo bash mailstack.sh update
  sudo bash mailstack.sh uninstall [--purge]
  sudo bash mailstack.sh status
  sudo bash mailstack.sh logs
  sudo bash mailstack.sh admin
  sudo bash mailstack.sh port
  bash mailstack.sh version
  bash mailstack.sh help

安装选项透传给 deploy/install.sh：
  --admin-user NAME
  --admin-port PORT
  --admin-host 127.0.0.1|::1|0.0.0.0
  --admin-password-stdin
  --non-interactive

安装完成后的快捷命令：
  ms
  ms admin
  ms port
  ms status
  ms logs

兼容命令：mailstack
EOF
}
copy_source(){
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  tar -C "$(dirname "$SELF")" \
    --exclude=.git --exclude=node_modules --exclude=dist \
    -cf - . | tar -C "$INSTALL_DIR" -xf -
}
install_cmd(){
  need_root install "$@"
  copy_source
  green "正在运行 MailStack 安装器..."
  bash "$INSTALL_DIR/deploy/install.sh" "$@"
  green "安装完成。以后在 VPS 直接运行：ms"
}
update_cmd(){
  need_root update
  command -v git >/dev/null || { red "缺少 git"; exit 1; }
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  green "正在从 GitHub 获取最新版本..."
  git clone --depth 1 "$REPO_URL" "$tmp/repo"
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  tar -C "$tmp/repo" --exclude=.git --exclude=node_modules --exclude=dist -cf - . | tar -C "$INSTALL_DIR" -xf -
  bash "$INSTALL_DIR/deploy/install.sh" --reuse-admin
  green "更新完成。"
}
uninstall_cmd(){
  need_root uninstall "$@"
  local purge=0
  [[ ${1:-} == --purge ]] && purge=1
  systemctl disable --now mailstack-web 2>/dev/null || true
  rm -f /etc/systemd/system/mailstack-web.service /etc/sudoers.d/mailstack-web /usr/local/bin/mailstack /usr/local/bin/ms
  systemctl daemon-reload
  rm -rf /opt/mailstack /opt/mailstack-source
  if ((purge)); then
    rm -rf /etc/mailstack
    green "MailStack 程序和管理配置已删除。Postfix、Dovecot 与邮件数据未自动删除。"
  else
    green "MailStack 程序已删除，/etc/mailstack 管理配置已保留。"
  fi
}
cmd=${1:-help}; shift || true
case "$cmd" in
  install) install_cmd "$@";;
  update) update_cmd;;
  uninstall) uninstall_cmd "$@";;
  status) need_root status; systemctl --no-pager status mailstack-web || true;;
  logs) need_root logs; journalctl -u mailstack-web -f;;
  admin) need_root admin; /usr/local/bin/ms admin;;
  port) need_root port; /usr/local/bin/ms port;;
  menu) need_root menu; /usr/local/bin/ms menu;;
  version|-v|--version) echo "$VERSION";;
  help|-h|--help) usage;;
  *) red "未知命令：$cmd"; usage; exit 1;;
esac

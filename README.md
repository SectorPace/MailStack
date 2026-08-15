# MailStack


> **版本状态：v0.1-beta1。** 这是公开测试版本，建议先在全新测试 VPS 上部署，不建议直接覆盖生产邮件服务器。

[中文](README.md) | [English](README_EN.md)

MailStack 是一个面向 systemd Linux 服务器的多域名邮件部署与管理套件，集成 Postfix、Dovecot、Liquid Glass Web 管理后台、SMTP Relay、TLS、DKIM、队列、日志、安全检查与可配置 AI 邮件顾问。

> 当前版本适合测试和持续开发。生产部署前仍需完成 DNS、PTR、TLS、备份、监控、防火墙和安全审计。MailStack 不保证邮件进入收件箱。

## 快速安装

```bash
git clone https://github.com/SectorPace/MailStack.git
cd debian-mail-server
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

安装时可设置 Web 管理员用户名、密码、管理端口和监听地址。默认监听 `127.0.0.1:8787`。

```bash
ssh -L 8787:127.0.0.1:8787 root@服务器IP
```

## 非交互安装

```bash
printf '%s\n' 'YourStrongPasswordHere' | sudo bash ./mailstack.sh install \
  --admin-user admin \
  --admin-port 8787 \
  --admin-host 127.0.0.1 \
  --admin-password-stdin \
  --non-interactive
```

## VPS 快捷命令

```bash
mailstack
mailstack admin
mailstack port
mailstack status
mailstack logs
```

## 更新与卸载

```bash
sudo bash ./mailstack.sh update
sudo bash ./mailstack.sh uninstall
sudo bash ./mailstack.sh uninstall --purge
```

## 主要能力

- React 19、TypeScript、Vite 和 Liquid Glass 风格
- 中文、英文、Light、Dark
- 域名、用户、别名、Relay、DNS、TLS、队列、日志、服务、安全和设置
- AI 提供商预设与自定义 OpenAI-compatible HTTPS API
- HttpOnly Session、CSRF、防登录暴力尝试和受限 sudo Helper

## 安全说明

- Web 管理员独立于 Linux root 和邮箱用户。
- 密码使用 PBKDF2-SHA256 派生，不保存明文。
- AI Key 只存于服务器，不返回浏览器。
- 不要提交 `/etc/mailstack`、SMTP 密码、DKIM 私钥或 ACME DNS Key。
- 后台默认仅监听回环地址，不建议直接暴露公网。

## 项目结构

```text
mailstack.sh                 统一安装、更新、卸载入口
deploy/install.sh            安装器
deploy/mailstack-cli         VPS 快捷管理菜单
backend/server.production.ts Web API
backend/mailstackctl.py      受限特权助手
src/                         React 前端
```

## 许可证

MIT，详见 [LICENSE](LICENSE)。

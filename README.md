<p align="center">
  <img src="assets/mailstack-logo.png" alt="MailStack Logo" width="180">
</p>

<h1 align="center">MailStack</h1>

<p align="center">
  面向 systemd Linux 服务器的多域名邮件部署与管理套件
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="https://github.com/SectorPace/MailStack">GitHub 项目</a> ·
  <a href="https://github.com/SectorPace/MailStack/releases">Releases</a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1--beta1-2476ff">
  <img alt="Status" src="https://img.shields.io/badge/status-public%20beta-f0a53a">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-27b36a">
  <img alt="Platform" src="https://img.shields.io/badge/platform-systemd%20Linux-22c7d6">
</p>

> **版本状态：v0.1-beta1。** 这是公开测试版本。建议先在全新测试 VPS 上部署，不要直接覆盖生产邮件服务器。

## 项目简介

MailStack 集成 Postfix、Dovecot、Liquid Glass Web 管理后台、出站 SMTP Relay、TLS、DKIM、DNS 指引、邮件队列、日志、安全检查与可配置 AI 邮件顾问，目标是为常见 systemd Linux 服务器提供相对统一的邮件服务部署和管理体验。

MailStack 不保证邮件进入收件箱。实际送达结果受 IP 与域名信誉、DNS 身份认证、邮件内容、退信与投诉、Relay 服务商策略以及接收方规则影响。

## 主要功能

- Liquid Glass 风格 React 管理后台
- 简体中文与英文界面
- Light 与 Dark 双主题
- 自定义 Web 管理员用户名、密码、管理端口和监听地址
- VPS `mailstack` 快捷管理菜单
- 邮件域名、Linux 邮箱用户与地址别名管理
- Postfix 和 Dovecot 服务状态管理
- SMTP Relay 配置与服务商预设
- TLS 证书、DKIM 与 DNS 管理界面
- 邮件队列、系统日志和安全中心
- HttpOnly Session Cookie 与 CSRF 防护
- 受限 sudo 特权助手
- Gemini、Groq、OpenRouter、Mistral、Cerebras 与自定义兼容 API
- 无外部 AI API 时可使用本地规则诊断

## 支持范围

当前主要面向：

- Debian 与 Ubuntu
- Rocky Linux、AlmaLinux、RHEL 系发行版
- Fedora
- openSUSE
- Arch Linux
- 其他使用 systemd 的常见 Linux 发行版

不同发行版的软件包名称、日志路径和服务单元可能存在差异。Beta 阶段建议优先使用全新 Debian 或 Ubuntu 测试服务器。

## 快速安装

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

安装器会询问：

- Web 管理员用户名
- Web 管理员密码
- 管理端口
- Web 服务监听地址

默认监听：

```text
127.0.0.1:8787
```

推荐通过 SSH 隧道访问：

```bash
ssh -L 8787:127.0.0.1:8787 root@服务器IP
```

然后在本机浏览器打开：

```text
http://127.0.0.1:8787
```

## 非交互安装

密码通过标准输入传递，避免直接进入 Shell 历史或进程参数：

```bash
printf '%s\n' 'YourStrongPasswordHere' | sudo bash ./mailstack.sh install \
  --admin-user admin \
  --admin-port 8787 \
  --admin-host 127.0.0.1 \
  --admin-password-stdin \
  --non-interactive
```

## VPS 快捷命令

安装完成后，在 VPS 任意目录运行：

```bash
mailstack
```

常用子命令：

```bash
mailstack admin
mailstack port
mailstack status
mailstack logs
```

## 更新

```bash
cd MailStack
git pull
sudo bash ./mailstack.sh update
```

更新过程应保留现有管理员配置。执行更新前仍建议创建 VPS 快照并备份 `/etc/mailstack`、Postfix、Dovecot、DKIM 和邮件数据。

## 卸载

保留 MailStack 管理配置：

```bash
sudo bash ./mailstack.sh uninstall
```

同时删除 `/etc/mailstack` 管理配置：

```bash
sudo bash ./mailstack.sh uninstall --purge
```

卸载流程不会自动删除 Postfix、Dovecot、Linux 邮箱用户和邮件数据，避免误删生产邮箱。

## AI 智能诊断

AI 中心支持：

- 邮件 DNS 配置解释
- MX、SPF、DKIM、DMARC 与 PTR 建议
- TLS 和 SMTP Relay 故障排查
- 日志与退信片段分析
- Gemini REST API
- OpenAI-compatible API
- Groq、OpenRouter、Mistral、Cerebras 预设
- 自定义公网 HTTPS API Endpoint
- 无 API Key 的本地规则模式

API Key 保存在服务器端，不返回浏览器。自定义 API Endpoint 会阻止回环、内网、链路本地和保留地址，以降低 SSRF 风险。

第三方服务商的免费额度、模型、地区限制和数据政策可能发生变化，请以服务商当前控制台与条款为准。

## 安全建议

- 默认保持 Web 后台监听 `127.0.0.1`
- 优先使用 SSH 隧道、VPN 或 HTTPS 反向代理
- 不要将 8787 端口直接暴露到公网
- 为后台配置 IP 白名单与登录保护
- 妥善保护 SMTP、AI、ACME DNS 和 DKIM 凭据
- 不要提交 `.env`、`/etc/mailstack`、`sasl_passwd` 或私钥
- 配置 MX、SPF、DKIM、DMARC 和 PTR
- 定期检查证书到期、磁盘空间、队列积压和异常登录
- 在执行危险操作前创建配置备份和 VPS 快照

## 项目结构

```text
mailstack.sh                 统一安装、更新和卸载入口
deploy/install.sh            交互式与非交互式安装器
deploy/mailstack-cli         VPS 快捷管理菜单
backend/server.production.ts 认证与 Web API
backend/mailstackctl.py      受限特权助手
src/                         React 管理后台源码
assets/mailstack-logo.png    项目 Logo
```

## 开发构建

```bash
npm install
npm run lint
npm run build
```

项目使用 React、TypeScript、Vite 和 Tailwind CSS。生产部署由安装脚本完成构建和 systemd 服务注册。

## 已知限制

- 当前仍为 Beta 版本，尚未完成所有发行版的端到端测试
- 部分高级 Relay 故障转移和防重复投递状态机仍需继续验证
- ACME 首次签发、DNS API 凭据轮换和多 CA 回滚仍需增强
- DKIM、Rspamd、ClamAV、Fail2ban 和防火墙功能在不同发行版上可能需要适配
- AI 建议不能代替管理员审查，也不能保证邮件送达
- 不应把演示数据或 Mock 状态理解为真实服务器结果

## 贡献

欢迎通过 Issue 报告可复现问题，并在提交前说明：

- 操作系统及版本
- MailStack 版本
- 安装方式
- 相关服务状态
- 已脱敏的错误日志
- 复现步骤

请勿公开提交 SMTP 密码、管理员哈希、AI Key、DKIM 私钥、TLS 私钥、ACME DNS Key、邮箱正文或未脱敏生产日志。

## 安全问题

安全漏洞不要直接公开披露。请使用 GitHub Private Vulnerability Reporting，或通过仓库维护者提供的私密渠道报告。

## 许可证

MailStack 使用 MIT License。详情请查看 [LICENSE](LICENSE)。

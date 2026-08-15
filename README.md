<p align="center">
  <img src="assets/mailstack-logo.png" alt="MailStack Logo" width="180">
</p>

<h1 align="center">MailStack</h1>

<p align="center">
  面向 Linux VPS 的多域名邮件服务部署与可视化管理平台
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="https://github.com/SectorPace/MailStack/issues">问题反馈</a> ·
  <a href="https://github.com/SectorPace/MailStack/releases">版本发布</a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1--beta1-2476ff">
  <img alt="Status" src="https://img.shields.io/badge/status-public%20beta-f0a53a">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-27b36a">
  <img alt="Platform" src="https://img.shields.io/badge/platform-systemd%20Linux-22c7d6">
</p>

> [!WARNING]
> **MailStack v0.1-beta1 是公开测试版本。** 建议先在全新 VPS 上测试，不要直接覆盖正在运行的生产邮件服务器。升级、恢复或卸载前，请先创建 VPS 快照并备份邮件数据与配置。

## 项目简介

MailStack 将邮件服务器常用能力、Web 管理后台和 VPS 运维菜单整合到同一套项目中，目标是降低 Postfix、Dovecot、SMTP Relay、TLS、DKIM、DNS、邮件队列和日志管理的使用门槛。

Web 管理后台采用 React、TypeScript、Vite 和 Liquid Glass 视觉风格，支持中文、英文、Light 和 Dark 模式。安装完成后，可通过公网 IP 和管理端口进入登录页面，也可以使用 `ms` 命令在 VPS 终端管理服务。

MailStack 不保证邮件一定进入收件箱。实际送达结果还会受到 IP 和域名信誉、PTR、SPF、DKIM、DMARC、邮件内容、投诉率、退信率、SMTP Relay 服务商策略以及接收方过滤规则的影响。

## 主要功能

### Web 管理后台

- 管理员用户名和密码登录
- HttpOnly Session Cookie
- CSRF 请求保护
- 登录失败限制
- 修改管理员用户名和密码
- 修改账户后自动注销全部旧会话
- 自定义管理端口和监听地址
- 默认公网监听，适合 VPS 管理
- 中文与英文界面
- Light 与 Dark 双主题
- 液态玻璃风格界面

### 邮件系统管理

- 邮件域名管理
- Linux 邮箱用户管理
- 邮件地址别名管理
- Postfix 和 Dovecot 服务状态
- SMTP Relay 配置与服务商预设
- TLS 证书管理界面
- DKIM 与 DNS 配置指引
- MX、SPF、DKIM、DMARC 和 PTR 建议
- 邮件队列查看与刷新
- 延迟队列清理
- 邮件服务日志查看
- 安全状态与基础诊断

### AI 邮件助手

- 邮件 DNS 配置分析
- TLS 和 SMTP Relay 故障排查
- 退信与日志片段解释
- Gemini REST API
- OpenAI-compatible API
- Groq、OpenRouter、Mistral 和 Cerebras 预设
- 自定义公网 HTTPS API
- 无外部 API 时的本地规则模式

AI API Key 仅保存在服务器端，不返回浏览器。自定义 API 地址会阻止回环、内网、链路本地和保留地址，以降低 SSRF 风险。

第三方 API 的免费额度、模型、地区限制和数据政策可能变化，使用前请以服务商当前控制台和条款为准。

## 系统要求

建议测试环境：

- 全新 Debian 或 Ubuntu VPS
- systemd
- root 或 sudo 权限
- 至少 1 GB 内存，建议 2 GB 或更多
- 可用公网 IPv4
- 可控制的域名 DNS
- 云安全组或 VPS 防火墙管理权限

安装器会尝试为支持的系统安装基础依赖。Debian 和 Ubuntu 环境缺少 Node.js 20 或更高版本时，安装器会尝试安装 Node.js 22。

其他 Linux 发行版可能因软件包名称、服务单元、日志路径和邮件组件版本不同而需要额外适配。

## 快速安装

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

安装器会要求设置：

- Web 管理员用户名
- Web 管理员密码
- 管理端口
- 监听地址

默认配置：

```text
监听地址：0.0.0.0
管理端口：8787
```

安装完成后访问：

```text
http://VPS公网IP:8787
```

还需要在云服务商安全组和 Linux 防火墙中放行对应的 TCP 管理端口。

> [!IMPORTANT]
> 默认公网访问便于 VPS 用户直接登录，但生产环境应尽快配置 HTTPS、强密码、防火墙和来源 IP 限制。不要在公网长期使用无加密 HTTP 登录。

## 非交互安装

密码通过标准输入传递，避免直接出现在 Shell 历史和进程参数中：

```bash
printf '%s\n' 'YourStrongPasswordHere' | sudo bash ./mailstack.sh install \
  --admin-user admin \
  --admin-port 8787 \
  --admin-host 0.0.0.0 \
  --admin-password-stdin \
  --non-interactive
```

管理员密码至少需要 12 个字符。

## `ms` VPS 快捷命令

安装完成后，在 VPS 任意目录运行：

```bash
ms
```

`ms` 是 MailStack 的正式管理命令。项目同时保留 `mailstack` 兼容别名，但新文档统一使用 `ms`。

常用子命令：

```bash
ms status
ms logs
ms health
ms admin
ms port
ms backup
ms update
ms repair
ms uninstall
ms purge
ms version
```

如果当前用户不是 root，可在命令前添加 `sudo`：

```bash
sudo ms
```

## VPS 管理菜单

运行：

```bash
ms
```

菜单提供以下功能。

### 后台管理

```text
1) 查看后台状态
2) 启动后台
3) 停止后台
4) 重启后台
5) 查看最近日志
6) 实时日志
7) 修改管理员账户
8) 修改监听地址和端口
9) 后台健康诊断
```

### 邮件系统

```text
10) 邮件服务状态
11) 重启邮件服务
12) 查看邮件队列
13) 刷新邮件队列
14) 清空延迟队列
15) 查看邮件日志
```

### 安全与网络

```text
16) 运行安全扫描
17) 查看防火墙状态
18) 查看网络与监听端口
```

### 备份与维护

```text
19) 创建配置备份
20) 查看备份
21) 恢复备份
22) 更新 MailStack
23) 修复或重新安装
24) 更新系统软件包
```

### 卸载与清除

```text
25) 卸载程序并保留配置
26) 彻底清除 MailStack 管理组件
```

危险操作需要输入指定确认文字，避免因误选菜单导致删除。

## 更新 MailStack

安装完成后，可在 VPS 任意目录更新：

```bash
sudo ms update
```

更新过程会尝试：

- 获取最新源码
- 保留管理员账户
- 保留管理端口和监听地址
- 更新前端与生产后端
- 更新 `ms` 快捷命令
- 重启 `mailstack-web`
- 检查 systemd 状态和健康接口

建议更新前创建备份：

```bash
sudo ms backup
```

如果更新后出现异常：

```bash
sudo ms repair
```

查看状态与日志：

```bash
sudo ms status
sudo ms logs
```

如果 `ms` 命令本身意外丢失，可在源码目录恢复：

```bash
cd ~/MailStack
sudo cp deploy/mailstack-cli /usr/local/bin/ms
sudo chmod 0755 /usr/local/bin/ms
sudo ln -sfn /usr/local/bin/ms /usr/local/bin/mailstack
```

## 修改管理员账户

在 VPS 中运行：

```bash
sudo ms admin
```

或者登录 Web 管理后台后，在系统设置中修改管理员用户名和密码。

保存新账户后，所有现有 Web 会话会立即失效，必须使用新凭据重新登录。

管理员账户与以下账户相互独立：

- Linux root 用户
- SSH 用户
- 邮箱用户
- Postfix SASL 用户
- Dovecot 邮箱认证用户

管理员凭据保存在：

```text
/etc/mailstack/admin.json
```

密码使用 PBKDF2-SHA256、随机 Salt 和多次迭代派生，不保存明文密码。

## 修改管理端口

```bash
sudo ms port
```

可以修改：

- 管理端口
- `0.0.0.0` 公网监听
- `127.0.0.1` 本机监听
- `::1` IPv6 本机监听

修改后，脚本会重新加载 systemd 并重启管理后台。

如果修改了端口，还需要同步修改：

- 云服务商安全组
- UFW、firewalld 或 nftables
- HTTPS 反向代理配置
- 监控和访问链接

## 备份与恢复

创建备份：

```bash
sudo ms backup
```

默认备份目录：

```text
/var/backups/mailstack/
```

备份可能包含当前存在的：

```text
/etc/mailstack
/etc/postfix
/etc/dovecot
/etc/opendkim
/etc/systemd/system/mailstack-web.service
/opt/mailstack
```

查看和恢复备份可通过 `ms` 菜单完成。

> [!CAUTION]
> 恢复操作会覆盖现有配置。恢复前请额外创建 VPS 快照，并确认备份文件完整可用。

## 卸载

### 卸载程序并保留配置

```bash
sudo ms uninstall
```

该模式删除 MailStack Web 管理程序、systemd 服务和快捷命令，但保留 `/etc/mailstack` 和邮件数据。

### 彻底清除管理组件

```bash
sudo ms purge
```

该模式还会删除 `/etc/mailstack` 中的管理员和 MailStack 管理配置。

默认不会自动删除：

- Postfix
- Dovecot
- Linux 邮箱用户
- 邮箱数据
- 邮件队列

这样可以降低误删真实邮箱数据的风险。

## 安装目录

```text
/opt/mailstack                  MailStack 运行目录
/opt/mailstack/ui               前端源码和构建结果
/opt/mailstack/server.cjs       生产 Web API
/opt/mailstack/backend          受限特权助手
/opt/mailstack-source           更新和修复使用的源码副本
/etc/mailstack                  管理员与 MailStack 配置
/usr/local/bin/ms               正式快捷命令
/usr/local/bin/mailstack        兼容别名
/var/backups/mailstack          默认备份目录
```

## 项目结构

```text
mailstack.sh                    安装、更新和卸载入口
deploy/install.sh               系统安装器
deploy/mailstack-cli            VPS 管理菜单与 ms 命令
backend/server.production.ts    登录认证与 Web API
backend/mailstackctl.py         受限特权助手
src/                            React 管理后台源码
assets/mailstack-logo.png       项目 Logo
```

## 开发构建

安装依赖：

```bash
npm install --include=optional
```

检查类型：

```bash
npm run lint
```

构建前端：

```bash
npm run build
```

生产后端由安装器从以下入口单独构建：

```text
backend/server.production.ts
```

这样可以避免把旧开发服务与带登录认证的生产 API 混在一起。

## 安全建议

- 为 Web 后台设置高强度独立密码
- 尽快在公网入口配置 HTTPS
- 使用防火墙限制后台来源 IP
- 不要把 SMTP 密码、AI Key、DKIM 私钥或 ACME DNS Key 放入 Git
- 不要提交 `.env`、`admin.json`、`ai-provider.json` 或 `sasl_passwd`
- 定期检查证书到期时间
- 监控磁盘空间和邮件队列积压
- 配置 MX、SPF、DKIM、DMARC 和 PTR
- 更新前创建 VPS 快照和 MailStack 备份
- 发布日志和 Issue 前必须脱敏

## 已知限制

- 当前仍是 Beta 版本
- 尚未完成所有 Linux 发行版的端到端验证
- 高级 SMTP Relay 故障转移和防重复投递仍需继续测试
- ACME 首次签发、DNS-01 自动化和证书回滚仍需增强
- DKIM、Rspamd、ClamAV、Fail2ban 和防火墙能力可能需要按发行版适配
- AI 建议不能代替管理员审查
- AI 诊断不能保证邮件送达
- Mock 或演示数据不能视为真实服务器状态

## 问题反馈

提交 Issue 时请提供：

- Linux 发行版和版本
- CPU 架构
- MailStack 版本
- 安装或更新方式
- 相关 systemd 服务状态
- 已脱敏的日志
- 可复现步骤

请勿公开提交：

- SMTP 密码
- 管理员密码或哈希
- AI API Key
- DKIM 或 TLS 私钥
- ACME DNS 凭据
- 邮箱正文
- 未脱敏生产日志

## 许可证

MailStack 使用 [MIT License](LICENSE)。

<p align="center">
  <img src="https://raw.githubusercontent.com/SectorPace/MailStack/main/assets/mailstack-logo.png" alt="MailStack Logo" width="160">
</p>

<h1 align="center">MailStack v0.1-beta1</h1>

<p align="center">
  首个公开 Beta 测试版本
</p>

> [!WARNING]
> **这是公开测试版本。** 建议优先部署在全新 VPS 上，不要直接覆盖现有生产邮件服务器。更新、恢复或卸载前，请先创建 VPS 快照并备份邮件数据与配置。

## 版本概览

MailStack v0.1-beta1 将邮件服务器基础能力、Web 管理后台和 VPS 运维菜单整合到同一项目中，提供 Postfix、Dovecot、SMTP Relay、TLS、DKIM、DNS 指引、邮件队列、日志、安全诊断和可配置 AI 邮件助手等功能。

本版本确立了两套主要管理入口：

- 通过 VPS 公网 IP 和管理端口访问 Web 登录页面
- 在服务器终端使用 `ms` 快捷命令打开管理菜单

MailStack 不保证邮件一定进入收件箱。实际送达还会受到 IP 和域名信誉、PTR、SPF、DKIM、DMARC、邮件内容、投诉率、退信率、Relay 服务商策略和接收方过滤规则的影响。

## 主要功能

### Web 管理后台

- Liquid Glass 风格 React 管理界面
- 简体中文和英文
- Light 与 Dark 双主题
- 管理员用户名和密码登录
- HttpOnly Session Cookie
- CSRF 请求保护
- 登录失败限制
- 修改管理员用户名和密码
- 修改账户后撤销全部旧会话
- 自定义管理端口和监听地址
- 默认监听 `0.0.0.0:8787`
- 支持通过 VPS 公网 IP 登录

### 邮件系统管理

- 邮件域名管理
- Linux 邮箱用户管理
- 邮件地址别名管理
- Postfix 和 Dovecot 服务状态
- SMTP Relay 配置和服务商预设
- TLS 证书管理界面
- DKIM 与 DNS 配置指引
- MX、SPF、DKIM、DMARC 和 PTR 建议
- 邮件队列查看与刷新
- 延迟队列清理
- 邮件服务日志查看
- 基础安全诊断

### AI 邮件助手

- 邮件 DNS 配置分析
- TLS 和 SMTP Relay 故障排查
- 退信与日志片段解释
- Gemini REST API
- OpenAI-compatible API
- Groq、OpenRouter、Mistral 和 Cerebras 预设
- 自定义公网 HTTPS API
- 无外部 API 时的本地规则模式

AI API Key 仅保存在服务器端，不返回浏览器。自定义 API 地址会拒绝回环、内网、链路本地和保留地址，以降低 SSRF 风险。

## `ms` VPS 管理命令

安装完成后，可在 VPS 任意目录运行：

```bash
ms
```

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

`ms` 是正式管理命令，同时保留 `mailstack` 作为兼容别名。

### 扩展管理菜单

菜单包含以下功能分组：

- 后台启动、停止、重启、状态和日志
- 管理员用户名与密码修改
- 监听地址和管理端口修改
- Web 与 API 健康诊断
- 邮件服务状态和重启
- 邮件队列查看、刷新和延迟队列清理
- 邮件日志、安全扫描和防火墙状态
- 网络接口与监听端口检查
- 配置备份、备份列表和恢复
- MailStack 更新和修复安装
- 系统软件包更新
- 安全卸载与彻底清除管理组件

危险操作需要输入指定确认文字，降低误删除风险。

## 安装器改进

本版本修复并增强了 Linux 安装流程：

- 自动检测支持的包管理器
- Debian 和 Ubuntu 自动安装基础依赖
- Node.js 版本不足时尝试安装 Node.js 22
- 保留 Rollup 平台可选依赖
- 修复 `@rollup/rollup-linux-x64-gnu` 缺失问题
- 前端 Vite 构建与生产 API 构建分离
- 生产后端统一使用 `backend/server.production.ts`
- 移除旧开发入口 `server.ts`
- 生产 API 打包为 `/opt/mailstack/server.cjs`
- 安装阶段不再提前依赖 `rsync`
- 更新时保留管理员账户、端口和监听地址
- 安装和修复时自动恢复 `/usr/local/bin/ms`
- 自动创建 `mailstack` 兼容软链接
- 安装后检查 systemd 服务状态
- 安装后检查 `/api/health` 健康接口

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

默认访问地址：

```text
http://VPS公网IP:8787
```

安装完成后运行：

```bash
ms
```

## 非交互安装

```bash
printf '%s\n' 'YourStrongPasswordHere' | sudo bash ./mailstack.sh install \
  --admin-user admin \
  --admin-port 8787 \
  --admin-host 0.0.0.0 \
  --admin-password-stdin \
  --non-interactive
```

管理员密码至少需要 12 个字符。

## 更新

```bash
sudo ms backup
sudo ms update
```

如果更新失败或安装状态异常：

```bash
sudo ms repair
```

检查状态和日志：

```bash
sudo ms status
sudo ms logs
```

## 备份与恢复

创建备份：

```bash
sudo ms backup
```

默认备份目录：

```text
/var/backups/mailstack/
```

备份可能包含：

```text
/etc/mailstack
/etc/postfix
/etc/dovecot
/etc/opendkim
/etc/systemd/system/mailstack-web.service
/opt/mailstack
```

恢复操作会覆盖当前配置。执行恢复前，请额外创建 VPS 快照并验证备份文件。

## 卸载

### 卸载程序并保留配置

```bash
sudo ms uninstall
```

该模式删除 Web 管理程序、systemd 服务和快捷命令，但保留 `/etc/mailstack` 与邮件数据。

### 彻底清除 MailStack 管理组件

```bash
sudo ms purge
```

该模式还会删除 `/etc/mailstack` 中的管理员账户和 MailStack 管理配置。

默认不会自动删除：

- Postfix
- Dovecot
- Linux 邮箱用户
- 邮箱数据
- 邮件队列

## 公网访问与安全提醒

MailStack 默认监听：

```text
0.0.0.0:8787
```

请在云服务商安全组和 Linux 防火墙中开放对应 TCP 端口。

生产使用前强烈建议：

- 为后台配置 HTTPS
- 使用高强度独立管理员密码
- 限制管理端口来源 IP
- 配置防火墙和登录保护
- 妥善保护 SMTP、AI、ACME DNS 和 DKIM 凭据
- 不要把无加密 HTTP 登录页面长期暴露在公网
- 定期检查磁盘、证书、邮件队列和失败登录

## 已知限制

- 当前仍是 Beta 版本
- 尚未完成所有 Linux 发行版的端到端验证
- 高级 SMTP Relay 故障转移和防重复投递仍需继续测试
- ACME 首次签发、DNS-01 自动化和证书回滚仍需增强
- DKIM、Rspamd、ClamAV、Fail2ban 和防火墙功能可能需要发行版适配
- AI 建议不能代替管理员审查
- AI 诊断不能保证邮件送达
- Mock 或演示数据不能视为真实服务器状态

## 问题反馈

反馈问题时请提供：

- Linux 发行版和版本
- CPU 架构
- MailStack 版本
- 安装或更新方式
- 相关 systemd 服务状态
- 已脱敏日志
- 可复现步骤

请勿公开提交：

- SMTP 密码
- 管理员密码或哈希
- AI API Key
- DKIM 或 TLS 私钥
- ACME DNS 凭据
- 邮箱正文
- 未脱敏生产日志

## 版本信息

```text
版本：v0.1-beta1
仓库：https://github.com/SectorPace/MailStack
许可证：MIT
```

感谢参与 MailStack 的首个公开 Beta 测试。

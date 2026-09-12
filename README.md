<p align="center">
  <img src="assets/mailstack-logo.png" alt="MailStack Logo" width="180">
</p>

<h1 align="center">MailStack</h1>

<p align="center">
  面向 systemd Linux 服务器的多域名邮件服务部署与管理套件<br>
  Postfix · Dovecot · OpenDKIM · Liquid Glass 管理后台 · 独立 Webmail · 智能诊断 · 一体化运维 CLI
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="https://github.com/SectorPace/MailStack">GitHub 项目</a> ·
  <a href="https://github.com/SectorPace/MailStack/releases">Releases</a> ·
  <a href="CHANGELOG.md">更新日志</a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.5.2--rc.3-2476ff">
  <img alt="Status" src="https://img.shields.io/badge/status-release%20candidate-f0a53a">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-27b36a">
  <img alt="Platform" src="https://img.shields.io/badge/platform-systemd%20Linux-22c7d6">
  <img alt="Node.js" src="https://img.shields.io/badge/Node.js-20%20%7C%2022%20%7C%2024-3c873a">
</p>

> **版本状态：v0.5.2-rc.3（发布候选版）。** 安装器、权限模型与邮件链路已经过四发行版干净容器装机矩阵与真机验证（Ubuntu 24.04 / Debian 12，见 [docs/verification](docs/verification)），但仍建议先在全新测试 VPS 上部署，不要直接覆盖生产邮件服务器。
>
> **重要声明：MailStack 不保证邮件进入收件箱。** 实际送达结果受 IP 与域名信誉、DNS 身份认证（MX / SPF / DKIM / DMARC / PTR）、邮件内容、退信与投诉率、Relay 服务商策略以及接收方规则影响。任何邮件系统都无法绕过这些因素。

---

## 目录

- [项目简介](#项目简介)
- [功能总览](#功能总览)
- [架构总览](#架构总览)
- [支持范围](#支持范围)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [四种网络访问模式](#四种网络访问模式)
- [非交互安装](#非交互安装)
- [部署向导](#部署向导)
- [DNS 记录指引](#dns-记录指引)
- [Webmail 使用](#webmail-使用)
- [CLI 命令参考](#cli-命令参考)
- [更新与升级](#更新与升级)
- [备份与灾难恢复](#备份与灾难恢复)
- [卸载](#卸载)
- [端口与环境变量](#端口与环境变量)
- [安全模型](#安全模型)
- [AI 邮件顾问](#ai-邮件顾问)
- [测试与质量保障](#测试与质量保障)
- [项目结构](#项目结构)
- [开发指南](#开发指南)
- [已知限制](#已知限制)
- [FAQ](#faq)
- [贡献](#贡献)
- [安全问题](#安全问题)
- [文档索引](#文档索引)
- [许可证](#许可证)

## 项目简介

MailStack 把在一台 Linux 服务器上自建邮件系统所需的整套组件 —— Postfix（SMTP）、Dovecot（IMAP/POP 与本地投递）、OpenDKIM（签名）、可选 Fail2ban / Rspamd / ClamAV —— 与一个 Liquid Glass 风格的 Web 管理后台、一个独立的 Webmail 客户端、一套受限特权的 Python 助手和统一的 `ms` 运维 CLI 组合在一起，通过一次安装完成部署、构建、systemd 服务注册、权限与沙箱配置，并提供 DNS 指引、TLS 证书、SMTP Relay、邮件队列、日志、安全检查与可配置 AI 邮件顾问等日常管理能力。

设计目标：

- **一键可用**：从 `git clone` 到双服务健康自检通过，一条命令完成；Node.js 等依赖自动装配。
- **默认安全**：Web 服务默认只监听 `127.0.0.1`，特权操作走白名单化的受限 sudo 助手，高危操作要求显式确认。
- **可运维**：健康体检、邮件闭环投递验证、配置备份 / 还原 / 回滚、日志与遥测全部内置。
- **可审计**：所有特权 RPC 调用写审计日志，发布产物带 SHA256 清单，安装脚本第三方下载留痕。

## 功能总览

### 管理后台（Liquid Glass Web Console）

- React 19 + TypeScript + Vite + Tailwind CSS 4 构建的 Liquid Glass 风格单页控制台
- 简体中文 / 英文双语界面，Light 与 Dark 双主题
- 可自定义头像、Logo 样式（3D 玻璃等）与背景渲染效果
- 全局搜索（`SearchModal`）、Toast 通知、错误边界（ErrorBoundary）
- 系统遥测：实时指标与历史图表（CPU / 负载 / 内存 / 磁盘 / 队列）

### 邮件核心能力

| 能力 | 说明 |
|---|---|
| 邮件域名管理 | 多域名添加 / 删除，Postfix 域名注册与校验 |
| 邮箱用户管理 | 创建 Linux 系统邮箱用户（nologin + Maildir），启停状态、密码重置、删除 |
| 地址别名 | 别名添加 / 删除，显式域名拆分校验 |
| 邮件队列 | Postfix 队列查看与队列操作（队列 ID 白名单校验） |
| 服务管理 | Postfix / Dovecot / OpenDKIM / Fail2ban / Rspamd / ClamAV / Redis 的 start / stop / restart / reload / status |
| TLS 证书 | 证书列表、续期、向导式签发（ACME） |
| DKIM | 密钥生成、DNS 公钥展示（正确处理 RFC 跨行拆分）、密钥轮换（`dkim.rotate`） |
| SMTP Relay | 一键配置中继并落盘 `sasl_passwd`（0600），内置 Oracle OCI / Amazon SES / SendGrid / Brevo / Resend 预设与自定义 SmartHost |
| 安全中心 | 安全评分与事件扫描（relay 限制、Fail2ban 状态、`sasl_passwd` 权限、证书缺失）、Fail2ban 封禁 / 解封 |
| 域名 DNS 体检 | MX / SPF / DKIM / DMARC / PTR 校验指引与逐记录状态（含 Relay 服务商专项检查，如 SES 的 `feedback-smtp` Mail From） |

### 独立 Webmail 客户端

- 独立的 `mailstack-webmail` systemd 服务，与管理后台完全隔离（独立系统账号、独立端口、独立沙箱）
- 使用 Linux 邮箱账号通过 Dovecot 认证登录，直接读取 Maildir
- 收件箱列表、搜索、邮件正文解析（MIME / encoded-word / 多字符集）、已读标记
- 通过本机 `sendmail`（Postfix）提交外发邮件
- 会话 Cookie、CSRF 防护、登录尝试限制与接口级速率限制
- 安全读取邮件文件：`O_NOFOLLOW` 防符号链接、大小上限、路径规范化

### 部署向导（Setup Wizard）

首次登录后的分步引导，覆盖：服务器身份 → DNS 校验 → 投递方式（Relay 测试 / 直连 EHLO 探测）→ TLS 证书签发 → 发信闭环测试 → 部署摘要。每一步都调用特权助手做真实校验，而不是仅前端提示。

### 一体化运维 CLI（`ms`）

`ms doctor` 全栈体检、`ms test-mail` 闭环投递验证、`ms backup / restore / rollback` 配置灾备、`ms upgrade` 热更新、`ms uninstall --dry-run` 卸载预检等，详见 [CLI 命令参考](#cli-命令参考)。

### AI 邮件顾问

- 内置 GLM (BigModel)、DeepSeek、OpenAI、Anthropic Claude 预设，以及任意自定义 OpenAI-compatible / Anthropic-protocol HTTPS 端点
- 聊天助手、DNS / TLS / Relay / 日志退信片段诊断、结果结构化解析
- 无外部 API Key 时自动降级为本地规则诊断，功能不缺席
- 端点解析后钉定 IP 连接，拦截回环 / 内网 / 链路本地 / CGNAT / 组播 / 保留地址，默认禁用内网 AI 端点，防 DNS Rebinding 与 SSRF

## 架构总览

```text
                        ┌────────────────────────────────────────────────┐
                        │                浏览器（管理员 / 邮箱用户）        │
                        └────────────┬──────────────────────┬────────────┘
                                     │ HTTPS / SSH 隧道      │
                   ┌─────────────────▼──────────┐  ┌────────▼─────────┐
   访问模式         │  mailstack-web (Admin)     │  │ mailstack-webmail │
  local/caddy/     │  Express + React 静态托管   │  │ Maildir Webmail   │
  direct/plain     │  127.0.0.1:8787            │  │ 127.0.0.1:18788   │
                   └───────────┬────────────────┘  └────────┬─────────┘
                               │ JSON-RPC（受限 sudo）        │ Dovecot auth socket
                               ▼                            │ 只读/受控读 Maildir
                   ┌────────────────────────────┐           │
                   │ mailstack-privileged       │           │
                   │ → mailstackctl.py (Python) │           │
                   │ 44 个白名单动作 + 审计日志    │           │
                   └───────┬────────────────────┘           │
                           │ postconf / doveadm / opendkim-genkey /
                           │ fail2ban-client / systemctl / certbot ...
              ┌────────────┼───────────────┬────────────────┐
              ▼            ▼               ▼                ▼
         ┌────────┐  ┌─────────┐   ┌────────────┐   ┌──────────────┐
         │Postfix │  │Dovecot  │   │ OpenDKIM   │   │ Fail2ban 等   │
         └────────┘  └─────────┘   └────────────┘   └──────────────┘
```

组件职责：

| 组件 | 进程 / 文件 | 系统账号 | 职责 |
|---|---|---|---|
| 管理控制台 | `mailstack-web.service` → `/opt/mailstack/server.cjs`（esbuild 打包的 Express） | `mailstack-admin`（nologin） | 登录认证、会话、静态资源、把 Web 请求转发为特权 RPC |
| 特权助手 | `/usr/local/libexec/mailstack-privileged` → `/opt/mailstack/backend/mailstackctl.py` | root（由 sudo 调起） | 全部需要 root 的操作；动作白名单 + 危险动作二次确认 + 审计日志 |
| Webmail | `mailstack-webmail.service` → `/opt/mailstack/webmail.cjs` | `mailstack-webmail`（nologin，属 dovecot/mail 组） | 邮箱用户登录、Maildir 读取、发信提交；**无任何 sudo 权限** |
| 邮件栈 | Postfix / Dovecot / OpenDKIM / Fail2ban | 系统服务 | 实际收发信、本地投递、DKIM 签名、暴力破解防护 |
| 运维 CLI | `/usr/local/bin/ms` → `/opt/mailstack-source/mailstack.sh` | root（自行提权） | 安装 / 更新 / 卸载 / 体检 / 备份 / 还原 / 回滚 |

## 支持范围

以下表格来自 [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)（以随版本的发布物为准）：

| 发行版 | 版本 | 支持级别 | 安装路径 | 验证方式 |
|---|---|---|---|---|
| Ubuntu | 22.04 / 24.04 LTS | **Tier 1** | APT + systemd | 真机验证记录 + CI 装机矩阵 |
| Debian | 12 (Bookworm) | **Tier 1** | APT + systemd | 真机验证记录 + CI 装机矩阵 |
| RHEL / Rocky / AlmaLinux | 9.x | Tier 2 | DNF + systemd | `scripts/test_distro_matrix.py` |
| openSUSE Leap / Tumbleweed | 15.x / rolling | Tier 2 | Zypper + systemd | `scripts/test_distro_matrix.py` |
| Alpine Linux | 3.19+ | 实验性 | APK + OpenRC | 生产使用前请自行验证 |

- **Tier 1**：每个发布候选都在干净机器上执行安装器、健康检查、邮件链路测试与卸载检查（CI 中对应 ubuntu:24.04、ubuntu:22.04、debian:12、rockylinux:9 四容器装机矩阵）。
- **Tier 2**：源码与独立构建经自动测试；建议生产部署前先在干净机器演练安装。
- 其他使用 systemd 的常见发行版（如 Fedora、Arch Linux）为尽力兼容，软件包名称、日志路径与服务单元可能存在差异。
- Beta / RC 阶段建议优先使用全新 **Debian 12 或 Ubuntu 22.04 / 24.04** 测试服务器。

## 环境要求

| 项目 | 要求 |
|---|---|
| 操作系统 | 上表所列 systemd Linux 发行版（Alpine 为 OpenRC 实验支持） |
| 权限 | root（安装脚本会自行 `sudo` 提权） |
| Shell | Bash |
| Node.js | **20 – 24**（`package.json` engines 为 `>=20 <25`）；不满足时安装器自动配置 Node 22 LTS |
| Python | ≥ 3.9（仅用标准库，特权助手与运维工具） |
| 其他命令 | `python3`、`sudo`、`rsync`、`tar`（缺失即中止安装）；`git`（更新时缺失会尝试自动安装） |
| 端口 | 25（SMTP，收发信必需）；管理 8787 与 Webmail 18788 默认仅监听本机回环 |
| DNS | 若使用 `caddy` 公网模式，域名 A/AAAA 记录需指向服务器公网 IP（80/443 需空闲，供 Caddy 签发证书） |

## 快速开始

### 交互式安装

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

安装流程会依次完成：

1. 安装并校验完整邮件基础栈（Postfix / Dovecot / OpenDKIM 等）
2. 检查 Node.js 运行时（不满足则自动配置 Node 22 LTS；第三方 setup 脚本先下载、SHA256 记入安装日志再执行）
3. 选择访问模式（见下节）、设置管理员用户名与密码（至少 8 位）
4. 构建（优先使用带 SHA256 清单校验的预构建产物，否则源码 `npm run build:all`）
5. 创建 `mailstack-admin` / `mailstack-webmail` 独立系统账号，写入 sudoers、Dovecot 认证 socket、logrotate 配置
6. 注册并启动 `mailstack-web` 与 `mailstack-webmail` systemd 服务（非 systemd 环境回退 SysV init 脚本）
7. 健康自检：`/api/health` 与 `/api/webmail/health` 全部通过才算安装成功
8. 把本次安装的有效参数持久化到 `/etc/mailstack/install-args.conf`（升级时原样透传，避免行为漂移）

安装日志位于 `/var/log/mailstack-install.log`。

### 安装后访问（local 模式）

默认监听 `127.0.0.1:8787`（管理台）与 `127.0.0.1:18788`（Webmail）。推荐通过 SSH 隧道访问：

```bash
ssh -L 8787:127.0.0.1:8787 -L 18788:127.0.0.1:18788 root@服务器IP
```

然后在本机浏览器打开：

```text
管理后台: http://127.0.0.1:8787
Webmail:  http://127.0.0.1:18788
```

若选择 `caddy` 模式，安装器会自动安装 / 配置 Caddy，生成含 HSTS 与安全响应头的 Caddyfile，并通过 Let's Encrypt 全自动签发与续期证书，直接用域名 HTTPS 访问即可。Caddy 不可用时**自动安全降级**回 local 监听并明确提示。

## 四种网络访问模式

| 模式 | 监听地址 | 适用场景 | 安全等级 | 访问方式 |
|---|---|---|:---:|---|
| **`local`** | `127.0.0.1` | 安全默认基线 | 🟢 高 | SSH 隧道 / VPN 转发 |
| **`caddy`** | `127.0.0.1` + Caddy 反代 | 公网生产多域名 | 🟢 高 | 自动签发 Let's Encrypt TLS，域名直接访问 |
| **`direct`** | `127.0.0.1` | 已有 Nginx 等反代 | 🟡 中 | 用户自备反向代理与 HTTPS 证书（参考 [deploy/reverse-proxy-nginx.example.conf](deploy/reverse-proxy-nginx.example.conf)） |
| **`plain`** | `0.0.0.0` | 内网隔离测试 | 🔴 极低 | 明文 HTTP 公网暴露；交互模式需输入 `yes` 二次确认，非交互模式必须显式传 `--i-understand-plain-http` |

对应安装参数：

```bash
sudo bash ./mailstack.sh install --access-mode local|caddy|direct|plain
```

`caddy` 模式还需 `--domain mail.example.com`（可选 `--webmail-domain`、`--email` 证书通知邮箱）。`direct` 模式会启用 HTTPS 安全 Cookie 标记（`COOKIE_SECURE=1`）。

## 非交互安装

密码通过标准输入传递（进程内再转环境变量并立即 `unsetenv`），不出现在 Shell 历史或 `/proc/<pid>/cmdline`：

```bash
printf '%s\n' 'YourStrongPasswordHere' | sudo bash ./mailstack.sh install \
  --access-mode caddy \
  --domain mail.example.com \
  --webmail-domain webmail.example.com \
  --email ops@example.com \
  --admin-user admin \
  --admin-port 8787 \
  --admin-host 127.0.0.1 \
  --admin-password-stdin \
  --non-interactive
```

全部安装参数：

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--access-mode <mode>` | `local` / `caddy` / `direct` / `plain` | 交互选择；非交互下有域名则 `caddy`，否则 `local` |
| `--domain <DOMAIN>` | 管理后台 / 主邮件域名（如 `mail.example.com`） | 空 |
| `--webmail-domain <DOMAIN>` | Webmail 域名 | 同主域名 |
| `--email <EMAIL>` | Let's Encrypt 证书通知邮箱 | 空 |
| `--admin-user <NAME>` | 管理员用户名 | `admin` |
| `--admin-port <PORT>` | 管理后台内部端口（1024–65535） | `8787` |
| `--admin-host <HOST>` | 管理后台监听地址 | `127.0.0.1` |
| `--webmail-port <PORT>` | Webmail 内部端口 | `18788` |
| `--webmail-host <HOST>` | Webmail 监听地址 | `127.0.0.1` |
| `--admin-password-stdin` | 从标准输入读取管理员密码 | 交互输入 |
| `--non-interactive` | 非交互静默安装 | 关 |
| `--reuse-admin` | 复用已有管理员凭证（升级用） | 关 |
| `--https` | 强制 HTTPS 安全 Cookie 标记 | 按模式决定 |
| `--i-understand-plain-http` | plain 模式非交互安装的显式风险确认 | 关 |
| `--allow-caddy-degrade` | 允许 Caddy 降级场景继续安装 | 关 |

## 部署向导

安装完成后首次登录管理后台，建议按向导完成部署（每步都调用特权助手做真实校验）：

1. **服务器身份**：设置主机名、时区、管理员邮箱等
2. **DNS 校验**：添加邮件域名，校验 MX / SPF / DKIM / DMARC / PTR 记录，可调用 AI 助手解释与给建议
3. **投递方式**：选择 SMTP Relay（内置 Oracle OCI / SES / SendGrid / Brevo / Resend 预设）或服务器直连；Relay 走真实 TLS 认证测试，直连模式对本机 Postfix 做纯 EHLO 探测
4. **TLS 证书**：ACME 签发（特权调用默认 120 秒超时，可用 `MAILSTACK_HELPER_TIMEOUT_MS` 调整）
5. **发信测试**：闭环投递验证
6. **部署摘要**：确认全部配置

也可随时在控制台的 Setup Guide 页面重新执行，或用 `ms test-mail` 复测投递链路。

## DNS 记录指引

要可靠收发外部邮件，域名需配置（控制台 DNS 页面会给出逐条记录与实时状态）：

| 记录类型 | 主机 | 示例值 | 作用 |
|---|---|---|---|
| A / AAAA | `mail.example.com` | 服务器公网 IP | 主机解析 |
| MX | `example.com` | `mail.example.com.`（优先级 10） | 接收邮件 |
| SPF | `example.com` | `v=spf1 mx -all`（使用 SES/SendGrid 等 Relay 时改为对应 `include:`） | 声明合法发信来源 |
| DKIM | `default._domainkey.example.com` | OpenDKIM 公钥（管理台一键复制） | 邮件签名验证 |
| DMARC | `_dmarc.example.com` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com` | 策略与报告 |
| PTR | 反向解析 | 指向 `mail.example.com` | 接收方信誉（在 VPS 控制台设置） |

## Webmail 使用

- 访问 `http://127.0.0.1:18788`（SSH 隧道）或 `https://webmail.example.com`（caddy 模式）
- 使用**邮箱用户**（在管理台「用户」页创建的 Linux 邮箱账号）登录，认证走 Dovecot
- 支持收件箱列表与搜索、邮件阅读（自动处理 MIME 与多字符集编码）、已读标记、发信
- Webmail 服务与管理台完全隔离：独立系统账号、无 sudo 权限、更严格的 systemd 沙箱（`ProtectSystem=strict`、`NoNewPrivileges=true`）

## CLI 命令参考

安装完成后系统会链接 `/usr/local/bin/ms`（别名 `mailstack`）。在 VPS 任意目录运行：

```bash
ms
```

### 常用命令

| 命令 | 说明 |
|---|---|
| `ms doctor` | 全栈健康体检：操作系统、负载、磁盘、内存、核心服务状态、Postfix/Dovecot 配置检查、端口连通、队列积压、托管域名、关键文件权限、AI 凭据；输出 PASS/WARN/FAIL 与修复建议，给出总体 HEALTHY/WARNING/CRITICAL |
| `ms test-mail [邮箱]` | 邮件闭环投递验证（Roundtrip Loopback）：真实发信 → 收信 → Maildir 落地确认，输出跟踪令牌与往返延迟毫秒数 |
| `ms status` | 查看 `mailstack-web` 与 `mailstack-webmail` 服务状态 |
| `ms logs [admin\|webmail]` | 实时查看服务日志（systemd 环境走 `journalctl`） |
| `ms version` | 查看当前安装版本 |

### 备份 / 恢复 / 回滚

| 命令 | 说明 |
|---|---|
| `ms backup create [--include-mails]` | 创建配置备份（Postfix / Dovecot / OpenDKIM / MailStack 配置；加 `--include-mails` 连邮件数据一起打包），输出路径与 SHA256 |
| `ms backup list` | 列出历史备份（名称、时间、大小、是否含邮件） |
| `ms restore <备份文件>` | 安全还原：自动生成「还原前回滚快照」，文件名 / SHA256 / 显式确认三重校验，还原后自动重载服务 |
| `ms rollback` | 快速回滚到最近一次还原前快照 |

### 安装与维护

| 命令 | 说明 |
|---|---|
| `sudo bash mailstack.sh install [选项]` | 安装（见[快速开始](#快速开始)） |
| `ms upgrade` | 从官方仓库热更新：拉取最新源码 → 用 `/etc/mailstack/install-args.conf` 中持久化的原部署参数静默重装 → 原子替换安装目录 |
| `ms uninstall --dry-run` | 卸载预演：列出将要停止的服务、删除的文件、保留的数据，不做任何改动 |
| `ms uninstall [--purge]` | 卸载（见[卸载](#卸载)） |
| `ms help` | 命令帮助 |

## 更新与升级

```bash
cd MailStack
git pull
sudo bash ./mailstack.sh update   # 或直接运行 ms upgrade
```

- 升级会读取 `/etc/mailstack/install-args.conf`，把首次安装时的访问模式、域名、端口、HTTPS 行为原样透传，避免升级后 plain/caddy 部署监听行为漂移
- 管理员凭证默认复用（`--reuse-admin`）
- 即使升级流程保留了管理配置，也**建议**执行前创建 VPS 快照并备份 `/etc/mailstack`、Postfix、Dovecot、DKIM 密钥与邮件数据；或先跑 `ms backup create`

## 备份与灾难恢复

- 备份存放于 `/var/backups/mailstack`，文件名与内容 SHA256 写入元数据
- **还原即换挡**：`ms restore` 会在还原前自动生成 `mailstack-backup-*-pre-restore.tar.gz` 回滚快照，任何还原失败或结果不符都可用 `ms rollback` 一步回退
- 还原链路有严格校验：仅接受规范的备份文件名、匹配元数据 SHA256、必须显式确认，且拒绝不安全的归档成员
- 恢复的对象是 Postfix / Dovecot / OpenDKIM / MailStack 管理配置；邮箱数据默认不动，需要时用 `--include-mails`

## 卸载

```bash
# 预演（不改动任何东西）
sudo bash ./mailstack.sh uninstall --dry-run

# 卸载程序，保留 /etc/mailstack 管理配置
sudo bash ./mailstack.sh uninstall

# 卸载程序并删除 /etc/mailstack 管理配置
sudo bash ./mailstack.sh uninstall --purge
```

卸载行为：

- 停止并注销 `mailstack-web`、`mailstack-webmail`，删除服务单元、`ms` 命令链接、特权助手与 sudoers 规则
- 清理 MailStack 写入的组件配置：Dovecot `99-mailstack*.conf`、logrotate 条目；`/etc/caddy/Caddyfile` 仅当含 MailStack 管理标记时先备份为 `Caddyfile.mailstack-backup` 再移除
- **绝不自动删除** Postfix、Dovecot 本体、Linux 邮箱用户和 `/home/*/Maildir`、`/var/vmail` 邮件数据，避免误删生产邮箱

## 端口与环境变量

| 服务 / 模块 | 默认端口 | 环境变量 | 默认监听 | 说明 |
|---|---|---|---|---|
| **Admin 控制台** | `8787` | `PORT`, `HOST`（兼容旧名 `ADMIN_PORT`, `ADMIN_HOST`，`ADMIN_*` 优先） | `127.0.0.1:8787` | 管理面板与特权 RPC 调度端点 |
| **Webmail 客户端** | `18788` | `WEBMAIL_PORT`, `WEBMAIL_HOST` | `127.0.0.1:18788` | 独立 Webmail 邮箱服务 |
| **安全 Cookie** | - | `COOKIE_SECURE` | `0`（local）/ `1`（caddy、direct） | 启用 `Secure; SameSite=Strict` |
| **运行环境** | - | `NODE_ENV` | `production` | 生产模式 |
| **特权调用超时** | - | `MAILSTACK_HELPER_TIMEOUT_MS` | `120000`（下限 5000） | ACME 首签通常需要 30–90 秒，默认超时已放宽 |
| **AI 托管密钥** | - | `GLM_API_KEY` | 空 | 可选：托管 GLM 诊断密钥（也可在界面配置） |
| **内网 AI 端点** | - | `MAILSTACK_ALLOW_PRIVATE_AI` | 未启用 | 显式允许内网 AI 端点（默认禁止，防 SSRF） |

环境变量可写入 `.env`（模板见 [.env.example](.env.example)）或配置在 systemd 服务的 `Environment=` 中。生产环境由安装器写入 systemd 单元，一般无需手工修改。

## 安全模型

MailStack 的特权面收敛到唯一入口，纵深防御各层如下：

### 进程与账号隔离

- `mailstack-admin`（管理台）与 `mailstack-webmail`（Webmail）是两个独立的无登录系统账号
- `/opt/mailstack` 目录本身属主为 `root:root 0755`，服务账号不可写——防止服务账号整体替换 `backend/` 并借 sudoers 规则以 root 执行伪造代码（本地提权链）；仅运行所需的 `ui/`、`server.cjs`、`webmail.cjs`、`webmail-public/` 归服务账号
- Webmail 账号**没有任何 sudo 权限**，不进 `mail` 组的管理面，只通过 Dovecot auth socket 认证并受控读取 Maildir

### 特权操作最小化

- 唯一特权入口 `/usr/local/libexec/mailstack-privileged`（root 属主、服务账号不可修改）；sudoers 精确到该文件，**无参数通配符**
- 特权助手内置 44 个动作白名单（`ALLOWED_ACTIONS`），白名单外直接拒绝
- 删除域名、删除用户、删除备份属危险动作（`DESTRUCTIVE_ACTIONS`），必须携带显式 `confirm: true`
- 所有特权 RPC 写审计日志 `/var/log/mailstack-rpc-audit.log`（0600）：时间、UID、动作、目标、结果、错误

### Web 认证与会话

- 管理员口令以 **PBKDF2-SHA256、310000 次迭代、16 字节随机盐** 存于 `/etc/mailstack/admin.json`（0640，root:mailstack-admin），永不明文落盘
- `HttpOnly` Session Cookie，HTTPS 模式附加 `Secure` 与 `SameSite=Strict`
- 全部 `/api/*`（登录与健康检查除外）要求会话；写操作带 CSRF 校验；AI 接口独立速率限制；JSON 请求体上限 256 KB
- 密码修改等敏感输入经 stdin / 环境变量传递后立即 `unsetenv`，不出现在进程 argv

### systemd 沙箱

- `mailstack-web`：`ProtectSystem=full` + `ReadWritePaths=/etc`（特权 helper 需要 `postconf -e` 写 `/etc/postfix` 等；`/usr`、`/boot` 保持只读）、`ProtectHome=read-only`、`PrivateTmp`、`ProtectKernelTunables`、`ProtectControlGroups`、`RestrictRealtime`
- `mailstack-webmail`：更严格的 `ProtectSystem=strict`、`NoNewPrivileges=true`、`ProtectKernelModules`、`RestrictSUIDSGID`，仅放行 `/home`、`/var/vmail` 写路径

### 出站请求加固（防 SSRF / DNS Rebinding）

- AI 与 SMTP 出站请求：先解析域名，校验每个解析结果的 IP（拦截回环、内网、链路本地、**CGNAT 100.64.0.0/10**、组播、保留地址），再**钉定解析到的 IP** 建立连接，防解析切换攻击
- 自定义 AI 端点强制 HTTPS、拒绝凭据内嵌 URL；默认禁止内网端点；响应 2 MB 上限；跨域重定向拒绝
- 直连投递探测使用固定回环部署常量（非用户输入），与 SSRF 防护语义解耦

### 发布与供应链

- 预构建产物带 `build-manifest.json`，安装器逐文件 SHA256 校验后才使用
- 可复现打包（`SOURCE_DATE_EPOCH`），发布物 ZIP / TAR.GZ 与分离的 `SHA256SUMS` 一同上传，CI 校验两次打包哈希一致
- 第三方安装脚本（NodeSource）不再 `curl | bash`：先下载到临时文件、SHA256 记入安装日志留痕再执行
- CI 供应链门禁：`npm audit` 高危硬门禁 + 可修复中危门禁 + CycloneDX SBOM 生成

### 运行时自检

- 安全中心持续扫描：Postfix relay 限制缺失、Fail2ban 未启用、`sasl_passwd` 权限过宽、无托管证书等事件并给出安全评分
- Fail2ban 封禁 / 解封（jail 名白名单校验）
- `ms doctor` 体检覆盖关键文件权限（如 `admin.json` 应为 0640）

## AI 邮件顾问

AI 中心（AiSuite）提供聊天助手、诊断与结构化解析三类能力：

- 邮件 DNS 配置解释与逐记录建议（MX / SPF / DKIM / DMARC / PTR）
- TLS 与 SMTP Relay 故障排查
- 日志与退信片段分析

支持的提供商：

| 提供商 | 预设端点 | 默认模型 | 协议 |
|---|---|---|---|
| **GLM (BigModel)**（默认） | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-flash`（可选 `glm-4-plus` / `glm-4-air` / `glm-4-long`） | OpenAI-compatible |
| **DeepSeek** | `https://api.deepseek.com/v1` | `deepseek-chat` | OpenAI-compatible |
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o-mini` | OpenAI-compatible |
| **Anthropic Claude** | `https://api.anthropic.com/v1` | `claude-3-5-sonnet-20241022` | Anthropic Messages |
| **自定义** | 任意公网 HTTPS OpenAI-compatible / Anthropic 端点 | 自填 | OpenAI / Anthropic |

安全与隐私：

- API Key 只保存在服务器端 `/etc/mailstack/ai-provider.json`，**不返回浏览器**（前端只拿到「已配置」状态与脱敏信息）
- 端点 SSRF 加固（见[安全模型](#安全模型)）；内网端点默认禁用
- 无外部 AI API 时自动使用**本地规则诊断**，核心检查能力不缺席
- 第三方服务商的免费额度、模型、地区限制和数据政策可能变化，请以服务商当前控制台与条款为准
- **AI 建议不能代替管理员审查，也不能保证邮件送达**

## 测试与质量保障

### 本地测试命令

| 命令 | 内容 |
|---|---|
| `npm run lint` | TypeScript 全量类型检查（`tsc --noEmit`） |
| `npm test` | Node 内置 test runner：API 契约、业务集成、生命周期兼容、安全静态检查、可观测性、清单完整性、发布一致性等 13 个测试套件（另有前端 Vitest 用例） |
| `npm run test:frontend` | Vitest + Testing Library 前端组件测试（jsdom） |
| `npm run test:helper` | Python 特权助手行为级单元测试（真实地址 / 真实参数调用） |
| `npm run test:backup` | 备份 / 还原端到端测试 |
| `npm run test:all` | 上述全部 + 构建 |
| `npm run build:all` | 前端构建 + 服务端打包 + Webmail 打包 + 产物清单生成 |

### CI 门禁（GitHub Actions）

| Job | 内容 |
|---|---|
| **build** | Node 20 / 22 / 24 三版本矩阵：类型检查、Python 助手测试、Node 契约与集成测试、前端测试、`build:all`、产物 `node --check`、发布版本一致性、清单哈希校验、shell 语法与 LF 检查、可复现打包校验（两次打包 SHA256SUMS 必须一致） |
| **shell-gate** | `shellcheck`（error 级硬门禁）+ 发布脚本未定义函数调用扫描——因 `warn()` 未定义导致安装崩溃的缺陷类问题在提交阶段即被拦截 |
| **install-matrix** | 在 **ubuntu:24.04、ubuntu:22.04、debian:12、rockylinux:9** 四个干净容器内执行真实非交互安装，断言双服务健康端点 + 权限模型（`/opt/mailstack` 必须为 root 属主） |
| **supply-chain** | `npm audit` 高危硬门禁、可修复中危门禁、CycloneDX SBOM 上传 |

## 项目结构

```text
mailstack.sh                      统一入口：install / update / doctor / test-mail /
                                  backup / restore / rollback / uninstall / status / logs
├── deploy/
│   ├── install.sh                交互式与非交互式安装器（访问模式、构建、账号、systemd、Caddy）
│   ├── install-mail-stack.sh     Postfix / Dovecot / OpenDKIM 等邮件基础栈安装与校验
│   ├── install-v05.sh            面向 Release 压缩包的安装入口
│   ├── mailstack-privileged      root 特权入口 wrapper（sudoers 唯一放行目标）
│   ├── mailstack.logrotate       日志轮转配置（单一来源）
│   ├── reverse-proxy-nginx.example.conf   Nginx 反代示例（direct 模式）
│   ├── verify-release-scripts.sh 发布脚本未定义函数扫描（CI shell-gate）
│   ├── verify-source-build.sh    Windows / 源码构建验证脚本
│   └── privacy-audit.sh          隐私扫描
├── backend/
│   ├── server.production.ts      Express 管理台：认证、会话、RPC 代理、遥测接口、静态托管
│   └── mailstackctl/
│       ├── core.py               常量、正则白名单、审计日志、服务控制、密码策略
│       ├── dispatcher.py         RPC 动作分发（白名单 + 危险动作确认）
│       ├── mail.py               域名 / 用户 / 别名 / 队列 / 闭环投递验证
│       ├── network.py            端口探测、部署向导（身份/DNS/Relay/发信测试）
│       ├── certs.py              证书签发 / 续期 / 列表、DKIM 轮换
│       ├── backup.py             备份 / 还原 / 快照（SHA256 元数据 + 安全归档校验）
│       ├── security.py           安全扫描、Fail2ban 封禁引擎
│       ├── telemetry.py          体检 doctor、日志、设置、实时指标、服务状态
│       ├── ai.py                 AI 预设、SSRF 防护、多协议请求、诊断
│       └── version.py            版本常量
├── webmail/
│   ├── server.mjs                独立 Webmail 服务（Dovecot 认证、Maildir、sendmail 提交）
│   └── public/                   Webmail 前端（无框架轻量实现）
├── src/                          React 管理后台源码
│   ├── components/views/         Dashboard / Domains / Users / Aliases / Queue / Logs /
│   │                             Services / Security / Certificates / DKIM-DNS / Relay /
│   │                             SetupGuide / AI 系列 / 设置 / 登录
│   ├── components/setup/         部署向导各步骤
│   ├── components/dns/           DNS 向导 / 指引表 / AI 助手
│   └── components/telemetry/     遥测图表
├── scripts/                      打包、清单生成、E2E 与矩阵测试脚本
├── tests/                        Node / Vitest / Python 测试套件
├── docs/
│   ├── SUPPORT_MATRIX.md         发行版支持矩阵
│   ├── DEPENDENCY_POLICY.md      依赖与运行时策略
│   ├── RELEASE_CHECKLIST.md      发布检查清单
│   └── verification/             真机验证记录（Ubuntu 24.04 / Debian 12 / 邮件投递 E2E）
├── .github/workflows/ci.yml      CI 四大门禁
├── .env.example                  环境变量模板
├── CHANGELOG.md                  逐版本变更（含安全修复背景）
└── assets/                       项目 Logo
```

## 开发指南

技术栈：React 19、TypeScript 5.8、Vite 6、Tailwind CSS 4、Express 4、esbuild、Node 内置 test runner、Vitest、Python 3 标准库。

```bash
npm install          # 安装依赖
npm run dev          # 启动 Vite 开发服务器（前端）
npm run lint         # 类型检查
npm run build:all    # 前端 + 管理台 + Webmail + 产物清单
npm start            # 运行打包后的管理台 (dist/server.cjs)
npm test             # Node 测试
```

生产部署不需要手工构建：安装脚本会优先校验并使用预构建产物，否则自动 `npm ci && npm run build:all` 并注册 systemd 服务。

依赖策略（见 [docs/DEPENDENCY_POLICY.md](docs/DEPENDENCY_POLICY.md)）：两个发布产物 `dist/server.cjs` 与 `dist/webmail.cjs` 为 esbuild 独立打包，**运行时无需 `node_modules`**；特权助手只用 Python 标准库；新增网络相关依赖需安全评审并记录发布说明。

## 已知限制

- RC 阶段：部分发行版（Tier 2 / 实验性）尚未完成端到端真机测试
- 前端日志页默认 5 秒轮询 `logs.list`，每次调用 spawn 一组 sudo + Python 进程，空载场景存在进程抖动（计划引入长驻 helper 或 WebSocket 推送）
- Webmail 前端部分模板插值尚未逐一过 `escapeHtml`（多数渲染受控状态，仍在逐点加固中）
- 高级 Relay 故障转移与防重复投递状态机仍需继续验证；ACME 首签、DNS API 凭据轮换与多 CA 回滚仍需增强
- DKIM、Rspamd、ClamAV、Fail2ban 与防火墙功能在不同发行版上可能需要适配
- 演示 / Mock 数据不代表真实服务器结果；AI 建议不能代替管理员审查

## FAQ

**Q: 为什么默认只监听 127.0.0.1？**
管理后台持有特权 RPC 通道，默认不暴露公网是最安全的基线。需要公网访问时选择 `caddy` 模式（自动 HTTPS）或 `direct` 模式（自备反代），`plain` 明文模式仅供内网隔离测试。

**Q: 忘记把端口暴露出去，打不开后台怎么办？**
本地执行 `ssh -L 8787:127.0.0.1:8787 -L 18788:127.0.0.1:18788 root@服务器IP`，再访问 `http://127.0.0.1:8787`。

**Q: Webmail 登录用什么账号？**
在管理台「用户」页创建的邮箱用户（即 Linux 系统邮箱账号），认证经 Dovecot 完成。

**Q: 升级会丢配置吗？**
升级会复用管理员凭证并透传首次安装持久化的部署参数（`/etc/mailstack/install-args.conf`）。稳妥起见，升级前执行 `ms backup create`。

**Q: 能保证邮件进对方收件箱吗？**
不能。送达率取决于 IP / 域名信誉、DNS 身份认证完整度、内容质量与接收方策略。MailStack 帮你把可控部分（MX / SPF / DKIM / DMARC / PTR / TLS / Relay）做对，并内置体检与 AI 诊断定位问题。

**Q: 特权助手能执行任意命令吗？**
不能。Web 侧全部特权操作收敛到唯一 wrapper，只接受 44 个白名单动作，危险动作需显式确认，所有调用写审计日志。

## 贡献

欢迎通过 Issue 报告可复现问题，提交前请说明：

- 操作系统及版本、MailStack 版本、安装方式
- 相关服务状态（`ms status`、`ms doctor` 输出）
- 已脱敏的错误日志与复现步骤

**请勿公开提交** SMTP 密码、管理员哈希、AI Key、DKIM 私钥、TLS 私钥、ACME DNS 凭据、邮箱正文或未脱敏生产日志。

提交代码请保证 `npm run test:all` 通过；涉及发布脚本请留意 CI 的 shellcheck 与装机矩阵门禁。

## 安全问题

安全漏洞**不要**在公开 Issue 披露。请使用 GitHub Private Vulnerability Reporting，或通过仓库维护者提供的私密渠道报告（见 [SECURITY.md](SECURITY.md)）。

## 文档索引

| 文档 | 内容 |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | 逐版本变更，含每个安全修复的完整背景分析 |
| [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) | 发行版支持矩阵与 Tier 定义 |
| [docs/DEPENDENCY_POLICY.md](docs/DEPENDENCY_POLICY.md) | 运行时模型、工具链与依赖规则 |
| [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) | 发布检查清单与可复现打包 |
| [docs/verification](docs/verification) | Ubuntu 24.04 / Debian 12 真机验证记录、邮件投递 E2E |
| [README_EN.md](README_EN.md) | English README |
| [.env.example](.env.example) | 环境变量模板 |

## 许可证

MailStack 使用 [MIT License](LICENSE)。

Copyright (c) 2026 MailStack contributors

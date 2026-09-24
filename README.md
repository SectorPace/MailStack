<p align="center">
  <img src="assets/mailstack-logo.png" alt="MailStack Logo" width="180">
</p>

<h1 align="center">MailStack</h1>

<p align="center">
  多平台 Linux 邮件服务部署与管理套件<br>
  Postfix · Dovecot · OpenDKIM · Liquid Glass 管理后台 · 独立 Webmail · 2FA · 签名升级 · Docker · 一体化运维 CLI
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="https://github.com/SectorPace/MailStack">GitHub 项目</a> ·
  <a href="https://github.com/SectorPace/MailStack/releases">Releases</a> ·
  <a href="CHANGELOG.md">更新日志</a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.8.0--beta.8-2476ff">
  <img alt="Status" src="https://img.shields.io/badge/status-public%20beta-f0a53a">
  <img alt="Security" src="https://img.shields.io/badge/security-hardened-27b36a">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-27b36a">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Docker-22c7d6">
  <img alt="Node.js" src="https://img.shields.io/badge/Node.js-20%20%7C%2022%20%7C%2024-3c873a">
</p>

> **版本状态：v0.8.0-beta.9（公开测试）。** 本版本是 beta.8 的「构建与测试可复现性」修复。其一，`scripts/generate_manifest.mjs` 的 `builtAt` 此前会退回墙上时间（只有在「构建」前导出 `SOURCE_DATE_EPOCH` 才被固定），于是同一份源码两次 build+package 得到的 `build-manifest.json` 不一致、归档哈希随之变化，与 README 及 RELEASE_CHECKLIST 承诺的「两次打包哈希一致」直接矛盾；现改为回落到与 `scripts/package.py` 相同的常量 `1704067200`，不再依赖调用方是否导出环境变量。其二，修复 `tests/public-mode-gate.test.mjs` 中 T-2FA-1a 的启动竞态：子进程的启动 banner 与 TCP 连通分属两条无同步的通道，`waitForReady()` 返回只证明端口已绑定、并不保证父进程已收到 banner，实测约 1.3% 的运行会丢；现改为轮询等待目标日志落地，并在两处否定断言前先等 banner 到达。无接口与数据格式变更。
>
> **重要声明：MailStack 不保证邮件进入收件箱。** 实际送达结果受 IP 与域名信誉、DNS 身份认证（MX / SPF / DKIM / DMARC / PTR）、邮件内容、退信与投诉率、Relay 服务商策略以及接收方规则影响。

---

## 目录

- [项目简介](#项目简介)
- [功能总览](#功能总览)
- [架构总览](#架构总览)
- [部署方式：裸机与 Docker](#部署方式裸机与-docker)
- [支持范围](#支持范围)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [四种网络访问模式与公网安全基线](#四种网络访问模式与公网安全基线)
- [非交互安装](#非交互安装)
- [部署向导](#部署向导)
- [DNS 记录指引](#dns-记录指引)
- [管理员 2FA 与会话管理](#管理员-2fa-与会话管理)
- [Webmail 使用](#webmail-使用)
- [CLI 命令参考](#cli-命令参考)
- [更新与升级（签名通道）](#更新与升级签名通道)
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

MailStack 把在一台 Linux 服务器（或 Docker 容器）上自建邮件系统所需的整套组件 —— Postfix（SMTP）、Dovecot（IMAP 与本地投递）、OpenDKIM（签名）、Fail2ban —— 与一个 Liquid Glass 风格的 Web 管理后台、一个独立的 Webmail 客户端、一个常驻特权的 Python 助手和统一的 `ms` 运维 CLI 组合在一起，通过一次安装完成部署、构建、systemd / OpenRC / Docker 服务编排、权限与沙箱配置，并提供 DNS 指引、TLS 证书、SMTP Relay、邮件队列、日志、安全检查与可配置 AI 邮件顾问等日常管理能力。

设计目标：

- **一键可用**：从一行 `curl`（或 `git clone`）到三服务健康自检通过，一条命令完成；Node.js 等依赖钉版本自动装配；或直接 `docker compose up`。
- **默认安全**：Web 服务默认只监听 `127.0.0.1`；公网模式强制 2FA、强制加密备份、默认关闭 AI 出站；特权操作走双通道白名单助手，升级只接受签名验证过的 Release 资产。
- **可运维**：健康体检（含 Fail2ban 实弹探针）、邮件闭环投递验证、配置备份 / 还原 / 回滚、审计链校验，全部内置。
- **可审计**：特权 RPC 全量审计 + prev_hash 哈希链防篡改 + syslog AUTHPRIV 外送；发布产物 SHA256 清单 + ssh-keygen 签名；依赖下载钉扎。

## 功能总览

### 管理后台（Liquid Glass Web Console）

- React 19 + TypeScript + Vite + Tailwind CSS 4 构建的 Liquid Glass 风格单页控制台
- 简体中文 / 英文双语界面，Light 与 Dark 双主题
- 可自定义头像、Logo 样式与背景渲染效果；全局搜索、Toast 通知、错误边界
- 系统遥测：实时指标与历史图表（CPU / 负载 / 内存 / 磁盘 / 队列）
- 管理员 TOTP 双因素认证与活跃会话管理（见[下文](#管理员-2fa-与会话管理)）

### 邮件核心能力

| 能力 | 说明 |
|---|---|
| 邮件域名管理 | 多域名添加 / 删除，Postfix 域名注册与校验 |
| 邮箱用户管理 | 创建 Linux 系统邮箱用户（nologin + Maildir），启停状态、密码重置、删除；注册表位于 `/var/lib/mailstack`（webmail 可读，与配置分离） |
| 地址别名 | 别名添加 / 删除，显式域名拆分校验 |
| 邮件队列 | Postfix 队列查看与队列操作（队列 ID 白名单校验） |
| 服务管理 | Postfix / Dovecot / OpenDKIM / Fail2ban / Rspamd / ClamAV / Redis 的 start / stop / restart / reload / status |
| TLS 证书 | 证书列表、续期、向导式签发（acme.sh 钉版本 3.1.4 安装） |
| DKIM | 密钥生成、DNS 公钥展示（正确处理 RFC 跨行拆分）、密钥轮换；私钥权限策略 `root:opendkim 0640` 并纳入体检扫描 |
| SMTP Relay | 一键配置中继并落盘 `sasl_passwd`（0600），内置 Oracle OCI / Amazon SES / SendGrid / Brevo / Resend 预设与自定义 SmartHost |
| 安全中心 | 安全评分与事件扫描（relay 限制、Fail2ban 状态、`sasl_passwd` 权限、证书缺失、明文备份归档）、Fail2ban 封禁 / 解封（运行时 jail 白名单，支持 `recidive` 等自定义 jail） |
| 域名 DNS 体检 | MX / SPF / DKIM / DMARC / PTR 校验指引与逐记录状态（含 Relay 服务商专项检查） |

### 独立 Webmail 客户端

- 独立 `mailstack-webmail` systemd 服务，与管理后台完全隔离（独立系统账号、独立端口、更严格沙箱、无任何 sudo 权限）
- 邮箱账号认证走 **Dovecot `auth-client` unix socket 协议**（`webmail/dovecot-auth.mjs`），密码只进 socket 负载、**绝不进入进程 argv**；socket 不可用时 fail-closed；错误密码与不存在用户返回完全相同的 401（消除用户枚举）
- 收件箱列表、搜索、MIME / encoded-word / 多字符集解析、已读标记；通过本机 `sendmail`（Postfix）提交外发
- 会话：滑动 TTL + **7 天绝对上限**；改密 / 锁定账号即按用户 bump 会话 epoch，全部旧会话失效
- CSRF 防护、登录尝试限制（5 次锁 15 分钟）与接口级速率限制
- 安全读取邮件文件：`O_NOFOLLOW` 防符号链接、大小上限、路径规范化

### 部署向导（Setup Wizard）

首次登录后的分步引导，覆盖：服务器身份 → DNS 校验 → 投递方式（Relay 测试 / 直连 EHLO 探测）→ TLS 证书签发 → 发信闭环测试 → 部署摘要。每一步都调用特权助手做真实校验。

### 一体化运维 CLI（`ms`）

`ms doctor` 全栈体检（含 Fail2ban ban/unban 实弹往返探针）、`ms audit-verify` 审计哈希链校验、`ms test-mail` 闭环投递验证、`ms backup / restore / rollback` 配置灾备（支持加密）、`ms upgrade` 签名升级（可钉版本、拒绝降级）等，详见 [CLI 命令参考](#cli-命令参考)。

### 灾备与可观测性

- 备份支持 **gpg 对称加密（AES256）**，口令只经 stdin 传递；公网模式强制加密
- 审计日志 prev_hash 哈希链 + `.head` 锚点（防截尾），镜像外送 syslog `AUTHPRIV`；`ms audit-verify` 校验链完整性供监控对接
- 实时指标、服务日志、安装日志、降级组件摘要

## 架构总览

```text
                        ┌────────────────────────────────────────────────┐
                        │                浏览器（管理员 / 邮箱用户）        │
                        └────────────┬──────────────────────┬────────────┘
                                     │ HTTPS / SSH 隧道      │
                   ┌─────────────────▼──────────┐  ┌────────▼─────────┐
                   │  mailstack-web (Admin)     │  │ mailstack-webmail │
   访问模式         │  Express + React 静态托管   │  │ Dovecot auth-     │
  local/caddy/     │  127.0.0.1:8787            │  │ client socket 认证│
  direct/plain     │  公网模式强制 2FA           │  │ 127.0.0.1:18788   │
                   └───────┬───────────┬────────┘  └────────┬─────────┘
                           │           │                    │ 受控读 Maildir
              RO: unix socket│           │ RW: sudo 包装器     │
                           ▼           ▼                    │
                   ┌────────────────────────────────┐          │
                   │  mailstack-helper (root 常驻)   │          │
                   │  helper-ro.sock 0660 只读面     │          │
                   │  helper.sock    0600 变更面     │          │
                   │  SO_PEERCRED 对端校验 + 动作白名单│          │
                   │  审计哈希链 → 文件 + syslog      │          │
                   └───────────────┬────────────────┘          │
                                   │ postconf / doveadm / opendkim-genkey /
                                   │ fail2ban-client / systemctl / acme.sh ...
                        ┌──────────┼───────────────┬───────────────┐
                        ▼          ▼               ▼               ▼
                   ┌────────┐ ┌─────────┐  ┌────────────┐  ┌────────────┐
                   │Postfix │ │Dovecot  │  │ OpenDKIM   │  │ Fail2ban   │
                   └────────┘ └─────────┘  └────────────┘  └────────────┘
```

组件职责：

| 组件 | 进程 / 文件 | 系统账号 | 职责 |
|---|---|---|---|
| 管理控制台 | `mailstack-web.service` → `/opt/mailstack/server.cjs` | `mailstack-admin`（nologin） | 登录认证（密码 + TOTP）、会话、静态资源；只读 RPC 直连 `helper-ro.sock`，变更 RPC 经 sudo 包装器转发 |
| 特权助手 | `mailstack-helper.service`（root 常驻 daemon）+ 一次性 sudo 包装器 `/usr/local/libexec/mailstack-privileged` | root | 全部需要 root 的操作；RO/RW 双 socket 通道、SO_PEERCRED 对端校验、动作白名单、危险动作二次确认、审计哈希链 |
| Webmail | `mailstack-webmail.service` → `/opt/mailstack/webmail.cjs` | `mailstack-webmail`（nologin，属 dovecot/mail 组） | 邮箱用户登录（Dovecot auth socket）、Maildir 读取、发信提交；**无任何 sudo 权限** |
| 邮件栈 | Postfix / Dovecot / OpenDKIM / Fail2ban | 系统服务 | 实际收发信、本地投递、DKIM 签名、暴力破解防护 |
| 运维 CLI | `/usr/local/bin/ms` → `/opt/mailstack-source/mailstack.sh` | root（自行提权） | 安装 / 升级 / 卸载 / 体检 / 备份 / 还原 / 回滚 / 审计校验 |

特权动作按「是否改变本机状态」拆分：

- **RO 通道**（`/run/mailstack/helper-ro.sock`，0660 root:mailstack-admin，Node 直连）：14 个只读动作（快照、体检、日志、指标、列表类查询等）
- **RW 通道**（`/run/mailstack/helper.sock`，0600 root:root，仅 sudo 包装器可达）：其余变更动作（域名 / 用户 / 别名 / 队列 / 备份 / 2FA / AI 配置等）
- 通道而非 uid 决定动作子集：RO 面收到 RW 动作即便 uid=0 也拒绝并写 `ro_channel_violation` 审计；每连接 `getsockopt(SO_PEERCRED)` 校验对端 uid，越权即断连

## 部署方式：裸机与 Docker

### 裸机部署（systemd / OpenRC / init.d）

完整邮件栈直接落在宿主机，注册三个 systemd 服务（`mailstack-helper`、`mailstack-web`、`mailstack-webmail`）；无 systemd 的环境（如 Alpine）走 OpenRC / init.d 分支（`setsid` 脱离安装会话）。

### Docker 单容器

无 systemd 环境（NAS、容器平台、临时验证环境）可使用官方镜像编排，详见 [docs/DOCKER.md](docs/DOCKER.md)：

```bash
# 构建（需要网络：apt + npm registry + nodejs.org 钉哈希下载）
docker compose build

# 首次启动：显式指定管理员口令（12-256 位，须同时含字母与数字）
MAILSTACK_ADMIN_PASSWORD='Your-Strong-Admin-Pass-7' docker compose up -d
# 或留空：entrypoint 生成随机口令并在日志中只打印一次
docker compose up -d
docker compose logs mailstack | grep -A4 '随机管理员口令'

# 验证（compose 默认只把管理台 / Webmail 绑到宿主回环）
curl http://127.0.0.1:8787/api/health
curl http://127.0.0.1:18788/api/webmail/health
```

要点：

- **6 进程前台模型**（helper / postfix / dovecot / opendkim 可选 / admin / webmail），任一进程退出即整体退出；`tini` 作 PID1
- 镜像基线 `ubuntu:24.04`，构建完全复用裸机安装器（与 CI 装机矩阵同一路径）；构建期口令当场随机生成、装完即删，**明文口令绝不进入任何镜像层**，真实口令在首启时由 entrypoint 写入数据卷
- 8 个数据卷：`/etc/mailstack`、`/var/lib/mailstack`、`/home`（Maildir）、`/var/spool/postfix`、`/var/backups/mailstack`、`/etc/postfix`、`/etc/dovecot`、`/etc/opendkim`
- 端口：管理台 8787 / Webmail 18788（默认绑宿主回环）；SMTP 25 / 465 / 587；IMAP 143 / 993；POP3 110 / 995
- **A6 管理口门**：容器内非环回 admin 绑定必须同时携带 `MAILSTACK_LISTEN_HOST=0.0.0.0` 与 `MAILSTACK_I_PUBLISH_ADMIN=1` 双旗标，缺一拒绝启动
- ⚠️ 家用 / 企业宽带出站 25 端口常被运营商封锁，对外投递测试很可能失败；本地验证以 587（提交）/ 143（IMAP）/ 8787 / 18788 为主

## 支持范围

Tier 表来自 [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)（以随版本的发布物为准）：

| 发行版 | 版本 | 支持级别 | 安装路径 | 验证方式 |
|---|---|---|---|---|
| Ubuntu | 22.04 / 24.04 LTS | **Tier 1** | APT + systemd | 真机验证记录 + CI 装机矩阵 |
| Debian | 12 (Bookworm) | **Tier 1** | APT + systemd | 真机验证记录 + CI 装机矩阵 |
| RHEL / Rocky / AlmaLinux | 9.x | Tier 2 | DNF + systemd | `scripts/test_distro_matrix.py` |
| openSUSE Leap / Tumbleweed | 15.x / rolling | Tier 2 | Zypper + systemd | `scripts/test_distro_matrix.py` |
| Alpine Linux | 3.19+ | 实验性 | APK + OpenRC | 生产使用前请自行验证 |

平台能力注记（详见 SUPPORT_MATRIX）：

- **musl 系统（Alpine）**：发行版仓库不满足 Node 20-24 时，回退 Node 官方 unofficial-builds `linux-x64-musl` 构建（v22.20.0，SHA256 钉死）；该渠道无 arm64-musl，musl + arm64 依赖发行版包
- **dnf 系 OpenDKIM 可选**：仓库无 opendkim 包时（如 openEuler 25.09）按预设降级路径跳过 DKIM——收发信不受影响，后续手动安装并 `dkim.rotate` 即可启用
- **EL9 Python ≥3.10 硬门禁**：后端使用 PEP 604 语法，解释器升级后仍不达标即明确失败（而非产出 import 即崩的栈）
- **Arch 旧快照自愈**：安装前刷新 `archlinux-keyring`；icu SONAME 缺失时从本地缓存 / archive.archlinux.org 动态解析补齐
- **fail2ban pip 兜底**：仓库无包时从钉 SHA256 的 GitHub 1.1.0 tarball 安装并手动展开 `/etc/fail2ban` 配置树
- **孤儿端口清理**：启动服务前 `fuser -k` 只杀实际占用 8787 / 18788 的进程，中断重跑安装不再 EADDRINUSE

**本地实测记录**：本版本线已在 **Ubuntu / Debian / Kali / AlmaLinux 10 / OracleLinux 9.5 / openEuler 25.09 / openSUSE Tumbleweed / Arch / Alpine 3.24** 九个发行版上完成两轮安装验证（含中断重跑、卸载重装；8/9 systemd + Alpine OpenRC/init.d 分支）全部通过。

## 环境要求

| 项目 | 要求 |
|---|---|
| 部署形态 | 裸机 Linux（systemd / OpenRC / init.d）或 Docker（`ubuntu:24.04` 基线镜像） |
| 权限 | root（安装脚本自行 `sudo` 提权）；Docker 与 docker compose |
| Shell | Bash |
| Node.js | **20 – 24**（`engines: >=20 <25`）；不满足时安装器自动安装钉 SHA256 的官方构建 |
| Python | **≥ 3.10（硬门禁）**（特权助手与运维工具，仅用标准库） |
| 其他命令 | `python3`、`sudo`、`rsync`、`tar`；`git`（仅开发者 git 升级通道需要）；`curl` + `ssh-keygen`（仅一行式安装与 `ms upgrade` 的签名 Release 通道需要，OpenSSH ≥ 8.0） |
| 可选组件 | `gpg`（备份加密；公网模式为必需）、`fail2ban`（安全中心与 doctor 探针） |
| 端口 | 25（SMTP 收信）；管理 8787 与 Webmail 18788 默认仅监听本机回环 |
| DNS | `caddy` 公网模式需要域名 A/AAAA 指向服务器公网 IP（80/443 空闲供 Caddy 签发证书） |

## 快速开始

### 一行式安装（推荐）

以 root 身份执行（`sudo -i` 或 `su -`）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh)
```

`curl -fsSL` 可换成 `wget -qO-`（引导段本身依赖 curl，最小化系统请先装 curl）。不想先切 root 就用等价的 `bash -c` 写法，同样是一行：

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh)"
```

> **别写成 `sudo bash <(curl …)`**：sudo 会关闭 3 号以上的文件描述符，bash 取不到 `/dev/fd/63`——实测 sudo 1.9.15 报 `bash: /dev/fd/63: No such file or directory`，退出码 127。进程替换必须由**将要执行脚本的那个 shell** 自己完成。

进程替换只是把脚本正文挂在一个 fd 上，**stdin 仍然是终端**：交互式问答、管理员口令输入、`--admin-password-stdin` 全都正常。这正是它优于 `curl … | sudo bash` 的地方——管道形态下 stdin 就是脚本正文，安装器的 `read` 只会拿到 EOF（脚本会把 stdin 接回 `/dev/tty` 兜底，确实没有控制终端时则明确失败而不是挂死）。

`deploy/install.sh` 不含任何源码与安装逻辑，它能单文件运行是因为按与 `ms upgrade` 完全相同的信任模型自举：从 GitHub Release 取 `MailStack-<tag>.tar.gz` + `SHA256SUMS` + `SHA256SUMS.sig` 三件套，先 `ssh-keygen -Y verify` 做分离签名验签、再 `sha256sum -c`，全部通过后才解压到 `/opt/mailstack-source` 并 `exec` 真正的安装器——**引导段本身不执行任何未经签名验证的远程内容**。

`sh`/`dash`/`csh` 等没有进程替换的 shell 用等价的两步写法：

```bash
curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh -o /tmp/mailstack-install.sh
sudo bash /tmp/mailstack-install.sh
```

### 从源码安装（贡献者）

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

安装流程：

1. 安装并校验完整邮件基础栈（Postfix / Dovecot / OpenDKIM / Fail2ban；不可安装的组件按预设降级并在结尾输出「降级组件清单」）
2. 检查 Node.js 运行时（不满足则自动安装钉 SHA256 的官方构建；第三方依赖全部钉版本，拒绝「下载即执行」）
3. 选择访问模式、设置管理员用户名与密码（**12-256 位，须同时含字母与数字**）
4. 构建（优先使用带 SHA256 清单校验的预构建产物，否则源码 `npm run build:all`）
5. 创建独立系统账号，写入单条 sudoers 规则、Dovecot 认证 socket、logrotate（copytruncate 三段策略）、生成 TOTP 主密钥信封（AES-256-GCM，root:root 0600）
6. 注册并启动 `mailstack-helper`、`mailstack-web`、`mailstack-webmail` 三个 systemd 服务
7. 健康自检：`/api/health` 与 `/api/webmail/health` 全部通过才算安装成功
8. 持久化安装参数到 `/etc/mailstack/install-args.conf`，并落位升级信任锚 `/etc/mailstack/release-allowed-signers`

安装日志位于 `/var/log/mailstack-install.log`。

### 安装后访问（local 模式）

默认监听 `127.0.0.1:8787`（管理台）与 `127.0.0.1:18788`（Webmail）。推荐通过 SSH 隧道访问：

```bash
ssh -L 8787:127.0.0.1:8787 -L 18788:127.0.0.1:18788 root@服务器IP
```

然后在本机浏览器打开 `http://127.0.0.1:8787`。若选择 `caddy` 模式，安装器自动配置 Caddy 并签发 Let's Encrypt 证书，直接用域名 HTTPS 访问；Caddy 不可用时自动安全降级回 local 监听并明确提示。

## 四种网络访问模式与公网安全基线

| 模式 | 监听地址 | 适用场景 | 安全等级 | 访问方式 |
|---|---|---|:---:|---|
| **`local`** | `127.0.0.1` | 安全默认基线 | 🟢 高 | SSH 隧道 / VPN 转发 |
| **`caddy`** | `127.0.0.1` + Caddy 反代 | 公网生产多域名 | 🟢 高 | 自动签发 Let's Encrypt TLS，域名直接访问 |
| **`direct`** | `127.0.0.1` | 已有 Nginx 等反代 | 🟡 中 | 自备反向代理与 HTTPS 证书（示例配置见 [deploy/reverse-proxy-nginx.example.conf](deploy/reverse-proxy-nginx.example.conf)） |
| **`plain`** | `0.0.0.0` | 内网隔离测试 | 🔴 极低 | 明文 HTTP 公网暴露；交互模式需输入 `yes` 二次确认，非交互必须显式传 `--i-understand-plain-http` |

**公网部署安全基线**：访问模式为 `caddy` / `direct`（或显式设置 `MAILSTACK_SECURITY_PROFILE=high`）时，以下控制 fail-closed 生效——

1. **2FA 强制启用**：未启用 TOTP 前，管理台只放行登录与 2FA 绑定端点（其余全部 403），控制台强制绑回 `127.0.0.1`，绑定窗口过期仍未启用 2FA 则进程直接退出
2. **备份强制加密**：`backup.create` 无口令在写任何文件前即拒绝；`gpg` 缺失绝不静默降级明文；`ms doctor` 把明文归档判 FAIL
3. **审计链强制完整**：审计失败放行（`MAILSTACK_AUDIT_FAILOPEN=1`）在公网模式被判 FAIL，hash 链 + `.head` 锚点 + syslog 外送始终开启
4. **AI 出站默认关闭**：全部 `ai.*` 出站动作默认拒绝，须显式开启（`MAILSTACK_AI_OUTBOUND=1` 或 `/etc/mailstack/ai.conf` 的 `enabled=true`）
5. **逃生门硬关**：`MAILSTACK_ALLOW_UNSAFE_GIT=1`、`COOKIE_SECURE=0`、`HOST=0.0.0.0`、`MAILSTACK_AUDIT_FAILOPEN=1` 任一出现（systemd unit 与 `/proc/<pid>/environ` 双来源扫描）即 doctor FAIL；git clone 升级通道公网下完全不可达（唯一开发者豁免需 `MAILSTACK_I_AM_A_DEVELOPER=1` 且 local 模式）

## 非交互安装

密码通过标准输入传递（进程内转环境变量并立即 `unsetenv`），不出现在 Shell 历史或 `/proc/<pid>/cmdline`。下面用「先落盘再执行」是因为带一长串参数时最好读、也最便于写进配置管理脚本；以 root 直接一行跑 `printf '%s\n' '口令' | bash <(curl -fsSL …) --non-interactive …` 同样可行（进程替换不占用 stdin）：

```bash
curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh -o /tmp/mailstack-install.sh
printf '%s\n' 'YourStrongPass123' | sudo bash /tmp/mailstack-install.sh \
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

从源码安装时把命令换成 `sudo bash ./mailstack.sh install`，参数完全相同。

全部安装参数：

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--access-mode <mode>` | `local` / `caddy` / `direct` / `plain` | 交互选择；非交互下有域名则 `caddy`，否则 `local` |
| `--domain <DOMAIN>` | 管理后台 / 主邮件域名 | 空 |
| `--webmail-domain <DOMAIN>` | Webmail 域名 | 同主域名 |
| `--email <EMAIL>` | Let's Encrypt 证书通知邮箱 | 空 |
| `--admin-user <NAME>` | 管理员用户名 | `admin` |
| `--admin-port <PORT>` | 管理后台内部端口（1024–65535） | `8787` |
| `--admin-host <HOST>` | 管理后台监听地址 | `127.0.0.1` |
| `--webmail-port <PORT>` | Webmail 内部端口 | `18788` |
| `--webmail-host <HOST>` | Webmail 监听地址 | `127.0.0.1` |
| `--admin-password-stdin` | 从标准输入读取管理员密码（12 位新策略） | 交互输入 |
| `--non-interactive` | 非交互静默安装 | 关 |
| `--reuse-admin` | 复用已有管理员凭证（升级用） | 关 |
| `--https` | 强制 HTTPS 安全 Cookie 标记 | 按模式决定 |
| `--i-understand-plain-http` | plain 模式非交互安装的显式风险确认 | 关 |
| `--i-have-external-tls` | direct 模式确认 TLS 由外部反代终结（跳过证书证据探测） | 关 |

## 部署向导

安装完成后首次登录管理后台，建议按向导完成部署（每步都调用特权助手做真实校验）：

1. **服务器身份**：主机名、时区、管理员邮箱等
2. **DNS 校验**：添加邮件域名，校验 MX / SPF / DKIM / DMARC / PTR，可调用 AI 助手解释与给建议
3. **投递方式**：SMTP Relay（内置 Oracle OCI / SES / SendGrid / Brevo / Resend 预设）或服务器直连；Relay 走真实 TLS 认证测试，直连模式对本机 Postfix 做纯 EHLO 探测
4. **TLS 证书**：ACME 签发（特权调用默认 120 秒超时，`MAILSTACK_HELPER_TIMEOUT_MS` 可调）
5. **发信测试**：闭环投递验证
6. **部署摘要**：确认全部配置

也可随时在 Setup Guide 页面重新执行，或用 `ms test-mail` 复测投递链路。

## DNS 记录指引

| 记录类型 | 主机 | 示例值 | 作用 |
|---|---|---|---|
| A / AAAA | `mail.example.com` | 服务器公网 IP | 主机解析 |
| MX | `example.com` | `mail.example.com.`（优先级 10） | 接收邮件 |
| SPF | `example.com` | `v=spf1 mx -all`（使用 Relay 时改为对应 `include:`） | 声明合法发信来源 |
| DKIM | `default._domainkey.example.com` | OpenDKIM 公钥（管理台一键复制） | 邮件签名验证 |
| DMARC | `_dmarc.example.com` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com` | 策略与报告 |
| PTR | 反向解析 | 指向 `mail.example.com` | 接收方信誉（在 VPS 控制台设置） |

## 管理员 2FA 与会话管理

- **TOTP 双因素**：管理台「账户设置」的 2FA 卡片完成绑定（otpauth URI / secret 展示、启用 / 停用 / 重新绑定）；重新绑定需先通过 TOTP 或恢复码验证，防止静默降级为单因子
- **一次性恢复码**：哈希存储、一次性消费，消费路径带文件锁保证原子性防并发重放
- **登录流程**：密码通过后，若已启用 2FA 而未带验证码，返回 `TOTP_REQUIRED` 进入验证码分支；TOTP 本地校验，恢复码走特权 helper
- **共享锁定台账**：TOTP 二因子错误与密码错误共享同一 strike / lockout 台账——密码持有者不能借锁定盲区爆破 6 位验证码
- **三层登录限流**：全局 500/分钟 + 每 IP 30/15 分钟 + 每账号 10/15 分钟，与 5 次失败锁定（5 分钟）共同生效；401 一律只回 `INVALID_CREDENTIALS`，不含剩余次数（反用户枚举）
- **活跃会话管理**：查看活跃会话并逐个吊销（`GET/DELETE /api/auth/sessions`、`POST /api/auth/sessions/revoke`）；改密清空全部管理会话
- TOTP 主密钥以 AES-256-GCM 信封加密存放（root:root 0600，仅特权 helper 可读）

## Webmail 使用

- 访问 `http://127.0.0.1:18788`（SSH 隧道）、`https://webmail.example.com`（caddy 模式）或 Docker 暴露端口
- 使用**邮箱用户**（管理台「用户」页创建的 Linux 邮箱账号）登录；认证经 Dovecot `auth-client` socket，密码不进任何进程参数
- 收件箱列表与搜索、邮件阅读（MIME / 多字符集）、已读标记、发信（本机 Postfix 提交）
- 会话 7 天绝对上限；改密 / 锁定账号即令该用户全部 webmail 会话失效（epoch 机制）

## CLI 命令参考

安装完成后系统会链接 `/usr/local/bin/ms`。在服务器任意目录运行 `ms` 查看帮助。

### 常用命令

| 命令 | 说明 |
|---|---|
| `ms doctor` | 全栈健康体检：系统、负载、磁盘、内存、核心服务、Postfix/Dovecot 配置、端口连通、队列积压、托管域名、密钥权限政策（KeyPermissionScan）、Fail2ban **实弹探针**（对 TEST-NET-1 做 ban/unban 往返，jail 不动作判 FAIL）、明文备份归档扫描、公网逃生门双来源扫描；输出总体 HEALTHY/WARNING/CRITICAL |
| `ms audit-verify` | 校验审计日志哈希链完整性（截尾 / 篡改 → 非零退出，可直接对接监控） |
| `ms test-mail [邮箱]` | 邮件闭环投递验证：真实发信 → 收信 → Maildir 落地确认，输出跟踪令牌与往返延迟 |
| `ms status` | 查看 `mailstack-helper` / `mailstack-web` / `mailstack-webmail` 服务状态 |
| `ms logs [admin\|webmail]` | 实时查看服务日志 |
| `ms version` | 查看当前安装版本 |

### 备份 / 恢复 / 回滚

| 命令 | 说明 |
|---|---|
| `ms backup create [--include-mails] [--encrypt]` | 创建配置备份；`--encrypt` 交互索取口令（或经 `MAILSTACK_BACKUP_PASSPHRASE`），gpg AES256 加密，口令绝不进 argv；公网模式强制加密 |
| `ms backup list` | 列出历史备份（名称、时间、大小、是否含邮件、是否加密） |
| `ms restore <备份文件>` | 安全还原：加密备份索要口令；自动生成「还原前回滚快照」；文件名 / SHA256 / 显式确认三重校验；拒绝恢复白名单外路径（如未管理用户的 `.ssh`）与符号链接等危险归档成员 |
| `ms rollback` | 快速回滚到最近一次还原前快照 |

### 安装与维护

| 命令 | 说明 |
|---|---|
| `bash <(curl -fsSL .../deploy/install.sh)` | 一行式安装（见[快速开始](#快速开始)）；单文件运行，自动从签名 Release 取回源码 |
| `sudo bash mailstack.sh install [选项]` | 从源码树安装（参数与上者相同） |
| `ms upgrade [版本标签]` | 从官方**签名 Release 三件套**（tar.gz + SHA256SUMS + SHA256SUMS.sig）升级；缺 `.sig` 直接拒绝；可指定标签钉扎版本 |
| `ms upgrade --allow-downgrade` | 显式放行降级（默认拒绝降级到低于已安装的版本，放行会写 `downgrade_allowed` 审计） |
| `ms uninstall --dry-run` | 卸载预演：列出将要停止的服务、删除的文件、保留的数据 |
| `ms uninstall [--purge]` | 卸载（见[卸载](#卸载)） |
| `ms help` | 命令帮助 |

## 更新与升级（签名通道）

```bash
ms upgrade              # 升级到最新签名 Release
ms upgrade v0.8.0-beta.9  # 钉扎到指定版本
```

升级通道设计：

- **默认只走签名 Release 资产**：下载 `MailStack-<tag>.tar.gz` + `SHA256SUMS` + `SHA256SUMS.sig` 三件套，先 `ssh-keygen -Y verify`（对仓内信任锚 `/etc/mailstack/release-allowed-signers`，发布流水线用同一锚自验），再校验 SHA256，之后才执行任何安装动作——**升级不执行任何未经签名验证的远程代码**
- **拒绝降级**：目标版本低于已安装版本即拒绝；latest 被劫持到旧签名包同样被拦；降级门位于验签与校验和之后、任何安装动作之前
- **拒绝非官方源**：`MAILSTACK_REPO_URL` 指向非官方地址直接拒绝
- **参数透传**：首次安装持久化在 `/etc/mailstack/install-args.conf` 的部署参数（访问模式、域名、端口、HTTPS 行为）原样透传，用户显式参数可覆盖
- **开发者 git 通道**：`MAILSTACK_ALLOW_UNSAFE_GIT=1` 显式开启 clone HEAD 升级，公网模式下被硬关（见[公网安全基线](#四种网络访问模式与公网安全基线)）
- 发布侧闭环：`.github/workflows/release.yml` 在 tag 推送时以仓库外私钥（GitHub Secret）签名并复验后上传四资产；`scripts/package.py` 支持本地门控签名

升级前仍建议 `ms backup create` 并创建 VPS 快照。

## 备份与灾难恢复

- 备份存放于 `/var/backups/mailstack`，文件 0600；文件名与 SHA256 写入元数据；加密归档带锁标记
- **加密**：`--encrypt` 使用 gpg 对称加密（AES256）；口令只经 stdin / 环境变量传递；`gpg` 缺失时拒绝加密请求（fail-closed，绝不静默降级明文）；加密过程失败会连同明文归档一并清除；公网模式强制加密
- **还原即换挡**：`ms restore` 在还原前自动生成回滚快照（同样按口令加密）；损坏快照不再登记为回滚点并附警告
- **恢复白名单**：只能写回允许的路径集合（不覆盖 `/etc/mailstack/admin.json` 权限语义，密钥文件恢复 0600，拒绝 `.ssh`、符号链接 / 硬链接 / 设备成员）
- `/var/lib/mailstack`（邮箱注册表）纳入备份源与恢复白名单，灾难恢复后 webmail 登录不再丢失
- 完整操作手册（含一分钟速查）见 [docs/DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md)

## 卸载

```bash
sudo bash ./mailstack.sh uninstall --dry-run   # 预演
sudo bash ./mailstack.sh uninstall             # 保留 /etc/mailstack
sudo bash ./mailstack.sh uninstall --purge     # 连管理配置一起删除
```

卸载会停止并注销 `mailstack-helper`、`mailstack-web`、`mailstack-webmail`，删除服务单元、`ms` 链接、特权包装器与 sudoers 规则，清理 MailStack 写入的组件配置；**绝不自动删除** Postfix、Dovecot 本体、Linux 邮箱用户和 `/home/*/Maildir`、`/var/vmail` 邮件数据。

## 端口与环境变量

| 服务 / 模块 | 默认端口 | 环境变量 | 默认监听 | 说明 |
|---|---|---|---|---|
| **Admin 控制台** | `8787` | `PORT`, `HOST`（兼容旧名 `ADMIN_PORT`, `ADMIN_HOST`） | `127.0.0.1:8787` | 管理面板与特权 RPC 调度端点 |
| **Webmail 客户端** | `18788` | `WEBMAIL_PORT`, `WEBMAIL_HOST` | `127.0.0.1:18788` | 独立 Webmail 服务 |
| **安全 Cookie** | - | `COOKIE_SECURE` | `0`（local）/ `1`（caddy、direct） | `Secure; SameSite=Strict` |
| **运行环境** | - | `NODE_ENV` | `production` | 生产模式 |

其他环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `MAILSTACK_SECURITY_PROFILE` | 空 | `high` 强制套用公网安全基线（与 caddy/direct 同级） |
| `MAILSTACK_HELPER_TIMEOUT_MS` | `120000` | 特权 RPC 超时（下限 5000；ACME 首签 30–90 秒） |
| `MAILSTACK_HELPER_RO_SOCKET` | `/run/mailstack/helper-ro.sock` | Node 直连的只读面 socket 路径 |
| `MAILSTACK_AI_OUTBOUND` | 未设置 | 公网模式 AI 出站总开关（`1`/`true` 开启；显式 `0`/`false` 关闭）；也可用 `/etc/mailstack/ai.conf` 的 `enabled=true` |
| `MAILSTACK_BACKUP_PASSPHRASE` | - | CLI 备份加密口令（配合 `--encrypt`，不进 argv） |
| `MAILSTACK_ALLOW_UNSAFE_GIT` | 未启用 | 开发者 git clone 升级逃生门；公网模式硬关 |
| `MAILSTACK_I_AM_A_DEVELOPER` | 未启用 | 上述逃生门在公网的唯一豁免（且须 local 模式） |
| `MAILSTACK_AUDIT_FAILOPEN` | 未启用 | 审计失败放行；公网模式 doctor 判 FAIL |
| `MAILSTACK_SIGNING_KEY` | - | 打包签名私钥路径（仅发布方，`scripts/package.py`） |
| `MAILSTACK_ADMIN_PASSWORD` | 空 | **Docker 专用**：首启管理员口令（仅首次生效，之后改密走控制台） |
| `MAILSTACK_ADMIN_USER` | `admin` | **Docker 专用**：首启管理员用户名 |
| `MAILSTACK_HOSTNAME` / `MAILSTACK_BIND` / `MAILSTACK_LISTEN_HOST` / `MAILSTACK_I_PUBLISH_ADMIN` | 见 compose | **Docker 专用**：容器主机名 / 宿主绑定地址 / 容器内监听 / A6 发布确认旗标 |

环境变量可写入 `.env`（模板见 [.env.example](.env.example)）或 systemd 服务 `Environment=`。生产环境由安装器写入 unit，一般无需手工修改。

## 安全模型

### 进程与账号隔离

- `mailstack-admin` 与 `mailstack-webmail` 是独立无登录系统账号；`/opt/mailstack` 目录属主 `root:root 0755`，服务账号不可写安装树（杜绝「服务账号整体替换 backend 并借 sudoers 以 root 执行伪造代码」的本地提权链）
- Webmail 账号**没有任何 sudo 权限**，只通过 Dovecot auth socket 认证并受控读取 Maildir
- sudoers 自 rc.5 起收敛为**单条规则**（精确到特权包装器，无参数通配符），并对旧机器清理残留

### 特权操作最小化（RO/RW 双通道 + 对端校验）

- 特权助手为 root 常驻 daemon（`mailstack-helper.service`），经 unix socket 服务 RPC；一次性 sudo 包装器保留为兜底与变更面入口
- RO 面（14 个只读动作）与 RW 面（其余变更动作）按 socket 通道分离；RO 面收到 RW 动作即便 uid=0 也拒绝
- 每连接 `SO_PEERCRED` 校验对端 uid：ro 通道白名单 `{0, mailstack-admin}`、rw 通道仅 root；getsockopt 异常同样拒绝
- 动作白名单（`ALLOWED_ACTIONS_RO | ALLOWED_ACTIONS_RW`）之外直接拒绝；删除域名 / 用户 / 备份需显式 `confirm: true`

### 认证、会话与凭据

- 管理员口令 PBKDF2-SHA256（310000 次迭代、16 字节盐）存 `/etc/mailstack/admin.json`（0640）；TOTP 主密钥 AES-256-GCM 信封（root:root 0600）；恢复码哈希存储
- **密码策略**：12–256 位、须同时含字母与数字、禁止 3+ 相同 / 连续字符、禁止包含账号身份 token；仅认证路径走旧策略校验，存量密码不被锁死
- Cookie `HttpOnly; SameSite=Strict`，HTTPS 模式加 `Secure`；滑动 TTL + 7 天绝对上限；改密 / 2FA 变更即清会话
- AI 接口独立速率限制；JSON 请求体上限 256 KB；登录响应去信息化

### systemd 沙箱

- `mailstack-helper`：全套加固集（`ProtectSystem` / `PrivateTmp` / `NoNewPrivileges` 等），只放行必要的 `/etc` 子树写路径
- `mailstack-web`：`ProtectSystem=strict` 且 `/etc/mailstack` 不可写（rc.5 的 B4 收窄）
- `mailstack-webmail`：`ProtectSystem=strict`、`NoNewPrivileges`、`RestrictSUIDSGID`，仅放行 `/home`、`/var/vmail`

### 出站请求加固（防 SSRF / DNS Rebinding）

- AI 与 SMTP 出站：解析后逐 IP 校验（回环 / 内网 / 链路本地 / CGNAT 100.64.0.0/10 / 组播 / 保留地址），并先解包 `::ffff:*` 等 IPv4-mapped / sixtofour / teredo 内嵌地址再应用 v4 规则（堵映射绕过），钉定 IP 连接
- 自定义 AI 端点强制 HTTPS、拒绝凭据内嵌 URL、响应 2 MB 上限、跨域重定向拒绝；**公网模式 AI 出站默认全关**

### 审计与防篡改

- 每条特权 RPC 审计记录携带 `prev_hash`（哈希链）+ `.head` 锚点：截尾、篡改、乱序都可被 `ms audit-verify` 检出
- 审计镜像外送 syslog `AUTHPRIV`（容器 / 无盘环境的日志外送通道）
- `MAILSTACK_AUDIT_FAILOPEN` 逃生门在公网模式被 doctor 判 FAIL

### 供应链与发布

- **Node.js**：发行版包优先；回退官方 tarball 并比对 SHA256 常量（musl 自动切 `linux-x64-musl` 渠道）；NodeSource `curl | bash` 已移除
- **安装引导**：`deploy/install.sh` 可脱离源码树单文件运行（自行从签名 Release 取回源码），但引导段只做「下载 → `ssh-keygen -Y verify` 验签 → `sha256sum -c` → 解压 → 转交安装器」，不含任何安装逻辑；验签或校验和不通过即中止，绝不执行未经验证的远程内容
- **Caddy**：回退 Cloudsmith 源前先验 GPG 指纹；**acme.sh**：钉版本 3.1.4 tarball + SHA256；**fail2ban** pip 兜底：钉 1.1.0 tarball SHA256
- **发布签名**：`scripts/package.py` 门控签名（`MAILSTACK_SIGNING_KEY`），`release.yml` 在 CI 内用仓库外私钥签名并复验；升级端逐字节一致的验签逻辑
- 预构建产物 `build-manifest.json` 逐文件 SHA256；可复现打包（固定 `SOURCE_DATE_EPOCH`，两次打包哈希一致）；CI `npm audit` 高危硬门禁 + CycloneDX SBOM

### 外部评审记录

[docs/pentest-2026-09.md](docs/pentest-2026-09.md) 入库了六面评审测试记录（登录爆破 / 用户枚举 / CSRF、helper 对端与通道滥用、备份路径穿越与明文归档、AI SSRF、升级验签 / 降级 / UNSAFE_GIT、webmail argv / Maildir 权限）：每项「已修」附实现位置与测试名，「未修残余」如实记录，方法论声明公开可复核。STRIDE 深化见 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)。

## AI 邮件顾问

| 提供商 | 预设端点 | 默认模型 | 协议 |
|---|---|---|---|
| **GLM (BigModel)**（默认） | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-flash`（可选 `glm-4-plus` / `glm-4-air` / `glm-4-long`） | OpenAI-compatible |
| **DeepSeek** | `https://api.deepseek.com/v1` | `deepseek-chat` | OpenAI-compatible |
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o-mini` | OpenAI-compatible |
| **Anthropic Claude** | `https://api.anthropic.com/v1` | `claude-3-5-sonnet-20241022` | Anthropic Messages |
| **自定义** | 任意公网 HTTPS OpenAI-compatible / Anthropic 端点 | 自填 | OpenAI / Anthropic |

- 聊天助手、DNS / TLS / Relay / 日志退信诊断、结构化解析；无外部 API Key 时自动降级为本地规则诊断
- API Key 只存服务器端 `/etc/mailstack/ai-provider.json`，不返回浏览器
- 公网模式 AI 出站默认关闭（见[公网安全基线](#四种网络访问模式与公网安全基线)），local 模式保持历史行为
- 第三方服务商的免费额度、模型与数据政策可能变化，以其当前条款为准；**AI 建议不能代替管理员审查，也不能保证邮件送达**

## 测试与质量保障

### 基线门禁（本版本实测）

| 门禁 | 结果 |
|---|---|
| Python 特权助手行为测试 | **106 test 通过**（Windows 环境依赖半区自动 skip=9） |
| Node 契约 / 集成 / 安全静态测试 | **86 pass** |
| 前端 Vitest | **12 pass** |
| `tsc --noEmit` | 零错误 |
| shellcheck `-S warning` | 全部 12 个部署 / 验证脚本零告警零豁免 |
| `verify_release_consistency` | 100% |

行为断言体系（T-*）：公网 2FA 门（T-2FA-1a/1b/2）、SO_PEERCRED 对端（T-PEER-2）、双 socket 通道（T-SOCK-1/2）、逃生门（T-ESC-1）、沙箱（T-PERM-1 helper/web）、备份加密（T-BKP-1）、审计链（T-AUD-1）、降级门（T-UP-1）、Docker 管理口（T-DOCK-1）等 14 条，以及登录爆破 / 用户枚举 / CSRF、备份路径穿越、AI SSRF、webmail 认证 socket 等专项测试。

### 本地测试命令

| 命令 | 内容 |
|---|---|
| `npm run lint` | TypeScript 全量类型检查 |
| `npm test` | Node 内置 test runner：API 契约、业务集成、生命周期、安全静态、可观测性、公网模式门、升级降级、webmail 认证 socket、Docker entrypoint 等 17 个测试套件 |
| `npm run test:frontend` | Vitest + Testing Library 前端测试 |
| `npm run test:helper` | Python 特权助手行为级测试 |
| `npm run test:backup` | 备份 / 还原端到端（含加密往返、`.ssh` 恢复拒绝） |
| `npm run test:all` | 上述全部 + 构建 |
| `npm run build:all` | 前端 + 管理台 + Webmail + 产物清单 |

### CI（GitHub Actions）

| Job | 内容 |
|---|---|
| **build** | Node 20 / 22 / 24 矩阵：类型检查、Python 助手测试、Node 契约与集成、前端测试、`build:all`、产物校验、版本一致性、可复现打包 |
| **shell-gate** | shellcheck（error 硬门禁 + warning 零告警目标）+ 发布脚本未定义函数调用扫描 |
| **install-matrix** | ubuntu:24.04 / ubuntu:22.04 / debian:12 / rockylinux:9 干净容器真实安装 + 健康断言 + 提权探针 + sudoers 单条 + jail 存在 + 信任锚 + 环回发信（`scripts/ci_install_assertions.sh`）+ **恶意域名注入 Caddyfile 门禁**（`scripts/ci_domain_injection_test.sh`） |
| **bootstrap-smoke** | **一行式安装引导链门禁**：用临时 ed25519 密钥签一份 `file://` 伪 Release，以 README 主推的 `bash <(curl -fsSL …)` 形态跑真实 `deploy/install.sh` 的引导段（验签 → 校验和 → 解压 → 铺开 → 转交），并逐条断言 缺签名 / 签名不匹配 / 归档被篡改 / 资产顶层多于一个 / 缺少 `deploy/install.sh` 均在铺开源码之前拒绝。全程不出网（`scripts/ci_bootstrap_smoke_test.sh`） |
| **supply-chain** | `npm audit` 高危硬门禁 + 可修复中危门禁 + CycloneDX SBOM |
| **release**（tag 触发） | tag 必须与 VERSION 一致 → 构建 → 门控签名 → 复验 → 归档布局断言 → 上传 tar.gz / zip / SHA256SUMS / SHA256SUMS.sig 四资产 |

## 项目结构

```text
mailstack.sh                      统一入口：install / update(upgrade) / doctor / audit-verify /
                                  test-mail / backup / restore / rollback / uninstall / status / logs
├── deploy/
│   ├── install.sh                交互式与非交互式安装器（访问模式、构建、账号、systemd、Caddy）
│   ├── install-mail-stack.sh     邮件基础栈安装与校验（含降级组件登记）
│   ├── install-v05.sh            Release 压缩包安装入口
│   ├── mailstack-privileged      root 特权包装器（sudoers 唯一放行目标）
│   ├── mailstack-release.pub / .allowed_signers   发布签名信任锚
│   ├── init.d-mailstack.in.sh    无 systemd 分支 init 脚本模板（shellcheck 纳管）
│   ├── mailstack.logrotate       日志轮转（三段 copytruncate 策略）
│   ├── reverse-proxy-nginx.example.conf   Nginx 反代示例（direct 模式）
│   ├── verify-release-scripts.sh 发布脚本未定义函数扫描
│   ├── verify-source-build.sh / privacy-audit.sh
├── backend/
│   ├── server.production.ts      Express 管理台：认证 + TOTP 分支、会话管理、公网模式门、RPC 代理
│   └── mailstackctl/
│       ├── core.py               常量、RO/RW 白名单、审计哈希链 + syslog 镜像、密码策略
│       ├── dispatcher.py         RPC 动作分发
│       ├── daemon.py             root 常驻 helper（双 socket、SO_PEERCRED、并发上限）
│       ├── mail.py / network.py / certs.py / backup.py / security.py / telemetry.py / ai.py
│       └── totp.py               TOTP 与恢复码（信封加密、原子消费）
├── webmail/
│   ├── server.mjs                独立 Webmail（epoch 会话、7 天上限、限流）
│   ├── dovecot-auth.mjs          Dovecot auth-client socket 协议实现（密码不进 argv）
│   └── public/                   Webmail 前端
├── docker/
│   └── entrypoint.sh             容器首启编排（数据卷种子、口令初始化、A6 门控）
├── Dockerfile / docker-compose.yml / .dockerignore
├── src/                          React 管理后台源码（views / setup / dns / telemetry）
├── scripts/                      打包、清单、CI 断言与 E2E 测试脚本
├── tests/                        Node / Vitest / Python 测试套件（17 个 Node 套件）
├── docs/
│   ├── SUPPORT_MATRIX.md         发行版支持矩阵与平台能力注记
│   ├── DOCKER.md                 Docker 部署指南
│   ├── THREAT_MODEL.md           STRIDE 威胁模型
│   ├── DISASTER_RECOVERY.md      灾难恢复操作手册
│   ├── DATA_PRIVACY.md           数据停留与日志红线
│   ├── VULNERABILITY_RESPONSE.md 漏洞响应 SLA 与 VEX（唯一权威来源）
│   ├── pentest-2026-09.md        六面外部评审测试记录
│   ├── RELEASE_CHECKLIST.md / DEPENDENCY_POLICY.md
│   └── verification/             Ubuntu 24.04 / Debian 12 真机记录、邮件投递 E2E
├── .github/workflows/ci.yml / release.yml
├── .env.example
└── CHANGELOG.md                  v0.1.0-beta.1 → v0.8.0-beta.9 全量变更
```

## 开发指南

技术栈：React 19、TypeScript 5.8、Vite 6、Tailwind CSS 4、Express 4、esbuild、Node 内置 test runner、Vitest、Python 3 标准库（≥3.10，PEP 604）。

```bash
npm install          # 安装依赖
npm run dev          # Vite 开发服务器（前端）
npm run lint         # 类型检查
npm run build:all    # 前端 + 管理台 + Webmail + 产物清单
npm start            # 运行打包后的管理台
npm test             # Node 测试
```

依赖策略（[docs/DEPENDENCY_POLICY.md](docs/DEPENDENCY_POLICY.md)）：发布产物 `dist/server.cjs` 与 `dist/webmail.cjs` 为 esbuild 独立打包，运行时无需 `node_modules`；特权助手只用 Python 标准库；新增网络相关依赖需安全评审并记录发布说明。

容器开发 / 验证可直接使用 `docker compose build && docker compose up`，镜像构建即跑一遍与 CI 相同的安装器路径。

## 已知限制

- 公开 beta：Tier 2 / 实验性平台的端到端覆盖仍以 CI 与本地实测为准，生产前建议干净机演练
- 前端默认 5 秒轮询仍在（RPC 已走常驻 helper socket，开销远低于早期 sudo + Python 逐次 spawn；推送机制在计划中）
- 高级 Relay 故障转移与防重复投递状态机仍需继续验证；ACME 首签、DNS API 凭据轮换与多 CA 回滚仍需增强
- 评审记录中的「未修残余」如实公开于 [docs/pentest-2026-09.md](docs/pentest-2026-09.md)，不以「已验证」名义冒充
- 演示 / Mock 数据不代表真实服务器结果；AI 建议不能代替管理员审查

## FAQ

**Q: 为什么公网模式强制 2FA？**
公网管理台是整个服务器的控制平面。单因子口令一旦泄露即完全接管，因此 `caddy` / `direct`（或 `MAILSTACK_SECURITY_PROFILE=high`）下未启用 TOTP 前，控制台只允许登录与绑定 2FA，且强制绑回 `127.0.0.1`——这是 fail-closed 的设计，不是提示。

**Q: Docker 首启口令是什么？**
提供 `MAILSTACK_ADMIN_PASSWORD` 则直接使用（不满足 12 位字母数字策略会启动失败）；不提供则生成随机口令并只在 `docker compose logs` 打印一次。该变量仅在首启（卷内无 admin.json）时生效。

**Q: 升级可以降到旧版本吗？**
默认拒绝。`ms upgrade --allow-downgrade` 显式放行并写 `downgrade_allowed` 审计；latest 被劫持到旧签名包同样会被降级门拦截。

**Q: 公网模式为什么 AI 功能不可用？**
公网基线下 AI 出站默认全关（防把服务器日志 / 配置片段发给第三方 API 的出口被滥用）。确认需要后设 `MAILSTACK_AI_OUTBOUND=1` 或在 `/etc/mailstack/ai.conf` 写 `enabled=true`。

**Q: 备份为什么要求口令？**
备份含 Postfix 配置、DKIM 私钥与凭据哈希，落盘明文等于把控制面打包。公网模式强制加密（gpg AES256），`gpg` 缺失时拒绝而非降级明文；local 模式加密为可选项。

**Q: 忘记把端口暴露出去，打不开后台？**
本地执行 `ssh -L 8787:127.0.0.1:8787 -L 18788:127.0.0.1:18788 root@服务器IP`，再访问 `http://127.0.0.1:8787`。

**Q: 能保证邮件进对方收件箱吗？**
不能。送达率取决于 IP / 域名信誉、DNS 身份认证完整度、内容质量与接收方策略。MailStack 帮你把可控部分做对，并内置体检与 AI 诊断定位问题。

## 贡献

欢迎通过 Issue 报告可复现问题，提交前请说明：操作系统及版本、MailStack 版本、安装方式、`ms status` / `ms doctor` 输出、已脱敏日志与复现步骤。

**请勿公开提交** SMTP 密码、管理员哈希、AI Key、DKIM 私钥、TLS 私钥、ACME DNS 凭据、邮箱正文或未脱敏生产日志。

提交代码请保证 `npm run test:all` 通过；涉及部署脚本请留意 shell-gate 与装机矩阵门禁；安全相关改动请对照 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) 的非目标与信任边界。

## 安全问题

安全漏洞**不要**在公开 Issue 披露。请使用 GitHub Private Vulnerability Reporting，或通过仓库维护者提供的私密渠道报告；响应时间承诺（SLA）与 VEX 政策的唯一权威来源是 [docs/VULNERABILITY_RESPONSE.md](docs/VULNERABILITY_RESPONSE.md)。支持的版本线与威胁模型概要见 [SECURITY.md](SECURITY.md)。

## 文档索引

| 文档 | 内容 |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | v0.1.0-beta.1 → v0.8.0-beta.9 逐版本变更，含每个安全修复的完整背景 |
| [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) | 发行版支持矩阵与平台能力注记 |
| [docs/DOCKER.md](docs/DOCKER.md) | Docker 部署：端口模型、卷布局、首启口令 |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | STRIDE 威胁模型（资产分级、信任边界、非目标） |
| [docs/DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md) | 灾难恢复操作手册（含一分钟速查） |
| [docs/DATA_PRIVACY.md](docs/DATA_PRIVACY.md) | 数据停留（数据在哪里、谁能读）与日志红线 |
| [docs/VULNERABILITY_RESPONSE.md](docs/VULNERABILITY_RESPONSE.md) | 漏洞响应 SLA 与 VEX 政策 |
| [docs/pentest-2026-09.md](docs/pentest-2026-09.md) | 六面评审测试记录（已修 / 未修残余如实记录） |
| [docs/verification](docs/verification) | Ubuntu 24.04 / Debian 12 真机验证记录、邮件投递 E2E |
| [README_EN.md](README_EN.md) | English README |
| [.env.example](.env.example) | 环境变量模板 |

## 许可证

MailStack 使用 [MIT License](LICENSE)。

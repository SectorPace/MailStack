<p align="center">
  <img src="https://raw.githubusercontent.com/SectorPace/MailStack/main/assets/mailstack-logo.png" alt="MailStack Logo" width="160">
</p>

<h1 align="center">MailStack v0.8-beta.6</h1>

<p align="center">
  公开测试版 6 · 2026-09-12<br>
  「冲 98」安全加固收官 × 0.5.3-rc.1 平台成果 合并发布
</p>

<p align="center">
  <a href="README.md">主 README（完整文档）</a> ·
  <a href="CHANGELOG.md">完整更新日志</a> ·
  <a href="https://github.com/SectorPace/MailStack/releases">Releases</a>
</p>

> **这是什么版本：** 0.8-beta.6 在九发行版实测 + musl 兑底 + Docker 化的平台上，合入安全加固 **PR-A1..A6** 与 **PR-B1..B6** 共十二项，新增 14 条 T-* 行为断言；基线 13 条门禁断言全部保持不回退（python 106 / npm 86 / vitest 12 / tsc 零错 / shellcheck 零告警 / 版本一致性 100%）。**无接口与数据格式变更。**
>
> **仍在测试阶段。** 建议只在全新测试 VPS 上部署，不要直接覆盖生产邮件服务器。MailStack 不保证邮件进入收件箱。

---

## 目录

- [版本脉络](#版本脉络)
- [本版本亮点](#本版本亮点)
- [安全加固 · 包 A（PR-A1..A6）](#安全加固--包-apr-a1a6)
- [安全加固 · 包 B（PR-B1..B6）](#安全加固--包-bpr-b1b6)
- [平台与容器](#平台与容器)
- [全新安装](#全新安装)
- [从旧版本升级](#从旧版本升级)
- [版本校验](#版本校验)
- [验证状态](#验证状态)
- [已知问题](#已知问题)
- [Beta 测试反馈重点](#beta-测试反馈重点)
- [安全提醒](#安全提醒)

## 版本脉络

如果你们的环境还停留在 0.5.2 线，这里是到本版本的完整路径：

| 版本 | 日期 | 主题 |
|---|---|---|
| v0.5.2-rc.3 | 2026-08-30 | 全量脚本审计修复（提权链 / rollback / warn 崩溃）+ CI 门禁 |
| v0.5.2-rc.4 | 2026-08-30 | 发布脚本本身的全量审计（非 systemd 分支修复、logrotate、CRLF 等） |
| v0.5.2-rc.5 | 2026-08-31 | 系统性安全加固：webmail 密码离开 argv、**签名升级通道**、**管理员 2FA（TOTP + 恢复码）**、**备份静态加密**、**长驻特权 helper**、sudoers 收敛单条、密码策略 12 位、供应链钉扎 |
| v0.5.3-rc.1 | 2026-08-31 | 平台覆盖：**九发行版两轮实测**、musl Node 兑底、安装器 16 处加固、**Docker 化资产入库** |
| **v0.8-beta.6** | **2026-09-12** | **本版本：上述平台成果 + PR-A/B 十二项安全加固收官** |

各版本完整变更见 [CHANGELOG.md](CHANGELOG.md)。

## 本版本亮点

- **公网模式强制 2FA**：未启用 TOTP 前，管理台只放行登录与绑定端点，控制台强制绑回 `127.0.0.1`，绑定窗口过期即进程退出
- **特权助手双 socket 通道**：只读面（0660，Node 直连）与变更面（0600，仅 sudo 包装器）按通道决定动作子集，配 SO_PEERCRED 对端 uid 校验
- **备份强制加密（公网）**：无口令在写任何文件前拒绝；gpg 缺失绝不静默降级明文；doctor 明文归档判 FAIL
- **审计链防篡改**：prev_hash 哈希链 + `.head` 锚点，新增 `ms audit-verify` 校验命令，镜像外送 syslog AUTHPRIV
- **升级降级门**：目标低于已安装版本即拒绝（latest 劫持到旧签名包同样被拦），`--allow-downgrade` 显式放行并写审计
- **逃生门硬关**：公网模式下四类不安全开关任一出现即 doctor FAIL（unit 文件与 `/proc/<pid>/environ` 双来源扫描）
- **Docker 管理口门**：容器内非环回 admin 绑定须双旗标确认，缺一拒绝启动
- **密钥权限政策**：DKIM 私钥 `root:opendkim 0640` 等断言纳入 doctor 扫描（KeyPermissionScan）

## 安全加固 · 包 A（PR-A1..A6）

| 项 | 内容 | 断言 |
|---|---|---|
| **A1 公网强制 2FA** | 公网模式（caddy/direct 或 `MAILSTACK_SECURITY_PROFILE=high`）未启用 2FA 时仅放行 login + 2FA enrollment（`ENROLL_ALLOWED_PATHS` 门）；窗口过期 `process.exit(1)`；监听地址强制 `127.0.0.1`（`EFFECTIVE_HOST`） | T-2FA-1a/1b/2 |
| **A2 SO_PEERCRED 对端门** | 特权 helper 每连接 `getsockopt(SO_PEERCRED)`：ro 通道白名单 uid ∈ {0, mailstack-admin}、rw 通道仅 uid==0；越权即 `peer_denied` 审计并立即断连（getsockopt 异常同样拒绝）；rw 动作恒走 sudo 包装器、公网 ro 不回落 sudo | T-PEER-2 |
| **A3 TOTP 信封** | TOTP 二因子错误与密码错误共享同一 strike/lockout 台账——密码持有者不能借锁定盲区爆破 6 位验证码 | （随登录测试） |
| **A4 禁止降级** | `ms upgrade` 降级门 `assert_no_downgrade`：目标低于已安装版本即拒绝，`--allow-downgrade` 显式放行并写 `downgrade_allowed` 审计；latest 劫持到旧签名包同样被拦；门位于验签 + 校验和之后、任何安装动作之前 | T-UP-1 |
| **A5 逃生门硬关** | 公网模式 `MAILSTACK_ALLOW_UNSAFE_GIT=1` / `COOKIE_SECURE=0` / `HOST=0.0.0.0` / `MAILSTACK_AUDIT_FAILOPEN=1` 任一即 doctor FAIL（unit 文件 `Environment=` 与 `/proc/<pid>/environ` 双来源扫描）；git clone 通道仅显式开发者旗标可达（`MAILSTACK_I_AM_A_DEVELOPER=1` 且 local） | T-ESC-1 |
| **A6 Docker 管理口门** | `docker/entrypoint.sh` 非环回 admin 绑定未同时携带 `MAILSTACK_LISTEN_HOST=0.0.0.0` + `MAILSTACK_I_PUBLISH_ADMIN=1` 双旗标即拒绝启动 | T-DOCK-1 |

## 安全加固 · 包 B（PR-B1..B6）

| 项 | 内容 | 断言 |
|---|---|---|
| **B1 双 socket 通道分离** | `/run/mailstack/helper-ro.sock` 0660 root:mailstack-admin（只读面）与 `/run/mailstack/helper.sock` 0600 root:root（变更面）；**通道而非 uid 决定动作子集**——ro 面收到 rw 动作即便 uid=0 也拒绝并写 `ro_channel_violation` 审计 | T-SOCK-1/2 |
| **B2 备份强制加密** | 公网模式 `backup.create` 无口令在打 tar 前拒绝（fail-closed 于任何副作用之前，覆盖 CLI / daemon / 直调全部路径）；gpg 缺失绝不静默降级明文；doctor 明文归档扫描 FAIL、备份文件逐个断言 0600 | T-BKP-1 |
| **B3 审计链外送** | 审计记录 prev_hash 哈希链防篡改 + `.head` 锚点（截尾检测），镜像外送 syslog AUTHPRIV（容器 / 无盘日志外送通道）；`ms audit-verify` 非零退出供监控对接 | T-AUD-1 |
| **B4 systemd 收窄** | helper unit 全套加固集；web unit `ProtectSystem=strict` 且不可写 `/etc/mailstack` | T-PERM-1（helper/web） |
| **B5 密钥政策** | KeyPermissionScan（DKIM 私钥 root:opendkim 0640 等断言）；公网模式 AI 出站默认关闭（`AI_OUTBOUND_ACTIONS` 全集 fail-closed，须 `MAILSTACK_AI_OUTBOUND=1` 或 `/etc/mailstack/ai.conf` 显式开启） | （随 doctor 测试） |
| **B6 pentest 记录入库** | [docs/pentest-2026-09.md](docs/pentest-2026-09.md)：六面评审测试记录，每项「已修」附实现位置与测试名，「未修残余」如实记录，方法论公开可复核 | — |

## 平台与容器

- **九发行版本地实测全部跑通**：Ubuntu / Debian / Kali / AlmaLinux 10 / OracleLinux 9.5 / openEuler 25.09 / openSUSE Tumbleweed / Arch / Alpine 3.24，两轮安装验证（中断重跑、卸载重装）；8/9 systemd + Alpine OpenRC/init.d 分支
- **musl 兑底**：Alpine 等 musl 系统回退 Node 官方 unofficial-builds `linux-x64-musl` 构建（v22.20.0，SHA256 钉死）
- **Docker 单容器**：`Dockerfile`（ubuntu:24.04 基线，构建复用裸机安装器路径）+ `docker-compose.yml`（8 数据卷、健康自检、管理台 / Webmail 默认绑宿主回环）+ `docker/entrypoint.sh`（6 进程前台模型、数据卷种子初始化、首启口令 `MAILSTACK_ADMIN_PASSWORD` 注入或随机生成仅日志打印一次）；见 [docs/DOCKER.md](docs/DOCKER.md)
- **安装器继承 0.5.3-rc.1 的 16 处加固**：EL9 Python ≥3.10 硬门禁、Arch keyring / icu 自愈、openSUSE 冲突处置、fail2ban pip 兜底（钉 SHA256）、孤儿端口清理、init.d setsid、显式降级组件摘要等

## 全新安装

### 裸机

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

安装要求 root、Bash、Python ≥ 3.10；Node.js 20-24 由安装器钉版本自动装配。密码策略 **12-256 位且须同时含字母与数字**。安装完成注册 `mailstack-helper` / `mailstack-web` / `mailstack-webmail` 三个服务并通过双健康自检。

### Docker

```bash
docker compose build
MAILSTACK_ADMIN_PASSWORD='Your-Strong-Admin-Pass-7' docker compose up -d
# 或留空：随机口令在 docker compose logs 中只打印一次
curl http://127.0.0.1:8787/api/health && curl http://127.0.0.1:18788/api/webmail/health
```

详见 [docs/DOCKER.md](docs/DOCKER.md)。

### Release 压缩包

Release 附四资产：`MailStack-<tag>.tar.gz` / `.zip` / `SHA256SUMS` / `SHA256SUMS.sig`（ssh-keygen 签名）。安装前校验：

```bash
sha256sum -c SHA256SUMS                      # 归档完整性
ssh-keygen -Y verify -f mailstack-release.allowed_signers \
  -I mailstack-release -n file -s SHA256SUMS.sig < SHA256SUMS   # 发布签名（信任锚随仓库分发）
```

解压后 `sudo bash mailstack.sh install` 或 `sudo bash deploy/install-v05.sh`。

## 从旧版本升级

### 已运行 0.5.2-rc.5+ / 0.5.3-rc.1（已有信任锚与签名通道）

```bash
ms upgrade              # 最新签名 Release
ms upgrade v0.8-beta.6  # 钉扎指定版本
```

默认只接受 `tar.gz + SHA256SUMS + SHA256SUMS.sig` 三件套（缺 `.sig` 直接拒绝）；拒绝降级，确需降级加 `--allow-downgrade`（写审计）；部署参数经 `/etc/mailstack/install-args.conf` 原样透传。

### 已运行 v0.5.2-rc.3 / rc.4 及更早（旧升级通道）

旧版本自带的 `ms upgrade` 走 git clone（无验签），升级到本版本建议改走发布物路径：

```bash
# 1) 下载本 Release 四资产并校验（见上节）
# 2) 解压后从新树执行升级（新安装器复用 install-args.conf 中的原部署参数）
tar -xzf MailStack-v0.8-beta.6.tar.gz && cd MailStack-v0.8-beta.6
sudo bash mailstack.sh update
# 或：sudo bash deploy/install.sh --reuse-admin <原部署参数>
```

升级完成后即可使用新的签名升级通道。

### 升级前后注意

- 升级前执行 `ms backup create`（公网部署请加密）并创建 VPS 快照
- **密码策略收紧至 12 位**：仅新设置的密码需满足新规，存量密码不受影响、不会被锁死
- 注册表位置已迁移至 `/var/lib/mailstack`（安装器含旧位置迁移，备份 / 恢复白名单同步覆盖）
- sudoers 收敛为单条：安装器会自动清理旧机器残留的 `mailstack-web-ctl` 规则

## 版本校验

```bash
bash -n mailstack.sh        # 脚本语法检查
bash mailstack.sh version   # 预期输出：
```

```text
v0.8-beta.6
```

CI 以固定 `SOURCE_DATE_EPOCH` 打包并校验两次独立构建哈希一致（可复现归档）；发布资产签名流水线见 `.github/workflows/release.yml`。

## 验证状态

- **基线门禁（本版本实测）**：python 106 test（Windows 环境依赖半区 skip=9）/ npm test 86 pass / vitest 12 pass / tsc --noEmit 零错 / shellcheck -S warning 零告警（12 个脚本）/ verify_release_consistency 100%
- **行为断言**：新增 14 条 T-*（T-2FA-1a/1b/2、T-PEER-2、T-SOCK-1/2、T-ESC-1、T-PERM-1 helper/web、T-BKP-1、T-AUD-1、T-UP-1、T-DOCK-1）
- **CI 装机矩阵**：ubuntu:24.04 / ubuntu:22.04 / debian:12 / rockylinux:9 干净容器非交互安装 + 健康断言 + 提权探针 + sudoers 单条 + jail 存在 + 信任锚 + 环回发信 + 域名注入门禁
- **本地实测**：九发行版两轮安装验证全部通过（见[平台与容器](#平台与容器)）
- **外部评审**：[docs/pentest-2026-09.md](docs/pentest-2026-09.md) 六面评审测试记录，基于仓库内已实现并通过的测试与门禁证据整理，可复跑验证；未在真实 Linux 主机执行过的行为如实记入「未修残余」

## 已知问题

- 前端默认 5 秒轮询仍在（RPC 已走常驻 helper socket，开销远低于早期 sudo + Python 逐次 spawn；推送机制在计划中）
- 高级 Relay 故障转移与防重复投递状态机仍需继续验证；ACME 首签、DNS API 凭据轮换与多 CA 回滚仍需增强
- 评审记录中的「未修残余」见 [docs/pentest-2026-09.md](docs/pentest-2026-09.md)，不以「已验证」名义冒充
- 演示 / Mock 数据不代表真实服务器结果；AI 建议不能代替管理员审查，也不能保证邮件送达

## Beta 测试反馈重点

- **公网模式 2FA 强制流程**：绑定窗口、`TOTP_REQUIRED` 分支、恢复码原子消费、窗口过期退出
- **升级降级门**：低版本目标被拒、`--allow-downgrade` 审计、latest 劫持场景
- **双 socket 通道**：RO 面发 RW 动作被拒、webmail / helper socket 权限
- **备份加密**：公网强制、gpg 缺失 fail-closed、加密往返还原
- **Docker**：首启口令注入 / 随机打印一次、数据卷跨重建保留、A6 双旗标门控
- **九发行版**中你所用平台的安装 / 升级 / 卸载

提交 Issue 时请附：操作系统与版本、MailStack 版本、安装方式、`ms doctor` 与 `ms audit-verify` 输出、已脱敏日志与复现步骤。

## 安全提醒

请勿在 Issue 或日志附件中公开：SMTP 密码、管理员哈希、AI API Key、DKIM 私钥、TLS 私钥、ACME DNS API Key、备份口令、邮箱正文、未脱敏的生产日志。

安全漏洞请使用 GitHub Private Vulnerability Reporting 私密报告；响应 SLA 与 VEX 政策见 [docs/VULNERABILITY_RESPONSE.md](docs/VULNERABILITY_RESPONSE.md)，威胁模型见 [SECURITY.md](SECURITY.md) 与 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)。

---

完整功能列表、架构说明、安全模型、CLI 命令参考与开发指南请阅读[主 README](README.md)。

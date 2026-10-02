# MailStack（Rust 全栈重写）

`MailStack` 从 Node/TypeScript 全栈重写为 Rust 的工程。规格书见
[`docs/REWRITE_TO_RUST.md`](docs/REWRITE_TO_RUST.md)（本仓库外的源码包内）。

- 版本：**0.8.1-beta1**（基线 `v0.8.0-beta.10`）
- 目标形态：单一二进制，生产环境**无 node / 无 npm / 无 Python**
- 保留 Dovecot 作为 IMAP/POP3 与 SASL 后端；自研替代 Postfix / OpenDKIM / fail2ban

## 当前状态

**Phase 0（契约冻结）+ Phase 1（只读面）+ Phase 2（SMTP 核心）+ Phase 4（写面，进行中）**：

| crate | 测试 | 内容 |
|---|---:|---|
| `mailstack-core` | 158 | 动作三集、口令策略、审计哈希链、`atomic`/`locked`、`warn`、命令与服务控制原语、配置 schema、部署模式、**2FA（AES-256-GCM 信封 + RFC 6238 + 恢复码持锁消费）**、**证书到期解析**、**`/proc` 只读采样**、**敏感文件权限体检** |
| `mailstack-priv` | 81 | 动作门控、RPC 帧、RO/RW socket 服务端、**内置动作处理器**（只读面、2FA 全生命周期、域名/别名/设置/管理员/DKIM 轮换、**只读聚合面 `snapshot`/`logs.list`/`metrics.realtime`/`certs.list`/`network.check_port`/`system.doctor`/`security.scan`/`backup.list`**）、fallback 规则、特权调用客户端 |
| `mailstack-smtp` | 132 | IP 固定拨号器、中继校验、分阶段测试、出站探测、反中继策略、落地与回滚、真实落盘载体、**MX 解析与直投目标选择** |
| `mailstack-queue` | 80 | 队列持久化与原子性、指数退避与去共振、DSN 退信、并发限流、快速失败、**出站必签 DKIM**、**直投（逐域 MX，绝不回退中继）** |
| `mailstack-store` | 41 | Postfix 表文件（域名/别名）、Dovecot LMTP 客户端（落箱唯一路径） |
| `mailstack-auth` | 42 | DKIM 密钥与签名（自签自验）、SPF、DMARC、ARC **校验与封印**（替代 OpenDKIM）、**离线 TXT 缓存（含 DMARC 树走查的终止桩）** |
| `mailstack-smtpd` | 131 + 11 | 入站 SMTP：命令解析、DATA 字节流（**SMTP 走私防护**）、会话状态机、反中继、会话驱动、TCP 监听、**TLS 1.2 起**（STARTTLS / 隐式 465）、**连接限速**、**IP 自动封禁**、**提交端口 SASL**（RFC 4954 + Dovecot auth socket，仅在 TLS 之上）、**SPF/DKIM/DMARC 认证与入队** |
| `mailstack-web` | 78 | 契约路由表、会话/CSRF、登录限流、错误模型、特权通道、Axum 装配、**2FA 路由** |
| `mailstackd` | 23 | **进程入口**：fail-closed 配置装配、三端口（25/465/587）共用准入状态、集中绑定、**特权 RPC 双通道（RO/RW socket）**、停机扇出、出站队列调度 |
| `mailstackctl` | 7 | **CLI**：参数→特权调用的翻译（`--confirm` 必须真布尔）、退出码区分「助手不可达 / 动作失败」 |

**797 个测试中 796 个通过、1 个集成测试红**（详见 [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) §5 首条：
`crates/smtpd/tests/inbound.rs::a_verified_message_enters_the_queue_end_to_end`
在真实 TCP 会话的 `MAIL FROM` 之后超时，**已确认与本轮改动无关**但尚未定位根因）。
另有 11 个入站 TCP/TLS/auth-socket 端到端 + 7 个真实 TLS 集成 + 10 个真实 unix socket LMTP 集成 + 6 个 Postfix 容器集成；
`clippy -D warnings` 与 `rustfmt` 全绿，CI 中 221 个安全不变量测试名全部存在（扫描范围含 `bin/`）。
真实二进制冒烟：收信 → 入队 → RPC 门控 → `mailstackctl` → SIGTERM 优雅停机。
详见 [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) 与 [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)。

## 目录结构

```
crates/core     mailstack-core    领域模型、配置、口令策略、审计链、文件与命令原语
crates/priv     mailstack-priv    特权边界：动作门控 + RPC 服务端
crates/smtp     mailstack-smtp    SMTP 客户端/拨号器、中继校验、分阶段测试、出站探测
crates/queue    mailstack-queue   出站队列：持久化、退避重试、DSN 退信、并发与快速失败、DKIM 签名
crates/store    mailstack-store   数据层：Postfix 表文件、Dovecot LMTP 投递
crates/auth     mailstack-auth    认证与签名：DKIM/SPF/DMARC/ARC（替代 OpenDKIM）
crates/smtpd    mailstack-smtpd   入站 SMTP 服务端（替代 Postfix smtpd）
crates/web      mailstack-web     管理 API（Axum）、会话/CSRF/限流
bin/mailstackd  mailstackd        守护进程：入站 SMTP（25/465/587）+ 出站队列调度 + 特权 RPC 双通道
bin/mailstackctl mailstackctl     CLI：调用特权 RPC 面上的已登记动作
deploy/         构建、质量门禁与 WSL 工具脚本
docs/           部署文档与测试报告
.github/        CI：质量门禁 + 供应链 + 不变量存在性检查
```

按规格书 §6，`crates/webmail` 将在后续 Phase 加入。

> `mailstackd` 的缺省端口是 25/465/587（**完全接管**才该用的值）。迁移期与 Postfix 双跑时
> 必须显式指定旁路端口，例如 `mailstackd --port 2525`。

## 构建与测试

```bash
# 生产目标平台是 Linux；Windows 开发机请用 WSL（见 TOOLCHAIN.md）
deploy/build.sh              # release 构建 + SHA256SUMS + SBOM
deploy/wsl-quality-gate.sh   # rustfmt + clippy(-D warnings) + cargo test
```

## 安全设计要点

- **特权模型**：只读动作直连 `helper-ro.sock`（0660 root:mailstack-admin）；
  变更动作恒经 `sudo /usr/local/libexec/mailstack-privileged`。
  **未登记动作默认走只读面**（静默提权防护）。
- **动作名编译期绑定**：处理器不从请求体读取动作名，白名单不可被绕过。
- **fail-closed**：助手不可达 → `503`，绝不降级为无特权执行；
  公网模式下只读动作不得 fallback 到 sudo。
- **审计哈希链**：`.head` 锚文件可检测截尾；格式与历史日志兼容。
- **TOTP secret** 以 AES-256-GCM 信封落盘，主密钥 `0600 root:root` 仅特权进程可读；
  动态码按 RFC 6238（HMAC-SHA1 / 6 位 / 30 秒 / ±1 步）校验。
- **恢复码**只以 SHA-256 落盘，消费在 `locked()` 临界区内完成 ——
  并发消费同一张码只有一次会成功（一次性，不可重放）。
- **只读聚合面读不到什么就说什么**：`snapshot` / `metrics.realtime` / `logs.list`
  把读不到的片段列进 `unavailable` 或回 `available: false` + 原因。静默省略会把
  「没数据」渲染成「没问题」，那正是运维最容易被误导的地方。
- **出站端口探测只探部署配置里的目标**，不接受请求体指定的主机；
  地址策略只允许公网地址，`198.18.0.0/15` 等段一律判为不可路由。

## 与规格书的偏差（实测）

1. 规格书 §5.2 称「共 51 条路由」，但按其给出的表格逐条清点实为 **62 条**
（认证 7 + 管理员 6 + 资源 26 + 初始化 7 + 备份 4 + 指标 2 + AI 10）。
本仓库以 62 条为实现与测试基线，并由 `contract::route_count_is_stable` 固定；
该数量变化必须是有意为之，因为它是对外兼容承诺的一部分。

2. 规格书 §3.4 推荐用 `mail-builder` 生成 DSN/退信，当前
[`crates/queue/src/dsn.rs`](crates/queue/src/dsn.rs) 为自研 MIME（结构仍遵循 RFC 3464，
含头注入与防回环防护）。该偏离的取舍与替换成本见
[`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) 的「§5.1 与规格书的偏差」。
# MailStack Rust 重写 —— 项目移交报告（检查点 `0.8.1-beta1`）

- 版本：`0.8.1-beta1`（`VERSION` / `Cargo.toml` 一致）
- 报告生成日期：**2026-10-03**
- 代码库路径：`e:\MailStack\mailstack-rust`（生产目标平台为 Linux，构建在 WSL Ubuntu 24.04）
- 对照基线（Python/FastAPI/Postfix 老栈）：`e:\MailStack\MailStack-v0.8-beta.6\MailStack-v0.8-beta.6`
- 规格书：`docs/REWRITE_TO_RUST.md` **v3**（在源码包内，**不在本仓库**）

> **本文件是「进度存档」而非「完工报告」。** 存档之后开发继续推进 —— 见 §3 待完成清单。
> 归档产物（源码快照 + 初始版本历史 + 校验和 + 恢复步骤）见：
> `e:\MailStack\backups\mailstack-rust-checkpoint-<时间戳>\`，其中 `CHECKPOINT.md` 是存单（在仓库之外）。

---

## 1. 项目背景与目标

### 1.1 背景

MailStack 原本是一套 **Python（FastAPI）+ Postfix + OpenDKIM + fail2ban + Node 前端** 的邮件服务器管理栈：
后端 `mailstackctl` 以特权助手的形式暴露一组动作，Web 层通过 sudo 包装器下发，Postfix 承担 SMTP、
OpenDKIM 承担签名、fail2ban 承担封禁。

这套组合的问题集中在三处：

1. **组件面过大**：五个异构服务（Python / Postfix / OpenDKIM / fail2ban / Node）各自有配置与升级路径，
   任意一个被替换或配置漂移，都会以「看起来正常、实际在丢信」的形式表现。
2. **安全边界靠约定**：中继 SSRF 防护、反中继、DKIM 私钥权限等关键性质写在文档与注释里，
   退化之后代码照样能跑、测试照样绿（规格书 §5.9.3 明确点出这一风险）。
3. **失败被静默**：读不到的数据被渲染成「没有数据」，探测失败被当成「服务没起来」等，
   运维拿到的是错误的结论而不是事实。

### 1.2 目标

按规格书 **§3.3 组件下线** 与 **§6 迁移路线**，把栈重写为 **单一 Rust 工作区**，做到：

| 目标 | 落地要求 |
|---|---|
| 移除 Postfix / OpenDKIM / fail2ban | SMTP 服务端、DKIM 签名、限速与封禁全部自研 |
| 安全性质**结构性**成立 | 用类型与模块边界表达（如拨号 API 只接受已固定的 IP），而不是靠约定 |
| 失效**响亮** | 读不到就报「读不到」，探测失败给出明确结论，绝不静默降级 |
| 磁盘契约不变 | `/etc/mailstack/*`、`/etc/postfix/mailstack_*`、`/var/vmail` 等布局与基线逐字一致 |
| 对外契约冻结 | 62 条 HTTP 路由、50 条特权动作、响应形状对齐基线（前端无需改写） |
| 可离线复现构建 | 无 C 依赖工具链（TLS 用 `ring` 而非 `aws-lc-rs`），锁定 `Cargo.lock` |

### 1.3 一句话现状

**机制层已完整可用**：`mailstackd` 能收信、按策略投递（本地 LMTP / 中继 / 直投）、承载特权 RPC 双通道、
优雅停机；管理台的写面动作已实现 38/50。**未完成**的是 `users.*`（用户模型）、ACME 签发、
AI 出站子系统，以及 11 条「动作已实现但尚未挂路由」的注册工作。

---

## 2. 当前进度状态

### 2.1 量化总览（均为实测，非估计）

| 维度 | 数值 | 说明 |
|---|---|---|
| 测试 | **906 passed / 0 failed** | `cargo test`；另有 6 个需真实 Postfix 的集成测试（容器内跑） |
| 不变量门禁 | **257 / 257 存在** | `deploy/verify-invariant-gate.sh`（从 `ci.yml` 动态取名单） |
| 质量门禁 | `QUALITY_GATE=PASS` | rustfmt + clippy(`-D warnings`) + 全量测试 |
| 交付物门禁 | `DELIVERABLES_OK` | `deploy/verify-deliverables.sh` |
| 特权动作 | **38 / 50** 已实现 | 只读面 13/14；变更面 25/36 |
| HTTP 路由 | **35 / 62 已注册** | 其中 8 条由 Web 进程内应答；27 条未注册 |
| 规格书 Phase | 0 ✅ / 1 ✅ / 2 🟡机制完成 / 3 ⏳ / 4 🟡进行中 / 5 ⏳ | 见 §2.4 |

### 2.2 完成百分比（分口径，避免一句话误导）

| 口径 | 完成度 | 计算依据 |
|---|---|---|
| 特权动作 | **76%** | 38 / 50 |
| 对外路由 | **56%** | 35 / 62 已注册 |
| SMTP 传输机制（Phase 2 范围） | **≈90%** | 收发/签名/认证/限速/封禁/队列/直投均已落地，缺「机会式 TLS」与真实环境验证 |
| 整体（含前端接入与组件下线） | **≈70%** | Phase 0/1 完成、Phase 2 机制完成、Phase 4 过半、Phase 3/5 未启动 |

> 三个口径差异很大是**刻意呈现**的：动作写完 ≠ 前端点得到 ≠ 生产验证过。
> 只看其中一个数字都会误判项目状态。

### 2.3 各 crate 规模与职责

| crate | 测试数 | 职责 |
|---|---:|---|
| `mailstack-core` | 187 | 动作三集/通道推导、原子写与锁、审计哈希链、配置 schema、口令策略、TOTP、证书解析、`/proc` 采样、权限体检、备份归档、手工封禁、命令原语与 `service_ctl` 降级链、部署模式与 AI 总闸 |
| `mailstack-priv` | 143 | 动作门控（`ActionGate`）、RPC 帧、RO/RW socket 服务端、**全部已落地的动作处理器**、只读聚合面、初始化向导、邮件环路自检、失败分类与 fallback 规则 |
| `mailstack-smtp` | 136 (+7 真机 TLS) | IP 固定拨号、中继校验、分阶段中继测试、出站探测、MX 解析与直投目标、先测后写/回读/回滚、配置载体、DNS 查询 |
| `mailstack-smtpd` | 139 (+11 真机 TCP/TLS) | 入站 SMTP 会话与命令、DATA 字节流（走私防护）、TLS 1.2 起、连接限速、IP 自动封禁、提交端口 SASL（Dovecot auth socket）、SPF/DKIM/DMARC 判定与入队 |
| `mailstack-queue` | 80 | 队列持久化与原子性、指数退避与去共振、DSN 退信、出站必签 DKIM、并发上限、快速失败与出站结论 |
| `mailstack-store` | 31 (+10 真机 LMTP) | Postfix 风格表文件（域名/别名）与 `postmap` 序列、LMTP 客户端 |
| `mailstack-auth` | 43 | DKIM 密钥（原生 RSA-2048 / SPKI 记录 / 0640 加固）、签名与自验、SPF、DMARC、ARC 校验与封印、离线 TXT 缓存 |
| `mailstack-web` | 78 | 契约路由表、会话与 CSRF、登录限流、错误模型、特权通道、Axum 装配 |
| `mailstackd` | 28 | 进程入口：fail-closed 装配、监听集中绑定、RPC 双通道、停机扇出、队列调度、封禁热重载 |
| `mailstackctl` | 7 | CLI：参数→特权调用的翻译、退出码映射 |
| **合计** | **900 + 6** | 6 = 真实 Postfix 集成测试（需显式开启） |

### 2.4 Phase 进度明细

| Phase | 状态 | 说明 |
|---|---|---|
| 0 契约冻结 | ✅ | `crates/web/src/contract.rs` 62 条路由、`crates/core/src/actions.rs` 动作三集、口令/审计/原子写原语 |
| 1 只读面 | ✅ | 只读聚合面 + 特权 RPC 协议与门控 |
| 2 SMTP 核心 | 🟡 **机制层完成** | 自研 SMTP / 队列 / DKIM / TLS / 限速 / 封禁 / SASL / 直投 / ARC 全部有测试；**尚未**：机会式 TLS、真实 Dovecot auth socket 与真实公网 MX 验证 |
| 3 前端切换 | ⏳ 未启动 | 新前端（用户自有、非 Rust 版）的 `dist/` 静态资源 + SPA fallback 尚未接入 |
| 4 写面切换 | 🟡 进行中 | 2FA、设置、域名/别名、DKIM、服务与队列、封禁、备份、初始化向导、环路自检已完成；剩 `users.*`、ACME、AI |
| 5 组件下线 | ⏳ 未启动 | 停用 Postfix / OpenDKIM / fail2ban / Node |

---

## 3. 已完成任务清单

### 3.1 基础设施与安全原语（`mailstack-core`）

| 功能点 | 实现细节 | 关键不变量 |
|---|---|---|
| 动作三集与通道推导 | `ALLOWED_ACTIONS_RO` 14 / `ALLOWED_ACTIONS_RW` 36 / `DESTRUCTIVE_ACTIONS` 3；**未登记动作默认归只读面** | INV-24 |
| 原子写 | 临时文件 → `chmod` → `fsync` → `rename`；**先设权限再改名**，中间态不比目标更宽松 | INV-33 |
| 进程间锁 | `locked()`：基于 sidecar 文件；**sidecar 名不与任何数据文件名碰撞** | INV-31 / INV-32 |
| 审计哈希链 | 规范化 JSON 哈希链 + 锚文件；支持 logrotate 截断检测（锚与尾行不一致即报） | INV-4 |
| 口令 | PBKDF2-SHA256 + 常量时间比较 + 弱口令/上下文词校验；旧路径放宽但仍拦控制字符 | INV-35 / INV-36 |
| 配置 schema | `settings.json`（11 键写白名单）、`admin.json`（**改密不得清 2FA 块**）、`setup.json` | INV-30 / INV-43 |
| 部署模式与 AI 总闸 | `ACCESS_MODE` 解析（兼容 shell 引号）；公网档下 AI 出站**缺配置即关** | INV-10 |
| 证书解析 | PEM/DER 双格式、到期天数、私钥权限（group/world 可读即告警） | — |
| 权限体检 | 判据是「超出**该文件应有**的权限」，不是「有没有 world 位」；可写比可读严重 | — |
| 备份归档 | 成员名白名单、拒绝符号/硬链接/设备/setuid、SHA256 先验、两阶段恢复 | 见 §3.6 |
| 手工封禁 | `manual-bans.json`（0600），**损坏即报错、绝不覆盖** | — |
| 命令原语 | `postmap` 序列、`service_ctl` 四级降级链（systemctl → rc-service → init 脚本 → Noop） | — |

### 3.2 SMTP 传输（`mailstack-smtp` / `mailstack-smtpd`）

| 功能点 | 实现细节 |
|---|---|
| IP 固定拨号 | `PinnedTarget` 的拨号字段是 `SocketAddr`；**不存在**接受 `host:port` 的连接函数（按域名重连在类型上不可表达） | 
| 地址策略 | 公网策略拒绝私网/环回/链路本地/CGNAT/文档段，并额外拒绝 **198.18.0.0/15**（透明代理 fake-IP 会让出站探测假报开放） |
| TLS | 仅 1.2 / 1.3；STARTTLS 与隐式 465；升级时**丢弃明文读缓冲**（防握手前残留注入） |
| 分阶段中继测试 | DNS → connect → TLS → auth 逐阶段可观测，失败**保留已完成阶段** |
| 先测后写 | 测试不通过**一行配置都不写**；写入后**回读校验**；失败**回滚到快照**；回滚未完成时诚实报 `rolledBack:false` |
| 中继载体 | 迁移期 `PostfixRelayStore`（`postconf` + `sasl_passwd`），目标态 `NativeRelayStore`（`relay.json`，0600） |
| 出站探测 | 端口 25 可达性 → direct 模式可用性判据；**本机提交探测 ≠ 出站可用性** |
| MX 直投 | 按 preference 稳定排序、去重、`MX 0 .`（RFC 7505）判永久失败、无 MX 退化为域本身 |
| 反中继 | 未认证 → 仅本域收件人；**空域名表 fail-closed**（拒收而非放行） |
| DATA 字节流 | 终止符必须是 `CRLF.CRLF`；正文已以 CRLF 结尾时不补空行（否则改写正文、破坏上游 DKIM） |
| SMTP 走私防护 | 裸 LF、跨块终止符、命令内 CRLF 均被拒 |
| 限速与封禁 | 每 IP 令牌桶（时钟回拨不白送额度）；失败计数滑动窗口 → 临时封禁 → 重复违规升级为永久 |
| 提交端口 SASL | Dovecot auth-client v1.2；明文连接拒绝 AUTH；认证成功才解锁外域中继 |
| 入站认证 | SPF/DKIM/DMARC/ARC 判定 → 生成 `Authentication-Results` 头 → **入队只在成功时发生**；非 UTF-8 正文 554 拒绝 |
| DNS 查询 | `dns_query` 模块：A/MX/TXT；TXT **分片拼接**（回归 `network.py:115` 的公钥截断事故） |

### 3.3 队列与投递（`mailstack-queue`）

| 功能点 | 实现细节 |
|---|---|
| 持久化与原子性 | 原子写 + fsync；坏条目**隔离到 corrupt 目录**而非丢弃；队列文件 0600 |
| 退避 | 5m→10m→20m…封顶 4h；抖动按条目 id 派生（**防重试风暴去共振**） |
| 失败语义 | 4xx 重试；5xx 立即退信；**未知结果可重试、绝不当场退信** |
| 部分成功 | 已接受某收件人后不再重放/退信（防重复投递） |
| DSN | null sender 与 DSN 自身失败**不再退信**（防双退信回环）；服务器文本做头注入净化 |
| 出站结论 | 连续失败达阈值 → `blocked/needsRelay` 结论并持久化（跨重启保留） |
| 出站必签 | 远端传输被**无条件**套上签名装饰器：未签名的出站路径不可表达；签名失败 fail-closed 且计为本机故障 |

### 3.4 特权边界与动作面（`mailstack-priv`）

| 动作族 | 状态 | 说明 |
|---|---|---|
| 只读聚合面 | ✅ | `snapshot` / `status`、`logs.list`、`metrics.realtime`、`certs.list`、`network.check_port`、`system.doctor`、`security.scan`、`backup.list`、`admin.get`、`ai.config.get`、`settings.get`、`domains.list`、`setup.status` |
| 设置与管理员 | ✅ | `settings.set`（白名单外键丢弃）、`admin.set`（保留 2FA 块） |
| 2FA | ✅ | `admin.totp.begin/enable/disable/verify/consume_recovery`；secret 只以 AES-256-GCM 信封落盘；恢复码持锁消费（INV-29/32） |
| 表写入 | ✅ | `domains.add/delete`、`aliases.add/delete`（删域名连清别名，不留孤儿路由；拒绝换行/空格注入） |
| DKIM | ✅ | `dkim.rotate`：原生 RSA-2048、SPKI 的 `p=`、0640 `root:opendkim` |
| 服务与队列 | ✅ | `services.action`（拒绝停控制台自身）、`queue.action`（`retry` 重置重试预算、id 先过路径穿越校验） |
| 封禁 | ✅ | `security.ban/unban`：写文件为准，守护进程热重载；**解封只动手工封禁** |
| 备份 | ✅ | `backup.create/restore/delete`：公网模式无口令拒绝、加密失败连明文一起删、预恢复快照 |
| 初始化向导 | ✅ | `setup.identity.apply`、`setup.dns.verify`、`setup.relay.test`、`setup.relay.apply` |
| 邮件环路自检 | ✅ | `setup.mail.test`、`mail.test_loopback` |

### 3.5 守护进程与 CLI（`bin/`）

- `mailstackd`：启动期 fail-closed 装配（身份缺失/域名表为空/队列目录不可写**直接拒绝启动**）；
  25/465/587 三个监听**共用同一份**限速配额与封禁表（否则轮换端口就能绕过限速）；
  RO/RW 双 socket 先绑定后起循环；SIGTERM 优雅停机（在途会话 10s 宽限）；封禁文件热重载；
  **读失败保持现状**（当成空集合就是静默解封）。
- `mailstackctl`：`--confirm` 必须是真布尔；退出码 `0/1/2/3/4` 可区分「动作失败 / 用法错误 / 助手不可达 / 中途超时」，
  且**没有**「强制走某通道」的开关（那等于提供绕过门控的入口）。

### 3.6 本检查点最近三轮的成果（供接续者定位）

1. **只读聚合面 + 写面**：`services.action`、`queue.action`、`security.ban/unban`（文件持久化 + 热重载）、
   `backup.*`（归档当不可信输入：成员白名单/拒绝链接与设备/SHA256 先验/O_NOFOLLOW/两阶段）。
2. **初始化向导**：`setup.identity.apply`（校验先于副作用）、`setup.dns.verify`（六条判据 + `observed` 摊开；
   解析故障上抛，与「DNS 里没有」严格区分）、`setup.relay.test/apply`（失败是结论不是 500）。
3. **邮件环路自检**：向硬编码 `127.0.0.1:25` 提交（`sendmail` 已随 Postfix 移除）；
   反中继守卫按「受管域」判据（与「有没有邮箱」无关 —— 基线旧写法在空邮箱时会整段跳过守卫）。

---

## 4. 待完成任务

> **关于工时**：本节给出**优先级**与**规模（S/M/L）**，不给小时/天数估计 —— 规模按
> 「是否需先做决策 / 是否引入新依赖 / 触及几个子系统」衡量，比时长更稳定、更可复现。

### 4.1 优先做（零新依赖、立刻让已有能力可见）

| 任务 | 规模 | 前置决策 | 说明 |
|---|---|---|---|
| 注册 11 条已有动作的路由 | **S** | 无 | `security.ban`、`security.unban`、`backup.create`、`backup.restore`、`backup.delete`、`setup.identity.apply`、`setup.dns.verify`、`setup.relay.test`、`setup.relay.apply`、`setup.mail.test`、`mail.test_loopback` 的 Axum 路由尚未注册；动作本身已实现并有测试 |
| 前端接入 | **M** | **需提供新前端产物** | 挂 `dist/` 静态资源 + SPA fallback；同时补上面 11 条路由 |
| `GET /api/metrics/telemetry` | **S** | 无 | 进程内路由，尚未注册 |

### 4.2 需要先裁决的子系统

| 任务 | 规模 | 必须先决定 |
|---|---|---|
| `users.add/status/password/delete` | **L** | **vmail 目录布局**（`<vmail>/<domain>/<user>` 还是带 `Maildir/` 层）与 **Dovecot 口令方案**（当前无用户模型，`backup.restore` 的家目录白名单不得不为空集） |
| `setup.cert.issue` + `certs.renew` | **M** | **ACME 依赖选择**（如 `instant-acme`）+ challenge 策略（HTTP-01 / DNS-01）+ 证书落地路径是否沿用 `/etc/tls/<domain>/` |
| `ai.config.set` / `ai.test` / `ai.chat` / `ai.diagnose` / `ai.parse` / `ai.models.list` | **L** | 出站 AI 客户端形态（是否复用 reqwest 类依赖、是否允许私网目标）、以及只读白名单最后一条 `ai.models.list` 的归属 |

### 4.3 生产验证与收尾

| 任务 | 规模 | 说明 |
|---|---|---|
| 真实 `mailstackd` 上的完整环路验证 | **M** | 提交 → 入站认证 → 入队 → LMTP → Dovecot 写 Maildir → 扫描命中；当前只用了注入替身 |
| 真实 Dovecot auth socket 联调 | **S** | 现有测试用替身；需在装好 Dovecot 的主机上跑一次 |
| 真实公网 MX 直投 + 机会式 TLS | **M** | 机会式 TLS 是独立的安全策略决定，需单独登记与测试（见 §8） |
| 审计链真实升级演练 | **S** | 需要一次真实迁移/升级过程来验证链的连续性 |
| Phase 5 组件下线 | **L** | 停用 Postfix / OpenDKIM / fail2ban / Node，切到本栈全量能力 |

### 4.4 工程债（建议尽早处理）

| 事项 | 规模 | 说明 |
|---|---|---|
| **建立版本控制** | **S** | **当前目录不是 git 仓库**（无 `.git`）。本次检查点已在快照内做了一次初始提交 + `git bundle`，但**工作目录本身仍无历史**。建议立即 `git init` 并把检查点作为首个提交 |
| 阶段性 `#[allow]` 与 TODO 清理 | **S** | `verify-auth-clean-tree.sh` 已用于守住一部分 |
| crate 边界复核 | **M** | `readers.rs` 已承载「只读面 + 写面 + 向导 + 环路自检」，接近需要拆分 |

---

## 5. 技术架构

### 5.1 分层与数据流

```
                         ┌──────────────────────────────┐
   浏览器/新前端  ──────▶ │  mailstack-web (Axum, 62 路由) │
                         │  会话/CSRF/登录限流/错误模型    │
                         └───────────┬──────────────────┘
                                     │ 动作名 + 载荷（不传通道，通道由动作唯一决定）
                     ┌───────────────┴────────────────┐
        RO 动作      │                                │  RW 动作
   直连只读 socket   ▼                                ▼  sudo 包装器
   (0660 root:mailstack-admin)              (0600 root:root，Web 进程连不上)
                     ┌────────────────────────────────┐
                     │  mailstack-priv: ActionGate     │  ①白名单 ②通道 ③confirm ④AI 总闸
                     │  未登记动作一律拒绝             │
                     └───────────┬────────────────────┘
                                 ▼
                     ┌────────────────────────────────┐
                     │  handlers / readers / mailtest  │  动作实现
                     └───┬────────┬────────┬──────────┘
                         │        │        │
        ┌────────────────┘        │        └──────────────────┐
        ▼                         ▼                           ▼
┌───────────────┐      ┌──────────────────┐        ┌────────────────────┐
│ mailstack-core│      │ mailstack-smtp   │        │ mailstack-smtpd    │
│ 原子写/锁/审计 │      │ IP 固定拨号/中继  │        │ 入站 SMTP/TLS      │
│ 配置/口令/2FA │      │ MX 直投/DNS 查询  │        │ 限速/封禁/SASL     │
└───────────────┘      └──────────────────┘        │ SPF/DKIM/DMARC/ARC │
        ▲                         ▲                └─────────┬──────────┘
        │                         │                          │ 入队（仅认证通过）
┌───────┴────────┐     ┌──────────┴──────────┐                ▼
│ mailstack-auth │     │ mailstack-queue     │      ┌──────────────────┐
│ DKIM/SPF/DMARC │     │ 退避/DSN/必签/并发   │      │ mailstack-store  │
│ ARC/离线缓存   │     │ 快速失败与出站结论   │      │ 表文件 + LMTP    │
└────────────────┘     └─────────────────────┘      └────────┬─────────┘
                                                              ▼
                                            本地投递按策略：LMTP / 中继 / 直投 MX
```

### 5.2 技术选型与理由

| 选型 | 理由 |
|---|---|
| Rust 2021 + 单 workspace | 10 个 target 的编译与测试统一；`Cargo.lock` 锁定可复现 |
| `tokio`（全特性） | 入站多连接、队列并发投递、RPC socket 均需异步 |
| `rustls` + `ring` + `webpki-roots` | **避开 `aws-lc-rs`**（需 cmake/nasm，会破坏「无 C 依赖链、可离线复现」）；内置 Mozilla 根，不依赖系统 CA 存储 |
| `axum` 0.7 | 与 `tower` 中间件模型契合，便于把「认证/限流/安全头」做成层 |
| `hickory-resolver`（受限特性） | 只开 `tokio` + `system-config`：UDP/TCP 普通查询即可，**不开** `tls-*`/`dnssec-*`（那些族里带 `aws-lc-rs` 的变体违反上一条） |
| `mail-auth`（受限特性） | DKIM 签名/验签、SPF、DMARC、ARC 的成熟实现；**刻意收紧特性**，并额外做 SPKI 封装（见 §6.2） |
| `tar` + `flate2`（纯 Rust） | 备份归档要在进程内逐成员读元数据，不能解析 `tar -tvzf` 的文本输出（文件名里的换行会让解析与实际不一致） |
| `serde` / `serde_json` | 响应形状即契约，序列化稳定性优先 |
| 不用数据库 | 契约是**文件**：表文件、队列条目、JSON 配置。无 DB 意味着无迁移、无额外常驻进程 |
| 自研 SMTP 客户端 | 分阶段测试需逐步可观测、队列需精确控制拨号目标，高层客户端不满足 |

### 5.3 目录结构

```
mailstack-rust/
├── Cargo.toml                # workspace 与统一依赖版本
├── VERSION / Cargo.lock      # 版本一致性由 deliverables 门禁校验
├── README.md / TOOLCHAIN.md  # 概览与工具链固定说明
├── .github/workflows/ci.yml  # fmt+clippy+test / 供应链 / 不变量存在性
├── deploy/                   # 构建、质量门禁、不变量门禁、容器 Postfix 测试、WSL 工具
├── docs/                     # TEST_REPORT.md（缺陷与验证）、DEPLOYMENT.md（部署）、HANDOVER.md（本文件）
├── crates/{core,priv,web,smtp,smtpd,queue,store,auth}/
└── bin/{mailstackd,mailstackctl}/
```

---

## 6. 关键代码模块与核心算法

### 6.1 原子写与锁（`core/src/atomic.rs`）—— INV-31/32/33

```
atomic_as(path, data, mode, group):
  1. 在目标同目录建临时文件（同目录才能保证 rename 原子）
  2. 写入 → 设置权限 mode（必要时 chown 属组）   ← 先设权限
  3. fsync 文件
  4. rename(tmp → path)                          ← 再改名
```

**为什么顺序不能反**：先改名再 chmod，会存在一个「内容已就位、权限还是默认」的窗口 ——
DKIM 私钥/中继口令正是在这个窗口里可能短暂可读。`locked()` 在 sidecar 文件上加锁实现
`read → 改 → write` 的临界区；two-factor 恢复码的「消费只花掉一张」就依赖它（INV-32）。

### 6.2 DKIM 的 `p=` 必须是 SPKI（`auth/src/keys.rs`）

`mail-auth` 的 `DkimKeyPair::encoded_public_key()` 返回 **PKCS#1** base64，
而 RFC 6376 的 `p=` 与生态里的既有记录都是 **SubjectPublicKeyInfo**。
危险之处在于：`mail-auth` 的验签侧 `try_strip_rsa_prefix(..).unwrap_or(bytes)` **两种都容忍**，
所以错用 PKCS#1 时**本地自签自验照样通过**，只有 Gmail 之类的对端会验签失败。
本栈用 `spki_from_pkcs1` 显式封装，并用两条测试钉死前缀（`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A`）。

同一模块的 `zone_txt_fragment` 负责把长 TXT 拆成 ≤255 字节的引号分片，
并用「去引号去空白后逐字等于原值」的往返测试固定性质 —— 这是对基线
`network.py:115` 那次「公钥被截断、DNS 记录失效」事故的回归守卫。

### 6.3 IP 固定拨号（`smtp/src/target.rs` + `dial.rs`）—— INV-14/15

攻击窗口：若「解析用于校验、发送时按域名重连」，两次解析之间可被换成内网地址（DNS rebinding / TOCTOU）。
做法不是「记得别用域名」，而是让退化**在类型上不可表达**：

```rust
pub struct PinnedTarget { pub hostname: String, pub addresses: Vec<IpAddr>, pub pinned: SocketAddr }
impl PinnedTarget { pub fn dial_addr(&self) -> SocketAddr { self.pinned } }  // 只有 IP 形态
// 所有连接 API 的入参都是 &PinnedTarget，没有接受 host:port 字符串的连接函数
```

TLS 握手用 `target.hostname` 做 SNI 与证书校验，TCP 只连 `pinned`。
地址策略 `public_only()` 除常规私网段外，**额外拒绝 `198.18.0.0/15`**：
透明代理（Clash/mihomo）的 fake-IP 模式会把任何域名答成该段，并让 TCP「连得上」，
从而使出站探测**假报端口开放**。

### 6.4 先测后写 + 回读 + 回滚（`smtp/src/relay_apply.rs`）—— INV-16/20

```
测试未连通                → 直接拒绝，一个字节都不写
逐键 read_key 取快照       → 用 postconf -n（显式值），不是 -h（有效值含默认）
写凭证(0600) → postmap → 写键 → reload
回读 relayhost 与期望比对  → 不一致 ⇒ 回滚
回滚                      → 原本「未设置」的键必须 remove(-X)，不能写空串
```

**「写空串」不是还原**：实测 Postfix 3.8.6 下把 `smtp_sasl_security_options` 设为空
会抹掉默认的 `noplaintext, noanonymous` —— 一次静默的安全策略弱化。
另有 INV-20：465/SSL-TLS 必须写 `smtp_tls_wrappermode=yes`，否则会以明文连 465、投递卡在队列。

### 6.5 反中继与出站路由（`smtp/src/policy.rs`）—— INV-17/18/21

判据按「本域 / 已认证 / 其余」三分：本域收件人无论是否认证都收；外域收件人必须已认证；
**域名表为空时一律拒收**（fail-closed，而不是「没有域所以都放行」）。
出站路径在配置层就定死：有中继配置 ⇒ 只走中继；无中继 ⇒ 只走直投。
不存在「中继失败退回直投」的分支 —— 那会绕过 relay、破坏 SPF 对齐，并把邮件打到已确认被封的 25 端口。

### 6.6 出站必签（`queue/src/signing.rs`）

把「远端传输」无条件套上签名装饰器，使**未签名的出站路径不可表达**。
签名失败时：**不发出未签名邮件**，标记为本机故障并延迟重试，且**不触发**出站封禁结论
（那是本机问题，不是网络问题）。

### 6.7 队列语义（`queue/src/delivery.rs` + `dsn.rs`）

- 退避 `5m→10m→20m…` 封顶 4h，抖动按条目 id 派生 → 同时刻入队的消息**不会集体重试**。
- `5xx` 立即退信；`4xx` 重试至上限后生成 DSN；**未知结果（连接断开/超时）可重试、绝不退信**。
- 已部分投递（部分收件人已接受）的条目不再重放/退信 → 防重复投递。
- null sender 与 DSN 自身的失败**丢弃不再退信** → 防双退信回环。
- 服务器文本经净化后再进 DSN 头（防 `\r\nBcc:` 头注入）。

### 6.8 备份：把归档当不可信输入（`core/src/backup.rs`）

三个攻击面与对应防线：

| 攻击面 | 防线 |
|---|---|
| 路径穿越（`..`、绝对路径、空分量） | 成员名白名单 + `normalize_member`，在**落地之前**判 |
| 链接攻击（归档内符号链接 → 后续成员顺它写出去） | 拒绝符号/硬链接；落地时 `O_NOFOLLOW` 并逐级父目录拒绝链接 |
| 元数据攻击（设备节点、setuid） | 逐成员读 tar 头部拒绝 |
| 内容篡改 | 先 `SHA256` 校验，之后才开始写目标 |
| 落地中途失败 | 两阶段：先解到临时目录全量校验，再复制到目标 |

`home/<user>/...` 成员在用户模型（`users.*`）落地前**一律拒绝**：无法证明某个家目录归 MailStack 管，就不往里写。

### 6.9 初始化向导的判据（`priv/src/readers.rs`）

- `setup.identity.apply`：**校验先于一切副作用**（被拒的请求不留下 `setup.json`，也不留下密钥目录）。
- `setup.dns.verify` 六条判据与基线一一对应，`observed` 原样摊开每条查询结果；
  **解析故障上抛为错误**，不折算成「记录没发布」——后者会让人去改一条本来正确的记录。
  `spfSingle` 的必要性：两条 `v=spf1` 会被收信方按 RFC 7208 直接判 permerror。
- `setup.relay.test` 区分两类失败：请求写错 → `Err`；对端不通 → `{connected:false, stages:[...]}` 结论。
- `mail.test_loopback`：反中继守卫以**受管域**为判据（与「有没有邮箱」无关）；
  `maildirDelivered` 是证据不是成败。

---

## 7. 开发环境配置指南

### 7.1 依赖

- **WSL Ubuntu 24.04**（生产目标平台即 Linux；Windows 侧仅做类型检查）
- rustup 工具链 **1.98.1**（`deploy/build.sh` 与 CI 双重固定；仓库根**刻意不放** `rust-toolchain.toml`，原因见 `TOOLCHAIN.md`）
- 组件：`rustfmt`、`clippy`
- 可选（仅真实集成测试需要）：`postfix`（容器内一次性）、`gpg`（备份加密）

### 7.2 关键环境变量

| 变量 | 用途 |
|---|---|
| `CARGO_TARGET_DIR` | 由 `deploy/wsl-cargo.sh` 指向 WSL 原生盘（`~/.cache/mailstack-target`）；放在 `/mnt/e` 会让增量构建慢一个数量级 |
| `CARGO_PROFILE_DEV_DEBUG=0` / `CARGO_PROFILE_TEST_DEBUG=0` | **构建铁律**：WSL 根分区仅 9.8G，完整 debuginfo 会把 `target/` 撑到 4.5G+ 并导致链接器 `Bus error`（表现为「链接失败」而不是「磁盘满」） |
| `CARGO_INCREMENTAL=0` | 同上，省盘 |
| `MAILSTACK_USE_PROXY=1` | 仅需联网取包时启用，走 Clash 混合端口 **7890**（7897 接受连接但不可代理）；`NO_PROXY` 覆盖本地环回 |
| `MAILSTACK_PORT_PROBE_TARGETS` | 覆盖出站探测目标（逗号分隔，最多 8 个） |
| `MAILSTACK_AI_OUTBOUND` | 覆盖 AI 出站总闸（`0/false/no/off` 视为关） |
| `MAILSTACK_SECURITY_PROFILE=high` | 强制按公网档处理 |

### 7.3 常用命令

```bash
# 类型检查（快）
wsl -d Ubuntu -e env HOME=/root CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  CARGO_PROFILE_TEST_DEBUG=0 bash /mnt/e/MailStack/mailstack-rust/deploy/wsl-cargo.sh check --all-targets

# 单 crate 测试
... deploy/wsl-cargo.sh test -p mailstack-priv

# 完整门禁（fmt --check + clippy -D warnings + 全量测试）
... bash /mnt/e/MailStack/mailstack-rust/deploy/wsl-quality-gate.sh

# 不变量存在性门禁 / 交付物门禁
... bash deploy/verify-invariant-gate.sh
... bash deploy/verify-deliverables.sh

# 真实 Postfix 集成（一次性容器，会改系统配置，必须显式开启）
... bash deploy/test-relay-postfix-in-container.sh
```

> **注意**：PowerShell 会吞掉管道里的 `head`/`tail`，此类命令请在 WSL shell 内组合。

### 7.4 部署步骤（旁路部署）

1. 构建：`deploy/build.sh`（`--release`、锁定、strip）
2. 放置二进制与 systemd unit（草稿见 `docs/DEPLOYMENT.md` §3.1）
3. 目录与权限按 `docs/DEPLOYMENT.md` §3.4 的表格准备（`0600` / `0640 root:opendkim` / socket `0660` 与 `0600`）
4. 初始化身份：`setup.identity.apply`（或等价 CLI 调用）→ 按返回的 `dkimPublicKey` 发布 DNS
5. DNS 校验：`setup.dns.verify`；中继：`setup.relay.test` → `setup.relay.apply`（**先测后写**）
6. 起 `mailstackd`；用 `mail.test_loopback` 做环路自检
7. 回滚：停掉 unit 即可（**注意**：停掉 `mailstackd` 会同时摘掉两个 RPC socket，管理台随之后端不可用；
   队列里可能留有未投递邮件 —— 直接删除就是丢信）

### 7.5 关于「数据库备份」

**本项目不使用数据库**（这是刻意的设计选择，见 §5.2）。需要备份的状态全部是文件：

| 路径 | 内容 |
|---|---|
| `/etc/mailstack/*.json` | admin（0600/0640）、settings、setup、relay（0600）、ai-provider（0600） |
| `/etc/opendkim/keys/<domain>/` | DKIM 私钥（0640 root:opendkim）+ `.txt` zone 片段 |
| `/var/tls/<domain>/`（或 `/etc/tls/`） | TLS `fullchain.pem` / `privkey.pem` |
| `/etc/postfix/mailstack_{domains,aliases}` | 虚拟域与别名表（Postfix 风格） |
| `/var/lib/mailstack/` | 队列条目、`manual-bans.json`、出站健康状态 |
| `/var/log/mailstack-rpc-audit.log{,.head}` | 审计哈希链与锚 |

这些**已经由产品自身的 `backup.create/restore/delete` 覆盖**（含加密、校验和、预恢复快照）。
本检查点备份的是**代码与文档**，不是某台部署主机的运行时数据 —— 两者不要混淆。

---

## 8. 注意事项、已知问题与风险

### 8.1 必须遵守的开发纪律

1. **构建铁律**：一律带 `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`
   并在 WSL 内构建；**绝不能删 `/root/.cargo/registry/cache`**（删了要重新联网下载）。
2. **不变量只增不减**：新增安全测试必须把测试名加进 `.github/workflows/ci.yml` 的 `required=(...)`，
   否则门禁形同虚设；`#[ignore]` 一律禁止（CI 会直接报错）。
3. **fail-closed 优先**：拿不准就拒绝并说清楚原因，不要静默降级。
4. **注释解释「为什么」**：尤其是「这里为什么不那么做」（例如「不写空串是因为…」）。

### 8.2 已知偏离（对基线的有意不同，均已在 `TEST_REPORT.md` 登记）

| 偏离 | 原因 |
|---|---|
| 移除 Postfix / OpenDKIM / fail2ban | 规格书 §3.3 的下线目标 |
| `setup.json` 无 `postmaster` 字段 | 本栈 schema 里没有它；不影响签名，也不被守护进程读取 |
| `setup.relay.test` 对端不通时返回**结论**而非抛错 | 保留分阶段可观测性（基线抛异常只剩一句「test failed」） |
| `setup.mail.test` 不做「邮箱存在 / 账号锁定」检查 | `users.*` 未移植；响应用 `mailboxChecksSkipped: true` 明说 |
| `backup.restore` 的家目录白名单为空集 | 同上：无法证明家目录归属就不写 |
| `setup.mail.test` 的 `username`/`password` 接受但忽略 | 它们原本只服务于上面那条已缺失的检查；不假装校验过 |

### 8.3 未验证项（诚实披露，来自 `TEST_REPORT.md` §5）

- 真实 `mailstackd` 上的完整环路（提交→认证→入队→LMTP→Maildir→找回）**未跑过**；测试用注入替身覆盖编排与守卫。
- 真实 Dovecot auth socket、真实公网 MX 直投**未联调**。
- **直投目前是明文投递**：机会式 TLS 在现实里必须「加密但不校验证书」，那是一条独立的安全策略决定，需单独登记与测试。
- 审计链的**真实升级演练**未做。
- 2FA 未实现动态码重放保护（RFC 6238 §5.2 可选项）—— 属已登记的已知取舍。

### 8.4 潜在风险与缓解

| 风险 | 现状 | 缓解 |
|---|---|---|
| **无版本控制** | 工作目录**不是 git 仓库** | 本次检查点内置了一次初始提交 + `git bundle`；**强烈建议立即 `git init` 并把它作为首个提交** |
| **`core.autocrlf=true` 会破坏脚本** | 实测本机为 `true`：在 Windows 上 `git clone` / 检出会把 `deploy/*.sh` 转成 CRLF，脚本随即不可执行 | 建议补 `.gitattributes`（`*.sh text eol=lf`），或在 Windows 侧 `git config core.autocrlf false`；**tar 快照不受影响**（已验证 21/21 个脚本为 LF） |
| 构建盘空间（9.8G） | 已因 debuginfo 触发过链接失败 | 铁律见 §8.1；`deploy/wsl-reclaim-space.sh` |
| `readers.rs` 职责膨胀 | 已容纳只读面 + 写面 + 向导 + 环路自检 | 在 `users.*` 落地前拆分 |
| 邮件环路自检依赖 `mailstackd` 在 25 上监听 | 向导阶段可能尚未启动 | 失败时报明确错误；文档已写明前置条件 |
| `mail.test_loopback` 的 Maildir 未命中 | 权威布局未定（`store/src/lib.rs` 已登记） | 只作证据返回 `false`，不当作故障；布局定死后收敛为一个候选 |
| 契约与实现的漂移 | 11 条动作已实现但路由未注册 | 本轮已量化登记；建议加一条「动作×路由」一致性测试 |

---

## 9. 相关文档与资源

### 9.1 本仓库内

| 文档 | 内容 |
|---|---|
| `README.md` | 仓库概览与快速上手 |
| `TOOLCHAIN.md` | 工具链固定策略与为何不放 `rust-toolchain.toml` |
| `docs/TEST_REPORT.md` | **最重要的文档**：规模、门禁结果、43 条不变量的覆盖映射、**§4 真实缺陷复盘（19 条）**、§5 未验证项与偏差登记 |
| `docs/DEPLOYMENT.md` | 部署：systemd、SASL、出站两条路、目录与权限契约、初始化向导、回滚、已知环境事实 |
| `docs/HANDOVER.md` | 本文件 |
| `.github/workflows/ci.yml` | 三道 job：fmt+clippy+test / 供应链（audit+deny） / **不变量存在性（`required=(...)` 名单）** |
| `deploy/*.sh` | 构建、质量门禁、不变量门禁、交付物门禁、容器 Postfix 测试、WSL 工具 |
| `crates/web/src/contract.rs` | **路由唯一真相源**（62 条） |
| `crates/core/src/actions.rs` | **动作白名单唯一真相源**（RO 14 / RW 36 / 破坏性 3） |

### 9.2 仓库外（对照用）

| 资源 | 用途 |
|---|---|
| `e:\MailStack\MailStack-v0.8-beta.6\MailStack-v0.8-beta.6` | Python/FastAPI 基线：**响应形状与错误文案的对照来源**（`backend/mailstackctl/*.py`） |
| `…/CHANGELOG.md` | 基线的变更日志 —— 可用作本项目的「更换日志替代来源」（本项目自身的变更记录在 `TEST_REPORT.md` §4） |
| `docs/REWRITE_TO_RUST.md` v3 | 规格书：§3.3 组件下线、§5.x 各子系统要求、§6 迁移路线、§8 的 43 条不变量 |

### 9.3 建议的接续起点

1. 先读 `docs/TEST_REPORT.md` §4（19 条缺陷复盘）——**项目的隐性知识几乎都在那里**。
2. 再读 §8.2 的偏离表，避免「把有意选择当成 bug 改回去」。
3. 然后从 §4.1 的「注册 11 条已有动作的路由」开始（零新依赖、立刻可见）。

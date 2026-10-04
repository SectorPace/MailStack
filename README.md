# MailStack（Rust 全栈重写）

`MailStack` 从 Node/TypeScript 全栈重写为 Rust 的工程。规格书见
[`docs/REWRITE_TO_RUST.md`](docs/REWRITE_TO_RUST.md)（本仓库外的源码包内）。

- 版本：**0.8.1-beta1**（基线 `v0.8.0-beta.10`）
- 目标形态：单一二进制，生产环境**无 node / 无 npm / 无 Python**
- 保留 Dovecot 作为 IMAP/POP3 与 SASL 后端；自研替代 Postfix / OpenDKIM / fail2ban

## 当前状态

**Phase 0（契约冻结）+ Phase 1（只读面）+ Phase 2（SMTP 核心）+ Phase 3（前端接入）+ Phase 4（写面，动作面完成）**：

| crate | 测试 | 内容 |
|---|---:|---|
| `mailstack-core` | 188 | 动作三集、口令策略、审计哈希链、`atomic`/`locked`、`warn`、命令与服务控制原语、配置 schema、部署模式、**2FA（AES-256-GCM 信封 + RFC 6238 + 恢复码持锁消费）**、**证书到期解析**、**`/proc` 只读采样**、**敏感文件权限体检**、**归档打包/恢复**、**手工封禁文件** |
| `mailstack-priv` | 228 | 动作门控、RPC 帧、RO/RW socket 服务端、**全部 58 个动作的处理器**（只读面、2FA 全生命周期、域名/别名/设置/管理员/DKIM 轮换、只读聚合面、服务与队列动作、手工封禁、备份、初始化向导 `setup.*`、**ACME 证书**、邮件环路自检、**邮箱用户 `users.*`**、**AI 出站 `ai.*`（SSRF/DNS-rebinding 防护）**、**为管理前端新增的 8 个只读列表动作**）、fallback 规则、特权调用客户端 |
| `mailstack-smtp` | 138 + 7 | IP 固定拨号器、中继校验、分阶段测试、出站探测、反中继策略、落地与回滚、真实落盘载体、**MX 解析与直投目标选择**、**DNS 查询（A/MX/TXT，TXT 分片拼接）**、**`AddressPolicy`（SSRF 地址筛选，含 IPv6 内嵌 IPv4 拆解）**（7 个为真实 TLS 集成） |
| `mailstack-queue` | 80 | 队列持久化与原子性、指数退避与去共振、DSN 退信、并发限流、快速失败、**出站必签 DKIM**、**直投（逐域 MX，绝不回退中继）** |
| `mailstack-store` | 31 + 10 | Postfix 表文件（域名/别名）、Dovecot LMTP 客户端（落箱唯一路径；10 个为真实 unix socket 端到端） |
| `mailstack-auth` | 43 | DKIM 密钥与签名（自签自验）、SPF、DMARC、ARC **校验与封印**（替代 OpenDKIM）、**离线 TXT 缓存（含 DMARC 树走查的终止桩）** |
| `mailstack-smtpd` | 139 + 11 | 入站 SMTP：命令解析、DATA 字节流（**SMTP 走私防护**）、会话状态机、反中继、会话驱动、TCP 监听、**TLS 1.2 起**（STARTTLS / 隐式 465）、**连接限速**、**IP 自动封禁**、**提交端口 SASL**（RFC 4954 + Dovecot auth socket，仅在 TLS 之上）、**SPF/DKIM/DMARC 认证与入队**（11 个为真实 TCP/TLS/auth-socket 端到端） |
| `mailstack-web` | 93 | 契约路由表、会话/CSRF、登录限流、错误模型、特权通道、Axum 装配、**2FA 路由**、**动作×路由一致性守卫**、**进程内时序遥测采集器**（`GET /api/metrics/telemetry`）、**RPC 桥（动作允许集来自契约表本身）** |
| `mailstack-web-bin` | 9 | **管理控制台服务入口**（`bin/mailstack-web`）：API + 前端产物托管、SPA 回退、`/api` 兜底保持 JSON、路径穿越拒绝、遥测后台采样宿主 |
| `mailstackd` | 28 | **进程入口**：fail-closed 配置装配、三端口（25/465/587）共用准入状态、集中绑定、**特权 RPC 双通道（RO/RW socket）**、停机扇出、出站队列调度 |
| `mailstackctl` | 7 | **CLI**：参数→特权调用的翻译（`--confirm` 必须真布尔）、退出码区分「助手不可达 / 动作失败」 |

**1018 个测试全部通过**（含 34 个需真实 TLS / TCP / unix socket / Postfix 的集成测试）；
`clippy -D warnings` 与 `rustfmt` 全绿，CI 中 277 个安全不变量测试名全部存在（扫描范围含 `bin/`）。
真实二进制冒烟：收信 → 入队 → RPC 门控 → `mailstackctl` → SIGTERM 优雅停机。
**58 条白名单动作已全部实现，72 条契约路由已全部接线**（无任何路径落到 `/api` 兜底）。
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
crates/web      mailstack-web     管理 API（Axum）、会话/CSRF/限流、时序遥测、RPC 桥
bin/mailstackd  mailstackd        守护进程：入站 SMTP（25/465/587）+ 出站队列调度 + 特权 RPC 双通道
bin/mailstackctl mailstackctl     CLI：调用特权 RPC 面上的已登记动作
bin/mailstack-web mailstack-web   管理控制台服务：管理 API + 前端产物托管（--dist）+ 遥测采样宿主
deploy/         构建、质量门禁与 WSL 工具脚本
docs/           部署文档与测试报告
.github/        CI：质量门禁 + 供应链 + 不变量存在性检查
```

按规格书 §6，`crates/webmail` 将在后续 Phase 加入。

> `mailstackd` 的缺省端口是 25/465/587（**完全接管**才该用的值）。迁移期与 Postfix 双跑时
> 必须显式指定旁路端口，例如 `mailstackd --port 2525`。

## 前端

管理界面是**独立的前端产物**（Vite + React 19 单页应用，不在本仓库内）。后端只托管它：

```bash
# 在前端仓库内构建，产出 dist/
npm ci && npm run build

# 启动管理控制台（只绑回环；对外暴露交给反向代理或 SSH 隧道）
mailstack-web --dist /usr/share/mailstack/admin
```

三点必须知道：

* **省略 `--dist` 就只提供 API**，页面请求会收到 **503**（「这台机器还没部署前端」是服务
  不可用，不是「页面不存在」）。这比回一个空白 200 更容易被监控发现。
* **`/api` 的兜底永远是 JSON 404**，绝不会回 `index.html`。否则前端打到不存在的接口时
  会拿到一段 HTML 并报「解析失败」，把「接口不存在」伪装成「服务端坏了」。
* 前端产物是**外部输入**，本项目不构建也不校验它；后端只负责路径安全（拒绝 `..` 与
  符号链接逃逸）、内容类型、以及上面两条形状约定。

## 构建与测试

```bash
# 生产目标平台是 Linux；Windows 开发机请用 WSL（见 TOOLCHAIN.md）
deploy/build.sh              # release 构建 + SHA256SUMS + SBOM
deploy/wsl-quality-gate.sh   # rustfmt + clippy(-D warnings) + cargo test

# 真实环路验证（需要先 build 出 mailstackd/mailstackctl；会实跑 SMTP 并用掉 25 端口）
deploy/wsl-cargo.sh build -p mailstackd -p mailstackctl
deploy/verify-loopback-e2e.sh
```

> `verify-loopback-e2e.sh` 之前必须保证 **25 端口空闲**（装了 Postfix 的话它会抢走 25）。
> 它验证的是**入站收信 → 队列落盘**这一段；LMTP → Dovecot Maildir、公网 MX 直投
> 与提交端口 SASL 仍需相应的真实环境（见 `docs/HANDOVER.md` §4.3）。

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

   **Phase 3 起为 72 条**（+10）：为 8 个新只读动作各加 1 条路由（其中 `GET /api/users`
   与 `GET /api/aliases` 是在既有路径上补方法），为既有动作 `ai.models.list` 补一条
   `GET /api/ai/models`（原本只有 `POST`），再加 1 条 RPC 桥 `POST /api/rpc`。
   **全部是新增，没有改动或删除任何既有条目**，因此对既有消费方是向后兼容的。

2. **新增 RPC 桥 `POST /api/rpc`**（`crates/web/src/routes.rs`）。这是全仓**唯一**
   从请求体读取动作名的地方，与本项目「动作名在注册时编译期静态绑定」的纪律直接冲突。
   之所以开这个口子：管理前端把它当作兜底传输层，没有它一批动作只能 404。
   安全性由「允许集 = 契约表里已有专门路由的动作」这一**真子集**约束
   （`contract::is_exposed_action`）—— 只被登录流程内部使用的 `admin.totp.verify` 与
   `admin.totp.consume_recovery` 因此不会暴露到 HTTP 面；破坏性动作的 `confirm: true`
   仍由助手侧 `ActionGate` 强制，请求体绕不过去。

3. 规格书 §3.4 推荐用 `mail-builder` 生成 DSN/退信，当前
[`crates/queue/src/dsn.rs`](crates/queue/src/dsn.rs) 为自研 MIME（结构仍遵循 RFC 3464，
含头注入与防回环防护）。该偏离的取舍与替换成本见
[`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) 的「§5.1 与规格书的偏差」。
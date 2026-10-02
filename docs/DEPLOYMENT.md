# MailStack v0.8.1-beta1 部署文档（Rust 重写）

> 对应规格书 `docs/REWRITE_TO_RUST.md`（v2）。本版本完成 **Phase 0 + Phase 1（只读面）**，
> 见文末「当前进度」。

## 1. 产物

| 产物 | 说明 |
|---|---|
| `mailstackd` | 主服务二进制：**入站 SMTP（25/465/587）+ 出站队列调度 + 特权 RPC 的两个 Unix socket**。尚未承载 webmail |
| `mailstackctl` | CLI：`mailstackctl <action> [JSON] [--confirm]`。只读动作直连 RO socket，变更动作经 `sudo` 包装器（见 §3.5） |
| `dist/SHA256SUMS` | 全部产物校验和 |
| `dist/sbom.spdx.json` | SBOM（依赖清单） |

> `mailstackd` 的参数：`--port <PORT>`（可重复，缺省 25 465 587）、`--config-dir <DIR>`
> （把 `/etc/mailstack` 视作 `<DIR>/etc/mailstack`，供测试与旁路部署）、`--log <LEVEL>`
> （`RUST_LOG` 优先）。**启动是 fail-closed 的**：缺少 `setup.json`、域名表为空、
> 证书缺失、`relay.json` 损坏或中继未启用加密，都会拒绝启动而不是带病运行。

供应链约束（规格书 §7）：
- 一律 `cargo build --locked`（`Cargo.lock` 已提交）
- 离线构建：`cargo vendor` + `.cargo/config.toml` 切换 `vendored-sources`
- 来源白名单：仅 crates.io，无 git 依赖
- **禁止**在生产机安装 cargo/rust；构建只在 WSL Ubuntu 24.04 或 CI 完成

## 2. 构建

```bash
# 前置：Linux（WSL Ubuntu 24.04）/ Rust 1.98.1 / C 编译器
# 开发机（Windows）请先执行 deploy/wsl-install-rust.sh 装配 WSL 工具链

deploy/build.sh             # release 构建 + SHA256SUMS + SBOM
deploy/build.sh --offline   # 使用已 vendor 的依赖离线构建
deploy/build.sh --vendor    # 先 vendor 再离线构建
```

质量门禁（与 CI 一致）：

```bash
deploy/wsl-quality-gate.sh   # rustfmt --check + clippy -D warnings + cargo test
```

## 3. 部署

> ⚠️ 本版本仍处于**与旧 Node/Python 实现双跑**的迁移期（规格书 §6）。
> 部署必须保留原 mailstack-web 服务与原 Postfix。
>
> **迁移期必须显式指定旁路端口**：`mailstackd` 的缺省端口是 25/465/587，那是
> **完全接管**时才该用的值，现在用它会和 Postfix 抢端口。双跑阶段请用
> `--port 2525`（已在 `ALLOWED_RELAY_PORTS` 白名单内的非特权端口），
> 由上游按需转发。真正的端口接管属于 Phase 5。

### 3.1 systemd unit（草稿，安装脚本随 Phase 推进落地）

```ini
# /etc/systemd/system/mailstackd.service
[Unit]
Description=MailStack Rust daemon (inbound SMTP + outbound queue)
After=network.target

[Service]
Type=simple
# 迁移期用非特权旁路端口；Phase 5 接管时改为 --port 25 --port 465 --port 587
ExecStart=/usr/local/bin/mailstackd --port 2525
RuntimeDirectory=mailstack
User=root
Restart=on-failure
ProtectSystem=strict
ReadWritePaths=/var/lib/mailstack /etc/mailstack /etc/postfix
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

> 端口 25/465/587 都低于 1024，绑定它们需要 root 或 `CAP_NET_BIND_SERVICE`。
> 三个监听**共用同一份**限速配额与封禁表（否则轮换端口就能绕过限速）。
>
> 特权 RPC 的两个 socket 由本进程创建，路径从 `run_dir` 推导：
>
> | socket | 生产路径 | 权限 | 谁能连 |
> |---|---|---|---|
> | 只读面 | `/run/mailstack/helper-ro.sock` | `0660` root:mailstack-admin | Web 进程（属 `mailstack-admin` 组） |
> | 变更面 | `/run/mailstack/helper.sock` | `0600` root:root | 只有 root；Web 进程必须经 `sudo` 包装器 |
>
> 两者在**启动阶段**就绑定：建不起来（目录不可写、被别的进程占着）会直接启动失败，
> 而不是留下一个「进程正常、管理台永远 503」的状态。门控仍由 `ActionGate` 判定：
> 走只读 socket 的变更动作一律被拒（INV-24）。
>
> 迁移期与旧的 RPC 交付方式**不要同时跑** —— 两边都想绑同一对 socket，后启动的会
> 把先启动的那个顶掉。请确认切换完成后再停旧的。

### 3.2 提交端口 SASL（Dovecot auth socket，§3.5）

25/465/587 三个端口的认证能力**不同**，这是刻意的：

| 端口 | 用途 | TLS | 通告 `AUTH PLAIN` |
|---|---|---|---|
| 25 | MX 收信 | STARTTLS | **否**（不在 MX 口开放认证，少一个口令攻击面） |
| 465 | 提交 | 隐式 TLS | 是（且仅在 TLS 之上） |
| 587 | 提交 | STARTTLS | 是（且仅在 TLS 之上） |

* 凭据**只**在 TLS 之上接收：明文连接上的 `AUTH` 一律 `538 5.7.11`。
* 口令的真相源只有一份 —— Dovecot 的 passdb。`mailstackd` 通过 Dovecot 的
  **auth-client 协议 v1.2** 校验，默认连 `/run/dovecot/auth-client`。
* 覆盖路径：环境变量 `MAILSTACK_DOVECOT_AUTH_SOCKET=/path/to/auth-client`。
  Dovecot 侧需要一个可被 `mailstackd` 读到该 socket 的 `unix_listener auth-client`
  （默认配置已具备）。
* 认证结果与响应码：`235` 成功 / `535` 凭据错 / `454` 后端暂时不可用。**535 与 454
  刻意分开**：前者让客户端提示重新输入口令，后者让它稍后重试。
* 连接失败（Dovecot 未运行）**不会**阻止 `mailstackd` 启动，只会让 AUTH 回 454 —— 
  Dovecot 重启不该连带停掉收信。反之，**通告 AUTH 却没有任何后端**会在启动时被拒绝。
* 认证成功后会话即被允许提交（可向任意域中继，INV-17 的 submission 语义）；
  未认证会话仍只能投递本机纳管域。

### 3.3 出站两条路：中继与直投（互不兜底）

| 配置状态 | 出站路径 | 说明 |
|---|---|---|
| `relay.json` 有 `relayhost` | **只能**经中继 | 全部外发（含退信、系统通知）走同一条路；不存在「中继失败就退回直投」的兜底（INV-18 / INV-21） |
| `relay.json` 不存在或没有 `relayhost` | **直投** | 逐收件域解析 MX，按优先级依次连 25 端口 |

直投的运维要点：

* **先确认出站 25 端口可用**：多数住宅/云环境封禁 25。被判定不可用时管理台会给出
  「建议配置中继」的结论（§5.10.2 的出站探测，属于本机探测而非直投自检）。
* **MX 指向私网/环回会被拒绝**：这是 SSRF 防线（INV-15）。收件域可以用 MX 记录把
  本机变成内网扫描器，公开档部署一律拒绝此类目标，且**不会**因此改用中继。
* **`MX 0 .`（RFC 7505 null MX）会立即退信**：对方明确声明不收信，重试没有意义。
* **没有 MX 记录不是错误**：按 RFC 5321 §5.1 退化为「把域本身当 MX」（查 A/AAAA）。
* ⚠️ **直投当前是明文投递**：直投链路上没有凭证（与中继相反），因此没有「口令泄露」
  风险；但**也没有**做机会式加密。原因是机会式 TLS 在现实里必须「加密但不校验证书」，
  而那是一条独立的安全策略决定，需单独登记与测试。需要全程加密时请配置支持 TLS 的中继。
* 直投**不发** `AUTH`，即便传输上误配了中继凭证（有测试锁定）。

### 3.4 目录与权限契约（§2.5，不得改变）

| 路径 | 用途 | 权限 |
|---|---|---|
| `/etc/mailstack/` | 应用配置 | — |
| `/etc/mailstack/admin.json` | 管理员凭证 + 2FA 信封 | `0640` root:mailstack-admin |
| `/etc/mailstack/setup.json` | 身份（域名 / 邮件主机 / 服务器 IP / DKIM selector） | `0600` |
| `/etc/mailstack/relay.json` | 中继端点 + 明文凭证（`mailstackd` 读它决定出站路径） | `0600` root:root |
| `/etc/opendkim/keys/<domain>/<selector>.private` | DKIM 私钥 | `0640` root:opendkim |
| `/etc/mailstack/totp.key` | TOTP 主密钥 | `0600` root:root（仅特权进程可读） |
| `/var/lib/mailstack/manual-bans.json` | 管理台手工封禁（唯一真相源） | `0600` root:root |
| `/var/log/mailstack-rpc-audit.log` | 审计哈希链 | `0600` |
| `/var/log/mailstack-rpc-audit.log.head` | 审计链锚文件 | `0600` |
| `/run/mailstack/helper-ro.sock` | 只读面 socket | `0660` root:mailstack-admin |
| `/run/mailstack/helper.sock` | 变更面 socket | `0600` root:root |

### 3.5 特权模型

```
RO action  → 直连 /run/mailstack/helper-ro.sock（服务进程属 mailstack-admin 组）
RW action  → sudo /usr/local/libexec/mailstack-privileged（恒走变更面）
```

`mailstackctl` 的用法：

```bash
mailstackctl domains.list                       # 只读 → 直连 RO socket
mailstackctl settings.set '{"transparency":50}' --confirm   # 变更 → sudo 包装器
mailstackctl domains.list --compact             # 紧凑 JSON（默认缩进）
```

退出码：`0` 成功 / `1` 动作失败 / `2` 用法错误 / `3` 助手不可达 / `4` 中途超时。
**`3` 与 `1` 必须分开** —— 脚本据此决定「重试/报警」还是「看错误信息」。
CLI **没有**「强制走某个通道」的开关：通道由动作唯一判定，提供开关就等于提供一个
绕过门控的入口。旁路部署时用 `--ro-socket` 与 `--sudo-wrapper` 把整条链一起挪开
（`--config-dir` 不会影响 `sudo` 包装器的系统级路径）。

**不得弱化的性质**：
1. 未登记动作一律拒绝，默认走只读面（静默提权防护）
2. 破坏性动作必须 `confirm: true`
3. 助手不可达 → `503 PRIVILEGED_HELPER_UNAVAILABLE`，绝不降级为无特权执行
4. 只读面业务错误/中途超时不得 fallback/重试；公网模式只读不得 fallback 到 sudo

### 3.6 初始化向导（`setup.*`）

管理台初始化向导的后端是四个变更面动作（`setup.*` 全部归 RW，因为即使 `dns.verify`
以出站查询为主，它仍属向导流程且不在只读白名单内）：

| 动作 | 做什么 | 落点 |
|---|---|---|
| `setup.identity.apply` | 校验身份 → 原生生成 DKIM → 写身份 | `/etc/mailstack/setup.json`、`/etc/opendkim/keys/<domain>/` |
| `setup.dns.verify` | A / MX / TXT（SPF、DKIM、DMARC）逐条比对 | 只读（不写任何东西） |
| `setup.relay.test` | 分阶段测试中继（DNS → connect → TLS → auth） | 只读（不写任何东西） |
| `setup.relay.apply` | **先测后写**，测试通过才落中继配置 | `/etc/mailstack/relay.json` |
| `setup.mail.test` | 向本机提交端点 `127.0.0.1:25` 投一封测试信 | 只读（本机 MTA 收下即入队） |
| `mail.test_loopback` | 投一封带一次性 token 的环路自检信，并在 Maildir 里找回它 | 只读（写入由本机 MTA/MDA 负责） |

三点运维语义：

* **`identity.apply` 不碰 Postfix / OpenDKIM**。本栈已移除它们（规格书 §3.3），DKIM
  密钥由进程内原生 RSA 生成，签名在出站路径完成。基线的 `postconf -e` /
  `opendkim-genkey` / `postmap` 在本栈**没有对应步骤**，不要按旧手册去改 `main.cf`。
* **`relay.apply` 先测后写**：测试不通过时**一行配置都不写**（`relay.json` 保持原样），
  响应里给 `{applied: false, test: {...}}`。中继测试失败是**结论**而非 HTTP 5xx，
  界面据 `connected` / `stages` 显示卡在哪一步。
* **两个自检动作都走本机提交端点**（`sendmail` 已随 Postfix 一起移除）。因此它们要求
  `mailstackd` 正在监听 25；提交被 `250` 接受即表示环路通了。`maildirDelivered: false`
  只说明没在 Maildir 里找到那封信（权威布局尚未定死），**不是**投递失败。
  `setup.mail.test` 的 `mailboxChecksSkipped: true` 表示邮箱存在性/锁定未检查
  （`users.*` 未移植），出现在响应里是为了不让人误以为查过了。

`setup.cert.issue`（ACME 签发）**尚未实现**（需要先定 ACME 依赖），见 TEST_REPORT §5。

## 4. 回滚

`mailstackd` 仍是旁路进程：停止并移除 unit 即可，原有 Postfix 与 mailstack-web 未被改动。
审计链未被改写（本二进制不含 `audit()` 调用点）。

三点必须注意：

* **停止 `mailstackd` 会同时摘掉特权 RPC 的两个 socket**，管理台随即失去后端。回滚时
  必须**先把旧的 RPC 交付方式恢复起来**，否则会从一个「新进程不在了」变成
  「旧进程也没有」。残留的 socket 文件不影响下次启动（绑定前会先移除陈旧文件）。
* **队列里可能留有未投递的邮件**（`/var/lib/mailstack/queue`）。那些是已经对发送方回过
  250 的邮件 —— 直接删掉就是丢信。回滚前先确认队列为空，或把该目录保留下来。
* 停止是**优雅**的：SIGTERM 之后监听不再接受新连接、在途会话有 10s 宽限期、队列调度
  停止排新轮（单轮投递另有 600s 上限）。若 10s 内没退干净，进程会强制中止在途任务。

## 5. 当前进度（对照规格书 §6）

| Phase | 状态 | 说明 |
|---|---|---|
| Phase 0 契约冻结 | ✅ 基础 | 路由表 `crates/web/src/contract.rs`（62 条）、动作三集 `crates/core/src/actions.rs`、口令/审计/原语移植 |
| Phase 1 只读面 | ✅ 完成 | `mailstack-core`（87 测试）+ `mailstack-priv`（38 测试）+ `mailstack-web`（76 测试），共 **203 测试**，clippy/rustfmt 全绿 |
| Phase 2 SMTP 核心 | 🟡 机制层完成，进程已可运行 | 自研 SMTP / 队列 / DKIM / TLS（1.2 起）/ 连接限速 / IP 封禁 / **提交端口 SASL（Dovecot auth socket）** / **直投（MX 解析，逐域按优先级）** / 入站认证（SPF+DKIM+DMARC）/ **ARC 校验与封印** 全部落地并有测试；`mailstackd` 已能收信、投递（本地 LMTP 或中继/直投）、承载 RO/RW 特权 RPC 与优雅停机。**尚未**：Maildir 只读、对真实 Dovecot auth socket / 真实公网 MX 验证、直投的机会式 TLS（见 TEST_REPORT §5）。风险项「中继 IP 固定」已按 §5.9.3 用真实握手验证 |
| Phase 3 前端切换 | ⏳ 待办 | 管理台 htmx + Askama；webmail 取舍 |
| Phase 4 写面切换 | 🟡 进行中 | **已完成**：2FA 全生命周期（AES-256-GCM 信封 + RFC 6238 + 恢复码持锁消费，INV-5/29/32）；写面动作 `admin.set`、`settings.set`、域名/别名表写入、`dkim.rotate`；**只读聚合面** `snapshot`、`logs.list`、`metrics.realtime`、`certs.list`、`network.check_port`、`system.doctor`、`security.scan`、`backup.list`（读不到的子项一律显式上报，不静默省略）；控制台写面 `services.action`、`queue.action`、`security.ban/unban`；备份 `backup.create/restore/delete`；**初始化向导** `setup.identity.apply`、`setup.dns.verify`、`setup.relay.test`、`setup.relay.apply`、`setup.mail.test`、`mail.test_loopback`（见 §3.6）。50 条白名单动作中已实现 **38** 条（只读面只剩 `ai.models.list`）；62 条契约路由中**已注册 35 条**，其余落 `/api` 兜底 —— 未注册的 27 条里有 **11 条对应的动作已实现但尚未挂路由**（`security.ban/unban`、`backup.create/restore/delete`、`setup.identity.apply`/`dns.verify`/`relay.test`/`relay.apply`、`setup.mail.test`、`mail.test_loopback`），随前端接入一并补。**未完成**：`users.*`、`certs.renew`、`setup.cert.issue`、`ai.*` 等动作族（各自需要独立子系统，见 TEST_REPORT §5），以及审计链的**真实升级演练** |
| Phase 5 组件下线 | ⏳ 待办 | 停用 Postfix/OpenDKIM/fail2ban/Node |

## 6. 已知环境事实（开发机）

- Windows 开发机 rustup default 为 msvc 但**无 link.exe**；可用的链接器只随
  `stable-x86_64-pc-windows-gnu` 提供。**任何 tokio 异步测试在该 mingw 工具链上
  都会以 STATUS_ACCESS_VIOLATION 崩溃**（已用最小复现证实是工具链而非代码问题）。
  因此：异步/Unix-socket 相关测试一律在 WSL 执行，Windows 侧仅用于
  `cargo check --target x86_64-unknown-linux-gnu` 类型校验。
- WSL 出网必须走 Clash 混合端口 **7890**（7897 会接受连接但不可代理）。
- 详见 `TOOLCHAIN.md` 与 `deploy/wsl-*.sh`。
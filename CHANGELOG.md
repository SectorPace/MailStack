# Changelog

All notable changes to the MailStack project are documented in this file.
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [v1.0.0] - 2026-11-03

**首个 Rust 全栈正式版，取代 legacy Node/Python 栈（基线 `v0.8.0-beta.10`）。**

- 生产运行时**不再需要 Node / npm / Python**；协议面、管理面、Webmail、安装链均为 Rust 实现
  （前端只在构建机用 Node 产出静态产物）。
- 交付 5 个二进制：`mailstackd`、`mailstackctl`、`mailstack-web`、`mailstack-imap`、`mailstack-webmail`；
  11 个 crate 的单一 Cargo workspace，`Cargo.lock` 锁定。
- 特权动作白名单 **52 条**（只读 20 + 变更 32，含 `setup.wizard.complete`）、HTTP 契约路由 **62 条**（AI 功能已移除，见「产品增量」）
  （2 条免认证：`/api/health`、`/api/auth/login`），全部接线且有守卫测试。
- 自带管理控制台与 Webmail；提供 curl 一键安装与源码构建两种安装方式。
- 发布前完成 7 份独立第三方代码审查（R1–R7，共 144 条发现：1 critical / 26 high / 59 medium / 58 low），
  修复以 critical/high 优先，其余在审查报告中登记并随 v1.0.x 跟进。

### 新增

- **安全加固（审查驱动）**：见下文「安全加固」一节。
- **管理控制台（Rust 服务 + 独立前端）**：`mailstack-web` 托管管理 API 与前端产物
  （默认 `127.0.0.1:8443`），覆盖初始化向导、域名/别名/邮箱用户、设置、2FA、DKIM 轮换、ACME 证书、
  服务与队列动作、手工封禁、备份/恢复、日志与遥测。前端 React 19 + Vite 7 + Tailwind CSS 4，
  中英双语、明暗主题；历史审计报告见 `docs/WEBUI_AUDIT.md`。
- **Webmail（Rust 版首次交付）**：独立进程 `mailstack-webmail`，默认 `127.0.0.1:8444`，
  与管理台**进程、端口、会话体系完全隔离**。功能对齐主流邮箱：文件夹树/未读徽标/配额、
  邮件列表与批量操作、阅读窗格（sandbox iframe 展示消毒 HTML、远程图片默认阻断、纯文本回退、
  附件下载）、写信（富文本/附件/草稿/Ctrl+Enter）、搜索、快捷键、移动端单栏、中英双语与明暗主题。
  legacy 的 Node 版 Webmail 随旧栈退役；新实现为新的独立进程（端口由 legacy 的 `18788`
  改为默认 `8444`）。详见 `docs/WEBMAIL.md`。
- **安装器（两种形态）**：
  - **一行安装 + 服务器管理脚本**：`curl ... install.sh | sudo bash -s -- --domain ... --admin-user ...
  --admin-password ... --access-mode ...` 一条命令完成全部前提；新增
  `/usr/local/bin/mailstack-manage`（3x-ui 风格 CLI/交互菜单）管理域名、账号、TLS 与访问方式。
- **六种访问模式**：SSH 隧道（默认）、Caddy、nginx、公网 IP + ACME、独立面板域名
  （panel.example.com，强制与 mail/imap/smtp 域区分）、Cloudflare Tunnel；统一生成
  反向代理/Tunnel 配置并以 `install-args.conf` 为唯一状态源。
- **deploy 脚本体系重写（面板式）**：`install.sh` 交互向导 + 非交互全参数、镜像/发布包
  SHA256 校验、依赖自动安装、防火墙放行、`--upgrade`（健康检查+自动回滚）/`--repair`/
  `--dry-run`/`--yes`；`mailstack-manage.sh` 面板菜单 + 全子命令（status --json、doctor、
  domain/account/tls/access/service/backup/update/security/repair/uninstall、审计日志）；
  `uninstall.sh` 安全守卫重写；staging 全程不污染宿主 `/etc` 与 systemd。
- **OCR 全量复审评级**：open-code-review + DeepSeek 复核 287 个文件、1411 条意见；
  人工复核确认并修复 13 项缺陷，无未修复 critical/high；质量分 **92/100**
  （口径：100 − 未修复确认缺陷加权扣分，门槛 ≥90），报告见 `docs/OCR_REVIEW.md`。
- **OCR 全量复审修复**：DMARC pct 采样改用随机化哈希（原确定哈希可被攻击者挑选 Message-ID
  绕过策略削弱）；`raw_message` 补 `X-Content-Type-Options: nosniff`；relay TLS 收紧
  wrappermode=yes（仅 465/显式 wrapper，587 冲突配置拒绝）；`mailstack-manage` 状态文件
  改为白名单解析（不再 `source` 可写前缀文件）；`verify-setup-wizard-e2e.sh` 的 `rm -rf`
  守卫改为 realpath + 前缀/仓库根校验。

- **Webmail UI 修复**：顶栏 flex 布局（此前子项堆叠导致右侧操作区被挤出）、移动端单栏
  玻璃卡片、窄窗格工具栏换行；管理台内容表面统一材质（列表/设置/域名页同一玻璃观感）。
- **注释清理与代码精简**：删除发行代码中的非功能性注释；发布脚本瘦身并补全
  install.sh 与管理脚本的集成（`write_deployment_state`、`STATE_REL_PATH`、访问层应用）。
- **特权通道修复**：`mailstackctl --privileged-stdin` 补齐 Readers 注册表，
  修复 users.* / setup.* / certs.* 经 sudo 包装器全部 NOT_IMPLEMENTED 的生产级缺陷。

- **curl 一键脚本**：从 GitHub Release 下载 `mailstack-v1.0.0-x86_64-unknown-linux-gnu.tar.gz`
    （可选 musl 变体）并校验 `SHA256SUMS`；创建系统用户/组、目录与权限、二进制、
    特权包装器与 sudoers、systemd unit，并初始化管理员凭据。
  - **源码构建**：`git clone` → `deploy/build.sh` → `deploy/install.sh --binary-dir dist`。
  - `deploy/uninstall.sh` 提供卸载路径（默认保留配置与数据，`--purge` 一并删除）。
  详见 `docs/INSTALL.md`。
- **自研 IMAP/POP3/ManageSieve 协议面**：`mailstack-imap` 承载 143/993、110/995、4190 与
  `127.0.0.1:9100` metrics；IMAP4rev1 核心命令 + `LITERAL+`/`UIDPLUS`/`MOVE`/`UNSELECT`/
  `SPECIAL-USE`/`LIST-EXTENDED`/`ESEARCH`/`CONDSTORE`/`QRESYNC`/`QUOTA`/`SORT`/`THREAD`/
  `METADATA`/`ACL`/`SCRAM-SHA-256`/`COMPRESS=DEFLATE` 等扩展；LMTP（RFC 2033）+ Sieve 安全子集
  本地投递；`--migrate-maildir` 提供 Dovecot 离线 UID/关键字迁移。
- **自研 SMTP 传输栈**：入站三端口共用一个准入状态（限速/封禁不可通过换端口绕过）、
  TLS 1.2+（rustls/ring）、SPF/DKIM/DMARC/ARC、SMTP 走私防护、RCPT 收件人名录查验；
  出站中继与直投（逐域 MX、固定 IP 拨号、null MX、SSRF 地址策略）互不兜底；
  队列持久化 + 指数退避 + 投递租约 + DSN 退信 + 出站必签 DKIM。
- **2FA 全生命周期**：AES-256-GCM 信封 + RFC 6238 + 恢复码持锁一次性消费；
  审计哈希链、系统备份/恢复、ACME 等运维能力。

### 安全加固

**2026-10 外部审查加固（`docs/REVIEW_FIXES.md`，批 1–6）**

- **批 1（9 条多报告收敛的 P0）**：远端 MX 可打挂整个服务器、登录限流窗口永久失效、认证失败不进封禁体系、
  空口令哈希可致认证绕过、特权路径把「命令没跑起来」当成功、原子写临时文件在 chmod 前的 umask 窗口、
  DATA 超限后行缓冲无上界导致的远程内存耗尽、TXT 缓存 TTL 被丢弃、per-IP 桶未接线。
- **批 2（出站侧）**：出站响应无长度上限、出站 SMTP 命令注入、发送方向裸 LF 走私、SSRF IPv6 缺口
  （反转为地址白名单）、DNS 解析无超时、LMTP 落箱多余空行。
- **批 3（认证与授权）**：DMARC 策略不再依赖上游 `Debug` 字符串、SPF/DKIM 对齐判定名副其实、
  RCPT 阶段校验收件人是否存在、`Authentication-Results` 防 `;` 注入、TOTP 重放保护、
  `admin.totp.disable` 零验证、会话 Cookie 加 `__Host-` 前缀、破坏性路由守卫双向对照。
- **批 4（特权与密码学，18 条）**：锁/读失败 fail-closed、命令执行超时与 PATH 劫持防护、
  账号管理三处忽略退出码、RPC 帧长度先校验后分配、出站动作的 SSRF/DNS-rebinding/CRLF 注入收紧。
- **批 5（Web 与队列，19 条）**：请求体上限真正生效、登录时序消除用户名枚举、PBKDF2 移入
  `spawn_blocking`、`503` 不计入账号锁定、CSRF 空 token 修复、会话时钟回拨与日志泄漏、
  队列重入/投递租约/回执/DSN 编码修复。
- **批 6（工程化，16 条）**：`cargo-deny`/`cargo audit` 真正强制并修掉 **7 条 RUSTSEC 通告**
  （rustls ×4、rustls-webpki、tokio、webpki-roots）、不变量门禁防「掏空测试」、CI action pin 到 SHA、
  `build.sh` 产物清单逐项齐全、`panic = "unwind"` + 任务失败非零退出、审计链严格读尾等。

**2026-11-03 发布前审查（R1–R7，`review/`）**

- 7 份独立审查共 **144 条发现**（critical 1 / high 26 / medium 59 / low 58）。代表性修复：
  - **R1-001（critical）DMARC 多 From 绕过**：`From:` 含多个域时上游返回「无策略」（None），
    而拒收判定只认 Fail → `p=reject` 域可被任意伪造。已按「多 From 不再豁免」收紧并配反例测试。
  - **R2-001（high）特权包装器协议错配**：唯一客户端以「无 argv + stdin JSON」调用，
    旧部署文档却让包装器转发 `"$@"`，导致全部变更动作（38 个）在生产不可用。包装器协议统一为
    `exec /usr/local/bin/mailstackctl --privileged-stdin`。
  - **R2-013（high）`backup.create --includeMails` 归档了废弃布局**：邮件从未被备份，响应却报
    `includeMails: true`；已按受管账号 `~/Maildir` 权威布局枚举，并在读不出邮件来源时**失败而非静默空归档**。
  - **R5-001（high）RPC 桥绕过会话吊销**：经 `POST /api/rpc` 调 `admin.set`/`admin.totp.*` 不吊销旧会话；
    已把「动作 → 会话吊销」抽成契约表共用判定（REST 与桥同源）。
  - **R5-006（high）未认证可永久锁死管理员登录**：失败计数键来自请求体用户名；已改为不可被未认证者
    无限续期的锁定策略。
  - **R3 系列（SMTP/传输）**：提交端口不再复用入站判定（外发不再被自家 DMARC 判死）、入站补 `Received:`
    与环路检测、提交口校验「发件人 == 认证身份」、中继 `wrappermode` 残留、提交口 PBKDF2 移出 async worker、
    每 IP 并发上限与 IPv6 `/64` 聚合、TLS 握手失败不再惩罚合法发信方、出站会话级总时限。
  - **R4 系列（IMAP/POP3）**：SCRAM 登录绕过邮箱开通校验、MOVE 不检查删除权限、Sieve `redirect`
    环路防护、`sync_uidlist` 并发丢 UID、`STORE 1:*` 的整表重写放大等按严重度修复。
  - **R6 系列（管理前端）**：后端不可达时不再静默降级为 mock/跳过认证（历史高危项）、
    日志「读不到」不再渲染成「没有日志」、`confirm: true` 不再被传输层无条件注入、隐私遮蔽与错误文案修复。
  - **R7 系列（工程化/发布链）**：补齐 `LICENSE`（完整 MIT）、恢复安装/发布链
    （`deploy/install.sh`/`uninstall.sh`/systemd unit/特权包装器）、`build.sh` 收集第 5 个 bin
    `mailstack-webmail`、修复「只打印不失败」的假门禁、`rust-version` 与依赖对齐、CI 覆盖面补齐。
- 其余条目（以 medium/low 为主）在 `review/R1…R7` 与 `docs/REVIEW_FIXES.md` §5 中逐条登记，
  随 v1.0.x 跟进（例如 R5-009 队列调度全量读内存、R4-016 标志变更触发的 uidlist 全表重写）。

### 破坏性变更（相对 legacy `v0.8.0-beta.10`）

1. **不能原地升级**：legacy 是 Python(FastAPI) + Postfix + OpenDKIM + fail2ban + Node 前端；
   v1.0.0 是 5 个 Rust 二进制的单 workspace。请按 `docs/INSTALL.md` 新装并迁移数据
   （迁移期允许与 Postfix 双跑；Phase 5「组件下线」是可选收尾步骤，不是自动完成项）。
2. **默认端口变化**：管理台内部端口 `8787 → 8443`；Webmail 内部端口 `18788 → 8444`。
   SMTP/IMAP/POP3/ManageSieve 端口不变（25/465/587、143/993、110/995、4190）。
3. **特权包装器协议变化**：唯一正确写法是
   `exec /usr/local/bin/mailstackctl --privileged-stdin`（无 argv + stdin JSON）。
   沿用旧包装器（`exec … "$@"` 指向旧 Python 助手）会让全部变更动作失败。
4. **HTTP 契约扩展**：路由表以 legacy 基线为起点新增 RPC 桥、向导收尾与只读列表端点；
   成功响应为**裸对象**（不再套 `{ok,data}` 外壳）；`/api` 兜底恒为 JSON 404。
5. **AI 功能整体移除（产品增量）**：管理台 AI 套件、`/api/ai/*` 契约路由、`ai.*` 特权动作与 AI 出站配置全部删除（前后端一致）；白名单动作降至 **52 条**（RO 20 + RW 32），契约路由降至 **62 条**，AI 相关安全测试与限流一并退役。
7. **`users.delete` 在 `userdel`/`deluser` 都不存在时返回错误**（legacy 为静默成功）——
   「注册表已删、系统账号还在」不能报成功。
8. **CLI 退出码固定**：`0` 成功 / `1` 动作失败 / `2` 用法错误 / `3` 助手不可达 / `4` 中途超时。
9. **Webmail 是新的独立服务**：不再随管理台进程提供；需要单独的 `mailstack-webmail` unit 与端口。

### 已知限制

以下为 v1.0.0 已知且**有意保留**的限制（诚实披露，详见 `docs/TEST_REPORT.md` §5 与各审查报告）：

- **直投没有机会式 TLS**：直投链路是明文投递（中继侧支持 TLS）。机会式 TLS 在现实中意味着
  「加密但不校验证书」，是一项独立的安全策略决定，尚未实现；对传输机密性敏感的场景请配置支持 TLS 的中继。
- **未做真实公网 MX 联调**：直投的 MX 解析、优先级、逐域退避有测试与注入验证，
  但没有用真实公网域名完成端到端投递联调；真实 Dovecot 生产数据迁移与审计链升级演练同样未做。
- **Webmail 不内建 TLS 终止**：只绑回环，公网访问必须经反向代理/SSH 隧道（管理台同策略）。
- **`pct=` 抽样在生产路径不生效（已登记的有意偏离）**：DMARC `pct=` 语义只在离线注入路径可用；
  生产路径由于上游 `mail-auth 0.13.3` 不回传原始记录文本，`pct=` 无法解析，按 100% 执行已公布策略
  （比发布策略更严格的方向，不属于放宽）。实现与理由见 `crates/auth/src/dmarc.rs` 模块文档，
  并有测试 `pct_is_not_available_on_the_network_parse_path` 钉住该事实（将来依赖升级修好后该测试会提醒改文档）。
- **部分 medium/low 审查项未在本版修复**：本轮以 critical/high 优先，其余在 R1–R7 报告与
  `docs/REVIEW_FIXES.md` §5 登记，随 v1.0.x 跟进（例：队列调度全量读内存、IMAP 标志变更的全表重写）。
- **IMAP 范围**：共享邮箱的结构性操作（CREATE/DELETE/RENAME/SUBSCRIBE）与跨存储 COPY/MOVE
  明确返回 `NO`；未实现 IMAP4rev2 与 JMAP。
- **内容治理不在范围内**：本栈负责投递与认证，不保证邮件进入收件箱；送达结果受 IP/域名信誉、
  内容、退信率与接收方策略影响。

### legacy 历史索引

legacy 栈（Node/Python + Postfix/OpenDKIM/fail2ban/Dovecot）的完整变更记录保留在 git 历史中：
`git show eea2ddf:CHANGELOG.md`（741 行）。版本链：

| legacy 版本 | 日期 | 主题 |
|---|---|---|
| `v0.1.0-beta.1` | 2026-08-10 | 首个 beta |
| `v0.5.1-beta.1` | 2026-08-20 | 核心架构与工程硬化、安全/认证基线统一 |
| `v0.5.2-rc.1` … `v0.5.2-rc.5` | 2026-08-30 ~ 08-31 | 运行时修复、安全加固、可观测性、CI 门禁 |
| `v0.5.3-rc.1` | 2026-08-31 | 平台覆盖、安装器加固、Docker 化 |
| `v0.8-beta.6` | 2026-09-12 | 平台与容器、安全加固包 A/B |
| `v0.8.0-beta.7` ~ `beta.10` | 2026-09-13 ~ 09-25 | 一行式安装、CI 修复、仓库清理（**v1.0.0 的基线**） |
| `v1.0.0` | 2026-11-03 | Rust 全栈重写正式版（本文件） |

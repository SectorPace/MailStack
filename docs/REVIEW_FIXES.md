# 外部审查加固台账（2026-10-04）

> 本文是 `docs/HANDOVER.md` §4.0 的**展开版**。它记录本轮「外部审查驱动的加固」的
> 每一条修复：**改了什么 / 为什么这么改 / 配了什么反例测试 / 我否掉了哪几条报告结论**，
> 以及**尚未修复**的清单。
>
> **接续者请先读本文**，再读 `TEST_REPORT.md` §4（历史缺陷复盘）。

---

## 0. 背景与工作方式

### 0.1 触发

收到 **5 份独立的第三方深度审查报告**，覆盖同一份代码：

| 报告 | 来源 | 覆盖 |
|---|---|---|
| `mailstack-rust-code-review.md` | CodeBuddy | 全量静态审查（4 路并行 agent + 主审复核） |
| `REVIEW-SCORECARD.md` | `e:\freeapi\review` | 静态精读 + **在真实 Linux 上实跑门禁** + 对抗性复核（含内存计数分配器实测） |
| `i.md` / `ff3.md` | — | 逐文件通读 + 差分 fuzz + 实证复现 |
| `154.md` / `333.md` / `456651.md` | — | 委托模式深度审查（多个子代理按安全边界分工） |

### 0.2 为什么这些报告值得认真对待

**它们在同一批缺陷上独立收敛。** 例如「登录限流窗口永不重置」这一条，**5 份报告全部独立发现**。
不同方法（静态精读 / 差分 fuzz / 实测复现 / 多个子代理分工）指向同一个位置 ——
这是最强的信号，远超单份报告的判断。

### 0.3 我的工作纪律

1. **不信报告，回源码逐条核实。** 报告本身也有误报（§4 列出我否掉的 3 条）。
2. **每条修复都配「反例测试」**，而不是补 happy path。审查报告的核心批评正是：
   > 「当前的测试体系擅长验证『我实现的东西是对的』，还不擅长验证『我声称的性质没有被破坏』。」

   所以判据是：**把修复改回坏代码，那条测试会变红吗？** 不会就不是守卫。
3. **修复后跑三道门禁**（`QUALITY_GATE` / `INVARIANT_GATE` / `DELIVERABLES`）才提交。

### 0.4 审查报告的共同结论（值得记住）

> 这是一个**文档与协议实现水准远超平均、但安全承诺与实现存在多处确证背离**的项目。
> 它最难的部分（SMTP 走私、IP 固定拨号、反中继 fail-closed、审计链设计）做对了，
> 却在几条**简单且被自己写进「不可动摇不变量(INV)」的性质**上失守 —— 而且这些失守
> 几乎都被「测试恰好构造在同一时间点 / 恰好以 RSET 收尾 / 恰好只测 happy path」
> 掩盖成了绿灯。

**这句话是本次加固的指导思想**：修复的重点不是「加功能」，而是**让代码追上文档已经许下的承诺**。

---

## 1. 批 1（提交 `075a86a`）：9 条多报告收敛的 P0

这 9 条**全部**有多份报告独立指出，且我逐条回源码实锤确认。

### 1.1 远端 MX 可远程打挂整个邮件服务器 🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/smtp/src/client.rs:429`、`crates/store/src/lmtp.rs:383` |
| 报告 | 5 份全部指出（含实测 `SIGABRT(134)`） |

**缺陷**：`line.len() < 3` 检查的是**字节**长度，而 `line[..3]` 是 `&str` 的**字节索引**。
`line` 来自 `String::from_utf8_lossy` —— 任意合法 UTF-8。对端发一行 `"éé"`
（字节 `C3 A9 C3 A9`，`len() == 4 >= 3`），下标 3 落在 `C3 A9 | C3` 中间
—— **不是字符边界 → panic**。

**为什么是 P0**：这条路径被**每一个被投域的 MX** 触发（`SmtpSession::connect` 之后
立即对原始 banner 调用）。根 `Cargo.toml` 设了 `panic = "abort"`，所以后果不是
「一个投递任务失败」，而是**整个 mailstackd 进程中止**。任意能回一行 UTF-8 垃圾的
对端（或任何劫持 25 端口的人）= 远程崩溃。**一个包，无需认证。**

**修法**：改为按字节判定 + 显式 ASCII 数字校验。

**反例测试**：`non_ascii_banner_does_not_panic`（发 `"éé x"` 与 `"😀 hi"`，断言返回
协议错误而非 panic）。

### 1.2 登录限流在进程启动 60 秒后永久失效 🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/web/src/ratelimit.rs:190-208` |
| 报告 | **5 份全部独立指出**（最强信号） |

**缺陷**：`Counter::peek` 是 `&self`，窗口过期直接 `return Allow`，
**从不重置 `window_start`/`count`**。于是任一计数器建立 60 秒后，
`now - window_start >= 1min` 恒成立 → 该桶**从此永远返回 Allow**。
`global 600/min`、`per-IP 20/min`、`per-account 10/min` 三档桶**全部作废**，
只剩「5 次失败锁 15 分钟」这一条还在工作。

**测试盲区（审查报告单独记了一笔）**：`window_slides_after_a_minute`、
`per_ip_bucket_is_independent_of_account`、`global_bucket_caps_total_throughput`
三个测试**全部在唯一的 t0 上构造**，从没有一条检查第二个窗口。
**这组测试恰好把最严重的 bug 掩盖成了绿灯。**

**修法**：`peek(&mut self)`，窗口过期时就地 `window_start = now; count = 0`。
连带修三处（审查报告 H-2）：判决前不再插入新键（原实现让「被限流的请求」也留下新键，
**限流器本身成了内存增长来源**）、键长上界（`MAX_KEY_LEN`）、表容量上界 + 淘汰
（`MAX_TRACKED_KEYS`，先按窗口清扫，仍超限则淘汰最旧的 —— 「最热的键」优先留下）。

**反例测试**：`the_second_window_limits_again`（**第二个窗口必须重新限流**，
这正是原测试的盲区）、`keys_longer_than_the_limit_are_truncated_without_colliding`、
`the_limiter_tables_are_bounded`。

### 1.3 认证失败完全不进封禁体系 🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/smtpd/src/connection.rs`、`crates/smtpd/src/listener.rs` |
| 报告 | 4 份指出 |

**缺陷**：`bans.record_failure` 的全部调用点是 TLS 握手失败 / STARTTLS 握手失败 /
会话 I/O 错误 / `admit()` 内的触发限速。**没有任何一处为认证失败记账。**
`InvalidCredentials` 分支只 `tracing::info!` 后回一条应答并**保持连接打开**；
`session.rs` 只在 `authenticated == true` 时拒绝重复认证，因此**同一条连接可以无限次
重发 `AUTH PLAIN`**，每次都真实打到 Dovecot auth socket。
`ratelimit.rs` 只按**连接数**计数 → 爆破不消耗任何配额。
**宣称替代 fail2ban 的 `ban.rs` 对最具价值的攻击面完全失明。**

**修法**：
- 会话驱动新增 `MAX_CONSECUTIVE_AUTH_FAILURES = 5`，达阈值即断开并把计数回传
  （新增 `ServeOutcome::ClosedAfterAuthFailures`）。
- 监听层逐次 `record_failure` 喂封禁表。
- **`TemporaryFailure`（454，后端挂了）不计入** —— 否则 Dovecot 一抖动就把正常用户全封了。
- **一次成功即清零** —— 要罚的是**连续**爆破，不是累计次数。

**反例测试**：`repeated_auth_failures_are_counted_and_the_connection_is_dropped`、
`a_success_resets_the_consecutive_failure_count`、
`a_temporary_backend_failure_does_not_accumulate`。

### 1.4 空口令哈希 → 任意口令通过（认证绕过，fail-open）🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/core/src/password.rs:161-175` |
| 报告 | 5 份全部指出 |

**缺陷**：`record.hash == ""` 时：
- `hex::decode("")` → `Ok(vec![])`，于是 `dk_len == 0`；
- `pbkdf2_sha256(.., dk_len = 0)` 里 `blocks = 0.div_ceil(32) == 0`，
  `for 1..=0` **一次都不执行**，返回空 `Vec`；
- `constant_time_eq(&[], &[])` → **`true`** —— **任意口令通过**。

**可达性**：`config.rs` 的 `password_configured: !config.hash.is_empty()` 说明
「空 hash」是**被显式考虑过的状态**；而 `admin.json` 会因手工编辑、半写损坏、
从旧备份恢复而出现这个值。**其它任何损坏形态都 fail-closed，唯独这一形态 fail-open。**

**同类问题**：`record.iterations` 被**完全信任**，只挡了 `0`。`iterations = 1`
让 PBKDF2 退化成一次 HMAC，口令哈希可被廉价爆破。

**修法**：先校验记录形状（算法 / 盐长 / 摘要长，且解码后再查一次 —— `hex::decode`
对奇数长度会成功但产生半字节）；`iterations` 取 `max(record.iterations, PBKDF2_ITERATIONS)`。

**反例测试**（5 条）：`an_empty_hash_record_accepts_nothing_at_all`、
`an_empty_salt_record_accepts_nothing`、`a_truncated_hash_record_accepts_nothing`、
`an_unknown_algorithm_record_accepts_nothing`、
`a_downgraded_iteration_count_neither_rejects_nor_weakens_verification`。

> **⚠️ 记一笔我自己的错**：这条测试我第一版写反了断言方向 —— 以为「迭代数被降级后
> 正确口令应当**失败**」。实际 `max()` 生效后正确口令**应该通过**（我们用 310k 重算，
> 与当初生成时一致）。测试当场变红，我才发现理解反了。**这就是反例测试的价值。**

### 1.5 特权路径把「命令没跑起来」当成成功 🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/core/src/exec.rs:341-352` + `:315-323` |
| 报告 | 3 份指出 |

**缺陷**：`output: runner.run(program, args).ok()` —— spawn 失败被压成 `None`；
而 `success()` 对 `None` 返回 `true`。程序不存在 / 权限不足 / fork 失败 →
`output = None` → `success() == true`。**正是该模块文档自称要根除的失败模式：
「配置改了但没人重载」。**

**修法**：新增 `spawn_error: Option<String>` 字段，`success()` 改为
`None => self.spawn_error.is_none()`，并加 `spawn_failed()` / `failure_reason()`
供 API 层如实上报。`ServiceBackend::Noop`（真的什么都不用做）保持 `None` 且返回成功。

**反例测试**：`a_command_that_never_started_is_not_reported_as_success`。

### 1.6 原子写的临时文件在 chmod 之前以 umask 落盘 🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/core/src/atomic.rs:77-91` |
| 报告 | 5 份全部指出（3 份标注「直接违反自己写的 INV-33」） |

**缺陷**：`File::create(&tmp)` 用 `O_CREAT|O_TRUNC` + umask 权限
（root 常见 umask 022 → **0644**），写完 + fsync **之后**才 `set_mode`。
于是 `/etc/mailstack/admin.json.tmp`（口令哈希）、`totp.key.tmp`（AES 主密钥）、
`tls/<domain>/privkey.pem.tmp`（TLS 私钥）、`ai-provider.json.tmp`（API Key）
在「写完 → chmod」之间存在**本机任意进程可读**的明文副本。
用 inotify 守着目录即可稳定命中。
且 `tmp` 名固定为 `<name>.tmp`、可预测、**跟随符号链接** →
能在目标目录预置文件的进程可把密钥内容引到自选路径（本地提权跳板）。

**这直接违反了自己写的 INV-33**（`atomic.rs:60` 注释明写「chmod 在 rename 之前，
secret 不得以进程 umask 落盘」）。同仓 `backup.rs:1073-1084` 的 `open_no_follow`
用了正确写法 —— **说明作者知道这个模式，只是这一处没用。**

**关键洞察**：文档承诺「chmod 在 rename 之前」，但**真正的风险窗口是「首字节落盘之前」**，
比 rename 早得多。

**修法**：`OpenOptions::new().write(true).create_new(true).mode(mode)` ——
权限在 `create(2)` 那一刻就生效；`create_new` 顺带堵住预置符号链接；
失败路径显式删除 tmp；`rename` 后 **fsync 父目录**（原来没有，掉电时 rename 可能
未落日志 → 队列条目整体消失 → **丢邮件**）。临时文件名加
`<pid>.<seq>.<nanos>` 唯一后缀（避免两个无锁写者交错出半写文件）。

**反例测试**：`atomic_applies_mode_before_the_first_byte_lands`（在写入回调里
检查 mode —— 原测试只锚了 rename 前的 mode，没锚「首字节落盘前」）、
`a_failed_rename_leaves_no_temp_file`、`temp_paths_are_unique_per_call`。

### 1.7 未认证远程内存耗尽（DATA 超限后行缓冲无上界）🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/smtpd/src/data.rs:138-141` + `:180-192` |
| 报告 | `REVIEW-SCORECARD` **实测复现**（计数分配器：喂 200 MiB → 堆 +257 MiB） |

**缺陷**：`check_size` 的清空逻辑写在 `if self.overflowed { return }` 的**后面**，
因此**只在首次超限时执行一次**。此后对端只要**不再发送 CRLF**，
`connection.rs:349-361` 的 `continue` 会让循环持续喂入字节，
而 `line` 每字节增长且永不被清空 → **未认证的远程攻击者可无限撑大入站进程内存**。

**为什么测试没拦住**：`data.rs:328-341` 的 `an_endless_line_cannot_exhaust_memory`
在**首次** `TooLarge` 就 `break` —— 测试名承诺的「巨大行不能耗尽内存」
**只覆盖了超限之前**。

**修法**：`push` 里超限后不再累积。**但有个陷阱**：超限后 `line` 恒为空，
于是 `line == b"."` 永远为假 —— **结束标记再也认不出来，会话会一直挂着直到超时**。
故引入饱和计数 `line_len`（0/1/≥2）与缓冲解耦，只回答「这一行是不是恰好一个点」。

**反例测试**（2 条）：
- `the_line_buffer_stops_growing_after_the_limit_is_hit` —— **已实测：把修复改回
  坏代码这条测试确实变红。** 这是本次加固中验证最扎实的一条。
- `a_line_starting_with_a_dot_is_not_mistaken_for_the_terminator` —— 钉住
  `.foo` 不被当成结束标记（否则正文截断即走私）。

### 1.8 TXT 缓存 TTL 被丢弃 🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/auth/src/cache.rs:157` |
| 报告 | 3 份指出 |

**缺陷**：`insert(&self, key, value, _valid_until: Instant)` —— **TTL 参数被丢弃**。
`get()` 也只做一次查表，**不校验任何过期时间**。
而 `mail-auth` 0.13 会把每次 TXT 查询结果 —— **包括失败结果** —— 无条件写回调用方缓存
（依赖源码 `common/resolver.rs:119,161-173`），该缓存与进程同寿。

后果：
1. **TTL 完全失效** —— 发件方轮换 DKIM 密钥、撤销 selector、把 DMARC 从 `p=none`
   提到 `p=reject`，本机**重启前永远看不到**；
2. **负结果永久生效** —— 域主事后修好也无效（一次瞬时 DNS 错误永久钉住该域）；
3. **攻击者可控的无界增长** —— 自己域上放通配 TXT，每个随机 `_domainkey` 查询
   都写入一条永不过期条目。

**修法**：条目带 `Option<Instant>` 过期时间；`get` 校验并顺带删除过期项；
新增 `MAX_TTL`（1 小时，防对端自称 TTL 极大而永久钉住）与 `MAX_ENTRIES`（4096）。

**关键设计**：注入条目（离线验签用）用 `None` 显式表示**不过期** ——
这个缓存有**两种来源、语义相反**，不能混成一种。注入的目的是绕开 DNS，
一旦过期，「同密钥对自签自验」会变成与墙钟赛跑的 flaky。

**修法中的陷阱（我踩了）**：`Option` 的序是 `None < Some(_)`，所以朴素的
`min_by_key(|(_, (_, until))| *until)` 会把**注入条目**排在最前并**优先淘汰它**
—— 与意图正好相反。改为分两步：先只在「带 TTL」的条目里挑最接近过期的。
这条被反例测试 `injected_records_outlive_ttl_bound_ones_under_pressure` 当场抓住。

**反例测试**（4 条）：`an_expired_lookup_result_is_no_longer_served`、
`a_fresh_lookup_result_is_still_served`、`an_absurdly_large_ttl_is_capped`、
`injected_records_outlive_ttl_bound_ones_under_pressure`。

### 1.9 per-IP 桶从未接线 🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/web/src/routes.rs:194` |
| 报告 | 4 份指出 |

**缺陷**：`let client_ip = "unknown";` —— **全站共享一个 20 次/分钟的桶**。
任意来源 21 次请求即让所有管理员登录持续 429，每 60 秒可复现 →
**管理员登录永久拒绝**（登录 DoS）。叠加 1.2 后撞库防护实质为零。

**修法**：改用 `ConnectInfo<SocketAddr>` 取**传输层真实对端**，
并在 `bin/mailstack-web` 启用 `into_make_service_with_connect_info`。

**关键决策：刻意不读 `X-Forwarded-For`。** 虽然本进程默认绑回环、
反代拓扑下对端是 `127.0.0.1` 会导致桶退化，但 XFF 是**请求可控的明文** ——
读它等于把限流器变成攻击者的工具（每次换一个值，per-IP 桶对真正的爆破者永久失效）。
**fail-closed 优先于「看起来能用」。** 反向代理拓扑下需要按跳数配置可信代理白名单，
那属于部署层决策，且在本进程默认绑回环的前提下没有收益。
`normalize_ip` 顺带把 IPv4-mapped 折叠到 v4（否则 `::ffff:1.2.3.4` 与 `1.2.3.4`
是两条独立记录，同一个攻击者占两个桶）。

**反例测试**：`client_key_prefers_the_transport_peer`、
`an_ipv4_mapped_peer_shares_the_bucket_with_its_v4_form`、
`a_missing_peer_uses_one_stable_key`。

### 1.10 `panic = "abort"` 的放大器效应（评估结论）

审查报告指出 `Cargo.toml:68` 的 `panic = "abort"` 把每一个 panic 放大成进程死亡，
并让 `core/src/warn.rs` 的 `catch_unwind`（「warn 永不抛出」）在 release 下**完全无效**。

**我的处理**：本轮**未改**这个设置，因为：
1. 1.1 与 1.7 的真正问题（可被远程触发的 panic）已经修掉；
2. 改成 unwind 后，panic 会被 tokio 任务边界吞掉，而
   `bin/mailstackd/src/lib.rs:121-124` 忽略 `JoinError` → **进程存活但出站调度永久死亡**，
   表现为「静默停投」。**两种模式都不可接受**，需要的是「panic 隔离 + 任务重启」，
   那是一个独立的设计决定（已列入批 6）。

---

## 2. 批 2（提交 `70b9c35`）：出站侧加固

**为什么要单独成批**：出站路径此前比入站宽松得多，而直投模式会连向
**任意收件域的 MX** —— 这些缺陷**不需要认证、不需要对端认识本机**，
只要收到一封邮件就自动暴露。审查报告的原话是「入站侧把输入限死，
出站侧只限时间不限字节 —— 不对称」。

### 2.1 出站响应无长度上限

`crates/smtp/src/client.rs` 的 `read_line` 只等 `\n`，一条永不出 LF 的应答
就能让投递任务内存无界增长。入站侧有两道限长，出站侧**一道都没有**。

**修法**：新增 `MAX_RESPONSE_LINE_BYTES = 4096` 与 `MAX_RESPONSE_LINES = 64`。
**超限按协议错误断开而不是截断** —— 截断出来的半行状态码恰好在前 3 字节，
会被上层当作完整应答解析，那比直接断开更危险。

### 2.2 出站 SMTP 命令注入

`MAIL FROM:<{}>` / `RCPT TO:<{}>` 是裸字符串拼接，地址里含 `\r\n` 就是两条命令，
本机随即以自己的身份向第三方投递。**这与入站侧 `smtpd` 拼死防的走私形态完全同构，
只是方向相反。**

原实现把安全性质建立在「上游生产者会校验」这个约定上 —— 而队列的入口有多个
（`queue.action`、DSN 生成、备份恢复），漏一个就能注入。

**修法**：新增 `checked_addr()` 在**拼接点**拒绝（对所有调用点同时成立），
并给它独立的 `SmtpError::HeaderInjection` 变体 —— 这是**本机代码或队列数据的缺陷**，
不是对端协议违规，排查方向完全不同。顺带禁 NUL。

### 2.3 裸 LF 走私（发送方向）

两处 `dot_stuff`（`smtp/client.rs` 与 `store/lmtp.rs`）都只按 `\r\n` 切分，
于是**含裸 LF 的行完全不做 stuffing**。队列是公共写入面，攻击者只需让正文里出现
`<裸 LF>.` 开头的行，邮件就会在那个「句点行」处被对端**截断**，
剩余部分被当作 SMTP 命令解析 —— **CVE-2023-51764 的发送侧形态**。

**修法**：按 `\n` 切分 + 剥掉切分带来的 `\r`。

> **副作用（有意）**：行尾一律规范成 CRLF。SMTP 的行边界就是 CRLF（RFC 5321 §2.1），
> 保留裸 LF 意味着交给对端一份「行边界与对端理解不一致」的数据。入站侧对裸 LF 的
> 默认策略也是 `Reject`，即**两端立场一致**。

**⚠️ 三个既有测试当场变红**（`dot_stuffing_prefixes_leading_dots_only` 等）——
正好证明它们此前只覆盖了 CRLF 输入。我核对后确认是「测试编码了旧行为」而非真实回归，
修正了 3 条断言的期望值并补了裸 LF 的用例。

### 2.4 SSRF 地址策略的 IPv6 缺口（**反转为白名单**）

原判定是「只拒 `2001:db8::/32`（文档段）」，等于**只拒这一个段，其余全放**。
实测下列地址**全部穿过** `public_only()`：

| 地址 | 问题 |
|---|---|
| `::127.0.0.1` | IPv4-compatible（`::/96`）。`is_loopback()` 只认 `::1`，`is_private()` 只认 `fc00::/7`，两者都不命中；内核按 v4 兼容处理，**实际连的是本机** |
| `::10.0.0.1` | 同上，指向私网 |
| `64:ff9b::127.0.0.1` | NAT64（RFC 6052）。NAT64 主机上 TCP 被翻译成 `127.0.0.1:25` |
| `64:ff9b:1::127.0.0.1` | local-use NAT64（RFC 8215） |
| `fec0::1` | 废弃的 site-local |

**修法：反转为 `2000::/3` 白名单**（全球单播只在 `2000::/3`，RFC 4291 §2.5）。
**这一个判断一次性消灭上面整类** —— 它们的首段全都不在 `0x2000..=0x3fff` 之内。
`2000::/3` 内部的 IANA 特殊登记段（`2001:db8::/32`、`2001::/32`、`2001:2::/48`、
`2001:20::/28`、`3fff::/20`）仍逐个排除。

**顺带修**：`192.88.99.0/24`（废弃的 6to4 relay anycast）漏在 v4 侧 ——
它是 IPv4 地址，报告里写在 v6 那段注释下，容易让人以为已覆盖。

**反例测试**：`non_global_unicast_ipv6_is_rejected_wholesale` ——
**同时钉住两侧**：15 个该拒的地址必须拒，且 2 个真全球单播（`2606:4700:4700::1111`
等）必须**放行**（否则整个 IPv6 投递全废）。

### 2.5 解析无超时（**同一进程两套 DNS 栈**）

`tokio::net::lookup_host` 在**阻塞**线程池做 `getaddrinfo`，而它是
**IP 固定拨号的前置条件** —— 连接有超时、解析没有，语义反了。
同 crate 的 `dns_query.rs` / `mx.rs` 用的是带超时的 hickory。**同一进程两套 DNS 栈。**

**修法**：加 `RESOLVE_TIMEOUT`（5 秒），超时归为**可重试**失败
（DNS 故障是基础设施问题，等一会儿重试通常就好了，不是退信信号）。

### 2.6 LMTP 落箱多一个空行

`format!("{}\r\n.\r\n", dot_stuff(data))` 无条件补 CRLF，正文已以 CRLF 结尾时
（**绝大多数邮件**）尾部凭空多出一个空行 —— **对正文的改写会让上游 DKIM body hash 失效**。

**讽刺的是**：同仓 `smtp/src/client.rs` 的 `terminate_data` 已把这个坑写进注释并正确规避，
而 `lmtp.rs` **正是那段注释警告的写法**。端到端测试只读到单独的 `.` 就停，测不出来。

**修法**：对齐 `terminate_data` 的判据。**刻意不复用那个函数** ——
为一个函数给 `store` 引入 `smtp` 这条边（`smtp` 带 TLS/拨号栈）不划算，
判据逐条一致即可（已在注释里说明这个取舍）。

---

## 3. 批 3（提交 `37ddfa1`）：认证与授权

### 3.1 DMARC 策略靠第三方 enum 的 `Debug` 字符串判定 🔴

| 项 | 内容 |
|---|---|
| 位置 | `crates/auth/src/dmarc.rs:118` + `crates/smtpd/src/sink.rs:100` |

**缺陷**：`policy: format!("{:?}", output.policy()).to_lowercase()`，消费侧比对
`== "reject"`。也就是说**安全判定依赖上游 mail-auth 的 `Debug` 派生输出** ——
上游一改（哪怕只是 `Reject` → `Policy(Reject)`），550 拒收分支**永不触发、
邮件静默放行**，而测试照样全绿。

**修法**：新增类型化的 `DmarcPolicy` enum + `policy_is_reject()`，
在 `evaluate()` 里同时产出展示字符串与类型值。展示字符串保留（界面与 A-R 头要用），
但**判定一律走类型**。变体增减从此是编译期错误。

### 3.2 `spf_aligned()` / `dkim_aligned()` 名不符实

名字叫 aligned，**实际只判 pass、完全不做组织域对齐比较**。
`From: bank@example.com` 由 `d=attacker.example` 签名 → 两者都 pass 但**不是对齐**。
当前无消费者（零实际影响），但它是 `pub` API，**是给下一个调用者挖的坑**。

**修法**：改名 `spf_pass()` / `dkim_pass()`，注释说明真正的对齐结论由上游给出、
**不在这一层**。

### 3.3 RCPT 阶段不查收件人是否存在

**两个后果**：
1. **目录枚举** —— 25 端口逐地址试 `RCPT`，用 250/550 的差别摸出全部真实邮箱
   （`VRFY` 已正确恒拒 502，但 `RCPT` 把同一信息面重新打开了）；
2. **退信垃圾（backscatter）** —— 伪造发件人 + 不存在的本域收件人 →
   本机向第三方发 DSN，损害 IP 信誉。

**修法**：新增 `crates/store/src/recipients.rs`，**复用**既有的
`managed-mailboxes.json` 与别名表（不另立第二份数据源）。

**最关键的设计是「三态」**：

```rust
pub enum Lookup { Known, Missing, Unavailable(String) }
```

**把「查不了」当成「不存在」会误拒真邮件** —— 一次磁盘抖动就变成全站拒收真邮件，
那比放过一次枚举**严重得多**。因此只有 `Missing` 才允许 550，
`Unavailable` 必须保持现状（只判域）并让调用方记日志。

配套决策：
- **不查 `/etc/passwd`** —— 那是系统账号库，含 `root`/`daemon`，
  用它判定「可投递」等于开一整条枚举面；
- **远程域不查名录** —— 去本地名录问「bob@gmail.com 在不在」没意义，
  且会把 587 提交变成拒绝服务向量（后端稍慢就整体不可用）；
- 大小写归一化（不归一化会把 `Alice@Example.org` 误判成不存在）。

**顺带修掉一个真 bug**：接上名录后 `RCPT TO:<postmaster>` 会变 550 ——
因为该地址是运维在 `SessionConfig::postmaster` 配的策略值，**不保证是注册邮箱**。
这破坏了 RFC 5321 §4.1.1.3「必须接受」的保留地址（Abuse 报告、DSN 都往这里发）。
已让它绕过名录，并加回归测试。

### 3.4 `Authentication-Results` 头可被 `;` 注入伪造

`MAIL FROM:<a;dmarc=pass@evil.com>` 里的 `;` 原样进入 A-R 头，
下游按 `;` 分词的组件会被骗出一个看似挂在真实 authserv-id 下的 `dmarc=pass` 段。

**为什么既有 `sanitize()` 没挡住**：它只把**控制字符**换成空格，`;` 不是控制字符。

**修法**：新增 `quoted_value()`，含 `;` / `"` / `\` 时按 RFC 8601 加引号并转义
（`\"` / `\\`）。**不删字符** —— 删会把 `a;b@c` 改成 `ab@c`，既改语义又可能让地址解析失败。
触发集只含这三个字符，因为 §2.2 的 `token` 本就允许 `@ : % = / ?`
（真实 MTA 一直是不加引号写裸地址的）。

### 3.5 TOTP 无重放保护

接受 `step-1 / step / step+1` 窗口（约 90 秒），但**不记录已用的 step** ——
一个 6 位动态码在 90 秒内可**无限次复用**。RFC 6238 §5.2 明确建议记录 lastUsedStep。
**恢复码有持锁一次性消费（已实现且有测试），动态码没有 —— 不对称。**

**修法**：新增 `usedSteps` 记账，沿用既有信封机制（复用 `admin.json`，不新建第二个存储）。

**三个关键设计**：

1. **「判已用 + 记账」整个在 `update_admin_config` 的 `locked()` 临界区内。**
   锁外读、锁外判的话，两个并发请求会各自看到「这一步还没用过」并双双放行 ——
   那等于没有重放保护。（`INV-32` 的那把锁在这里终于有了真正的消费者。）
2. **记账只增不减**（有界 `USED_STEPS_KEPT = 8`，超出淘汰最旧）——
   因此**时钟回拨不会让旧码复活**：回拨后集合里那个 step 仍在，同一个码照样被拒。
3. **「已用过」与「码不对」返回同一结论同一文案。**
   若给一个「该码已被使用」的错误，攻击者就能用它区分「我猜的码曾经有效过」
   与「从没有效过」，**把 6 位空间的搜索效率提高一个量级**。

**反例测试**（7 条，含）：`a_totp_code_cannot_be_used_twice_in_the_same_step`、
`concurrent_totp_verifications_of_one_step_yield_exactly_one_success`（8 线程并发）、
`a_clock_rollback_does_not_revive_a_previously_used_code`、
`step_zero_is_recorded_like_any_other_step`、
`used_steps_ledger_is_bounded_and_drops_the_oldest_first`、
`a_corrupt_used_steps_ledger_does_not_lock_the_admin_out`、
`a_wrong_guess_does_not_burn_the_real_code_of_the_current_step`。

### 3.6 `admin.totp.disable` 零验证

原先**不需要** TOTP 码、不需要口令、不在 `DESTRUCTIVE` 名单。
会话被劫持后可直接**静默拆掉 2FA**。

**修法**：要求二次因子（走 `totp.verify` 同一条路径，不另写一套），
并加入 `DESTRUCTIVE_ACTIONS`（3 → 4）。

**基线曾把它排除在外**，理由是「2FA 已经不在了，确认没有意义」——
但恰恰相反：会话被劫持时攻击者拿到的是**已认证会话**，不是第二个因子；
此时唯一还能证明「你是你」的东西就是这个因子。**基线这条推理是错的。**

### 3.7 `revoke_user` 是死代码

`SessionStore::revoke_user` 定义了但**无任何非测试调用点**。
于是「我改密码了」与「攻击者的会话失效了」毫无关系 —— 攻击者那 **7 天绝对上限**内
的会话仍完全可用。**事故响应的第一步形同虚设。**

**修法**：`admin.set` / `totp.enable` / `totp.disable` 成功后一律按用户维度全量吊销。

**决策：连当前会话一起吊销**（而非保留当前、吊销其余）。理由：
1. **无法区分「当前会话」是不是攻击者的。** 劫持场景下两种可能各占一半，
   猜错的那一半等于什么都没做 —— 而这恰是事故响应最不能承受的失败模式；
2. **基线也是这么做的**：`server.production.ts` 的 `POST /api/admin` 在 `admin.set`
   成功后 `sessions.clear()` 并回 `reauthenticate: true`；
3. 体验代价只有「再输一次口令」，误判代价是攻击者全身而退。

**用户名从 `admin.json` 读而不是从请求体取** —— 请求体的 `username` 可以是空串
（「只改密码」是既有语义），也可能被篡改。吊销是**按用户维度全量生效**的操作，
一旦用户名取错就会「踢光别人、留下自己」，**恰好与目的相反**。

**若 `admin.json` 读不到 → 返回 500**，而不是静默当作成功：那是「凭据已改但
吊销目标不明」的**半完成状态**，必须让调用方看见。

### 3.8 会话 Cookie 缺 `__Host-` 前缀

加 `__Host-` 后浏览器强制「必须 `Secure` + 必须 `Path=/` + **不得**有 `Domain`」，
把「同站子域写入同名 cookie 覆盖会话」这条路径关掉 ——
攻击者控制的 `evil.example.com` 无法给 `example.com` 写 cookie。
改名会让**所有人重新登录**，这在一次安全修复里可接受（强制重登恰好也是想顺手做掉的）。

**关键决策：`Secure` 刻意不无条件加。**

默认部署只提供 HTTP（`DEFAULT_BIND = 127.0.0.1:8443`，TLS 属部署层），
强加 `Secure` 后浏览器**根本不回传 cookie** → 登录**直接坏掉**，
用户看到的现象是「密码输对了却提示未登录」。

**两种后果严重度不对称**：
- 漏加 `Secure` = 「明文多传一跳」（需要抓包才能发现）；
- 误加 `Secure` = 「所有人都登不进去」（只有用户能发现，且产品**开箱即坏**）。

故 `session_cookie_secure()` 按四级判定：显式配置 `MAILSTACK_COOKIE_SECURE`
→ 公网模式 → **可信回环对端 + `X-Forwarded-Proto: https`** → 其余不加。
**第 3 条只信回环** —— XFF 是请求可控的明文，这与 `client_key` 不读 `X-Forwarded-For`
是**同一个理由的两面**。

### 3.9 破坏性路由守卫改为双向对照

`web/contract.rs` 的守卫原先硬编码 3 个字符串。改为与 `DESTRUCTIVE_ACTIONS`
**双向对照**并显式钉住当前 4 个 —— 避免有人同时改两边而断言仍然通过。

### 3.10 `Secure` 与「作废 cookie」必须配对

`clear_session_cookie` 用**同一套** `session_cookie_secure()` 判定。
若作废时算出的属性与下发时不一致，浏览器就**清不掉那一枚**
（属性不同的同名 cookie 是两条独立记录）—— 表现为「登出了但立刻又自动登录」。
因此两处必须用同一个函数，且在响应阶段**刻意不推断**「当前是不是 https」
（响应阶段没有请求信息），只读显式配置项。

---

## 3B. 批 4（提交 `1ff8a7b`）：特权与密码学，§5.1 的 18 条全部修复

> 本节是 §5.1 的完成态。§5.1 里那 18 行已被本节取代，只保留一条指针。
> **零新依赖**：`regex` 本就是 workspace 既有依赖，`Cargo.toml` / `Cargo.lock`
> 未因本批改动。
>
> **这一批此前从未验证过**：代码在 2026-10-04 22:45 → 10-05 10:56 之间陆续写入，
> 但最近一次门禁是 10-04 18:04。本节所有「已修」结论都来自 `1ff8a7b` 上
> **首次实跑**的三道门禁。

### 3B.1 门禁结果（首次实跑）

| 门禁 | 结果 |
|---|---|
| `deploy/wsl-quality-gate.sh`（rustfmt + clippy `-D warnings` + 全量测试） | **PASS** |
| `deploy/verify-invariant-gate.sh` | **INVARIANT_GATE_OK**（`checked=277 missing=0`） |
| `deploy/verify-deliverables.sh` | **DELIVERABLES_OK** |
| 测试总数 | **1083 → 1111 passed / 0 failed** |

> ⚠️ 复现环境与台账 §6.3 不同：原 Ubuntu 发行版的 `ext4.vhdx` 被 EFS
> 「Application Protected」加密，WSL 挂载失败并**只读回退**（根分区只剩 952M）。
> 本轮改用 **Debian 13 (trixie)** 重跑，生产目标平台仍是 Linux，结论不受影响。

### 3B.2 fail-closed：拿不到锁 / 读不出来 → 报错，不降级

| # | 原缺陷 | 修法 | 反例测试 |
|---|---|---|---|
| **4.1** | `locked()` 的锁是空壳 RAII：sidecar 打不开返回 `None`、`FileLock::acquire` 失败只 warn、`Drop` 什么都不做 | `core/atomic.rs` 两处入口改为 `FileLock::acquire(open_lock_sidecar(..)?, ..)?`；`FileLock` 改为**真正持有 `File`** 的 guard（原先是零字段 struct，句柄当场即丢） | `locked_fails_closed_when_the_sidecar_cannot_be_opened`、`atomic_fails_closed_when_the_sidecar_cannot_be_opened` |
| **4.2** | `add_domain` / `add_alias` / `delete_domain` 纯 RMW 完全没用 `locked()` | 新增 `locked_with<T,E>`（错误类型由调用方给），三处变更全部持锁；`delete_domain` 对 domains+aliases **同时**持锁 | `table_mutations_wait_for_their_read_modify_write_locks`、`add_domain_refuses_to_replace_a_table_when_reading_it_fails`、`delete_domain_does_not_modify_either_table_when_alias_read_fails` |
| **4.3** | `file_snapshot` 先 `exists()` 再读，EACCES 被当成「文件不存在」，随后的 `file_restore` 会 `remove_file` **销毁既存配置** | 改用 `symlink_metadata`，只把 `ErrorKind::NotFound` 当作不存在，其余一律 `Err` | `file_snapshot_reports_metadata_errors_instead_of_treating_them_as_missing` |

**配套**：`store/error.rs` 的 `From<CoreError>` 原先把所有 `CoreError` 塌成
`StoreError::Invalid` —— 锁失败会被伪装成「参数非法」。改为按变体分流，
`CoreError::Io` 直通为 `StoreError::Io`。

### 3B.3 命令执行：超时、正则、PATH 劫持

| # | 原缺陷 | 修法 | 反例测试 |
|---|---|---|---|
| **4.4** | `service_ctl` 走的 `run` / `run_with_input` **完全无超时** | 改走 `run_with_timeout(..., SERVICE_COMMAND_TIMEOUT)` | `service_ctl_runs_its_command_with_a_bounded_timeout` |
| **4.5** | `pgrep -f <unit>` 按**正则**解释单元名（`postfix\|bash` 会误判在运行） | `format!(".*{}.*", regex::escape(unit))` | 由既有的 `is_service_active_*` 系列覆盖 |
| **4.6** | `resolve_program` 只判 `is_file()`，不判可执行位 → PATH 里可写目录可劫持 root 助手的 `postconf` / `systemctl` | 新增 `resolve_program_for_execution`：必须 root 或 euid 拥有、具备执行位、`mode & 0o022 == 0`，并**逐级向上检查整条父目录链**；`SystemCommandRunner` 的 `run` / `run_with_input` / `run_with_timeout` 三入口全部改用它 | `resolve_program_*` 系列 |

### 3B.4 账号管理：三处忽略退出码 + 保留名

| # | 原缺陷 | 修法 | 反例测试 |
|---|---|---|---|
| **4.7** | `set_password` 忽略 `chpasswd` 退出码 → **账号建了但口令没设上**，界面报成功 | `chpasswd` 与 `passwd` 降级路径都检查 `result.success()` | `failed_chpasswd_does_not_report_mailbox_creation_as_success` |
| **4.8** | `users.status` 不看 `passwd` 的 status → 禁用邮箱可能没生效 | 检查退出码；失败时**不 bump session epoch**（否则已失效的会话反而被续命） | `failed_passwd_status_does_not_bump_session_epoch` |
| **4.9** | `users.delete` 的 `userdel -r` 与降级路径都不看 status，照旧从注册表删除 → 系统账号带原口令留在机器上 | 两级降级都检查退出码 | `failed_userdel_fallback_preserves_both_managed_registries` |
| **4.10** | `add` 不查 `PROTECTED_USERS`，且 `USER_RE` 允许保留名 | 在**跑任何命令之前**前置拒绝；`PROTECTED_USERS` 补入 `mailstack-web` | `add_rejects_protected_service_users_before_running_commands` |

> **有意偏离（已登记）**：4.9 的降级链在 `userdel` 与 `deluser` 都不存在时，
> 基线是「静默什么都不做（不是错误）」。现在改为
> **返回错误** —— 因为「静默成功」正是本条要修的洞（注册表已删、系统账号还在）。
> 见 `HANDOVER.md` §8.2。

### 3B.5 RPC 连接与帧

| # | 原缺陷 | 修法 | 反例测试 |
|---|---|---|---|
| **4.11** | `bind → set_permissions` 的 world-connectable 窗口；`chown` 失败仅 warn | 属组解析失败直接中止 bind，并确保失败的 bind 不留下可被抢占的 socket | `socket_group_resolution_failure_aborts_binding` |
| **4.12** | RPC 连接无超时，`Semaphore::new(8)` → 8 个只连不发的客户端即可让助手不可用 | 单请求帧读取超时 30s；`try_acquire_owned`，无 permit 时**立即拒连接**而不是无限排队 | `idle_rpc_connections_are_closed_after_the_request_read_timeout` |
| **4.13** | `MAX_REQUEST_BYTES = 256KB` 定义了但全仓无引用；`read_frame` 只比对 16MB，且先分配后读 | 新增 `read_json_request_frame`，请求面按 256KB **先校验后分配** | `rejects_requests_above_256_kib_before_reading_or_allocating_the_payload` |

### 3B.6 AI 出站：三处一并收紧

| # | 原缺陷 | 修法 | 反例测试 |
|---|---|---|---|
| **4.14** | AI 配置与 **TLS 私钥**用 `atomic::atomic()`（= 落进 `mailstack-admin` 组），Web 进程能直接读出 apiKey 与私钥 | 两处改 `atomic_as(..., 0o600, None)`；acme.sh 的输出先写进 **0700 私有暂存目录**，chmod 后再原子搬运，消除 world-readable 窗口 | `certificate_mode_failure_is_returned_instead_of_ignored` 等 |
| **4.15** | `with_ai_outbound` 是生产可见的 pub 构造器，可硬覆盖 AI 出站总闸（INV-10） | 降为 `#[cfg(test)]` 私有 | 由既有 `assert_denied` 系列覆盖 |
| **4.16** | `MAILSTACK_ALLOW_PRIVATE_AI=1` 时 IP 筛选与 HTTPS 强制**全部跳过** → `ai.chat` 的 `baseUrl` 可直指 `http://169.254.169.254/` | 开关不再等于「放行一切」：新增 `smtp::is_private_network_address`，**即便开启也只放行 RFC1918 / IPv6 ULA**；link-local、CGNAT、文档段、loopback 一律拒（含 IPv4-mapped、6to4、Teredo 里的内嵌地址） | `private_network_address_policy_excludes_loopback_link_local_and_special_ranges` |
| **4.17** | 出站 HTTP 请求行/头直接 `format!` 拼接，`parse_url` 不拒 `\r\n` → **请求走私** | URL / 方法 / 目标 / 头名 / 头值**五处**全部拒控制字符与空格 | `request_bytes_reject_crlf_injection_in_method_target_and_headers`、`endpoint_urls_reject_control_characters_and_spaces` |
| **4.18** | RO 面泄露 AI 密钥：`ai.models.list` 在 `ALLOWED_ACTIONS_RO`（免 sudo，0660 socket 直连），却用**请求体里的 `baseUrl`** 决定目标，并把配置中的 `apiKey` 作为 `Bearer` 发过去 | ① `models_list(&self, _data)` **整体忽略请求体**；② `actions.rs` 把该动作从 **RO 移到 RW**；③ `contract.rs` 注明 GET/POST 都必须经特权路由 | `models_list_sends_a_bearer_token_and_the_documented_headers`、`model_listing_is_confined_to_the_privileged_channel` |

> **有意偏离（已登记）**：4.16 的修法让 `http://` 端点在**任何**配置下都被拒
> （原先 `allow_private` 时放行 http）。因此**自托管本地模型**
> （`http://127.0.0.1:11434` 之类）不再可用。这是收紧不是放宽，
> 但确实砍掉了一条合法用法 —— 见 `HANDOVER.md` §8.2。

---

## 3C. 批 5（Web 与队列）：§5.2 的 19 条中 17 条已修

### 3C.1 Web 面（5.1–5.8）

| # | 原缺陷 | 修法 | 反例测试 |
|---|---|---|---|
| **5.1** | `API_BODY_LIMIT_BYTES = 256KB` **定义了但从未被引用** | 两道防线：`DefaultBodyLimit`（限制实际读取量，覆盖分块）+ `reject_oversized_bodies` 中间件（按 `Content-Length` 在进处理器前回 413） | `an_oversized_request_body_is_rejected_before_it_is_buffered`、`an_oversized_body_is_rejected_even_for_an_authenticated_request`、`a_chunked_oversized_body_is_still_refused`、`a_body_just_under_the_limit_is_still_accepted_by_the_transport` |
| **5.2** | 登录 `config.username == username && verify_password(..)` **短路** → 用户名枚举预言机 | 拆成两个独立布尔再合并，PBKDF2 无条件执行 | `a_wrong_username_costs_the_same_as_a_wrong_password`（耗时对比） |
| **5.3** | PBKDF2（310k 次）同步跑在 async worker 上，全仓生产代码零 `spawn_blocking` | 搬进 `tokio::task::spawn_blocking` | `password_hashing_does_not_block_the_async_worker`（`worker_threads=1`，并发 1ms sleep 不得被顶住） |
| **5.4** | 助手不可达（503）也 `record_failure` → 基础设施抖动升级为管理员锁定 | 503 分支**不**记失败计数 | `an_unreachable_helper_does_not_count_towards_account_lockout`（连续 7 次 503 后仍不得锁定） |
| **5.5** | `touch().map(..).unwrap_or_default()` 交付**空 CSRF** 仍回 `200 {ok:true}`；`if let Ok(..)` 静默跳过 Set-Cookie | 新增 `create_session()` 一次返回 `(id, csrf)`，`unreachable` 分支消失；Cookie 构造失败 → 撤销会话 + 500 | `a_successful_login_never_yields_an_empty_csrf_or_a_missing_cookie`（8 轮，并验证 csrf 真能通过一次写操作校验）、`create_session_returns_a_usable_id_and_a_non_empty_csrf` |
| **5.6** | `AI_RATE_LIMIT_PER_MINUTE` 与 `is_ai_path` **无任何调用点** | 新增 `AiRateLimiter`（有界表 + 无副作用判决），中间件挂在认证**之后**（避免未认证洪水耗尽共享出口的 AI 额度） | `the_ai_quota_is_enforced_and_scoped_per_source`、`a_rejected_ai_call_does_not_extend_its_own_window`、`the_ai_limiter_table_stays_bounded` |
| **5.7** | 时钟回拨使 `last_seen` 倒退 → 会话永不过期；`#[derive(Debug)]` 把 `id` 与 `csrf` 打进日志 | `last_seen` 钳为单调不减；手写 `Debug` 只输出指纹 | `a_clock_rollback_cannot_extend_a_session_past_its_ttl`、`debug_output_redacts_the_session_id_and_the_csrf_token` |
| **5.8** | `uptimeSec` 恒为 `0`（注释「Phase 1 尚未接线」）→ **谎报** | `OnceLock<Instant>` 钉住进程启动时刻，输出真实秒数 | `health_reports_a_monotonically_growing_uptime_instead_of_a_constant_zero`（间隔 1.1s 两次调用必须递增） |

### 3C.2 队列面（5.9 / 5.11 / 5.12 / 5.13 / 5.14 / 5.15 / 5.16 / 5.17）

| # | 原缺陷 | 修法 | 反例测试 |
|---|---|---|---|
| **5.9** | `run_once` 无重入保护，两轮重叠各投一遍 | `AtomicBool` + `compare_exchange`，冲突返回新的 `QueueError::Busy`；`RoundGuard`（`Drop`）保证任何提前返回都复位 | `overlapping_rounds_are_refused_instead_of_double_delivering` |
| **5.11** | 5xx 永久失败也累加「出站连续失败」→ 正常退信把整条出站判成「25 被封」 | `record_remote_failure` 只接受 `FailureClass::Transient` | `permanent_failures_never_trip_the_outbound_blocked_verdict`（12 次永久失败后计数仍为 0） |
| **5.12** | 回执照常只记 `accepted` 数却移除**全部**收件人 → 未被接受的静默丢信 | 在本地/远端两个 Ok 分支钉住 `receipt.accepted == attempted.len()`，不满足即报错而非静默移除 | 由既有 84 条队列测试覆盖（三条生产传输恒满足该不变量） |
| **5.13** | `rows()` 把 EACCES / IO 错 / 坏 UTF-8 一律塌缩成「空表」 | 新增 `atomic::try_rows()`（只把 `NotFound` 当空表）；`users.add` 的授权判据、`domains.list`、`snapshot`、`managed_domains`（DKIM/DNS）全部改用 `try_rows` 并如实报错 | 由 `crates/priv` 既有测试与编译期签名收敛覆盖 |
| **5.14** | MIME 边界由 `id + 失败数` 派生，**从不检查原邮件正文是否含同一串** | 128 位随机边界 + 显式冲突检测（撞上则加长到 256 位重取） | `mime_boundary_is_unpredictable_and_never_collides_with_the_original`（两次退信边界不同 + 正文预置候选必须避开） |
| **5.15** | 快速失败期间每 10 秒把**全部积压条目**原样重写磁盘 | `process` 增加 `mutated` 标记；未改动则不写回 | 由 `blocked_queue_fast_fails_instead_of_hammering` 覆盖 |
| **5.16** | `backlog`/`len()` 每 2 秒 `load_all()` 解析全部正文 | `len()` 只 stat 条目文件、不解析 | `len_counts_entry_files_without_parsing_them`（坏条目仍被计入，正是「没解析」的证据）、`len_ignores_non_entry_files` |
| **5.17** | DSN 写死 `Content-Transfer-Encoding: 8bit` | 文本部分恒 `7bit`（由我们生成、恒 ASCII）；`message/rfc822` 部分按原邮件实际字节选 `7bit`/`8bit` | `content_transfer_encoding_matches_the_actual_bytes` |

### 3C.3 守护进程（5.18 / 5.19）

| # | 原缺陷 | 修法 |
|---|---|---|
| **5.18** | `select!` 直接 return 时 `timeout(ROUND_TIMEOUT, run_once)` 的 future 被 **drop** → `ROUND_TIMEOUT` 从未生效，在途投递被取消（与 5.10 叠加产生重复投递） | 每轮 `spawn` 成独立任务；`select!` 丢弃的只是 `JoinHandle` 的等待权。停机时对句柄做**有界等待**（等满 `ROUND_TIMEOUT` 才放弃）。上一轮未结束时 ticker 到点也跳过 |
| **5.19** | 任一任务异常退出只打日志，最终永远 `Ok(())` → systemd 不重启，「进程活着但半个服务没了」 | `JoinSet<Result<(), String>>`；监听器/RPC 面/panic 全部作为失败汇总，非零返回新的 `DaemonError::Task` |

### 3C.4 投递租约（5.10）

原状：`runner.rs` 的「投递成功」与「把成功写下来」之间**没有任何 in-flight 标记**。
崩溃 / 掉电 / 停机取消之后，条目仍带全部收件人 → 下一轮**整批重投**，收件人收到重复邮件，
而运维看不出原因。

修法（两层）：

1. **租约文件**：`queue/claims/<id>.claim`，内容是取得时刻。开始投递前用
   `OpenOptions::create_new`（`O_EXCL`）创建 —— 不是 `exists()` 再写，
   否则判存在与建文件之间的空隙正是原竞态本身。结束后由 `ClaimGuard`（`Drop`）
   释放，因此正常返回、`?` 提前返回、任务 panic/取消都会释放。
2. **跳过与接管**：`run_once` 先把仍有效的租约对应的条目排除，并在 spawn 前
   `try_claim` 兜底；租约过期（`CLAIM_TTL_SECONDS = 900s`，必须大于
   `ROUND_TIMEOUT = 600s`）后可被接管。`remove()` 会一并清掉租约，避免孤儿文件。

**语义变化（要说清楚）**：崩溃后的在途条目不再「重启即刻重投」，而是
**先等至多一个 TTL 再重试** —— 重复投递从「必然发生」变成「只有在租约过期后
才可能发生」。真正的 exactly-once 需要把每个收件人的 ack 在事务中途落盘，
那是投递协议层重新设计，不在本项范围内。

反例测试：`an_entry_under_a_live_claim_is_skipped_and_delivered_after_expiry`
（被持有 → `considered=0` 且零投递；过期后 → 正常投递并释放租约）、
`a_claim_is_exclusive_until_released`、`an_expired_claim_can_be_taken_over`、
`claimed_ids_reflects_only_live_leases`、`removing_an_entry_releases_its_claim`、
`a_corrupt_claim_timestamp_falls_back_to_mtime_not_to_a_deadlock`。

**负向验证**：把「排除被租约持有的条目」与 `try_claim` 兜底**两道都去掉**后，
上面那条行为测试精确变红（`left: 1, right: 0`，断言文案「被租约持有的条目不应被处理」）。
---

## 3D. 管理前端 webui（§WEBUI_AUDIT 的 41 条）

前端由独立工作流完成，改动**全部限于 `webui/`**，与后端加固是两套账。
`npm run build`（tsc `--noEmit` + Vite）通过，`noUnusedLocals`/`noUnusedParameters` 已开启。

**关键验证（实测，非仅编译）**

| 项 | 结果 |
|---|---|
| 生产包硬编码 TOTP 密钥 `JBSWY3DPEHPK3PXP` | **NO MATCH** |
| `mock2fa` / `?mock=1` / `mock 口令 123456` | 均不存在（整块 mock 由 `import.meta.env.DEV` 门控并在生产被 DCE） |
| 无后端时 | 渲染「后端不可达」错误页 + 重试，**不再**进入控制台（H1 fail-closed） |
| `hidden!` 残留 | 只剩 `Settings.tsx:321`（有意隐藏 `<input type="file">`，审计明确要求保留） |

**逐条**（H1–H4 / M1–M9 / L1–L28）见该轮交付记录；其中三条需要接续者知道：

1. **H3 的修复方向被修正**：审计建议「由 `security.scan` 的 findings 推导 SPF/DMARC/DKIM」
   **不可行** —— 后端 `findings` 是文件系统审计项，与 DNS 无关。改用
   `dns.records`（`ok` 为该记录实查结果）+ `services.list`（fail2ban 活性）。
2. **M5 只能部分修**：后端 `session.rs` 确实没有 `current`/`ip`/`userAgent`，
   前端无法判断当前会话。已做到：不再依赖不存在字段、吊销后**重新拉取**真实列表
   （消除「谎报成功」）、UI 明示「吊销自身会话会立即登出」。
3. **M9 按删除处理**：「保持登录」在后端没有对应语义（只读 `username/password/code`，
   `Max-Age` 固定），任何「实现」都只能是假实现，故删控件并留注释。

---

## 4. 我**否掉**的报告结论（复核后未改代码）

审查报告本身也有误报。**逐条回源码核实**是必要步骤 —— 否则会把有意选择
当成 bug 改回去。

| 报告结论 | 我的复核结果 |
|---|---|
| `keys.rs:235` 的 `split_at` 可 panic | **不可达**。该函数有 `debug_assert!(value.is_ascii())` 兜底，且 DKIM 的 `p=` 恒为 base64（必 ASCII）。改它要动公开签名，**不划算**。 |
| `bind → chmod` 竞态可被本地用户利用（原判 HIGH） | **实际风险低**。`REVIEW-SCORECARD` 已实测：umask 022 下非 root `connect` 被 **EACCES 拒绝**，仅 umask 0 时窗口可利用。且修法要动部署层。接受其「降级为 Low」的裁决，本轮不改。 |
| 「审计链零写入」（原判 High/Critical） | **收窄为迁移就绪度问题**。Python 助手（`core.py:172-192`）**有同一套哈希链**且在生产写入，Rust `readers.rs` 读取并校验的就是它。真实缺口只是「Rust 的动作执行路径不调用 `audit()`」—— 那是**切换助手之后**才会暴露的就绪度问题，不是「当前生产无审计」。 |
| `relay.test` 应改为 `setup.relay.test`（子代理结论） | **否决**。`restCall` 按动作名查 `REST` 表，而 `relay.test` 就在表里（映射到 `/api/setup/relay/test`），**本来就能通**。已改回并把注释写成「保持与映射表键一致」。 |

> 报告里还有大量 Medium/Low（约 40 + 35 条），其中一部分是**真问题但未修**
> （见 §5），一部分是「纵深防御建议」而非缺陷。**接续者请按 §5 的清单逐条判断，
> 不要照单全收。**

---

## 5. ⏳ 未修项清单（已证实存在，尚未修复）

> **这些不是猜测。** 每一条都在至少一份报告里给出 `文件:行号` 证据，
> 其中若干被实测复现。按子系统分组，标注影响与建议修法。

### 5.1 批 4：特权与密码学（`crates/core` / `crates/priv`）

> ✅ **批 4 已于提交 `1ff8a7b` 全部修复**，逐条记录见 **§3B**。
> 下表原 18 行已被取代，此处只留口径：
>
> - **4.1–4.18：已修**（含配套改动：store 错误分流、readers 的 runner 超时兜底、
>   `smtp::is_private_network_address` 新导出、RO→RW 迁移带来的 `ALLOWED_ACTIONS_RO`
>   22→21 与契约表注释更新）。
> - **部分修需要特别注意**：`5.13` 与 4.2 是同一个文件的两个面。批 4 只修了
>   `store/tables.rs` 的**变更路径**（新增 `read_rows_for_update`，读失败不再
>   当成空表）；**读面未修** —— `core::atomic::rows()` 至今仍把 EACCES / IO 错 /
>   坏 UTF-8 一律塌缩成「空表」，且仍有 4 个生产调用点
>   （`priv/handlers.rs:480`、`priv/readers.rs:719`、`priv/readers.rs:2457`、
>   `priv/users.rs:573`）。**这条仍算未修**，只是危险面从「一次读错误清空整张路由表」
>   收窄到了「静默显示为空」。接续者若要彻底关掉它，需要给 `rows()` 加一个
>   `Result` 版本并逐个改调用点 —— 会波及 RO 动作的返回形状，属于独立一轮。
>
> 批 4 修复过程中新登记的两条，见 §3B.4 与 §3B.6 的「有意偏离」两段。

### 5.2 批 5：Web 与队列

> ✅ **批 5 已全部修复（19/19）**，逐条记录见 **§3C**。
>
> - **5.1–5.19：已修**（含配套改动：新增 `AiRateLimiter`、
>   `atomic::try_rows`、`QueueError::Busy` / `is_busy()`、`DaemonError::Task`）。
> - **5.10 投递 lease**：`claims/<id>.claim` + `O_EXCL` 认领 + TTL 接管，详见 §3C.4。（原计划说明：
>   `load_all` 语义，需要独立的崩溃恢复回归面。**5.18 已把它从「必然发生」
>   降为「崩溃窗口内才发生」**，但窗口仍在。详见 §3C.4。
>
> 下表是原始清单（保留作对照，状态以本节说明为准）：

| # | 位置 | 缺陷 | 影响 |
|---|---|---|---|
| 5.1 | `web/lib.rs:47 / 392-396` | `API_BODY_LIMIT_BYTES = 256KB` 定义了但**从未启用**（无 `RequestBodyLimitLayer`） | 叠加 `panic = "abort"` → 单请求即可打死控制台进程。模块头注释（INV-12）与实现不符 |
| 5.2 | `web/routes.rs:214` | `config.username == username && verify_password(..)` **短路** | 用户名错误时不跑 310k 次 PBKDF2，**响应快几个数量级 → 用户名枚举预言机**，正好击穿 INV-23 同形错误体的用意 |
| 5.3 | `web/routes.rs:206` + 全仓 | **未认证的登录处理器在 async worker 上同步跑 310k 次 HMAC-PBKDF2**，且 `spawn_blocking` 在全仓生产代码中**一次都没出现** | mailstackd 单进程同时承载 25/465/587 + 出站队列 + RO/RW 面 → **阻塞会直接饿死收信与投递** |
| 5.4 | `web/routes.rs:255` | 助手不可达（503）也 `record_failure` | 基础设施抖动**升级为管理员锁定** |
| 5.5 | `web/routes.rs:265-286` | `touch().unwrap_or_default()` 与 `if let Ok(value) = HeaderValue::from_str(&cookie)` | 可能返回 `200 {ok:true}` 却**既无可用 CSRF token 也无 Set-Cookie**（静默假成功） |
| 5.6 | `web/contract.rs:271-289` | `AI_RATE_LIMIT_PER_MINUTE` 与 `is_ai_path` **无任何调用点** | AI 路由的「独立限流 20 次/分」是**死代码**，出站付费 LLM 调用可被单点刷爆 |
| 5.7 | `web/session.rs:115` | 时钟回拨使 `last_seen` 倒退 → 会话在时间恢复前**永不过期** | 另：`:30` 的 `#[derive(Debug)]` 会把 `id` 与 `csrf` 一起打印进日志（与「绝不暴露 ID」的约定冲突） |
| 5.8 | `web/lib.rs:193` | `uptimeSec` 恒为 0 | **谎报**，而非 `unavailable`（违反本项目的「诚实可观测」原则） |
| 5.9 | `queue/runner.rs:234` | `run_once` **无重入保护**：两轮重叠会 `load_all` 同一批条目 → **重复投递**，并各自重置 `half_open_used` | store 侧没有 per-entry claim 标志；安全性依赖调用方（daemon）串行化 |
| 5.10 | `queue/runner.rs:311-389` | 投递成功与「把成功写下来」之间**无 lease / in-flight 标记** | 崩溃 / 掉电 / 停机取消后条目仍带全部收件人 → **整批重投、收件人收到重复邮件**。`bin/mailstackd/src/queue.rs:117` 明确会在超时时 drop 在途任务。**零测试覆盖投递原子性** |
| 5.11 | `queue/runner.rs:525-530` | **5xx 永久失败也累加「出站连续失败」** | 10 封收件人不存在的正常退信就会把整条出站链路判为「25 被封」，转入快速失败并**停止全部外域投递** —— 自造全站故障 |
| 5.12 | `queue/runner.rs:380,355` | 投递成功但 `store.remove/enqueue` 失败 → 下轮重投；回执照常只记 `accepted` 数却移除**全部**收件人 | 未被接受的收件人**静默丢信** |
| 5.13 | `store/tables.rs:259` + `atomic.rs:270` | `rows()` 把 EACCES / IO 错 / 坏 UTF-8 **一律塌缩成「空表」** | `add_domain` 是 read→filter→write：**一次读错误就清空整张 Postfix 路由表**（且违背「读不到要如实说」） |
| 5.14 | `queue/dsn.rs:65-72` | MIME 边界由 `id + 失败数` 决定，**从不检查原邮件正文是否含同一串** | 发件人可在退信里**注入任意 MIME 部件**（以「Mail Delivery System」身份呈现）。应改用随机边界 |
| 5.15 | `queue/runner.rs:373-387` | 快速失败期间每 10 秒把**所有积压条目全量重写一遍磁盘**（内容完全没变） | 出站被封时积压最大、I/O 压力也最大 |
| 5.16 | `queue/store.rs:168-174` | `backlog` / `len()` 每 2 秒全量 `load_all()` 解析全部邮件正文 | 千条积压时每 2 秒数百 MB 解析开销，**阻塞 tokio worker** |
| 5.17 | `queue/dsn.rs:100` | DSN 写死 `Content-Transfer-Encoding: 8bit` 且不做 8BITMIME 协商 | 对只通告 7BIT 的 MX 是 RFC 违规，可能被拒或静默改写正文（破坏 DKIM） |
| 5.18 | `bin/mailstackd/src/queue.rs:96-121` | 收到停机信号时 `select!` 直接 return，`timeout(ROUND_TIMEOUT, run_once(..))` 的 future 被 **drop** | `ROUND_TIMEOUT = 600s`（注释称「保证停机不会被在途投递卡死」）**从未生效**，在途投递被取消 → 与 5.10 叠加产生重复投递 |
| 5.19 | `bin/mailstackd/src/lib.rs:92-124` | 任一监听/RPC/队列任务异常退出都只打日志，最终**永远返回 `Ok(())`** | systemd 不重启，表现为「进程活着但半个服务没了」且退出码看不出来 |

### 5.3 批 6：工程化（CI / deploy / 架构）

> ✅ **批 6 已全部修复（16/16）**；6.16 早在批 3 修完。
>
> | # | 修法 | 反例 / 验证 |
> |---|---|---|
> | **6.1** | 新增 `deny.toml`（漏洞/许可/通配/来源四类检查）；`cargo-deny` 去掉 `continue-on-error`；`cargo audit` 去掉两处 `|| true` | **已用 cargo-deny 0.20.2 对真实依赖树实跑通过**（advisories/bans/licenses/sources 全 ok），并据此修掉 **7 条 RUSTSEC 漏洞**、收窄白名单 15→11、修正 4 处 0.20 已移除的配置键。详见 §5.4 |
> | **6.2** | 门禁从 `grep -rq "fn $name"` 升级为三项校验：函数存在 + **带 `#[test]`/`#[tokio::test]`** + 函数体内**至少一个断言** | 负例实测：普通函数名 → `NOT_TEST`；测试掏空成空壳 → `NO_ASSERT`，两次都正确变红 |
> | **6.3** | 四个 action 全部 pin 到 **40 位 commit SHA**；workflow 级 `permissions: contents: read`；三处 checkout 加 `persist-credentials: false` | 逐个核验 SHA 为 commit 对象（rust-cache v2=2.9.3 PGP 已验证；cargo-deny-action v2=2.1.1 **unsigned**，故 SHA 是唯一完整性依据）；`dtolnay` 的 tag 名即工具链选择器，改为 pin master commit + `with.toolchain: 1.98.1` |
> | **6.4** | `wsl-install-rust.sh`：`mktemp -d` 私有目录（0700、不可预测）替代可预测的 `/tmp/rustup-init.sh`；支持 `MAILSTACK_RUSTUP_SHA256` 显式钉扎；升为 `set -euo pipefail` | `bash -n` 校验；未设哈希时**明确告警**「仅依赖 HTTPS，未做独立钉扎」而非假装安全 |
> | **6.5** | 23 个脚本按用途分级：门禁/安装/清理类 → `set -euo pipefail`；探查/诊断类 → `set -uo pipefail`（某条探测失败是预期内的，不能中断） | `bash -n` 全绿；两道门禁在 `set -eo pipefail` 下仍通过 |
> | **6.6** | `build.sh` 的 `BINS` 补上 `mailstack-web`；判定从 `FOUND -gt 0`（任一产物存在即通过）改为**逐个齐全**，缺一个就 `die` | 产物清单 / SHA256SUMS / SBOM 不再随发布包缺项 |
> | **6.7** | 6 处硬编码 `/mnt/e/MailStack/mailstack-rust` 全部改为脚本相对路径；代理改为 `${MAILSTACK_PROXY:-...}` | `deploy/` 下 `grep /mnt/e/MailStack` **零命中** |
> | **6.8** | 277 条清单抽到 `deploy/required-invariants.txt`（唯一数据源），CI 直接调用共享脚本，内联拷贝删除 | python 校验器断言「CI 里不得再出现 `required=(`」 |
> | **6.9** | `panic = "abort"` → **`unwind`**，并把两处依赖写进 Cargo.toml 注释：① `warn()` 的 `catch_unwind` 只在 unwind 下有效；② **必须**配合 5.19 的非零退出，否则任务 panic 会被 tokio 吞掉变成静默停投 | 注明「若把 5.19 的结果汇总改回只记日志，必须同时改回 abort」 |
> | **6.10–6.15** | 见 §3B.6 与上一轮记录（审计链严格读尾、fsync、`enabled` 整串匹配、settings patch 静默丢弃、DMARC 信封域清洗、TOTP 主密钥竞态） | 各自配反例测试 |
>
> 下表是原始清单（保留作对照）：

| # | 位置 | 缺陷 | 影响 |
|---|---|---|---|
| 6.1 | `.github/workflows/ci.yml:52-58` | `cargo-deny` 用 `continue-on-error: true`，且仓库中**根本不存在 `deny.toml`**（该 step 必然失败，永远被吞掉）；`cargo audit \|\| true` | **供应链门禁实质失效**，有 RUSTSEC 通告也不拦 |
| 6.2 | `.github/workflows/ci.yml:501-507` | 不变量门禁只 `grep -rq "fn $name"` —— **子串匹配、不要求 `#[test]`** | 把某个不变量测试的函数体改成 `assert!(true)`，门禁依然 OK。**门禁本意正是「防有人掏空断言」** |
| 6.3 | `ci.yml` 全体 | 所有 action **只 pin 到 tag** 未 pin SHA；三个 job 无 `permissions:` 声明；`checkout` 未设 `persist-credentials: false` | 供应链与最小权限 |
| 6.4 | `deploy/wsl-install-rust.sh:42-44` | `curl → sh` 下载 rustup **无 SHA256/签名校验**，且落盘到**可预测的 `/tmp/rustup-init.sh`**（/tmp 竞态提权）；该文件只有 `set -u` | 供应链 |
| 6.5 | `deploy/*.sh` 多数 | 缺 `set -e` / `pipefail`（只有 3 个有，且其中 2 个仍缺 `-e`） | 中间步骤失败被静默吞掉 |
| 6.6 | `deploy/build.sh:77-88` | `BINS=(mailstackd mailstackctl)` **漏了 `mailstack-web`**，而 workspace 明确包含它；且 `FOUND > 0` 的宽松判定使构建照样成功 | 产物清单 / SHA256SUMS / SBOM **随之为发布包缺项** |
| 6.7 | `deploy/*.sh` | 硬编码开发机路径 `/mnt/e/MailStack/mailstack-rust` 与代理 `http://127.0.0.1:7890` | 这些是「开发机一次性脚本」而非可交付部署资产 |
| 6.8 | `deploy/verify-invariant-gate.sh` vs `ci.yml` | 同一逻辑的**两份拷贝** | 必然漂移 |
| 6.9 | `Cargo.toml:68` | `panic = "abort"` 把每个 panic 放大成进程死亡，并让 `core/warn.rs` 的 `catch_unwind` 在 release 下**完全无效** | 需重评估为「unwind + 顶层 catch + 任务重启」，见 §1.10 |
| 6.10 | `core/audit.rs:190` | `read_last_audit_hash(..).unwrap_or_else(\|\| AUDIT_GENESIS)` —— 读尾失败（被 truncate、权限错误）时**静默从创世值重开一条链** | 把故障伪装成新链。应区分「文件为空」与「读不出来」 |
| 6.11 | `core/audit.rs:207-220` | 追加日志与写 `.head` 锚之间无原子性；`write_all` 后**无 `sync_all`** | 掉电产生「假篡改告警」 |
| 6.12 | `core/totp.rs:154-164` | 主密钥「存在性检查 → 生成 → 写」**竞态**，两个并发 `begin()` 会各自生成密钥并覆盖写（`atomic_as` 用 `File::create` 非 `O_EXCL`） | 先写者封装的信封**永久解不开**，管理员被锁在 2FA 之外 |
| 6.13 | `core/mode.rs:77` | `enabled` 键用 `starts_with("enabled")` **前缀匹配** | `enabledx=1` 也会开关注 |
| 6.14 | `core/config.rs:118-121` | `apply_settings_patch` 中 `if let Ok(updated) = from_value::<Settings>(current)` —— 任一键值类型不匹配就**整包静默丢弃且不 warn**，但 `applied` 仍把键名列成「已应用」 | **API 说成功、磁盘没变** |
| 6.15 | `auth/dmarc.rs:102` | `rfc5321_mail_from_domain` 用裸 `rsplit_once('@')` **不清洗**（对比 `dkim::from_domain` 会剥离 `>`/空白并小写） | 若上游传入括号包裹的地址，DMARC 对齐比较会被污染（`example.com>`） |
| 6.16 | `auth/dmarc.rs:126-134` | `spf_aligned()` / `dkim_aligned()` 名字叫 aligned 却**不做对齐检查** | ✅ **已在批 3 修复**（改名 `_pass`） |

> **NAT64 / `2000::/3` 白名单**已列入批 2 修复（§2.4）。
> **`tables.rs` 的 RMW 无锁**属 4.2 与 5.13，是同一个文件的两个面。

---

## 5.4 供应链门禁的**实地验证**（2026-10-30，提交 `289afdf`）

> 上一轮把 `cargo-deny` 从「被 `continue-on-error` 吞掉」改成强制，但**没有本地跑过**。
> 这一轮用官方 **0.20.2** 预编译二进制（SHA256 与发布值一致：
> `9f12ed4c…824c8d5f`）对**真实依赖树**实跑 `cargo deny check`。
> 结论：原配置**根本跑不起来**，而且树里有 **7 条真实漏洞**。

### 5.4.1 修掉的 7 条 RUSTSEC 漏洞

| 通告 | crate | 问题 | 处理 |
|---|---|---|---|
| RUSTSEC-2026-0346 | rustls | `Debug` 实现把客户端会话值（含 TLS secrets）打出来 | 0.23.45 → **0.23.46** |
| RUSTSEC-2026-0347 | rustls | ECH 被拒后仍把缓冲的应用数据发给外层服务器 | 同上 |
| RUSTSEC-2026-0348 | rustls | Brotli 证书解压可在**认证前**分配最多 1 GiB | 同上 |
| RUSTSEC-2026-0349 | rustls | 未认证的 ServerHello 可把后续连接降级到经典密钥交换 | 同上 |
| RUSTSEC-2026-0382 | rustls-webpki | 证书校验可能接受已被 distrust 的中间证书 | 0.103.15 → **0.103.16** |
| RUSTSEC-2026-0386 | tokio（unsound） | `AsyncFd::new` 等构造器违反 I/O safety | 1.53.1 → **1.54.1** |
| RUSTSEC-2026-0381 | webpki-roots | 内置根证书仍信任已被 distrust 的 emSign 中间证书 | 1.0.9 → **1.0.11** |

**唯一保留的 ignore**：`RUSTSEC-2023-0071`（`rsa 0.9.10`，Marvin Attack）——
**没有安全升级可用**。该通告针对 RSA **解密**路径的时序侧信道；本项目 rsa 只经
`mail-auth` 用于 DKIM **签名**，不存在「投喂密文给解密预言机」的路径。
理由写在 `deny.toml` 的 `ignore` 条目里；上游出修复版时
`unused-ignored-advisory = "warn"` 会提醒我们删掉它。

### 5.4.2 原 `deny.toml` 里 4 处「照旧版文档写就会红」的配置

| 问题 | 实情（0.20） |
|---|---|
| `advisories.vulnerability = "deny"` | **键已移除**。0.20 起漏洞通告一律报错 |
| `advisories.notice = "warn"`、`severity-threshold` | **已移除**，notice 一律报错 |
| `licenses.unlicensed = "deny"` | **已移除**；未声明许可证本来必然失败 |
| `advisories.unmaintained = "warn"` | 它是**作用域**枚举（`all`/`workspace`/`transitive`/`none`），不是级别 |

这些不会报「配置有问题」以外的东西 —— 但会让 CI **红在配置解析**，
而不是红在「真的有问题」，等于门禁又换了一种失效方式。

### 5.4.3 自有 crate 的许可证与通配依赖

- **11 个 workspace crate 被判 `unlicensed`**：本仓库用
  `license = "SEE LICENSE IN LICENSE"`（Cargo 合法、**非 SPDX**）。
  修法是如实声明它们不对外发布 —— `[workspace.package] publish = false`
  + 每个 crate `publish.workspace = true`，再配 `[licenses] private = { ignore = true }`。
  **这不是放行外部依赖**：外部 crate 的许可证仍逐条按白名单校验。
- **`wildcards = "deny"` 把内部 path 依赖全部误报**：workspace 里
  `mailstack-core = { path = "crates/core" }` 被 `.workspace = true` 继承后没有版本
  要求，cargo-deny 看到的就是 `*`。加 `allow-wildcard-paths = true` ——
  路径依赖放行，其余通配仍然拒绝。
- **许可白名单从 15 收窄到 11**：按实跑输出删掉从未出现的
  `CC0-1.0` / `MPL-2.0` / `OpenSSL` / `Unicode-DFS-2016`。
  原列表是从本机 registry 449 个 crate 归纳的偏宽集合。

### 5.4.4 磁盘：增量编译曾把根分区撑满

依赖升级触发的全量重建让 `target/debug/incremental` 涨到 **3.3G**，
9.8G 根分区被撑满，报错是 `No space left on device (os error 28)` ——
同样属于「报错不指向真因」。`deploy/wsl-cargo.sh` 现在默认
`CARGO_INCREMENTAL=0`（可显式覆盖为 1）。

### 5.4.5 最终结果

```
$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok        # 退出码 0
```

依赖升级后的全量回归：`QUALITY_GATE=PASS`（1145 passed / 0 failed）、
`INVARIANT_GATE_OK`（277）、`DELIVERABLES_OK`。

---

## 6. 过程留痕（诚实记录）

### 6.1 子代理中断事故

批 2 的两个子任务由一个 `general_purpose_task` 子代理执行
（RCPT 名录 + A-R 注入；TOTP 重放 + `totp.disable` + `revoke_user` + Cookie）。

**它在返回前中断** —— 只回了一句话：「Now update the router to use these handlers, and build:」。
留下三处**半成品**：

1. `crates/web/src/routes.rs` 里 `clear_session_cookie` **重复定义**（两份实现并存）。
   更要命的是：**被弃的那份用了 `unwrap_or_default()`** —— 正是新版刻意修掉的 bug
   （空用户名 → 吊销不到任何人，恰好「踢光别人、留下自己」）。
2. 六处调用点缺 `&`（`admin_username(state)` 应为 `&state`），编译不过。
3. 两个测试仍在用**旧的 cookie 名**（`mailstack_session` vs `__Host-mailstack_session`）。

**这些由我手工收拾完毕**，并补了两条测试：
`session_cookie_parsing_requires_the_host_prefix`（旧名不得再被接受）、
以及把登录测试的 cookie 断言改成读 `SESSION_COOKIE` 常量。

**教训**：子代理产出的**核心逻辑可用**（TOTP 重放的三条关键设计、
RCPT 名录的三态判定、A-R 的 RFC 8601 引用 —— 我逐条复核过，质量好），
但**它的收尾不可信**。这正是「trust but verify」的实例：
**必须读实际改动，而不是读它的汇报**。

### 6.2 我自己的错（两次）

1. **限流修复第一次改坏了计数**：我把 `entry().or_insert_with(..)` 换成 `get_mut`，
   导致**首次出现的键永远不会被建立计数器** —— 计数静默停止。
   6 个既有测试当场变红（`five_failures_lock_the_account` 等），修回。
2. **`iterations` 测试断言方向写反**：以为降级后「正确口令应当失败」，
   实际 `max()` 生效后正确口令**应该通过**。测试变红才发现理解反了（见 §1.4 的 ⚠️）。

**两次都是既有测试/新测试当场抓住的** —— 这是「反例测试必须有」的最直接证据。

### 6.3 环境陷阱（接手前值得知道）

| 陷阱 | 实情 |
|---|---|
| WSL 的 `/tmp` **每次 `wsl` 命令启动时被清** | 实测：建标记后下一条独立 wsl 命令读已是 No such file。夹具必须放 `/root`，且生成与消费**合并进同一条命令** |
| 本机 `core.autocrlf=true` 是**系统级** | `git config --system --get core.autocrlf` → true。`.gitattributes` 是必需的，否则 `deploy/*.sh` 与 CI YAML 被转 CRLF 会让**门禁脚本与 CI 静默失效** |
| PowerShell 陷阱 | `git commit -F "<多行字符串>"` 把整段当**文件名**；管道 `\| tail` 报 `CommandNotFound`；`wsl -e sh -c "嵌套引号"` 被吞；`2>/dev/null` 被当路径 |
| `beta.10` 路径有**两层**同名嵌套 | 写成单层会**静默查不到文件**（`Get-ChildItem` 不报错，只列不出内容） |
| 磁盘 | WSL 根分区仅 9.8G。满了跑仓库自带的 `deploy/wsl-reclaim-space.sh`（只清 apt 缓存 + 可再生的 incremental，**不碰** `/root/.cargo/registry/cache`） |

---

## 7. 验证方式（接续者复现用）

```bash
# 全部在 WSL 内跑（生产目标平台是 Linux）
W='wsl -d Ubuntu -e env HOME=/root CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0'
R=/mnt/e/MailStack/mailstack-rust

# 1) 全量测试（应为 1145 passed / 0 failed）
$W bash $R/deploy/wsl-cargo.sh test --workspace --all-targets

# 2) 三道门禁
$W bash $R/deploy/wsl-quality-gate.sh          # → QUALITY_GATE=PASS
$W bash $R/deploy/verify-invariant-gate.sh     # → INVARIANT_GATE_OK（277/277）
$W bash $R/deploy/verify-deliverables.sh       # → DELIVERABLES_OK
```

**当前状态（2026-10-05，提交 `1ff8a7b` 之后）**：三道门禁全过，工作区干净，
`main` 分支 11 个提交、**无远端**。

> ⚠️ **复现环境已变更（2026-10-05）**：原 `Ubuntu` 发行版的 `ext4.vhdx` 被 EFS
> 「Application Protected」加密（`cipher /c` 显示 `Compatibility Level: Application Protected`，
> 而另外 7 个发行版的 vhdx 都是普通 `Archive`）。WSL 服务无法解密该卷，
> 每次启动都**只读回退**，根分区只剩 952M —— 上面三条命令在 Ubuntu 下**跑不起来**。
>
> 现改用 **`Debian` 发行版**复现（同样在 WSL2 内、同样是 Linux 目标平台）：
>
> ```powershell
> # 一次性准备
> wsl -d Debian -e bash -lc "apt-get install -y pkg-config libssl-dev; curl -sSf -x http://127.0.0.1:7890 https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path"
> wsl -d Debian -e bash -lc "export PATH=\$HOME/.cargo/bin:\$PATH; rustup component add clippy rustfmt"
>
> # 跑门禁（必须带代理，否则 cargo 会卡在 crates.io index 更新）
> wsl -d Debian -e bash -lc "export MAILSTACK_USE_PROXY=1 HTTP_PROXY=http://127.0.0.1:7890 HTTPS_PROXY=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 https_proxy=http://127.0.0.1:7890 NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1; bash /mnt/e/MailStack/mailstack-rust/deploy/wsl-quality-gate.sh"
> ```
>
> 两个必须知道的坑：**①** `MAILSTACK_USE_PROXY=1` 不设的话 cargo 会在
> 「Updating crates.io index」上静默挂几十分钟（`retry = 3` × 每次 10s 超时 ×
> 几百个 index 条目）；**②** `--profile minimal` 装的 rustup **不含 clippy/rustfmt**，
> 门禁会报 `'cargo-clippy' is not installed` 并计为 FAIL。

---

## 8. 一句话交接

> 前四批已修完并提交（1018 → **1111** 测试，全部带反例守卫）：
> 批 1–3 是「审查报告独立收敛的 P0」+「出站侧 + 认证授权」，
> 批 4 是**特权与密码学**（`1ff8a7b`，§5.1 的 18 条全修，逐条记录见 **§3B**）。
> 剩下 **批 5（Web 与队列，19 条）与批 6（工程化，16 条）的清单在 §5** ——
> 其中 5.1 / 5.2 / 5.3 是真正会打死线上的（请求体无上限、用户名枚举预言机、
> PBKDF2 阻塞 async worker），但**每条都必须配一个能真正失败的反例测试**，
> 否则就是重复审查报告批评的那个错误。
>
> 修代码之前先读 §4（我否掉了哪些结论）与 `HANDOVER.md` §8.2（有意偏离），
> **别把有意选择当成 bug 改回去**。

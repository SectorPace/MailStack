# imappop3 集成说明（替代 Dovecot 的协议面）

- 日期：2026-10-31
- 涉及 crate：`crates/imappop3`（自研协议面）、`crates/imapd`（新增装配层）、
  `bin/mailstack-imap`（新增二进制）、`crates/core`（新增口令记录库）
- 验收：`cargo test` 全绿，含 6 个多用户端到端测试（真实 TCP + 真实 Maildir）

---

## 1. 总体结构

```
                     ┌──────────────────────────────────────────┐
mailstack-imap ──►   │ crates/imapd                             │
(143/993/110/995)    │  directory.rs ── mailbox-passwords.json  │──► AuthBackend
                     │  resolver.rs  ── /etc/passwd + ~/Maildir │──► MailboxResolver
                     │  servers.rs   ── Let's Encrypt 证书      │──► TlsAcceptor
                     └───────────────┬──────────────────────────┘
                                     ▼
                          crates/imappop3（协议面）
                     IMAP4rev1 / POP3 / LMTP / ManageSieve
```

`crates/imapd` 只做"接线路由"：不实现协议、不解析 Maildir、不做加密。
协议与存储都在 `imappop3` 里，可以独立测试。

---

## 2. 对 `crates/imappop3` 的改动（4 处，都不改单用户行为）

### 2.1 认证成功后按登录名切换邮箱（**关键**）

**问题**：原实现里 `ImapServer` / `Pop3Server` 把**同一个** `Context` 克隆给所有
连接，而 `Context` 只持有一个 `MailStore`。也就是说一个监听器只能服务一个邮箱，
多账号部署根本没法用 —— 但 `lib.rs` 的架构图写的是
`mailstackd ──► imappop3::imap (143/993)`。

**改法**：`ImapSessionContext` / `Pop3SessionContext` 的 `resolver` 字段从
"只给共享邮箱用"扩展为"认证后解析本人邮箱"：

```rust
// crates/imappop3/src/imap/session.rs, AuthOutcome::Success 分支
if let Some(resolver) = self.ctx.resolver.as_ref() {
    let Some(store) = resolver.resolve(&user) else {
        // 口令对但邮箱没开：拒绝，绝不退回 ctx.store
        return self.no_code(tag, "UNAVAILABLE", "mailbox is not provisioned").await;
    };
    self.store = Arc::clone(&store);
    self.own_store = store;   // 供 deselect_to_personal 还原
}
```

* **不声明 `resolver` 时行为完全不变**（`self.store == ctx.store`），
  既有的单用户测试与共享邮箱测试全部照旧通过（162 单测 + 29 e2e）。
* 新增 `own_store` 字段：从共享邮箱 `UNSELECT` 回来时还原**本人**邮箱，
  而不是 `ctx.store`（多用户下 `ctx.store` 只是占位）。
* 命令处理里 12 处 `Arc::clone(&self.ctx.store)` 改为 `self.store` —— 原先
  这些地方绕过了会话自己的 store，即使切过去也读不到本人邮箱。

### 2.2 `Pop3SessionContext` 加 `resolver` 字段

POP3 与 IMAP 同一语义。`derive(Clone)` 是为多个监听口（110/995）各持一份上下文。

### 2.3 `TlsAcceptor` 改为公开重导出

`tls::acceptor()` 的返回类型出现在公共 API 上，部署层要跨多个监听器共享同一个
acceptor 就必须能命名它。原先是私有 `use tokio_rustls::TlsAcceptor;`。

### 2.4 `ImapSessionContext` 加 `derive(Clone)`

同上：143 与 993 各需要一份上下文。

---

## 3. 口令来源：为什么不用 `/etc/shadow`

MailStack 的账号口令一直走 `chpasswd`（PAM/系统口令）。协议面若继续读
`/etc/shadow`，要在纯 Rust 里实现 yescrypt / `$6$` / `$2b$` 多套 crypt 算法，
而且**违反正本仓库 INV-37**（「PBKDF2-SHA256 记录是口令的唯一真相源」）。

因此新增 `crates/core/src/mailbox_passwords.rs`：

* 文件 `/etc/mailstack/mailbox-passwords.json`，`0600 root:root`；
* 键是**小写邮箱地址**，值是既有的 `PasswordRecord`（复用它做常量时间校验）；
* 缺失文件 = 空库；**损坏/版本不符 = 错误**，绝不当作空库（否则一次截断会让
  所有邮箱"查不到口令"，排障方向被误导到认证逻辑）；
* 读改写全程持 `atomic::locked` 文件锁 + 临时文件 rename，并发写不丢记录。

`users.create` / `users.password` 现在**并写**系统口令与这条记录；写失败会
如实报错（不允许"系统口令改了、IMAP 还是旧口令"）。`users.delete` 连带删记录。

---

## 4. 邮箱布局

`crates/store` 已定死：**账号就是系统账号，Maildir = `<家目录>/Maildir`**
（Dovecot 侧 `mail_location = maildir:~/Maildir`）。`resolver.rs` 只解析
`/etc/passwd` 拿家目录，不猜 `<vmail>/<domain>/<user>`（`mailtest` 的令牌探测会
并列试多个候选，那是只读兼容探测，不能当成写入布局）。

登录名 → unix 账号名：取 `@` 之前的部分（与 `users.create` 的建号规则一致）。
解析不到账号或家目录不存在 → 拒绝登录，**不会凭空造 Maildir**。

---

## 5. 验收测试

`crates/imapd/tests/multi_user.rs`（6 个，真实 TCP + 真实 Maildir）：

| 测试 | 断言 |
|---|---|
| `two_accounts_on_one_listener_each_see_their_own_maildir` | 一个监听器、两个账号，各自 FETCH 到自己的信，且看不到对方的 |
| `a_wrong_password_is_rejected` | 错口令 → `NO`/`BAD` |
| `an_account_without_a_mailbox_is_refused_rather_than_served_the_default_one` | 口令对但无 passwd 账号 → 拒绝（**不退回默认邮箱**） |
| `a_fresh_account_gets_an_empty_inbox_created` | 首次 SELECT 自动建出 Maildir 结构 |
| `the_resolver_resolves_the_maildir_that_actually_has_the_message` | 解析器指向的目录里确实有那封信（把失败定位到层） |
| `the_fixture_roots_are_the_only_thing_being_touched` | 只碰测试临时根 |

`crates/imapd/src/` 另有 14 个单测（目录键回退、损坏库 fail-closed、
passwd 解析、TLS 配置校验等）；`crates/core` 有 10 个（口令库）；
`crates/priv` 有 4 个（并写/改密/删号/写失败报错）。

---

## 6. 尚未接线（诚实披露）

1. ~~SMTP 提交端口的 SASL 仍走 Dovecot auth-client~~ **已切换**：`mailstackd`
   的提交端口现在用 `mailstack_smtpd::MailboxPasswordsAuthenticator` 直连本套口令库
   （`mailbox-passwords.json`），与 IMAP/POP3/ManageSieve 同源；`DovecotAuthClient`
   保留但默认不装配。
2. ~~LMTP / ManageSieve 监听器未装配~~ **已装配**：`mailstack-imap --managesieve`
   开 4190（脚本上传即生效）；本地投递由 `mailstackd` 的**自有** LMTP unix socket
   落箱（`<run_dir>/lmtp.sock`），队列 `LmtpClient` 连它，Sieve 在这一层生效
   （`redirect`/`vacation` 产物回到同一条出站队列）。
3. ~~`/metrics` HTTP 端点未接~~ **已接**：`mailstack-imap --metrics <ADDR>` 暴露
   Prometheus 文本端点，按协议各持一份注册表（imap/pop3/managesieve）一次抓全。
4. ~~真实 Dovecot 数据迁移未演练~~ **已演练**：
   `crates/imappop3/tests/dovecot_cutover.rs` 用真实布局夹具（v3 uidlist、
   leading-colon、关键字表、已删除记录、uidlist 外文件、子文件夹）验证
   UID/UIDVALIDITY 保留、关键字接管、重复运行幂等；入口是
   `mailstack-imap --migrate-maildir <DIR>`。

**仍然未做**：在**真实 Dovecot 生产数据**上跑一次迁移（当前演练用的是合成夹具）；
`mailstack-web` 对 `/metrics` 的抓取展示；停用 Postfix / OpenDKIM / fail2ban / Node
（组件下线的其余部分）。

//! MailStack IMAP/POP3 装配层 —— 把自研协议面（`mailstack-imappop3`）接进 MailStack。
//!
//! ## 这一层解决什么
//!
//! `mailstack-imappop3` 只懂协议与 Maildir，不知道 MailStack 的账号存在哪、
//! 家目录怎么定、证书从哪来。这一层补的就是这三件事：
//!
//! ```text
//! crates/imapd
//!   ├─ directory.rs  账号：mailbox-passwords.json（PBKDF2 记录，INV-37）→ AuthBackend
//!   ├─ resolver.rs   邮箱：/etc/passwd 家目录 + ~/Maildir            → MailboxResolver
//!   └─ servers.rs    装配：TLS（Let's Encrypt）+ 绑定 143/993/110/995 + 停机信号
//! ```
//!
//! ## 与 Dovecot 的对应关系
//!
//! | Dovecot 侧 | 本层 |
//! |---|---|
//! | `passdb pam`（读 `/etc/shadow`） | `mailbox-passwords.json` 的 PBKDF2 记录 |
//! | `userdb static`（`mail_location = maildir:~/Maildir`） | [`resolver::SystemMaildirResolver`] |
//! | `ssl_cert = </etc/letsencrypt/live/…/fullchain.pem` | [`servers::cert_pair_from_le`] |
//! | `service imap-login` / `pop3-login` | [`servers::run`] 绑定的监听器 |
//! | dovecot-uidlist | imappop3 的 `.mailstack-uidlist`（**迁移需 `migrate_maildir`**） |
//!
//! ## 多用户
//!
//! 一个监听器服务所有账号：会话在认证成功后按登录名经 `resolver` 切到本人 Maildir
//! （见 `crates/imappop3` 的 `AuthOutcome::Success`）。解析不到就拒绝登录，
//! 不会退回默认邮箱。
//!
//! ⚠️ **从 Dovecot 切换前必须先离线迁移 UID**：两套 UID 映射同时写一个 Maildir 会让
//! 客户端把同一封信重复拉一遍。用 `mailstack_imappop3::migrate_maildir`，
//! 且切换期间**只能有一个实现**在写。
//!
//! ## 尚未接线（诚实披露）
//!
//! * LMTP / ManageSieve 的监听器：`mailstack-imappop3` 已实现，但 MailStack 的
//!   入站仍走 SMTP + 队列，接管需要同时改 `mailstackd` 的投递路径，属 Phase 5。
//! * `metrics` 的 `/metrics` HTTP 端点：由 `mailstack-web` 抓取，尚未接。

pub mod directory;
pub mod resolver;
pub mod servers;

pub use directory::{backend, MailboxDirectory};
pub use resolver::{account_name, SystemMaildirResolver};
pub use servers::{assemble, cert_pair_from_le, Assembly, CertPair, Config, ImapdError, Listeners};

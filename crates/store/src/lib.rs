//! MailStack 数据层（规格书 §3.3、§3.5）。
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`tables`] | Postfix 表文件：虚拟域名表与别名表（格式兼容 `hash:` 表） |
//! | [`lmtp`] | Dovecot LMTP 客户端 —— **收信落箱的唯一投递路径**（INV-11） |
//! | [`lmtp_transport`] | 把 LMTP 接到队列的 [`mailstack_queue::Transport`] 上 |
//!
//! ## INV-11 的落点
//!
//! > 邮件写入只能经 LMTP；Rust 侧不得直接写 Maildir 索引。
//!
//! 本 crate **不提供任何写 Maildir 的 API** —— 这不是「记得别写」，而是根本没有
//! 这样的函数可调用。落箱只有 [`lmtp::LmtpClient::deliver`] 一条路。
//!
//! ## 尚未实现（诚实披露）
//!
//! * **Maildir 只读访问**：规格书把它列在 store 的职责里，但存在一个必须先定的
//!   前提 —— 权威布局。基线是 Postfix 的 `local` 代理写系统用户的 `~/Maildir`
//!   （`mail.py` 的环路自检同时探测 `/home/<u>/Maildir` 与 `/var/vmail/<domain>/<u>`），
//!   而 Dovecot 的配置是 `mail_location = maildir:~/Maildir`。**在把权威布局定死之前
//!   实现一个靠猜的路径解析，比不实现更糟**：它会在生产上静默读错目录。
//!   目前也没有消费者（webmail 尚未开始）。
//! * **Dovecot auth socket**（webmail 认证桥，§3.5 第二行）：属 `mailstack-webmail`
//!   的范围。

pub mod error;
pub mod lmtp;
pub mod lmtp_transport;
pub mod tables;

pub use error::{StoreError, StoreResult};
pub use lmtp::{LmtpClient, LmtpDelivery, LmtpEndpoint, RecipientResult, DEFAULT_LMTP_SOCKET};
pub use lmtp_transport::{classify_lmtp_error, classify_partial, LmtpTransport};
pub use tables::{validated_domain, AliasEntry, TableStore, MAX_ALIAS_DESTINATIONS};

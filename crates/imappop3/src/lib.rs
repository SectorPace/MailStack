//! MailStack IMAP4rev1 / POP3 服务端 —— 替代 Dovecot 的协议面（规格书 §3.5、§6）。
//!
//! ## 这个 crate 解决什么问题
//!
//! 重写前 IMAP/POP3、LMTP 与 SASL 全部由 Dovecot 提供。本 crate 把**协议面**收回：
//! 直接读 Maildir，直接校验口令记录，不再有 `dovecot` 进程、不再有 auth socket、
//! 不再有 LMTP 中转。
//!
//! ```text
//! mailstackd ──┬─► imappop3::imap  (143 / 993, STARTTLS 或隐式 TLS)
//!              └─► imappop3::pop3  (110 / 995, STLS 或隐式 TLS)
//!                        │
//!                        ├─ Maildir（磁盘布局，Dovecot 兼容的 cur/new/tmp + 标志后缀）
//!                        └─ mailstack_core::password（PBKDF2 口令记录）
//! ```
//!
//! ## 与 Dovecot 的兼容边界（必须知道）
//!
//! * **Maildir 本体兼容**：`cur/`、`new/`、`tmp/`、`<unique>:2,<flags>` 都是标准
//!   Maildir。Dovecot 写的邮件本 crate 能读，反之亦然。
//! * **UID 映射不兼容**：Dovecot 用 `dovecot-uidlist`（v3），本 crate 用
//!   `.mailstack-uidlist`（自有格式，见 [`maildir`] 模块文档）。两者都写同一个
//!   Maildir 会让同一个文件被分配**两套 UID**，客户端会重复拉信。切换实现前必须
//!   **离线**迁移：用 [`migrate_maildir`]（见 [`migration`]）把 Dovecot 的 UID 与
//!   关键字字母表接管过来，避免所有客户端整体重新同步。`mailstackd` 装配时也只
//!   允许二选一。
//! * **关键字兼容**：本 crate 的 `.mailstack-keywords` 与 Dovecot 的
//!   `.dovecot-keywords` 同为「字母 → 关键字」映射，但文件名不同、互不读取；
//!   [`migrate_maildir`] 会在迁移时把后者转换成前者。
//!
//! ## 实现范围（诚实披露）
//!
//! 已实现：IMAP4rev1 核心命令（登录、SELECT/EXAMINE、LIST/LSUB、STATUS、CREATE/
//! DELETE/RENAME、SUBSCRIBE、APPEND、CHECK、CLOSE、EXPUNGE、SEARCH、FETCH、STORE、
//! COPY、UID 变体、IDLE、NAMESPACE），扩展 `LITERAL+`、`UIDPLUS`、`MULTIAPPEND`、
//! `MOVE`、`UNSELECT`、`ID`、`ENABLE`、`SASL-IR`、`SPECIAL-USE`、`CHILDREN`、
//! `LIST-EXTENDED`、`ESEARCH`（RETURN MIN/MAX/ALL/COUNT）、`CONDSTORE`、`QRESYNC`、
//! `QUOTA`（RFC 9208）、`SORT`/`THREAD`（RFC 5256）、`SORT=DISPLAY`（RFC 5957）、
//! `METADATA`（RFC 5464）、`ACL`（RFC 4314：GETACL/SETACL/DELETEACL/LISTRIGHTS/
//! MYRIGHTS 与权限存储，并作为**跨用户共享邮箱** `shared/<user>/<folder>` 的访问
//! 依据；用户目录由 [`MailboxResolver`] 注入）、`SCRAM-SHA-256`、
//! `COMPRESS=DEFLATE`（RFC 4978）、
//! `BINARY`/`BINARY.SIZE`（RFC 3516）、`SEARCHRES`（RFC 5182：`RETURN (SAVE)` 与
//! `$`），STARTTLS 与隐式 TLS；POP3（RFC 1939）+ `CAPA`、
//! `STLS`、`TOP`、`UIDL` 与独占锁；LMTP
//! （RFC 2033，TCP 与 Unix 套接字）直接投递到 Maildir，并在投递前执行
//! **Sieve 安全子集**（[`sieve`]：`fileinto`/`reject`/`redirect`/`vacation`/`body`
//! 与条件测试；`redirect`/`vacation` 经 [`OutboundSink`] 投递到外发队列；脚本缺失或
//! 编译失败时回退 INBOX，绝不丢信）；**ManageSieve**（[`managesieve`]，RFC 5804）供
//! 客户端上传/管理脚本（默认 4190，STARTTLS/隐式 TLS，用户目录由 [`MailboxResolver`]
//! 注入）；认证面覆盖 PBKDF2 口令记录、
//! SCRAM、每 IP 连接限速与每用户失败锁定；运维面提供 SNI 多证书热重载（[`tls`]）、
//! Prometheus 文本指标（[`metrics`]：连接/传输层 + IMAP 命令/认证）与 Dovecot
//! 离线迁移（[`migration`]）。
//!
//! 未实现（有意为之，见各模块文档）：共享邮箱上的结构性操作（CREATE/DELETE/RENAME/
//! SUBSCRIBE）与跨存储 COPY/MOVE（都会明确返回 NO）——共享邮箱的常规读写、标志、
//! EXPUNGE、STATUS、APPEND 与 ACL 管理已支持；IMAP4rev2（RFC 9051）与 JMAP。
//! 指标覆盖连接/传输层
//! 与 IMAP 命令/认证；只有 LMTP 逐收件人交付结果尚未埋点（见 [`metrics`]）。`/metrics`
//! HTTP 端点由部署层（`mailstack-web`）抓取 [`Metrics::render_prometheus`] 暴露。
//! 这些是**协议扩展与运维增强**，不是核心收发信能力；缺失时客户端会退回基础路径，
//! 而不是坏掉。
//!
//! ## 运行时要求（诚实披露）
//!
//! Maildir 层使用同步 `std::fs`（文件原子性与 flock 更容易写对），会话层通过
//! 内部的 blocking 线程池把每次扫描 / 读写 / 改名移出 async worker，因此慢盘
//! 不会阻塞运行时。生产部署仍应使用**多线程 runtime**，并把 Maildir 放在本地
//! 磁盘（不要放 9p/NFS）。
//!
//! `SELECT`/`STATUS` 是 O(邮件数) 的目录扫描；NOOP/IDLE 先用 `cur/`、`new/` 的
//! mtime 指纹做快速路径，每 10 次仍强制全量扫描一次。`max_connections`、
//! `idle_poll` 与 `max_message_size` 是主要的背压参数。
//!
//! ## 分层
//!
//! * [`protocol`]（[`imap`] / [`pop3`]）只处理协议，不碰网络；
//! * [`maildir`] 只处理磁盘，不碰协议；
//! * [`auth`] 只做「凭据 → 身份」，不碰存储布局；
//! * [`server`] 之下的 [`tls`]、[`limiter`]、[`lineio`]、[`metrics`] 提供网络、
//!   防护与观测原语；[`migration`] 只在切换实现时一次性使用。
//!
//! 协议层与 I/O 无关，因此 FETCH/SEARCH 的语法、literal 处理、UID 稳定性这些
//! **远程可利用**的行为可以被离线穷举验证。

pub mod acl;
pub mod auth;
mod blocking;
pub mod date;
pub mod error;
pub mod imap;
pub mod limiter;
pub mod lineio;
pub mod lmtp;
pub mod maildir;
pub mod managesieve;
pub mod metrics;
pub mod migration;
pub mod mime;
pub mod outbound;
pub mod pop3;
pub mod render;
pub mod resolver;
pub mod seqset;
pub mod sieve;
pub mod tls;

pub use auth::{
    AuthBackend, AuthFuture, AuthOutcome, AuthRequest, AuthThrottle, AuthThrottleConfig,
    Authenticator, MemoryDirectory, PasswordDirectory, ThrottleDecision, ThrottledAuthenticator,
    UserDirectory,
};
pub use date::{format_date, format_date_time, parse_date_only, parse_date_time};
pub use error::{MailError, Result};
pub use imap::{ImapConfig, ImapExit, ImapServer, ImapServerConfig, ImapSessionContext};
pub use lmtp::{LmtpConfig, LmtpContext, LmtpRouter, LmtpServer, LmtpServerConfig, MapRouter};
pub use maildir::{
    Clock, Flag, FlagSet, FolderState, MailStore, MessageMeta, NewMessage, SystemClock, SystemFlag,
    INBOX,
};
pub use managesieve::{
    ManageSieveContext, ManageSieveExit, ManageSieveServer, ManageSieveServerConfig,
};
pub use metrics::{Metrics, MetricsSnapshot};
pub use migration::{migrate_maildir, MigrationReport};
pub use outbound::{OutboundSink, QueueOutboundSink};
pub use pop3::{Pop3Config, Pop3Exit, Pop3Server, Pop3ServerConfig, Pop3SessionContext};
pub use resolver::{MailboxResolver, MapResolver};
pub use seqset::SequenceSet;

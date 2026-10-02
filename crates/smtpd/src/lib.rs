//! MailStack 入站 SMTP 服务端 —— 替代 Postfix 的 `smtpd`（规格书 §3.3、§5.10）。
//!
//! ## 为什么是独立 crate 而不是塞进 `mailstack-smtp`
//!
//! `mailstack-smtp` 是**纯出站**的（拨号器、中继校验、出站探测），而
//! [`mailstack_queue`] 已经依赖它做投递。入站服务端要反过来依赖队列（把收下的信
//! 入队），放进同一个 crate 会形成依赖环。两者的威胁模型也完全不同：出站关心
//! 「不要把凭证发给错的对方」，入站关心「不要让对端决定我们的行为」。
//!
//! ## 模块划分
//!
//! * [`reply`] —— 应答构造与渲染（含应答注入防护）
//! * [`command`] —— 命令解析（含命令注入与长度耗尽防护）
//! * [`data`] —— DATA 正文的字节流解析（含 **SMTP 走私**防护）
//! * [`session`] —— 会话状态机（事务序列、反中继 INV-17、大小与收件人上限）
//! * [`connection`] —— 会话驱动：把字节流接到状态机上（单一输入缓冲）
//! * [`tls`] —— 入站 TLS：证书装载、**TLS 1.2 起**的版本策略、明文/加密流统一
//! * [`ratelimit`] —— 每 IP 令牌桶连接限速（替代 fail2ban 的限速半边）
//! * [`ban`] —— IP 自动封禁：失败计数 → 临时 / 永久（替代 fail2ban 的封禁半边）
//! * [`listener`] —— TCP 监听、连接数上限、优雅停机与 STARTTLS/隐式 TLS 升级
//! * [`auth_results`] —— `Authentication-Results` 渲染（RFC 8601，含头注入防护）
//! * [`sasl`] —— 提交端口 SASL 认证（RFC 4954）与 Dovecot auth socket 客户端（§3.5）
//! * [`sink`] —— 收信去处：认证（SPF/DKIM/DMARC）→ 加头 → 入队
//!
//! ## 尚未实现（诚实披露）
//!
//! * 出站队列的 ARC 封印（`arc` 只做了校验这一半）
//!
//! ## 分层理由
//!
//! 协议核心（`reply`/`command`/`data`/`session`/`connection`）与 I/O 无关，因此
//! 走私、注入、长度耗尽这些**远程可利用**的缺陷可以被离线穷举验证；`listener`
//! 与 `tls` 在其上叠加网络与密码学，`ratelimit`/`ban` 的判定全部接收注入的时钟，
//! 于是「限速窗口」与「封禁到期」这类与时间相关的行为也能被确定性验证。

pub mod auth_results;
pub mod ban;
pub mod command;
pub mod connection;
pub mod data;
pub mod listener;
pub mod ratelimit;
pub mod reply;
pub mod sasl;
pub mod session;
pub mod sink;
pub mod tls;

pub use auth_results::render as render_authentication_results;
pub use ban::{Ban, BanConfig, BanList, ManualBanDiff};
pub use command::{parse as parse_command, Command, CommandError, MailParams};
pub use connection::{
    serve, serve_after_upgrade, MessageSink, ServeOutcome, ServerLimits, SinkFuture,
};
pub use data::{BareNewlinePolicy, DataEvent, DataSink};
pub use listener::{Clock, ConfigError, MailServer, ServerConfig, SystemClock};
pub use ratelimit::{RateDecision, RateLimitConfig, RateLimiter};
pub use reply::Reply;
pub use sasl::{
    AuthBackend, AuthFuture, AuthOutcome, AuthRequest, Authenticator, DovecotAuthClient,
    UnavailableAuthenticator, DEFAULT_AUTH_SOCKET,
};
pub use session::{AcceptedMessage, Action, Session, SessionConfig};
pub use sink::QueueSink;
pub use tls::{acceptor as tls_acceptor, CertPaths, TlsError, TlsMode};

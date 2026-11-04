pub mod auth_results;
pub mod ban;
pub mod command;
pub mod connection;
pub mod data;
pub mod listener;
mod peer;
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
    MailboxPasswordsAuthenticator, UnavailableAuthenticator, DEFAULT_AUTH_SOCKET,
};
pub use session::{
    AcceptedMessage, Action, AnyRecipient, DirectoryRecipients, RecipientChecker, Session,
    SessionConfig, SessionRole,
};
pub use sink::QueueSink;
pub use tls::{acceptor as tls_acceptor, CertPaths, TlsError, TlsMode};

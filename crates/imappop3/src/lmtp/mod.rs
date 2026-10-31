//! LMTP 服务（RFC 2033）：收件人路由、逐收件人应答、直接 Maildir 投递。

pub mod router;
pub mod server;
pub mod session;

pub use router::{LmtpRouter, MapRouter};
pub use server::{LmtpServer, LmtpServerConfig};
pub use session::{LmtpConfig, LmtpContext, LmtpExit};

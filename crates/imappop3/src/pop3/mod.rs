//! POP3 服务端（RFC 1939 + CAPA/STLS/TOP/UIDL）。

pub mod server;
pub mod session;

pub use server::{Pop3Server, Pop3ServerConfig};
pub use session::{Pop3Config, Pop3ConnectionOptions, Pop3Exit, Pop3SessionContext};

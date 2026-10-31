//! IMAP4rev1 服务端（协议解析、FETCH/SEARCH、会话状态机、监听器）。

pub mod fetch;
pub mod parser;
pub mod scram;
pub mod search;
pub mod server;
pub mod session;
pub mod sort;
pub mod thread;

pub use fetch::{BodySpec, FetchItem, Section};
pub use parser::{Command, ParserLimits, Token};
pub use server::{ImapServer, ImapServerConfig};
pub use session::{ConnectionOptions, ImapConfig, ImapExit, ImapSessionContext};

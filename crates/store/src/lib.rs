pub mod error;
pub mod lmtp;
pub mod lmtp_transport;
pub mod recipients;
pub mod tables;

pub use error::{StoreError, StoreResult};
pub use lmtp::{LmtpClient, LmtpDelivery, LmtpEndpoint, RecipientResult, DEFAULT_LMTP_SOCKET};
pub use lmtp_transport::{classify_lmtp_error, classify_partial, LmtpTransport};
pub use recipients::{LocalRecipients, Lookup};
pub use tables::{validated_domain, AliasEntry, TableStore, MAX_ALIAS_DESTINATIONS};

use std::path::PathBuf;

use mailstack_core::CoreError;

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("io error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Invalid(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("authentication backend error: {0}")]
    Auth(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("timed out")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, MailError>;

impl MailError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::AlreadyExists(message.into())
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn kind(&self) -> &'static str {
        match self {
            MailError::Io { .. } => "IoError",
            MailError::Invalid(_) => "InvalidInput",
            MailError::Protocol(_) => "ProtocolError",
            MailError::NotFound(_) => "NotFound",
            MailError::AlreadyExists(_) => "AlreadyExists",
            MailError::Storage(_) => "StorageError",
            MailError::QuotaExceeded(_) => "QuotaExceeded",
            MailError::Auth(_) => "AuthError",
            MailError::Config(_) => "ConfigError",
            MailError::Timeout => "Timeout",
        }
    }

    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            MailError::Io { .. } | MailError::Storage(_) | MailError::Auth(_)
        )
    }
}

impl From<CoreError> for MailError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Invalid(message) => MailError::Invalid(message),
            CoreError::NotFound(path) => MailError::NotFound(path.display().to_string()),
            CoreError::Io { path, source } => MailError::Io { path, source },
            CoreError::Json(error) => MailError::Storage(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_stable_and_classify_server_faults() {
        assert_eq!(MailError::invalid("x").kind(), "InvalidInput");
        assert_eq!(MailError::protocol("x").kind(), "ProtocolError");
        assert_eq!(MailError::not_found("x").kind(), "NotFound");
        assert_eq!(MailError::already_exists("x").kind(), "AlreadyExists");
        assert!(MailError::storage("x").is_server_error());
        assert!(MailError::io("/tmp/x", std::io::Error::other("y")).is_server_error());
        assert!(!MailError::invalid("x").is_server_error());
        assert!(!MailError::Timeout.is_server_error());
    }

    #[test]
    fn core_errors_map_without_losing_the_path() {
        let mapped = MailError::from(CoreError::io(
            "/var/mail/user/Maildir/cur/x",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        ));
        assert!(matches!(mapped, MailError::Io { .. }));
        assert!(mapped.to_string().contains("/var/mail/user/Maildir/cur/x"));
    }
}

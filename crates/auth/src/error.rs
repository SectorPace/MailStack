use std::path::PathBuf;

impl From<mailstack_core::CoreError> for AuthError {
    fn from(error: mailstack_core::CoreError) -> Self {
        match error {
            mailstack_core::CoreError::Io { path, source } => AuthError::Io { path, source },
            other => AuthError::Signing(other.to_string()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("io error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Invalid(String),

    #[error("DKIM key generation failed")]
    KeyGeneration,

    #[error("DKIM signing failed: {0}")]
    Signing(String),

    #[error("{0}")]
    Dns(String),
}

pub type AuthResult<T> = Result<T, AuthError>;

impl AuthError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn kind(&self) -> &'static str {
        match self {
            AuthError::Io { .. } => "IoError",
            AuthError::Invalid(_) => "InvalidInput",
            AuthError::KeyGeneration => "KeyGenerationFailed",
            AuthError::Signing(_) => "SigningError",
            AuthError::Dns(_) => "DnsError",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_messages_are_verbatim() {
        assert_eq!(
            AuthError::invalid("invalid domain format").to_string(),
            "invalid domain format"
        );
        assert_eq!(
            AuthError::invalid("invalid DKIM selector").to_string(),
            "invalid DKIM selector"
        );
    }

    #[test]
    fn error_kinds_are_stable() {
        assert_eq!(
            AuthError::io("/tmp/x", std::io::Error::other("y")).kind(),
            "IoError"
        );
        assert_eq!(AuthError::invalid("bad").kind(), "InvalidInput");
        assert_eq!(AuthError::KeyGeneration.kind(), "KeyGenerationFailed");
        assert_eq!(AuthError::Signing("nope".into()).kind(), "SigningError");
        assert_eq!(AuthError::Dns("nope".into()).kind(), "DnsError");
    }
}

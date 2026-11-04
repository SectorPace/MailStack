use std::path::PathBuf;

use mailstack_core::CoreError;

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("io error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("queue storage error: {0}")]
    Storage(String),

    #[error("{0}")]
    Invalid(String),

    #[error("queue round already in flight: {0}")]
    Busy(String),
}

pub type QueueResult<T> = Result<T, QueueError>;

impl QueueError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn busy(message: impl Into<String>) -> Self {
        Self::Busy(message.into())
    }

    pub fn is_busy(&self) -> bool {
        matches!(self, QueueError::Busy(_))
    }

    pub fn kind(&self) -> &'static str {
        match self {
            QueueError::Io { .. } => "IoError",
            QueueError::Json(_) => "JsonError",
            QueueError::Storage(_) => "StorageError",
            QueueError::Invalid(_) => "InvalidInput",
            QueueError::Busy(_) => "RoundInFlight",
        }
    }
}

impl From<CoreError> for QueueError {
    fn from(e: CoreError) -> Self {
        QueueError::Storage(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kinds_are_stable_and_do_not_leak_payloads() {
        let io = QueueError::io("/var/lib/mailstack/queue", std::io::Error::other("x"));
        assert_eq!(io.kind(), "IoError");

        let invalid = QueueError::invalid("bad input");
        assert_eq!(invalid.kind(), "InvalidInput");
        assert_eq!(invalid.to_string(), "bad input");

        let busy = QueueError::busy("round 1");
        assert_eq!(busy.kind(), "RoundInFlight");
        assert!(busy.is_busy(), "重叠必须可被调用方识别为「跳过」而非故障");
        assert!(!invalid.is_busy());

        let core = QueueError::from(CoreError::invalid("nope"));
        assert_eq!(core.kind(), "StorageError");
        assert!(
            core.to_string().contains("nope"),
            "底层原因应保留在文本里，供日志排查"
        );
    }
}

//! 队列错误类型。

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

    /// 队列落盘原语失败（`atomic_as` / `locked` 等）。
    #[error("queue storage error: {0}")]
    Storage(String),

    /// 配置或调用方输入非法。
    #[error("{0}")]
    Invalid(String),
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

    /// 稳定的错误「类别名」，用于 JSON 输出与界面归类。
    ///
    /// 刻意只暴露类别而不是完整文本：队列条目里含信封地址与报文，不应泄漏到前端。
    pub fn kind(&self) -> &'static str {
        match self {
            QueueError::Io { .. } => "IoError",
            QueueError::Json(_) => "JsonError",
            QueueError::Storage(_) => "StorageError",
            QueueError::Invalid(_) => "InvalidInput",
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

        let core = QueueError::from(CoreError::invalid("nope"));
        assert_eq!(core.kind(), "StorageError");
        assert!(
            core.to_string().contains("nope"),
            "底层原因应保留在文本里，供日志排查"
        );
    }
}

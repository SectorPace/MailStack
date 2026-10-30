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

    /// 上一轮调度尚未结束（5.9 的排他保护）。
    ///
    /// 单独成一个变体而不是塞进 `Invalid`：调用方需要能区分
    /// 「这轮被跳过（正常，不是故障）」与「这轮失败了（要报错）」。
    /// 把两者混在一起，要么会让 daemon 把正常的重叠误报成故障，
    /// 要么会让真正的失败被当成「跳过」而静默吞掉。
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

    /// 上一轮仍在运行时构造的「跳过」错误（5.9）。
    pub fn busy(message: impl Into<String>) -> Self {
        Self::Busy(message.into())
    }

    /// 是否是「上一轮还在跑」这种**可预期**的跳过（不是故障）。
    pub fn is_busy(&self) -> bool {
        matches!(self, QueueError::Busy(_))
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

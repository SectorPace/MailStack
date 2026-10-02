//! 统一错误类型。
//!
//! 原 Python 实现用 `ValueError` 表达校验失败、`OSError`/`RuntimeError` 表达
//! 系统调用失败。Rust 侧保留同样的区分度，因为 HTTP 层需要把「用户输入非法」
//! 映射为 4xx、把「系统调用失败」映射为 5xx。

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// 对应 Python 的 `ValueError`：调用方输入非法，消息面与原文逐字一致。
    #[error("{0}")]
    Invalid(String),

    /// 对应 `FileNotFoundError`。
    #[error("not found: {}", .0.display())]
    NotFound(PathBuf),

    #[error("io error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl CoreError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// 把 `std::io::Error` 绑定到具体路径，便于运维定位。
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// 供 HTTP 层区分「客户端错误」与「服务端错误」。
    pub fn is_client_error(&self) -> bool {
        matches!(self, CoreError::Invalid(_))
    }
}

pub type CoreResult<T> = Result<T, CoreError>;

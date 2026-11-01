//! store 错误类型。

use std::path::PathBuf;

use mailstack_core::CoreError;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("json error on {}: {source}", .path.display())]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// 调用方输入非法（域名、邮箱、别名等校验失败）。
    ///
    /// 文案与 Python 原实现的 `ValueError` 逐字一致 —— 它是对外契约的一部分。
    #[error("{0}")]
    Invalid(String),

    #[error("LMTP error: {0}")]
    Lmtp(String),

    /// 表文件已写入，但 Postfix 侧的 `postmap` / `check` / `reload` 失败。
    ///
    /// 与 `Io` 刻意分开：磁盘上的表文件是新的，坏的是「Postfix 读到的仍是旧表」
    /// —— 静默返回 Ok 会把「改了路由却没生效」变成无日志的悬案；运维需要的
    /// 处置（重跑 postmap / reload）也与「文件写失败」完全不同。
    #[error("postmap error: {0}")]
    Postmap(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

impl StoreError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn json(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::Json {
            path: path.into(),
            source,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// 稳定的错误「类别名」，用于 JSON 输出与界面归类。
    pub fn kind(&self) -> &'static str {
        match self {
            StoreError::Io { .. } => "IoError",
            StoreError::Json { .. } => "JsonError",
            StoreError::Invalid(_) => "InvalidInput",
            StoreError::Lmtp(_) => "LmtpError",
            StoreError::Postmap(_) => "PostmapError",
        }
    }
}

impl From<CoreError> for StoreError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Invalid(message) => StoreError::Invalid(message),
            CoreError::NotFound(path) => StoreError::Io {
                path,
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            CoreError::Io { path, source } => StoreError::Io { path, source },
            CoreError::Json(error) => StoreError::Invalid(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kinds_are_stable() {
        assert_eq!(
            StoreError::io("/tmp/x", std::io::Error::other("y")).kind(),
            "IoError"
        );
        assert_eq!(StoreError::invalid("bad").kind(), "InvalidInput");
        assert_eq!(StoreError::Lmtp("down".into()).kind(), "LmtpError");
        assert_eq!(
            StoreError::from(CoreError::invalid("core said no")).to_string(),
            "core said no"
        );
        assert_eq!(
            StoreError::from(CoreError::io(
                "/tmp/x",
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            ))
            .kind(),
            "IoError"
        );
    }
}

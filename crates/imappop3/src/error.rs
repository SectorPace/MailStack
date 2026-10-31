//! 统一错误类型。
//!
//! 分层与 `mailstack-store` 一致：**调用方输入非法**（协议语法、非法邮箱名）与
//! **系统调用失败**（磁盘、锁、认证后端）必须可分辨 —— 前者回 `BAD`/`NO`，
//! 后者回 `NO [SERVERBUG]` 并让运维看到日志。把两者压成一个字符串会迫使协议层
//! 用字符串前缀反推错误类别，那正是错误分类漂移的开始。

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

    /// 调用方输入非法（协议语法、非法名称、非法参数组合）。对外是客户端错误。
    #[error("{0}")]
    Invalid(String),

    /// 协议违例（literal 超限、命令过长、状态不对）。与 [`MailError::Invalid`]
    /// 分开是为了让服务器能把「语法错」与「业务拒绝」映射成不同应答码。
    #[error("protocol error: {0}")]
    Protocol(String),

    /// 协议格式合法但对象不存在（邮箱、邮件、UID）。对外 `NO` / `-ERR no such`。
    #[error("not found: {0}")]
    NotFound(String),

    /// 创建/重命名时目标已存在。对外 `NO [ALREADYEXISTS]`。
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// 存储层故障（uidlist 损坏、锁超时、磁盘写入失败）。对外 `NO [SERVERBUG]`。
    #[error("storage error: {0}")]
    Storage(String),

    /// 存储配额超限（IMAP `OVERQUOTA` / LMTP 552）。
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),

    /// 认证后端故障（与「口令错」区分：后者是 [`AuthOutcome::InvalidCredentials`]）。
    #[error("authentication backend error: {0}")]
    Auth(String),

    /// 构造期配置错误。启动时拒绝，而不是运行期静默降级。
    #[error("configuration error: {0}")]
    Config(String),

    /// 读超时。服务器应发 `* BYE` / `-ERR` 后断开，而不是无限等待。
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

    /// 稳定的类别名，用于日志与指标；**不随文案变化**。
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

    /// 是否属于「服务器自己的问题」——决定对外应答是 `NO` 还是带 `[SERVERBUG]`。
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

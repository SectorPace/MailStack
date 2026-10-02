//! auth 错误类型。
//!
//! 与 `crates/store`、`crates/smtp` 同形：输入类错误的消息文本是**对外契约**
//! （Python 基线把它们直接抛给上层，界面按此归类）。

use std::path::PathBuf;

/// 认证/签名子系统的错误。
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("io error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 调用方输入非法。文案与 Python 基线逐字一致。
    ///
    /// 已对齐的两条：`invalid domain format`（`certs.py:176`）、
    /// `invalid DKIM selector`（`certs.py:179`）。
    #[error("{0}")]
    Invalid(String),

    /// DKIM 密钥生成失败。
    ///
    /// **偏离登记**：基线 `certs.py:188` 抛的是 `OpenDKIM key generation failed`，
    /// 并在 `certs.py:180` 先判 `opendkim-genkey` 是否安装。Rust 版改为**原生生成**
    /// （不再调用外部二进制），因此「未安装」这一前置条件消失，文案也不再声称是
    /// OpenDKIM 的产出 —— 继续输出 `OpenDKIM ...` 会让运维去排查一个已被移除的组件。
    #[error("DKIM key generation failed")]
    KeyGeneration,

    /// 私钥无法用于签名（DER 解析失败等）。
    #[error("DKIM signing failed: {0}")]
    Signing(String),

    /// DNS 查询或记录解析失败。
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

    /// 稳定的错误「类别名」，用于日志归类（与 store/smtp 同样式）。
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
        // 这两条文案是对外契约，改了就是破坏兼容。
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

//! SMTP 子系统错误类型。

use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error("invalid relay endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("DNS resolution failed: {0}")]
    Dns(String),

    /// 解析成功但没有任何地址通过私网策略 —— **fail-closed**，不得回落到按域名连接。
    #[error("no acceptable address for {0} (all resolved addresses were rejected by policy)")]
    NoAcceptableAddress(String),

    /// RFC 7505 null MX（`MX 0 .`）：该域**明确声明**不接收邮件，重试没有意义。
    #[error("domain {0} publishes a null MX and accepts no mail")]
    NullMx(String),

    #[error("cannot connect to {addr}: {source}")]
    Connect {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("connecting to {addr} timed out after {secs}s")]
    ConnectTimeout { addr: SocketAddr, secs: u64 },

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("SMTP protocol error: {0}")]
    Protocol(String),

    /// 信封地址里含 CR/LF —— 命令注入。
    ///
    /// 单独一个变体而不是塞进 [`SmtpError::Protocol`]：这是**本机代码或队列
    /// 数据的缺陷**，不是对端的协议违规，排查方向完全不同（前者要查数据来源，
    /// 后者要查网络）。而且它必须是**硬失败**：`MAIL FROM:<a\r\nRCPT TO:<b>>`
    /// 这种拼接会让攻击者往命令流里注入第二条命令，以本机身份向第三方投递。
    #[error("refusing to build a command from an address containing CR or LF: {0:?}")]
    HeaderInjection(String),

    #[error("SMTP server rejected the command: {0}")]
    Rejected(String),

    #[error("SMTP username and password must be provided together")]
    IncompleteCredentials,

    #[error("TLS is required for relay endpoint")]
    TlsRequired,

    /// 文案是**对外契约**（规格书 §5.9.2 原文），首字母大写不得改动。
    #[error("Private SMTP relay access is disabled by deployment policy")]
    PrivateRelayDisabled,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// 配置读写失败（命令执行、文件解析、原子写等）。
    #[error("{0}")]
    Config(String),
}

impl From<mailstack_core::CoreError> for SmtpError {
    fn from(e: mailstack_core::CoreError) -> Self {
        SmtpError::Config(e.to_string())
    }
}

impl From<serde_json::Error> for SmtpError {
    fn from(e: serde_json::Error) -> Self {
        SmtpError::Config(format!("json error: {e}"))
    }
}

pub type SmtpResult<T> = Result<T, SmtpError>;

impl SmtpError {
    /// 错误「类别名」。
    ///
    /// 分阶段中继测试的失败阶段要回填一个类别名（原实现回填 Python 异常类名），
    /// 供界面归类展示；用枚举变体名而不是完整错误文本，避免把内网地址、
    /// 凭证细节之类的信息透到前端。
    pub fn kind(&self) -> &'static str {
        match self {
            SmtpError::InvalidEndpoint(_) => "InvalidEndpoint",
            SmtpError::Dns(_) => "DnsError",
            SmtpError::NoAcceptableAddress(_) => "NoAcceptableAddress",
            SmtpError::NullMx(_) => "NullMx",
            SmtpError::Connect { .. } => "ConnectionError",
            SmtpError::ConnectTimeout { .. } => "ConnectTimeout",
            SmtpError::Tls(_) => "TlsError",
            SmtpError::Protocol(_) => "ProtocolError",
            SmtpError::HeaderInjection(_) => "HeaderInjection",
            SmtpError::Rejected(_) => "SmtpRejected",
            SmtpError::IncompleteCredentials => "IncompleteCredentials",
            SmtpError::TlsRequired => "TlsRequired",
            SmtpError::PrivateRelayDisabled => "PrivateRelayDisabled",
            SmtpError::Io(_) => "IoError",
            SmtpError::Config(_) => "ConfigError",
        }
    }
}

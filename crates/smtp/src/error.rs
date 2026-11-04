use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error("invalid relay endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("DNS resolution failed: {0}")]
    Dns(String),

    #[error("no acceptable address for {0} (all resolved addresses were rejected by policy)")]
    NoAcceptableAddress(String),

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

    #[error("refusing to build a command from an address containing CR or LF: {0:?}")]
    HeaderInjection(String),

    #[error("SMTP server rejected the command: {0}")]
    Rejected(String),

    #[error("SMTP username and password must be provided together")]
    IncompleteCredentials,

    #[error("TLS is required for relay endpoint")]
    TlsRequired,

    #[error("Private SMTP relay access is disabled by deployment policy")]
    PrivateRelayDisabled,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

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

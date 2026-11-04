use std::path::PathBuf;

use mailstack_smtp::SmtpError;
use mailstack_smtpd::{ConfigError, TlsError};

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("缺少或无法解析 {0}：无法确定本机身份，拒绝启动")]
    SetupMissing(PathBuf),

    #[error("TLS 材料不可用：{0}")]
    Tls(#[from] TlsError),

    #[error("域名表为空（{0}）：没有可纳管的域。库层会静默拒收全部收件人，因此这里直接拒绝启动")]
    DomainTableEmpty(PathBuf),

    #[error("队列目录不可用 {path}：{message}")]
    QueueDir { path: PathBuf, message: String },

    #[error("中继配置读取失败：{0}")]
    RelayConfig(#[source] SmtpError),

    #[error("中继配置非法：{0}")]
    Relay(#[source] SmtpError),

    #[error("relayhost 无法解析：{0:?}")]
    RelayHost(String),

    #[error("relayhost 是裸 IPv6 地址 {0:?}：IPv6 字面量必须用方括号包住并附端口，例如 [::1]:25")]
    RelayHostBareIpv6(String),

    #[error(
        "端口 {0} 上的中继未启用加密：请设置 smtp_tls_wrappermode=yes、改用 465，\
         或把 smtp_tls_security_level 设为 encrypt/secure/dane/verify"
    )]
    RelayNotEncrypted(u16),

    #[error("没有指定任何监听端口")]
    NoListeners,

    #[error("监听端口 {port} 绑定失败：{source}")]
    Bind {
        port: u16,
        #[source]
        source: std::io::Error,
    },

    #[error("监听配置自相矛盾：{0}")]
    ServerConfig(#[from] ConfigError),

    #[error("特权 RPC socket 绑定失败 {path}：{source}")]
    RpcBind {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("入站认证组件初始化失败：{0}")]
    Sink(String),

    #[error("LMTP 落箱服务装配失败：{0}")]
    Lmtp(String),

    #[error("组成部分异常退出：{0}")]
    Task(String),
}

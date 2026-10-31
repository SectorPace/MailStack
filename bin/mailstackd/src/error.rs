//! 守护进程的错误类型。
//!
//! 这里区分两类失败，因为它们对运维的含义完全不同：
//!
//! * [`DaemonError`] 的各个变体都是**启动期**失败 —— 一律非零退出。宁可不起，
//!   也不要带着「不知道自己是谁」「没有证书却通告 STARTTLS」这种状态进入服务。
//! * 运行期的失败（某一轮投递出错、某一轮超时）**不在这里** —— 那些只 `warn`，
//!   见 `queue::schedule`。一次磁盘抖动不应该让整台服务器停止收信。

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

    /// 读取中继配置本身失败（文件存在但损坏/不可读）。**绝不能**当成「未配置」。
    #[error("中继配置读取失败：{0}")]
    RelayConfig(#[source] SmtpError),

    /// 中继配置可读但不可用（明文 TLS、端口不在白名单、凭证不成对等）。
    #[error("中继配置非法：{0}")]
    Relay(#[source] SmtpError),

    #[error("relayhost 无法解析：{0:?}")]
    RelayHost(String),

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

    /// 本地投递的 LMTP 落箱服务装配失败（socket 目录、服务端配置等）。
    #[error("LMTP 落箱服务装配失败：{0}")]
    Lmtp(String),

    /// 运行期某个组成部分**异常退出**（5.19）。
    ///
    /// 这不是「某一轮投递出错」（那种只 warn），而是「一整块服务没了」：
    /// 监听器崩掉、队列调度 panic、RPC 面挂掉。原实现把它们全部记成日志后
    /// 仍然返回 `Ok(())`，于是 systemd 认为进程正常退出、**不会重启** ——
    /// 表现为「进程活着但半个服务没了」，而退出码看不出任何问题。
    #[error("组成部分异常退出：{0}")]
    Task(String),
}

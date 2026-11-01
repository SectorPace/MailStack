//! IP 固定拨号器（规格书 §5.9.3；INV-14）。
//!
//! rustls 天然把「拨到哪里」与「校验哪个名字」分开：
//! `TcpStream::connect(SocketAddr)` 决定拨号目标，`ServerName` 只用于 SNI 与
//! 证书校验，**rustls 自身不做任何 DNS 解析**。因此 IP 固定不需要修改第三方
//! 客户端，也不需要自研 TLS 栈 —— 这正是 §5.9.3 担心的那个风险的实际答案。
//!
//! 本模块把这个性质固化下来：所有连接 API 的入参都是 [`PinnedTarget`]，
//! 而它的拨号字段是 `SocketAddr`。**不存在**接受 `host:port` 字符串的连接函数。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::SmtpError;
use crate::target::PinnedTarget;

/// TLS 模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// STARTTLS：先明文建连，EHLO 后再升级。
    StartTls,
    /// 隐式 TLS（SMTPS，通常 465）：建连后立即握手。
    Implicit,
}

impl TlsMode {
    /// 从端口推导默认模式。465 是隐式 TLS，其余默认 STARTTLS。
    pub fn for_port(port: u16) -> Self {
        if port == 465 {
            TlsMode::Implicit
        } else {
            TlsMode::StartTls
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TlsMode::StartTls => "STARTTLS",
            TlsMode::Implicit => "SSL/TLS",
        }
    }
}

/// TLS 握手超时。
///
/// ## 为什么握手必须独立限时
///
/// TCP 建连有 [`PinnedDialer::connect`] 的 `connect_timeout`，但握手**没有**：
/// `start_tls` 的 `connector.connect` 原先裸 `await`。对端（直投模式下是任意
/// 收件域的 MX）可以完成三次握手后让 TLS 握手永远不结束 —— 连接与 worker 一起
/// 挂住。STARTTLS（[`PinnedDialer::start_tls`] 被两处复用）与隐式 TLS 三条路径
/// 都汇聚到这一处，在这里限时即可全覆盖。
pub const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 拨号器：持有 TLS 配置与超时。
#[derive(Clone)]
pub struct PinnedDialer {
    tls_config: Arc<ClientConfig>,
    connect_timeout: std::time::Duration,
}

impl std::fmt::Debug for PinnedDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedDialer")
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl PinnedDialer {
    /// 用内置 Mozilla 根证书构造（生产默认）。
    ///
    /// 刻意不用系统 CA 存储：`webpki-roots` 是纯 Rust 的内置根，
    /// 满足 §3.4「无系统依赖、可离线复现」。
    pub fn with_webpki_roots(connect_timeout: std::time::Duration) -> Result<Self, SmtpError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Self {
            tls_config: Arc::new(config),
            connect_timeout,
        })
    }

    /// 用指定的根证书构造（测试与私有 CA 场景）。
    pub fn with_roots(roots: rustls::RootCertStore, connect_timeout: std::time::Duration) -> Self {
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            tls_config: Arc::new(config),
            connect_timeout,
        }
    }

    /// 用现成的 `ClientConfig` 构造。
    pub fn from_config(config: Arc<ClientConfig>, connect_timeout: std::time::Duration) -> Self {
        Self {
            tls_config: config,
            connect_timeout,
        }
    }

    /// 拨号：按 `target.addresses` 的顺序逐个尝试（第一个就是 `pinned`）。
    ///
    /// 全部地址都来自**同一次**解析、过了**同一轮**地址策略筛选 —— 逐个尝试没有
    /// 脱离 IP 固定（INV-14）：任何时刻都不存在「按域名重连」。原实现只连第一个
    /// 地址，其余 A/AAAA 记录被丢弃；解析出多个地址的域（多线机房很常见）会因
    /// 第一台瞬时不可用而整次投递失败。全部失败时上报**最后一个**错误。
    ///
    /// 总时长仍以 `connect_timeout` 为上界：所有尝试共享一个截止时间，而不是
    /// 每个地址各领一份 —— 否则一个多地址的坏目标能把投递任务挂上 N 倍超时。
    pub async fn connect(&self, target: &PinnedTarget) -> Result<TcpStream, SmtpError> {
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        let port = target.pinned.port();
        let mut last_error: Option<SmtpError> = None;

        for ip in &target.addresses {
            let addr = SocketAddr::new(*ip, port);
            match tokio::time::timeout_at(deadline, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    // 关闭 Nagle：SMTP 是请求-响应式小包交互，延迟比吞吐重要。
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Ok(Err(e)) => last_error = Some(SmtpError::Connect { addr, source: e }),
                Err(_) => {
                    last_error = Some(SmtpError::ConnectTimeout {
                        addr,
                        secs: self.connect_timeout.as_secs(),
                    })
                }
            }
        }

        // 两个构造函数都保证 `addresses` 非空；这个兜底只是为了不引入 `unwrap`。
        Err(last_error.unwrap_or_else(|| {
            SmtpError::InvalidEndpoint(format!("no address to dial for {}", target.hostname))
        }))
    }

    /// 在已建立的 TCP 连接上做 TLS 握手。
    ///
    /// SNI 与证书校验使用 `target.hostname`（原域名），连接对象是已固定的 IP。
    /// 这正是 §5.9.3 要求的形态。
    pub async fn start_tls(
        &self,
        stream: TcpStream,
        target: &PinnedTarget,
    ) -> Result<TlsStream<TcpStream>, SmtpError> {
        let server_name = ServerName::try_from(target.hostname.clone()).map_err(|_| {
            SmtpError::InvalidEndpoint(format!("invalid TLS server name: {}", target.hostname))
        })?;

        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        // 握手限时：对端可以「TCP 收下、握手挂起」，没有这条超时连接就会永久占用。
        // 与 TCP 建连的 `connect_timeout` 同一立场 —— 慢与坏是同一种失败。
        match tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(result) => result
                .map_err(|e| SmtpError::Tls(format!("TLS handshake with {}: {e}", target.hostname))),
            Err(_) => Err(SmtpError::Tls(format!(
                "TLS handshake with {} timed out after {}s",
                target.hostname,
                TLS_HANDSHAKE_TIMEOUT.as_secs()
            ))),
        }
    }

    /// 一步完成「拨号 →（隐式 TLS 时）握手」。
    pub async fn connect_with_mode(
        &self,
        target: &PinnedTarget,
        mode: TlsMode,
    ) -> Result<EstablishedStream, SmtpError> {
        let stream = self.connect(target).await?;
        match mode {
            TlsMode::Implicit => {
                let tls = self.start_tls(stream, target).await?;
                Ok(EstablishedStream::Tls(Box::new(tls)))
            }
            TlsMode::StartTls => Ok(EstablishedStream::Plain(stream)),
        }
    }
}

/// 建连后的流：可能是明文（等待 STARTTLS）或已加密。
pub enum EstablishedStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl EstablishedStream {
    /// 升级为 TLS。已是 TLS 时返回错误（重复升级是协议错误）。
    pub async fn upgrade(
        self,
        dialer: &PinnedDialer,
        target: &PinnedTarget,
    ) -> Result<EstablishedStream, SmtpError> {
        match self {
            EstablishedStream::Plain(stream) => {
                let tls = dialer.start_tls(stream, target).await?;
                Ok(EstablishedStream::Tls(Box::new(tls)))
            }
            EstablishedStream::Tls(_) => Err(SmtpError::Protocol(
                "connection is already using TLS".to_string(),
            )),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, EstablishedStream::Tls(_))
    }
}

impl tokio::io::AsyncRead for EstablishedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            EstablishedStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            EstablishedStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for EstablishedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            EstablishedStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            EstablishedStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            EstablishedStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            EstablishedStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            EstablishedStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            EstablishedStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

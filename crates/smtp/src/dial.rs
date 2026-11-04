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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    StartTls,

    Implicit,
}

impl TlsMode {
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

pub const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub fn client_supported_versions() -> &'static [&'static rustls::SupportedProtocolVersion] {
    static VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
        [&rustls::version::TLS12, &rustls::version::TLS13];
    &VERSIONS
}

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
    pub fn with_webpki_roots(connect_timeout: std::time::Duration) -> Result<Self, SmtpError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder_with_protocol_versions(client_supported_versions())
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Self {
            tls_config: Arc::new(config),
            connect_timeout,
        })
    }

    pub fn with_roots(roots: rustls::RootCertStore, connect_timeout: std::time::Duration) -> Self {
        let config = ClientConfig::builder_with_protocol_versions(client_supported_versions())
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            tls_config: Arc::new(config),
            connect_timeout,
        }
    }

    pub fn from_config(config: Arc<ClientConfig>, connect_timeout: std::time::Duration) -> Self {
        Self {
            tls_config: config,
            connect_timeout,
        }
    }

    pub async fn connect(&self, target: &PinnedTarget) -> Result<TcpStream, SmtpError> {
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        let port = target.pinned.port();
        let mut last_error: Option<SmtpError> = None;

        for ip in &target.addresses {
            let addr = SocketAddr::new(*ip, port);
            match tokio::time::timeout_at(deadline, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
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

        Err(last_error.unwrap_or_else(|| {
            SmtpError::InvalidEndpoint(format!("no address to dial for {}", target.hostname))
        }))
    }

    pub async fn start_tls(
        &self,
        stream: TcpStream,
        target: &PinnedTarget,
    ) -> Result<TlsStream<TcpStream>, SmtpError> {
        let server_name = ServerName::try_from(target.hostname.clone()).map_err(|_| {
            SmtpError::InvalidEndpoint(format!("invalid TLS server name: {}", target.hostname))
        })?;

        let connector = TlsConnector::from(Arc::clone(&self.tls_config));

        match tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(result) => result.map_err(|e| {
                SmtpError::Tls(format!("TLS handshake with {}: {e}", target.hostname))
            }),
            Err(_) => Err(SmtpError::Tls(format!(
                "TLS handshake with {} timed out after {}s",
                target.hostname,
                TLS_HANDSHAKE_TIMEOUT.as_secs()
            ))),
        }
    }

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

pub enum EstablishedStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl EstablishedStream {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_tls_versions_are_explicitly_pinned_to_1_2_and_1_3() {
        let versions = client_supported_versions();
        assert_eq!(versions.len(), 2, "只允许 TLS 1.2 与 1.3");
        assert!(
            std::ptr::eq(versions[0], &rustls::version::TLS12),
            "必须显式列出 TLS 1.2"
        );
        assert!(
            std::ptr::eq(versions[1], &rustls::version::TLS13),
            "必须显式列出 TLS 1.3"
        );
    }
}

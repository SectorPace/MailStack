use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::error::{MailError, Result};
use crate::imap::session::{serve_connection, ConnectionOptions, ImapExit, ImapSessionContext};
use crate::limiter::{RateLimitConfig, RateLimiter};
use crate::metrics::Metrics;

#[derive(Debug, Clone)]
pub struct ImapServerConfig {
    pub bind: SocketAddr,

    pub implicit_tls: bool,
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub shutdown_grace: Duration,

    pub rate_limit: Option<RateLimitConfig>,
}

impl Default for ImapServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:143".parse().expect("常量地址合法"),
            implicit_tls: false,
            max_connections: 512,
            handshake_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(10),
            rate_limit: Some(RateLimitConfig::default()),
        }
    }
}

pub struct ImapServer {
    pub context: ImapSessionContext,
    pub config: ImapServerConfig,
    pub tls: Option<TlsAcceptor>,

    pub metrics: Arc<Metrics>,
}

impl ImapServer {
    pub fn new(
        context: ImapSessionContext,
        config: ImapServerConfig,
        tls: Option<TlsAcceptor>,
    ) -> Result<Self> {
        if config.max_connections == 0 {
            return Err(MailError::config("max_connections must be positive"));
        }
        if config.implicit_tls && tls.is_none() {
            return Err(MailError::config("implicit TLS requires a TlsAcceptor"));
        }
        if !config.implicit_tls && context.config.require_tls && tls.is_none() {
            return Err(MailError::config(
                "require_tls is set but neither STARTTLS nor implicit TLS is configured",
            ));
        }
        Ok(Self {
            context,
            config,
            tls,
            metrics: Arc::new(Metrics::new("imap")),
        })
    }

    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.context.metrics = Arc::clone(&metrics);
        self.metrics = metrics;
        self
    }

    pub async fn serve(self, shutdown: watch::Receiver<bool>) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.bind).await?;
        let local = listener.local_addr()?;
        tracing::info!(addr = %local, "IMAP server listening");
        self.serve_on(listener, shutdown).await
    }

    pub async fn serve_on(
        self,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        if *shutdown.borrow() {
            return Ok(());
        }
        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let limiter = self
            .config
            .rate_limit
            .clone()
            .map(|config| Arc::new(RateLimiter::new(config)));
        let clock = self.context.store.clock().clone();
        let context = Arc::new(self.context);
        let config = Arc::new(self.config);
        let tls = self.tls;
        let metrics = self.metrics;
        let mut tasks: JoinSet<()> = JoinSet::new();

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(%error, "IMAP accept failed");
                            continue;
                        }
                    };
                    if let Some(limiter) = &limiter {
                        if !limiter.allow(peer.ip(), clock.now_secs()) {
                            tracing::warn!(%peer, "IMAP connection rate limited");
                            metrics.connection_rate_limited();
                            let mut stream = stream;
                            let _ = stream
                                .write_all(b"* BYE [UNAVAILABLE] Too many connections\r\n")
                                .await;
                            continue;
                        }
                    }
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::warn!(%peer, "IMAP connection limit reached");
                            metrics.connection_busy();
                            let mut stream = stream;
                            let _ = stream
                                .write_all(b"* BYE [UNAVAILABLE] Server is busy\r\n")
                                .await;
                            continue;
                        }
                    };
                    metrics.connection_accepted();
                    let context = Arc::clone(&context);
                    let config = Arc::clone(&config);
                    let tls = tls.clone();
                    let metrics = Arc::clone(&metrics);
                    tasks.spawn(async move {
                        let _permit = permit;
                        handle_connection(stream, peer, context, config, tls, metrics).await;
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::warn!(%error, "IMAP connection task panicked");
                    }
                }
            }
        }

        let grace = config.shutdown_grace;
        if timeout(grace, async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(%error, "IMAP connection task panicked during shutdown");
                }
            }
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            tracing::warn!("IMAP connections exceeded the shutdown grace period; aborted");
        }
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    context: Arc<ImapSessionContext>,
    config: Arc<ImapServerConfig>,
    tls: Option<TlsAcceptor>,
    metrics: Arc<Metrics>,
) {
    let _active = Metrics::track_active(&metrics);
    if config.implicit_tls {
        let Some(acceptor) = tls else {
            return;
        };
        match timeout(config.handshake_timeout, acceptor.accept(stream)).await {
            Ok(Ok(stream)) => {
                let options = ConnectionOptions {
                    secured: true,
                    starttls_available: false,
                    greet: true,
                };
                match serve_connection(stream, &context, peer, options).await {
                    Ok(_) => metrics.session_completed(),
                    Err(error) => log_exit(peer, error, &metrics),
                }
            }
            Ok(Err(error)) => {
                metrics.tls_handshake_failed();
                tracing::warn!(%peer, %error, "IMAP TLS handshake failed");
            }
            Err(_) => {
                metrics.tls_handshake_timeout();
                tracing::warn!(%peer, "IMAP TLS handshake timed out");
            }
        }
        return;
    }

    let options = ConnectionOptions {
        secured: false,
        starttls_available: tls.is_some(),
        greet: true,
    };
    match serve_connection(stream, &context, peer, options).await {
        Ok(ImapExit::StartTls(stream)) => {
            let Some(acceptor) = tls else {
                return;
            };
            match timeout(config.handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let options = ConnectionOptions {
                        secured: true,
                        starttls_available: false,
                        greet: false,
                    };
                    match serve_connection(stream, &context, peer, options).await {
                        Ok(_) => metrics.session_completed(),
                        Err(error) => log_exit(peer, error, &metrics),
                    }
                }
                Ok(Err(error)) => {
                    metrics.tls_handshake_failed();
                    tracing::warn!(%peer, %error, "IMAP STARTTLS handshake failed");
                }
                Err(_) => {
                    metrics.tls_handshake_timeout();
                    tracing::warn!(%peer, "IMAP STARTTLS handshake timed out");
                }
            }
        }
        Ok(ImapExit::Logout(_)) | Ok(ImapExit::Closed(_)) => metrics.session_completed(),
        Err(error) => log_exit(peer, error, &metrics),
    }
}

fn log_exit(peer: SocketAddr, error: MailError, metrics: &Metrics) {
    if error.is_server_error() {
        metrics.session_server_error();
        tracing::warn!(%peer, error = %error, "IMAP session ended with a server error");
    } else {
        metrics.session_completed();
        tracing::debug!(%peer, error = %error, "IMAP session ended");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthBackend, MemoryDirectory, PasswordDirectory};
    use crate::imap::session::ImapConfig;
    use crate::maildir::{MailStore, SystemClock};

    fn context(require_tls: bool) -> ImapSessionContext {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(MailStore::new(directory.path(), Arc::new(SystemClock)).unwrap());

        std::mem::forget(directory);
        ImapSessionContext {
            store,
            auth: AuthBackend::new(Arc::new(PasswordDirectory::new(MemoryDirectory::new()))),
            config: ImapConfig {
                require_tls,
                ..ImapConfig::default()
            },
            metrics: Arc::new(Metrics::new("imap")),
            resolver: None,
        }
    }

    #[test]
    fn configurations_that_promise_unavailable_tls_are_refused() {
        let server = ImapServer::new(
            context(false),
            ImapServerConfig {
                implicit_tls: true,
                ..ImapServerConfig::default()
            },
            None,
        );
        assert!(server.is_err());

        let server = ImapServer::new(context(true), ImapServerConfig::default(), None);
        assert!(server.is_err(), "require_tls 但没有 TLS 能力必须拒绝启动");

        let server = ImapServer::new(
            context(false),
            ImapServerConfig {
                max_connections: 0,
                ..ImapServerConfig::default()
            },
            None,
        );
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn accepted_connections_and_active_gauge_are_counted() {
        use tokio::io::AsyncReadExt;

        let metrics = Arc::new(Metrics::new("imap"));
        let server = ImapServer::new(
            context(false),
            ImapServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                rate_limit: None,
                ..ImapServerConfig::default()
            },
            None,
        )
        .unwrap()
        .with_metrics(Arc::clone(&metrics));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move { server.serve_on(listener, shutdown_rx).await });

        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut buffer = vec![0u8; 256];
        let read = timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("* OK"));

        assert_eq!(metrics.snapshot().connections_accepted, 1);
        assert_eq!(metrics.active(), 1, "连接存活期间活动量应为 1");

        stream.write_all(b"z1 LOGOUT\r\n").await.unwrap();
        let mut sink = Vec::new();
        let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut sink)).await;
        drop(stream);

        for _ in 0..200 {
            if metrics.active() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(metrics.active(), 0, "会话结束后活动量必须归零");
        assert_eq!(metrics.snapshot().sessions_completed, 1);
        assert!(
            metrics.snapshot().commands_total >= 1,
            "LOGOUT 应计入命令指标"
        );

        shutdown_tx.send(true).unwrap();
        timeout(Duration::from_secs(10), handle)
            .await
            .expect("停机超时")
            .unwrap()
            .unwrap();
    }
}

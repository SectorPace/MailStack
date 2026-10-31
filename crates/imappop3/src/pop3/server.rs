//! POP3 监听器：连接配额、限速、隐式 TLS 与 STLS 升级。
//!
//! 结构上与 IMAP 监听器同构（见 [`crate::imap::server`]），差异只有两处：
//! POP3 没有问候语能力列表（CAPA 单独发），以及 STLS 之后**不重发**问候语。

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
use crate::limiter::{RateLimitConfig, RateLimiter};
use crate::metrics::Metrics;
use crate::pop3::session::{serve_connection, Pop3ConnectionOptions, Pop3Exit, Pop3SessionContext};

#[derive(Debug, Clone)]
pub struct Pop3ServerConfig {
    pub bind: SocketAddr,
    pub implicit_tls: bool,
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub shutdown_grace: Duration,
    pub rate_limit: Option<RateLimitConfig>,
}

impl Default for Pop3ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:110".parse().expect("常量地址合法"),
            implicit_tls: false,
            max_connections: 256,
            handshake_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(10),
            rate_limit: Some(RateLimitConfig::default()),
        }
    }
}

pub struct Pop3Server {
    pub context: Pop3SessionContext,
    pub config: Pop3ServerConfig,
    pub tls: Option<TlsAcceptor>,
    /// 传输层指标注册表。默认每个监听器一份；用 [`Pop3Server::with_metrics`] 可让
    /// 多个监听器（如 110 与 995）汇总到同一份。
    pub metrics: Arc<Metrics>,
}

impl Pop3Server {
    pub fn new(
        context: Pop3SessionContext,
        config: Pop3ServerConfig,
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
                "require_tls is set but neither STLS nor implicit TLS is configured",
            ));
        }
        Ok(Self {
            context,
            config,
            tls,
            metrics: Arc::new(Metrics::new("pop3")),
        })
    }

    /// 用一份共享的指标注册表替换默认的每实例注册表。
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub async fn serve(self, shutdown: watch::Receiver<bool>) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.bind).await?;
        let local = listener.local_addr()?;
        tracing::info!(addr = %local, "POP3 server listening");
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
                            tracing::warn!(%error, "POP3 accept failed");
                            continue;
                        }
                    };
                    if let Some(limiter) = &limiter {
                        if !limiter.allow(peer.ip(), clock.now_secs()) {
                            metrics.connection_rate_limited();
                            let mut stream = stream;
                            let _ = stream.write_all(b"-ERR [SYS/TEMP] Too many connections\r\n").await;
                            continue;
                        }
                    }
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            metrics.connection_busy();
                            let mut stream = stream;
                            let _ = stream.write_all(b"-ERR [SYS/TEMP] Server is busy\r\n").await;
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
                        tracing::warn!(%error, "POP3 connection task panicked");
                    }
                }
            }
        }

        let grace = config.shutdown_grace;
        if timeout(grace, async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(%error, "POP3 connection task panicked during shutdown");
                }
            }
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            tracing::warn!("POP3 connections exceeded the shutdown grace period; aborted");
        }
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    context: Arc<Pop3SessionContext>,
    config: Arc<Pop3ServerConfig>,
    tls: Option<TlsAcceptor>,
    metrics: Arc<Metrics>,
) {
    // 活动量表在会话结束（含 panic/提前返回）时由 guard 减回去。
    let _active = Metrics::track_active(&metrics);
    if config.implicit_tls {
        let Some(acceptor) = tls else {
            return;
        };
        match timeout(config.handshake_timeout, acceptor.accept(stream)).await {
            Ok(Ok(stream)) => {
                let options = Pop3ConnectionOptions {
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
                tracing::warn!(%peer, %error, "POP3 TLS handshake failed");
            }
            Err(_) => {
                metrics.tls_handshake_timeout();
                tracing::warn!(%peer, "POP3 TLS handshake timed out");
            }
        }
        return;
    }

    let options = Pop3ConnectionOptions {
        secured: false,
        starttls_available: tls.is_some(),
        greet: true,
    };
    match serve_connection(stream, &context, peer, options).await {
        Ok(Pop3Exit::StartTls(stream)) => {
            let Some(acceptor) = tls else {
                return;
            };
            match timeout(config.handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let options = Pop3ConnectionOptions {
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
                    tracing::warn!(%peer, %error, "POP3 STLS handshake failed");
                }
                Err(_) => {
                    metrics.tls_handshake_timeout();
                    tracing::warn!(%peer, "POP3 STLS handshake timed out");
                }
            }
        }
        Ok(Pop3Exit::Logout(_)) | Ok(Pop3Exit::Closed(_)) => metrics.session_completed(),
        Err(error) => log_exit(peer, error, &metrics),
    }
}

fn log_exit(peer: SocketAddr, error: MailError, metrics: &Metrics) {
    if error.is_server_error() {
        metrics.session_server_error();
        tracing::warn!(%peer, error = %error, "POP3 session ended with a server error");
    } else {
        metrics.session_completed();
        tracing::debug!(%peer, error = %error, "POP3 session ended");
    }
}

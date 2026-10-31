//! LMTP 监听器：连接配额、超时、优雅停机。
//!
//! 生产部署应只绑定回环地址或 Unix socket（由上游 MTA 连接），不需要公网监听；
//! 本模块提供 TCP 监听，Unix socket 由部署层按需要转发。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::error::{MailError, Result};
use crate::lmtp::session::{serve_connection, LmtpContext};
use crate::metrics::Metrics;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::net::UnixListener;

#[derive(Debug, Clone)]
pub struct LmtpServerConfig {
    pub bind: SocketAddr,
    pub max_connections: usize,
    pub shutdown_grace: Duration,
}

impl Default for LmtpServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:24".parse().expect("常量地址合法"),
            max_connections: 128,
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

pub struct LmtpServer {
    pub context: LmtpContext,
    pub config: LmtpServerConfig,
    /// 传输层指标注册表。默认每个监听器一份；用 [`LmtpServer::with_metrics`] 可让
    /// TCP 与 Unix 监听器汇总到同一份。
    pub metrics: Arc<Metrics>,
}

impl LmtpServer {
    pub fn new(context: LmtpContext, config: LmtpServerConfig) -> Result<Self> {
        if config.max_connections == 0 {
            return Err(MailError::config("max_connections must be positive"));
        }
        Ok(Self {
            context,
            config,
            metrics: Arc::new(Metrics::new("lmtp")),
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
        tracing::info!(addr = %local, "LMTP server listening");
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
        let context = Arc::new(self.context);
        let config = Arc::new(self.config);
        let metrics = self.metrics;
        let mut tasks: JoinSet<()> = JoinSet::new();

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(%error, "LMTP accept failed");
                            continue;
                        }
                    };
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            metrics.connection_busy();
                            let mut stream = stream;
                            let _ = stream.write_all(b"421 4.3.2 Server busy\r\n").await;
                            continue;
                        }
                    };
                    metrics.connection_accepted();
                    let context = Arc::clone(&context);
                    let metrics = Arc::clone(&metrics);
                    tasks.spawn(async move {
                        let _permit = permit;
                        handle_connection(stream, peer, context, metrics).await;
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::warn!(%error, "LMTP connection task panicked");
                    }
                }
            }
        }

        let grace = config.shutdown_grace;
        drain(&mut tasks, grace).await;
        Ok(())
    }

    /// 在 Unix domain socket 上提供服务（上游 MTA 走本地套接字投递）。
    ///
    /// * 先清理**残留**的套接字文件：上次崩溃会留下它，否则 `bind` 直接
    ///   `EADDRINUSE`。仅当同名路径确实是套接字时才删除；是普通文件/目录则报错，
    ///   避免误删用户数据。
    /// * `bind` 之后显式 `set_permissions(mode)`：套接字文件的默认权限受 umask 影响
    ///   不可控，而 MTA 通常以另一个用户/组连接，需要明确的 `0660`/`0600`。
    /// * 停机后删除套接字文件，保持运行目录干净。
    #[cfg(unix)]
    pub async fn serve_unix<P: AsRef<Path>>(
        self,
        path: P,
        mode: u32,
        mut shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let path = path.as_ref().to_path_buf();
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_socket() => {
                let _ = std::fs::remove_file(&path);
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            Err(_) => {}
        }
        if *shutdown.borrow() {
            return Ok(());
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        tracing::info!(path = %path.display(), "LMTP server listening on a unix socket");

        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let context = Arc::new(self.context);
        let grace = self.config.shutdown_grace;
        let metrics = self.metrics;
        let mut tasks: JoinSet<()> = JoinSet::new();

        let result: std::io::Result<()> = loop {
            tokio::select! {
                _ = shutdown.changed() => break Ok(()),
                accepted = listener.accept() => {
                    let stream = match accepted {
                        Ok((stream, _addr)) => stream,
                        Err(error) => {
                            tracing::warn!(%error, "LMTP unix accept failed");
                            continue;
                        }
                    };
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            metrics.connection_busy();
                            let mut stream = stream;
                            let _ = stream.write_all(b"421 4.3.2 Server busy\r\n").await;
                            continue;
                        }
                    };
                    metrics.connection_accepted();
                    let context = Arc::clone(&context);
                    let metrics = Arc::clone(&metrics);
                    tasks.spawn(async move {
                        let _permit = permit;
                        // Unix 套接字没有对端网络地址；用回环占位，日志里表现为本地投递。
                        let peer = SocketAddr::from(([127, 0, 0, 1], 0));
                        handle_connection(stream, peer, context, metrics).await;
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::warn!(%error, "LMTP connection task panicked");
                    }
                }
            }
        };

        drain(&mut tasks, grace).await;
        let _ = std::fs::remove_file(&path);
        result
    }
}

/// 停机时在 `grace` 内等待在途会话结束，超时则 abort。TCP 与 Unix 监听共用。
async fn drain(tasks: &mut JoinSet<()>, grace: Duration) {
    if timeout(grace, async {
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "LMTP connection task panicked during shutdown");
            }
        }
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        tracing::warn!("LMTP connections exceeded the shutdown grace period; aborted");
    }
}

async fn handle_connection<S>(
    stream: S,
    peer: SocketAddr,
    context: Arc<LmtpContext>,
    metrics: Arc<Metrics>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _active = Metrics::track_active(&metrics);
    match serve_connection(stream, &context, peer).await {
        Ok(_) => metrics.session_completed(),
        Err(error) => {
            if error.is_server_error() {
                metrics.session_server_error();
                tracing::warn!(%peer, %error, "LMTP session ended with a server error");
            } else {
                metrics.session_completed();
                tracing::debug!(%peer, %error, "LMTP session ended");
            }
        }
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use crate::lmtp::router::MapRouter;
    use crate::lmtp::session::LmtpConfig;
    use crate::maildir::{MailStore, SystemClock};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn unix_socket_greets_delivers_and_is_removed_on_shutdown() {
        let run = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MailStore::new(store_dir.path(), Arc::new(SystemClock)).unwrap());
        let mut router = MapRouter::new();
        router.insert("bob@example.com", Arc::clone(&store));
        let context = LmtpContext {
            router: Arc::new(router),
            config: LmtpConfig::default(),
            outbound: None,
        };
        let server = LmtpServer::new(
            context,
            LmtpServerConfig {
                max_connections: 4,
                ..LmtpServerConfig::default()
            },
        )
        .unwrap();

        let socket = run.path().join("lmtp.sock");
        let (tx, rx) = watch::channel(false);
        let path = socket.clone();
        let handle = tokio::spawn(async move { server.serve_unix(path, 0o600, rx).await });

        // bind 在监听任务里异步完成，轮询套接字文件出现后再连接。
        for _ in 0..400 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(socket.exists(), "socket file must appear once bound");

        let stream = UnixStream::connect(&socket)
            .await
            .expect("connect to the unix socket");
        let mut io = BufReader::new(stream);
        let mut greeting = String::new();
        io.read_line(&mut greeting).await.unwrap();
        assert!(greeting.starts_with("220 "), "greeting was {greeting:?}");

        io.get_mut().write_all(b"QUIT\r\n").await.unwrap();
        let mut bye = String::new();
        io.read_line(&mut bye).await.unwrap();
        assert!(bye.starts_with("221 "), "quit reply was {bye:?}");
        drop(io);

        tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            !socket.exists(),
            "socket file must be removed after a clean shutdown"
        );
    }

    #[tokio::test]
    async fn unix_socket_refuses_to_clobber_a_regular_file() {
        let run = tempfile::tempdir().unwrap();
        let socket = run.path().join("lmtp.sock");
        std::fs::write(&socket, b"important data\n").unwrap();

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MailStore::new(store_dir.path(), Arc::new(SystemClock)).unwrap());
        let mut router = MapRouter::new();
        router.insert("bob@example.com", store);
        let server = LmtpServer::new(
            LmtpContext {
                router: Arc::new(router),
                config: LmtpConfig::default(),
                outbound: None,
            },
            LmtpServerConfig::default(),
        )
        .unwrap();

        let (_tx, rx) = watch::channel(false);
        let error = server
            .serve_unix(&socket, 0o600, rx)
            .await
            .expect_err("a non-socket path must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&socket).unwrap(),
            b"important data\n",
            "the pre-existing file must be left untouched"
        );
    }
}

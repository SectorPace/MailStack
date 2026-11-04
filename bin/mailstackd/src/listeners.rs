use std::sync::Arc;

use mailstack_smtpd::{
    tls_acceptor, AuthBackend, BanList, Clock, DirectoryRecipients, MailServer,
    MailboxPasswordsAuthenticator, MessageSink, RateLimiter, ServerConfig, SessionConfig, TlsMode,
};
use mailstack_store::LocalRecipients;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::{ListenerPlan, RuntimeConfig};
use crate::error::DaemonError;

fn load_tls(config: &RuntimeConfig) -> Result<TlsAcceptor, DaemonError> {
    Ok(tls_acceptor(
        &config.cert_paths.cert,
        &config.cert_paths.key,
    )?)
}

pub async fn bind_all<S>(
    config: &RuntimeConfig,
    sink: Arc<S>,
    clock: Arc<dyn Clock>,
    rate: Arc<RateLimiter>,
    bans: Arc<BanList>,
) -> Result<Vec<(u16, MailServer<S>)>, DaemonError>
where
    S: MessageSink + ?Sized + 'static,
{
    let tls = load_tls(config)?;

    let mut bound = Vec::with_capacity(config.listeners.len());
    for plan in &config.listeners {
        let addr = crate::config::listen_addr(plan.port);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| DaemonError::Bind {
                port: plan.port,
                source,
            })?;
        bound.push((*plan, listener));
    }

    let mut servers = Vec::with_capacity(bound.len());
    for (plan, listener) in bound {
        let server = build_server(
            listener,
            config,
            plan,
            Some(tls.clone()),
            Arc::clone(&sink),
            Arc::clone(&clock),
            Arc::clone(&rate),
            Arc::clone(&bans),
        )?;
        servers.push((plan.port, server));
    }
    Ok(servers)
}

#[allow(clippy::too_many_arguments)]
pub fn build_server<S>(
    listener: TcpListener,
    config: &RuntimeConfig,
    plan: ListenerPlan,
    tls: Option<TlsAcceptor>,
    sink: Arc<S>,
    clock: Arc<dyn Clock>,
    rate: Arc<RateLimiter>,
    bans: Arc<BanList>,
) -> Result<MailServer<S>, DaemonError>
where
    S: MessageSink + ?Sized + 'static,
{
    let session = SessionConfig {
        offer_starttls: plan.offer_starttls,
        tls_active: plan.mode == TlsMode::Implicit,
        offer_auth: plan.offer_auth,
        require_auth_for_submission: plan.require_auth_for_submission,
        ..config.session.clone()
    };
    let server_config = ServerConfig {
        session,
        relay: config.relay_policy.clone(),
        rate_limit: config.rate_limit,
        ban: config.ban,

        auth: plan
            .offer_auth
            .then(|| AuthBackend::new(Arc::new(MailboxPasswordsAuthenticator::at(&config.paths)))),

        recipients: Some(Arc::new(DirectoryRecipients::new(LocalRecipients::new(
            &config.paths,
        )))),
        ..ServerConfig::default()
    };

    let server = MailServer::with_shared(
        listener,
        server_config,
        tls,
        plan.mode,
        sink,
        clock,
        rate,
        bans,
    )?;
    tracing::info!(port = plan.port, mode = ?plan.mode, "监听已就绪");
    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_PORTS;
    use crate::shutdown::Shutdown;
    use mailstack_core::Paths;
    use mailstack_smtpd::{AcceptedMessage, BanConfig, RateLimitConfig, SinkFuture, SystemClock};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SETUP: &str = r#"{
  "domain": "example.org",
  "mailHost": "mail.example.org",
  "serverIp": "203.0.113.10",
  "dkimSelector": "mailstack",
  "updatedAt": "2026-10-01T00:00:00Z"
}"#;

    #[derive(Default)]
    struct RecordingSink {
        accepted: Mutex<Vec<AcceptedMessage>>,
    }

    impl MessageSink for RecordingSink {
        fn accept<'a>(&'a self, message: AcceptedMessage, _peer: SocketAddr) -> SinkFuture<'a> {
            Box::pin(async move {
                self.accepted.lock().unwrap().push(message);
                Ok(())
            })
        }
    }

    fn test_config() -> (tempfile::TempDir, RuntimeConfig) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        std::fs::create_dir_all(paths.etc.clone()).unwrap();
        std::fs::create_dir_all(paths.postfix.clone()).unwrap();
        std::fs::write(&paths.setup_config, SETUP).unwrap();
        std::fs::write(&paths.domains, "example.org ok\n").unwrap();
        let config = crate::config::assemble(paths, DEFAULT_PORTS).expect("装配配置");
        (dir, config)
    }

    #[tokio::test]
    async fn binding_is_refused_when_the_tls_material_is_missing() {
        let (_dir, config) = test_config();
        let sink = Arc::new(RecordingSink::default());
        let error = bind_all(
            &config,
            sink,
            Arc::new(SystemClock),
            Arc::new(RateLimiter::new(RateLimitConfig::default())),
            Arc::new(BanList::new(BanConfig::default())),
        )
        .await
        .err()
        .expect("缺少证书必须拒绝启动");
        assert!(matches!(error, DaemonError::Tls(_)), "实际：{error:?}");
    }

    async fn read_reply(stream: &mut tokio::net::TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            if let Some(end) = reply_end(&buffer) {
                return String::from_utf8_lossy(&buffer[..end]).to_string();
            }
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
                .await
                .expect("读取应答超时")
                .expect("读取失败");
            assert!(
                read > 0,
                "连接在应答结束前关闭：{:?}",
                String::from_utf8_lossy(&buffer)
            );
            buffer.extend_from_slice(&chunk[..read]);
        }
    }

    fn reply_end(bytes: &[u8]) -> Option<usize> {
        let mut offset = 0;
        loop {
            let rest = &bytes[offset..];
            let newline = rest.iter().position(|&byte| byte == b'\n')?;
            let line = &rest[..=newline];
            offset += newline + 1;
            if line.get(3) == Some(&b' ') {
                return Some(offset);
            }
        }
    }

    #[tokio::test]
    async fn a_bound_server_serves_a_session_and_stops_on_the_shutdown_signal() {
        let (_dir, config) = test_config();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let sink = Arc::new(RecordingSink::default());
        let server = build_server(
            listener,
            &config,
            ListenerPlan {
                port: 0,
                mode: TlsMode::StartTls,
                offer_starttls: false,
                offer_auth: false,
                require_auth_for_submission: false,
            },
            None,
            Arc::clone(&sink),
            Arc::new(SystemClock),
            Arc::new(RateLimiter::new(RateLimitConfig::default())),
            Arc::new(BanList::new(BanConfig::default())),
        )
        .expect("构造监听");

        let shutdown = Shutdown::channel();
        let waiter = shutdown.waiter();
        let handle = tokio::spawn(async move { server.run(waiter).await });

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("连接");
        let greeting = read_reply(&mut stream).await;
        assert!(greeting.starts_with("220 "), "{greeting}");

        stream.write_all(b"EHLO client.test\r\n").await.unwrap();
        let ehlo = read_reply(&mut stream).await;
        assert!(ehlo.starts_with("250"), "{ehlo}");
        assert!(
            !ehlo.contains("STARTTLS"),
            "未装载 TLS 时不得通告 STARTTLS：{ehlo}"
        );

        stream.write_all(b"QUIT\r\n").await.unwrap();
        assert!(read_reply(&mut stream).await.starts_with("221 "));

        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("停机信号必须让监听退出")
            .expect("任务不得 panic")
            .expect("监听不应返回 I/O 错误");
    }
}

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mailstack_auth::TxtCache;
use mailstack_queue::QueueStore;
use mailstack_smtp::RelayPolicy;
use mailstack_smtpd::{
    AcceptedMessage, AuthBackend, DovecotAuthClient, MessageSink, QueueSink, ServerConfig,
    SessionConfig, SinkFuture, SystemClock, TlsMode,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const TLS_HOSTNAME: &str = "localhost";

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

impl RecordingSink {
    fn count(&self) -> usize {
        self.accepted.lock().unwrap().len()
    }
}

struct Client<S> {
    stream: S,
    buffered: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            buffered: Vec::new(),
        }
    }

    fn into_inner(self) -> (S, Vec<u8>) {
        (self.stream, self.buffered)
    }

    async fn send(&mut self, data: &str) {
        self.stream.write_all(data.as_bytes()).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    async fn read_reply(&mut self) -> String {
        loop {
            if let Some((reply, consumed)) = take_reply(&self.buffered) {
                self.buffered.drain(..consumed);
                return reply;
            }
            let mut chunk = [0u8; 1024];
            let read = tokio::time::timeout(Duration::from_secs(5), self.stream.read(&mut chunk))
                .await
                .expect("读取应答超时")
                .expect("读取应答失败");
            assert!(
                read > 0,
                "连接在应答结束前关闭，已缓冲：{:?}",
                String::from_utf8_lossy(&self.buffered)
            );
            self.buffered.extend_from_slice(&chunk[..read]);
        }
    }
}

fn take_reply(buffer: &[u8]) -> Option<(String, usize)> {
    let mut offset = 0;
    let mut out = String::new();
    loop {
        let rest = &buffer[offset..];
        let newline = rest.iter().position(|&byte| byte == b'\n')?;
        let line = &rest[..=newline];
        out.push_str(&String::from_utf8_lossy(line));
        offset += newline + 1;
        if line.get(3) == Some(&b' ') {
            return Some((out, offset));
        }
    }
}

struct TestPki {
    ca_der: CertificateDer<'static>,
    cert_dir: tempfile::TempDir,
}

impl TestPki {
    fn generate() -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "MailStack Test CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut params = CertificateParams::new(vec![TLS_HOSTNAME.to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, TLS_HOSTNAME);
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        std::fs::write(dir.path().join("fullchain.pem"), &cert_pem).unwrap();
        std::fs::write(dir.path().join("privkey.pem"), &key_pem).unwrap();

        Self {
            ca_der: ca_cert.der().clone(),
            cert_dir: dir,
        }
    }

    fn acceptor(&self) -> TlsAcceptor {
        let cert = self.cert_dir.path().join("fullchain.pem");
        let key = self.cert_dir.path().join("privkey.pem");
        mailstack_smtpd::tls_acceptor(&cert, &key).expect("装载 TLS 材料")
    }

    fn client_config(&self) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_der.clone()).unwrap();
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn tls12_client_config(&self) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_der.clone()).unwrap();
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn connector(&self, config: ClientConfig) -> TlsConnector {
        TlsConnector::from(Arc::new(config))
    }

    fn server_name(&self) -> ServerName<'static> {
        ServerName::try_from(TLS_HOSTNAME).unwrap()
    }
}

fn base_config() -> ServerConfig {
    ServerConfig {
        session: SessionConfig {
            hostname: "mx.mailstack.test".to_string(),
            postmaster: Some("postmaster@example.org".to_string()),
            ..SessionConfig::default()
        },
        relay: RelayPolicy::new(["example.org"]),
        max_connections: 16,
        shutdown_grace: Duration::from_millis(200),
        ..ServerConfig::default()
    }
}

struct Harness {
    addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
}

impl Harness {
    async fn connect(&self) -> Client<TcpStream> {
        let stream = TcpStream::connect(self.addr).await.expect("连接服务端");
        Client::new(stream)
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
    }
}

async fn spawn<S: MessageSink + 'static>(
    config: ServerConfig,
    tls: Option<TlsAcceptor>,
    mode: TlsMode,
    sink: Arc<S>,
) -> Harness {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server =
        mailstack_smtpd::MailServer::new(listener, config, tls, mode, sink, Arc::new(SystemClock))
            .expect("构造服务端");
    let (shutdown, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let _ = server
            .run(async move {
                let _ = receiver.await;
            })
            .await;
    });
    Harness { addr, shutdown }
}

async fn run_transaction<S: AsyncRead + AsyncWrite + Unpin>(client: &mut Client<S>) {
    let greeting = client.read_reply().await;
    assert!(greeting.starts_with("220 "), "{greeting}");

    client.send("EHLO client.test\r\n").await;
    let reply = client.read_reply().await;
    assert!(reply.starts_with("250"), "{reply}");

    client.send("MAIL FROM:<alice@remote.test>\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));

    client.send("RCPT TO:<bob@example.org>\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));

    client.send("DATA\r\n").await;
    assert!(client.read_reply().await.starts_with("354"));

    client.send("Subject: hi\r\n\r\nbody\r\n.\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));

    client.send("QUIT\r\n").await;
    assert!(client.read_reply().await.starts_with("221"));
}

#[tokio::test]
async fn a_full_transaction_over_real_tcp_reaches_the_sink() {
    let sink = Arc::new(RecordingSink::default());
    let harness = spawn(base_config(), None, TlsMode::StartTls, Arc::clone(&sink)).await;

    let mut client = harness.connect().await;
    run_transaction(&mut client).await;

    assert_eq!(sink.count(), 1, "整封邮件应交到 sink");
    harness.stop();
}

#[tokio::test]
async fn starttls_upgrades_in_place_and_the_session_restarts_at_ehlo() {
    let pki = TestPki::generate();
    let sink = Arc::new(RecordingSink::default());
    let mut config = base_config();
    config.session.offer_starttls = true;

    let harness = spawn(
        config,
        Some(pki.acceptor()),
        TlsMode::StartTls,
        Arc::clone(&sink),
    )
    .await;

    let mut client = harness.connect().await;
    assert!(client.read_reply().await.starts_with("220 "));
    client.send("EHLO client.test\r\n").await;
    let ehlo = client.read_reply().await;
    assert!(
        ehlo.contains("STARTTLS"),
        "未加密的会话必须通告 STARTTLS：{ehlo}"
    );

    client.send("STARTTLS\r\n").await;
    assert!(client.read_reply().await.starts_with("220 "));

    let (stream, leftover) = client.into_inner();
    assert!(leftover.is_empty(), "升级前不应有未消费的明文");
    let tls = pki
        .connector(pki.client_config())
        .connect(pki.server_name(), stream)
        .await
        .expect("STARTTLS 握手应成功");
    let mut client = Client::new(tls);

    client.send("EHLO client.test\r\n").await;
    let ehlo = client.read_reply().await;
    assert!(ehlo.starts_with("250"), "{ehlo}");
    assert!(
        !ehlo.contains("STARTTLS"),
        "已加密后不得再通告 STARTTLS：{ehlo}"
    );

    client.send("MAIL FROM:<alice@remote.test>\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("RCPT TO:<bob@example.org>\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("DATA\r\n").await;
    assert!(client.read_reply().await.starts_with("354"));
    client.send("Subject: over tls\r\n\r\nbody\r\n.\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("QUIT\r\n").await;
    assert!(client.read_reply().await.starts_with("221"));

    assert_eq!(sink.count(), 1);
    harness.stop();
}

#[tokio::test]
async fn a_client_that_only_speaks_tls12_can_still_connect() {
    let pki = TestPki::generate();
    let sink = Arc::new(RecordingSink::default());
    let harness = spawn(
        base_config(),
        Some(pki.acceptor()),
        TlsMode::Implicit,
        Arc::clone(&sink),
    )
    .await;

    let stream = TcpStream::connect(harness.addr).await.unwrap();
    let tls = pki
        .connector(pki.tls12_client_config())
        .connect(pki.server_name(), stream)
        .await
        .expect("仅支持 TLS 1.2 的客户端应当被接受");
    let mut client = Client::new(tls);
    assert!(client.read_reply().await.starts_with("220 "));
    harness.stop();
}

#[tokio::test]
async fn implicit_tls_handshakes_before_the_greeting() {
    let pki = TestPki::generate();
    let sink = Arc::new(RecordingSink::default());
    let harness = spawn(
        base_config(),
        Some(pki.acceptor()),
        TlsMode::Implicit,
        Arc::clone(&sink),
    )
    .await;

    let stream = TcpStream::connect(harness.addr).await.unwrap();
    let tls = pki
        .connector(pki.client_config())
        .connect(pki.server_name(), stream)
        .await
        .expect("隐式 TLS 握手应成功");
    let mut client = Client::new(tls);
    let greeting = client.read_reply().await;
    assert!(greeting.starts_with("220 "), "{greeting}");
    harness.stop();
}

#[tokio::test]
async fn connections_beyond_the_burst_are_refused_with_421() {
    let sink = Arc::new(RecordingSink::default());
    let mut config = base_config();

    config.rate_limit.burst = 2;
    config.rate_limit.refill_per_second = 0.001;
    let harness = spawn(config, None, TlsMode::StartTls, Arc::clone(&sink)).await;

    for _ in 0..2 {
        let mut client = harness.connect().await;
        assert!(client.read_reply().await.starts_with("220 "));
    }
    let mut client = harness.connect().await;
    let reply = client.read_reply().await;
    assert!(reply.starts_with("421 "), "超速的连接必须被拒：{reply}");
    assert!(reply.contains("Too many connections"), "{reply}");
    harness.stop();
}

#[tokio::test]
async fn repeated_rate_limit_triggers_ban_the_address() {
    let sink = Arc::new(RecordingSink::default());
    let mut config = base_config();
    config.rate_limit.burst = 1;
    config.rate_limit.refill_per_second = 0.001;
    config.ban.max_failures = 2;
    config.ban.permanent_after = 0;
    config.ban.temp_ban_secs = 300;
    let harness = spawn(config, None, TlsMode::StartTls, Arc::clone(&sink)).await;

    let mut first = harness.connect().await;
    assert!(first.read_reply().await.starts_with("220 "));

    for _ in 0..2 {
        let mut client = harness.connect().await;
        assert!(client.read_reply().await.starts_with("421 "));
    }

    let mut client = harness.connect().await;
    let reply = client.read_reply().await;
    assert!(reply.starts_with("421 "), "{reply}");
    assert!(
        reply.contains("blocked"),
        "触发限速累积到阈值后必须封禁：{reply}"
    );
    harness.stop();
}

#[tokio::test]
async fn tls_handshake_failures_do_not_get_the_peer_banned() {
    let pki = TestPki::generate();
    let sink = Arc::new(RecordingSink::default());
    let mut config = base_config();

    config.rate_limit.burst = 100;
    config.rate_limit.refill_per_second = 100.0;
    config.ban.max_failures = 2;
    config.ban.permanent_after = 0;
    config.ban.temp_ban_secs = 300;

    let harness = spawn(
        config,
        Some(pki.acceptor()),
        TlsMode::Implicit,
        Arc::clone(&sink),
    )
    .await;

    for _ in 0..4 {
        let mut stream = TcpStream::connect(harness.addr).await.unwrap();
        let _ = stream
            .write_all(b"this is not a TLS ClientHello\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        drop(stream);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let stream = TcpStream::connect(harness.addr).await.unwrap();
    let tls = pki
        .connector(pki.client_config())
        .connect(pki.server_name(), stream)
        .await
        .expect("握手失败不得连坐正常客户端");
    let mut client = Client::new(tls);
    let reply = client.read_reply().await;
    assert!(
        reply.starts_with("220 "),
        "TLS 握手失败不得触发封禁（实际应答：{reply}）"
    );
    harness.stop();
}

async fn serve_fake_dovecot(listener: UnixListener, accept: bool) {
    let (stream, _) = listener.accept().await.expect("接受认证连接");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half
        .write_all(b"VERSION\t1\t2\nSPID\t1\nCUID\t1\nMECH\tPLAIN\nMECH\tLOGIN\nDONE\n")
        .await
        .unwrap();

    let mut auth_line = String::new();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await.expect("读认证请求");
        if read == 0 {
            break;
        }
        if line.starts_with("AUTH\t") {
            auth_line = line;
            break;
        }
    }
    assert!(
        auth_line.contains("\tservice=smtp\t"),
        "必须声明 service=smtp：{auth_line:?}"
    );
    assert!(
        auth_line.contains("\tresp="),
        "必须把 base64 应答放进 resp 字段：{auth_line:?}"
    );
    assert!(
        auth_line.contains("\tsecured=tls"),
        "TLS 之上必须如实声明 secured：{auth_line:?}"
    );

    let reply = if accept {
        "OK\t1\tuser=alice@example.org\n"
    } else {
        "FAIL\t1\ttemp\treason=backend+down\n"
    };
    write_half.write_all(reply.as_bytes()).await.unwrap();
    write_half.flush().await.unwrap();
}

#[tokio::test]
async fn a_submission_over_implicit_tls_authenticates_against_a_dovecot_auth_socket() {
    let pki = TestPki::generate();
    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("auth-client");
    let dovecot = UnixListener::bind(&socket_path).expect("绑定假 auth socket");
    let fake = tokio::spawn(serve_fake_dovecot(dovecot, true));

    let mut config = base_config();
    config.session.offer_auth = true;
    config.auth = Some(AuthBackend::new(Arc::new(
        DovecotAuthClient::new(&socket_path).with_timeout(Duration::from_secs(5)),
    )));

    let sink = Arc::new(RecordingSink::default());
    let harness = spawn(
        config,
        Some(pki.acceptor()),
        TlsMode::Implicit,
        Arc::clone(&sink),
    )
    .await;

    let tcp = TcpStream::connect(harness.addr).await.expect("连接");
    let tls = pki
        .connector(pki.client_config())
        .connect(ServerName::try_from(TLS_HOSTNAME).unwrap(), tcp)
        .await
        .expect("TLS 握手");
    let mut client = Client::new(tls);

    assert!(client.read_reply().await.starts_with("220 "));

    client.send("EHLO client.test\r\n").await;
    let ehlo = client.read_reply().await;
    assert!(
        ehlo.contains("AUTH PLAIN"),
        "隐式 TLS 上必须通告 AUTH PLAIN：{ehlo}"
    );

    client.send("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n").await;
    let auth = client.read_reply().await;
    assert!(auth.starts_with("235 "), "认证应成功：{auth}");

    client.send("MAIL FROM:<alice@example.org>\r\n").await;
    assert!(client.read_reply().await.starts_with("250 "));
    client.send("RCPT TO:<bob@gmail.com>\r\n").await;
    let rcpt = client.read_reply().await;
    assert!(rcpt.starts_with("250 "), "认证后应允许向外部域提交：{rcpt}");

    client.send("DATA\r\n").await;
    assert!(client.read_reply().await.starts_with("354 "));
    client.send("Subject: hi\r\n\r\nbody\r\n.\r\n").await;
    assert!(client.read_reply().await.starts_with("250 "));

    client.send("QUIT\r\n").await;
    assert!(client.read_reply().await.starts_with("221 "));

    fake.await.expect("假 Dovecot 任务不应 panic");
    assert_eq!(sink.count(), 1, "认证后的提交应被投递");
    harness.stop();
}

#[tokio::test]
async fn a_dovecot_temporary_failure_surfaces_as_454_and_keeps_the_peer_unauthenticated() {
    let pki = TestPki::generate();
    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("auth-client");
    let dovecot = UnixListener::bind(&socket_path).expect("绑定假 auth socket");
    let fake = tokio::spawn(serve_fake_dovecot(dovecot, false));

    let mut config = base_config();
    config.session.offer_auth = true;
    config.auth = Some(AuthBackend::new(Arc::new(
        DovecotAuthClient::new(&socket_path).with_timeout(Duration::from_secs(5)),
    )));

    let harness = spawn(
        config,
        Some(pki.acceptor()),
        TlsMode::Implicit,
        Arc::new(RecordingSink::default()),
    )
    .await;

    let tcp = TcpStream::connect(harness.addr).await.expect("连接");
    let tls = pki
        .connector(pki.client_config())
        .connect(ServerName::try_from(TLS_HOSTNAME).unwrap(), tcp)
        .await
        .expect("TLS 握手");
    let mut client = Client::new(tls);
    assert!(client.read_reply().await.starts_with("220 "));

    client.send("EHLO client.test\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n").await;
    let auth = client.read_reply().await;
    assert!(auth.starts_with("454 "), "后端抖动应回 454：{auth}");
    assert!(!auth.starts_with("535"), "后端不可达不得说成凭据错：{auth}");

    client.send("MAIL FROM:<alice@example.org>\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("RCPT TO:<bob@gmail.com>\r\n").await;
    let rcpt = client.read_reply().await;
    assert!(rcpt.starts_with("554 "), "认证未成功时不得中继：{rcpt}");

    fake.await.expect("假 Dovecot 任务不应 panic");
    harness.stop();
}

#[tokio::test]
async fn contradictory_tls_configuration_is_refused_at_construction() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink = Arc::new(RecordingSink::default());
    let error = mailstack_smtpd::MailServer::new(
        listener,
        base_config(),
        None,
        TlsMode::Implicit,
        Arc::clone(&sink),
        Arc::new(SystemClock),
    )
    .err()
    .expect("隐式 TLS 缺少材料应被拒绝");
    assert_eq!(
        error,
        mailstack_smtpd::ConfigError::ImplicitTlsWithoutAcceptor
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = base_config();
    config.session.offer_starttls = true;
    let error = mailstack_smtpd::MailServer::new(
        listener,
        config,
        None,
        TlsMode::StartTls,
        Arc::clone(&sink),
        Arc::new(SystemClock),
    )
    .err()
    .expect("通告 STARTTLS 却没有材料应被拒绝");
    assert_eq!(
        error,
        mailstack_smtpd::ConfigError::StartTlsAdvertisedWithoutAcceptor
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = base_config();
    config.session.offer_auth = true;
    config.auth = None;
    let error = mailstack_smtpd::MailServer::new(
        listener,
        config,
        None,
        TlsMode::StartTls,
        Arc::clone(&sink),
        Arc::new(SystemClock),
    )
    .err()
    .expect("通告 AUTH 却没有后端应被拒绝");
    assert_eq!(
        error,
        mailstack_smtpd::ConfigError::AuthAdvertisedWithoutAuthenticator
    );
}

#[tokio::test]
async fn a_verified_message_enters_the_queue_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let cache = TxtCache::new();

    cache.pin_dmarc_walk("example.com");

    cache.pin_absent("client.test");
    cache
        .add_spf("example.com", b"v=spf1 ip4:127.0.0.1 -all")
        .unwrap();
    cache
        .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject")
        .unwrap();
    let sink = Arc::new(QueueSink::new(
        "mx.mailstack.test",
        mailstack_auth::system_resolver().expect("构造系统解析器"),
        cache,
        QueueStore::new(dir.path()),
        Arc::new(SystemClock),
    ));

    let harness = spawn(base_config(), None, TlsMode::StartTls, Arc::clone(&sink)).await;

    let mut client = harness.connect().await;
    assert!(client.read_reply().await.starts_with("220 "));
    client.send("EHLO client.test\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("MAIL FROM:<alice@example.com>\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("RCPT TO:<bob@example.org>\r\n").await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("DATA\r\n").await;
    assert!(client.read_reply().await.starts_with("354"));
    client
        .send("From: alice@example.com\r\nSubject: e2e\r\n\r\nbody\r\n.\r\n")
        .await;
    assert!(client.read_reply().await.starts_with("250"));
    client.send("QUIT\r\n").await;
    assert!(client.read_reply().await.starts_with("221"));
    harness.stop();

    let entries = QueueStore::new(dir.path()).load_all().expect("读取队列");
    assert_eq!(entries.len(), 1, "通过认证的邮件必须入队");

    assert!(
        entries[0].data.starts_with("Received: from client.test"),
        "入站必须写 Received 头：{}",
        &entries[0].data[..entries[0].data.len().min(160)]
    );
    assert!(
        entries[0].data.contains("Return-Path: <alice@example.com>"),
        "入站必须写 Return-Path：{}",
        entries[0].data
    );
    assert!(
        entries[0]
            .data
            .contains("Authentication-Results: mx.mailstack.test;"),
        "认证结论必须存在：{}",
        &entries[0].data[..entries[0].data.len().min(200)]
    );
    assert!(
        entries[0].data.contains("dmarc=pass"),
        "{}",
        entries[0].data
    );
}

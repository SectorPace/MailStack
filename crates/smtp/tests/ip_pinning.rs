use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use mailstack_smtp::dial::{PinnedDialer, TlsMode};
use mailstack_smtp::target::{pinned_from_addresses, AddressPolicy, PinnedTarget};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const RELAY_HOSTNAME: &str = "relay.example.test";
const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

struct TestPki {
    ca_der: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
}

fn generate_pki() -> TestPki {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

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

    let mut server_params = CertificateParams::new(vec![RELAY_HOSTNAME.to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, RELAY_HOSTNAME);
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    TestPki {
        ca_der: ca_cert.der().clone(),
        server_chain: vec![server_cert.der().clone()],
        server_key: PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
    }
}

impl TestPki {
    fn dialer(&self) -> PinnedDialer {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca_der.clone()).unwrap();
        PinnedDialer::with_roots(roots, Duration::from_secs(5))
    }
}

async fn spawn_tls_server(pki: &TestPki) -> (u16, tokio::sync::oneshot::Receiver<Option<String>>) {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(pki.server_chain.clone(), pki.server_key.clone_key())
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let mut seen_sni = None;
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(tls) = acceptor.accept(stream).await {
                let (_io, conn) = tls.get_ref();
                seen_sni = conn.server_name().map(|s| s.to_string());

                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        let _ = tx.send(seen_sni);
    });

    (port, rx)
}

fn pinned_loopback(hostname: &str, port: u16) -> PinnedTarget {
    pinned_from_addresses(
        hostname,
        port,
        vec![LOOPBACK],
        AddressPolicy::allow_private(),
    )
    .unwrap()
}

#[tokio::test]
async fn dials_the_pinned_ip_while_verifying_the_original_hostname() {
    let pki = generate_pki();
    let (port, sni_rx) = spawn_tls_server(&pki).await;

    let dialer = pki.dialer();
    let target = pinned_loopback(RELAY_HOSTNAME, port);

    let dial_addr: SocketAddr = target.dial_addr();
    assert_eq!(dial_addr.ip(), LOOPBACK);

    let stream = dialer.connect(&target).await.expect("应以固定 IP 建连");
    let tls = dialer
        .start_tls(stream, &target)
        .await
        .expect("SNI/证书校验应使用原域名并成功");

    let seen_sni = sni_rx.await.unwrap();
    assert_eq!(
        seen_sni.as_deref(),
        Some(RELAY_HOSTNAME),
        "SNI 必须是原域名，而不是被拨号的 IP —— 这正是 DNS rebinding 防护的形态"
    );

    drop(tls);
}

#[tokio::test]
async fn certificate_verification_is_actually_enforced() {
    let server_pki = generate_pki();
    let (port, _sni_rx) = spawn_tls_server(&server_pki).await;

    let unrelated_pki = generate_pki();
    let dialer = unrelated_pki.dialer();

    let target = pinned_loopback(RELAY_HOSTNAME, port);
    let stream = dialer.connect(&target).await.expect("TCP 层仍应连上");
    let result = dialer.start_tls(stream, &target).await;

    assert!(
        result.is_err(),
        "信任库不含签发者时必须拒绝 —— 否则证书校验形同虚设"
    );
}

#[tokio::test]
async fn wrong_sni_fails_verification() {
    let pki = generate_pki();
    let (port, _sni_rx) = spawn_tls_server(&pki).await;
    let dialer = pki.dialer();

    let wrong = pinned_loopback("wrong.example.test", port);
    let stream = dialer.connect(&wrong).await.expect("TCP 层仍应连上");
    let result = dialer.start_tls(stream, &wrong).await;

    assert!(
        result.is_err(),
        "SNI 与证书 SAN 不匹配时必须拒绝，实际却成功了"
    );
}

#[tokio::test]
async fn pinned_target_never_carries_a_hostname_into_the_dial_path() {
    let target = pinned_loopback(RELAY_HOSTNAME, 443);
    let addr = target.dial_addr();
    assert!(addr.ip().is_ipv4() || addr.ip().is_ipv6());
    assert_eq!(addr.port(), 443);
    assert!(!addr.to_string().contains(RELAY_HOSTNAME));

    assert_eq!(target.hostname, RELAY_HOSTNAME);
    assert_eq!(target.addresses, vec![LOOPBACK]);
}

#[tokio::test]
async fn implicit_tls_mode_connects_and_handshakes_in_one_step() {
    let pki = generate_pki();
    let (port, sni_rx) = spawn_tls_server(&pki).await;
    let dialer = pki.dialer();
    let target = pinned_loopback(RELAY_HOSTNAME, port);

    let stream = dialer
        .connect_with_mode(&target, TlsMode::Implicit)
        .await
        .expect("隐式 TLS 应一步完成建连与握手");
    assert!(stream.is_encrypted(), "隐式 TLS 之后流必须已加密");

    assert_eq!(sni_rx.await.unwrap().as_deref(), Some(RELAY_HOSTNAME));
}

#[tokio::test]
async fn starttls_mode_returns_a_plaintext_stream_first() {
    let pki = generate_pki();
    let (port, _sni_rx) = spawn_tls_server(&pki).await;
    let dialer = pki.dialer();
    let target = pinned_loopback(RELAY_HOSTNAME, port);

    let stream = dialer
        .connect_with_mode(&target, TlsMode::StartTls)
        .await
        .expect("应以明文建连");
    assert!(
        !stream.is_encrypted(),
        "STARTTLS 模式下建连阶段必须是明文，否则会与 EHLO 流程冲突"
    );
}

#[tokio::test]
async fn upgrading_twice_is_rejected() {
    let pki = generate_pki();
    let (port, _sni_rx) = spawn_tls_server(&pki).await;
    let dialer = pki.dialer();
    let target = pinned_loopback(RELAY_HOSTNAME, port);

    let stream = dialer
        .connect_with_mode(&target, TlsMode::Implicit)
        .await
        .unwrap();
    let again = stream.upgrade(&dialer, &target).await;
    assert!(again.is_err(), "重复升级必须被拒绝");
}

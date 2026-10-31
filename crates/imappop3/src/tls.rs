//! IMAP/POP3 的 TLS 材料装载与版本策略。
//!
//! 与 `mailstack-smtpd::tls` 同一套策略（rustls + ring、**TLS 1.2 起**），但刻意
//! 不跨 crate 复用：`smtpd` 依赖 `queue`/`store`，让邮箱服务依赖发信服务会形成
//! 一条没有必要的编译边。重复的只有 60 行装载代码，语义漂移风险由两边的
//! `only_tls_12_and_13_are_offered` 测试各自钉住。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
// 公开重导出：`acceptor()` 的返回类型出现在公共 API 上，调用方（部署层
// `crates/imapd`）必须能命名它才能跨多个监听器共享同一个 acceptor。
pub use tokio_rustls::TlsAcceptor;

/// 允许协商的版本：只有 1.2 与 1.3。显式列出而不是依赖库默认值 —— 策略要可测。
pub fn supported_versions() -> &'static [&'static rustls::SupportedProtocolVersion] {
    static VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
        [&rustls::version::TLS12, &rustls::version::TLS13];
    &VERSIONS
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// STARTTLS 升级前后、隐式 TLS 前后统一的流类型。
pub type BoxedStream = Box<dyn AsyncStream>;

/// 明文建连 + STARTTLS，还是建连即握手（993 / 995）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    StartTls,
    Implicit,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("无法读取 TLS 材料 {path}: {message}")]
    Material { path: PathBuf, message: String },
    #[error("证书文件 {0} 不含任何证书")]
    NoCertificates(PathBuf),
    #[error("TLS 配置被拒绝: {0}")]
    Config(String),
}

/// 装载证书链（PEM，可含中间证书）。
fn load_cert_chain(cert_path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|error| TlsError::Material {
            path: cert_path.to_path_buf(),
            message: error.to_string(),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TlsError::Material {
            path: cert_path.to_path_buf(),
            message: error.to_string(),
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(cert_path.to_path_buf()));
    }
    Ok(certs)
}

/// 装载私钥（PKCS#8 / PKCS#1 / SEC1）。
fn load_key(key_path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_file(key_path).map_err(|error| TlsError::Material {
        path: key_path.to_path_buf(),
        message: error.to_string(),
    })
}

/// 把一对证书/私钥文件编译成 rustls 的 [`CertifiedKey`]（含签名器）。
fn load_certified_key(
    provider: &CryptoProvider,
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let certs = load_cert_chain(cert_path)?;
    let key = load_key(key_path)?;
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|error| TlsError::Material {
            path: key_path.to_path_buf(),
            message: error.to_string(),
        })?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// 装载服务端配置：证书文件可含证书链，私钥支持 PKCS#8 / PKCS#1 / SEC1。
pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, TlsError> {
    let certs = load_cert_chain(cert_path)?;
    let key = load_key(key_path)?;
    ServerConfig::builder_with_protocol_versions(supported_versions())
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| TlsError::Config(error.to_string()))
}

pub fn acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, TlsError> {
    Ok(TlsAcceptor::from(Arc::new(server_config(
        cert_path, key_path,
    )?)))
}

/// 由已构造好的 [`ServerConfig`] 生成 acceptor（SNI 解析器路径用）。
pub fn acceptor_from_config(config: ServerConfig) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(config))
}

/// 一张证书材料：证书链文件 + 私钥文件。多域名部署时每个 SNI 名字对应一份。
#[derive(Debug, Clone)]
pub struct CertFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CertFiles {
    pub fn new(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            cert: cert.into(),
            key: key.into(),
        }
    }
}

/// 已编译的证书集合：一份兜底 + 若干按 SNI 名字索引的证书。
struct CertStore {
    default: Arc<CertifiedKey>,
    named: HashMap<String, Arc<CertifiedKey>>,
}

impl CertStore {
    /// 按 SNI 名字选证书：精确匹配 → 通配匹配（`*.parent`）→ 兜底。
    /// 名字统一小写（DNS 名大小写不敏感）。
    fn select(&self, server_name: Option<&str>) -> Arc<CertifiedKey> {
        if let Some(name) = server_name {
            let name = name.to_ascii_lowercase();
            if let Some(key) = self.named.get(&name) {
                return Arc::clone(key);
            }
            // 通配只匹配「去掉最左标签」的一层，与 RFC 6125 一致：`*.a.test`
            // 命中 `x.a.test`，但不命中 `a.test` 本身，也不命中 `y.x.a.test`。
            if let Some(dot) = name.find('.') {
                let parent = &name[dot + 1..];
                let mut candidate = String::with_capacity(parent.len() + 2);
                candidate.push_str("*.");
                candidate.push_str(parent);
                if let Some(key) = self.named.get(&candidate) {
                    return Arc::clone(key);
                }
            }
        }
        Arc::clone(&self.default)
    }
}

/// SNI 证书解析器：支持多域名与**热重载**。
///
/// ## 为什么需要它
///
/// 一台服务器托管多个域名（poste.io 式）时，同一 `IP:端口` 要按客户端 `server_name`
/// 出示不同证书。`with_single_cert` 只能给一张、所有域名共用 —— 名字对不上的域名
/// 会让邮件客户端弹证书告警。
///
/// ## 热重载
///
/// [`SniResolver::reload`] 重新读盘并原子替换内部证书集合。ACME 续期把新证书写到
/// 同一批路径后调用一次即可生效，**无需重启进程、不断开在途连接**（已建立的 TLS
/// 会话继续用旧证书直到关闭）。因此 `reload` 用 `&self`，可通过 `Arc<SniResolver>`
/// 句柄在运行期调用，而 `ServerConfig` 持有的是同一个 Arc。
pub struct SniResolver {
    default_src: CertFiles,
    named_src: Vec<(String, CertFiles)>,
    store: RwLock<CertStore>,
}

// `ResolvesServerCert: Debug`。手写而不是 derive：`CertifiedKey` 不保证实现 Debug，
// 而运维真正想看的是「从哪些文件装载、服务哪些名字」，不是证书字节。
impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver")
            .field("default", &self.default_src)
            .field(
                "named",
                &self
                    .named_src
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl SniResolver {
    /// 从磁盘装载。`named` 的键是 SNI 主机名，支持 `*.example.com` 通配。
    pub fn from_files(
        default: CertFiles,
        named: Vec<(String, CertFiles)>,
    ) -> Result<Arc<Self>, TlsError> {
        let store = Self::build(&default, &named)?;
        Ok(Arc::new(Self {
            default_src: default,
            named_src: named,
            store: RwLock::new(store),
        }))
    }

    /// 热重载：重新读同一批文件并原子替换。读盘/解析失败时保留旧证书不动。
    pub fn reload(&self) -> Result<(), TlsError> {
        // 先在锁外完成全部 I/O 与解析，只有成功后才短暂持写锁做指针替换 ——
        // 避免慢盘上的 reload 阻塞并发握手的读锁。
        let store = Self::build(&self.default_src, &self.named_src)?;
        match self.store.write() {
            Ok(mut guard) => {
                *guard = store;
                Ok(())
            }
            Err(_) => Err(TlsError::Config(
                "SNI certificate store lock is poisoned".into(),
            )),
        }
    }

    /// 构造使用本解析器的服务端配置（TLS 1.2/1.3、无客户端认证）。
    pub fn server_config(resolver: Arc<Self>) -> Result<ServerConfig, TlsError> {
        let provider = Arc::new(default_provider());
        let builder = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(supported_versions())
            .map_err(|error| TlsError::Config(error.to_string()))?;
        Ok(builder.with_no_client_auth().with_cert_resolver(resolver))
    }

    fn build(default: &CertFiles, named: &[(String, CertFiles)]) -> Result<CertStore, TlsError> {
        let provider = default_provider();
        let default_key = load_certified_key(&provider, &default.cert, &default.key)?;
        let mut map = HashMap::new();
        for (name, files) in named {
            let key = load_certified_key(&provider, &files.cert, &files.key)?;
            map.insert(name.to_ascii_lowercase(), key);
        }
        Ok(CertStore {
            default: default_key,
            named: map,
        })
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // 读锁中毒时返回 None：rustls 会以「无证书」中止握手（fail-closed），
        // 好过用错证书继续。
        let store = self.store.read().ok()?;
        Some(store.select(client_hello.server_name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tls_12_and_13_are_offered() {
        let versions = supported_versions();
        assert_eq!(versions.len(), 2);
        assert!(std::ptr::eq(versions[0], &rustls::version::TLS12));
        assert!(std::ptr::eq(versions[1], &rustls::version::TLS13));
    }

    #[test]
    fn missing_material_is_refused_instead_of_starting_without_tls() {
        let dir = tempfile::tempdir().unwrap();
        let error = acceptor(
            &dir.path().join("fullchain.pem"),
            &dir.path().join("privkey.pem"),
        )
        .err()
        .expect("缺少材料时必须拒绝启动");
        assert!(matches!(error, TlsError::Material { .. }), "{error:?}");
    }

    #[test]
    fn a_certificate_without_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("fullchain.pem");
        let key = dir.path().join("privkey.pem");
        let generated =
            rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).unwrap();
        std::fs::write(&cert, generated.cert.pem()).unwrap();
        std::fs::write(&key, "not a key\n").unwrap();
        let error = acceptor(&cert, &key).err().expect("损坏私钥必须被拒绝");
        assert!(matches!(error, TlsError::Material { .. }), "{error:?}");

        std::fs::write(&cert, "not a certificate\n").unwrap();
        std::fs::write(&key, generated.key_pair.serialize_pem()).unwrap();
        let error = acceptor(&cert, &key).err().expect("空证书必须被拒绝");
        assert!(matches!(error, TlsError::NoCertificates(_)), "{error:?}");
    }

    /// 生成一张自签证书写入文件，返回材料句柄与证书 DER（供 SNI 断言比对）。
    fn write_cert(dir: &Path, tag: &str, subject: &str) -> (CertFiles, CertificateDer<'static>) {
        let generated = rcgen::generate_simple_self_signed(vec![subject.to_string()]).unwrap();
        let der = generated.cert.der().clone();
        let cert_path = dir.join(format!("{tag}.crt"));
        let key_path = dir.join(format!("{tag}.key"));
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();
        (CertFiles::new(cert_path, key_path), der)
    }

    #[test]
    fn sni_selects_named_wildcard_and_default() {
        let dir = tempfile::tempdir().unwrap();
        let (default_files, _) = write_cert(dir.path(), "default", "default.test");
        let (a_files, _) = write_cert(dir.path(), "a", "a.test");
        let (wild_files, _) = write_cert(dir.path(), "wild", "*.a.test");
        let resolver = SniResolver::from_files(
            default_files,
            vec![
                ("a.test".to_string(), a_files),
                ("*.a.test".to_string(), wild_files),
            ],
        )
        .unwrap();

        let store = resolver.store.read().unwrap();
        let a = store.named.get("a.test").unwrap();
        let wild = store.named.get("*.a.test").unwrap();
        assert!(
            Arc::ptr_eq(&store.select(Some("A.TEST")), a),
            "精确匹配且大小写不敏感"
        );
        assert!(
            Arc::ptr_eq(&store.select(Some("x.a.test")), wild),
            "子域名命中通配"
        );
        assert!(
            Arc::ptr_eq(&store.select(Some("deep.sub.a.test")), &store.default),
            "通配只匹配一层，更深的子域名回落兜底"
        );
        assert!(
            Arc::ptr_eq(&store.select(Some("other.test")), &store.default),
            "无匹配回落兜底"
        );
        assert!(
            Arc::ptr_eq(&store.select(None), &store.default),
            "无 SNI 回落兜底"
        );
    }

    #[test]
    fn reload_swaps_in_renewed_material_without_restarting() {
        let dir = tempfile::tempdir().unwrap();
        let (default_files, _) = write_cert(dir.path(), "default", "default.test");
        let resolver = SniResolver::from_files(default_files.clone(), vec![]).unwrap();
        let before = Arc::as_ptr(&resolver.store.read().unwrap().default);

        // 模拟 ACME 续期：把同一批路径覆盖成新证书，然后 reload。
        let renewed = rcgen::generate_simple_self_signed(vec!["default.test".to_string()]).unwrap();
        std::fs::write(&default_files.cert, renewed.cert.pem()).unwrap();
        std::fs::write(&default_files.key, renewed.key_pair.serialize_pem()).unwrap();
        resolver.reload().unwrap();

        let after = Arc::as_ptr(&resolver.store.read().unwrap().default);
        assert_ne!(before, after, "reload 必须换上新证书对象");
    }

    #[test]
    fn reload_failure_keeps_the_previous_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let (default_files, _) = write_cert(dir.path(), "default", "default.test");
        let resolver = SniResolver::from_files(default_files.clone(), vec![]).unwrap();
        let before = Arc::as_ptr(&resolver.store.read().unwrap().default);

        // 续期写坏了证书文件：reload 必须报错且保留旧证书（fail-safe）。
        std::fs::write(&default_files.cert, "not a certificate\n").unwrap();
        assert!(resolver.reload().is_err());
        let after = Arc::as_ptr(&resolver.store.read().unwrap().default);
        assert_eq!(before, after, "失败的 reload 不得改动在用证书");
    }

    #[test]
    fn sni_server_config_builds_into_an_acceptor() {
        let dir = tempfile::tempdir().unwrap();
        let (default_files, _) = write_cert(dir.path(), "default", "default.test");
        let resolver = SniResolver::from_files(default_files, vec![]).unwrap();
        let config = SniResolver::server_config(resolver).unwrap();
        let _acceptor = acceptor_from_config(config);
    }

    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &rustls_pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    #[tokio::test]
    async fn sni_handshake_presents_the_named_certificate() {
        use rustls::ClientConfig;
        use rustls_pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let dir = tempfile::tempdir().unwrap();
        let (default_files, _) = write_cert(dir.path(), "default", "default.test");
        let (a_files, a_der) = write_cert(dir.path(), "a", "a.test");
        let resolver =
            SniResolver::from_files(default_files, vec![("a.test".to_string(), a_files)]).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(SniResolver::server_config(resolver).unwrap()));

        let client_cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(supported_versions())
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let _tls = acceptor.accept(server_io).await.expect("server handshake");
        });
        let name = ServerName::try_from("a.test").unwrap();
        let client = connector
            .connect(name, client_io)
            .await
            .expect("client handshake");
        let presented = client
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first().cloned())
            .expect("server must present a certificate");
        assert_eq!(presented, a_der, "SNI 命中 a.test 必须出示 a.test 证书");
        server.await.unwrap();
    }
}

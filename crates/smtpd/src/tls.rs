//! 入站 TLS：证书装载、最低版本约束与「明文 / 加密」流的统一类型（规格书 §5.10）。
//!
//! ## 最低版本是**写死的策略**，不是默认值的巧合
//!
//! [`supported_versions`] 显式列出 TLS 1.2 与 TLS 1.3。rustls 本身不实现 1.0/1.1，
//! 但把它写成显式列表的意义在于：**策略可见、可测**。依赖「库的默认值恰好安全」
//! 是一种隐式假设 —— 库升级或特性开关变化时它会静默失效，而这里不会。
//!
//! ## 为什么需要 [`BoxedStream`]
//!
//! STARTTLS 是**就地**升级：同一条连接先明文、后加密，而 `TcpStream` 与
//! `TlsStream<TcpStream>` 是两个不同的类型。监听层要在同一个变量里保存二者，
//! 且会话驱动只要求 `AsyncRead + AsyncWrite + Unpin`。用 trait object 收敛成
//! 一个类型，比在监听层写一堆泛型分支要清楚得多。

use std::path::{Path, PathBuf};

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

/// 允许的最低/最高 TLS 版本 —— 只有 1.2 与 1.3。
pub fn supported_versions() -> &'static [&'static rustls::SupportedProtocolVersion] {
    static VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
        [&rustls::version::TLS12, &rustls::version::TLS13];
    &VERSIONS
}

/// 统一「明文 TCP」与「TLS 之上的 TCP」两种字节流。
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// 会话驱动接受的统一流类型。
pub type BoxedStream = Box<dyn AsyncStream>;

/// 隐式 TLS（465，建连即握手）还是明文 + STARTTLS（25/587）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// 明文建连；由 `STARTTLS` 命令升级。
    StartTls,
    /// 建连即握手（SMTPS，465）。
    Implicit,
}

/// TLS 材料与配置的错误。
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// 读取证书 / 私钥文件失败（文件不存在、PEM 结构损坏等）。
    #[error("无法读取 TLS 材料 {path}: {message}")]
    Material { path: PathBuf, message: String },
    /// 证书文件里没有任何证书。
    #[error("证书文件 {0} 不含任何证书")]
    NoCertificates(PathBuf),
    /// 域名不合法（用于拼证书路径，必须挡住路径穿越）。
    #[error("非法域名: {0}")]
    InvalidDomain(String),
    /// rustls 拒绝了配置（通常是证书与私钥不匹配）。
    #[error("TLS 配置被拒绝: {0}")]
    Config(String),
}

/// 一个域名的证书/私钥路径。
///
/// 布局与基线一致：`<etc>/tls/<domain>/fullchain.pem` 与 `privkey.pem`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CertPaths {
    /// 据域名推导路径。
    ///
    /// 域名先经 [`validate_domain`](mailstack_auth::validate_domain) 校验：它只允许
    /// 字母/数字/连字符/点，因此 `..`、`/` 这类路径穿越串根本构造不出来。
    pub fn for_domain(etc: &Path, domain: &str) -> Result<Self, TlsError> {
        let domain = mailstack_auth::validate_domain(domain)
            .map_err(|_| TlsError::InvalidDomain(domain.to_string()))?;
        let dir = etc.join("tls").join(domain);
        Ok(Self {
            cert: dir.join("fullchain.pem"),
            key: dir.join("privkey.pem"),
        })
    }
}

/// 装载 rustls 服务端配置。
///
/// 证书文件可以包含多条证书（证书链），顺序即链序；私钥用 PKCS#8 / PKCS#1 / SEC1
/// 均可（`PrivateKeyDer` 会自动识别）。
pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, TlsError> {
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

    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|error| TlsError::Material {
        path: key_path.to_path_buf(),
        message: error.to_string(),
    })?;

    ServerConfig::builder_with_protocol_versions(supported_versions())
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| TlsError::Config(error.to_string()))
}

/// 装载 [`TlsAcceptor`]。
pub fn acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, TlsError> {
    Ok(TlsAcceptor::from(std::sync::Arc::new(server_config(
        cert_path, key_path,
    )?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tls_12_and_13_are_offered() {
        // 策略必须可测：协商列表**恰好**是 1.2 与 1.3，低版本无从谈起。
        // 用引用相等而不是名字比较 —— `SupportedProtocolVersion` 只暴露 `version`，
        // 而这两个常量正是 rustls 里唯一的 1.2/1.3 定义。
        let versions = supported_versions();
        assert_eq!(versions.len(), 2, "只应协商两个版本");
        assert!(std::ptr::eq(versions[0], &rustls::version::TLS12));
        assert!(std::ptr::eq(versions[1], &rustls::version::TLS13));
    }

    #[test]
    fn missing_material_is_refused_instead_of_starting_without_tls() {
        let dir = tempfile::tempdir().unwrap();
        let missing_cert = dir.path().join("fullchain.pem");
        let missing_key = dir.path().join("privkey.pem");
        let error = acceptor(&missing_cert, &missing_key)
            .err()
            .expect("缺少材料时必须拒绝启动");
        assert!(
            matches!(error, TlsError::Material { .. }),
            "实际：{error:?}"
        );
    }

    #[test]
    fn an_empty_certificate_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("fullchain.pem");
        let key = dir.path().join("privkey.pem");
        std::fs::write(&cert, b"not a certificate\n").unwrap();
        std::fs::write(&key, b"not a key\n").unwrap();
        let error = acceptor(&cert, &key).err().expect("空证书文件必须被拒绝");
        assert!(
            matches!(error, TlsError::NoCertificates(_)),
            "空证书文件不得被当成「没有证书也没关系」：{error:?}"
        );
    }

    #[test]
    fn cert_paths_reject_traversal_domains() {
        let etc = Path::new("/etc/mailstack");
        assert!(CertPaths::for_domain(etc, "../../etc/shadow").is_err());
        assert!(CertPaths::for_domain(etc, "example.org").is_ok());

        let paths = CertPaths::for_domain(etc, "MAIL.Example.ORG").unwrap();
        assert_eq!(
            paths.cert,
            Path::new("/etc/mailstack/tls/mail.example.org/fullchain.pem"),
            "域名应被规范化后再拼路径"
        );
    }
}

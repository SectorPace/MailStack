use std::path::{Path, PathBuf};

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

pub fn supported_versions() -> &'static [&'static rustls::SupportedProtocolVersion] {
    static VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
        [&rustls::version::TLS12, &rustls::version::TLS13];
    &VERSIONS
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedStream = Box<dyn AsyncStream>;

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

    #[error("非法域名: {0}")]
    InvalidDomain(String),

    #[error("TLS 配置被拒绝: {0}")]
    Config(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CertPaths {
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

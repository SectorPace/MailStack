//! 证书读取（`certs.list`）。
//!
//! 布局与基线一致：`<etc>/tls/<domain>/fullchain.pem` 与 `privkey.pem`
//! （与 `mailstack_smtpd::tls::CertPaths` 同源，改一侧必须改另一侧）。
//!
//! 这里只做**读取与解析**，不做链校验 —— 校验由 rustls 在握手时完成，
//! 在那之前先接受一个证书毫无意义。本模块存在的理由是运维真正要看的那个数：
//! **还有几天到期**。

use std::path::{Path, PathBuf};

use base64::Engine as _;
use time::OffsetDateTime;

/// 一个域名的证书状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    pub domain: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub cert_present: bool,
    pub key_present: bool,
    /// 私钥权限位（八进制）。
    pub key_mode: Option<u32>,
    /// 私钥是否对「非属主」可读 —— 这是一个必须能被看见的问题。
    pub key_group_or_world_readable: bool,
    pub not_after: Option<String>,
    pub not_before: Option<String>,
    pub days_until_expiry: Option<i64>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    /// 读取或解析失败的原因。存在它时 `not_after` 之类仍可能为 `None`。
    pub error: Option<String>,
}

impl CertificateInfo {
    /// 是否在 `days` 天内到期（或已过期）。
    pub fn expires_within(&self, days: i64) -> bool {
        self.days_until_expiry.map(|d| d <= days).unwrap_or(false)
    }
}

/// TLS 目录：`<etc>/tls`。
pub fn tls_dir(etc: &Path) -> PathBuf {
    etc.join("tls")
}

/// 枚举 `<etc>/tls/*/` 下的证书。
///
/// 目录名不是合法域名的条目会被**跳过**（它们不是本模块管辖的对象），
/// 而不合法内容不会被当作域名拼进路径。
pub fn list_certificates(etc: &Path, now: OffsetDateTime) -> Vec<CertificateInfo> {
    let dir = tls_dir(etc);
    let Ok(read) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in read.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_dir() {
            continue;
        }
        let domain = entry.file_name().to_string_lossy().to_string();
        if !crate::validate::DOMAIN_RE.is_match(&domain) {
            continue;
        }
        out.push(read_certificate(etc, &domain, now));
    }
    out.sort_by(|a, b| a.domain.cmp(&b.domain));
    out
}

/// 读取单个域名的证书。
///
/// **不返回 `Option`**：证书缺失也是要上报的事实（`cert_present: false`），
/// 而不是「没有这一项」—— 前者会在界面上显示为「未配置证书」，后者会显示为
/// 「这个域不存在」，两者对运维的含义完全不同。
pub fn read_certificate(etc: &Path, domain: &str, now: OffsetDateTime) -> CertificateInfo {
    let dir = tls_dir(etc).join(domain);
    let cert_path = dir.join("fullchain.pem");
    let key_path = dir.join("privkey.pem");

    let mut info = CertificateInfo {
        domain: domain.to_string(),
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        cert_present: cert_path.is_file(),
        key_present: key_path.is_file(),
        key_mode: file_mode(&key_path),
        key_group_or_world_readable: file_mode(&key_path)
            .map(|m| m & 0o077 != 0)
            .unwrap_or(false),
        not_after: None,
        not_before: None,
        days_until_expiry: None,
        issuer: None,
        subject: None,
        error: None,
    };

    if !info.cert_present {
        return info;
    }
    let Ok(pem) = std::fs::read_to_string(&cert_path) else {
        info.error = Some("certificate file is not readable as text".to_string());
        return info;
    };
    let Some(der) = first_certificate_der(&pem) else {
        info.error = Some("no PEM CERTIFICATE block found".to_string());
        return info;
    };
    match x509_parser::parse_x509_certificate(&der) {
        Ok((_rest, cert)) => {
            info.not_before = Some(crate::time_fmt::format_iso8601(
                cert.validity().not_before.to_datetime(),
            ));
            let not_after = cert.validity().not_after.to_datetime();
            info.not_after = Some(crate::time_fmt::format_iso8601(not_after));
            info.days_until_expiry = Some((not_after - now).whole_days());
            info.issuer = Some(render_name(cert.issuer()));
            info.subject = Some(render_name(cert.subject()));
        }
        Err(e) => info.error = Some(format!("certificate is not parseable: {e}")),
    }
    info
}

/// 从 PEM 文本里取出第一段 `CERTIFICATE` 的 DER 字节。
///
/// 只认第一段：`fullchain.pem` 的后续条目是中间证书，到期判断看的是叶证书。
pub fn first_certificate_der(pem: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let start = pem.find(BEGIN)? + BEGIN.len();
    let rest = &pem[start..];
    let end = rest.find(END)?;
    // PEM 正文可以跨多行；去掉所有空白后才是纯 base64。
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// 把 X.509 名称渲染成一行：`CN=mail.example.com, O=Example`。
///
/// `asn1-rs` 的 `Oid` 打完是点分形式（`2.5.4.3`），直接透出去运维读不懂；
/// 这里把最常见的几个属性映射成 openssl 风格的短名，其余保留点分形式
/// （**不猜**，认不出来就如实显示 OID）。
fn render_name(name: &x509_parser::x509::X509Name<'_>) -> String {
    name.iter()
        .map(|rdn| {
            rdn.iter()
                .map(|attr| {
                    let value = attr.as_str().unwrap_or("<non-utf8>");
                    let oid = attr.attr_type().to_string();
                    format!("{}={value}", short_attribute_name(&oid))
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// 常见 X.509 名称属性的短名（来自 `oid_registry` 的标准 OID）。
fn short_attribute_name(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "emailAddress",
        other => other,
    }
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-certs-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(tls_dir(&root)).unwrap();
            Self { root }
        }

        /// 用 rcgen 现场签一张自签证书 —— 不预置 fixture 是为了让「解析出来的
        /// 到期时间」与「生成时声明的时间」能做逐字比对，而不是只断言「非空」。
        fn issue(&self, domain: &str, days: i64) -> Vec<u8> {
            let not_before = now();
            let not_after = not_before + time::Duration::days(days);
            let ymd = |dt: OffsetDateTime| {
                rcgen::date_time_ymd(dt.year(), u8::from(dt.month()), dt.day())
            };

            let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
            // rcgen 默认不写 DN，只写 SAN；这里显式写 CN，好让「subject 渲染」
            // 这条断言真的在验解析结果，而不是在验一个空串。
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, domain);
            params.not_before = ymd(not_before);
            params.not_after = ymd(not_after);
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();

            let dir = tls_dir(&self.root).join(domain);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("fullchain.pem"), cert.pem()).unwrap();
            fs::write(dir.join("privkey.pem"), key.serialize_pem()).unwrap();
            cert.der().to_vec()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap()
    }

    #[test]
    fn a_certificate_reports_its_expiry_in_days() {
        let f = Fixture::new("expiry");
        let der = f.issue("mail.example.com", 45);

        let info = read_certificate(&f.root, "mail.example.com", now());
        assert!(info.cert_present);
        assert!(info.key_present);
        assert_eq!(info.error, None);
        assert_eq!(info.days_until_expiry, Some(45));
        assert!(info
            .not_after
            .as_deref()
            .unwrap()
            .starts_with("2026-02-15T"));
        assert!(info
            .subject
            .as_deref()
            .unwrap()
            .contains("CN=mail.example.com"));
        // 自签证书的签发者就是自己。
        assert!(info
            .issuer
            .as_deref()
            .unwrap()
            .contains("CN=mail.example.com"));
        // 解析出的 DER 必须与生成时的相同。
        assert_eq!(
            first_certificate_der(
                &fs::read_to_string(tls_dir(&f.root).join("mail.example.com/fullchain.pem"))
                    .unwrap()
            ),
            Some(der)
        );
    }

    #[test]
    fn expiry_helpers_flag_the_soon_danger_window() {
        let f = Fixture::new("soon");
        f.issue("about-to-expire.example.com", 7);
        let info = read_certificate(&f.root, "about-to-expire.example.com", now());
        assert!(info.expires_within(14), "7 天内到期必须被判为即将到期");
        assert!(!info.expires_within(3));
    }

    #[test]
    fn a_missing_certificate_is_reported_as_absent_not_as_an_absent_domain() {
        let f = Fixture::new("absent");
        let info = read_certificate(&f.root, "never-issued.example.com", now());
        assert!(!info.cert_present);
        assert!(!info.key_present);
        assert_eq!(info.days_until_expiry, None);
        assert_eq!(info.error, None, "「没有证书」不是解析错误");
    }

    #[test]
    fn an_unparseable_certificate_reports_why_instead_of_pretending_it_is_fine() {
        let f = Fixture::new("garbage");
        let dir = tls_dir(&f.root).join("broken.example.com");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("fullchain.pem"), "not a pem at all\n").unwrap();
        fs::write(dir.join("privkey.pem"), "x").unwrap();

        let info = read_certificate(&f.root, "broken.example.com", now());
        assert!(info.cert_present);
        assert_eq!(info.days_until_expiry, None);
        assert!(
            info.error
                .as_deref()
                .unwrap()
                .contains("no PEM CERTIFICATE"),
            "实际: {:?}",
            info.error
        );

        fs::write(
            dir.join("fullchain.pem"),
            "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let info = read_certificate(&f.root, "broken.example.com", now());
        assert!(
            info.error.as_deref().unwrap().contains("not parseable"),
            "实际: {:?}",
            info.error
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_private_key_is_flagged() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("keymode");
        f.issue("mail.example.com", 30);
        let key = tls_dir(&f.root).join("mail.example.com/privkey.pem");

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let info = read_certificate(&f.root, "mail.example.com", now());
        assert_eq!(info.key_mode, Some(0o600));
        assert!(!info.key_group_or_world_readable);

        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let info = read_certificate(&f.root, "mail.example.com", now());
        assert!(info.key_group_or_world_readable, "0644 的私钥必须被标出来");
    }

    #[test]
    fn listing_skips_directory_names_that_are_not_domains() {
        let f = Fixture::new("listing");
        f.issue("b.example.com", 30);
        f.issue("a.example.com", 30);
        // 非域名的目录不该被当作证书条目（它可能是运维留下的临时目录）。
        fs::create_dir_all(tls_dir(&f.root).join("not a domain")).unwrap();
        fs::create_dir_all(tls_dir(&f.root).join(".hidden")).unwrap();

        let list = list_certificates(&f.root, now());
        let names: Vec<&str> = list.iter().map(|c| c.domain.as_str()).collect();
        assert_eq!(names, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn listing_a_host_without_a_tls_directory_is_empty_not_an_error() {
        let mut root = std::env::temp_dir();
        root.push(format!("mailstack-certs-none-{}", std::process::id()));
        assert!(list_certificates(&root, now()).is_empty());
    }

    #[test]
    fn name_attributes_use_openssl_style_short_names() {
        assert_eq!(short_attribute_name("2.5.4.3"), "CN");
        assert_eq!(short_attribute_name("2.5.4.10"), "O");
        assert_eq!(short_attribute_name("1.2.840.113549.1.9.1"), "emailAddress");
        // 认不出来的 OID 如实显示，不猜一个名字出来。
        assert_eq!(short_attribute_name("1.2.3.4.5"), "1.2.3.4.5");
    }

    #[test]
    fn pem_extraction_handles_multiline_and_padded_bodies() {
        // 单行 base64、带空行、带行尾空白 —— 都应当被还原成同一段字节。
        let der = first_certificate_der(
            "junk before\n-----BEGIN CERTIFICATE-----\nZm9v\nYmFy\n-----END CERTIFICATE-----\njunk after\n",
        )
        .unwrap();
        assert_eq!(der, b"foobar");
        assert_eq!(
            first_certificate_der(
                "-----BEGIN CERTIFICATE-----\n  Zm9v\tYmFy  \n-----END CERTIFICATE-----"
            ),
            Some(b"foobar".to_vec())
        );
        assert_eq!(first_certificate_der("no block here"), None);
    }
}

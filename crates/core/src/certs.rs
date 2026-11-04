use std::path::{Path, PathBuf};

use base64::Engine as _;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    pub domain: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub cert_present: bool,
    pub key_present: bool,

    pub key_mode: Option<u32>,

    pub key_group_or_world_readable: bool,
    pub not_after: Option<String>,
    pub not_before: Option<String>,
    pub days_until_expiry: Option<i64>,
    pub issuer: Option<String>,
    pub subject: Option<String>,

    pub error: Option<String>,
}

impl CertificateInfo {
    pub fn expires_within(&self, days: i64) -> bool {
        self.days_until_expiry.map(|d| d <= days).unwrap_or(false)
    }
}

pub fn tls_dir(etc: &Path) -> PathBuf {
    etc.join("tls")
}

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

pub fn first_certificate_der(pem: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let start = pem.find(BEGIN)? + BEGIN.len();
    let rest = &pem[start..];
    let end = rest.find(END)?;

    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

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

        fn issue(&self, domain: &str, days: i64) -> Vec<u8> {
            let not_before = now();
            let not_after = not_before + time::Duration::days(days);
            let ymd = |dt: OffsetDateTime| {
                rcgen::date_time_ymd(dt.year(), u8::from(dt.month()), dt.day())
            };

            let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();

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

        assert!(info
            .issuer
            .as_deref()
            .unwrap()
            .contains("CN=mail.example.com"));

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

        assert_eq!(short_attribute_name("1.2.3.4.5"), "1.2.3.4.5");
    }

    #[test]
    fn pem_extraction_handles_multiline_and_padded_bodies() {
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

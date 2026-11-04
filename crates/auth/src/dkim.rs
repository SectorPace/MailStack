use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;
use mail_auth::{AuthenticatedMessage, DkimOutput, DkimResult, MessageAuthenticator, Parameters};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};

use crate::cache::TxtCache;
use crate::error::{AuthError, AuthResult};

pub const DEFAULT_SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Cc",
    "Reply-To",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimStatus {
    Pass,
    Fail(String),
    PermissionError(String),
    TemporaryError(String),
    Neutral(String),

    None,
}

impl DkimStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, DkimStatus::Pass)
    }

    pub fn keyword(&self) -> &'static str {
        match self {
            DkimStatus::Pass => "pass",
            DkimStatus::Fail(_) => "fail",
            DkimStatus::PermissionError(_) => "permerror",
            DkimStatus::TemporaryError(_) => "temperror",
            DkimStatus::Neutral(_) => "neutral",
            DkimStatus::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimVerdict {
    pub domain: String,
    pub selector: String,
    pub status: DkimStatus,
}

impl DkimVerdict {
    pub(crate) fn from_result(result: &DkimResult, domain: &str, selector: &str) -> Self {
        let status = match result {
            DkimResult::Pass => DkimStatus::Pass,
            DkimResult::Fail(error) => DkimStatus::Fail(error.to_string()),
            DkimResult::PermError(error) => DkimStatus::PermissionError(error.to_string()),
            DkimResult::TempError(error) => DkimStatus::TemporaryError(error.to_string()),
            DkimResult::Neutral(error) => DkimStatus::Neutral(error.to_string()),
            DkimResult::None => DkimStatus::None,
        };
        Self {
            domain: domain.to_string(),
            selector: selector.to_string(),
            status,
        }
    }
}

pub(crate) fn verdicts_from(outputs: &[DkimOutput<'_>]) -> Vec<DkimVerdict> {
    outputs
        .iter()
        .map(|output| {
            let (domain, selector) = output
                .signature()
                .map(|signature| (signature.d.as_str(), signature.s.as_str()))
                .unwrap_or_default();
            DkimVerdict::from_result(output.result(), domain, selector)
        })
        .collect()
}

pub fn from_domain(message: &[u8]) -> Option<String> {
    let parsed = AuthenticatedMessage::parse(message)?;
    let mut domains: Vec<String> = Vec::new();
    for address in &parsed.from {
        let Some((_, domain)) = address.rsplit_once('@') else {
            continue;
        };

        let domain: String = domain
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            .collect();
        let domain = domain.trim_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        if !domains.iter().any(|seen| seen == &domain) {
            domains.push(domain);
        }
    }
    match domains.len() {
        1 => domains.pop(),

        _ => None,
    }
}

pub fn sign(
    private_key_der: &[u8],
    domain: &str,
    selector: &str,
    headers: &[&str],
    message: &[u8],
) -> AuthResult<Vec<u8>> {
    let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
        private_key_der,
    )))
    .map_err(|error| AuthError::Signing(error.to_string()))?;

    let signature = DkimSigner::from_key(key)
        .domain(domain)
        .selector(selector)
        .headers(headers.iter().copied())
        .sign(message)
        .map_err(|error| AuthError::Signing(error.to_string()))?;

    let mut signed = signature.to_header().into_bytes();
    signed.extend_from_slice(message);
    Ok(signed)
}

pub fn sign_with_default_headers(
    private_key_der: &[u8],
    domain: &str,
    selector: &str,
    message: &[u8],
) -> AuthResult<Vec<u8>> {
    sign(
        private_key_der,
        domain,
        selector,
        DEFAULT_SIGNED_HEADERS,
        message,
    )
}

pub async fn verify_with(
    resolver: &MessageAuthenticator,
    cache: &TxtCache,
    message: &[u8],
) -> AuthResult<Vec<DkimVerdict>> {
    let parsed = AuthenticatedMessage::parse(message)
        .ok_or_else(|| AuthError::Signing("message could not be parsed".to_string()))?;

    let params = Parameters::new(&parsed).with_txt_cache(cache);
    let outputs = resolver.verify_dkim(params).await;

    Ok(verdicts_from(&outputs))
}

pub async fn verify(message: &[u8]) -> AuthResult<Vec<DkimVerdict>> {
    let resolver = crate::cache::system_resolver()?;
    verify_with(&resolver, &TxtCache::new(), message).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{dkim_txt_value, generate_key_material, DKIM_KEY_BITS};
    use std::sync::OnceLock;

    const MESSAGE: &str = concat!(
        "From: alice@example.com\r\n",
        "To: bob@example.net\r\n",
        "Subject: 自检\r\n",
        "Date: Wed, 01 Oct 2026 10:00:00 +0800\r\n",
        "Message-ID: <selftest@example.com>\r\n",
        "\r\n",
        "这是一封用于验签自检的邮件。\r\n"
    );

    struct Fixture {
        material: crate::keys::DkimKeyMaterial,
        _dir: tempfile::TempDir,
    }

    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| Fixture {
            material: generate_key_material("example.com", "mailstack", DKIM_KEY_BITS)
                .expect("生成密钥"),
            _dir: tempfile::tempdir().unwrap(),
        })
    }

    fn private_key_der(material: &crate::keys::DkimKeyMaterial) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.private");
        std::fs::write(&path, material.private_key_pem.as_bytes()).unwrap();
        crate::keys::load_private_key_der(&path).expect("解出私钥 DER")
    }

    fn resolver() -> MessageAuthenticator {
        crate::cache::system_resolver().expect("构造系统解析器")
    }

    fn cache_with_public_key(material: &crate::keys::DkimKeyMaterial) -> TxtCache {
        let cache = TxtCache::new();
        let value = dkim_txt_value(&material.public_key_spki_b64);
        cache
            .add_domain_key(
                &format!("{}._domainkey.{}", material.selector, material.domain),
                value.as_bytes(),
            )
            .expect("装载公钥记录");
        cache
    }

    #[tokio::test]
    async fn a_message_signed_with_a_key_pair_verifies_with_the_same_pair() {
        let material = &fixture().material;
        let der = private_key_der(material);

        let signed = sign_with_default_headers(
            &der,
            &material.domain,
            &material.selector,
            MESSAGE.as_bytes(),
        )
        .expect("签名");

        assert!(
            signed.starts_with(b"DKIM-Signature:"),
            "签名头必须前置到报文之前"
        );
        assert!(
            signed.ends_with(MESSAGE.as_bytes()),
            "原报文必须逐字保留在签名头之后"
        );

        let verdicts = verify_with(&resolver(), &cache_with_public_key(material), &signed)
            .await
            .expect("验签");

        assert_eq!(verdicts.len(), 1, "应当只有一条 DKIM 签名");
        assert_eq!(
            verdicts[0].status,
            DkimStatus::Pass,
            "自签自验必须通过：{:?}",
            verdicts[0]
        );
        assert_eq!(verdicts[0].domain, "example.com");
        assert_eq!(verdicts[0].selector, "mailstack");
    }

    #[tokio::test]
    async fn a_tampered_body_fails_verification() {
        let material = &fixture().material;
        let der = private_key_der(material);
        let signed = sign_with_default_headers(
            &der,
            &material.domain,
            &material.selector,
            MESSAGE.as_bytes(),
        )
        .expect("签名");

        let mut tampered = signed.clone();

        let needle = "自检".as_bytes();
        let position = tampered
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("正文里应当有被替换的词");
        tampered[position] = b'?';

        let verdicts = verify_with(&resolver(), &cache_with_public_key(material), &tampered)
            .await
            .expect("验签");
        assert_eq!(verdicts.len(), 1);
        assert!(
            !verdicts[0].status.is_pass(),
            "正文被改动后不得通过：{:?}",
            verdicts[0]
        );
    }

    #[tokio::test]
    async fn a_message_without_dkim_headers_yields_no_verdicts() {
        let verdicts = verify_with(&resolver(), &TxtCache::new(), MESSAGE.as_bytes())
            .await
            .expect("解析无签名报文");
        assert!(verdicts.is_empty(), "没有 DKIM 头就不该有结论");
    }

    #[test]
    fn signing_rejects_a_key_that_is_not_pkcs1() {
        let error = sign(
            b"not a key",
            "example.com",
            "mailstack",
            &["From"],
            MESSAGE.as_bytes(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), "SigningError");
    }

    #[test]
    fn from_domain_handles_display_names_brackets_and_folding() {
        for (header, expected) in [
            ("From: alice@example.com\r\n", Some("example.com")),
            ("From: <alice@example.com>\r\n", Some("example.com")),
            (
                "From: \"Alice\" <alice@Example.COM>\r\n",
                Some("example.com"),
            ),
            ("From: \"a@b\" <alice@example.com>\r\n", Some("example.com")),
            (
                "From: \"Alice\r\n Anderson\"\r\n <alice@sub.example.com>\r\n",
                Some("sub.example.com"),
            ),
        ] {
            let message = format!("{header}Subject: t\r\n\r\nbody\r\n");
            assert_eq!(
                from_domain(message.as_bytes()).as_deref(),
                expected,
                "头为 {header:?}"
            );
        }

        assert_eq!(from_domain(b"Subject: t\r\n\r\nbody\r\n"), None);
        assert_eq!(from_domain(b"From: not-an-address\r\n\r\nbody\r\n"), None);
        assert_eq!(from_domain(b""), None);
    }

    #[test]
    fn from_domain_refuses_messages_with_multiple_from_domains() {
        for header in [
            "From: me@example.com, ceo@bank.com\r\n",
            "From: ceo@bank.com\r\nFrom: me@example.com\r\n",
            "From: a@Example.COM, b@example.com, c@evil.test\r\n",
        ] {
            let message = format!("{header}Subject: t\r\n\r\nbody\r\n");
            assert_eq!(
                from_domain(message.as_bytes()),
                None,
                "多个不同 From 域时不得挑一个来签名：{header:?}"
            );
        }

        assert_eq!(
            from_domain(b"From: a@example.com, b@EXAMPLE.com\r\n\r\nbody\r\n").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn status_keywords_follow_rfc8601() {
        assert_eq!(DkimStatus::Pass.keyword(), "pass");
        assert_eq!(DkimStatus::Fail(String::new()).keyword(), "fail");
        assert_eq!(
            DkimStatus::PermissionError(String::new()).keyword(),
            "permerror"
        );
        assert_eq!(
            DkimStatus::TemporaryError(String::new()).keyword(),
            "temperror"
        );
        assert_eq!(DkimStatus::Neutral(String::new()).keyword(), "neutral");
        assert_eq!(DkimStatus::None.keyword(), "none");
    }
}

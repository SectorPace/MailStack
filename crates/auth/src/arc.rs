use std::net::IpAddr;

use mail_auth::arc::ArcSealer;
use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::{
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimResult, MessageAuthenticator,
    Parameters,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};

use crate::cache::TxtCache;
use crate::error::{AuthError, AuthResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcStatus {
    Pass,
    Fail(String),
    TemporaryError(String),
    PermissionError(String),

    None,
}

impl ArcStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, ArcStatus::Pass)
    }

    pub fn keyword(&self) -> &'static str {
        match self {
            ArcStatus::Pass => "pass",
            ArcStatus::Fail(_) => "fail",
            ArcStatus::TemporaryError(_) => "temperror",
            ArcStatus::PermissionError(_) => "permerror",
            ArcStatus::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcVerdict {
    pub status: ArcStatus,

    pub sets: usize,
}

fn verdict(output: &ArcOutput<'_>) -> ArcVerdict {
    let status = match output.result() {
        DkimResult::Pass => ArcStatus::Pass,
        DkimResult::Fail(error) => ArcStatus::Fail(error.to_string()),
        DkimResult::PermError(error) => ArcStatus::PermissionError(error.to_string()),
        DkimResult::TempError(error) => ArcStatus::TemporaryError(error.to_string()),
        DkimResult::Neutral(error) => ArcStatus::Fail(error.to_string()),
        DkimResult::None => ArcStatus::None,
    };
    ArcVerdict {
        status,
        sets: output.sets().len(),
    }
}

pub async fn verify_with(
    resolver: &MessageAuthenticator,
    cache: &TxtCache,
    message: &[u8],
) -> AuthResult<ArcVerdict> {
    let parsed = AuthenticatedMessage::parse(message)
        .ok_or_else(|| AuthError::Signing("message could not be parsed".to_string()))?;

    let output = resolver
        .verify_arc(Parameters::new(&parsed).with_txt_cache(cache))
        .await;

    Ok(verdict(&output))
}

pub async fn verify(message: &[u8]) -> AuthResult<ArcVerdict> {
    let resolver = crate::cache::system_resolver()?;
    verify_with(&resolver, &TxtCache::new(), message).await
}

pub const ARC_SIGNED_HEADERS: &[&str] = &[
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
    "DKIM-Signature",
];

#[derive(Debug, Clone, Copy)]
pub struct SealContext<'a> {
    pub hostname: &'a str,

    pub remote_ip: IpAddr,

    pub helo_domain: &'a str,

    pub mail_from: &'a str,

    pub domain: &'a str,

    pub selector: &'a str,
}

fn header_from(message: &AuthenticatedMessage<'_>, fallback: &str) -> String {
    message
        .from
        .first()
        .and_then(|address| address.rsplit_once('@'))
        .map(|(_, domain)| crate::dmarc::sanitize_domain_part(domain))
        .filter(|domain| !domain.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

pub async fn seal_with(
    resolver: &MessageAuthenticator,
    cache: &TxtCache,
    message: &[u8],
    private_key_der: &[u8],
    context: &SealContext<'_>,
) -> AuthResult<Vec<u8>> {
    let parsed = AuthenticatedMessage::parse(message)
        .ok_or_else(|| AuthError::Signing("message could not be parsed".to_string()))?;

    let arc_output = resolver
        .verify_arc(Parameters::new(&parsed).with_txt_cache(cache))
        .await;
    if !arc_output.can_be_sealed() {
        return Err(AuthError::Signing(
            "ARC chain cannot be sealed (cv=fail)".to_string(),
        ));
    }

    let spf_output = crate::spf::check_raw(
        resolver,
        cache,
        context.remote_ip,
        context.helo_domain,
        context.hostname,
        context.mail_from,
    )
    .await;
    let dkim_outputs = resolver
        .verify_dkim(Parameters::new(&parsed).with_txt_cache(cache))
        .await;

    let mail_from_domain = crate::dmarc::sanitized_domain(context.mail_from);
    let dmarc_output = resolver
        .verify_dmarc(
            Parameters::new(DmarcParameters {
                message: &parsed,
                dkim_output: &dkim_outputs,
                dkim2_output: None,
                rfc5321_mail_from_domain: mail_from_domain.as_str(),
                spf_output: &spf_output,
            })
            .with_txt_cache(cache),
        )
        .await;

    let from = header_from(&parsed, context.hostname);
    let auth_results = AuthenticationResults::new(context.hostname)
        .with_dkim_results(&dkim_outputs, &from)
        .with_spf_mailfrom_result(
            &spf_output,
            context.remote_ip,
            context.mail_from,
            context.helo_domain,
        )
        .with_dmarc_result(&dmarc_output)
        .with_arc_result(&arc_output, context.remote_ip);

    let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
        private_key_der,
    )))
    .map_err(|error| AuthError::Signing(error.to_string()))?;

    let set = ArcSealer::from_key(key)
        .domain(context.domain)
        .selector(context.selector)
        .headers(ARC_SIGNED_HEADERS.iter().copied())
        .seal(&parsed, &auth_results, &arc_output)
        .map_err(|error| AuthError::Signing(error.to_string()))?;

    let mut sealed = set.to_header().into_bytes();
    sealed.extend_from_slice(auth_results.to_header().as_bytes());
    sealed.extend_from_slice(message);
    Ok(sealed)
}

pub async fn seal(
    message: &[u8],
    private_key_der: &[u8],
    context: &SealContext<'_>,
) -> AuthResult<Vec<u8>> {
    let resolver = crate::cache::system_resolver()?;
    seal_with(
        &resolver,
        &TxtCache::new(),
        message,
        private_key_der,
        context,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE_WITHOUT_ARC: &str = concat!(
        "From: alice@example.com\r\n",
        "To: bob@example.net\r\n",
        "Subject: no arc\r\n",
        "\r\n",
        "body\r\n"
    );

    fn resolver() -> MessageAuthenticator {
        crate::cache::system_resolver().expect("构造系统解析器")
    }

    #[tokio::test]
    async fn a_message_without_arc_headers_reports_none_rather_than_pass() {
        let result = verify_with(
            &resolver(),
            &TxtCache::new(),
            MESSAGE_WITHOUT_ARC.as_bytes(),
        )
        .await
        .expect("校验");
        assert_eq!(result.status, ArcStatus::None, "{result:?}");
        assert_eq!(result.sets, 0);
        assert!(!result.status.is_pass(), "无链不得判为 pass");
    }

    #[tokio::test]
    async fn a_truncated_arc_header_is_rejected_instead_of_being_ignored() {
        let message = concat!(
            "ARC-Seal: i=1; a=rsa-sha256\r\n",
            "From: alice@example.com\r\n",
            "To: bob@example.net\r\n",
            "\r\n",
            "body\r\n"
        );
        let result = verify_with(&resolver(), &TxtCache::new(), message.as_bytes())
            .await
            .expect("校验");
        assert!(
            !result.status.is_pass(),
            "残缺的 ARC 头不得判为 pass：{result:?}"
        );
    }

    #[test]
    fn keywords_follow_rfc8601() {
        assert_eq!(ArcStatus::Pass.keyword(), "pass");
        assert_eq!(ArcStatus::Fail(String::new()).keyword(), "fail");
        assert_eq!(ArcStatus::None.keyword(), "none");
    }

    #[test]
    fn header_from_domain_is_sanitised_and_falls_back_when_absent() {
        fn header_domain_for(from_line: &str, fallback: &str) -> String {
            let raw = format!("From: {from_line}\r\nTo: bob@example.net\r\n\r\nbody\r\n");
            let message = AuthenticatedMessage::parse(raw.as_bytes()).expect("报文应可解析");
            header_from(&message, fallback)
        }

        assert_eq!(
            header_domain_for("Alice@Example.COM", "fallback.test"),
            "example.com"
        );

        assert_eq!(
            header_domain_for("<Alice@Example.COM>", "fallback.test"),
            "example.com"
        );

        assert_eq!(
            header_domain_for("no-at-sign", "fallback.test"),
            "fallback.test"
        );
    }

    use crate::dkim::DEFAULT_SIGNED_HEADERS;
    use crate::keys::{dkim_txt_value, generate_key_material, DKIM_KEY_BITS};
    use std::net::Ipv4Addr;
    use std::sync::OnceLock;

    const MESSAGE: &str = concat!(
        "From: alice@example.com\r\n",
        "To: bob@example.net\r\n",
        "Subject: arc seal\r\n",
        "Date: Wed, 01 Oct 2026 10:00:00 +0800\r\n",
        "Message-ID: <arcselftest@example.com>\r\n",
        "\r\n",
        "这是一封用于 ARC 封印自检的邮件。\r\n"
    );

    struct Fixture {
        material: crate::keys::DkimKeyMaterial,
    }

    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| Fixture {
            material: generate_key_material("example.com", "mailstack", DKIM_KEY_BITS)
                .expect("生成密钥"),
        })
    }

    fn private_key_der(material: &crate::keys::DkimKeyMaterial) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.private");
        std::fs::write(&path, material.private_key_pem.as_bytes()).unwrap();
        crate::keys::load_private_key_der(&path).expect("解出私钥 DER")
    }

    fn cache(material: &crate::keys::DkimKeyMaterial) -> TxtCache {
        let cache = TxtCache::new();
        let value = dkim_txt_value(&material.public_key_spki_b64);
        cache
            .add_domain_key(
                &format!("{}._domainkey.{}", material.selector, material.domain),
                value.as_bytes(),
            )
            .expect("装载公钥记录");

        cache.pin_dmarc_walk(&material.domain);

        cache.pin_absent("mail.example.com");
        cache
            .add_spf(&material.domain, b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");
        cache
            .add_dmarc(
                &format!("_dmarc.{}", material.domain),
                b"v=DMARC1; p=reject",
            )
            .expect("装载 DMARC 记录");
        cache
    }

    fn context<'a>(material: &'a crate::keys::DkimKeyMaterial) -> SealContext<'a> {
        SealContext {
            hostname: "mx.mailstack.test",
            remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            helo_domain: "mail.example.com",
            mail_from: "alice@example.com",
            domain: &material.domain,
            selector: &material.selector,
        }
    }

    #[test]
    fn the_arc_header_set_is_the_dkim_set_plus_the_dkim_signature_header() {
        assert_eq!(
            &ARC_SIGNED_HEADERS[..DEFAULT_SIGNED_HEADERS.len()],
            DEFAULT_SIGNED_HEADERS,
            "前半段必须与 DKIM 默认集逐项一致"
        );
        assert_eq!(
            &ARC_SIGNED_HEADERS[DEFAULT_SIGNED_HEADERS.len()..],
            &["DKIM-Signature"],
            "只允许多出 DKIM-Signature 一项"
        );
        assert!(
            !ARC_SIGNED_HEADERS
                .iter()
                .any(|name| name.starts_with("ARC-")),
            "ARC-* 头不得进入 h=：本集合的三个头是在签名之后才前置的，写进去会让验签多出自己这一份"
        );
    }

    #[tokio::test]
    async fn a_sealed_message_verifies_as_an_arc_pass_and_keeps_the_original_bytes() {
        let material = &fixture().material;
        let cache = cache(material);

        let sealed = seal_with(
            &resolver(),
            &cache,
            MESSAGE.as_bytes(),
            &private_key_der(material),
            &context(material),
        )
        .await
        .expect("封印");

        let text = String::from_utf8(sealed.clone()).expect("封印结果是文本");

        assert!(text.starts_with("ARC-Seal:"), "{text:.200}");
        let seal_at = text.find("ARC-Seal:").unwrap();
        let sig_at = text.find("ARC-Message-Signature:").unwrap();
        let aar_at = text.find("ARC-Authentication-Results:").unwrap();
        let ar_at = text.find("Authentication-Results:").unwrap();
        assert!(
            seal_at < sig_at && sig_at < aar_at && aar_at < ar_at,
            "头部顺序必须是 AS → AMS → AAR → AR"
        );
        assert!(
            sealed.ends_with(MESSAGE.as_bytes()),
            "原报文必须逐字保留在最后（重排会让下游 DKIM 验签失败）"
        );
        assert!(
            text.contains("i=1;") && text.contains("cv=none"),
            "第一跳必须是 i=1、cv=none：{text:.400}"
        );

        let verdict = verify_with(&resolver(), &cache, &sealed)
            .await
            .expect("校验");
        assert_eq!(verdict.status, ArcStatus::Pass, "{verdict:?}");
        assert_eq!(verdict.sets, 1);
    }

    #[tokio::test]
    async fn sealing_twice_extends_the_chain_instead_of_replacing_it() {
        let material = &fixture().material;
        let cache = cache(material);
        let der = private_key_der(material);

        let once = seal_with(
            &resolver(),
            &cache,
            MESSAGE.as_bytes(),
            &der,
            &context(material),
        )
        .await
        .expect("第一次封印");
        let twice = seal_with(&resolver(), &cache, &once, &der, &context(material))
            .await
            .expect("第二次封印");

        let text = String::from_utf8(twice.clone()).expect("文本");
        assert!(text.contains("i=2;"), "第二跳必须递增到 i=2：{text:.300}");
        assert!(
            text.contains("cv=pass"),
            "第二跳的 cv 必须是上一跳的结论（pass）：{text:.300}"
        );

        let verdict = verify_with(&resolver(), &cache, &twice)
            .await
            .expect("校验");
        assert_eq!(verdict.status, ArcStatus::Pass, "{verdict:?}");
        assert_eq!(verdict.sets, 2, "两个集合都要在链上");
    }

    #[tokio::test]
    async fn a_tampered_body_fails_arc_verification_after_sealing() {
        let material = &fixture().material;
        let cache = cache(material);
        let sealed = seal_with(
            &resolver(),
            &cache,
            MESSAGE.as_bytes(),
            &private_key_der(material),
            &context(material),
        )
        .await
        .expect("封印");

        let mut tampered = sealed.clone();
        let marker = b"ARC \xe5\xb0\x81\xe5\x8d\xb0\xe8\x87\xaa\xe6\xa3\x80";
        let at = tampered
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("正文里应有标记串");
        tampered[at] = b'X';

        let verdict = verify_with(&resolver(), &cache, &tampered)
            .await
            .expect("校验");
        assert!(
            !verdict.status.is_pass(),
            "篡改正文后不得判为 pass：{verdict:?}"
        );
    }

    #[tokio::test]
    async fn an_unusable_key_or_message_is_refused_rather_than_half_sealed() {
        let material = &fixture().material;
        let cache = cache(material);

        let error = seal_with(
            &resolver(),
            &cache,
            MESSAGE.as_bytes(),
            b"not a private key",
            &context(material),
        )
        .await
        .expect_err("私钥不可用必须拒绝");
        assert_eq!(error.kind(), "SigningError");

        let error = seal_with(
            &resolver(),
            &cache,
            b"\x00\x01\x02",
            &private_key_der(material),
            &context(material),
        )
        .await
        .expect_err("不可解析的报文必须拒绝");
        assert_eq!(error.kind(), "SigningError");
    }
}

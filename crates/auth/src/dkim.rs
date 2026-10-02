//! DKIM 签名与验签（RFC 6376）。
//!
//! ## 签名
//!
//! [`sign`] 用 PKCS#1 DER 私钥对整封邮件签名，并把 `DKIM-Signature` 头**前置**到
//! 原报文之前（`DkimSigner` 的 `write(_, true)` 自带行尾 CRLF，所以直接拼接即可）。
//! 规范化默认 relaxed/relaxed —— 这是转发链路上最不容易被破坏的一种。
//!
//! ## 验签自检
//!
//! [`verify_with`] 用一个**注入的 TXT 缓存**在完全离线的情况下跑完整的 DKIM 验签。
//! 这是本阶段的验收要求之一：同一密钥对发出的邮件必须能验过。它同时是
//! 「`p=` 是否为 SPKI」的守门测试 —— mail-auth 的验签侧对 PKCS#1/SPKI **两种都容忍**
//! （`try_strip_rsa_prefix(..).unwrap_or(bytes)`），所以单靠验签通过**不能**证明
//! 记录形态正确；`keys.rs` 里另有前缀断言负责那一半。

use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;
use mail_auth::{AuthenticatedMessage, DkimOutput, DkimResult, MessageAuthenticator, Parameters};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};

use crate::cache::TxtCache;
use crate::error::{AuthError, AuthResult};

/// 默认签名的头集合。
///
/// `From` 是 RFC 6376 强制要求；其余是邮件生态里最常被篡改或用于展示的字段。
/// 列表里不存在于报文中的头会被自动跳过，因此不需要按邮件裁剪。
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

/// 单条 DKIM 签名的判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimStatus {
    Pass,
    Fail(String),
    PermissionError(String),
    TemporaryError(String),
    Neutral(String),
    /// 报文里根本没有 DKIM 签名。
    None,
}

impl DkimStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, DkimStatus::Pass)
    }

    /// `Authentication-Results` 里用的关键字（RFC 8601）。
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

/// 一条 DKIM 签名的验签结论。
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

/// 把 mail-auth 的逐签名输出折算成稳定结论。
///
/// 只有这一个折算点：验签自检与 DMARC 编排都走它，避免两处各写一份映射。
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

/// 取 RFC 5322 `From` 头的域（小写）。
///
/// 用来判断「这一封该不该由本机签名」：只有发件域落在本机策略覆盖范围内才签，
/// 否则就是拿自己的密钥去替别人的域背书。
///
/// 复用 mail-auth 的报文解析，而不是自己写一个取头正则 —— 头折叠、显示名里带
/// `@`、地址被 `<>` 包住、注释，这些坑它都已经处理过了。
pub fn from_domain(message: &[u8]) -> Option<String> {
    let parsed = AuthenticatedMessage::parse(message)?;
    let address = parsed.from.first()?;
    let (_, domain) = address.rsplit_once('@')?;
    // addr-spec 可能被 `>`、空白或注释包着，只取合法的域名字符。
    let domain: String = domain
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let domain = domain.trim_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// 用 PKCS#1 DER 私钥签名，返回「`DKIM-Signature` 头 + 原报文」。
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

/// 用 [`DEFAULT_SIGNED_HEADERS`] 签名。
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

/// 用给定的解析器 + TXT 缓存验签（离线可复现）。
///
/// 返回**逐签名**的结论；报文里没有任何 DKIM 头时返回空向量。
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

/// 用系统解析器验签。
///
/// 与 [`verify_with`] 的区别只在解析器来源：收信时校验对端必须走真实 DNS。
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

    /// 2048 位生成较慢，整个测试模块共用一套。
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
        // 缓存命中后不会真的发 DNS 查询，但解析器本身需要构造出来。
        crate::cache::system_resolver().expect("构造系统解析器")
    }

    /// 把 fixture 的公钥记录装进缓存，键必须是 mail-auth 会去查的 FQDN。
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
        // 本阶段的验收要求：自己签的邮件必须能自己验过。
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
        // 反例守卫：验签必须真的在做事，而不是「有签名就返回 pass」。
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
        // 注意按字节切片时窗口宽度必须是 need 的长度 —— 中文是多字节。
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
        // 这几种写法在真实邮件里都常见；写错任何一种都会让「该签的没签」。
        for (header, expected) in [
            ("From: alice@example.com\r\n", Some("example.com")),
            ("From: <alice@example.com>\r\n", Some("example.com")),
            (
                "From: \"Alice\" <alice@Example.COM>\r\n",
                Some("example.com"),
            ),
            // 显示名里带 @ 时，最后一个 @ 才是分隔符。
            ("From: \"a@b\" <alice@example.com>\r\n", Some("example.com")),
            // 折叠头：续行以空白开头。
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

        // 没有 From 或没有 @ 时不得凭空猜一个域出来。
        assert_eq!(from_domain(b"Subject: t\r\n\r\nbody\r\n"), None);
        assert_eq!(from_domain(b"From: not-an-address\r\n\r\nbody\r\n"), None);
        assert_eq!(from_domain(b""), None);
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

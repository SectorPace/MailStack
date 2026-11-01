//! ARC 链的校验与封印（RFC 8617）。
//!
//! ## 为什么校验本身就值得做
//!
//! ARC 的全部意义在于「经过转发后，第一跳的认证结果仍然可信」。转发链上的 ARC 头
//! 是**对端写进来的**，必须假定其内容不可信 —— 校验链的 `cv=` 与每一把
//! `ARC-Seal` 的签名，正是把「不可信输入」变成「可用结论」的那一步。
//!
//! ## 封印（[`seal_with`]）解决的是什么
//!
//! 一个**中转** MTA 收到邮件、做完 SPF/DKIM/DMARC/ARC 判定之后，如果还要把它转发
//! 出去，就必须把自己那一次判定连同「它当时看到的整条链」一起签进一个新集合：
//! `ARC-Authentication-Results`（结论）+ `ARC-Message-Signature`（正文与头部没被
//! 改动）+ `ARC-Seal`（整条链，含前几跳，未被改动）。下游因此可以越过一个「会破坏
//! SPF 的转发者」继续信任最初那一跳。
//!
//! 封印的输出是「ARC 三件套 + `Authentication-Results` + 原报文」。原报文**逐字**
//! 保留在最后 —— 任何重排都会让下游的 DKIM 验签失败。
//!
//! ## 两处刻意收紧的地方
//!
//! 1. **链已损坏就拒绝封印**（`cv=fail`）。mail-auth 的 `can_be_sealed()` 就是这条
//!    判据：在一个已经断裂的链上继续盖章，只会把「不可信」包装成「可信」。
//! 2. **`ARC-Message-Signature` 的 `h=` 里不写 `ARC-*`**。这不是疏漏：我们的实现
//!    （mail-auth）在解析 `h=` 时会收集**所有**同名头，而本集合的三个头是在签名
//!    之后才前置进报文的 —— 写进去会让验签时多出自己这一份，签名必然对不上。
//!    整条链的完整性由 **`ARC-Seal`** 保证（它按 RFC 8617 §4.1.3 覆盖前几跳的
//!    AAR/AMS/AS 与本次的三件套），见 [`ARC_SIGNED_HEADERS`]。

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

/// ARC 链的判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcStatus {
    Pass,
    Fail(String),
    TemporaryError(String),
    PermissionError(String),
    /// 报文里没有 ARC 链（不是错误，只是没有可继承的结论）。
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

/// 一条 ARC 链的校验结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcVerdict {
    pub status: ArcStatus,
    /// 链上封存的集合数（`i=` 的最大值）；无链时为 0。
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

/// 用给定解析器 + TXT 缓存校验 ARC 链（离线可复现）。
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

/// 用系统解析器校验 ARC 链。
pub async fn verify(message: &[u8]) -> AuthResult<ArcVerdict> {
    let resolver = crate::cache::system_resolver()?;
    verify_with(&resolver, &TxtCache::new(), message).await
}

/// ARC-Message-Signature 覆盖的头字段。
///
/// 等于 DKIM 的默认集加上 `DKIM-Signature`（把「上游那一跳的签名头」也纳入覆盖，
/// 否则它可以被单独剥掉）。**刻意不含任何 `ARC-*`**，理由见模块说明。
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

/// 封印所需的事实（入站 MTA 在处理这条连接时已经全部掌握）。
#[derive(Debug, Clone, Copy)]
pub struct SealContext<'a> {
    /// authserv-id：本机对外主机名（同时用作 SPF 的 `%{h}` 宏输入）。
    pub hostname: &'a str,
    /// 对端连接源地址。
    pub remote_ip: IpAddr,
    /// 对端声明的 HELO 域。
    pub helo_domain: &'a str,
    /// `MAIL FROM` 的完整地址（空串表示 null sender）。
    pub mail_from: &'a str,
    /// 盖章域：本机 DKIM 密钥的 `d=`。
    pub domain: &'a str,
    /// 盖章选择器：本机 DKIM 密钥的 `s=`。
    pub selector: &'a str,
}

/// 取 RFC 5322 `From` 的域（供 `dkim=` / `dmarc=` 的 `header.from=` 使用）。
///
/// 与信封侧共用同一套清洗（`dmarc::sanitize_domain_part`）：域半段可能带 `>`
/// 尾巴或大写，直接进 `Authentication-Results` / 对齐比较会静默失配。
/// mail-auth 解析 `From` 时已做过一次小写折叠与括号剥离，这里是**纵深防御**
/// （两条口径必须同源，而不是各自信任上游的某个实现细节）。
/// 清洗后为空（如 `user@`）或没有 `@` 时退回 `fallback`。
fn header_from(message: &AuthenticatedMessage<'_>, fallback: &str) -> String {
    message
        .from
        .first()
        .and_then(|address| address.rsplit_once('@'))
        .map(|(_, domain)| crate::dmarc::sanitize_domain_part(domain))
        .filter(|domain| !domain.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// 为一封**已收到的**邮件加一个 ARC 集合，返回新的完整报文。
///
/// 输入是「原报文 + 入站上下文 + 本机私钥」，输出是
/// `ARC-Seal` → `ARC-Message-Signature` → `ARC-Authentication-Results` →
/// `Authentication-Results` → 原报文（逐字）。
///
/// 内部的 SPF/DKIM/DMARC 结论**重算一次**并写进 `ARC-Authentication-Results`：
/// 这是「本次盖章的 MTA 自己的判定」，与调用方在收信时算的那一份内容一致；
/// 不共享调用方的中间结论，是为了让这个 API 不依赖调用方把 mail-auth 的原始输出
/// 一路透传上来（那会让 seal 的签名输入与验证输入分属两处，更容易走样）。
///
/// 失败即**拒绝盖章**（不产出半成品）：链已损坏、报文不可解析、私钥不可用。
pub async fn seal_with(
    resolver: &MessageAuthenticator,
    cache: &TxtCache,
    message: &[u8],
    private_key_der: &[u8],
    context: &SealContext<'_>,
) -> AuthResult<Vec<u8>> {
    let parsed = AuthenticatedMessage::parse(message)
        .ok_or_else(|| AuthError::Signing("message could not be parsed".to_string()))?;

    // 1) 先看现有链能不能被续封。`cv=fail` 时拒绝对外盖章。
    let arc_output = resolver
        .verify_arc(Parameters::new(&parsed).with_txt_cache(cache))
        .await;
    if !arc_output.can_be_sealed() {
        return Err(AuthError::Signing(
            "ARC chain cannot be sealed (cv=fail)".to_string(),
        ));
    }

    // 2) 本次的判定（与收信侧同一套实现，避免两处各算一份）。
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
    // 信封域与 dmarc::evaluate 共用同一套清洗（crate::dmarc::sanitized_domain）：
    // 上游传来的 MAIL FROM 可能是 `<User@Example.COM>` 这类形态，裸
    // `rsplit_once('@')` 会切出 `Example.COM>` —— DMARC 对齐比较是逐字的，
    // 于是**静默**失败。两条路径只有一个清洗来源，才不会各走样一份。
    // 无 `@`（null sender 等）时为空串，与「无信封发件人身份」的 DMARC 语义一致。
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

/// 用系统解析器封印。
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
        // 关键语义：没有链**不等于**通过。把「没有 ARC」当成 pass 会让一条
        // 被剥掉 ARC 头的邮件伪装成已验证。
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
        // ARC-Seal 缺少必需标签时必须判失败，而不是「跳过这条头继续」。
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

    /// `header_from` 与信封侧必须共用同一套域清洗（`dmarc::sanitize_domain_part`）：
    /// 大写折叠、去 `>` 尾巴，且没有可用域时退回 fallback 而不是产出空域 ——
    /// 空域进 `Authentication-Results` / 对齐比较会静默失配。
    #[test]
    fn header_from_domain_is_sanitised_and_falls_back_when_absent() {
        // 解析结果借用了报文字节，所以在这个辅助函数内完成「解析 → 取域」，
        // 只把 owned 的结果带出去。
        fn header_domain_for(from_line: &str, fallback: &str) -> String {
            let raw = format!("From: {from_line}\r\nTo: bob@example.net\r\n\r\nbody\r\n");
            let message =
                AuthenticatedMessage::parse(raw.as_bytes()).expect("报文应可解析");
            header_from(&message, fallback)
        }

        // 大写折叠为小写域。
        assert_eq!(header_domain_for("Alice@Example.COM", "fallback.test"), "example.com");

        // 角括号形式同样取域（mail-auth 解析时已剥离，清洗不得破坏）。
        assert_eq!(
            header_domain_for("<Alice@Example.COM>", "fallback.test"),
            "example.com"
        );

        // 没有 @（解析不出地址或域为空）：退回 fallback。
        assert_eq!(header_domain_for("no-at-sign", "fallback.test"), "fallback.test");
    }

    // ─────────────────────────── 封印（RFC 8617 §5） ───────────────────────────

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

    /// 2048 位生成较慢，整个测试模块共用一套。
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

    /// 把盖章用的公钥与 SPF/DMARC 记录装进缓存 —— 让整条链**离线可复现**。
    fn cache(material: &crate::keys::DkimKeyMaterial) -> TxtCache {
        let cache = TxtCache::new();
        let value = dkim_txt_value(&material.public_key_spki_b64);
        cache
            .add_domain_key(
                &format!("{}._domainkey.{}", material.selector, material.domain),
                value.as_bytes(),
            )
            .expect("装载公钥记录");
        // DMARC 会从 From 域逐级向上走查；不把祖先那一级也钉住就会漏到真实 DNS。
        cache.pin_dmarc_walk(&material.domain);
        // SPF 会**先查 HELO 域**（`Sender::Full`）；不钉住就会发真实 DNS。
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
        // 防漂移：ARC-Message-Signature 覆盖的头必须**恰好**是 DKIM 默认集再加一个
        // `DKIM-Signature`（少签 DKIM 头，上游签名就能被单独剥掉）。
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
        // 本阶段的验收要求：自己封的链必须能自己验过（与 DKIM 的自签自验同构）。
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
        // 顺序：三件套 → Authentication-Results → 原报文。顺序错了下游会读不懂。
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
        // 反例守卫：验签必须真的在做事，而不是「有 ARC 头就返回 pass」。
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
        let marker = b"ARC \xe5\xb0\x81\xe5\x8d\xb0\xe8\x87\xaa\xe6\xa3\x80"; // "ARC 封印自检"
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

        // 私钥不是 DER：拒绝，而不是产出没有签名能力的「半成品」。
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

        // 报文不可解析：同样拒绝。
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

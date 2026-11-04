use std::net::IpAddr;

use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::{AuthenticatedMessage, DmarcResult, MessageAuthenticator, Parameters};

use crate::cache::TxtCache;
use crate::dkim::{DkimStatus, DkimVerdict};
use crate::error::{AuthError, AuthResult};
use crate::spf::{SpfCheck, SpfStatus};

pub const MULTI_FROM_REASON: &str = "multiple RFC5322.From domains";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcStatus {
    Pass,
    Fail(String),
    TemporaryError(String),
    PermissionError(String),

    None,
}

impl DmarcStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, DmarcStatus::Pass)
    }

    pub fn keyword(&self) -> &'static str {
        match self {
            DmarcStatus::Pass => "pass",
            DmarcStatus::Fail(_) => "fail",
            DmarcStatus::TemporaryError(_) => "temperror",
            DmarcStatus::PermissionError(_) => "permerror",
            DmarcStatus::None => "none",
        }
    }

    pub fn is_multi_from(&self) -> bool {
        matches!(self, DmarcStatus::Fail(reason) if reason.starts_with(MULTI_FROM_REASON))
    }
}

impl From<&DmarcResult> for DmarcStatus {
    fn from(value: &DmarcResult) -> Self {
        match value {
            DmarcResult::Pass => DmarcStatus::Pass,
            DmarcResult::Fail(error) => DmarcStatus::Fail(error.to_string()),
            DmarcResult::TempError(error) => DmarcStatus::TemporaryError(error.to_string()),
            DmarcResult::PermError(error) => DmarcStatus::PermissionError(error.to_string()),
            DmarcResult::None => DmarcStatus::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcCheck {
    pub status: DmarcStatus,

    pub domain: String,

    pub policy: String,

    pub policy_value: DmarcPolicy,
    pub spf: SpfCheck,
    pub dkim: Vec<DkimVerdict>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,

    Quarantine,

    Reject,

    Unspecified,
}

impl DmarcPolicy {
    pub fn is_reject(self) -> bool {
        matches!(self, DmarcPolicy::Reject)
    }

    pub fn keyword(self) -> &'static str {
        match self {
            DmarcPolicy::None => "none",
            DmarcPolicy::Quarantine => "quarantine",
            DmarcPolicy::Reject => "reject",
            DmarcPolicy::Unspecified => "unspecified",
        }
    }
}

impl From<mail_auth::dmarc::Policy> for DmarcPolicy {
    fn from(value: mail_auth::dmarc::Policy) -> Self {
        use mail_auth::dmarc::Policy as P;
        match value {
            P::None => DmarcPolicy::None,
            P::Quarantine => DmarcPolicy::Quarantine,
            P::Reject => DmarcPolicy::Reject,

            P::Unspecified => DmarcPolicy::Unspecified,
        }
    }
}

pub async fn evaluate(
    resolver: &MessageAuthenticator,
    cache: &TxtCache,
    message: &[u8],
    ip: IpAddr,
    helo_domain: &str,
    host_domain: &str,
    sender: &str,
) -> AuthResult<DmarcCheck> {
    let spf_output =
        crate::spf::check_raw(resolver, cache, ip, helo_domain, host_domain, sender).await;
    let spf = SpfCheck::from_output(&spf_output);

    let parsed = AuthenticatedMessage::parse(message)
        .ok_or_else(|| AuthError::Signing("message could not be parsed".to_string()))?;

    let dkim_outputs = resolver
        .verify_dkim(Parameters::new(&parsed).with_txt_cache(cache))
        .await;
    let dkim = crate::dkim::verdicts_from(&dkim_outputs);

    let from_domains = from_domains(&parsed);
    if from_domains.len() > 1 {
        let domains = from_domains.join(", ");
        return Ok(DmarcCheck {
            status: DmarcStatus::Fail(format!(
                "{MULTI_FROM_REASON} ({domains}); RFC 7489 §6.6.1 requires the most strict \
                 policy, and the strictest available reading is fail-closed"
            )),
            domain: domains,

            policy: String::new(),
            policy_value: DmarcPolicy::Reject,
            spf,
            dkim,
        });
    }

    let mail_from_domain = sanitized_domain(sender);

    let params = DmarcParameters {
        message: &parsed,
        dkim_output: &dkim_outputs,
        dkim2_output: None,
        rfc5321_mail_from_domain: mail_from_domain.as_str(),
        spf_output: &spf_output,
    };
    let output = resolver
        .verify_dmarc(Parameters::new(params).with_txt_cache(cache))
        .await;

    let status = DmarcStatus::from(&output.result());
    let domain = output.domain().to_string();

    let published = DmarcPolicy::from(output.policy());

    let policy_value = if matches!(status, DmarcStatus::Fail(_))
        && matches!(published, DmarcPolicy::Reject | DmarcPolicy::Quarantine)
    {
        match cache.raw_dmarc_record(&domain) {
            None => published,
            Some(raw) => {
                let message_id = parsed
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(b"message-id"))
                    .map(|(_, value)| *value)
                    .unwrap_or_default();
                let draw = policy_sample_draw(&domain, message_id);
                effective_policy(published, parse_pct(&raw), draw)
            }
        }
    } else {
        published
    };

    Ok(DmarcCheck {
        status,
        domain,
        policy: format!("{:?}", output.policy()).to_lowercase(),
        policy_value,
        spf,
        dkim,
    })
}

impl DmarcCheck {
    pub fn spf_pass(&self) -> bool {
        self.spf.status == SpfStatus::Pass
    }

    pub fn dkim_pass(&self) -> bool {
        self.dkim
            .iter()
            .any(|verdict| verdict.status == DkimStatus::Pass)
    }

    pub fn policy_is_reject(&self) -> bool {
        self.policy_value.is_reject()
    }
}

pub fn weaken_one_step(published: DmarcPolicy) -> DmarcPolicy {
    match published {
        DmarcPolicy::Reject => DmarcPolicy::Quarantine,
        DmarcPolicy::Quarantine => DmarcPolicy::None,
        other => other,
    }
}

pub fn effective_policy(published: DmarcPolicy, pct: Option<u8>, draw: u8) -> DmarcPolicy {
    match pct {
        Some(pct) if pct < 100 && draw >= pct => weaken_one_step(published),
        _ => published,
    }
}

pub fn parse_pct(record: &str) -> Option<u8> {
    for tag in record.split(';') {
        let Some((name, value)) = tag.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("pct") {
            continue;
        }
        let value = value.trim();

        if value.is_empty() || value.len() > 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let parsed: u16 = value.parse().ok()?;
        return (parsed <= 100).then_some(parsed as u8);
    }
    None
}

pub fn policy_sample_draw(domain: &str, message_id: &[u8]) -> u8 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    policy_sample_draw_from(domain, message_id, nanos)
}

fn policy_sample_draw_from(domain: &str, message_id: &[u8], nanos: u128) -> u8 {
    use std::hash::Hasher;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(domain.as_bytes());
    hasher.write(message_id);
    hasher.write(&nanos.to_le_bytes());
    (hasher.finish() % 100) as u8
}

pub fn from_domains(parsed: &AuthenticatedMessage<'_>) -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    for address in &parsed.from {
        let Some((_, domain)) = address.rsplit_once('@') else {
            continue;
        };
        let domain = sanitize_domain_part(domain);
        if domain.is_empty() {
            continue;
        }
        if !domains.iter().any(|seen| seen == &domain) {
            domains.push(domain);
        }
    }
    domains
}

pub(crate) fn sanitize_domain_part(domain: &str) -> String {
    domain.trim().trim_end_matches('>').to_ascii_lowercase()
}

pub(crate) fn sanitized_domain(sender: &str) -> String {
    let sender = sender.trim().trim_matches(|c| c == '<' || c == '>').trim();
    sender
        .rsplit_once('@')
        .map(|(_, domain)| sanitize_domain_part(domain))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const MESSAGE: &str = concat!(
        "From: alice@example.com\r\n",
        "To: bob@example.net\r\n",
        "Subject: dmarc\r\n",
        "Date: Wed, 01 Oct 2026 10:00:00 +0800\r\n",
        "\r\n",
        "body\r\n"
    );

    fn resolver() -> MessageAuthenticator {
        crate::cache::system_resolver().expect("构造系统解析器")
    }

    fn message_with_id(id: usize) -> String {
        format!(
            "From: alice@example.com\r\n\
             To: bob@example.net\r\n\
             Subject: dmarc\r\n\
             Message-ID: <pct{id}@example.com>\r\n\
             Date: Wed, 01 Oct 2026 10:00:00 +0800\r\n\
             \r\n\
             body\r\n"
        )
    }

    #[tokio::test]
    async fn an_aligned_spf_passes_dmarc_without_any_dkim_signature() {
        let cache = TxtCache::new();

        cache.pin_dmarc_walk("example.com");

        cache.pin_absent("mail.example.com");
        cache
            .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");
        cache
            .add_dmarc(
                "_dmarc.example.com",
                b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            )
            .expect("装载 DMARC 记录");

        let check = evaluate(
            &resolver(),
            &cache,
            MESSAGE.as_bytes(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            "mail.example.com",
            "mx.mailstack.test",
            "alice@example.com",
        )
        .await
        .expect("评估");

        assert_eq!(check.status, DmarcStatus::Pass, "{check:?}");
        assert_eq!(check.domain, "example.com");
        assert_eq!(check.policy, "reject");

        assert!(check.policy_is_reject());
        assert_eq!(check.policy_value, DmarcPolicy::Reject);
        assert!(check.spf_pass());
        assert!(
            !check.dkim_pass(),
            "报文里没有 DKIM 签名，不该凭空产生通过结论"
        );
    }

    #[tokio::test]
    async fn an_unaligned_source_fails_a_reject_policy() {
        let cache = TxtCache::new();
        cache.pin_dmarc_walk("example.com");

        cache.pin_absent("mail.example.com");
        cache
            .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");
        cache
            .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject")
            .expect("装载 DMARC 记录");

        let check = evaluate(
            &resolver(),
            &cache,
            MESSAGE.as_bytes(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            "mail.example.com",
            "mx.mailstack.test",
            "alice@example.com",
        )
        .await
        .expect("评估");

        assert!(
            !check.status.is_pass(),
            "SPF 与 DKIM 都不对齐时必须判失败：{check:?}"
        );
        assert_eq!(
            check.status,
            DmarcStatus::Fail("Policy not aligned".to_string())
        );

        assert_eq!(check.policy_value, DmarcPolicy::Reject);
        assert!(check.policy_is_reject());
        assert_eq!(check.policy, "reject", "展示字符串仍是已公布策略");
    }

    const MULTI_FROM_ONE_HEADER: &str = concat!(
        "From: ceo@bank.com, x@evil.test\r\n",
        "To: bob@example.net\r\n",
        "Subject: multi\r\n",
        "Date: Wed, 01 Oct 2026 10:00:00 +0800\r\n",
        "\r\n",
        "body\r\n"
    );

    const MULTI_FROM_TWO_HEADERS: &str = concat!(
        "From: ceo@bank.com\r\n",
        "From: x@evil.test\r\n",
        "To: bob@example.net\r\n",
        "Subject: multi\r\n",
        "Date: Wed, 01 Oct 2026 10:00:00 +0800\r\n",
        "\r\n",
        "body\r\n"
    );

    fn cache_with_names_absent(names: &[&str]) -> TxtCache {
        let cache = TxtCache::new();
        for name in names {
            cache.pin_absent(name);
        }
        cache
    }

    #[tokio::test]
    async fn a_single_from_header_with_two_domains_is_failed_instead_of_exempted() {
        let cache =
            cache_with_names_absent(&["mail.example.com", "bank.com", "evil.test", "example.com"]);

        let check = evaluate(
            &resolver(),
            &cache,
            MULTI_FROM_ONE_HEADER.as_bytes(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            "mail.example.com",
            "mx.mailstack.test",
            "ceo@bank.com",
        )
        .await
        .expect("评估");

        assert!(
            check.status.is_multi_from(),
            "多 From 域必须被显式识别并判 fail：{check:?}"
        );
        assert!(
            !matches!(check.status, DmarcStatus::None),
            "多 From 域不得被当成「该域没有策略」放行"
        );
        assert_eq!(check.status.keyword(), "fail");
        assert!(
            check.policy_is_reject(),
            "无法确定唯一作者域/策略时必须按最严策略处理（fail-closed）"
        );
        assert_eq!(check.domain, "bank.com, evil.test", "判定要带上全部作者域");
        assert_eq!(
            check.policy, "",
            "没有唯一可引用的已公布策略，不得编一个出来"
        );
    }

    #[tokio::test]
    async fn two_from_headers_with_different_domains_are_failed_too() {
        let cache =
            cache_with_names_absent(&["mail.example.com", "bank.com", "evil.test", "example.com"]);
        let check = evaluate(
            &resolver(),
            &cache,
            MULTI_FROM_TWO_HEADERS.as_bytes(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            "mail.example.com",
            "mx.mailstack.test",
            "ceo@bank.com",
        )
        .await
        .expect("评估");

        assert!(check.status.is_multi_from(), "{check:?}");
        assert!(check.policy_is_reject());
    }

    #[tokio::test]
    async fn same_domain_multiple_from_addresses_still_evaluate_normally() {
        let cache = TxtCache::new();
        cache.pin_dmarc_walk("example.com");
        cache.pin_absent("mail.example.com");
        cache
            .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");
        cache
            .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject")
            .expect("装载 DMARC 记录");

        let message = concat!(
            "From: alice@example.com, bob@EXAMPLE.com\r\n",
            "To: carol@example.net\r\n",
            "Subject: same domain\r\n",
            "Date: Wed, 01 Oct 2026 10:00:00 +0800\r\n",
            "\r\n",
            "body\r\n"
        );
        let check = evaluate(
            &resolver(),
            &cache,
            message.as_bytes(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            "mail.example.com",
            "mx.mailstack.test",
            "alice@example.com",
        )
        .await
        .expect("评估");

        assert!(
            !check.status.is_multi_from(),
            "同域多地址不得被当成多 From 域：{check:?}"
        );
        assert_eq!(check.status, DmarcStatus::Pass, "对齐的 SPF 仍应 pass");
        assert!(check.policy_is_reject());
    }

    #[test]
    fn from_domains_dedups_and_normalises_before_the_multi_from_check() {
        let parsed = AuthenticatedMessage::parse(
            b"From: \"A\" <a@Example.COM>, b@example.com\r\nFrom: c@other.test\r\n\r\nbody",
        )
        .expect("解析报文");
        assert_eq!(
            from_domains(&parsed),
            vec!["example.com".to_string(), "other.test".to_string()]
        );

        let parsed =
            AuthenticatedMessage::parse(b"From: not-an-address\r\n\r\nbody").expect("解析");
        assert!(
            from_domains(&parsed).is_empty(),
            "没有合法域时不得凭空造出一个域（否则会误判为多域）"
        );
    }

    #[tokio::test]
    async fn pct_is_not_available_on_the_network_parse_path() {
        use mail_auth::common::parse::TxtRecordParser;
        use mail_auth::dmarc::Dmarc;
        use mail_auth::ResolverCache;
        use std::time::{Duration, Instant};

        let cache = TxtCache::new();
        cache.pin_dmarc_walk("example.com");
        cache.pin_absent("mail.example.com");
        cache
            .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");

        let parsed = Dmarc::parse(b"v=DMARC1; p=reject; pct=0").expect("解析记录");
        let value: mail_auth::Txt = parsed.into();
        cache.insert(
            "_dmarc.example.com.".into(),
            value,
            Instant::now() + Duration::from_secs(60),
        );

        assert!(
            cache.raw_dmarc_record("example.com").is_none(),
            "联网解析路径拿不到原始文本（pct 已被上游丢弃）"
        );

        let check = evaluate(
            &resolver(),
            &cache,
            MESSAGE.as_bytes(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            "mail.example.com",
            "mx.mailstack.test",
            "alice@example.com",
        )
        .await
        .expect("评估");

        assert_eq!(
            check.status,
            DmarcStatus::Fail("Policy not aligned".to_string())
        );
        assert_eq!(
            check.policy_value,
            DmarcPolicy::Reject,
            "pct=0 在生产路径不生效：按 100% 执行（已知偏离）"
        );
        assert!(check.policy_is_reject());
    }

    #[test]
    fn every_dmarc_result_maps_to_a_status() {
        for (raw, expected) in [
            (DmarcResult::Pass, DmarcStatus::Pass),
            (
                DmarcResult::Fail(mail_auth::Error::NotAligned),
                DmarcStatus::Fail("Policy not aligned".to_string()),
            ),
            (DmarcResult::None, DmarcStatus::None),
        ] {
            assert_eq!(DmarcStatus::from(&raw), expected, "{raw:?}");
        }
    }

    #[test]
    fn keywords_follow_rfc8601() {
        assert_eq!(DmarcStatus::Pass.keyword(), "pass");
        assert_eq!(DmarcStatus::Fail(String::new()).keyword(), "fail");
        assert_eq!(
            DmarcStatus::TemporaryError(String::new()).keyword(),
            "temperror"
        );
        assert_eq!(
            DmarcStatus::PermissionError(String::new()).keyword(),
            "permerror"
        );
        assert_eq!(DmarcStatus::None.keyword(), "none");
    }

    #[tokio::test]
    async fn pct_zero_weakens_every_failing_message() {
        let cache = TxtCache::new();
        cache.pin_dmarc_walk("example.com");
        cache.pin_absent("mail.example.com");
        cache
            .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");
        cache
            .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject; pct=0")
            .expect("装载 DMARC 记录");
        let resolver = resolver();

        for id in 0..3 {
            let message = message_with_id(id);
            let check = evaluate(
                &resolver,
                &cache,
                message.as_bytes(),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                "mail.example.com",
                "mx.mailstack.test",
                "alice@example.com",
            )
            .await
            .expect("评估");
            assert_eq!(
                check.status,
                DmarcStatus::Fail("Policy not aligned".to_string()),
                "pct 只弱化处置，不改变判定本身"
            );
            assert_eq!(
                check.policy_value,
                DmarcPolicy::Quarantine,
                "pct=0 时第 {id} 封必须被弱化"
            );
            assert!(!check.policy_is_reject());
            assert_eq!(check.policy, "reject", "展示字符串仍是已公布策略");
        }
    }

    #[tokio::test]
    async fn pct_hundred_and_absent_keep_the_published_policy() {
        for record in [
            b"v=DMARC1; p=reject; pct=100".as_slice(),
            b"v=DMARC1; p=reject".as_slice(),
        ] {
            let cache = TxtCache::new();
            cache.pin_dmarc_walk("example.com");
            cache.pin_absent("mail.example.com");
            cache
                .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
                .expect("装载 SPF 记录");
            cache
                .add_dmarc("_dmarc.example.com", record)
                .expect("装载 DMARC 记录");

            for id in 0..3 {
                let message = message_with_id(id);
                let check = evaluate(
                    &resolver(),
                    &cache,
                    message.as_bytes(),
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                    "mail.example.com",
                    "mx.mailstack.test",
                    "alice@example.com",
                )
                .await
                .expect("评估");
                assert_eq!(
                    check.policy_value,
                    DmarcPolicy::Reject,
                    "record = {}，第 {id} 封不得被弱化",
                    String::from_utf8_lossy(record)
                );
            }
        }
    }

    #[tokio::test]
    async fn pct_ten_weakens_most_but_not_all_failing_messages() {
        let cache = TxtCache::new();
        cache.pin_dmarc_walk("example.com");
        cache.pin_absent("mail.example.com");
        cache
            .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");
        cache
            .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject; pct=10")
            .expect("装载 DMARC 记录");
        let resolver = resolver();

        let mut rejected = 0;
        let mut quarantined = 0;
        for id in 0..60 {
            let message = message_with_id(id);
            let check = evaluate(
                &resolver,
                &cache,
                message.as_bytes(),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                "mail.example.com",
                "mx.mailstack.test",
                "alice@example.com",
            )
            .await
            .expect("评估");
            match check.policy_value {
                DmarcPolicy::Reject => rejected += 1,
                DmarcPolicy::Quarantine => quarantined += 1,
                other => panic!("p=reject 的弱化只可能到 quarantine，实际 {other:?}"),
            }
        }
        assert!(
            rejected > 0,
            "抽样必须命中一部分（期望 ~10%）：{rejected}/60"
        );
        assert!(
            quarantined >= 30,
            "落选必须占绝大多数（期望 ~90%）：rejected={rejected} quarantined={quarantined}"
        );
    }

    #[test]
    fn mail_from_domain_is_sanitised_before_dmarc_alignment() {
        for (raw, expected) in [
            ("alice@example.com", "example.com"),
            ("<alice@example.com>", "example.com"),
            ("  alice@Example.COM  ", "example.com"),
            ("<Alice@Example.COM>", "example.com"),
            ("alice@sub.example.com", "sub.example.com"),
            ("<>", ""),
            ("", ""),
            ("postmaster", ""),
        ] {
            assert_eq!(sanitized_domain(raw), expected, "raw = {raw:?}");
        }
    }

    #[test]
    fn sanitize_domain_part_is_the_shared_normaliser() {
        assert_eq!(sanitize_domain_part(" Example.COM> "), "example.com");
        assert_eq!(sanitize_domain_part("Sub.Example.COM"), "sub.example.com");
        assert_eq!(sanitize_domain_part("example.com>"), "example.com");
        assert_eq!(sanitize_domain_part(""), "");
    }

    #[test]
    fn parse_pct_follows_rfc7489_defaults() {
        assert_eq!(parse_pct("v=DMARC1; p=reject; pct=25"), Some(25));
        assert_eq!(parse_pct("v=DMARC1; p=quarantine; pct=0"), Some(0));
        assert_eq!(parse_pct("v=DMARC1; p=reject; pct=100"), Some(100));

        assert_eq!(parse_pct("v=DMARC1; p=reject; PCT=25"), Some(25));

        assert_eq!(parse_pct("v=DMARC1; p=reject"), None);

        assert_eq!(parse_pct("v=DMARC1; p=reject; pct="), None);
        assert_eq!(parse_pct("v=DMARC1; p=reject; pct=abc"), None);
        assert_eq!(parse_pct("v=DMARC1; p=reject; pct=101"), None);
        assert_eq!(parse_pct("v=DMARC1; p=reject; pct=-1"), None);
        assert_eq!(parse_pct("v=DMARC1; p=reject; pct=2 5"), None);
    }

    #[test]
    fn effective_policy_follows_rfc7489_pct_sampling() {
        let reject = DmarcPolicy::Reject;
        let quarantine = DmarcPolicy::Quarantine;

        for draw in [0u8, 25, 99] {
            assert_eq!(effective_policy(reject, None, draw), reject);
            assert_eq!(effective_policy(reject, Some(100), draw), reject);
        }

        assert_eq!(effective_policy(reject, Some(25), 0), reject);
        assert_eq!(effective_policy(reject, Some(25), 24), reject);

        assert_eq!(effective_policy(reject, Some(25), 25), quarantine);
        assert_eq!(effective_policy(reject, Some(25), 99), quarantine);

        assert_eq!(
            effective_policy(quarantine, Some(10), 50),
            DmarcPolicy::None
        );
        assert_eq!(
            effective_policy(DmarcPolicy::None, Some(10), 50),
            DmarcPolicy::None
        );
        assert_eq!(
            effective_policy(DmarcPolicy::Unspecified, Some(10), 50),
            DmarcPolicy::Unspecified
        );

        assert_eq!(effective_policy(reject, Some(0), 0), quarantine);

        for published in [reject, quarantine] {
            let weakened = effective_policy(published, Some(10), 99);
            assert_ne!(weakened, DmarcPolicy::Reject, "落选不得落在 reject 上");
        }
    }

    #[test]
    fn sample_draw_is_deterministic_bounded_and_spread() {
        assert_eq!(
            policy_sample_draw_from("example.com", b"<id@example.com>", 1_000),
            policy_sample_draw_from("example.com", b"<id@example.com>", 1_000)
        );

        for nanos in [0u128, 1, 42, u128::from(u64::MAX), u128::MAX] {
            let draw = policy_sample_draw_from("example.com", b"x", nanos);
            assert!(draw < 100, "抽签必须落在 0..100，实际 {draw}");
        }

        let draws: std::collections::HashSet<u8> = (0u128..32)
            .map(|nanos| policy_sample_draw_from("example.com", b"m", nanos))
            .collect();
        assert!(draws.len() > 1, "抽签不应退化成常数: {draws:?}");
    }
}

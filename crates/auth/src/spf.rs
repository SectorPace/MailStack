use std::net::IpAddr;

use mail_auth::spf::verify::SpfParameters;
use mail_auth::{MessageAuthenticator, Parameters, SpfResult};

use crate::cache::TxtCache;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfStatus {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,

    None,
}

impl SpfStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, SpfStatus::Pass)
    }

    pub fn keyword(&self) -> &'static str {
        match self {
            SpfStatus::Pass => "pass",
            SpfStatus::Fail => "fail",
            SpfStatus::SoftFail => "softfail",
            SpfStatus::Neutral => "neutral",
            SpfStatus::TempError => "temperror",
            SpfStatus::PermError => "permerror",
            SpfStatus::None => "none",
        }
    }
}

impl From<SpfResult> for SpfStatus {
    fn from(value: SpfResult) -> Self {
        match value {
            SpfResult::Pass => SpfStatus::Pass,
            SpfResult::Fail => SpfStatus::Fail,
            SpfResult::SoftFail => SpfStatus::SoftFail,
            SpfResult::Neutral => SpfStatus::Neutral,
            SpfResult::TempError => SpfStatus::TempError,
            SpfResult::PermError => SpfStatus::PermError,
            SpfResult::None => SpfStatus::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfCheck {
    pub status: SpfStatus,

    pub domain: String,
    pub explanation: Option<String>,
}

impl SpfCheck {
    pub(crate) fn from_output(output: &mail_auth::SpfOutput) -> Self {
        Self {
            status: output.result().into(),
            domain: output.domain().to_string(),
            explanation: output.explanation().map(str::to_string),
        }
    }
}

pub async fn check(
    resolver: &MessageAuthenticator,
    cache: &TxtCache,
    ip: IpAddr,
    helo_domain: &str,
    host_domain: &str,
    sender: &str,
) -> SpfCheck {
    SpfCheck::from_output(&check_raw(resolver, cache, ip, helo_domain, host_domain, sender).await)
}

pub(crate) async fn check_raw(
    resolver: &MessageAuthenticator,
    cache: &TxtCache,
    ip: IpAddr,
    helo_domain: &str,
    host_domain: &str,
    sender: &str,
) -> mail_auth::SpfOutput {
    let params = SpfParameters::verify(ip, helo_domain, host_domain, sender);
    resolver
        .verify_spf(Parameters::new(params).with_txt_cache(cache))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn resolver() -> MessageAuthenticator {
        crate::cache::system_resolver().expect("构造系统解析器")
    }

    #[tokio::test]
    async fn a_matching_ip_passes_and_a_stranger_ip_does_not() {
        let cache = TxtCache::new();

        cache.pin_absent("mail.example.com");
        cache
            .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");

        let sender = "alice@example.com";
        let allowed = check(
            &resolver(),
            &cache,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            "mail.example.com",
            "mx.mailstack.test",
            sender,
        )
        .await;
        assert_eq!(allowed.status, SpfStatus::Pass, "{allowed:?}");
        assert_eq!(allowed.domain, "example.com");

        let stranger = check(
            &resolver(),
            &cache,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            "mail.example.com",
            "mx.mailstack.test",
            sender,
        )
        .await;
        assert_eq!(
            stranger.status,
            SpfStatus::Fail,
            "`-all` 之外的来源必须是 Fail：{stranger:?}"
        );
    }

    #[test]
    fn every_rfc7208_result_maps_to_a_status() {
        for (raw, expected) in [
            (SpfResult::Pass, SpfStatus::Pass),
            (SpfResult::Fail, SpfStatus::Fail),
            (SpfResult::SoftFail, SpfStatus::SoftFail),
            (SpfResult::Neutral, SpfStatus::Neutral),
            (SpfResult::TempError, SpfStatus::TempError),
            (SpfResult::PermError, SpfStatus::PermError),
            (SpfResult::None, SpfStatus::None),
        ] {
            assert_eq!(SpfStatus::from(raw), expected, "{raw:?}");
        }
    }

    #[test]
    fn keywords_follow_rfc8601() {
        assert_eq!(SpfStatus::Pass.keyword(), "pass");
        assert_eq!(SpfStatus::SoftFail.keyword(), "softfail");
        assert_eq!(SpfStatus::PermError.keyword(), "permerror");
        assert_eq!(SpfStatus::None.keyword(), "none");
    }
}

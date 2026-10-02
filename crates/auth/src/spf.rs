//! SPF 校验（RFC 7208）。
//!
//! 收信侧的第一道判据。用 `SpfParameters::verify` 的「EHLO + MAIL FROM 双身份」
//! 语义：RFC 7208 §2.4 要求先按 HELO 判，HELO 判定失败或 `MAIL FROM` 为空时才以
//! HELO 结论为准 —— 这正是 mail-auth 内部 `verify_spf` 的分支，直接复用可以避免
//! 自己写一份容易走样的版本。
//!
//! 拒绝策略不在这里：本模块只产出**结论**（[`SpfStatus`]），要不要据此 5xx 是
//! 入站 MTA 的决定。

use std::net::IpAddr;

use mail_auth::spf::verify::SpfParameters;
use mail_auth::{MessageAuthenticator, Parameters, SpfResult};

use crate::cache::TxtCache;

/// SPF 判定结果（RFC 7208 §2.6 的七个取值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfStatus {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,
    /// 该域没有 SPF 记录。
    None,
}

impl SpfStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, SpfStatus::Pass)
    }

    /// `Authentication-Results` 里用的关键字（RFC 8601）。
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

/// 一次 SPF 校验的完整结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfCheck {
    pub status: SpfStatus,
    /// 实际被校验的域（MAIL FROM 非空时是它，否则是 HELO 域）。
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

/// 校验一封入站邮件的 SPF。
///
/// * `ip` —— 对端连接的源地址
/// * `helo_domain` —— 对端在 EHLO/HELO 里声明的域
/// * `host_domain` —— 本机主机名（`%{h}` 宏与 `exp=` 需要）
/// * `sender` —— `MAIL FROM` 的完整地址（可为空串，表示 null sender）
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

/// 原始输出版本：DMARC 需要未经折算的 [`mail_auth::SpfOutput`] 才能做对齐判断，
/// 而重新算一遍 SPF 会产生第二次 DNS 查询 —— 所以这里把原始结论透出来。
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
        // `SpfParameters::verify` 是「EHLO + MAIL FROM 双身份」语义，**先查 HELO 域**；
        // 不把 HELO 域也钉住，这里就会去发真实 DNS（见 `TxtCache::pin_absent`）。
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
        // 刻意**不**断言「无 SPF 记录 → None」：那要发真实 DNS 查询，而本机 DNS
        // 由 Clash 的 fake-IP 接管（任意域名都会「解析成功」），断言会随环境漂移。
        // 该路径属于 mail-auth 的行为，我们只负责映射 —— 所以在这里测映射。
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

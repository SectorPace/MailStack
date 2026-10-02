//! DMARC 评估（RFC 7489）。
//!
//! DMARC 不是「再查一条记录」，而是**对 SPF 与 DKIM 结果做对齐判断**，因此它必须
//! 和这两个结论一起算。本模块的 [`evaluate`] 就是那个唯一的编排点：一次调用完成
//! SPF 校验 → DKIM 验签 → DMARC 对齐，并返回全部中间结论。
//!
//! 把编排放在这里而不是调用方，是为了避免出现「调用方自己拼 SPF 结果传给 DMARC」
//! 这种各拼一份、迟早走样的局面。

use std::net::IpAddr;

use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::{AuthenticatedMessage, DmarcResult, MessageAuthenticator, Parameters};

use crate::cache::TxtCache;
use crate::dkim::{DkimStatus, DkimVerdict};
use crate::error::{AuthError, AuthResult};
use crate::spf::{SpfCheck, SpfStatus};

/// DMARC 判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcStatus {
    Pass,
    Fail(String),
    TemporaryError(String),
    PermissionError(String),
    /// 该域没有 DMARC 记录。
    None,
}

impl DmarcStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, DmarcStatus::Pass)
    }

    /// `Authentication-Results` 里用的关键字（RFC 8601）。
    pub fn keyword(&self) -> &'static str {
        match self {
            DmarcStatus::Pass => "pass",
            DmarcStatus::Fail(_) => "fail",
            DmarcStatus::TemporaryError(_) => "temperror",
            DmarcStatus::PermissionError(_) => "permerror",
            DmarcStatus::None => "none",
        }
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

/// 一次入站评估的完整结论。
///
/// `status` 是 DMARC 的最终判定；`spf` / `dkim` 是它的两个输入，一并返回是为了
/// 让 `Authentication-Results` 头与排障日志不必重新算一遍。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcCheck {
    pub status: DmarcStatus,
    /// 被评估的域（RFC5322.From 的域）。
    pub domain: String,
    /// 该域公布的策略（`p=`），无记录时为空串。
    pub policy: String,
    pub spf: SpfCheck,
    pub dkim: Vec<DkimVerdict>,
}

/// 对一封入站邮件做 SPF + DKIM + DMARC 的完整评估。
///
/// * `ip` —— 对端连接的源地址
/// * `helo_domain` —— 对端声明的 HELO 域
/// * `host_domain` —— 本机主机名
/// * `sender` —— `MAIL FROM` 完整地址（空串表示 null sender）
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

    let mail_from_domain = sender.rsplit_once('@').map_or("", |(_, domain)| domain);

    let params = DmarcParameters {
        message: &parsed,
        dkim_output: &dkim_outputs,
        dkim2_output: None,
        rfc5321_mail_from_domain: mail_from_domain,
        spf_output: &spf_output,
    };
    let output = resolver
        .verify_dmarc(Parameters::new(params).with_txt_cache(cache))
        .await;

    Ok(DmarcCheck {
        status: DmarcStatus::from(&output.result()),
        domain: output.domain().to_string(),
        policy: format!("{:?}", output.policy()).to_lowercase(),
        spf,
        dkim,
    })
}

/// `DkimStatus` 与 `SpfStatus` 的便捷判定：DMARC 通过要么靠 SPF 对齐、要么靠 DKIM 对齐。
impl DmarcCheck {
    pub fn spf_aligned(&self) -> bool {
        self.spf.status == SpfStatus::Pass
    }

    pub fn dkim_aligned(&self) -> bool {
        self.dkim
            .iter()
            .any(|verdict| verdict.status == DkimStatus::Pass)
    }
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

    #[tokio::test]
    async fn an_aligned_spf_passes_dmarc_without_any_dkim_signature() {
        let cache = TxtCache::new();
        // 树走查必须在缓存内终止，否则会去查真实 DNS（见 `pin_dmarc_walk`）。
        cache.pin_dmarc_walk("example.com");
        // SPF 的「EHLO + MAIL FROM 双身份」会**先查 HELO 域**；不钉住就会发真实 DNS
        // （见 `TxtCache::pin_absent`）。
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
        assert!(check.spf_aligned());
        assert!(
            !check.dkim_aligned(),
            "报文里没有 DKIM 签名，不该凭空产生对齐"
        );
    }

    #[tokio::test]
    async fn an_unaligned_source_fails_a_reject_policy() {
        let cache = TxtCache::new();
        cache.pin_dmarc_walk("example.com");
        // SPF 的「EHLO + MAIL FROM 双身份」会**先查 HELO 域**；不钉住就会发真实 DNS
        // （见 `TxtCache::pin_absent`）。
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
            // 不在 SPF 授权范围内，且没有 DKIM 签名可以救场。
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
    }

    #[test]
    fn every_dmarc_result_maps_to_a_status() {
        // 同 spf.rs：不断言「无记录 → None」，那会依赖真实 DNS（本机 Clash 的
        // fake-IP 让任何域名都「解析成功」）。该路径属于 mail-auth，我们只测映射。
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
}

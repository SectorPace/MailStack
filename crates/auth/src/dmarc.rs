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
    ///
    /// 这是**给界面与 `Authentication-Results` 看的原文**；要判定「是否拒收」
    /// 请用 [`DmarcCheck::policy_is_reject`]，不要比较字符串 —— 见那里的理由。
    pub policy: String,
    /// 类型化的策略值（`p=` 的语义）。
    ///
    /// ## 为什么不能靠 `policy` 字符串做判定
    ///
    /// 原实现是 `format!("{:?}", output.policy()).to_lowercase()`，消费侧
    /// （`smtpd::sink`）再比 `== "reject"`。也就是说**安全判定依赖第三方
    /// enum 的 `Debug` 输出**：上游一改派生输出（哪怕只是给变体加字段、
    /// 或从 `Reject` 改成 `Policy(Reject)`），这个字符串就再也匹配不上，
    /// 于是 **550 拒收分支永不触发、邮件静默放行**，而测试照样全绿。
    ///
    /// 用类型化的 [`DmarcPolicy`] 就没这个问题：变体增减是编译期错误，
    /// 而 `matches!(p, DmarcPolicy::Reject)` 永远成立。
    pub policy_value: DmarcPolicy,
    pub spf: SpfCheck,
    pub dkim: Vec<DkimVerdict>,
}

/// DMARC 策略的类型化表示（对应 `mail_auth::dmarc::Policy`）。
///
/// 之所以自己再定义一份而不直接用上游的：上游那个 enum 的
/// `Unspecified`（无记录）与 `None`（`p=none`）语义不同，我们需要**两套都拒**
/// 才能 fail-closed，而把它暴露到本 crate 的公开接口上会让调用方直接依赖
/// 上游类型 —— 上游一改派生就是破坏性变更。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// `p=none`：只监测，不要求处置。
    None,
    /// `p=quarantine`。
    Quarantine,
    /// `p=reject`：判定为 fail 时应拒收。
    Reject,
    /// 无 `p=` 标签（含整个 DMARC 记录缺失）。
    ///
    /// 按 RFC 7489 §6.3，`p` 缺省等价于 `none`，但为了**fail-closed**，
    /// 这里与 [`DmarcPolicy::None`] 同等对待：无法确定策略时一律不拒收邮件
    /// （拒收是破坏性动作，宁可放行并留痕）。
    Unspecified,
}

impl DmarcPolicy {
    /// 是否应当拒收（`p=reject`）。
    ///
    /// 这是**唯一**该用于「要不要 550」的判据。
    pub fn is_reject(self) -> bool {
        matches!(self, DmarcPolicy::Reject)
    }

    /// `Authentication-Results` / 日志里用的关键字。
    pub fn keyword(self) -> &'static str {
        match self {
            DmarcPolicy::None => "none",
            DmarcPolicy::Quarantine => "quarantine",
            DmarcPolicy::Reject => "reject",
            DmarcPolicy::Unspecified => "unspecified",
        }
    }
}

/// 上游的 `policy()` 按值返回（`Policy` 是 `Copy`），所以这里也按值收。
impl From<mail_auth::dmarc::Policy> for DmarcPolicy {
    fn from(value: mail_auth::dmarc::Policy) -> Self {
        use mail_auth::dmarc::Policy as P;
        match value {
            P::None => DmarcPolicy::None,
            P::Quarantine => DmarcPolicy::Quarantine,
            P::Reject => DmarcPolicy::Reject,
            // 上游把「无记录」也归到 `Unspecified`，这里保持一致。
            P::Unspecified => DmarcPolicy::Unspecified,
        }
    }
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
        // 展示用的原文（`p=` 的值），**不作判定用**。
        policy: format!("{:?}", output.policy()).to_lowercase(),
        policy_value: DmarcPolicy::from(output.policy()),
        spf,
        dkim,
    })
}

impl DmarcCheck {
    /// SPF 是否通过。
    ///
    /// ## 为什么叫 `spf_pass` 而不是 `spf_aligned`
    ///
    /// 原名 `spf_aligned()` 有误导性：它**只判 pass，完全不做组织域对齐比较**。
    /// DMARC 的「对齐」要求签名域与 RFC5322.From 的域**同组织域**（RFC 7489
    /// §3.1.1）—— `From: bank@example.com` 由 `d=attacker.example` 签名，
    /// SPF/DKIM 都是 pass，但**不是对齐**的。
    ///
    /// 真正的对齐结论由上游 `verify_dmarc` 给出（体现在
    /// [`DmarcStatus::Pass`] 里），本类型上的方法只是它两个输入的便捷读取。
    /// 名字改成 `_pass` 就是为了不再暗示这里做了对齐判断 —— 那个判断**不在**
    /// 这一层。
    pub fn spf_pass(&self) -> bool {
        self.spf.status == SpfStatus::Pass
    }

    /// 是否有**任一** DKIM 签名通过（同样不含对齐判断，理由见 [`Self::spf_pass`]）。
    pub fn dkim_pass(&self) -> bool {
        self.dkim
            .iter()
            .any(|verdict| verdict.status == DkimStatus::Pass)
    }

    /// 该域的策略是否要求拒收（`p=reject`）。
    ///
    /// **判定拒收时用这个，不要比较 [`DmarcCheck::policy`] 字符串。**
    pub fn policy_is_reject(&self) -> bool {
        self.policy_value.is_reject()
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
        // 展示字符串仍在（界面与 A-R 头要用），但**判定**走类型化字段。
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

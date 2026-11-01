//! DMARC 评估（RFC 7489）。
//!
//! DMARC 不是「再查一条记录」，而是**对 SPF 与 DKIM 结果做对齐判断**，因此它必须
//! 和这两个结论一起算。本模块的 [`evaluate`] 就是那个唯一的编排点：一次调用完成
//! SPF 校验 → DKIM 验签 → DMARC 对齐，并返回全部中间结论。
//!
//! 把编排放在这里而不是调用方，是为了避免出现「调用方自己拼 SPF 结果传给 DMARC」
//! 这种各拼一份、迟早走样的局面。
//!
//! ## `pct=` 抽样（RFC 7489 §6.6.4，已接线）
//!
//! [`parse_pct`]（从原始记录文本解析）→ [`policy_sample_draw`]（每条消息的抽签）
//! → [`effective_policy`]（抽样折算，只弱化不强化），由 [`evaluate`] 在判定为
//! fail 且已公布策略有处置动作（reject / quarantine）时执行，并把**本条消息实际
//! 执行**的策略写进 [`DmarcCheck::policy_value`] —— 所有消费方（SMTP 收信的 550
//! 判定等）经 [`DmarcCheck::policy_is_reject`] 自动带上 pct 语义，不必各自重算。
//! 方向 fail-closed：`pct` 只可能**概率性地弱化**处置；记录损坏（`pct` 取不到）
//! 或抽签熵异常集中时，最坏等价于「未实现 pct」（全量执行已公布策略）。
//!
//! 已知边界（诚实披露）：原始记录文本只有 [`crate::cache::TxtCache::add_dmarc`]
//! 注入路径才拿得到 —— mail-auth 0.13 联网解析 DMARC 时在解析器内部就把原始
//! 字节消费掉了，[`crate::cache::TxtCache`] 的回调里只有解析后的结构（`pct`
//! 已被丢弃）。联网解析路径上 `raw_dmarc_record` 因此返回 `None`，pct 按
//! 「未公布」处理（全量执行已公布策略）—— 正是 fail-closed 方向的退化，
//! 不会更严。

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
    /// 这是**给界面与 `Authentication-Results` 看的原文**（`policy=` 属性按
    /// RFC 8601 的语义写「对方公布了什么」）；要判定「是否拒收」请用
    /// [`DmarcCheck::policy_is_reject`]，不要比较字符串 —— 见那里的理由。
    pub policy: String,
    /// 类型化的策略值 —— **本条消息实际执行**的策略。
    ///
    /// 无 `pct=`（或抽样命中）时等于已公布策略；抽样落选时按 RFC 7489 §6.6.4
    /// 弱化一级（reject → quarantine → none）。由 [`evaluate`] 折算，消费方的
    /// 「要不要处置」判定走 [`DmarcCheck::policy_is_reject`]。
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

    // 6.15：裸 `rsplit_once('@')` 不做任何清洗。上游传进来的 `sender` 可能是
    // `MAIL FROM:<User@Example.COM>` 这类带尖括号/空白/大写的形态，
    // 直接切出来的域名变成 `Example.COM>` —— DMARC 的对齐比较随后必然失败，
    // 而且是**静默**失败（报文被判成不对齐，收件方直接按 p=reject 处置）。
    // 与 `dkim::from_domain` 用同一套清洗语义，避免两条路径口径不一致。
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
    // 已公布策略（`p=` 的原文展示，`Authentication-Results` 的 `policy=` 属性用
    // 它 —— 那是「对方公布了什么」，与抽样无关）。
    let published = DmarcPolicy::from(output.policy());

    // `pct=` 抽样（RFC 7489 §6.6.4）：只对「判定为 fail 且已公布策略有处置动作」
    // 的消息有意义 —— pct 只会概率性地**弱化** fail 的处置，pass / none /
    // 错误态不受影响。折算结果写进 `policy_value`，消费方的「要不要处置」判定
    // 因此自动带上 pct 语义，不必各自重算。
    let policy_value = if matches!(status, DmarcStatus::Fail(_))
        && matches!(published, DmarcPolicy::Reject | DmarcPolicy::Quarantine)
    {
        match cache.raw_dmarc_record(&domain) {
            // 拿不到原始文本 = 视同「未公布 pct」= 全量执行已公布策略
            // （fail-closed）。联网解析路径正是如此（见模块文档的已知边界）。
            None => published,
            Some(raw) => {
                // 抽签熵：域 + Message-ID + 纳秒时钟（见 `policy_sample_draw`）。
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

    /// 本条消息**实际执行**的策略是否要求拒收（`p=reject` 且未被 `pct=` 抽样弱化）。
    ///
    /// **判定拒收时用这个，不要比较 [`DmarcCheck::policy`] 字符串。**
    ///
    /// `pct=` 抽样（RFC 7489 §6.6.4）已由 [`evaluate`] 折算进
    /// [`DmarcCheck::policy_value`]：抽样落选的消息这里返回 `false`（处置弱化为
    /// quarantine），而已公布的策略本身仍是 reject —— 后者只体现在
    /// [`DmarcCheck::policy`] 展示字符串里。
    pub fn policy_is_reject(&self) -> bool {
        self.policy_value.is_reject()
    }
}

/// 按已公布策略弱化一级（RFC 7489 §6.6.4：抽样落选者的处置）。
///
/// `reject → quarantine → none`；`none` / `Unspecified` 已无可弱化，原样返回。
pub fn weaken_one_step(published: DmarcPolicy) -> DmarcPolicy {
    match published {
        DmarcPolicy::Reject => DmarcPolicy::Quarantine,
        DmarcPolicy::Quarantine => DmarcPolicy::None,
        other => other,
    }
}

/// 按 `pct=` 抽样折算一条消息**实际执行**的策略（RFC 7489 §6.6.4）。
///
/// * `pct` 为 `None` 或 ≥ 100 → 原样执行已公布策略（缺省即 100，全量执行）。
/// * `draw < pct` → 命中抽样，原样执行已公布策略。
/// * 其余 → 弱化一级（[`weaken_one_step`]）。
///
/// 方向是**只弱化、绝不强化**：抽样只能在已公布的处置上放松。这样即使
/// [`parse_pct`] 对坏记录返回 `None`、或抽签熵意外集中，最坏结果也只是
/// 「回到未实现 pct 的旧行为」（全量执行已公布策略），不会更严。
pub fn effective_policy(published: DmarcPolicy, pct: Option<u8>, draw: u8) -> DmarcPolicy {
    match pct {
        Some(pct) if pct < 100 && draw >= pct => weaken_one_step(published),
        _ => published,
    }
}

/// 从**原始** DMARC 记录文本解析 `pct=`（RFC 7489 §6.3：0..=100 的整数，缺省 100）。
///
/// ## 为什么必须自己解析
///
/// 上游 mail-auth 0.13 的 `Dmarc` 结构没有 `pct` 字段（解析时直接丢弃，
/// `DmarcOutput::record` 拿到的同样是不完整的结构），[`TxtCache`] 里存的又是
/// 解析后的结构 —— 原始文本一旦进了验签管线就取不回来。因此只能由拿到原始
/// TXT 的那一侧（记录注入路径、或调用方自行查询）先经这里解析，再把结果传给
/// [`effective_policy`]。
///
/// 标签名大小写不敏感（与上游解析器把 key 折小写后匹配的行为一致）。
/// 缺失、语法非法或超出 0..=100 一律返回 `None` —— 抽样只准**弱化**，记录
/// 坏了按「未公布 pct」处理（= 全量执行已公布策略），绝不因此误弱化。
pub fn parse_pct(record: &str) -> Option<u8> {
    for tag in record.split(';') {
        let Some((name, value)) = tag.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("pct") {
            continue;
        }
        let value = value.trim();
        // 0..=100 的十进制整数；长度上界只是防御性的（含符号、空格、超长的
        // 一律按「非法」走 None 分支）。
        if value.is_empty() || value.len() > 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let parsed: u16 = value.parse().ok()?;
        return (parsed <= 100).then_some(parsed as u8);
    }
    None
}

/// 为一条消息抽一个 0..100 的样（RFC 7489 §6.6.4 的 pct 抽样用）。
///
/// 廉价熵：`domain` + `message_id` + 当前纳秒时钟经 `DefaultHasher` 混合。
/// 刻意不引入 `rand` 依赖（本 crate 未声明；§3.4 的依赖面纪律）—— 对
/// 「每条消息一次」的抽样判定，哈希熵足够。`message_id` 虽是对端可控的输入，
/// 但与纳秒时钟混合后无法离线预言结果；反复重发撞抽样本质上是 RFC 允许的
/// 重试行为，不构成新的放大面。
pub fn policy_sample_draw(domain: &str, message_id: &[u8]) -> u8 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    policy_sample_draw_from(domain, message_id, nanos)
}

/// [`policy_sample_draw`] 的确定性内核（纳秒由调用方给定，可穷举测试）。
fn policy_sample_draw_from(domain: &str, message_id: &[u8], nanos: u128) -> u8 {
    use std::hash::Hasher;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(domain.as_bytes());
    hasher.write(message_id);
    hasher.write(&nanos.to_le_bytes());
    (hasher.finish() % 100) as u8
}

/// 清洗一个**已经是域名**的字符串（域半段）：去尖括号残留与空白、折叠小写。
///
/// [`sanitized_domain`]（整地址 → 域）与 `arc::header_from`（已解析地址的域半段）
/// 共用这一步 —— 两条路径各写一份清洗迟早走样，口径必须只有一个来源。
pub(crate) fn sanitize_domain_part(domain: &str) -> String {
    domain.trim().trim_end_matches('>').to_ascii_lowercase()
}

/// 从信封发件人里取出可用于 DMARC 对齐的域名（6.15）。
///
/// 上游可能传 `alice@example.com`、`<alice@example.com>`、` alice@Example.COM ` 等
/// 形态。裸 `rsplit_once('@')` 会把尖括号与空白一起带进域名，而 DMARC 的对齐比较
/// 是**逐字**的 —— 于是对齐静默失败、报文被按 `p=reject` 处置，且日志里看不出原因。
///
/// 清洗规则与 `dkim::from_domain` 保持一致：去掉 `<>` 与空白、折叠小写；
/// 取不到 `@` 时返回空串（= 无信封发件人身份，DMARC 按无对齐处理）。
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

    /// 带 Message-ID 的测试报文：pct 抽签的熵输入之一（域 + message-id + 时钟）。
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
        // pct= 抽样接线：记录未公布 pct ⇒ 全量执行已公布策略（行为与接线前一致）。
        assert_eq!(check.policy_value, DmarcPolicy::Reject);
        assert!(check.policy_is_reject());
        assert_eq!(check.policy, "reject", "展示字符串仍是已公布策略");
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

    /// pct= 抽样接线的端到端语义：pct=0 的 reject 记录对**每一封**失败邮件都
    /// 弱化一级（reject → quarantine）—— 没有任何消息命中抽样。
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
                // 不在 SPF 授权范围内，且没有 DKIM 可以救场 ⇒ DMARC fail。
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

    /// pct=100 / 未公布 pct：全量执行已公布策略 —— 与未实现 pct 时行为一致。
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

    /// pct=10：抽样只准弱化 —— 大样本下绝大多数失败邮件被弱化为 quarantine，
    /// 但两种处置都必须出现（否则抽样退化成了常数）。
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
        assert!(rejected > 0, "抽样必须命中一部分（期望 ~10%）：{rejected}/60");
        assert!(
            quarantined >= 30,
            "落选必须占绝大多数（期望 ~90%）：rejected={rejected} quarantined={quarantined}"
        );
    }

    /// 6.15：信封发件人域必须先清洗，再用于 DMARC 对齐比较。
    ///
    /// 原实现是裸 `sender.rsplit_once('@')`。上游传 `MAIL FROM:<User@Example.COM>`
    /// 时会切出 `Example.COM>` —— 对齐比较**逐字**进行，于是静默失败，
    /// 报文被按 `p=reject` 处置而日志里看不出原因。
    #[test]
    fn mail_from_domain_is_sanitised_before_dmarc_alignment() {
        for (raw, expected) in [
            ("alice@example.com", "example.com"),
            ("<alice@example.com>", "example.com"),
            ("  alice@Example.COM  ", "example.com"),
            ("<Alice@Example.COM>", "example.com"),
            ("alice@sub.example.com", "sub.example.com"),
            // 没有 `@`：没有信封发件人身份，返回空串（按无对齐处理）。
            ("<>", ""),
            ("", ""),
            ("postmaster", ""),
        ] {
            assert_eq!(sanitized_domain(raw), expected, "raw = {raw:?}");
        }
    }

    /// 共享清洗原语的直接覆盖：`arc::header_from` 也走这里，两边口径必须一致。
    #[test]
    fn sanitize_domain_part_is_the_shared_normaliser() {
        assert_eq!(sanitize_domain_part(" Example.COM> "), "example.com");
        assert_eq!(sanitize_domain_part("Sub.Example.COM"), "sub.example.com");
        assert_eq!(sanitize_domain_part("example.com>"), "example.com");
        assert_eq!(sanitize_domain_part(""), "");
    }

    #[test]
    fn parse_pct_follows_rfc7489_defaults() {
        // 常规值。
        assert_eq!(parse_pct("v=DMARC1; p=reject; pct=25"), Some(25));
        assert_eq!(parse_pct("v=DMARC1; p=quarantine; pct=0"), Some(0));
        assert_eq!(parse_pct("v=DMARC1; p=reject; pct=100"), Some(100));
        // 标签名大小写不敏感（与上游解析器折小写匹配的行为一致）。
        assert_eq!(parse_pct("v=DMARC1; p=reject; PCT=25"), Some(25));
        // 缺省 = 100 = 「未公布」（None，调用方按全量执行处理）。
        assert_eq!(parse_pct("v=DMARC1; p=reject"), None);
        // 非法值一律 None：抽样只准弱化，记录坏了绝不因此弱化。
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

        // 未公布 / 满 100：全量执行已公布策略（与未实现 pct 时行为一致）。
        for draw in [0u8, 25, 99] {
            assert_eq!(effective_policy(reject, None, draw), reject);
            assert_eq!(effective_policy(reject, Some(100), draw), reject);
        }
        // 命中抽样（draw < pct）：执行已公布策略。
        assert_eq!(effective_policy(reject, Some(25), 0), reject);
        assert_eq!(effective_policy(reject, Some(25), 24), reject);
        // 落选（draw >= pct）：弱化一级。
        assert_eq!(effective_policy(reject, Some(25), 25), quarantine);
        assert_eq!(effective_policy(reject, Some(25), 99), quarantine);
        // 弱化链：quarantine → none；none / unspecified 已到底，不再变化。
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
        // pct=0：没有任何消息命中抽样 → 全部弱化一级。
        assert_eq!(effective_policy(reject, Some(0), 0), quarantine);
        // 抽样绝不强化：落选的结果只能比公布策略轻，不能更重。
        for published in [reject, quarantine] {
            let weakened = effective_policy(published, Some(10), 99);
            assert_ne!(weakened, DmarcPolicy::Reject, "落选不得落在 reject 上");
        }
    }

    #[test]
    fn sample_draw_is_deterministic_bounded_and_spread() {
        // 确定性内核：同样的输入必有同样的输出（可测试性的要求）。
        assert_eq!(
            policy_sample_draw_from("example.com", b"<id@example.com>", 1_000),
            policy_sample_draw_from("example.com", b"<id@example.com>", 1_000)
        );
        // 输出必然落在 0..100。
        for nanos in [0u128, 1, 42, u128::from(u64::MAX), u128::MAX] {
            let draw = policy_sample_draw_from("example.com", b"x", nanos);
            assert!(draw < 100, "抽签必须落在 0..100，实际 {draw}");
        }
        // 大批量输入应覆盖多个桶：全部落在同一桶的概率 ~100^-31，实际不可能。
        let draws: std::collections::HashSet<u8> = (0u128..32)
            .map(|nanos| policy_sample_draw_from("example.com", b"m", nanos))
            .collect();
        assert!(draws.len() > 1, "抽签不应退化成常数: {draws:?}");
    }
}

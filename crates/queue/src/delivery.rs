//! 投递层：路由、失败分类与经中继的 SMTP 投递（规格书 §5.8 / §5.9；INV-18、INV-21）。
//!
//! ## 失败分类为什么是核心
//!
//! 队列的全部决策都建立在「这次失败该重试还是该退信」之上：
//!
//! * **已判定失败**（服务器明确回了 4xx / 5xx）→ 4xx 重试、5xx 退信
//! * **未知结果**（连接断开、超时、协议错乱）→ **只能重试**。此时邮件可能已经
//!   投出去了，贸然退信会让发件人以为没投递而重复发送
//!
//! 因此 [`DeliveryFailure`] 只表达「已判定」的失败；未知结果一律归
//! [`FailureClass::Transient`]，绝不退信。
//!
//! ## INV-18 / INV-21
//!
//! 远端投递**只**接受 [`OutboundRoute`]（由 `mailstack_smtp::select_outbound_route`
//! 从配置推导）。两条路各自独立、**互不兜底**：配了中继就只有中继（[`OutboundRoute::ViaRelay`]），
//! 没配中继才轮到直投（[`OutboundRoute::Direct`]）。直投失败就是失败，不会回头改用
//! 中继（那会绕过 relay、破坏 SPF 对齐，并把邮件直接打到 25 端口）。
//!
//! ## 直投为什么必须逐域
//!
//! 一封邮件可能同时投给多个外域，而每个域有各自的 MX。因此直投路径先按收件域分组、
//! 逐域完成一次事务，再把各域结果**如实合并**：部分成功时把已投递的收件人放进
//! [`DeliveryFailure::accepted`]，否则重试会重复投递。
//!
//! ## 直投不加密（显式登记，不是遗漏）
//!
//! 直投链路上**没有凭证**，因此不存在「明文泄露口令」这一类风险（与中继路径相反，
//! 见 INV-13）。现实中的机会式 TLS 必须「加密但不校验证书」，否则大量自签/不匹配
//! 证书的 MX 会收不到信 —— 而「不校验证书」是一条**独立的安全策略决定**，必须有自己
//! 的登记与测试，不能顺手塞进本次改动。因此当前直投是明文 25 端口投递，与 SMTP 的
//! 默认行为一致；机会式加密作为后续独立项。

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use mailstack_smtp::client::{MessageOutcome, SmtpSession};
use mailstack_smtp::{
    resolve_mx_targets, resolve_pinned, AddressPolicy, MxResolver, OutboundRoute, PinnedDialer,
    PinnedTarget, SmtpError, TlsMode, DIRECT_DELIVERY_PORT,
};

use crate::entry::QueueEntry;

/// 装箱的投递 Future。
///
/// 用装箱而不是 `impl Future` 是为了让 [`Transport`] 可作 `dyn Trait` 使用 ——
/// 队列需要「本地传输」与「远端传输」两个实现共存，且测试要能整体替换。
pub type DeliveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DeliveryReceipt, DeliveryFailure>> + Send + 'a>>;

/// 失败的类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// 临时失败：应退避重试。
    Transient,
    /// 永久失败：重试无意义，应退信。
    Permanent,
}

/// 一次已判定的投递失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryFailure {
    pub class: FailureClass,
    /// 稳定的类别名（用于统计与界面归类，不泄漏内网地址或凭证）。
    pub kind: &'static str,
    /// 描述（允许包含对端返回的文本；写出到 DSN 前会被净化）。
    pub message: String,
    /// 对端状态码（仅当服务器给出了明确应答时存在）。
    pub code: Option<u16>,
    /// 本次尝试中**已被对端接受**的收件人。
    ///
    /// 投递可以是部分成功的：LMTP 在 `DATA` 之后**逐收件人**应答（如一个用户已落箱、
    /// 另一个超配额），SMTP 也可能在前几个 `RCPT` 成功后拒绝后一个。这些收件人
    /// 已经投出去了，绝不能因为整批被判失败而在重试时**再投一次** —— 用户会收到
    /// 重复邮件。删除重试队列的语义必须建立在「成功的那部分不再重放」之上。
    pub accepted: Vec<String>,
    /// 这次失败是否属于**本机故障**（DKIM 签名失败、私钥不可读等），而非出站链路问题。
    ///
    /// 把它计进「出站健康」会让运维看到「Outbound port 25 is blocked / 请配置中继」
    /// 这种**指向完全错误方向**的结论，然后去查防火墙 —— 与「本地 LMTP 失败不得计入
    /// 出站健康」是同一类问题。
    pub local_fault: bool,
}

impl DeliveryFailure {
    pub fn transient(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            class: FailureClass::Transient,
            kind,
            message: message.into(),
            code: None,
            accepted: Vec::new(),
            local_fault: false,
        }
    }

    pub fn permanent(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            class: FailureClass::Permanent,
            kind,
            message: message.into(),
            code: None,
            accepted: Vec::new(),
            local_fault: false,
        }
    }

    /// 标记为「本机故障」：不得计入出站健康判据。
    pub fn with_local_fault(mut self) -> Self {
        self.local_fault = true;
        self
    }

    /// 记录本次尝试中已经投递成功的收件人。
    pub fn with_accepted(mut self, accepted: Vec<String>) -> Self {
        self.accepted = accepted;
        self
    }

    /// 记录对端状态码。
    pub fn with_code(mut self, code: u16) -> Self {
        self.code = Some(code);
        self
    }

    pub fn is_permanent(&self) -> bool {
        self.class == FailureClass::Permanent
    }
}

/// 投递成功回执。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryReceipt {
    /// 被对端接受的收件人数量。
    pub accepted: usize,
}

/// 投递目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTarget {
    /// 本域收件人 → Dovecot（LMTP）。由 `crates/store` 提供实现。
    Local,
    /// 外域收件人 → 直投或经中继。路由**只能**来自配置（INV-18 / INV-21）。
    Remote(OutboundRoute),
}

/// 投递传输。
///
/// 实现者必须遵守两条：**只能**按传入的 [`DeliveryTarget`] 投递（不得自行改路由）；
/// 未知结果只能报 [`FailureClass::Transient`]。
pub trait Transport: Send + Sync {
    fn deliver<'a>(
        &'a self,
        entry: &'a QueueEntry,
        target: DeliveryTarget,
        recipients: &'a [String],
    ) -> DeliveryFuture<'a>;
}

/// 由状态码判定失败类别（RFC 5321 §4.2.3：4yz 持久性瞬态、5yz 永久）。
pub fn classify_code(code: u16) -> FailureClass {
    if (500..600).contains(&code) {
        FailureClass::Permanent
    } else {
        FailureClass::Transient
    }
}

/// 把本地传输/协议错误映射为失败类别。
///
/// 配置类错误（端点非法、缺凭证、策略禁用）判为**永久**：它们重试一万次也不会
/// 变好，继续重试只会把队列撑大并把真正的错误淹掉。
pub fn classify_smtp_error(error: &SmtpError) -> DeliveryFailure {
    let kind = error.kind();
    let message = error.to_string();
    match error {
        SmtpError::InvalidEndpoint(_)
        | SmtpError::TlsRequired
        | SmtpError::IncompleteCredentials
        | SmtpError::PrivateRelayDisabled
        | SmtpError::NoAcceptableAddress(_)
        // RFC 7505：该域明确声明不收信，重试一万次也不会变。
        | SmtpError::NullMx(_) => DeliveryFailure::permanent(kind, message),
        _ => DeliveryFailure::transient(kind, message),
    }
}

/// 由服务器应答构造已判定失败。
pub fn classify_response(code: u16, banner: impl Into<String>) -> DeliveryFailure {
    DeliveryFailure {
        class: classify_code(code),
        kind: "SmtpRejected",
        message: banner.into(),
        code: Some(code),
        accepted: Vec::new(),
        local_fault: false,
    }
}

/// 一条远端目标的加密要求。
#[derive(Debug, Clone, Copy)]
enum DeliveryTls {
    /// 必须加密。中继走这条：链路上要发 SASL 凭证（INV-13、INV-20）。
    Required(TlsMode),
    /// 明文。直投走这条：没有凭证，理由见模块说明。
    Plaintext,
}

/// 远端 SMTP 传输：按 [`DeliveryTarget::Remote`] 的路由投给中继**或**逐域直投。
///
/// 结构上只认路由：`ViaRelay` 与 `Direct` 各有自己的实现，任何一条路径都**不**包含
/// 「改用另一条」的分支（INV-18 / INV-21）。
pub struct SmtpRemoteTransport {
    dialer: PinnedDialer,
    timeout: Duration,
    helo_name: String,
    credentials: Option<(String, String)>,
    policy: AddressPolicy,
    /// MX 解析后端。未配置时 `Direct` 路由**明确失败**（而不是假装成功，
    /// 也**不会**改用中继）。
    mx: Option<Arc<dyn MxResolver>>,
    /// 直投端口。RFC 5321 §5.1 规定是 25；可覆盖是为了让端到端测试能在非特权端口上
    /// 跑（与 `--port 2525` 旁路部署同一个理由）。
    direct_port: u16,
}

impl std::fmt::Debug for SmtpRemoteTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpRemoteTransport")
            .field("helo_name", &self.helo_name)
            .field("has_credentials", &self.credentials.is_some())
            .field("has_mx_resolver", &self.mx.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl SmtpRemoteTransport {
    pub fn new(dialer: PinnedDialer, helo_name: impl Into<String>, timeout: Duration) -> Self {
        Self {
            dialer,
            timeout,
            helo_name: helo_name.into(),
            credentials: None,
            policy: AddressPolicy::public_only(),
            mx: None,
            direct_port: DIRECT_DELIVERY_PORT,
        }
    }

    /// 配置 SMTP AUTH 凭证（**只在**中继路径上使用）。
    pub fn with_credentials(mut self, username: String, password: String) -> Self {
        self.credentials = Some((username, password));
        self
    }

    /// 覆盖地址策略（仅当目标位于私网且部署显式开启时才应放宽）。
    pub fn with_policy(mut self, policy: AddressPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// 配置 MX 解析后端，使 [`OutboundRoute::Direct`] 可用。
    pub fn with_mx(mut self, resolver: Arc<dyn MxResolver>) -> Self {
        self.mx = Some(resolver);
        self
    }

    /// 覆盖直投端口（默认 25；仅供测试与旁路部署）。
    pub fn with_direct_port(mut self, port: u16) -> Self {
        self.direct_port = port;
        self
    }

    async fn deliver_remote(
        &self,
        entry: &QueueEntry,
        target: DeliveryTarget,
        recipients: &[String],
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let route = match target {
            DeliveryTarget::Remote(route) => route,
            DeliveryTarget::Local => {
                return Err(DeliveryFailure::permanent(
                    "WrongTransport",
                    "本地投递不应经 SMTP 传输",
                ))
            }
        };

        match &route {
            OutboundRoute::ViaRelay {
                host,
                port,
                wrappermode,
            } => {
                let pinned = resolve_pinned(host, *port, self.policy)
                    .await
                    .map_err(|e| classify_smtp_error(&e))?;
                // INV-20：wrappermode（或 465）必须走隐式 TLS，否则会以明文去连 465。
                let mode = if *wrappermode || *port == 465 {
                    TlsMode::Implicit
                } else {
                    TlsMode::StartTls
                };
                self.deliver_one(&pinned, DeliveryTls::Required(mode), entry, recipients)
                    .await
            }
            OutboundRoute::Direct => self.deliver_direct(entry, recipients).await,
        }
    }

    /// 一次「连一台目标 → 投一批收件人」的事务。
    async fn deliver_one(
        &self,
        pinned: &PinnedTarget,
        tls: DeliveryTls,
        entry: &QueueEntry,
        recipients: &[String],
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        // `TlsMode::StartTls` 在连接阶段就是「先明文连上」；是否真的升级由 `tls` 决定。
        let connect_mode = match tls {
            DeliveryTls::Required(mode) => mode,
            DeliveryTls::Plaintext => TlsMode::StartTls,
        };

        let (mut session, _banner) =
            SmtpSession::connect(&self.dialer, pinned, connect_mode, self.timeout)
                .await
                .map_err(|e| classify_smtp_error(&e))?;

        let ehlo = session
            .ehlo(&self.helo_name)
            .await
            .map_err(|e| classify_smtp_error(&e))?;
        if !ehlo.is_positive_completion() {
            return Err(classify_response(ehlo.code, ehlo.banner()));
        }

        if let DeliveryTls::Required(mode) = tls {
            if mode == TlsMode::StartTls {
                if !session.capabilities().starttls {
                    // INV-13：明文中继一律拒绝。宁可退信也不降级为明文发送凭证。
                    return Err(DeliveryFailure::permanent(
                        "TlsUnavailable",
                        "relay does not offer STARTTLS; refusing to send credentials in the clear",
                    ));
                }
                let (upgraded, _) = session
                    .starttls(&self.dialer, pinned)
                    .await
                    .map_err(|e| classify_smtp_error(&e))?;
                session = upgraded;
                let re_ehlo = session
                    .ehlo(&self.helo_name)
                    .await
                    .map_err(|e| classify_smtp_error(&e))?;
                if !re_ehlo.is_positive_completion() {
                    return Err(classify_response(re_ehlo.code, re_ehlo.banner()));
                }
            }

            // 凭证**只**在必须加密的路径上发送。直投即便被误配了凭证也绝不发出去。
            if let Some((username, password)) = &self.credentials {
                if session.capabilities().auth_mechanisms.is_empty() {
                    return Err(DeliveryFailure::permanent(
                        "AuthNotOffered",
                        "relay offers no AUTH mechanism but credentials are configured",
                    ));
                }
                let auth = session
                    .authenticate(username, password)
                    .await
                    .map_err(|e| classify_smtp_error(&e))?;
                if !auth.is_positive_completion() {
                    return Err(classify_response(auth.code, auth.banner()));
                }
            }
        }

        let outcome = session
            .send_message_detailed(&entry.mail_from, recipients, &entry.data)
            .await
            .map_err(|e| classify_smtp_error(&e))?;
        let _ = session.quit().await;

        match outcome {
            MessageOutcome::Accepted { .. } => Ok(DeliveryReceipt {
                accepted: recipients.len(),
            }),
            MessageOutcome::Rejected {
                response, accepted, ..
            } => {
                // 部分成功必须如实上报：拒绝发生之前已被对端接受的收件人要随失败
                // 带回给队列（`DeliveryFailure::accepted`），否则整批按失败处理时
                // 他们会在重试里**再投一遍**。LMTP 路径（`lmtp_transport.rs`）一直是
                // 这个语义；这里把远端 SMTP 路径补齐 —— outcome 未携带 accepted 集
                // 时它就是空集，行为与原先完全一致。
                Err(classify_response(response.code, response.banner()).with_accepted(accepted))
            }
        }
    }

    /// 直投：逐收件域解析 MX，按优先级依次尝试。
    async fn deliver_direct(
        &self,
        entry: &QueueEntry,
        recipients: &[String],
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let Some(mx) = self.mx.as_ref() else {
            // 没有 MX 后端＝直投不可用。**明确失败**，绝不改用中继。
            return Err(DeliveryFailure::transient(
                "DirectDeliveryUnavailable",
                "direct MX delivery is not configured on this transport; configure a relay (smarthost)",
            ));
        };

        let mut accepted: Vec<String> = Vec::new();
        let mut failures: Vec<DeliveryFailure> = Vec::new();

        for (domain, group) in group_by_domain(recipients) {
            match self
                .deliver_direct_to_domain(mx.as_ref(), &domain, &group, entry)
                .await
            {
                Ok(_) => accepted.extend(group),
                Err(failure) => {
                    // 该域内可能已经投出一部分（例如同一域的两台 MX 各成功一半）。
                    accepted.extend(failure.accepted.iter().cloned());
                    failures.push(failure);
                }
            }
        }

        if failures.is_empty() {
            return Ok(DeliveryReceipt {
                accepted: accepted.len(),
            });
        }

        // 单个域失败时保留原始类别与状态码（更有诊断价值）；多域失败时合并。
        // 合并规则与 LMTP 一致：**只要有一个可重试的，整批就可重试**（宁可多试，不可丢信）。
        let merged = if failures.len() == 1 {
            failures.pop().expect("已判定非空")
        } else {
            let any_transient = failures.iter().any(|failure| !failure.is_permanent());
            let detail = failures
                .iter()
                .map(|failure| failure.message.clone())
                .collect::<Vec<_>>()
                .join("; ");
            if any_transient {
                DeliveryFailure::transient("DirectDeliveryFailed", detail)
            } else {
                DeliveryFailure::permanent("DirectDeliveryFailed", detail)
            }
        };
        Err(merged.with_accepted(accepted))
    }

    /// 单个域的直投：按 MX 优先级依次尝试，前一跳失败就换下一台。
    async fn deliver_direct_to_domain(
        &self,
        mx: &dyn MxResolver,
        domain: &str,
        recipients: &[String],
        entry: &QueueEntry,
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let targets = resolve_mx_targets(mx, domain, self.direct_port, self.policy)
            .await
            .map_err(|error| classify_smtp_error(&error))?;

        let mut last: Option<DeliveryFailure> = None;
        for pinned in &targets {
            match self
                .deliver_one(pinned, DeliveryTls::Plaintext, entry, recipients)
                .await
            {
                Ok(receipt) => return Ok(receipt),
                Err(failure) => {
                    // 已判定的永久失败（如 550 用户不存在）换一台 MX 也不会变好；
                    // 只有连接层/临时失败才值得换下一台。
                    if failure.is_permanent() {
                        return Err(failure);
                    }
                    // 部分成功（这台 MX 已接受了其中一些人）：换下一台会把已接受的
                    // 人**再投一遍**。如实上报部分结果并停止尝试 —— 队列会把已投递
                    // 者从重试集合里摘除。
                    if !failure.accepted.is_empty() {
                        return Err(failure);
                    }
                    last = Some(failure);
                }
            }
        }

        Err(last.unwrap_or_else(|| {
            DeliveryFailure::transient("NoMxTarget", format!("no usable MX target for {domain}"))
        }))
    }
}

/// 按收件域分组（域名小写），顺序确定，便于复现与断言。
fn group_by_domain(recipients: &[String]) -> Vec<(String, Vec<String>)> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for recipient in recipients {
        let domain = recipient
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_ascii_lowercase())
            .unwrap_or_default();
        groups.entry(domain).or_default().push(recipient.clone());
    }
    groups.into_iter().collect()
}

impl Transport for SmtpRemoteTransport {
    fn deliver<'a>(
        &'a self,
        entry: &'a QueueEntry,
        target: DeliveryTarget,
        recipients: &'a [String],
    ) -> DeliveryFuture<'a> {
        Box::pin(async move { self.deliver_remote(entry, target, recipients).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_xx_is_transient_and_five_xx_is_permanent() {
        // RFC 5321 §4.2.3 的分类是整个队列决策的基石。
        for code in [400u16, 421, 450, 451, 452, 499] {
            assert_eq!(
                classify_code(code),
                FailureClass::Transient,
                "{code} 应可重试"
            );
        }
        for code in [500u16, 550, 551, 552, 553, 554, 599] {
            assert_eq!(
                classify_code(code),
                FailureClass::Permanent,
                "{code} 应退信"
            );
        }
        // 2xx/3xx 不属于「失败」，但若被误传，按可重试处理（宁可重试也不误退信）。
        assert_eq!(classify_code(250), FailureClass::Transient);
    }

    #[test]
    fn unknown_transport_errors_are_retryable_never_bounces() {
        // 连接超时 / 断开意味着**结果未知**，邮件可能已投出。据此退信会让发件人
        // 重复发送。故一律判为可重试。
        let cases = vec![
            SmtpError::Connect {
                addr: "1.2.3.4:25".parse().unwrap(),
                source: std::io::Error::other("refused"),
            },
            SmtpError::ConnectTimeout {
                addr: "1.2.3.4:25".parse().unwrap(),
                secs: 20,
            },
            SmtpError::Protocol("bad framing".into()),
            SmtpError::Io(std::io::Error::other("reset")),
            SmtpError::Tls("handshake aborted".into()),
            SmtpError::Dns("timeout".into()),
        ];
        for error in cases {
            let failure = classify_smtp_error(&error);
            assert_eq!(
                failure.class,
                FailureClass::Transient,
                "{} 必须可重试（否则可能误退信已投递的邮件）",
                error.kind()
            );
        }
    }

    #[test]
    fn misconfiguration_is_permanent_so_it_does_not_flood_the_queue() {
        // 配置错了重试一万次也不会变好；判为永久可让它尽快退信并让运维看到原因。
        let cases = vec![
            SmtpError::InvalidEndpoint("bad host".into()),
            SmtpError::TlsRequired,
            SmtpError::IncompleteCredentials,
            SmtpError::PrivateRelayDisabled,
            SmtpError::NoAcceptableAddress("relay.example.test".into()),
        ];
        for error in cases {
            assert!(
                classify_smtp_error(&error).is_permanent(),
                "{} 应判为永久失败",
                error.kind()
            );
        }
    }

    #[test]
    fn response_classification_keeps_the_status_code() {
        let transient = classify_response(421, "421 service not available");
        assert_eq!(transient.class, FailureClass::Transient);
        assert_eq!(transient.code, Some(421));
        assert_eq!(transient.kind, "SmtpRejected");

        let permanent = classify_response(550, "550 no such user");
        assert!(permanent.is_permanent());
        assert_eq!(permanent.code, Some(550));
    }

    /// 一个只回固定 MX 记录的解析器。
    struct StubMxResolver {
        records: Vec<mailstack_smtp::MxRecord>,
    }

    impl mailstack_smtp::MxResolver for StubMxResolver {
        fn lookup_mx(&self, domain: &str) -> mailstack_smtp::MxFuture<'_> {
            let domain = domain.to_string();
            let records = self.records.clone();
            Box::pin(async move {
                // 与真实解析器同形：空域名不是一条可查询的名字。
                if domain.is_empty() {
                    return Err(SmtpError::Dns("empty domain".to_string()));
                }
                Ok(records)
            })
        }
    }

    fn outbound_entry(recipients: &[&str]) -> QueueEntry {
        QueueEntry::new(
            crate::entry::EntryKind::Outbound,
            "s@example.org",
            recipients.iter().map(|r| r.to_string()).collect(),
            "body",
            0,
        )
        .unwrap()
    }

    fn dialer() -> PinnedDialer {
        PinnedDialer::with_webpki_roots(Duration::from_secs(2)).unwrap()
    }

    #[tokio::test]
    async fn direct_route_fails_loudly_and_never_falls_back_to_the_relay() {
        // INV-18 的队列侧落点：直投**不可用**（未注入 MX 后端）时，结果是明确的失败，
        // 而不是「悄悄改用中继」这种会破坏 SPF 对齐的兜底。
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1));
        let entry = outbound_entry(&["r@example.net"]);

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();

        assert_eq!(failure.kind, "DirectDeliveryUnavailable");
        assert_eq!(
            failure.class,
            FailureClass::Transient,
            "不得把「不可用」伪装成永久失败去退掉用户的邮件"
        );
        assert!(failure.message.contains("configure a relay"));
    }

    #[tokio::test]
    async fn a_null_mx_is_a_permanent_failure_not_a_retry() {
        // RFC 7505：对端明确声明不收信。重试只会把队列撑大，必须立刻退信。
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1))
                .with_policy(AddressPolicy::allow_private())
                .with_mx(Arc::new(StubMxResolver {
                    records: vec![mailstack_smtp::MxRecord {
                        preference: 0,
                        host: String::new(),
                    }],
                }));
        let entry = outbound_entry(&["r@example.net"]);

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();

        assert_eq!(failure.kind, "NullMx");
        assert_eq!(failure.class, FailureClass::Permanent, "null MX 必须退信");
    }

    #[tokio::test]
    async fn direct_delivery_is_refused_when_the_mx_points_into_private_space() {
        // INV-15 的直投侧：收件域可以用 MX 记录把本机当成内网扫描器。
        // 公网策略必须拒绝环回/私网 MX —— 而且**不回落**到中继。
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1))
                .with_policy(AddressPolicy::public_only())
                .with_mx(Arc::new(StubMxResolver {
                    records: vec![mailstack_smtp::MxRecord {
                        preference: 10,
                        host: "127.0.0.1".to_string(),
                    }],
                }));
        let entry = outbound_entry(&["r@example.net"]);

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();

        assert_eq!(failure.kind, "NoAcceptableAddress");
        assert_eq!(failure.class, FailureClass::Permanent);
    }

    #[tokio::test]
    async fn a_recipient_without_a_domain_is_never_silently_accepted() {
        // 防御性：没有 `@` 的收件人不可能有 MX，绝不能因此被判成「投递成功」。
        // （收件人语法在 SMTP 收信阶段就要求带 `@`，这里是第二道。）
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1))
                .with_policy(AddressPolicy::allow_private())
                .with_mx(Arc::new(StubMxResolver {
                    records: vec![mailstack_smtp::MxRecord {
                        preference: 10,
                        host: "127.0.0.1".to_string(),
                    }],
                }));
        let entry = QueueEntry::new(
            crate::entry::EntryKind::Outbound,
            "s@example.org",
            vec!["no-at-sign".to_string()],
            "body",
            0,
        )
        .unwrap();

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();
        assert_eq!(failure.kind, "DnsError", "空域名应报解析错误");
        assert!(failure.accepted.is_empty(), "不得声称投出去过");
    }

    /// 一个最小的假 MX：把收到的命令记下来，能收下一封邮件。
    async fn serve_fake_mx(
        listener: tokio::net::TcpListener,
        seen: Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (socket, _) = listener.accept().await.expect("接受直投连接");
        let (read_half, mut write) = socket.into_split();
        let mut reader = BufReader::new(read_half);
        write
            .write_all(b"220 fake.example.org ESMTP\r\n")
            .await
            .unwrap();

        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line).await.unwrap();
            if read == 0 {
                break;
            }
            let command = line.trim_end().to_string();
            seen.lock().unwrap().push(command.clone());
            let upper = command.to_ascii_uppercase();
            let reply: &[u8] = if upper.starts_with("EHLO") {
                b"250-fake.example.org\r\n250 SIZE 10240000\r\n"
            } else if upper.starts_with("DATA") {
                write
                    .write_all(b"354 End data with <CRLF>.<CRLF>\r\n")
                    .await
                    .unwrap();
                // 按**字节**找结束标记，而不是按行：正文可能不带结尾 CRLF，
                // 逐行切分会把 "body.\r\n" 当成一行而永远等不到标记。
                let mut body: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let read = tokio::io::AsyncReadExt::read(&mut reader, &mut chunk)
                        .await
                        .unwrap();
                    if read == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..read]);
                    if body.ends_with(b"\r\n.\r\n") || body == b".\r\n" {
                        break;
                    }
                }
                b"250 2.0.0 Ok: queued\r\n"
            } else if upper.starts_with("QUIT") {
                write.write_all(b"221 Bye\r\n").await.unwrap();
                break;
            } else if upper.starts_with("STARTTLS") {
                b"454 TLS not available\r\n"
            } else {
                b"250 OK\r\n"
            };
            write.write_all(reply).await.unwrap();
        }
    }

    #[tokio::test]
    async fn direct_delivery_follows_the_mx_and_never_sends_credentials() {
        // 端到端：真实 TCP 上的假 MX。要证明两件事 ——
        // 1) 直投真的把邮件按 MX 投出去了（而不是「明确失败」）；
        // 2) 直投路径**绝不**发送凭证（即便传输上误配了凭证），也不去碰 STARTTLS。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handle = {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move { serve_fake_mx(listener, seen).await })
        };

        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(5))
                .with_policy(AddressPolicy::allow_private())
                .with_direct_port(port)
                // 故意配上凭证：直投路径不得把它们发出去。
                .with_credentials("relay-user".to_string(), "relay-pass".to_string())
                .with_mx(Arc::new(StubMxResolver {
                    records: vec![mailstack_smtp::MxRecord {
                        preference: 10,
                        host: "127.0.0.1".to_string(),
                    }],
                }));

        let entry = outbound_entry(&["r@example.net"]);
        let result = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await;

        let commands = seen.lock().unwrap().clone();
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(failure) => panic!("直投应成功，实际 {failure:?}；对端收到的命令：{commands:?}"),
        };
        assert_eq!(receipt.accepted, 1);

        handle.await.expect("假 MX 任务不应 panic");
        assert!(
            commands
                .iter()
                .any(|c| c.to_uppercase().starts_with("EHLO")),
            "{commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c.to_lowercase().starts_with("mail from:<s@example.org>")),
            "信封发件人必须原样送达：{commands:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|c| c.to_uppercase().starts_with("AUTH")),
            "直投路径绝不能发送凭证：{commands:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|c| c.to_uppercase().starts_with("STARTTLS")),
            "直投当前不做机会式 TLS：{commands:?}"
        );
    }

    #[test]
    fn recipients_are_grouped_by_domain_in_a_deterministic_order() {
        let groups = group_by_domain(&[
            "b@y.test".to_string(),
            "a@x.test".to_string(),
            "c@y.test".to_string(),
        ]);
        assert_eq!(
            groups,
            vec![
                ("x.test".to_string(), vec!["a@x.test".to_string()]),
                (
                    "y.test".to_string(),
                    vec!["b@y.test".to_string(), "c@y.test".to_string()]
                ),
            ],
            "顺序必须确定（按域名），否则行为不可复现"
        );
    }

    #[tokio::test]
    async fn local_target_is_rejected_by_the_smtp_transport() {
        // 结构性守卫：SMTP 传输不得被用来投本地收件人（那样会绕过 Dovecot/LMTP）。
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1));
        let entry = outbound_entry(&["r@example.net"]);

        let failure = transport
            .deliver(&entry, DeliveryTarget::Local, &entry.recipients)
            .await
            .unwrap_err();
        assert_eq!(failure.kind, "WrongTransport");
        assert!(failure.is_permanent());
    }
}

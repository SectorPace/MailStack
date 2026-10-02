//! 出站 DKIM 签名（规格书 §5.8、§3.3）。
//!
//! ## 为什么是「远端传输的装饰器」而不是「运行器里的一句调用」
//!
//! 签名是**外发邮件的必经步骤**，不是可选的收尾动作。做成 [`SigningTransport`]
//! 装饰器并由 [`crate::QueueRunner::new`] **无条件**套上之后，「存在一条未签名的
//! 出站路径」这件事在代码里就不可表达了 —— 与 `crates/store` 不提供任何写 Maildir
//! 的 API 是同一个思路：不是「记得别写」，而是根本没有那样的入口。
//!
//! 本地投递（LMTP → Dovecot）**不**套这层：收件人是本机自己的用户，DKIM 的意义在
//! 于向**外部**接收方证明身份。
//!
//! ## 失败语义：失败关闭（已裁定）
//!
//! 三类结果被刻意区分开：
//!
//! | 结果 | 含义 | 行为 |
//! |---|---|---|
//! | [`SigningOutcome::NotApplicable`] | 没有签名策略（还没初始化），或发件域不属于本机 | 原样发出 |
//! | [`SigningOutcome::Signed`] | 已签名 | 用签名后的报文投递 |
//! | [`SigningOutcome::Failed`] | **该签却没签成**（私钥读不出、DER 损坏） | **不发出**，报明确的本机故障 |
//!
//! 失败关闭的理由：基线里 Postfix + OpenDKIM 在签名内部错误上默认就是 `tempfail`；
//! 而失败开放会让邮件带着「未签名」的状态去撞收件方的 DMARC（本机 DNS 向导发布的
//! 正是 `p=quarantine/reject`），错误发生在远端、定位难度远高于本地退信。
//!
//! 失败被标记为 [`DeliveryFailure::with_local_fault`]，因此**不会**污染「出站健康」——
//! 否则运维会看到「出站 25 被封，请配置中继」，然后去查一个完全无关的方向。

use std::sync::Arc;

use mailstack_auth::keys::load_private_key_der;
use mailstack_auth::policy::{signing_policy, SigningPolicyOutcome};
use mailstack_auth::{from_domain, sign, DEFAULT_SIGNED_HEADERS};
use mailstack_core::paths::Paths;

use crate::delivery::{DeliveryFailure, DeliveryFuture, DeliveryTarget, Transport};
use crate::entry::QueueEntry;

/// 签名失败的稳定类别名（会出现在队列条目的 `lastError` 与 DSN 诊断里）。
pub const SIGNING_FAILURE_KIND: &str = "DkimSigningFailed";

/// 一次签名决策的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningOutcome {
    /// 已签名，返回「签名头 + 原报文」。
    Signed(String),
    /// 本封不需要签名。
    NotApplicable,
    /// 需要签名但失败了。**队列把它当作失败关闭**（见模块说明）。
    Failed(String),
}

/// 报文签名器。
///
/// 抽成 trait 是为了让队列的失败路径可以被离线验证 —— 真实的 RSA 签名不可能
/// 按测试意图失败。
pub trait MessageSigner: Send + Sync {
    fn sign(&self, message: &str) -> SigningOutcome;
}

/// 生产签名器：策略来自 `setup.json`，私钥来自 `/etc/opendkim/keys/<domain>/`。
///
/// 每次都重新解析策略与私钥，因此**密钥轮换后下一次投递就生效**，不需要重启。
pub struct DkimSigner {
    paths: Paths,
    headers: Vec<String>,
}

impl std::fmt::Debug for DkimSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkimSigner")
            .field("etc", &self.paths.etc)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

impl DkimSigner {
    /// 使用 [`DEFAULT_SIGNED_HEADERS`]。
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            headers: DEFAULT_SIGNED_HEADERS
                .iter()
                .map(|header| (*header).to_string())
                .collect(),
        }
    }

    /// 覆盖要签名的头集合（测试与特殊投递场景）。
    pub fn with_headers(mut self, headers: Vec<String>) -> Self {
        self.headers = headers;
        self
    }
}

impl MessageSigner for DkimSigner {
    fn sign(&self, message: &str) -> SigningOutcome {
        let policy = match signing_policy(&self.paths) {
            SigningPolicyOutcome::Sign(policy) => policy,
            // 还没做过 setup 就不是错误，只是「本机不负责签名」。
            SigningPolicyOutcome::Skip { .. } => return SigningOutcome::NotApplicable,
        };

        // 只签本机负责的域。拿自己的密钥去给别人的域背书，是越权而不是「多加一层保护」。
        let Some(from_domain) = from_domain(message.as_bytes()) else {
            return SigningOutcome::NotApplicable;
        };
        if !policy.covers(&from_domain) {
            return SigningOutcome::NotApplicable;
        }

        let key = match load_private_key_der(&policy.private_key) {
            Ok(key) => key,
            Err(error) => return SigningOutcome::Failed(error.to_string()),
        };

        let headers: Vec<&str> = self.headers.iter().map(String::as_str).collect();
        match sign(
            &key,
            &policy.domain,
            &policy.selector,
            &headers,
            message.as_bytes(),
        ) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(signed) => SigningOutcome::Signed(signed),
                // 原文是 String、前缀是 ASCII，所以这里不可达。真发生了也**必须**
                // 失败：用 lossy 转换会把签名悄悄写坏或改写正文。
                Err(_) => SigningOutcome::Failed("signed message is not valid UTF-8".to_string()),
            },
            Err(error) => SigningOutcome::Failed(error.to_string()),
        }
    }
}

/// 给任意远端传输套上 DKIM 签名。
pub struct SigningTransport {
    inner: Arc<dyn Transport>,
    signer: Arc<dyn MessageSigner>,
}

impl SigningTransport {
    pub fn new(inner: Arc<dyn Transport>, signer: Arc<dyn MessageSigner>) -> Self {
        Self { inner, signer }
    }
}

impl Transport for SigningTransport {
    fn deliver<'a>(
        &'a self,
        entry: &'a QueueEntry,
        target: DeliveryTarget,
        recipients: &'a [String],
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            match self.signer.sign(&entry.data) {
                SigningOutcome::NotApplicable => {
                    self.inner.deliver(entry, target, recipients).await
                }
                SigningOutcome::Signed(data) => {
                    // 只替换报文：信封、收件人、重试计数都保持原样。
                    let mut signed = entry.clone();
                    signed.data = data;
                    self.inner.deliver(&signed, target, recipients).await
                }
                SigningOutcome::Failed(reason) => {
                    Err(DeliveryFailure::transient(SIGNING_FAILURE_KIND, reason).with_local_fault())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryReceipt, FailureClass};
    use crate::entry::EntryKind;
    use mailstack_core::config::{write_setup_config, SetupConfig};
    use std::sync::Mutex;

    const MESSAGE: &str = concat!(
        "From: alice@example.org\r\n",
        "To: bob@example.net\r\n",
        "Subject: outbound\r\n",
        "\r\n",
        "body\r\n"
    );

    /// 记录收到的报文，便于断言「传输实际看到了什么」。
    struct RecordingTransport {
        seen: Mutex<Vec<QueueEntry>>,
    }

    impl RecordingTransport {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
            })
        }

        fn data(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|entry| entry.data.clone())
                .collect()
        }
    }

    impl Transport for RecordingTransport {
        fn deliver<'a>(
            &'a self,
            entry: &'a QueueEntry,
            _target: DeliveryTarget,
            recipients: &'a [String],
        ) -> DeliveryFuture<'a> {
            Box::pin(async move {
                self.seen.lock().unwrap().push(entry.clone());
                Ok(DeliveryReceipt {
                    accepted: recipients.len(),
                })
            })
        }
    }

    struct FixedSigner(SigningOutcome);

    impl MessageSigner for FixedSigner {
        fn sign(&self, _message: &str) -> SigningOutcome {
            self.0.clone()
        }
    }

    fn entry() -> QueueEntry {
        QueueEntry::new(
            EntryKind::Outbound,
            "alice@example.org",
            vec!["bob@example.net".to_string()],
            MESSAGE,
            1_000,
        )
        .unwrap()
    }

    async fn deliver_with(
        signer: SigningOutcome,
    ) -> (Vec<String>, Result<DeliveryReceipt, DeliveryFailure>) {
        let inner = RecordingTransport::new();
        let transport = SigningTransport::new(inner.clone(), Arc::new(FixedSigner(signer)));
        let entry = entry();
        let result = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(mailstack_smtp::OutboundRoute::Direct),
                &entry.recipients,
            )
            .await;
        (inner.data(), result)
    }

    #[tokio::test]
    async fn the_signed_bytes_are_what_the_inner_transport_receives() {
        let (seen, result) =
            deliver_with(SigningOutcome::Signed("SIGNED-MESSAGE".to_string())).await;
        assert!(result.is_ok());
        assert_eq!(
            seen,
            vec!["SIGNED-MESSAGE".to_string()],
            "内层传输必须收到签名后的报文"
        );
    }

    #[tokio::test]
    async fn not_applicable_passes_the_entry_through_unchanged() {
        let (seen, result) = deliver_with(SigningOutcome::NotApplicable).await;
        assert!(result.is_ok());
        assert_eq!(seen, vec![MESSAGE.to_string()], "不该签的邮件必须原样发出");
    }

    #[tokio::test]
    async fn a_signing_failure_is_fail_closed_and_marked_as_a_local_fault() {
        // 失败关闭 + 不得污染出站健康，两条都在这一条断言里。
        let (seen, result) =
            deliver_with(SigningOutcome::Failed("key is unreadable".to_string())).await;

        assert!(seen.is_empty(), "签名失败时绝不能把未签名邮件发出去");
        let failure = result.unwrap_err();
        assert_eq!(failure.kind, SIGNING_FAILURE_KIND);
        assert_eq!(failure.class, FailureClass::Transient, "应退回队列重试");
        assert!(
            failure.local_fault,
            "DKIM 签名失败是本机故障，不得计入出站健康"
        );
        assert!(failure.message.contains("key is unreadable"));
    }

    // ───────────── 真实密钥路径 ─────────────

    struct Fixture {
        _dir: tempfile::TempDir,
        paths: Paths,
    }

    fn config() -> SetupConfig {
        SetupConfig {
            domain: "example.org".to_string(),
            mail_host: "mail.example.org".to_string(),
            server_ip: "203.0.113.10".to_string(),
            dkim_selector: "mailstack".to_string(),
            expected_spf: None,
            updated_at: "2026-10-01T00:00:00Z".to_string(),
        }
    }

    /// RSA-2048 生成较慢，整个模块共用一份真实密钥。
    fn fixture() -> &'static Fixture {
        static FIXTURE: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::rooted(dir.path());
            write_setup_config(&paths, &config()).unwrap();
            mailstack_auth::keys::rotate(&paths, "example.org", None).expect("生成真实 DKIM 密钥");
            Fixture { _dir: dir, paths }
        })
    }

    #[test]
    fn a_real_key_signs_covered_senders_and_leaves_foreign_senders_unsigned() {
        let signer = DkimSigner::new(fixture().paths.clone());

        let signed = match signer.sign(MESSAGE) {
            SigningOutcome::Signed(signed) => signed,
            other => panic!("本域发件人必须被签名，实际 {other:?}"),
        };
        assert!(signed.starts_with("DKIM-Signature:"), "签名头必须前置");
        assert!(signed.ends_with(MESSAGE), "原报文必须逐字保留");
        assert!(signed.contains("d=example.org"), "d= 必须是策略域");
        assert!(signed.contains("s=mailstack"), "s= 必须是策略 selector");

        // 子域也在策略覆盖范围内（DMARC relaxed 对齐比较的是组织域）。
        let subdomain = "From: bob@sub.example.org\r\nSubject: t\r\n\r\nbody\r\n";
        assert!(matches!(signer.sign(subdomain), SigningOutcome::Signed(_)));

        // 外域发件人：不得用本机密钥替它背书。
        let foreign = "From: eve@other.test\r\nSubject: t\r\n\r\nbody\r\n";
        assert_eq!(signer.sign(foreign), SigningOutcome::NotApplicable);
    }

    #[test]
    fn an_uninitialised_host_reports_not_applicable_rather_than_failing() {
        // 没跑过 setup 的新装环境是**正常状态**，不是故障 ——
        // 否则每封外发邮件的第一次尝试都会失败。
        let dir = tempfile::tempdir().unwrap();
        let signer = DkimSigner::new(Paths::rooted(dir.path()));
        assert_eq!(signer.sign(MESSAGE), SigningOutcome::NotApplicable);
    }

    #[test]
    fn a_broken_key_fails_instead_of_silently_sending_unsigned() {
        // 策略在（私钥文件存在）但内容不可解析 —— 必须 Failed，而不是降级为不签。
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        write_setup_config(&paths, &config()).unwrap();
        let key = mailstack_auth::keys::private_key_path(&paths, "example.org", "mailstack");
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        std::fs::write(
            &key,
            b"-----BEGIN RSA PRIVATE KEY-----\nnot base64 at all\n",
        )
        .unwrap();

        let signer = DkimSigner::new(paths);
        match signer.sign(MESSAGE) {
            SigningOutcome::Failed(reason) => {
                assert!(
                    reason.contains("mailstack.private"),
                    "原因要指明是哪把钥匙：{reason}"
                )
            }
            other => panic!("损坏的私钥必须判为失败，实际 {other:?}"),
        }
    }
}

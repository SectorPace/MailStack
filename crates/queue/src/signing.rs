use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use mailstack_auth::keys::load_private_key_der;
use mailstack_auth::policy::{signing_policy, SigningPolicyOutcome};
use mailstack_auth::{from_domain, sign, DEFAULT_SIGNED_HEADERS};
use mailstack_core::paths::Paths;

use crate::delivery::{DeliveryFailure, DeliveryFuture, DeliveryTarget, Transport};
use crate::entry::QueueEntry;

pub const SIGNING_FAILURE_KIND: &str = "DkimSigningFailed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningOutcome {
    Signed(String),

    NotApplicable,

    Failed(String),
}

pub trait MessageSigner: Send + Sync {
    fn sign(&self, message: &str) -> SigningOutcome;
}

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
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            headers: DEFAULT_SIGNED_HEADERS
                .iter()
                .map(|header| (*header).to_string())
                .collect(),
        }
    }

    pub fn with_headers(mut self, headers: Vec<String>) -> Self {
        self.headers = headers;
        self
    }
}

impl MessageSigner for DkimSigner {
    fn sign(&self, message: &str) -> SigningOutcome {
        let policy = match signing_policy(&self.paths) {
            SigningPolicyOutcome::Sign(policy) => policy,

            SigningPolicyOutcome::Skip { .. } => return SigningOutcome::NotApplicable,
        };

        let Some(from_domain) = from_domain(message.as_bytes()) else {
            return SigningOutcome::NotApplicable;
        };
        if !policy.covers(&from_domain) {
            return SigningOutcome::NotApplicable;
        }

        let key = match cached_private_key(&policy.private_key) {
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

                Err(_) => SigningOutcome::Failed("signed message is not valid UTF-8".to_string()),
            },
            Err(error) => SigningOutcome::Failed(error.to_string()),
        }
    }
}

struct KeyCache {
    path: PathBuf,
    mtime: Option<SystemTime>,
    len: Option<u64>,
    parsed: Arc<Vec<u8>>,
}

static KEY_CACHE: OnceLock<Mutex<Option<KeyCache>>> = OnceLock::new();

fn cached_private_key(path: &Path) -> mailstack_auth::AuthResult<Arc<Vec<u8>>> {
    let fingerprint = std::fs::metadata(path)
        .ok()
        .map(|meta| (meta.modified().ok(), meta.len()));

    let cache = KEY_CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = guard.as_ref() {
        if let Some((mtime, len)) = &fingerprint {
            if cached.path == path && cached.mtime == *mtime && cached.len == Some(*len) {
                return Ok(Arc::clone(&cached.parsed));
            }
        }
    }
    let parsed = Arc::new(load_private_key_der(path)?);
    *guard = Some(KeyCache {
        path: path.to_path_buf(),
        mtime: fingerprint.as_ref().and_then(|(mtime, _)| *mtime),
        len: fingerprint.as_ref().map(|(_, len)| *len),
        parsed: Arc::clone(&parsed),
    });
    Ok(parsed)
}

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

            wizard_completed: false,
            updated_at: "2026-10-01T00:00:00Z".to_string(),
        }
    }

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

        let subdomain = "From: bob@sub.example.org\r\nSubject: t\r\n\r\nbody\r\n";
        assert!(matches!(signer.sign(subdomain), SigningOutcome::Signed(_)));

        let foreign = "From: eve@other.test\r\nSubject: t\r\n\r\nbody\r\n";
        assert_eq!(signer.sign(foreign), SigningOutcome::NotApplicable);
    }

    #[test]
    fn an_uninitialised_host_reports_not_applicable_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let signer = DkimSigner::new(Paths::rooted(dir.path()));
        assert_eq!(signer.sign(MESSAGE), SigningOutcome::NotApplicable);
    }

    #[test]
    fn a_broken_key_fails_instead_of_silently_sending_unsigned() {
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

    #[test]
    fn a_changed_key_file_is_picked_up_by_the_next_message() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        write_setup_config(&paths, &config()).unwrap();
        mailstack_auth::keys::rotate(&paths, "example.org", None).expect("生成 DKIM 密钥");
        let signer = DkimSigner::new(paths.clone());
        let key_path = mailstack_auth::keys::private_key_path(&paths, "example.org", "mailstack");

        assert!(
            matches!(signer.sign(MESSAGE), SigningOutcome::Signed(_)),
            "首次签名应成功（同时填充缓存）"
        );

        std::thread::sleep(std::time::Duration::from_millis(150));
        std::fs::write(
            &key_path,
            b"-----BEGIN RSA PRIVATE KEY-----\nnot base64 at all\n",
        )
        .unwrap();

        match signer.sign(MESSAGE) {
            SigningOutcome::Failed(reason) => {
                assert!(reason.contains("mailstack.private"), "{reason}")
            }
            other => panic!("密钥文件变化后必须被重新读取，实际 {other:?}"),
        }
    }
}

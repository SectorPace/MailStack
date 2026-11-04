use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{QueueError, QueueResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Outbound,

    Bounce,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryKind::Outbound => "outbound",
            EntryKind::Bounce => "bounce",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueEntry {
    pub id: String,
    pub kind: EntryKind,

    #[serde(rename = "mailFrom")]
    pub mail_from: String,

    pub recipients: Vec<String>,

    pub data: String,

    #[serde(rename = "createdAt")]
    pub created_at: String,

    pub attempts: u32,

    #[serde(rename = "nextAttemptUnix")]
    pub next_attempt_unix: i64,

    #[serde(rename = "lastError", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,

    #[serde(rename = "lastCode", skip_serializing_if = "Option::is_none")]
    pub last_code: Option<u16>,
}

const MAX_ADDRESS_LEN: usize = 320;

impl QueueEntry {
    pub fn new(
        kind: EntryKind,
        mail_from: impl Into<String>,
        recipients: Vec<String>,
        data: impl Into<String>,
        now_unix: i64,
    ) -> QueueResult<Self> {
        let entry = Self {
            id: new_id(),
            kind,
            mail_from: mail_from.into(),
            recipients,
            data: data.into(),
            created_at: mailstack_core::format_iso8601(
                time::OffsetDateTime::from_unix_timestamp(now_unix)
                    .unwrap_or_else(|_| time::OffsetDateTime::now_utc()),
            ),
            attempts: 0,
            next_attempt_unix: now_unix,
            last_error: None,
            last_code: None,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn is_null_sender(&self) -> bool {
        self.mail_from.is_empty()
    }

    pub fn is_due(&self, now_unix: i64) -> bool {
        self.next_attempt_unix <= now_unix
    }

    pub fn validate(&self) -> QueueResult<()> {
        if !is_safe_id(&self.id) {
            return Err(QueueError::invalid(format!(
                "unsafe queue id: {:?}",
                self.id
            )));
        }
        if self.recipients.is_empty() {
            return Err(QueueError::invalid("queue entry has no recipients"));
        }
        if self.data.is_empty() {
            return Err(QueueError::invalid("queue entry has an empty message"));
        }
        for address in self
            .recipients
            .iter()
            .chain(std::iter::once(&self.mail_from))
        {
            if address.len() > MAX_ADDRESS_LEN {
                return Err(QueueError::invalid(format!(
                    "address exceeds {MAX_ADDRESS_LEN} characters"
                )));
            }
            if address.contains(['\r', '\n', '\0']) {
                return Err(QueueError::invalid(
                    "address must not contain CR, LF or NUL (SMTP command injection)",
                ));
            }
        }
        Ok(())
    }
}

pub fn is_safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub fn new_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{:011X}{:08X}{:04X}", millis, random_prefix(), seq & 0xFFFF)
}

fn random_prefix() -> u32 {
    static PREFIX: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *PREFIX.get_or_init(|| os_entropy().unwrap_or_else(fallback_entropy))
}

#[cfg(unix)]
fn os_entropy() -> Option<u32> {
    use std::io::Read;
    let mut file = std::fs::File::open("/dev/urandom").ok()?;
    let mut bytes = [0u8; 4];
    file.read_exact(&mut bytes).ok()?;
    Some(u32::from_be_bytes(bytes))
}

#[cfg(not(unix))]
fn os_entropy() -> Option<u32> {
    None
}

fn fallback_entropy() -> u32 {
    use std::hash::{BuildHasher, Hash, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    std::process::id().hash(&mut hasher);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        .hash(&mut hasher);
    hasher.finish() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(mail_from: &str, recipients: &[&str]) -> QueueResult<QueueEntry> {
        QueueEntry::new(
            EntryKind::Outbound,
            mail_from,
            recipients.iter().map(|s| s.to_string()).collect(),
            "Subject: t\r\n\r\nbody",
            1_700_000_000,
        )
    }

    #[test]
    fn new_entry_is_immediately_due_and_has_no_attempts() {
        let e = entry("s@example.org", &["r@example.net"]).unwrap();
        assert_eq!(e.attempts, 0);
        assert!(e.is_due(1_700_000_000));
        assert!(e.is_due(1_700_000_001));
        assert!(!e.is_due(1_699_999_999));
        assert!(!e.is_null_sender());
    }

    #[test]
    fn null_sender_is_recognised() {
        let e = entry("", &["r@example.net"]).unwrap();
        assert!(e.is_null_sender(), "空信封发件人 = null sender");
    }

    #[test]
    fn rejects_addresses_containing_crlf_or_nul() {
        for bad in ["r@example.net\r\nRCPT TO:<evil@x>", "r@x\n", "r@x\0y"] {
            let err = entry("s@example.org", &[bad]).unwrap_err();
            assert_eq!(err.kind(), "InvalidInput", "{bad:?} 必须被拒绝");
        }

        assert!(entry("s@example.org\r\nBcc: evil@x", &["r@example.net"]).is_err());
    }

    #[test]
    fn rejects_empty_recipients_and_empty_message() {
        assert!(entry("s@example.org", &[]).is_err());
        assert!(QueueEntry::new(
            EntryKind::Outbound,
            "s@example.org",
            vec!["r@example.net".to_string()],
            "",
            1
        )
        .is_err());
    }

    #[test]
    fn rejects_oversized_addresses() {
        let long = format!("{}@example.net", "a".repeat(MAX_ADDRESS_LEN));
        assert!(entry("s@example.org", &[long.as_str()]).is_err());
    }

    #[test]
    fn ids_stay_unique_across_many_generations() {
        let ids: std::collections::HashSet<String> = (0..10_000).map(|_| new_id()).collect();
        assert_eq!(
            ids.len(),
            10_000,
            "批量生成的 id 出现重复 —— 随机前缀缺失或过短"
        );

        let sample = new_id();
        assert_eq!(sample.len(), 23, "id 形状被改变：{sample}");
        assert!(is_safe_id(&sample));
    }

    #[test]
    fn entry_id_is_filename_safe_and_time_sortable() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b, "同一毫秒内也必须是唯一 id");
        assert!(is_safe_id(&a) && is_safe_id(&b));

        for bad in [
            "../etc/passwd",
            "/abs/path",
            "a/b",
            "a\\b",
            "",
            "x".repeat(65).as_str(),
        ] {
            assert!(!is_safe_id(bad), "{bad:?} 不得通过 id 校验");
        }
    }

    #[test]
    fn entry_rejects_unsafe_id() {
        let mut e = entry("s@example.org", &["r@example.net"]).unwrap();
        e.id = "../escape".to_string();
        assert!(e.validate().is_err(), "非法 id 必须在落盘前被拒绝");
    }

    #[test]
    fn json_round_trip_preserves_every_field() {
        let mut e = entry("s@example.org", &["r@example.net", "r2@example.net"]).unwrap();
        e.attempts = 3;
        e.next_attempt_unix = 1_700_000_600;
        e.last_error = Some("550 no such user".to_string());
        e.last_code = Some(550);

        let json = serde_json::to_string(&e).unwrap();
        let back: QueueEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e, "条目必须能无损往返序列化");

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("mailFrom").is_some());
        assert!(value.get("nextAttemptUnix").is_some());
        assert!(value.get("createdAt").is_some());
        assert!(value.get("lastCode").is_some());
    }

    #[test]
    fn json_omits_absent_failure_fields() {
        let e = entry("s@example.org", &["r@example.net"]).unwrap();
        let value: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert!(value.get("lastError").is_none());
        assert!(value.get("lastCode").is_none());
    }
}

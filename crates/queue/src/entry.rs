//! 队列条目（规格书 §5.8）。
//!
//! 条目是队列的唯一数据单位，**必须可序列化且自包含**：进程重启后仅凭磁盘上的
//! 这一个 JSON 就能重建投递所需的一切（信封、报文、重试计数、下次尝试时间）。
//!
//! 与安全相关的两条：
//!
//! 1. [`EntryKind`] **仅供展示**：投递路径只能由中继配置决定（INV-18 / INV-21），
//!    任何「按条目类型分流」的实现都是缺陷。DSN 退信因此只是一条普通条目。
//! 2. 信封地址与 id 都做字符校验：地址里的 CR/LF 会变成 SMTP 命令注入与头注入，
//!    id 会被拼进文件名（路径穿越）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{QueueError, QueueResult};

/// 条目类型。
///
/// **仅供展示与统计**，不参与任何路由或投递决策 —— DSN 退信与用户外发邮件走
/// 完全相同的出站路径（INV-21）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// 用户外发邮件。
    Outbound,
    /// DSN 退信（信封发件人必须为空，见 [`QueueEntry::is_null_sender`]）。
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

/// 队列条目。
///
/// 没有单独的「状态」字段：可投递性完全由既有字段推导（`recipients` 是否为空、
/// `next_attempt_unix` 是否已到），多存一个状态字段只会引入不一致的可能。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueEntry {
    /// 队列 ID（同时是文件名，见 [`is_safe_id`]）。
    pub id: String,
    pub kind: EntryKind,
    /// 信封发件人。空串表示 null sender（`<>`）—— DSN 必须使用它（RFC 3464 §3）。
    #[serde(rename = "mailFrom")]
    pub mail_from: String,
    /// **尚未完成**的收件人：已投递或已退信的会从列表移除。
    pub recipients: Vec<String>,
    /// 原始报文（RFC 5322 文本，CRLF 行结束）。
    pub data: String,
    /// 入队时间（ISO 8601 UTC）。
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// 已尝试投递次数。
    pub attempts: u32,
    /// 下次允许尝试的 Unix 秒。**持久化**，因此重启不会重置退避进度。
    #[serde(rename = "nextAttemptUnix")]
    pub next_attempt_unix: i64,
    /// 最近一次失败的描述（已判定失败的原因或未知失败的类别）。
    #[serde(rename = "lastError", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// 最近一次失败的状态码（仅当服务器给出了明确应答时存在）。
    #[serde(rename = "lastCode", skip_serializing_if = "Option::is_none")]
    pub last_code: Option<u16>,
}

/// 收发件地址的长度上限（RFC 5321 §4.5.3.1.3 的 254 已不够宽松，取 320 留余量）。
const MAX_ADDRESS_LEN: usize = 320;

impl QueueEntry {
    /// 新建条目：校验输入、生成 id、立即可投递。
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

    /// 信封发件人是否为空（null sender）。
    ///
    /// 空发件人意味着**绝不能对它退信** —— 否则退信本身会再次触发退信，
    /// 形成双退信回环（RFC 5321 §4.5.5）。
    pub fn is_null_sender(&self) -> bool {
        self.mail_from.is_empty()
    }

    /// 是否已到可尝试时间。
    pub fn is_due(&self, now_unix: i64) -> bool {
        self.next_attempt_unix <= now_unix
    }

    /// 校验条目是否可安全投递。
    ///
    /// 拒绝的条件都在「会产生错误行为」的类别里，而不是风格问题：
    /// 空收件人（无处投递）、控制字符地址（命令/头注入）、空报文、非法 id（路径穿越）。
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

/// id 是否可安全用作文件名。
///
/// 允许的字符集刻意很窄（ASCII 字母数字与 `-`），因此 `..`、`/`、`\` 之类的
/// 路径穿越写法**在字符集层面就不成立**。
pub fn is_safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// 生成队列 ID：毫秒时间戳（十六进制）+ 进程级随机前缀 + 进程内序号。
///
/// 时间戳在前，因此字典序即时间序，便于运维按顺序查看队列；序号保证同一毫秒内
/// 的多条消息不重名。
///
/// 中间那段随机前缀是**跨进程撞车**的防线：原实现只有「时间戳 + 进程内序号」，
/// 两个进程只要在同一毫秒各自从 0 开始计数，就会生成**同一个 id** —— 而入队是
/// 覆盖写，后写的一方会把先写的那封邮件无声覆盖掉。前缀来自进程生命周期内的
/// 一次随机采样（见 [`random_prefix`]），把跨进程撞车概率压到 2^-32 量级；
/// store 侧的 [`crate::store::QueueStore::enqueue_new`] 再兜底最后一层。
pub fn new_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{:011X}{:08X}{:04X}", millis, random_prefix(), seq & 0xFFFF)
}

/// 进程生命周期内固定的 32 位随机前缀。
///
/// 熵来源按序退化：unix 上先取 `/dev/urandom` 的 4 字节；拿不到（非 unix、
/// 文件缺失、读取失败）就用 `RandomState` 的种子哈希 pid 与纳秒时钟 ——
/// `RandomState` 每次构造都带操作系统注入的随机性，对「避免巧合相等」足够。
/// 用 [`std::sync::OnceLock`] 保证整个进程只生成一次：同一个进程内不存在重置问题。
fn random_prefix() -> u32 {
    static PREFIX: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *PREFIX.get_or_init(|| os_entropy().unwrap_or_else(fallback_entropy))
}

/// unix：从 `/dev/urandom` 读恰好 4 字节。
///
/// 刻意不用 `fs::read`：`/dev/urandom` 是**无限**文件，整体读入会把进程挂死；
/// 必须按定长 `read_exact`。
#[cfg(unix)]
fn os_entropy() -> Option<u32> {
    use std::io::Read;
    let mut file = std::fs::File::open("/dev/urandom").ok()?;
    let mut bytes = [0u8; 4];
    file.read_exact(&mut bytes).ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// 非 unix 平台没有 `/dev/urandom`，直接走回退。
#[cfg(not(unix))]
fn os_entropy() -> Option<u32> {
    None
}

/// 回退熵：哈希 `RandomState` 种子 + pid + 纳秒时钟。
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
        // SMTP 命令注入：地址里塞 CRLF 可以在事务中插入额外命令。
        for bad in ["r@example.net\r\nRCPT TO:<evil@x>", "r@x\n", "r@x\0y"] {
            let err = entry("s@example.org", &[bad]).unwrap_err();
            assert_eq!(err.kind(), "InvalidInput", "{bad:?} 必须被拒绝");
        }
        // 发件人同样要校验。
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

    /// 随机前缀把跨进程撞车压到可忽略：大批量连续生成也不得重复，
    /// 且「时间戳在前、字典序即时间序」的形状不得被破坏。
    #[test]
    fn ids_stay_unique_across_many_generations() {
        let ids: std::collections::HashSet<String> = (0..10_000).map(|_| new_id()).collect();
        assert_eq!(
            ids.len(),
            10_000,
            "批量生成的 id 出现重复 —— 随机前缀缺失或过短"
        );

        // 形状契约：11 位毫秒时间戳 + 8 位随机前缀 + 4 位序号，仍是文件名安全的。
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

        // 路径穿越写法在字符集层面就不成立。
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

        // 磁盘格式是对外契约（camelCase），改名会让旧队列文件读不出来。
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

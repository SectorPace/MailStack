//! Maildir 存储后端：文件夹、UID 映射、Maildir 标志与关键字。
//!
//! ## 磁盘布局（与 Dovecot 的 Maildir 本体兼容）
//!
//! ```text
//! <root>/                        ← INBOX
//!   cur/ new/ tmp/
//!   .mailstack-uidlist           ← UID 映射（本实现私有，见下）
//!   .mailstack-keywords          ← 关键字字母表（本实现私有）
//!   subscriptions                ← 订阅清单
//!   .Sent/                       ← 文件夹 "Sent"（IMAP 层级分隔符 '.'）
//!   .Sent.2026/                  ← 文件夹 "Sent.2026"
//! ```
//!
//! ## UID 稳定的关键：映射键是 **unique base**，不是文件名
//!
//! Maildir 的文件名由 `<unique>` + `:2,<flags>` 组成，flags 会随 `\Seen` /
//! `\Deleted` 变化 —— 也就是**文件名会变**。若 UID 映射以文件名为键，一次
//! `STORE \Seen` 就会让同一封邮件换一个 UID，客户端缓存全部失效。因此：
//!
//! * 映射键 = `:2,` 之前的 unique 部分；
//! * `new/` → `cur/` 的搬迁、标志重命名都不影响映射；
//! * 只有文件消失（EXPUNGE / 外部删除）才移除条目。
//!
//! ## uidlist 的损坏处理：换 UIDVALIDITY，而不是猜
//!
//! 文件缺失/损坏/形状不对时，本实现**重建**映射并分配新的 `UIDVALIDITY`。
//! 这是 RFC 3501 §2.3.1.1 要求的语义：UID 只有在 UIDVALIDITY 不变时才必须稳定。
//! 静默复用旧 UID 会让客户端把 A 邮件的内容贴到 B 邮件上，比「重新同步」危险得多。
//!
//! ## 关键字
//!
//! Maildir 只规定 `S/F/R/T/D/P` 六个字母；IMAP 的 `$Junk`、`$Forwarded` 等
//! 需要额外字母。本实现用 `.mailstack-keywords`（`<letter> <keyword>`）持久化
//! 字母表，字母 a–z、每个文件夹最多 26 个关键字。字母一旦分配就不再回收 ——
//! 回收会让「删掉关键字再重建」复用字母，导致历史文件名被误读。
//!
//! ## 并发与崩溃一致性
//!
//! * 所有 uidlist/keywords/subscriptions 的读改写都在 `flock` 临界区内；
//! * 投递先写 `tmp/`、`sync_all` 后 `rename` 到 `cur|new/`（同文件系统原子）；
//! * uidlist 用「临时文件 + rename」写入；崩溃最多丢掉「刚刚分配、尚未提交」的
//!   UID，下次打开会重新分配并换 UIDVALIDITY（客户端重新同步，但不串信）。
//!
//! ## 有意不做的事
//!
//! * **运行期不读写 Dovecot `dovecot-uidlist`**：两套实现同时写一个 Maildir 会
//!   产生两套 UID。切换实现时用 [`crate::migration::migrate_maildir`] **离线**把
//!   Dovecot 的 UID 与关键字接管过来；之后只由本实现维护 `.mailstack-uidlist`。
//! * **扫描是 O(邮件数)**：单次打开最多索引 [`MAX_SCAN_ENTRIES`] 封，超过返回
//!   存储错误而不是把内存吃光。大信箱调优（缓存 mtime、索引文件）是后续版本。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;

use crate::error::{MailError, Result};

pub const INBOX: &str = "INBOX";
pub const DELIMITER: char = '.';

const UIDLIST: &str = ".mailstack-uidlist";
const UIDLIST_LOCK: &str = ".mailstack-uidlist.lock";
const KEYWORDS: &str = ".mailstack-keywords";
const KEYWORDS_LOCK: &str = ".mailstack-keywords.lock";
const SPECIAL_USE: &str = ".mailstack-special-use";
/// QRESYNC 的消失记录：`<uid> <modseq>`，每次 EXPUNGE 追加。
const EXPUNGED: &str = ".mailstack-expunged";
const EXPUNGED_MAX_BYTES: u64 = 8 * 1024 * 1024;
const QUOTA: &str = ".mailstack-quota";
const QUOTA_LOCK: &str = ".mailstack-quota.lock";
/// RFC 5464 METADATA：邮箱级元数据（`<entry> <base64-value>` 每行一条）。
const METADATA: &str = ".mailstack-metadata";
const METADATA_LOCK: &str = ".mailstack-metadata.lock";
/// 服务器级元数据（`GETMETADATA ""`）存放在存储根目录。
const SERVER_METADATA: &str = ".mailstack-metadata-server";
const SERVER_METADATA_LOCK: &str = ".mailstack-metadata-server.lock";
/// RFC 4314 ACL：`<identifier> <rights>` 每行一条。
const ACL: &str = ".mailstack-acl";
const ACL_LOCK: &str = ".mailstack-acl.lock";
const USAGE: &str = ".mailstack-usage";
const SUBSCRIPTIONS: &str = "subscriptions";
const SUBSCRIPTIONS_LOCK: &str = "subscriptions.lock";

/// RFC 6154 + RFC 8457 的特殊用途属性。
pub const SPECIAL_USE_ATTRS: [&str; 8] = [
    "\\All",
    "\\Archive",
    "\\Drafts",
    "\\Flagged",
    "\\Important",
    "\\Junk",
    "\\Sent",
    "\\Trash",
];

pub fn canonical_special_use(value: &str) -> Option<&'static str> {
    SPECIAL_USE_ATTRS
        .iter()
        .find(|attribute| attribute.eq_ignore_ascii_case(value))
        .copied()
}

pub fn is_special_use_attr(value: &str) -> bool {
    canonical_special_use(value).is_some()
}

fn default_special_use(name: &str) -> Option<&'static str> {
    let leaf = name
        .rsplit(DELIMITER)
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_lowercase();
    match leaf.as_str() {
        "sent" | "sent items" | "sent mail" => Some("\\Sent"),
        "drafts" => Some("\\Drafts"),
        "trash" | "deleted items" | "deleted messages" => Some("\\Trash"),
        "junk" | "spam" => Some("\\Junk"),
        "archive" => Some("\\Archive"),
        "all" | "all mail" => Some("\\All"),
        "flagged" => Some("\\Flagged"),
        "important" => Some("\\Important"),
        _ => None,
    }
}

const MAX_FOLDER_NAME: usize = 200;
const MAX_SCAN_ENTRIES: usize = 200_000;
const MAX_KEYWORDS: usize = 26;

/// 时间源（Unix 秒）。注入让 UIDVALIDITY 与 unique 名的生成可被确定性验证。
pub trait Clock: Send + Sync + 'static {
    fn now_secs(&self) -> i64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// 标志
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SystemFlag {
    Answered,
    Deleted,
    Draft,
    Flagged,
    Seen,
}

impl SystemFlag {
    pub fn imap_name(self) -> &'static str {
        match self {
            SystemFlag::Answered => "\\Answered",
            SystemFlag::Deleted => "\\Deleted",
            SystemFlag::Draft => "\\Draft",
            SystemFlag::Flagged => "\\Flagged",
            SystemFlag::Seen => "\\Seen",
        }
    }

    fn maildir_char(self) -> char {
        match self {
            SystemFlag::Draft => 'D',
            SystemFlag::Flagged => 'F',
            SystemFlag::Answered => 'R',
            SystemFlag::Seen => 'S',
            SystemFlag::Deleted => 'T',
        }
    }

    fn from_char(value: char) -> Option<Self> {
        match value {
            'D' => Some(SystemFlag::Draft),
            'F' => Some(SystemFlag::Flagged),
            'R' => Some(SystemFlag::Answered),
            'S' => Some(SystemFlag::Seen),
            'T' => Some(SystemFlag::Deleted),
            _ => None,
        }
    }

    fn from_imap(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "\\answered" => Some(SystemFlag::Answered),
            "\\deleted" => Some(SystemFlag::Deleted),
            "\\draft" => Some(SystemFlag::Draft),
            "\\flagged" => Some(SystemFlag::Flagged),
            "\\seen" => Some(SystemFlag::Seen),
            _ => None,
        }
    }

    /// 固定顺序，保证同一个标志集合生成的文件名稳定（测试与缓存都依赖它）。
    const ORDER: [SystemFlag; 5] = [
        SystemFlag::Draft,
        SystemFlag::Flagged,
        SystemFlag::Answered,
        SystemFlag::Seen,
        SystemFlag::Deleted,
    ];

    pub const ALL: [SystemFlag; 5] = [
        SystemFlag::Answered,
        SystemFlag::Flagged,
        SystemFlag::Deleted,
        SystemFlag::Seen,
        SystemFlag::Draft,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    System(SystemFlag),
    Keyword(String),
}

impl Flag {
    pub fn imap_name(&self) -> String {
        match self {
            Flag::System(system) => system.imap_name().to_string(),
            Flag::Keyword(keyword) => keyword.clone(),
        }
    }

    /// 解析 IMAP 标志 token。`\Recent` 不可设置，返回 `None`；未知的 `\Xxx`
    /// 视为非法（由调用方回 `BAD`），关键字则归一化为小写。
    pub fn parse_imap(token: &str) -> Option<Self> {
        if let Some(system) = SystemFlag::from_imap(token) {
            return Some(Flag::System(system));
        }
        if token.starts_with('\\') {
            return None;
        }
        validate_keyword(token).ok()?;
        Some(Flag::Keyword(token.to_ascii_lowercase()))
    }

    pub fn is_seen(&self) -> bool {
        matches!(self, Flag::System(SystemFlag::Seen))
    }

    pub fn is_deleted(&self) -> bool {
        matches!(self, Flag::System(SystemFlag::Deleted))
    }
}

pub type FlagSet = BTreeSet<Flag>;

/// IMAP 关键字的字符集：可见 ASCII，排除 IMAP 语法特殊字符。
fn validate_keyword(keyword: &str) -> Result<()> {
    if keyword.is_empty() || keyword.len() > 64 {
        return Err(MailError::invalid("keyword must be 1-64 characters"));
    }
    let valid = keyword.bytes().all(|byte| {
        byte.is_ascii_graphic()
            && !matches!(byte, b'(' | b')' | b'{' | b'}' | b'%' | b'*' | b'"' | b'\\')
    });
    if !valid {
        return Err(MailError::invalid("keyword contains invalid characters"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 数据模型
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MessageMeta {
    pub uid: u32,
    /// Maildir unique 部分（`:2,` 之前）。UID 映射的键。
    pub base: String,
    /// 当前文件名（可能带 `:2,<flags>`）。
    pub filename: String,
    pub path: PathBuf,
    pub size: u64,
    /// Unix 秒（文件 mtime；APPEND 可显式指定）。
    pub internal_date: i64,
    /// CONDSTORE 修改序列。每次标志变化都会递增并持久化到 uidlist。
    pub modseq: u64,
    pub flags: FlagSet,
    /// 本次 SELECT 之前位于 `new/` 的邮件。RECENT 语义只对「第一次打开」成立。
    pub recent: bool,
}

/// 一封待投递的邮件（MULTIAPPEND 与 LMTP 共用）。
#[derive(Debug, Clone)]
pub struct NewMessage {
    pub data: Vec<u8>,
    pub flags: FlagSet,
    pub internal_date: Option<i64>,
}

/// 用户级配额（覆盖整个 MailStore 的所有文件夹）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaLimits {
    pub messages: Option<u32>,
    /// 字节数（IMAP 侧显示为 KiB）。
    pub storage_bytes: Option<u64>,
}

impl QuotaLimits {
    pub fn is_unlimited(&self) -> bool {
        self.messages.is_none() && self.storage_bytes.is_none()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaStatus {
    pub limits: QuotaLimits,
    pub messages: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub messages: u32,
    pub recent: u32,
    pub unseen: u32,
    pub uidnext: u32,
    pub uidvalidity: u32,
}

/// `cur/` 与 `new/` 目录 mtime 的轻量指纹。
///
/// Maildir 的增删、改名（`STORE` 改标志）都会更新目录 mtime，因此指纹不变时
/// 可以跳过整次目录扫描。会话层每 N 次仍强制全量扫描一次，防止粗粒度时间戳
/// 或异常文件系统漏掉变化。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderStamp {
    pub cur: (i64, u32),
    pub new: (i64, u32),
}

#[derive(Debug, Clone)]
pub struct FolderState {
    pub name: String,
    pub uidvalidity: u32,
    pub uidnext: u32,
    /// CONDSTORE 的 HIGHESTMODSEQ。
    pub highest_modseq: u64,
    pub messages: Vec<MessageMeta>,
}

impl FolderState {
    pub fn status(&self) -> Status {
        Status {
            messages: self.messages.len() as u32,
            recent: self
                .messages
                .iter()
                .filter(|message| message.recent)
                .count() as u32,
            unseen: self
                .messages
                .iter()
                .filter(|message| !message.flags.iter().any(Flag::is_seen))
                .count() as u32,
            uidnext: self.uidnext,
            uidvalidity: self.uidvalidity,
        }
    }

    /// `*` 在 UID 语义下的值。
    pub fn max_uid(&self) -> u32 {
        self.messages.last().map(|message| message.uid).unwrap_or(0)
    }

    pub fn max_seq(&self) -> u32 {
        self.messages.len() as u32
    }

    pub fn position_of_uid(&self, uid: u32) -> Option<usize> {
        self.messages.iter().position(|message| message.uid == uid)
    }
}

// ---------------------------------------------------------------------------
// 文件夹名
// ---------------------------------------------------------------------------

pub fn is_inbox(name: &str) -> bool {
    name.eq_ignore_ascii_case(INBOX)
}

/// 侧车文件的保留前缀：磁盘路径是 `.{name}`，`mailstack-…` 会与
/// `.mailstack-uidlist` 等私有文件撞名（大小写不敏感地拒绝，兼容大小写
/// 不敏感的文件系统）。
const RESERVED_FOLDER_PREFIX: &str = "mailstack-";

/// 规范化并校验邮箱名。
///
/// 允许层级（`.` 分隔），但拒绝：空段、前导/尾随点、控制字符、路径分隔符、
/// Windows 保留字符、LIST 通配符 `*`/`%`（允许它们会让 LIST 模式产生歧义）、
/// 以及保留前缀 `mailstack-`。
pub fn normalize_folder_name(name: &str) -> Result<String> {
    if is_inbox(name) {
        return Ok(INBOX.to_string());
    }
    if name.is_empty() {
        return Err(MailError::invalid("mailbox name is empty"));
    }
    if name.len() > MAX_FOLDER_NAME {
        return Err(MailError::invalid("mailbox name is too long"));
    }
    if name
        .get(..RESERVED_FOLDER_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(RESERVED_FOLDER_PREFIX))
    {
        return Err(MailError::invalid("mailbox name is reserved"));
    }
    if name.starts_with(DELIMITER) || name.ends_with(DELIMITER) {
        return Err(MailError::invalid(
            "mailbox name may not start or end with the hierarchy delimiter",
        ));
    }
    for segment in name.split(DELIMITER) {
        if segment.is_empty() {
            return Err(MailError::invalid("mailbox name has an empty segment"));
        }
        if segment.starts_with('.') {
            // 磁盘布局用前导 `.` 表示文件夹；允许这一前缀会造成映射歧义。
            return Err(MailError::invalid(
                "mailbox name segment may not start with '.'",
            ));
        }
    }
    let invalid = name.chars().any(|ch| {
        ch.is_control()
            || matches!(
                ch,
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '%'
            )
    });
    if invalid {
        return Err(MailError::invalid(
            "mailbox name contains invalid characters",
        ));
    }
    Ok(name.to_string())
}

// ---------------------------------------------------------------------------
// MailStore
// ---------------------------------------------------------------------------

pub struct MailStore {
    root: PathBuf,
    clock: Arc<dyn Clock>,
}

impl MailStore {
    /// 打开（必要时初始化）INBOX 目录树。
    pub fn new(root: impl Into<PathBuf>, clock: Arc<dyn Clock>) -> Result<Self> {
        let root = root.into();
        ensure_maildir_dirs(&root)?;
        Ok(Self { root, clock })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub(crate) fn folder_path(&self, name: &str) -> Result<PathBuf> {
        let normalized = normalize_folder_name(name)?;
        if normalized == INBOX {
            Ok(self.root.clone())
        } else {
            Ok(self.root.join(format!(".{normalized}")))
        }
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        let path = self.folder_path(name)?;
        Ok(path.is_dir())
    }

    pub fn create(&self, name: &str) -> Result<()> {
        let normalized = normalize_folder_name(name)?;
        if normalized == INBOX {
            return Err(MailError::already_exists(INBOX));
        }
        let path = self.folder_path(&normalized)?;
        if path.exists() {
            return Err(MailError::already_exists(normalized));
        }
        ensure_maildir_dirs(&path)?;
        Ok(())
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let normalized = normalize_folder_name(name)?;
        if normalized == INBOX {
            return Err(MailError::invalid("INBOX cannot be deleted"));
        }
        let path = self.folder_path(&normalized)?;
        if !path.is_dir() {
            return Err(MailError::not_found(normalized));
        }
        let children = self
            .folders()?
            .into_iter()
            .any(|folder| folder.starts_with(&format!("{normalized}.")));
        if children {
            return Err(MailError::invalid(format!(
                "mailbox {normalized} has children and cannot be deleted"
            )));
        }
        // RFC 3501 §6.3.4：删除邮箱会连同其中的邮件一起删除。拒绝非空邮箱会让
        // 客户端（Thunderbird 等）无法删除任何有邮件的文件夹 —— 那才是 bug。
        let mut removed_messages = 0u64;
        let mut removed_bytes = 0u64;
        scan_usage_dir(&path, &mut removed_messages, &mut removed_bytes)?;
        fs::remove_dir_all(&path).map_err(|error| MailError::io(&path, error))?;
        let _ = self.unsubscribe(&normalized);
        self.release_quota(Some((removed_messages, removed_bytes)));
        Ok(())
    }

    pub fn rename(&self, old: &str, new: &str) -> Result<()> {
        let old = normalize_folder_name(old)?;
        let new = normalize_folder_name(new)?;
        if old == new {
            return Err(MailError::invalid("source and destination are the same"));
        }
        if !self.exists(&old)? {
            return Err(MailError::not_found(old));
        }
        if self.exists(&new)? {
            return Err(MailError::already_exists(new));
        }
        let folders = self.folders()?;

        if old == INBOX {
            // RFC 3501 §6.3.5：重命名 INBOX 是「把内容搬到新邮箱」，INBOX 本身保留。
            let destination = self.folder_path(&new)?;
            ensure_maildir_dirs(&destination)?;
            for sub in ["cur", "new"] {
                move_directory_contents(&self.root.join(sub), &destination.join(sub))?;
            }
            for meta in [UIDLIST, KEYWORDS, EXPUNGED] {
                let source = self.root.join(meta);
                if source.exists() {
                    let target = destination.join(meta);
                    fs::rename(&source, &target).map_err(|error| MailError::io(&target, error))?;
                }
            }
            self.subscribe(&new)?;
            return Ok(());
        }

        let source = self.folder_path(&old)?;
        let destination = self.folder_path(&new)?;
        fs::rename(&source, &destination).map_err(|error| MailError::io(&destination, error))?;

        // 子文件夹在磁盘上是独立目录（`.Old.Child`），必须逐个改名。
        let prefix = format!("{old}.");
        let mut renames: Vec<(String, String)> = folders
            .iter()
            .filter(|folder| folder.starts_with(&prefix))
            .map(|folder| {
                let suffix = &folder[old.len()..];
                (folder.clone(), format!("{new}{suffix}"))
            })
            .collect();
        renames.sort();
        // 已完成的改名（现路径, 原路径）：中途失败时按逆序 rename 回去，
        // 否则一个冲突的子文件夹会让 rename 半途而废、邮箱树自相矛盾。
        let mut completed: Vec<(PathBuf, PathBuf)> = vec![(destination, source)];
        for (from, to) in renames {
            let from_path = self.folder_path(&from)?;
            let to_path = self.folder_path(&to)?;
            if to_path.exists() {
                rollback_renames(&completed);
                return Err(MailError::already_exists(to));
            }
            if let Err(error) = fs::rename(&from_path, &to_path) {
                rollback_renames(&completed);
                return Err(MailError::io(&to_path, error));
            }
            completed.push((to_path, from_path));
            self.rewrite_subscription(&from, &to)?;
        }
        self.rewrite_subscription(&old, &new)?;
        Ok(())
    }

    pub fn has_children(&self, name: &str) -> Result<bool> {
        let prefix = format!("{name}.");
        Ok(self
            .folders()?
            .iter()
            .any(|folder| folder.starts_with(&prefix)))
    }

    pub fn folders(&self) -> Result<Vec<String>> {
        let mut names = BTreeSet::new();
        names.insert(INBOX.to_string());
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(vec![INBOX.to_string()])
            }
            Err(error) => return Err(MailError::io(&self.root, error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| MailError::io(&self.root, error))?;
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            let raw = entry.file_name();
            let Some(raw) = raw.to_str() else { continue };
            let Some(name) = raw.strip_prefix('.') else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if normalize_folder_name(name).is_ok() {
                names.insert(name.to_string());
            }
        }
        Ok(names.into_iter().collect())
    }

    pub fn subscribe(&self, name: &str) -> Result<()> {
        let normalized = normalize_folder_name(name)?;
        let path = self.root.join(SUBSCRIPTIONS);
        with_lock(&self.root.join(SUBSCRIPTIONS_LOCK), || {
            let mut list = read_lines_set(&path);
            if list.insert(normalized.clone()) {
                write_lines_sorted(&path, &list)?;
            }
            Ok(())
        })
    }

    pub fn unsubscribe(&self, name: &str) -> Result<()> {
        let normalized = normalize_folder_name(name)?;
        let path = self.root.join(SUBSCRIPTIONS);
        with_lock(&self.root.join(SUBSCRIPTIONS_LOCK), || {
            let mut list = read_lines_set(&path);
            if list.remove(&normalized) {
                write_lines_sorted(&path, &list)?;
            }
            Ok(())
        })
    }

    pub fn subscriptions(&self) -> Result<Vec<String>> {
        Ok(read_lines_set(&self.root.join(SUBSCRIPTIONS))
            .into_iter()
            .collect())
    }

    fn rewrite_subscription(&self, from: &str, to: &str) -> Result<()> {
        let path = self.root.join(SUBSCRIPTIONS);
        with_lock(&self.root.join(SUBSCRIPTIONS_LOCK), || {
            let mut list = read_lines_set(&path);
            if list.remove(from) {
                list.insert(to.to_string());
                write_lines_sorted(&path, &list)?;
            }
            Ok(())
        })
    }

    /// 打开文件夹：索引文件、同步 UID、可选地把 `new/` 搬进 `cur/`。
    ///
    /// `promote_recent` 只在 SELECT 时为 `true`：STATUS 与 POP3 的快照不应改变
    /// 「这封邮件还是不是 Recent」的判定。
    pub fn open_folder(&self, name: &str, promote_recent: bool) -> Result<FolderState> {
        let normalized = normalize_folder_name(name)?;
        let path = self.folder_path(&normalized)?;
        if !path.is_dir() {
            return Err(MailError::not_found(normalized));
        }
        ensure_maildir_dirs(&path)?;

        let keywords = read_keywords(&path);
        let mut scanned = scan_folder(&path, &keywords)?;
        if scanned.len() > MAX_SCAN_ENTRIES {
            return Err(MailError::storage(format!(
                "mailbox has more than {MAX_SCAN_ENTRIES} messages"
            )));
        }

        let bases: BTreeSet<String> = scanned.keys().cloned().collect();
        let mapping = sync_uidlist(&path, &bases, self.clock.as_ref())?;

        if promote_recent {
            let recent_bases: Vec<String> = scanned
                .iter()
                .filter(|(_, file)| file.recent)
                .map(|(base, _)| base.clone())
                .collect();
            // 提升同样要持 uidlist 锁：EXPUNGE 在锁内先按 base 找文件再删除，
            // 两者交错会让「文件刚改名、删除落空、映射却被移除」，同一封邮件
            // 随后会在 UIDVALIDITY 不变的情况下拿到新 UID。
            with_lock(&path.join(UIDLIST_LOCK), || {
                for base in recent_bases {
                    if let Some(file) = scanned.get_mut(&base) {
                        let suffix = flags_suffix(&file.flags, &keywords);
                        let target = path.join("cur").join(format!("{}:2,{}", base, suffix));
                        let source = path.join("new").join(&file.filename);
                        match fs::rename(&source, &target) {
                            Ok(()) => {
                                file.directory = "cur";
                                file.filename = target
                                    .file_name()
                                    .map(|name| name.to_string_lossy().to_string())
                                    .unwrap_or_default();
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                // 另一个会话刚刚搬过它；本次打开跳过这封邮件即可。
                                file.filename = target
                                    .file_name()
                                    .map(|name| name.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                file.directory = "cur";
                            }
                            Err(error) => return Err(MailError::io(&target, error)),
                        }
                    }
                }
                Ok(())
            })?;
        }

        let mut messages = Vec::with_capacity(scanned.len());
        for (base, file) in scanned {
            let Some((uid, modseq)) = mapping.by_base.get(&base).copied() else {
                // 映射刚同步过，缺失说明这封邮件在同步与 stat 之间被删除。
                continue;
            };
            let full_path = path.join(file.directory).join(&file.filename);
            let metadata = match fs::metadata(&full_path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(MailError::io(&full_path, error)),
            };
            let internal_date = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or(0);
            messages.push(MessageMeta {
                uid,
                base,
                filename: file.filename,
                path: full_path,
                size: metadata.len(),
                internal_date,
                modseq,
                flags: file.flags,
                recent: file.recent,
            });
        }
        messages.sort_by_key(|message| message.uid);

        Ok(FolderState {
            name: normalized,
            uidvalidity: mapping.uidvalidity,
            uidnext: mapping.uidnext,
            highest_modseq: mapping.highest_modseq,
            messages,
        })
    }

    pub fn status(&self, name: &str) -> Result<Status> {
        Ok(self.open_folder(name, false)?.status())
    }

    /// 目录 mtime 指纹（不做目录扫描）。用于 NOOP/IDLE 的快速路径。
    pub fn folder_stamp(&self, name: &str) -> Result<FolderStamp> {
        let path = self.folder_path(name)?;
        let stamp = |directory: &str| -> (i64, u32) {
            fs::metadata(path.join(directory))
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|elapsed| (elapsed.as_secs() as i64, elapsed.subsec_nanos()))
                .unwrap_or((0, 0))
        };
        Ok(FolderStamp {
            cur: stamp("cur"),
            new: stamp("new"),
        })
    }

    /// 读取特殊用途（RFC 6154）。文件存在时以其为准（空文件表示刻意清空），
    /// 否则按标准文件夹名推导默认值。
    pub fn special_use(&self, name: &str) -> Result<Vec<String>> {
        let normalized = normalize_folder_name(name)?;
        let path = self.folder_path(&normalized)?;
        if !path.is_dir() {
            return Err(MailError::not_found(normalized));
        }
        match fs::read_to_string(path.join(SPECIAL_USE)) {
            Ok(contents) => {
                let mut uses: BTreeSet<String> = BTreeSet::new();
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Some(attribute) = canonical_special_use(line) {
                        uses.insert(attribute.to_string());
                    }
                }
                Ok(uses.into_iter().collect())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(default_special_use(&normalized)
                    .map(|attribute| vec![attribute.to_string()])
                    .unwrap_or_default())
            }
            Err(error) => Err(MailError::io(path.join(SPECIAL_USE), error)),
        }
    }

    /// 写入特殊用途（空列表写空文件，用于压掉默认推导）。
    pub fn set_special_use(&self, name: &str, uses: &[String]) -> Result<()> {
        let normalized = normalize_folder_name(name)?;
        let path = self.folder_path(&normalized)?;
        if !path.is_dir() {
            return Err(MailError::not_found(normalized));
        }
        let mut canonical: BTreeSet<&'static str> = BTreeSet::new();
        for value in uses {
            let attribute = canonical_special_use(value).ok_or_else(|| {
                MailError::invalid(format!("unknown special-use attribute: {value}"))
            })?;
            canonical.insert(attribute);
        }
        let mut buffer = String::new();
        for attribute in canonical {
            buffer.push_str(attribute);
            buffer.push('\n');
        }
        write_atomic(&path.join(SPECIAL_USE), buffer.as_bytes())
    }

    /// 所有非空特殊用途邮箱（LIST 一次读取，避免逐名字开文件）。
    pub fn special_use_map(&self) -> Result<BTreeMap<String, Vec<String>>> {
        let mut map = BTreeMap::new();
        for name in self.folders()? {
            let uses = self.special_use(&name)?;
            if !uses.is_empty() {
                map.insert(name, uses);
            }
        }
        Ok(map)
    }

    /// 读取配额上限（文件不存在 = 无限制）。
    pub fn quota_limits(&self) -> Result<QuotaLimits> {
        let path = self.root.join(QUOTA);
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(QuotaLimits::default())
            }
            Err(error) => return Err(MailError::io(&path, error)),
        };
        let mut limits = QuotaLimits::default();
        for line in contents.lines() {
            let Some((key, value)) = line.trim().split_once(' ') else {
                continue;
            };
            match key {
                "messages" => {
                    let value: u32 = value
                        .parse()
                        .map_err(|_| MailError::storage("invalid quota file"))?;
                    limits.messages = (value > 0).then_some(value);
                }
                "storage" => {
                    let value: u64 = value
                        .parse()
                        .map_err(|_| MailError::storage("invalid quota file"))?;
                    limits.storage_bytes = (value > 0).then_some(value);
                }
                _ => {}
            }
        }
        Ok(limits)
    }

    /// 设置配额。两者都为 `None` 时删除配额文件（无限制）。
    pub fn set_quota(&self, messages: Option<u32>, storage_bytes: Option<u64>) -> Result<()> {
        with_lock(&self.root.join(QUOTA_LOCK), || {
            // 用量缓存可能是在「无配额」期间产生的（那时投递不更新它），
            // 设置配额后必须作废，下一次投递会重新扫描。
            let _ = fs::remove_file(self.root.join(USAGE));
            let path = self.root.join(QUOTA);
            if messages.is_none() && storage_bytes.is_none() {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(MailError::io(&path, error)),
                }
                return Ok(());
            }
            let mut buffer = String::new();
            if let Some(messages) = messages {
                buffer.push_str(&format!("messages {messages}\n"));
            }
            if let Some(storage) = storage_bytes {
                buffer.push_str(&format!("storage {storage}\n"));
            }
            write_atomic(&path, buffer.as_bytes())
        })
    }

    pub fn quota_status(&self) -> Result<QuotaStatus> {
        let limits = self.quota_limits()?;
        let (messages, bytes) = self.cached_or_recompute_usage()?;
        Ok(QuotaStatus {
            limits,
            messages,
            bytes,
        })
    }

    /// 重新扫描所有文件夹并刷新用量缓存（迁移或缓存丢失后调用）。
    pub fn recompute_usage(&self) -> Result<(u64, u64)> {
        let usage = self.scan_usage()?;
        self.write_usage(usage)?;
        Ok(usage)
    }

    fn scan_usage(&self) -> Result<(u64, u64)> {
        let mut messages = 0u64;
        let mut bytes = 0u64;
        scan_usage_dir(&self.root, &mut messages, &mut bytes)?;
        for folder in self.folders()? {
            if folder == INBOX {
                continue;
            }
            let path = self.folder_path(&folder)?;
            scan_usage_dir(&path, &mut messages, &mut bytes)?;
        }
        Ok((messages, bytes))
    }

    fn load_usage(&self) -> Result<Option<(u64, u64)>> {
        let path = self.root.join(USAGE);
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(MailError::io(&path, error)),
        };
        let mut messages = None;
        let mut bytes = None;
        for line in contents.lines() {
            let Some((key, value)) = line.trim().split_once(' ') else {
                continue;
            };
            match key {
                "messages" => messages = value.parse().ok(),
                "bytes" => bytes = value.parse().ok(),
                _ => {}
            }
        }
        Ok(match (messages, bytes) {
            (Some(messages), Some(bytes)) => Some((messages, bytes)),
            _ => None,
        })
    }

    fn write_usage(&self, (messages, bytes): (u64, u64)) -> Result<()> {
        write_atomic(
            &self.root.join(USAGE),
            format!("messages {messages}\nbytes {bytes}\n").as_bytes(),
        )
    }

    fn cached_or_recompute_usage(&self) -> Result<(u64, u64)> {
        match self.load_usage()? {
            Some(usage) => Ok(usage),
            None => self.recompute_usage(),
        }
    }

    /// 预留配额（投递前调用）。无配额时返回 `None`，不维护用量缓存。
    fn reserve_quota(&self, messages: u64, bytes: u64) -> Result<Option<(u64, u64)>> {
        let limits = self.quota_limits()?;
        if limits.is_unlimited() {
            return Ok(None);
        }
        with_lock(&self.root.join(QUOTA_LOCK), || {
            let (mut used_messages, mut used_bytes) = self.cached_or_recompute_usage()?;
            if let Some(max) = limits.messages {
                if used_messages.saturating_add(messages) > u64::from(max) {
                    return Err(MailError::QuotaExceeded(format!(
                        "message quota exceeded ({}/{max})",
                        used_messages.saturating_add(messages)
                    )));
                }
            }
            if let Some(max) = limits.storage_bytes {
                if used_bytes.saturating_add(bytes) > max {
                    return Err(MailError::QuotaExceeded(format!(
                        "storage quota exceeded ({} bytes)",
                        used_bytes.saturating_add(bytes)
                    )));
                }
            }
            used_messages = used_messages.saturating_add(messages);
            used_bytes = used_bytes.saturating_add(bytes);
            self.write_usage((used_messages, used_bytes))?;
            Ok(Some((messages, bytes)))
        })
    }

    fn release_quota(&self, reservation: Option<(u64, u64)>) {
        let Some((messages, bytes)) = reservation else {
            return;
        };
        if !self.root.join(QUOTA).exists() {
            return;
        }
        let result = with_lock(&self.root.join(QUOTA_LOCK), || {
            let (mut used_messages, mut used_bytes) = self.cached_or_recompute_usage()?;
            used_messages = used_messages.saturating_sub(messages);
            used_bytes = used_bytes.saturating_sub(bytes);
            self.write_usage((used_messages, used_bytes))
        });
        if let Err(error) = result {
            tracing::warn!(%error, "failed to release quota reservation");
        }
    }

    /// 投递一封邮件。返回 `(uidvalidity, uid)`。
    pub fn append(
        &self,
        folder: &str,
        data: &[u8],
        flags: &FlagSet,
        internal_date: Option<i64>,
    ) -> Result<(u32, u32)> {
        // APPEND 未指定任何标志时，邮件是 Recent（RFC 3501 §6.3.11）。
        let recent = flags.is_empty();
        self.append_internal(folder, data, flags, internal_date, recent)
    }

    fn append_internal(
        &self,
        folder: &str,
        data: &[u8],
        flags: &FlagSet,
        internal_date: Option<i64>,
        recent: bool,
    ) -> Result<(u32, u32)> {
        let path = self.folder_path(folder)?;
        if !path.is_dir() {
            return Err(MailError::not_found(folder));
        }
        ensure_maildir_dirs(&path)?;
        let reservation = self.reserve_quota(1, data.len() as u64)?;
        let result = self.append_internal_reserved(&path, data, flags, internal_date, recent);
        if result.is_err() {
            self.release_quota(reservation);
        }
        result
    }

    fn append_internal_reserved(
        &self,
        path: &Path,
        data: &[u8],
        flags: &FlagSet,
        internal_date: Option<i64>,
        recent: bool,
    ) -> Result<(u32, u32)> {
        let base = self.unique_base();
        // 关键字字母分配可能失败（>26 个关键字）；必须在写 tmp 之前完成，
        // 否则失败路径会在 tmp/ 里留下一个孤儿文件。
        let destination = if recent {
            path.join("new").join(&base)
        } else {
            let suffix = suffix_with_keyword_allocation(path, flags)?;
            path.join("cur").join(format!("{base}:2,{suffix}"))
        };

        let tmp = write_tmp_file(path, &base, data, internal_date)?;

        if let Err(error) = fs::rename(&tmp, &destination) {
            let _ = fs::remove_file(&tmp);
            return Err(MailError::io(&destination, error));
        }
        if let Some(parent) = destination.parent() {
            fsync_dir_best_effort(parent);
        }

        match assign_uid(path, &base, self.clock.as_ref()) {
            Ok(result) => Ok(result),
            Err(error) => {
                // 分配失败时撤回落盘，否则客户端重试会产生重复邮件。
                let _ = fs::remove_file(&destination);
                Err(error)
            }
        }
    }

    /// 原子性尽量高的批量投递（MULTIAPPEND）。
    ///
    /// 步骤：全部先写 `tmp/`（fsync）→ 全部 rename 到 `cur|new` → 在**一次**
    /// uidlist 锁内分配 UID 并写映射。任一步失败都会回滚已落盘的文件，因此
    /// 「客户端收到 NO」时不留下部分消息（进程崩溃落在 rename 中间是例外：
    /// 文件已落盘但未入映射，下次打开会补分配 UID）。
    pub fn append_many(&self, folder: &str, messages: &[NewMessage]) -> Result<(u32, Vec<u32>)> {
        if messages.is_empty() {
            return Err(MailError::invalid("no messages to append"));
        }
        let path = self.folder_path(folder)?;
        if !path.is_dir() {
            return Err(MailError::not_found(folder));
        }
        ensure_maildir_dirs(&path)?;
        let total_bytes: u64 = messages
            .iter()
            .map(|message| message.data.len() as u64)
            .sum();
        let reservation = self.reserve_quota(messages.len() as u64, total_bytes)?;
        let result = self.append_many_reserved(&path, messages);
        if result.is_err() {
            self.release_quota(reservation);
        }
        result
    }

    fn append_many_reserved(
        &self,
        path: &Path,
        messages: &[NewMessage],
    ) -> Result<(u32, Vec<u32>)> {
        struct Staged {
            tmp: PathBuf,
            destination: PathBuf,
            base: String,
        }
        let mut staged: Vec<Staged> = Vec::with_capacity(messages.len());
        let staging: Result<()> = (|| {
            for message in messages {
                let base = self.unique_base();
                let destination = if message.flags.is_empty() {
                    path.join("new").join(&base)
                } else {
                    let suffix = suffix_with_keyword_allocation(path, &message.flags)?;
                    path.join("cur").join(format!("{base}:2,{suffix}"))
                };
                let tmp = write_tmp_file(path, &base, &message.data, message.internal_date)?;
                staged.push(Staged {
                    tmp,
                    destination,
                    base,
                });
            }
            Ok(())
        })();
        if let Err(error) = staging {
            for stage in &staged {
                let _ = fs::remove_file(&stage.tmp);
            }
            return Err(error);
        }

        let mut renamed: Vec<PathBuf> = Vec::with_capacity(staged.len());
        for stage in &staged {
            if let Err(error) = fs::rename(&stage.tmp, &stage.destination) {
                for path in &renamed {
                    let _ = fs::remove_file(path);
                }
                for pending in &staged {
                    let _ = fs::remove_file(&pending.tmp);
                }
                return Err(MailError::io(&stage.destination, error));
            }
            renamed.push(stage.destination.clone());
        }

        let bases: Vec<String> = staged.iter().map(|stage| stage.base.clone()).collect();
        match assign_uids_many(path, &bases, self.clock.as_ref()) {
            Ok((uidvalidity, uids)) => {
                for directory in ["cur", "new"] {
                    fsync_dir_best_effort(&path.join(directory));
                }
                Ok((uidvalidity, uids))
            }
            Err(error) => {
                for path in &renamed {
                    let _ = fs::remove_file(path);
                }
                Err(error)
            }
        }
    }

    /// 把同一封邮件投递到多个文件夹（Sieve 的多目标 `fileinto`）。
    ///
    /// 与 [`Self::append_many`] 相同的三段式（全部写 tmp → 全部 rename → 分配
    /// UID），但横跨多个文件夹：先校验**所有**目标、一次预留**所有**副本的配额，
    /// 任一步失败都回滚全部已落盘文件并释放配额 —— 多目标投递要么每个文件夹各
    /// 一份、要么一份都没有（进程崩溃落在 rename 中间是例外，未入映射的文件
    /// 下次打开会补分配 UID，与 append_many 一致）。
    ///
    /// 返回值与 `folders` 顺序对齐：每个文件夹的 `(uidvalidity, [uid])`。
    pub fn append_many_folders(
        &self,
        folders: &[&str],
        message: &NewMessage,
    ) -> Result<Vec<(u32, Vec<u32>)>> {
        if folders.is_empty() {
            return Err(MailError::invalid("no folders to deliver to"));
        }
        // 第一遍：解析并校验所有目标文件夹，不存在的在动第一份拷贝前就失败。
        let mut paths = Vec::with_capacity(folders.len());
        for folder in folders {
            let path = self.folder_path(folder)?;
            if !path.is_dir() {
                return Err(MailError::not_found(folder.to_string()));
            }
            ensure_maildir_dirs(&path)?;
            paths.push(path);
        }

        let total_bytes = message.data.len() as u64 * folders.len() as u64;
        let reservation = self.reserve_quota(folders.len() as u64, total_bytes)?;

        struct Staged {
            tmp: PathBuf,
            destination: PathBuf,
            base: String,
        }
        let mut staged: Vec<Staged> = Vec::with_capacity(folders.len());
        let staging: Result<()> = (|| {
            for path in &paths {
                let base = self.unique_base();
                let destination = if message.flags.is_empty() {
                    path.join("new").join(&base)
                } else {
                    let suffix = suffix_with_keyword_allocation(path, &message.flags)?;
                    path.join("cur").join(format!("{base}:2,{suffix}"))
                };
                let tmp = write_tmp_file(path, &base, &message.data, message.internal_date)?;
                staged.push(Staged {
                    tmp,
                    destination,
                    base,
                });
            }
            Ok(())
        })();
        if let Err(error) = staging {
            for stage in &staged {
                let _ = fs::remove_file(&stage.tmp);
            }
            self.release_quota(reservation);
            return Err(error);
        }

        let mut renamed: Vec<PathBuf> = Vec::with_capacity(staged.len());
        for stage in &staged {
            if let Err(error) = fs::rename(&stage.tmp, &stage.destination) {
                for path in &renamed {
                    let _ = fs::remove_file(path);
                }
                for pending in &staged {
                    let _ = fs::remove_file(&pending.tmp);
                }
                self.release_quota(reservation);
                return Err(MailError::io(&stage.destination, error));
            }
            renamed.push(stage.destination.clone());
        }

        // 逐文件夹分配 UID（各持各的 uidlist 锁）。失败时撤掉所有已落盘文件：
        // 已分配的映射条目由下次 open 的同步清理（文件已不在）。
        let mut results = Vec::with_capacity(paths.len());
        let assign: Result<()> = (|| {
            for (index, path) in paths.iter().enumerate() {
                let bases = vec![staged[index].base.clone()];
                let (uidvalidity, uids) = assign_uids_many(path, &bases, self.clock.as_ref())?;
                results.push((uidvalidity, uids));
            }
            Ok(())
        })();
        if let Err(error) = assign {
            for path in &renamed {
                let _ = fs::remove_file(path);
            }
            self.release_quota(reservation);
            return Err(error);
        }
        for path in &paths {
            for directory in ["cur", "new"] {
                fsync_dir_best_effort(&path.join(directory));
            }
        }
        Ok(results)
    }

    /// 更新标志。返回更新后的元数据（会话用它刷新 EXISTS/FETCH 缓存）。
    pub fn set_flags(&self, folder: &str, uid: u32, flags: &FlagSet) -> Result<MessageMeta> {
        let path = self.folder_path(folder)?;
        if !path.is_dir() {
            return Err(MailError::not_found(folder));
        }
        // 改名必须与 EXPUNGE 互斥：EXPUNGE 在 uidlist 锁内「查文件 → 删文件」，
        // 若这里在锁外改名，删除会落空而映射已被移除（邮件以新 UID 复活）。
        with_lock(&path.join(UIDLIST_LOCK), || {
            let uidlist_path = path.join(UIDLIST);
            let mut list = load_uidlist(&uidlist_path)?
                .ok_or_else(|| MailError::storage("uidlist is unavailable; reopen the mailbox"))?;
            let Some((base, _)) = list.by_uid.get(&uid).cloned() else {
                return Err(MailError::not_found(format!("uid {uid}")));
            };
            let (directory, suffixed) = find_file(&path, &base)?
                .ok_or_else(|| MailError::not_found(format!("uid {uid}")))?;
            let suffix = suffix_with_keyword_allocation(&path, flags)?;
            let target_name = format!("{base}:2,{suffix}");
            let target = path.join("cur").join(&target_name);

            if directory != "cur" || suffixed != target_name {
                let source = path.join(directory).join(&suffixed);
                fs::rename(&source, &target).map_err(|error| MailError::io(&target, error))?;
            }

            // CONDSTORE：每次标志变化分配新的 modseq，并与映射一起落盘。
            list.highest_modseq = list.highest_modseq.saturating_add(1);
            let modseq = list.highest_modseq;
            if let Some(entry) = list.by_uid.get_mut(&uid) {
                entry.1 = modseq;
            }
            write_uidlist(&uidlist_path, &list)?;

            let metadata = fs::metadata(&target).map_err(|error| MailError::io(&target, error))?;
            let internal_date = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or(0);
            Ok(MessageMeta {
                uid,
                base,
                filename: target_name,
                path: target,
                size: metadata.len(),
                internal_date,
                modseq,
                flags: flags.clone(),
                recent: false,
            })
        })
    }

    /// 物理删除给定 UID。返回实际删除的邮件数。
    pub fn expunge(&self, folder: &str, uids: &[u32]) -> Result<usize> {
        let path = self.folder_path(folder)?;
        if !path.is_dir() {
            return Err(MailError::not_found(folder));
        }
        with_lock(&path.join(UIDLIST_LOCK), || {
            let mut list = load_uidlist(&path.join(UIDLIST))?.unwrap_or_default();
            // 先删文件、全部成功后再删映射：删文件失败时直接返回，磁盘上的
            // 映射保持原样（UID 语义不被破坏）。已成功删除但尚未写回映射的
            // 条目会在下次 open 的同步中被清理。
            let mut removed_uids: Vec<u32> = Vec::new();
            let mut removed_bytes = 0u64;
            for uid in uids {
                let Some((base, _)) = list.by_uid.get(uid) else {
                    continue;
                };
                // 文件早已不在（外部删除 / 上次 expunge 已删但映射未及写回）：
                // 用量统计里本就没有这封邮件，若仍计入 removed_uids，配额会按
                // 「删掉一封」递减 ⇒ usage 永久偏低。映射条目留给下次 open 的
                // 同步清理（sync_uidlist 只保留磁盘上存在的 base）。
                let Some((directory, filename)) = find_file(&path, base)? else {
                    continue;
                };
                let file = path.join(directory).join(&filename);
                // 只为真实存在的文件计字节：stat 在 remove 之前。
                if let Ok(metadata) = fs::metadata(&file) {
                    removed_bytes = removed_bytes.saturating_add(metadata.len());
                }
                match fs::remove_file(&file) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(MailError::io(&file, error)),
                }
                removed_uids.push(*uid);
            }
            for uid in &removed_uids {
                list.by_uid.remove(uid);
            }
            if !removed_uids.is_empty() {
                // QRESYNC：每个消失事件推进 modseq 并写入消失日志。
                let mut events = Vec::with_capacity(removed_uids.len());
                for uid in &removed_uids {
                    list.highest_modseq = list.highest_modseq.saturating_add(1);
                    events.push((*uid, list.highest_modseq));
                }
                append_expunged(&path, &events)?;
                write_uidlist(&path.join(UIDLIST), &list)?;
                self.release_quota(Some((removed_uids.len() as u64, removed_bytes)));
            }
            Ok(removed_uids.len())
        })
    }

    /// 复制多封邮件到另一文件夹。一次打开源邮箱、一次读取索引，避免
    /// 「每复制一封就全量扫描一遍源文件夹」的 O(k·n)。
    ///
    /// 全部源 UID 先经一次读取校验存在，再动第一份拷贝：否则第 k 个 UID 不存在
    /// 时前 k-1 份已落盘，客户端收到 NO 却留下成堆副本。校验之后源邮件仍可能
    /// 被并发删除（竞态不可避免）：此时报告错误并保留已完成的副本。
    pub fn copy_many(&self, from: &str, uids: &[u32], to: &str) -> Result<(u32, Vec<u32>)> {
        if uids.is_empty() {
            return Ok((0, Vec::new()));
        }
        let state = self.open_folder(from, false)?;
        let by_uid: HashMap<u32, &MessageMeta> = state
            .messages
            .iter()
            .map(|message| (message.uid, message))
            .collect();
        let sources: Vec<&MessageMeta> = uids
            .iter()
            .map(|uid| {
                by_uid
                    .get(uid)
                    .copied()
                    .ok_or_else(|| MailError::not_found(format!("uid {uid}")))
            })
            .collect::<Result<_>>()?;
        let mut uidvalidity = 0;
        let mut copies = Vec::with_capacity(sources.len());
        for message in sources {
            let data = self.read(message)?;
            let (validity, new_uid) = self.append_internal(
                to,
                &data,
                &message.flags,
                Some(message.internal_date),
                false,
            )?;
            uidvalidity = validity;
            copies.push(new_uid);
        }
        Ok((uidvalidity, copies))
    }

    /// QRESYNC：返回在 `since` 之后消失的 UID。
    pub fn expunged_since(&self, name: &str, since: u64) -> Result<Vec<u32>> {
        let path = self.folder_path(name)?;
        if !path.is_dir() {
            return Err(MailError::not_found(name));
        }
        let contents = match fs::read_to_string(path.join(EXPUNGED)) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(MailError::io(path.join(EXPUNGED), error)),
        };
        let mut uids = BTreeSet::new();
        for line in contents.lines() {
            let mut fields = line.split_whitespace();
            let Some(uid) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
                continue;
            };
            let Some(modseq) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            if uid > 0 && modseq > since {
                uids.insert(uid);
            }
        }
        Ok(uids.into_iter().collect())
    }

    /// 复制一封邮件到另一文件夹，保留标志与内部日期。副本不是 Recent。
    pub fn copy(&self, from: &str, uid: u32, to: &str) -> Result<(u32, u32)> {
        let (uidvalidity, copies) = self.copy_many(from, &[uid], to)?;
        let new_uid = copies
            .into_iter()
            .next()
            .ok_or_else(|| MailError::storage("copy produced no message"))?;
        Ok((uidvalidity, new_uid))
    }

    fn unique_base(&self) -> String {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let now = self.clock.now_secs().max(1);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos())
            .unwrap_or(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let host = hostname();
        format!("{now}.M{nanos}P{}Q{sequence}.{host}", std::process::id())
    }

    /// 只读打开邮件内容。调用方负责限制大小（`size` 已带在元数据里）。
    ///
    /// 路径可能在两处被并发改名（`new → cur` 提升、`STORE` 改标志）。若按旧
    /// 路径读不到，按 base 在当前目录里重查一次 —— 这比把一次正常的 FETCH
    /// 变成 `NO [SERVERBUG]` 更符合客户端的预期。
    pub fn read(&self, message: &MessageMeta) -> Result<Vec<u8>> {
        match fs::read(&message.path) {
            Ok(data) => Ok(data),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match self.locate_after_rename(message)? {
                    Some(path) => read_message(&path),
                    None => Err(MailError::io(&message.path, error)),
                }
            }
            Err(error) => Err(MailError::io(&message.path, error)),
        }
    }

    /// 只读邮件头前缀（用于 ENVELOPE / BODY[HEADER] 这类只需要头部的 FETCH）。
    pub fn read_prefix(&self, message: &MessageMeta, limit: usize) -> Result<Vec<u8>> {
        use std::io::Read;

        let read_from = |path: &Path| -> std::io::Result<Vec<u8>> {
            let file = File::open(path)?;
            let mut data = Vec::with_capacity(limit.min(64 * 1024));
            file.take(limit as u64).read_to_end(&mut data)?;
            Ok(data)
        };
        match read_from(&message.path) {
            Ok(data) => Ok(data),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match self.locate_after_rename(message)? {
                    Some(path) => read_from(&path).map_err(|error| MailError::io(&path, error)),
                    None => Err(MailError::io(&message.path, error)),
                }
            }
            Err(error) => Err(MailError::io(&message.path, error)),
        }
    }

    /// 按 base 在当前文件夹里重查被并发改名的文件。
    fn locate_after_rename(&self, message: &MessageMeta) -> Result<Option<std::path::PathBuf>> {
        let folder = message.path.parent().and_then(std::path::Path::parent);
        let Some(folder) = folder else {
            return Ok(None);
        };
        Ok(find_file(folder, &message.base)?
            .map(|(directory, filename)| folder.join(directory).join(filename)))
    }
}

pub fn read_message(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| MailError::io(path, error))
}

fn scan_usage_dir(folder: &Path, messages: &mut u64, bytes: &mut u64) -> Result<()> {
    for directory in ["cur", "new"] {
        let dir = folder.join(directory);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(MailError::io(&dir, error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| MailError::io(&dir, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| MailError::io(&dir, error))?;
            if !file_type.is_file() {
                continue;
            }
            let metadata = entry
                .metadata()
                .map_err(|error| MailError::io(entry.path(), error))?;
            *messages = messages.saturating_add(1);
            *bytes = bytes.saturating_add(metadata.len());
        }
    }
    Ok(())
}

fn unix_to_system_time(seconds: i64) -> Option<SystemTime> {
    if seconds < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
}

fn hostname() -> String {
    let raw = std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .unwrap_or_else(|| "mailstack".to_string());
    let sanitized: String = raw
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "mailstack".to_string()
    } else {
        sanitized
    }
}

fn ensure_maildir_dirs(path: &Path) -> Result<()> {
    for sub in ["cur", "new", "tmp"] {
        let directory = path.join(sub);
        fs::create_dir_all(&directory).map_err(|error| MailError::io(&directory, error))?;
    }
    Ok(())
}

fn move_directory_contents(from: &Path, to: &Path) -> Result<()> {
    let entries = match fs::read_dir(from) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(MailError::io(from, error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| MailError::io(from, error))?;
        if !entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        let target = to.join(entry.file_name());
        fs::rename(entry.path(), &target).map_err(|error| MailError::io(&target, error))?;
    }
    Ok(())
}

/// 尽力回滚已完成的改名：按逆序 rename 回原路径，失败只记日志（返回给调用方
/// 的仍是触发回滚的原始错误）。订阅清单不回滚 —— 与既有行为一致。
fn rollback_renames(completed: &[(PathBuf, PathBuf)]) {
    for (current, original) in completed.iter().rev() {
        if let Err(error) = fs::rename(current, original) {
            tracing::warn!(
                from = %current.display(),
                to = %original.display(),
                %error,
                "failed to roll back a completed folder rename"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 文件名 / 标志
// ---------------------------------------------------------------------------

/// 解析文件名里的标志后缀。返回 `(base, flags)`。
fn parse_flags_from_name<'a>(
    name: &'a str,
    keywords: &BTreeMap<char, String>,
) -> (&'a str, FlagSet) {
    let (base, suffix) = match name.split_once(":2,") {
        Some((base, suffix)) => (base, suffix),
        None => (name, ""),
    };
    let mut flags = FlagSet::new();
    for ch in suffix.chars() {
        if let Some(system) = SystemFlag::from_char(ch) {
            flags.insert(Flag::System(system));
        } else if let Some(keyword) = keywords.get(&ch) {
            flags.insert(Flag::Keyword(keyword.clone()));
        }
        // 未知字母（含 P）忽略：Maildir 的 P=Passed、以及别家实现的关键字，
        // 本实现不认识就不声称自己认识。
    }
    (base, flags)
}

fn flags_suffix(flags: &FlagSet, keywords: &BTreeMap<char, String>) -> String {
    let mut out = String::new();
    for system in SystemFlag::ORDER {
        if flags.contains(&Flag::System(system)) {
            out.push(system.maildir_char());
        }
    }
    let mut letters: Vec<char> = flags
        .iter()
        .filter_map(|flag| match flag {
            Flag::Keyword(keyword) => keywords
                .iter()
                .find(|(_, value)| *value == keyword)
                .map(|(letter, _)| *letter),
            Flag::System(_) => None,
        })
        .collect();
    letters.sort_unstable();
    letters.dedup();
    out.extend(letters);
    out
}

struct ScannedFile {
    directory: &'static str,
    filename: String,
    recent: bool,
    flags: FlagSet,
}

fn scan_folder(
    path: &Path,
    keywords: &BTreeMap<char, String>,
) -> Result<BTreeMap<String, ScannedFile>> {
    let mut scanned: BTreeMap<String, ScannedFile> = BTreeMap::new();
    for (directory, recent) in [("new", true), ("cur", false)] {
        let dir = path.join(directory);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(MailError::io(&dir, error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| MailError::io(&dir, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| MailError::io(&dir, error))?;
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with('.') {
                continue;
            }
            let (base, flags) = parse_flags_from_name(name, keywords);
            if !is_valid_base(base) {
                // 不认识的（含空白/控制字符的）文件名不能被 uidlist 安全表示；
                // 跳过它，而不是让整次 SELECT 失败。
                continue;
            }
            // `cur` 里的同名副本覆盖 `new` 里的（崩溃恢复的残留）。
            scanned.insert(
                base.to_string(),
                ScannedFile {
                    directory,
                    filename: name.to_string(),
                    recent,
                    flags,
                },
            );
            if scanned.len() > MAX_SCAN_ENTRIES {
                return Err(MailError::storage(format!(
                    "mailbox has more than {MAX_SCAN_ENTRIES} messages"
                )));
            }
        }
    }
    Ok(scanned)
}

fn is_valid_base(base: &str) -> bool {
    !base.is_empty()
        && base.len() <= 512
        && base
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':' && byte != b'\\')
}

fn find_file(path: &Path, base: &str) -> Result<Option<(&'static str, String)>> {
    for directory in ["cur", "new"] {
        let dir = path.join(directory);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(MailError::io(&dir, error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| MailError::io(&dir, error))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name == base || name.starts_with(&format!("{base}:2,")) {
                return Ok(Some((directory, name.to_string())));
            }
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// uidlist
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct UidList {
    uidvalidity: u32,
    uidnext: u32,
    highest_modseq: u64,
    /// uid → (unique base, modseq)
    by_uid: BTreeMap<u32, (String, u64)>,
}

impl UidList {
    fn by_base(&self) -> HashMap<String, (u32, u64)> {
        self.by_uid
            .iter()
            .map(|(uid, (base, modseq))| (base.clone(), (*uid, *modseq)))
            .collect()
    }
}

struct Mapping {
    uidvalidity: u32,
    uidnext: u32,
    highest_modseq: u64,
    by_base: HashMap<String, (u32, u64)>,
}

fn load_uidlist(path: &Path) -> Result<Option<UidList>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MailError::io(path, error)),
    };
    let mut lines = contents.lines();
    let version = match lines.next() {
        Some("MAILSTACK-UIDLIST 1") => 1u32,
        Some("MAILSTACK-UIDLIST 2") => 2u32,
        _ => {
            tracing::warn!(path = %path.display(), "uidlist header is invalid; rebuilding");
            return Ok(None);
        }
    };
    let mut uidvalidity: Option<u32> = None;
    let mut uidnext: Option<u32> = None;
    let mut highest_modseq: Option<u64> = if version == 1 { Some(0) } else { None };
    let mut by_uid: BTreeMap<u32, (String, u64)> = BTreeMap::new();
    let mut seen_bases: HashSet<String> = HashSet::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("uidvalidity ") {
            match value.parse::<u32>() {
                Ok(value) if value > 0 && uidvalidity.is_none() => uidvalidity = Some(value),
                _ => return Ok(None),
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("uidnext ") {
            match value.parse::<u32>() {
                Ok(value) if value > 0 && uidnext.is_none() => uidnext = Some(value),
                _ => return Ok(None),
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("highestmodseq ") {
            if version < 2 {
                return Ok(None);
            }
            match value.parse::<u64>() {
                Ok(value) if highest_modseq.is_none() => highest_modseq = Some(value),
                _ => return Ok(None),
            }
            continue;
        }
        let Some((uid_field, rest)) = line.split_once(' ') else {
            return Ok(None);
        };
        let Ok(uid) = uid_field.parse::<u32>() else {
            return Ok(None);
        };
        let (modseq, base) = if version >= 2 {
            let Some((modseq_field, base)) = rest.split_once(' ') else {
                return Ok(None);
            };
            let Ok(modseq) = modseq_field.parse::<u64>() else {
                return Ok(None);
            };
            if modseq == 0 {
                return Ok(None);
            }
            (modseq, base)
        } else {
            (0u64, rest)
        };
        if uid == 0
            || !is_valid_base(base)
            || by_uid.contains_key(&uid)
            || !seen_bases.insert(base.to_string())
        {
            return Ok(None);
        }
        by_uid.insert(uid, (base.to_string(), modseq));
    }
    let (Some(uidvalidity), Some(uidnext)) = (uidvalidity, uidnext) else {
        return Ok(None);
    };
    if let Some(max_uid) = by_uid.keys().next_back() {
        if *max_uid >= uidnext {
            return Ok(None);
        }
    }
    let highest_modseq = if version == 1 {
        // v1 → v2 迁移：按 UID 顺序赋予递增 modseq。
        let mut counter = 0u64;
        for entry in by_uid.values_mut() {
            counter += 1;
            entry.1 = counter;
        }
        counter
    } else {
        let highest = highest_modseq.unwrap_or(0);
        let max_modseq = by_uid
            .values()
            .map(|(_, modseq)| *modseq)
            .max()
            .unwrap_or(0);
        if highest < max_modseq {
            return Ok(None);
        }
        highest
    };
    Ok(Some(UidList {
        uidvalidity,
        uidnext,
        highest_modseq,
        by_uid,
    }))
}

fn write_uidlist(path: &Path, list: &UidList) -> Result<()> {
    let mut buffer = String::new();
    buffer.push_str("MAILSTACK-UIDLIST 2\n");
    buffer.push_str(&format!("uidvalidity {}\n", list.uidvalidity));
    buffer.push_str(&format!("uidnext {}\n", list.uidnext));
    buffer.push_str(&format!("highestmodseq {}\n", list.highest_modseq));
    for (uid, (base, modseq)) in &list.by_uid {
        buffer.push_str(&format!("{uid} {modseq} {base}\n"));
    }
    write_atomic(path, buffer.as_bytes())
}

/// 追加 QRESYNC 消失记录；超过 8 MiB 时只保留最近 5 万条。
fn append_expunged(folder: &Path, events: &[(u32, u64)]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let path = folder.join(EXPUNGED);
    if fs::metadata(&path)
        .map(|metadata| metadata.len() > EXPUNGED_MAX_BYTES)
        .unwrap_or(false)
    {
        let contents = fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = contents.lines().collect();
        let keep = lines.len().saturating_sub(50_000);
        let mut retained = lines[keep..].join("\n");
        if !retained.is_empty() {
            retained.push('\n');
        }
        write_atomic(&path, retained.as_bytes())?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| MailError::io(&path, error))?;
    let mut buffer = String::new();
    for (uid, modseq) in events {
        buffer.push_str(&format!("{uid} {modseq}\n"));
    }
    file.write_all(buffer.as_bytes())
        .map_err(|error| MailError::io(&path, error))?;
    file.sync_all()
        .map_err(|error| MailError::io(&path, error))?;
    Ok(())
}

/// 生成新的 UIDVALIDITY。
///
/// 只在「映射缺失/损坏」时调用。要求两次重建得到不同的值（哪怕时钟同一秒），
/// 否则客户端会以为旧 UID 仍然有效，把旧缓存贴到新邮件上。混合进程内序号与
/// 当前纳秒，既保证同进程内单调，又让跨进程的同一秒重建也几乎不可能相同。
fn fresh_uidvalidity(now_secs: i64) -> u32 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::from(elapsed.subsec_nanos()))
        .unwrap_or(0);
    let mixed = (now_secs.clamp(1, i64::from(u32::MAX)) as u64)
        .wrapping_mul(1_000_003)
        .wrapping_add(sequence.wrapping_mul(0x9E37_79B9))
        .wrapping_add(nanos);
    ((mixed ^ (mixed >> 32)) as u32).max(1)
}

fn sync_uidlist(path: &Path, bases: &BTreeSet<String>, clock: &dyn Clock) -> Result<Mapping> {
    with_lock(&path.join(UIDLIST_LOCK), || {
        let uidlist_path = path.join(UIDLIST);
        let (mut list, rebuilt) = match load_uidlist(&uidlist_path)? {
            Some(list) => (list, false),
            None => (
                UidList {
                    uidvalidity: fresh_uidvalidity(clock.now_secs()),
                    uidnext: 1,
                    highest_modseq: 0,
                    by_uid: BTreeMap::new(),
                },
                true,
            ),
        };

        let mut changed = rebuilt || !uidlist_path.exists();
        if rebuilt {
            // UIDVALIDITY 已改变，旧的 VANISHED 历史不再有语义。
            let _ = fs::remove_file(path.join(EXPUNGED));
        }
        let before = list.by_uid.len();
        list.by_uid.retain(|_, (base, _)| bases.contains(base));
        if list.by_uid.len() != before {
            changed = true;
        }
        let existing: HashSet<String> =
            list.by_uid.values().map(|(base, _)| base.clone()).collect();
        let mut next = list.uidnext.max(
            list.by_uid
                .keys()
                .next_back()
                .copied()
                .unwrap_or(0)
                .saturating_add(1)
                .max(1),
        );
        for base in bases {
            if !existing.contains(base) {
                list.highest_modseq = list.highest_modseq.saturating_add(1);
                let modseq = list.highest_modseq;
                list.by_uid.insert(next, (base.clone(), modseq));
                next = next
                    .checked_add(1)
                    .ok_or_else(|| MailError::storage("UID space exhausted"))?;
                changed = true;
            }
        }
        if next != list.uidnext {
            list.uidnext = next;
            changed = true;
        }
        if changed {
            write_uidlist(&uidlist_path, &list)?;
        }

        Ok(Mapping {
            uidvalidity: list.uidvalidity,
            uidnext: list.uidnext,
            highest_modseq: list.highest_modseq,
            by_base: list.by_base(),
        })
    })
}

fn assign_uid(path: &Path, base: &str, clock: &dyn Clock) -> Result<(u32, u32)> {
    let (uidvalidity, uids) = assign_uids_many(path, &[base.to_string()], clock)?;
    let uid = uids
        .into_iter()
        .next()
        .ok_or_else(|| MailError::storage("UID assignment produced no uid"))?;
    Ok((uidvalidity, uid))
}

/// 在**一次** uidlist 锁内为一批 base 分配 UID（保持输入顺序）。
fn assign_uids_many(path: &Path, bases: &[String], clock: &dyn Clock) -> Result<(u32, Vec<u32>)> {
    with_lock(&path.join(UIDLIST_LOCK), || {
        let uidlist_path = path.join(UIDLIST);
        let (mut list, rebuilt) = match load_uidlist(&uidlist_path)? {
            Some(list) => (list, false),
            None => (
                UidList {
                    uidvalidity: fresh_uidvalidity(clock.now_secs()),
                    uidnext: 1,
                    highest_modseq: 0,
                    by_uid: BTreeMap::new(),
                },
                true,
            ),
        };
        let mut changed = rebuilt || !uidlist_path.exists();
        if rebuilt {
            let _ = fs::remove_file(path.join(EXPUNGED));
        }
        let mut existing: HashMap<String, u32> = list
            .by_uid
            .iter()
            .map(|(uid, (base, _))| (base.clone(), *uid))
            .collect();
        let mut next = list.uidnext.max(
            list.by_uid
                .keys()
                .next_back()
                .copied()
                .unwrap_or(0)
                .saturating_add(1)
                .max(1),
        );
        let mut uids = Vec::with_capacity(bases.len());
        for base in bases {
            if let Some(uid) = existing.get(base) {
                uids.push(*uid);
                continue;
            }
            let uid = next;
            next = next
                .checked_add(1)
                .ok_or_else(|| MailError::storage("UID space exhausted"))?;
            list.highest_modseq = list.highest_modseq.saturating_add(1);
            let modseq = list.highest_modseq;
            list.by_uid.insert(uid, (base.clone(), modseq));
            existing.insert(base.clone(), uid);
            uids.push(uid);
            changed = true;
        }
        if next != list.uidnext {
            list.uidnext = next;
            changed = true;
        }
        if changed {
            write_uidlist(&uidlist_path, &list)?;
        }
        Ok((list.uidvalidity, uids))
    })
}

/// 写 `tmp/<unique>` 并 fsync；失败时清理半成品。
fn write_tmp_file(
    folder: &Path,
    base: &str,
    data: &[u8],
    internal_date: Option<i64>,
) -> Result<PathBuf> {
    let tmp = folder.join("tmp").join(base);
    let write: Result<()> = (|| {
        let mut file = open_private(&tmp, true).map_err(|error| MailError::io(&tmp, error))?;
        file.write_all(data)
            .map_err(|error| MailError::io(&tmp, error))?;
        file.sync_all()
            .map_err(|error| MailError::io(&tmp, error))?;
        if let Some(date) = internal_date {
            if let Some(time) = unix_to_system_time(date) {
                file.set_modified(time)
                    .map_err(|error| MailError::io(&tmp, error))?;
            }
        }
        Ok(())
    })();
    if let Err(error) = write {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(tmp)
}

// ---------------------------------------------------------------------------
// keywords
// ---------------------------------------------------------------------------

fn read_keywords(path: &Path) -> BTreeMap<char, String> {
    let mut map = BTreeMap::new();
    let Ok(contents) = fs::read_to_string(path.join(KEYWORDS)) else {
        return map;
    };
    for line in contents.lines() {
        let Some((letter, keyword)) = line.split_once(' ') else {
            continue;
        };
        let mut chars = letter.chars();
        let Some(letter) = chars.next() else { continue };
        if chars.next().is_some() || !letter.is_ascii_lowercase() {
            continue;
        }
        if validate_keyword(keyword).is_err() {
            continue;
        }
        map.insert(letter, keyword.to_ascii_lowercase());
    }
    map
}

fn write_keywords(path: &Path, map: &BTreeMap<char, String>) -> Result<()> {
    let mut buffer = String::new();
    for (letter, keyword) in map {
        buffer.push_str(&format!("{letter} {keyword}\n"));
    }
    write_atomic(&path.join(KEYWORDS), buffer.as_bytes())
}

/// 为标志集合分配关键字字母（必要时写回关键字表），返回 Maildir 后缀。
fn suffix_with_keyword_allocation(path: &Path, flags: &FlagSet) -> Result<String> {
    with_lock(&path.join(KEYWORDS_LOCK), || {
        let mut keywords = read_keywords(path);
        let mut changed = false;
        for flag in flags {
            if let Flag::Keyword(keyword) = flag {
                if !keywords.values().any(|value| value == keyword) {
                    let letter = ('a'..='z')
                        .find(|letter| !keywords.contains_key(letter))
                        .ok_or_else(|| MailError::invalid("mailbox has more than 26 keywords"))?;
                    if keywords.len() >= MAX_KEYWORDS {
                        return Err(MailError::invalid("mailbox has more than 26 keywords"));
                    }
                    keywords.insert(letter, keyword.clone());
                    changed = true;
                }
            }
        }
        if changed {
            write_keywords(path, &keywords)?;
        }
        Ok(flags_suffix(flags, &keywords))
    })
}

// ---------------------------------------------------------------------------
// Dovecot 迁移接缝（仅供 crate 内 `migration` 模块调用）
// ---------------------------------------------------------------------------

/// 导入一份 Dovecot 关键字字母表。
///
/// 只在目标文件夹**尚未**有 `.mailstack-keywords` 时写入；已存在则返回
/// [`MailError::AlreadyExists`]，绝不覆盖 MailStack 自己分配的字母（覆盖会让
/// 历史文件名里的字母被重新解释）。非法字母/关键字被逐条跳过而不是让整次导入
/// 失败。返回实际写入的关键字数量（0 表示没有可导入的条目，不创建文件）。
pub(crate) fn import_keywords(folder: &Path, map: &BTreeMap<char, String>) -> Result<usize> {
    with_lock(&folder.join(KEYWORDS_LOCK), || {
        if folder.join(KEYWORDS).exists() {
            return Err(MailError::already_exists(KEYWORDS));
        }
        let mut imported: BTreeMap<char, String> = BTreeMap::new();
        for (letter, keyword) in map {
            if !letter.is_ascii_lowercase() || validate_keyword(keyword).is_err() {
                continue;
            }
            imported.insert(*letter, keyword.to_ascii_lowercase());
        }
        if imported.is_empty() {
            return Ok(0);
        }
        write_keywords(folder, &imported)?;
        Ok(imported.len())
    })
}

/// 一次 Dovecot UID 映射导入的结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UidImport {
    /// 在磁盘上确认存在、成功保留 Dovecot UID 的消息数。
    pub mapped: usize,
    /// Dovecot 记录里 base 不在磁盘上（已删除/解析不出）或自相矛盾而被丢弃的条数。
    pub unresolved: usize,
}

/// 导入 Dovecot 的 `dovecot-uidlist`，尽最大努力保留原 UID 与 UIDVALIDITY。
///
/// 安全不变量（迁移正确性的全部依据）：
///
/// * **只保留落盘成功的候选**：`base` 必须出现在 `scan_folder` 的结果里，否则
///   丢弃并计入 `unresolved`。Dovecot 的 uidlist 可能领先于磁盘（崩溃、外部
///   删除），照单全收会把不存在的消息也占住一个 UID。
/// * **`mapped == 0` 时什么都不写**：没有任何 Dovecot 记录能对上磁盘，就**不**
///   写 uidlist，让首次 `open_folder` 用全新的 UIDVALIDITY 重建。保留旧
///   UIDVALIDITY 却换了一套 UID，会让客户端把缓存里的旧 UID 贴到别的邮件上 ——
///   这比强制重新同步危险得多（见模块级文档「换 UIDVALIDITY，而不是猜」）。
/// * **未映射的磁盘文件由后续 `sync_uidlist` 分配 >= `uidnext` 的新 UID**，
///   绝不复用旧 UID 指向不同消息。`uidnext` 取 `max(hint, max_uid + 1, 1)`。
/// * modseq 按 UID 升序赋 `1..=n`（CONDSTORE 要求非零、单调）。
///
/// 只在目标文件夹**尚未**有 `.mailstack-uidlist` 时写入；已存在则返回
/// [`MailError::AlreadyExists`]。`uidvalidity` 必须 > 0。
pub(crate) fn import_uidlist(
    folder: &Path,
    uidvalidity: u32,
    uidnext_hint: u32,
    candidates: &[(u32, String)],
) -> Result<UidImport> {
    if uidvalidity == 0 {
        return Err(MailError::invalid("uidvalidity must be greater than zero"));
    }
    with_lock(&folder.join(UIDLIST_LOCK), || {
        if folder.join(UIDLIST).exists() {
            return Err(MailError::already_exists(UIDLIST));
        }
        // 关键字表此时应已导入；但 base 提取只看 `:2,` 之前，传空表即可。
        let on_disk = scan_folder(folder, &BTreeMap::new())?;
        let mut by_uid: BTreeMap<u32, (String, u64)> = BTreeMap::new();
        let mut seen_bases: HashSet<String> = HashSet::new();
        let mut unresolved = 0usize;
        for (uid, base) in candidates {
            if *uid == 0 || !is_valid_base(base) || !on_disk.contains_key(base) {
                unresolved += 1;
                continue;
            }
            if by_uid.contains_key(uid) || !seen_bases.insert(base.clone()) {
                unresolved += 1;
                continue;
            }
            by_uid.insert(*uid, (base.clone(), 0));
        }
        if by_uid.is_empty() {
            return Ok(UidImport {
                mapped: 0,
                unresolved,
            });
        }
        let mut modseq = 0u64;
        for entry in by_uid.values_mut() {
            modseq += 1;
            entry.1 = modseq;
        }
        let max_uid = by_uid.keys().next_back().copied().unwrap_or(0);
        let uidnext = uidnext_hint.max(max_uid.saturating_add(1)).max(1);
        let mapped = by_uid.len();
        let list = UidList {
            uidvalidity,
            uidnext,
            highest_modseq: modseq,
            by_uid,
        };
        write_uidlist(&folder.join(UIDLIST), &list)?;
        Ok(UidImport { mapped, unresolved })
    })
}

// ---------------------------------------------------------------------------
// 元数据（RFC 5464 METADATA）：邮箱级与服务器级
// ---------------------------------------------------------------------------

impl MailStore {
    /// 读取元数据表：`Some(folder)` 为邮箱级，`None` 为服务器级。
    ///
    /// 邮箱不存在时返回 [`MailError::NotFound`]；元数据文件缺失视为空表。值按
    /// base64 存储，因此可以是任意字节（不做文本假设）。
    pub fn read_metadata(&self, folder: Option<&str>) -> Result<BTreeMap<String, Vec<u8>>> {
        let (file, _lock) = self.metadata_paths(folder)?;
        if let Some(name) = folder {
            if !self.folder_path(name)?.is_dir() {
                return Err(MailError::not_found(name));
            }
        }
        let contents = match fs::read_to_string(&file) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => return Err(MailError::io(&file, error)),
        };
        let mut map = BTreeMap::new();
        for line in contents.lines() {
            let Some((entry, encoded)) = line.split_once(' ') else {
                continue;
            };
            if let Ok(value) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                map.insert(entry.to_string(), value);
            }
        }
        Ok(map)
    }

    /// 原子写入元数据表（`flock` 保护读改写）。邮箱不存在时返回 `NotFound`。
    pub fn write_metadata(
        &self,
        folder: Option<&str>,
        map: &BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        let (file, lock) = self.metadata_paths(folder)?;
        if let Some(name) = folder {
            if !self.folder_path(name)?.is_dir() {
                return Err(MailError::not_found(name));
            }
        }
        with_lock(&lock, || {
            let mut buffer = String::new();
            for (entry, value) in map {
                buffer.push_str(entry);
                buffer.push(' ');
                buffer.push_str(&base64::engine::general_purpose::STANDARD.encode(value));
                buffer.push('\n');
            }
            write_atomic(&file, buffer.as_bytes())
        })
    }

    fn metadata_paths(&self, folder: Option<&str>) -> Result<(PathBuf, PathBuf)> {
        match folder {
            Some(name) => {
                let dir = self.folder_path(name)?;
                Ok((dir.join(METADATA), dir.join(METADATA_LOCK)))
            }
            None => Ok((
                self.root.join(SERVER_METADATA),
                self.root.join(SERVER_METADATA_LOCK),
            )),
        }
    }

    /// 读取邮箱 ACL（`<identifier> <rights>`）。邮箱不存在返回 `NotFound`。
    pub fn read_acl(&self, folder: &str) -> Result<BTreeMap<String, String>> {
        let dir = self.folder_path(folder)?;
        if !dir.is_dir() {
            return Err(MailError::not_found(folder));
        }
        let path = dir.join(ACL);
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => return Err(MailError::io(&path, error)),
        };
        let mut map = BTreeMap::new();
        for line in contents.lines() {
            if let Some((identifier, rights)) = line.split_once(' ') {
                map.insert(identifier.to_string(), rights.to_string());
            }
        }
        Ok(map)
    }

    /// 原子写入邮箱 ACL（`flock` 保护读改写）。邮箱不存在返回 `NotFound`。
    pub fn write_acl(&self, folder: &str, map: &BTreeMap<String, String>) -> Result<()> {
        let dir = self.folder_path(folder)?;
        if !dir.is_dir() {
            return Err(MailError::not_found(folder));
        }
        let path = dir.join(ACL);
        let lock = dir.join(ACL_LOCK);
        with_lock(&lock, || {
            let mut buffer = String::new();
            for (identifier, rights) in map {
                buffer.push_str(identifier);
                buffer.push(' ');
                buffer.push_str(rights);
                buffer.push('\n');
            }
            write_atomic(&path, buffer.as_bytes())
        })
    }
}

// ---------------------------------------------------------------------------
// 文件原语
// ---------------------------------------------------------------------------

/// 模块级文件锁原语（`sieve` 的 vacation 状态也复用同一把锁纪律）。
pub(crate) fn with_lock<T>(lock_path: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|error| MailError::io(parent, error))?;
    }
    let file = open_private(lock_path, false).map_err(|error| MailError::io(lock_path, error))?;
    fs2::FileExt::lock_exclusive(&file).map_err(|error| MailError::io(lock_path, error))?;
    let result = action();
    // 解锁失败不会让语义变错（close 也会释放），但如果是权限/句柄问题，
    // 下一次加锁会失败并留下日志。
    if let Err(error) = fs2::FileExt::unlock(&file) {
        tracing::warn!(path = %lock_path.display(), %error, "failed to unlock");
    }
    result
}

/// 以 0600 打开/创建敏感文件（uidlist、关键字表、邮件本体、锁 sidecar）。
///
/// Unix 上默认 umask 022 会让 `File::create` 产出 0644 —— 邮件与 UID 映射是
/// 私密数据，不能靠部署机的 umask 碰运气。Windows 没有「创建时指定权限」的
/// 概念，权限由 ACL 决定。
fn open_private(path: &Path, create_new: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// 临时文件 + rename。`rename` 在同目录内原子；调用方必须持有相应锁。
/// `sieve` 的脚本/vacation 状态写入复用同一实现（唯一临时名 + fsync）。
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default(),
        std::process::id(),
        sequence
    ));
    {
        let mut file = open_private(&temp, true).map_err(|error| MailError::io(&temp, error))?;
        file.write_all(data)
            .map_err(|error| MailError::io(&temp, error))?;
        file.sync_all()
            .map_err(|error| MailError::io(&temp, error))?;
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(MailError::io(path, error));
    }
    if let Some(parent) = path.parent() {
        fsync_dir_best_effort(parent);
    }
    Ok(())
}

/// 目录 fsync：让「文件已改名」这件事在掉电后也成立。
///
/// 某些文件系统（Windows 的目录句柄、部分 FUSE）不支持打开目录；失败只记日志，
/// 不应让写入整体失败 —— 那些文件系统本来也不提供目录级持久化保证。
fn fsync_dir_best_effort(dir: &Path) {
    match File::open(dir) {
        Ok(handle) => {
            if let Err(error) = handle.sync_all() {
                tracing::debug!(path = %dir.display(), %error, "directory fsync failed");
            }
        }
        Err(error) => {
            tracing::debug!(path = %dir.display(), %error, "cannot open directory for fsync");
        }
    }
}

fn read_lines_set(path: &Path) -> BTreeSet<String> {
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| normalize_folder_name(line).is_ok())
        .map(|line| normalize_folder_name(line).unwrap_or_else(|_| line.to_string()))
        .collect()
}

fn write_lines_sorted(path: &Path, lines: &BTreeSet<String>) -> Result<()> {
    let mut buffer = String::new();
    for line in lines {
        buffer.push_str(line);
        buffer.push('\n');
    }
    write_atomic(path, buffer.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI64;

    struct FixedClock(AtomicI64);

    impl FixedClock {
        fn new(value: i64) -> Self {
            Self(AtomicI64::new(value))
        }
    }

    impl Clock for FixedClock {
        fn now_secs(&self) -> i64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    fn store() -> (tempfile::TempDir, Arc<FixedClock>, MailStore) {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(FixedClock::new(1_700_000_000));
        let store = MailStore::new(dir.path(), clock.clone()).unwrap();
        (dir, clock, store)
    }

    fn seen() -> FlagSet {
        let mut flags = FlagSet::new();
        flags.insert(Flag::System(SystemFlag::Seen));
        flags
    }

    #[test]
    fn metadata_round_trips_per_mailbox_and_server_scope() {
        let (_dir, _clock, store) = store();
        store.create("Notes").unwrap();

        let mut map = BTreeMap::new();
        map.insert("/private/comment".to_string(), b"hello".to_vec());
        map.insert("/shared/color".to_string(), vec![0, 1, 2, 255]);
        store.write_metadata(Some("Notes"), &map).unwrap();
        assert_eq!(store.read_metadata(Some("Notes")).unwrap(), map);

        // 服务器级与邮箱级互不干扰。
        let mut server = BTreeMap::new();
        server.insert("/private/vendor/example".to_string(), b"s".to_vec());
        store.write_metadata(None, &server).unwrap();
        assert_eq!(store.read_metadata(None).unwrap(), server);
        assert_eq!(store.read_metadata(Some("Notes")).unwrap(), map);

        // 删除一个条目再写回。
        let mut trimmed = map.clone();
        trimmed.remove("/private/comment");
        store.write_metadata(Some("Notes"), &trimmed).unwrap();
        assert_eq!(store.read_metadata(Some("Notes")).unwrap(), trimmed);

        // 不存在的邮箱返回 NotFound（而不是静默成功）。
        assert!(store.read_metadata(Some("Missing")).is_err());
        assert!(store.write_metadata(Some("Missing"), &map).is_err());
    }

    #[test]
    fn acl_round_trips_and_requires_an_existing_mailbox() {
        let (_dir, _clock, store) = store();
        store.create("Shared").unwrap();

        let mut acl = BTreeMap::new();
        acl.insert("bob@example.com".to_string(), "lrsw".to_string());
        acl.insert("anyone".to_string(), "l".to_string());
        store.write_acl("Shared", &acl).unwrap();
        assert_eq!(store.read_acl("Shared").unwrap(), acl);

        // 不存在的邮箱：读写都返回 NotFound。
        assert!(store.read_acl("Missing").is_err());
        assert!(store.write_acl("Missing", &acl).is_err());
    }

    #[test]
    fn folders_are_created_listed_and_protected() {
        let (_dir, _clock, store) = store();
        store.create("Sent").unwrap();
        store.create("Sent.2026").unwrap();
        assert_eq!(store.folders().unwrap(), vec!["INBOX", "Sent", "Sent.2026"]);
        assert!(store.has_children("Sent").unwrap());
        assert!(!store.has_children("INBOX").unwrap());
        assert!(store.delete("INBOX").is_err());
        assert!(store.delete("Sent").is_err(), "有子文件夹时不得删除");
        assert!(store.delete("Sent.2026").is_ok());
        assert!(store.delete("Sent").is_ok());
        assert_eq!(store.folders().unwrap(), vec!["INBOX"]);
    }

    #[test]
    fn invalid_folder_names_are_rejected_before_touching_disk() {
        let (_dir, _clock, store) = store();
        for name in [
            "", ".hidden", "a..b", "a.", ".a", "a/b", "a\\b", "a:b", "a*b", "a%b",
        ] {
            assert!(store.create(name).is_err(), "{name:?} 必须被拒绝");
        }
        assert!(
            store.create("inbox").is_err(),
            "INBOX 已存在（大小写不敏感）"
        );
        assert_eq!(normalize_folder_name("Inbox").unwrap(), "INBOX");
        assert!(store.create("Sent Items").is_ok());
    }

    #[test]
    fn append_assigns_a_stable_uid_even_when_flags_change() {
        let (_dir, _clock, store) = store();
        let (uidvalidity, uid) = store
            .append(
                "INBOX",
                b"Subject: x\r\n\r\nbody\r\n",
                &FlagSet::new(),
                None,
            )
            .unwrap();
        assert!(uidvalidity > 0);
        assert_eq!(uid, 1);

        let state = store.open_folder("INBOX", false).unwrap();
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.messages[0].uid, uid);
        assert!(state.messages[0].recent, "未带标志的 APPEND 是 Recent");

        store.set_flags("INBOX", uid, &seen()).unwrap();
        let state = store.open_folder("INBOX", false).unwrap();
        assert_eq!(state.messages[0].uid, uid, "改标志不得改变 UID");
        assert!(state.messages[0]
            .flags
            .contains(&Flag::System(SystemFlag::Seen)));
        assert!(state.messages[0].filename.contains(":2,"));
    }

    #[test]
    fn recent_is_only_reported_by_the_first_select() {
        let (_dir, _clock, store) = store();
        store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        let first = store.open_folder("INBOX", true).unwrap();
        assert_eq!(first.status().recent, 1);
        let second = store.open_folder("INBOX", true).unwrap();
        assert_eq!(second.status().recent, 0, "RECENT 只对第一次 SELECT 成立");
        assert!(second.messages[0].path.parent().unwrap().ends_with("cur"));
    }

    #[test]
    fn appending_with_flags_skips_recent_and_persists_flags() {
        let (_dir, _clock, store) = store();
        let (_, _) = store.append("INBOX", b"x\r\n", &seen(), None).unwrap();
        let state = store.open_folder("INBOX", true).unwrap();
        assert!(!state.messages[0].recent);
        assert!(state.messages[0]
            .flags
            .contains(&Flag::System(SystemFlag::Seen)));
        assert!(state.messages[0].filename.contains("S"));
    }

    #[test]
    fn internal_date_is_preserved_from_append() {
        let (_dir, _clock, store) = store();
        let date = 1_600_000_000;
        store
            .append("INBOX", b"x\r\n", &FlagSet::new(), Some(date))
            .unwrap();
        let state = store.open_folder("INBOX", false).unwrap();
        assert_eq!(state.messages[0].internal_date, date);
    }

    #[test]
    fn keywords_get_letters_and_survive_reopen() {
        let (_dir, _clock, store) = store();
        let (_, uid) = store
            .append("INBOX", b"x\r\n", &FlagSet::new(), None)
            .unwrap();
        let mut flags = seen();
        flags.insert(Flag::Keyword("$junk".to_string()));
        store.set_flags("INBOX", uid, &flags).unwrap();
        let state = store.open_folder("INBOX", false).unwrap();
        assert!(state.messages[0]
            .flags
            .contains(&Flag::Keyword("$junk".to_string())));
        assert!(
            state.messages[0].filename.contains('a'),
            "第一个关键字应拿到字母 a：{}",
            state.messages[0].filename
        );
    }

    #[test]
    fn expunge_removes_the_file_and_the_mapping_and_keeps_uidnext_monotonic() {
        let (_dir, _clock, store) = store();
        let (_, first) = store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        let (_, second) = store
            .append("INBOX", b"two\r\n", &FlagSet::new(), None)
            .unwrap();
        let before = store.open_folder("INBOX", false).unwrap();
        assert_eq!(store.expunge("INBOX", &[first]).unwrap(), 1);
        let after = store.open_folder("INBOX", false).unwrap();
        assert_eq!(after.messages.len(), 1);
        assert_eq!(after.messages[0].uid, second);
        assert!(after.uidnext >= before.uidnext, "已分配的 UID 不得回收");

        let (_, third) = store
            .append("INBOX", b"three\r\n", &FlagSet::new(), None)
            .unwrap();
        assert!(third > second);
    }

    #[test]
    fn copy_preserves_flags_and_date_but_clears_recent() {
        let (_dir, _clock, store) = store();
        store.create("Archive").unwrap();
        let date = 1_600_000_000;
        store
            .append("INBOX", b"Subject: a\r\n\r\nbody\r\n", &seen(), Some(date))
            .unwrap();
        let state = store.open_folder("INBOX", false).unwrap();
        let uid = state.messages[0].uid;
        let (_uv, copied) = store.copy("INBOX", uid, "Archive").unwrap();
        let archive = store.open_folder("Archive", false).unwrap();
        assert_eq!(archive.messages[0].uid, copied);
        assert!(archive.messages[0]
            .flags
            .contains(&Flag::System(SystemFlag::Seen)));
        assert_eq!(archive.messages[0].internal_date, date);
        assert!(!archive.messages[0].recent);
    }

    #[test]
    fn uidvalidity_is_stable_across_reopens_and_changes_when_the_mapping_is_lost() {
        let (dir, _clock, store) = store();
        store
            .append("INBOX", b"x\r\n", &FlagSet::new(), None)
            .unwrap();
        let first = store.open_folder("INBOX", false).unwrap();
        let second = store.open_folder("INBOX", false).unwrap();
        assert_eq!(first.uidvalidity, second.uidvalidity);

        fs::remove_file(dir.path().join(UIDLIST)).unwrap();
        let rebuilt = store.open_folder("INBOX", false).unwrap();
        assert_ne!(
            rebuilt.uidvalidity, first.uidvalidity,
            "映射丢失后必须换 UIDVALIDITY（UID 语义已不可保证）"
        );
    }

    #[test]
    fn a_corrupt_uidlist_is_rebuilt_instead_of_crashing() {
        let (dir, _clock, store) = store();
        store
            .append("INBOX", b"x\r\n", &FlagSet::new(), None)
            .unwrap();
        let before = store.open_folder("INBOX", false).unwrap();
        fs::write(dir.path().join(UIDLIST), "garbage\n").unwrap();
        let after = store.open_folder("INBOX", false).unwrap();
        assert_eq!(after.messages.len(), 1);
        assert_ne!(after.uidvalidity, before.uidvalidity);
    }

    #[test]
    fn renaming_moves_children_and_rewrites_subscriptions() {
        let (_dir, _clock, store) = store();
        store.create("Old").unwrap();
        store.create("Old.Child").unwrap();
        store.subscribe("Old").unwrap();
        store.subscribe("Old.Child").unwrap();
        store.rename("Old", "New").unwrap();
        assert_eq!(store.folders().unwrap(), vec!["INBOX", "New", "New.Child"]);
        assert_eq!(store.subscriptions().unwrap(), vec!["New", "New.Child"]);
    }

    #[test]
    fn renaming_inbox_moves_messages_but_keeps_inbox() {
        let (_dir, _clock, store) = store();
        store
            .append("INBOX", b"x\r\n", &FlagSet::new(), None)
            .unwrap();
        store.rename("INBOX", "Saved").unwrap();
        assert!(store.exists("INBOX").unwrap());
        assert_eq!(store.open_folder("INBOX", false).unwrap().messages.len(), 0);
        assert_eq!(store.open_folder("Saved", false).unwrap().messages.len(), 1);
    }

    #[test]
    fn deleting_a_folder_removes_its_messages_but_children_block_it() {
        let (_dir, _clock, store) = store();
        store.create("Temp").unwrap();
        store
            .append("Temp", b"x\r\n", &FlagSet::new(), None)
            .unwrap();
        assert!(store.delete("Temp").is_ok(), "删除非空邮箱必须成功");

        store.create("Parent").unwrap();
        store.create("Parent.Child").unwrap();
        assert!(store.delete("Parent").is_err(), "有子文件夹时不得删除");
        assert!(store.delete("Parent.Child").is_ok());
        assert!(store.delete("Parent").is_ok());
    }

    #[test]
    fn reading_a_message_survives_a_concurrent_flag_rename() {
        let (_dir, _clock, store) = store();
        store
            .append(
                "INBOX",
                b"Subject: x\r\n\r\nbody\r\n",
                &FlagSet::new(),
                None,
            )
            .unwrap();
        let state = store.open_folder("INBOX", false).unwrap();
        let stale = state.messages[0].clone();
        // 模拟另一个会话改了标志（文件名变化，base 不变）。
        store.set_flags("INBOX", stale.uid, &seen()).unwrap();
        assert_eq!(
            store.read(&stale).unwrap(),
            b"Subject: x\r\n\r\nbody\r\n",
            "旧路径失效后应按 base 重查，而不是把 FETCH 变成 NO"
        );
    }

    #[test]
    fn copy_many_copies_all_requested_messages_in_order() {
        let (_dir, _clock, store) = store();
        store.create("Archive").unwrap();
        for body in [&b"one\r\n"[..], b"two\r\n", b"three\r\n"] {
            store.append("INBOX", body, &FlagSet::new(), None).unwrap();
        }
        let state = store.open_folder("INBOX", false).unwrap();
        let uids: Vec<u32> = state.messages.iter().map(|message| message.uid).collect();
        let (uidvalidity, copies) = store.copy_many("INBOX", &uids, "Archive").unwrap();
        assert!(uidvalidity > 0);
        assert_eq!(copies.len(), 3);
        let archive = store.open_folder("Archive", false).unwrap();
        assert_eq!(archive.messages.len(), 3);
        assert_eq!(archive.messages[0].uid, copies[0]);
        assert_eq!(archive.messages[2].uid, copies[2]);
    }

    #[test]
    fn copy_many_rejects_a_missing_uid_before_copying_anything() {
        let (_dir, _clock, store) = store();
        store.create("Archive").unwrap();
        for body in [&b"one\r\n"[..], b"two\r\n"] {
            store.append("INBOX", body, &FlagSet::new(), None).unwrap();
        }
        let state = store.open_folder("INBOX", false).unwrap();
        let first = state.messages[0].uid;
        // 第二个 UID 不存在：整批必须在落盘前被拒绝，不能留下第一份副本。
        let missing = state.messages.last().unwrap().uid + 999;
        assert!(matches!(
            store.copy_many("INBOX", &[first, missing], "Archive"),
            Err(MailError::NotFound(_))
        ));
        assert_eq!(
            store.open_folder("Archive", false).unwrap().messages.len(),
            0
        );
    }

    #[test]
    fn multi_folder_delivery_is_all_or_nothing() {
        let (_dir, _clock, store) = store();
        store.create("Keep").unwrap();
        let message = NewMessage {
            data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
            flags: FlagSet::new(),
            internal_date: None,
        };
        // 第二个目标不存在：整个调用失败，第一个目标不得留下副本。
        assert!(matches!(
            store.append_many_folders(&["Keep", "Missing"], &message),
            Err(MailError::NotFound(_))
        ));
        assert_eq!(store.open_folder("Keep", false).unwrap().messages.len(), 0);

        // 全部目标可用：每个文件夹各一份，顺序与入参对齐。
        store.create("Too").unwrap();
        let results = store
            .append_many_folders(&["Keep", "Too"], &message)
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1.len(), 1);
        assert_eq!(results[1].1.len(), 1);
        assert_eq!(store.open_folder("Keep", false).unwrap().messages.len(), 1);
        assert_eq!(store.open_folder("Too", false).unwrap().messages.len(), 1);
    }

    #[test]
    fn reserved_mailstack_prefix_is_rejected_as_a_mailbox_name() {
        let (_dir, _clock, store) = store();
        // `.{name}` 会与 `.mailstack-uidlist` 等侧车文件撞名。
        for name in [
            "mailstack-uidlist",
            "MailStack-UidList.lock",
            "MAILSTACK-anything",
        ] {
            assert!(store.create(name).is_err(), "{name:?} 必须被拒绝");
            assert!(normalize_folder_name(name).is_err(), "{name:?} 必须被拒绝");
        }
        // 不带保留前缀的近名不受影响。
        assert!(store.create("mailstack").is_ok());
        assert!(store.create("my-mailstack-uidlist").is_ok());
    }

    #[test]
    fn failed_rename_leaves_the_mailbox_tree_unchanged() {
        let (_dir, _clock, store) = store();
        store.create("Old").unwrap();
        store.create("Old.A").unwrap();
        store.create("Old.B").unwrap();
        // 预置一个冲突目录：父目录已改名、前几个子目录改完之后才会撞上它。
        std::fs::create_dir_all(_dir.path().join(".New.B")).unwrap();

        assert!(store.rename("Old", "New").is_err());
        // 已改名的父目录与子目录全部回滚。
        assert!(store.exists("Old").unwrap());
        assert!(store.exists("Old.A").unwrap());
        assert!(store.exists("Old.B").unwrap());
        assert!(!store.exists("New").unwrap());
        assert!(!store.exists("New.A").unwrap());
    }

    #[test]
    fn expunge_does_not_release_quota_for_already_missing_files() {
        let (_dir, _clock, store) = store();
        store.set_quota(Some(2), None).unwrap();
        let (_, first) = store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        let (_, second) = store
            .append("INBOX", b"two\r\n", &FlagSet::new(), None)
            .unwrap();
        // 外部删除第二封的文件（映射条目还在）：expunge 两封只应释放一封的用量。
        let base = store.open_folder("INBOX", false).unwrap();
        let second_base = base
            .messages
            .iter()
            .find(|message| message.uid == second)
            .unwrap()
            .base
            .clone();
        // 文件在 new/（未带标志），按 base 找到并删除。
        let new_dir = store.root().join("new");
        let victim = std::fs::read_dir(&new_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&second_base)
            })
            .unwrap();
        std::fs::remove_file(victim).unwrap();

        store.expunge("INBOX", &[first, second]).unwrap();
        assert_eq!(
            store.quota_status().unwrap().messages,
            1,
            "文件早已不在的 UID 不得再释放一封的配额"
        );
    }

    #[test]
    fn concurrent_flag_rename_and_expunge_never_reassigns_an_uid() {
        let (_dir, _clock, store) = store();
        let store = Arc::new(store);
        for _ in 0..40 {
            let (_, uid) = store
                .append("INBOX", b"x\r\n", &FlagSet::new(), None)
                .unwrap();
            let flagger_store = Arc::clone(&store);
            let expunger_store = Arc::clone(&store);
            let flagger = std::thread::spawn(move || {
                let _ = flagger_store.set_flags("INBOX", uid, &seen());
            });
            let expunger = std::thread::spawn(move || {
                let _ = expunger_store.expunge("INBOX", &[uid]);
            });
            flagger.join().unwrap();
            expunger.join().unwrap();

            let state = store.open_folder("INBOX", false).unwrap();
            assert!(state.messages.len() <= 1);
            if let Some(message) = state.messages.first() {
                assert_eq!(
                    message.uid, uid,
                    "同一封邮件不得在 UIDVALIDITY 不变的情况下换 UID"
                );
                let _ = store.expunge("INBOX", &[message.uid]);
            }
        }
    }

    #[test]
    fn append_many_preserves_order_flags_and_dates() {
        let (_dir, _clock, store) = store();
        let messages = vec![
            NewMessage {
                data: b"one\r\n".to_vec(),
                flags: FlagSet::new(),
                internal_date: Some(1_600_000_000),
            },
            NewMessage {
                data: b"two\r\n".to_vec(),
                flags: seen(),
                internal_date: None,
            },
            NewMessage {
                data: b"three\r\n".to_vec(),
                flags: FlagSet::new(),
                internal_date: None,
            },
        ];
        let (uidvalidity, uids) = store.append_many("INBOX", &messages).unwrap();
        assert!(uidvalidity > 0);
        assert_eq!(uids.len(), 3);
        assert!(uids[0] < uids[1] && uids[1] < uids[2]);
        let state = store.open_folder("INBOX", false).unwrap();
        assert_eq!(state.messages.len(), 3);
        assert_eq!(state.messages[0].uid, uids[0]);
        assert_eq!(state.messages[0].internal_date, 1_600_000_000);
        assert!(state.messages[1]
            .flags
            .contains(&Flag::System(SystemFlag::Seen)));
    }

    #[test]
    fn append_many_does_not_leave_files_when_the_mailbox_is_missing() {
        let (dir, _clock, store) = store();
        let messages = vec![NewMessage {
            data: b"x\r\n".to_vec(),
            flags: FlagSet::new(),
            internal_date: None,
        }];
        assert!(matches!(
            store.append_many("NoSuch", &messages),
            Err(MailError::NotFound(_))
        ));
        // INBOX 的 tmp/cur/new 不应出现任何残留。
        for directory in ["tmp", "cur", "new"] {
            let count = std::fs::read_dir(dir.path().join(directory))
                .unwrap()
                .count();
            assert_eq!(count, 0, "{directory} 不得有残留文件");
        }
    }

    #[test]
    fn special_use_defaults_can_be_overridden_and_cleared() {
        let (_dir, _clock, store) = store();
        store.create("Sent").unwrap();
        assert_eq!(store.special_use("Sent").unwrap(), vec!["\\Sent"]);
        assert_eq!(
            store.special_use_map().unwrap().get("Sent").unwrap(),
            &vec!["\\Sent".to_string()]
        );

        store.create("Projects").unwrap();
        store
            .set_special_use("Projects", &["\\Archive".to_string()])
            .unwrap();
        assert_eq!(store.special_use("Projects").unwrap(), vec!["\\Archive"]);
        assert!(store
            .set_special_use("Projects", &["\\Bogus".into()])
            .is_err());

        store.set_special_use("Projects", &[]).unwrap();
        assert!(store.special_use("Projects").unwrap().is_empty());
    }

    #[test]
    fn modseq_is_persisted_and_increases_on_flag_changes() {
        let (_dir, _clock, store) = store();
        store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        store
            .append("INBOX", b"two\r\n", &FlagSet::new(), None)
            .unwrap();
        let before = store.open_folder("INBOX", false).unwrap();
        assert_eq!(before.highest_modseq, 2);
        assert_eq!(before.messages[0].modseq, 1);
        assert_eq!(before.messages[1].modseq, 2);

        let uid = before.messages[0].uid;
        let updated = store.set_flags("INBOX", uid, &seen()).unwrap();
        assert_eq!(updated.modseq, 3);
        let after = store.open_folder("INBOX", false).unwrap();
        assert_eq!(after.highest_modseq, 3);
        assert_eq!(
            after
                .messages
                .iter()
                .find(|message| message.uid == uid)
                .unwrap()
                .modseq,
            3
        );
    }

    #[test]
    fn uidlist_v1_is_migrated_to_v2_with_modseq() {
        let (dir, _clock, store) = store();
        store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        let state = store.open_folder("INBOX", false).unwrap();
        let base = state.messages[0].base.clone();
        std::fs::write(
            dir.path().join(".mailstack-uidlist"),
            format!("MAILSTACK-UIDLIST 1\nuidvalidity 4242\nuidnext 2\n1 {base}\n"),
        )
        .unwrap();

        let migrated = store.open_folder("INBOX", false).unwrap();
        assert_eq!(migrated.uidvalidity, 4242);
        assert_eq!(migrated.highest_modseq, 1);
        assert_eq!(migrated.messages[0].modseq, 1);

        store
            .set_flags("INBOX", migrated.messages[0].uid, &seen())
            .unwrap();
        let contents = std::fs::read_to_string(dir.path().join(".mailstack-uidlist")).unwrap();
        assert!(contents.starts_with("MAILSTACK-UIDLIST 2\n"));
        assert!(contents.contains("highestmodseq 2"));
    }

    #[test]
    fn expunge_records_qresync_vanished_events() {
        let (_dir, _clock, store) = store();
        store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        store
            .append("INBOX", b"two\r\n", &FlagSet::new(), None)
            .unwrap();
        let before = store.open_folder("INBOX", false).unwrap();
        let uid = before.messages[0].uid;
        let since = before.highest_modseq;
        store.expunge("INBOX", &[uid]).unwrap();

        let after = store.open_folder("INBOX", false).unwrap();
        assert!(after.highest_modseq > since);
        assert_eq!(
            store.expunged_since("INBOX", since).unwrap(),
            vec![uid],
            "QRESYNC 必须能看到消失的 UID"
        );
        assert!(store
            .expunged_since("INBOX", after.highest_modseq)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn quota_limits_message_count_and_releases_on_expunge() {
        let (_dir, _clock, store) = store();
        store.set_quota(Some(2), None).unwrap();
        let (_, first) = store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        store
            .append("INBOX", b"two\r\n", &FlagSet::new(), None)
            .unwrap();
        assert!(matches!(
            store.append("INBOX", b"three\r\n", &FlagSet::new(), None),
            Err(MailError::QuotaExceeded(_))
        ));
        let status = store.quota_status().unwrap();
        assert_eq!(status.messages, 2);
        assert_eq!(status.limits.messages, Some(2));

        store.expunge("INBOX", &[first]).unwrap();
        assert_eq!(store.quota_status().unwrap().messages, 1);
        assert!(store
            .append("INBOX", b"three\r\n", &FlagSet::new(), None)
            .is_ok());
    }

    #[test]
    fn quota_limits_storage_bytes() {
        let (_dir, _clock, store) = store();
        store.set_quota(None, Some(20)).unwrap();
        assert!(store
            .append("INBOX", b"0123456789\r\n", &FlagSet::new(), None)
            .is_ok());
        assert!(matches!(
            store.append("INBOX", b"0123456789\r\n", &FlagSet::new(), None),
            Err(MailError::QuotaExceeded(_))
        ));
        assert_eq!(store.quota_status().unwrap().bytes, 12);
    }

    #[test]
    fn setting_a_quota_discards_a_stale_usage_cache() {
        let (_dir, _clock, store) = store();
        // 先算一次用量（写入 0），再在无配额状态下投递一封（当时不更新缓存）。
        assert_eq!(store.quota_status().unwrap().messages, 0);
        store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        store.set_quota(Some(1), None).unwrap();
        assert!(matches!(
            store.append("INBOX", b"two\r\n", &FlagSet::new(), None),
            Err(MailError::QuotaExceeded(_))
        ));
    }

    #[test]
    fn deleting_a_folder_releases_quota_usage() {
        let (_dir, _clock, store) = store();
        store.set_quota(Some(2), None).unwrap();
        store.create("Temp").unwrap();
        store
            .append("Temp", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        store
            .append("Temp", b"two\r\n", &FlagSet::new(), None)
            .unwrap();
        assert_eq!(store.quota_status().unwrap().messages, 2);
        store.delete("Temp").unwrap();
        assert_eq!(store.quota_status().unwrap().messages, 0);
        store
            .append("INBOX", b"one\r\n", &FlagSet::new(), None)
            .unwrap();
        store
            .append("INBOX", b"two\r\n", &FlagSet::new(), None)
            .unwrap();
    }

    #[test]
    fn flag_set_cannot_carry_recent_and_keywords_are_ascii() {
        assert!(Flag::parse_imap("\\Recent").is_none());
        assert!(Flag::parse_imap("\\Nonsense").is_none());
        assert_eq!(
            Flag::parse_imap("Junk").unwrap(),
            Flag::Keyword("junk".into())
        );
        assert!(Flag::parse_imap("bad keyword").is_none());
    }
}

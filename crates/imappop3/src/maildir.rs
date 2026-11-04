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

const EXPUNGED: &str = ".mailstack-expunged";
const EXPUNGED_MAX_BYTES: u64 = 8 * 1024 * 1024;
const QUOTA: &str = ".mailstack-quota";
const QUOTA_LOCK: &str = ".mailstack-quota.lock";

const METADATA: &str = ".mailstack-metadata";
const METADATA_LOCK: &str = ".mailstack-metadata.lock";

const SERVER_METADATA: &str = ".mailstack-metadata-server";
const SERVER_METADATA_LOCK: &str = ".mailstack-metadata-server.lock";

const ACL: &str = ".mailstack-acl";
const ACL_LOCK: &str = ".mailstack-acl.lock";
const USAGE: &str = ".mailstack-usage";
const SUBSCRIPTIONS: &str = "subscriptions";
const SUBSCRIPTIONS_LOCK: &str = "subscriptions.lock";

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

#[derive(Debug, Clone)]
pub struct MessageMeta {
    pub uid: u32,

    pub base: String,

    pub filename: String,
    pub path: PathBuf,
    pub size: u64,

    pub internal_date: i64,

    pub modseq: u64,
    pub flags: FlagSet,

    pub recent: bool,
}

#[derive(Debug, Clone)]
pub struct NewMessage {
    pub data: Vec<u8>,
    pub flags: FlagSet,
    pub internal_date: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaLimits {
    pub messages: Option<u32>,

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

pub fn is_inbox(name: &str) -> bool {
    name.eq_ignore_ascii_case(INBOX)
}

const RESERVED_FOLDER_PREFIX: &str = "mailstack-";

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

pub struct MailStore {
    root: PathBuf,
    clock: Arc<dyn Clock>,
}

impl MailStore {
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

    pub fn set_quota(&self, messages: Option<u32>, storage_bytes: Option<u64>) -> Result<()> {
        with_lock(&self.root.join(QUOTA_LOCK), || {
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

    pub fn append(
        &self,
        folder: &str,
        data: &[u8],
        flags: &FlagSet,
        internal_date: Option<i64>,
    ) -> Result<(u32, u32)> {
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
                let _ = fs::remove_file(&destination);
                Err(error)
            }
        }
    }

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

    pub fn append_many_folders(
        &self,
        folders: &[&str],
        message: &NewMessage,
    ) -> Result<Vec<(u32, Vec<u32>)>> {
        if folders.is_empty() {
            return Err(MailError::invalid("no folders to deliver to"));
        }

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

    pub fn set_flags(&self, folder: &str, uid: u32, flags: &FlagSet) -> Result<MessageMeta> {
        let path = self.folder_path(folder)?;
        if !path.is_dir() {
            return Err(MailError::not_found(folder));
        }

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

    pub fn expunge(&self, folder: &str, uids: &[u32]) -> Result<usize> {
        let path = self.folder_path(folder)?;
        if !path.is_dir() {
            return Err(MailError::not_found(folder));
        }
        with_lock(&path.join(UIDLIST_LOCK), || {
            let mut list = load_uidlist(&path.join(UIDLIST))?.unwrap_or_default();

            let mut removed_uids: Vec<u32> = Vec::new();
            let mut removed_bytes = 0u64;
            for uid in uids {
                let Some((base, _)) = list.by_uid.get(uid) else {
                    continue;
                };

                let Some((directory, filename)) = find_file(&path, base)? else {
                    continue;
                };
                let file = path.join(directory).join(&filename);

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
                continue;
            }

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

#[derive(Debug, Clone, Default)]
struct UidList {
    uidvalidity: u32,
    uidnext: u32,
    highest_modseq: u64,

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UidImport {
    pub mapped: usize,

    pub unresolved: usize,
}

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

impl MailStore {
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

pub(crate) fn with_lock<T>(lock_path: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|error| MailError::io(parent, error))?;
    }
    let file = open_private(lock_path, false).map_err(|error| MailError::io(lock_path, error))?;
    fs2::FileExt::lock_exclusive(&file).map_err(|error| MailError::io(lock_path, error))?;
    let result = action();

    if let Err(error) = fs2::FileExt::unlock(&file) {
        tracing::warn!(path = %lock_path.display(), %error, "failed to unlock");
    }
    result
}

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

        let mut server = BTreeMap::new();
        server.insert("/private/vendor/example".to_string(), b"s".to_vec());
        store.write_metadata(None, &server).unwrap();
        assert_eq!(store.read_metadata(None).unwrap(), server);
        assert_eq!(store.read_metadata(Some("Notes")).unwrap(), map);

        let mut trimmed = map.clone();
        trimmed.remove("/private/comment");
        store.write_metadata(Some("Notes"), &trimmed).unwrap();
        assert_eq!(store.read_metadata(Some("Notes")).unwrap(), trimmed);

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

        assert!(matches!(
            store.append_many_folders(&["Keep", "Missing"], &message),
            Err(MailError::NotFound(_))
        ));
        assert_eq!(store.open_folder("Keep", false).unwrap().messages.len(), 0);

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

        for name in [
            "mailstack-uidlist",
            "MailStack-UidList.lock",
            "MAILSTACK-anything",
        ] {
            assert!(store.create(name).is_err(), "{name:?} 必须被拒绝");
            assert!(normalize_folder_name(name).is_err(), "{name:?} 必须被拒绝");
        }

        assert!(store.create("mailstack").is_ok());
        assert!(store.create("my-mailstack-uidlist").is_ok());
    }

    #[test]
    fn failed_rename_leaves_the_mailbox_tree_unchanged() {
        let (_dir, _clock, store) = store();
        store.create("Old").unwrap();
        store.create("Old.A").unwrap();
        store.create("Old.B").unwrap();

        std::fs::create_dir_all(_dir.path().join(".New.B")).unwrap();

        assert!(store.rename("Old", "New").is_err());

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

        let base = store.open_folder("INBOX", false).unwrap();
        let second_base = base
            .messages
            .iter()
            .find(|message| message.uid == second)
            .unwrap()
            .base
            .clone();

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

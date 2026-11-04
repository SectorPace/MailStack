use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use mailstack_imappop3::maildir::{
    self, Flag, FlagSet, FolderState, MailStore, MessageMeta, SystemClock, SystemFlag,
};
use mailstack_imappop3::mime;

use crate::account::Account;
use crate::error::{WebmailError, WebmailResult};
use crate::mime_view::{self, AddressView, AttachmentView, HeadersView};
use crate::sanitize::{self, SanitizeOptions};
use crate::{
    MAX_BATCH_UIDS, MAX_DETAIL_BYTES, MAX_LIST_LIMIT, MAX_RAW_BYTES, MAX_SEARCH_QUERY_CHARS,
    MAX_SEARCH_SCAN, MAX_SUBJECT_CHARS, MESSAGE_PREFIX_BYTES, SEARCH_TEXT_BYTES,
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FolderItem {
    pub name: String,
    pub special_use: Vec<String>,
    pub subscribed: bool,
    pub total: u32,
    pub unseen: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessageSummary {
    pub uid: u32,
    pub flags: Vec<String>,
    pub size: u64,
    pub from: AddressView,
    pub to: Vec<AddressView>,
    pub subject: String,
    pub date: String,
    pub snippet: String,
    pub has_attachments: bool,
    pub message_id: Option<String>,
    pub thread_key: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessageList {
    pub folder: String,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub messages: Vec<MessageSummary>,

    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BodyView {
    pub text: Option<String>,

    pub html: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessageDetail {
    pub uid: u32,
    pub folder: String,
    pub flags: Vec<String>,
    pub size: u64,
    pub headers: HeadersView,
    pub body: BodyView,
    pub attachments: Vec<AttachmentView>,
    pub remote_images_blocked: u32,
}

#[derive(Debug, Clone)]
pub struct RawMessage {
    pub data: Vec<u8>,

    pub filename: String,
}

#[derive(Debug, Clone)]
pub struct PartData {
    pub data: Vec<u8>,
    pub content_type: String,
    pub filename: Option<String>,
    pub disposition: Option<String>,
    pub inline: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuotaView {
    pub messages: u64,
    pub storage_bytes: u64,
    pub limits: QuotaLimitsView,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuotaLimitsView {
    pub messages: Option<u32>,
    pub storage_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FlagPatch {
    pub seen: Option<bool>,
    pub flagged: Option<bool>,
    pub answered: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ListOptions {
    pub offset: usize,
    pub limit: usize,
    pub unread_only: bool,
    pub flagged_only: bool,
    pub sort: SortOrder,

    pub query: Option<String>,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: crate::DEFAULT_LIST_LIMIT,
            unread_only: false,
            flagged_only: false,
            sort: SortOrder::DateDesc,
            query: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    DateDesc,
    DateAsc,
}

impl SortOrder {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "date_desc" => Some(SortOrder::DateDesc),
            "date_asc" => Some(SortOrder::DateAsc),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchRequest {
    pub folder: String,
    #[serde(default)]
    pub uids: Vec<u32>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MoveResult {
    pub uid: u32,
    pub folder: String,
}

#[derive(Debug, Clone)]
pub struct MaildirService {
    maildir: std::path::PathBuf,
}

impl MaildirService {
    pub fn new(account: &Account) -> Self {
        Self {
            maildir: account.maildir.clone(),
        }
    }

    pub fn list_folders(&self) -> WebmailResult<Vec<FolderItem>> {
        let store = self.open_store()?;
        let names = store.folders().map_err(WebmailError::from_mail)?;
        let special_use_map = store.special_use_map().map_err(WebmailError::from_mail)?;
        let subscriptions: HashSet<String> = store
            .subscriptions()
            .map_err(WebmailError::from_mail)?
            .into_iter()
            .collect();

        let mut items = Vec::with_capacity(names.len());
        for name in &names {
            let status = store
                .open_folder(name, false)
                .map_err(WebmailError::from_mail)?
                .status();
            let special_use =
                special_use_names(name, special_use_map.get(name).map(std::vec::Vec::as_slice));
            items.push(FolderItem {
                name: name.clone(),
                special_use,
                subscribed: subscriptions.contains(name),
                total: status.messages,
                unseen: status.unseen,
            });
        }

        items.sort_by(|a, b| {
            let inbox_a = a.name != maildir::INBOX;
            let inbox_b = b.name != maildir::INBOX;
            inbox_a
                .cmp(&inbox_b)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(items)
    }

    pub fn create_folder(&self, name: &str) -> WebmailResult<String> {
        let normalized = maildir::normalize_folder_name(name).map_err(WebmailError::from_mail)?;
        if normalized == maildir::INBOX {
            return Err(WebmailError::conflict(
                "FOLDER_EXISTS",
                "INBOX always exists and cannot be created",
            ));
        }
        let store = self.open_store()?;
        store.create(&normalized).map_err(map_folder_create_error)?;
        Ok(normalized)
    }

    pub fn rename_folder(&self, from: &str, to: &str) -> WebmailResult<String> {
        let from = maildir::normalize_folder_name(from).map_err(WebmailError::from_mail)?;
        let to = maildir::normalize_folder_name(to).map_err(WebmailError::from_mail)?;
        if from == maildir::INBOX {
            return Err(WebmailError::bad_request(
                "INVALID_FOLDER",
                "INBOX cannot be renamed",
            ));
        }
        let store = self.open_store()?;
        store.rename(&from, &to).map_err(WebmailError::from_mail)?;
        Ok(to)
    }

    pub fn delete_folder(&self, name: &str) -> WebmailResult<()> {
        let normalized = maildir::normalize_folder_name(name).map_err(WebmailError::from_mail)?;
        if normalized == maildir::INBOX {
            return Err(WebmailError::bad_request(
                "INVALID_FOLDER",
                "INBOX cannot be deleted",
            ));
        }
        let store = self.open_store()?;
        if !store.exists(&normalized).map_err(WebmailError::from_mail)? {
            return Err(WebmailError::not_found("folder not found"));
        }
        let state = store
            .open_folder(&normalized, false)
            .map_err(WebmailError::from_mail)?;
        let has_children = store
            .has_children(&normalized)
            .map_err(WebmailError::from_mail)?;
        if !state.messages.is_empty() || has_children {
            return Err(WebmailError::conflict(
                "FOLDER_NOT_EMPTY",
                "folder is not empty and cannot be deleted",
            ));
        }
        store.delete(&normalized).map_err(WebmailError::from_mail)
    }

    pub fn list_messages(&self, folder: &str, options: &ListOptions) -> WebmailResult<MessageList> {
        if let Some(query) = options.query.as_deref().filter(|q| !q.trim().is_empty()) {
            return self.search(folder, query, options.offset, options.limit);
        }
        let normalized = maildir::normalize_folder_name(folder).map_err(WebmailError::from_mail)?;
        let store = self.open_store()?;
        let state = store
            .open_folder(&normalized, false)
            .map_err(WebmailError::from_mail)?;

        let mut messages: Vec<&MessageMeta> = state
            .messages
            .iter()
            .filter(|message| {
                if options.unread_only && has_flag(&message.flags, SystemFlag::Seen) {
                    return false;
                }
                if options.flagged_only && !has_flag(&message.flags, SystemFlag::Flagged) {
                    return false;
                }
                true
            })
            .collect();
        sort_messages(&mut messages, options.sort);
        let total = messages.len();
        let offset = options.offset.min(total);
        let limit = options.limit.clamp(1, MAX_LIST_LIMIT);
        let page: Vec<&MessageMeta> = messages.into_iter().skip(offset).take(limit).collect();
        let summaries = self.summaries(&store, &page)?;
        Ok(MessageList {
            folder: normalized,
            total,
            offset,
            limit,
            messages: summaries,
            truncated: false,
        })
    }

    pub fn search(
        &self,
        folder: &str,
        query: &str,
        offset: usize,
        limit: usize,
    ) -> WebmailResult<MessageList> {
        let query = query.trim();
        if query.is_empty() {
            return Err(WebmailError::bad_request(
                "INVALID_QUERY",
                "search query must not be empty",
            ));
        }
        if query.chars().count() > MAX_SEARCH_QUERY_CHARS {
            return Err(WebmailError::bad_request(
                "INVALID_QUERY",
                format!("search query must be at most {MAX_SEARCH_QUERY_CHARS} characters"),
            ));
        }
        let normalized = maildir::normalize_folder_name(folder).map_err(WebmailError::from_mail)?;
        let store = self.open_store()?;
        let state = store
            .open_folder(&normalized, false)
            .map_err(WebmailError::from_mail)?;
        let total_in_folder = state.messages.len();

        let mut candidates: Vec<&MessageMeta> = state.messages.iter().collect();
        sort_messages(&mut candidates, SortOrder::DateDesc);

        let needle = query.to_lowercase();
        let mut matched: Vec<&MessageMeta> = Vec::new();
        let mut scanned = 0usize;
        for meta in candidates.iter().take(MAX_SEARCH_SCAN) {
            scanned += 1;

            let Ok(prefix) = store.read_prefix(meta, SEARCH_TEXT_BYTES) else {
                continue;
            };
            if mime_view::searchable_text(&prefix).contains(&needle) {
                matched.push(meta);
            }
        }
        let total = matched.len();
        let truncated = total_in_folder > scanned;
        let offset = offset.min(total);
        let limit = limit.clamp(1, MAX_LIST_LIMIT);
        let page: Vec<&MessageMeta> = matched.into_iter().skip(offset).take(limit).collect();
        let summaries = self.summaries(&store, &page)?;
        Ok(MessageList {
            folder: normalized,
            total,
            offset,
            limit,
            messages: summaries,
            truncated,
        })
    }

    fn summaries(
        &self,
        store: &MailStore,
        messages: &[&MessageMeta],
    ) -> WebmailResult<Vec<MessageSummary>> {
        let mut out = Vec::with_capacity(messages.len());
        for meta in messages {
            out.push(self.summary(store, meta));
        }
        Ok(out)
    }

    fn summary(&self, store: &MailStore, meta: &MessageMeta) -> MessageSummary {
        let prefix = store
            .read_prefix(meta, MESSAGE_PREFIX_BYTES)
            .unwrap_or_default();
        let fields = mime_view::summary_fields(&prefix);
        let date = fields
            .date
            .or_else(|| internal_date_string(meta.internal_date))
            .unwrap_or_default();
        let thread_key = mime_view::thread_key(&fields.subject, fields.message_id.as_deref());
        MessageSummary {
            uid: meta.uid,
            flags: flag_names(&meta.flags),
            size: meta.size,
            from: fields.from.unwrap_or_default(),
            to: fields.to,
            subject: fields.subject,
            date,
            snippet: fields.snippet,
            has_attachments: fields.has_attachments,
            message_id: fields.message_id,
            thread_key,
        }
    }

    pub fn message_detail(
        &self,
        folder: &str,
        uid: u32,
        allow_remote_images: bool,
    ) -> WebmailResult<MessageDetail> {
        let (normalized, store, meta) = self.locate(folder, uid)?;
        let truncated_read = meta.size > MAX_DETAIL_BYTES as u64;
        let data = if truncated_read {
            store
                .read_prefix(&meta, MAX_DETAIL_BYTES)
                .map_err(WebmailError::from_mail)?
        } else {
            store.read(&meta).map_err(WebmailError::from_mail)?
        };
        let parsed = mime_view::parse_message(&data);

        let mut cid_urls: HashMap<String, String> = HashMap::new();
        for attachment in &parsed.attachments {
            if let Some(cid) = attachment.cid.as_deref() {
                let url = part_url(&normalized, uid, &attachment.part_id);
                cid_urls.insert(cid.to_string(), url.clone());
                cid_urls.insert(cid.to_ascii_lowercase(), url);
            }
        }
        let options = SanitizeOptions {
            allow_remote_images,
            cid_urls: &cid_urls,
        };
        let sanitized = match parsed.html.as_deref() {
            Some(html) if !html.is_empty() => sanitize::sanitize_html(html, &options),
            _ => sanitize::SanitizeOutcome {
                html: String::new(),
                remote_images_blocked: 0,
            },
        };
        let html = if sanitized.html.is_empty() {
            None
        } else {
            Some(sanitized.html)
        };

        Ok(MessageDetail {
            uid,
            folder: normalized,
            flags: flag_names(&meta.flags),
            size: meta.size,
            headers: parsed.headers,
            body: BodyView {
                text: parsed.text,
                html,
                truncated: parsed.body_truncated || truncated_read,
            },
            attachments: parsed.attachments,
            remote_images_blocked: sanitized.remote_images_blocked,
        })
    }

    pub fn raw_message(&self, folder: &str, uid: u32) -> WebmailResult<RawMessage> {
        let (_normalized, store, meta) = self.locate(folder, uid)?;
        if meta.size > MAX_RAW_BYTES as u64 {
            return Err(WebmailError::payload_too_large(
                "raw message exceeds the download size limit",
            ));
        }
        let data = store.read(&meta).map_err(WebmailError::from_mail)?;
        let headers = mime::parse_headers(&data);
        let subject = mime_view::decode_rfc2047(headers.get("subject").unwrap_or(""));
        let subject: String = subject.chars().take(MAX_SUBJECT_CHARS).collect();
        let stem = crate::compose::sanitize_filename(&subject);
        let filename = format!("{stem}.eml");
        Ok(RawMessage { data, filename })
    }

    pub fn part(&self, folder: &str, uid: u32, part_id: &str) -> WebmailResult<PartData> {
        let (_normalized, store, meta) = self.locate(folder, uid)?;
        if meta.size > MAX_DETAIL_BYTES as u64 {
            return Err(WebmailError::payload_too_large(
                "message is too large to extract a part from",
            ));
        }
        if part_id.is_empty()
            || part_id.len() > 64
            || !part_id.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
        {
            return Err(WebmailError::bad_request(
                "INVALID_PART",
                "part id must be a dotted digit sequence",
            ));
        }
        let data = store.read(&meta).map_err(WebmailError::from_mail)?;
        let structure = mime_view::collect_parts(&data, MAX_DETAIL_BYTES);
        let leaf = structure
            .leaves
            .into_iter()
            .find(|leaf| leaf.part_id == part_id)
            .ok_or_else(|| WebmailError::not_found("message part not found"))?;
        let inline = leaf.is_inline();
        Ok(PartData {
            data: leaf.data,
            content_type: leaf.content_type,
            filename: leaf.filename,
            disposition: leaf.disposition,
            inline,
        })
    }

    pub fn patch_flags(
        &self,
        folder: &str,
        uid: u32,
        patch: &FlagPatch,
    ) -> WebmailResult<Vec<String>> {
        let (normalized, store, meta) = self.locate(folder, uid)?;
        let mut flags = meta.flags.clone();
        apply_flag(&mut flags, SystemFlag::Seen, patch.seen);
        apply_flag(&mut flags, SystemFlag::Flagged, patch.flagged);
        apply_flag(&mut flags, SystemFlag::Answered, patch.answered);
        let updated = store
            .set_flags(&normalized, uid, &flags)
            .map_err(WebmailError::from_mail)?;
        Ok(flag_names(&updated.flags))
    }

    pub fn move_message(
        &self,
        folder: &str,
        uid: u32,
        target: &str,
        copy_only: bool,
    ) -> WebmailResult<MoveResult> {
        let normalized_from =
            maildir::normalize_folder_name(folder).map_err(WebmailError::from_mail)?;
        let normalized_to =
            maildir::normalize_folder_name(target).map_err(WebmailError::from_mail)?;
        let store = self.open_store()?;
        let state = store
            .open_folder(&normalized_from, false)
            .map_err(WebmailError::from_mail)?;
        if state.position_of_uid(uid).is_none() {
            return Err(WebmailError::not_found("message not found"));
        }
        if !store
            .exists(&normalized_to)
            .map_err(WebmailError::from_mail)?
        {
            return Err(WebmailError::not_found("target folder not found"));
        }
        let (_, new_uid) = store
            .copy(&normalized_from, uid, &normalized_to)
            .map_err(WebmailError::from_mail)?;
        if !copy_only {
            store
                .expunge(&normalized_from, &[uid])
                .map_err(WebmailError::from_mail)?;
        }
        Ok(MoveResult {
            uid: new_uid,
            folder: normalized_to,
        })
    }

    pub fn delete_message(&self, folder: &str, uid: u32) -> WebmailResult<()> {
        let (normalized, store, meta) = self.locate(folder, uid)?;
        let mut flags = meta.flags.clone();
        flags.insert(Flag::System(SystemFlag::Deleted));
        store
            .set_flags(&normalized, uid, &flags)
            .map_err(WebmailError::from_mail)?;
        store
            .expunge(&normalized, &[uid])
            .map_err(WebmailError::from_mail)?;
        Ok(())
    }

    pub fn batch(&self, request: &BatchRequest) -> WebmailResult<usize> {
        if request.uids.is_empty() {
            return Ok(0);
        }
        if request.uids.len() > MAX_BATCH_UIDS {
            return Err(WebmailError::bad_request(
                "TOO_MANY_UIDS",
                format!("at most {MAX_BATCH_UIDS} uids can be batched at once"),
            ));
        }
        let normalized =
            maildir::normalize_folder_name(&request.folder).map_err(WebmailError::from_mail)?;
        let action = request.action.trim().to_ascii_lowercase();
        let store = self.open_store()?;
        let state = store
            .open_folder(&normalized, false)
            .map_err(WebmailError::from_mail)?;
        let available: HashMap<u32, &MessageMeta> = state
            .messages
            .iter()
            .map(|message| (message.uid, message))
            .collect();
        let uids: Vec<u32> = request
            .uids
            .iter()
            .copied()
            .filter(|uid| available.contains_key(uid))
            .collect();
        if uids.is_empty() {
            return Ok(0);
        }

        match action.as_str() {
            "move" | "copy" => {
                let target = request.target.as_deref().ok_or_else(|| {
                    WebmailError::bad_request(
                        "INVALID_REQUEST",
                        "move/copy requires a target folder",
                    )
                })?;
                let target =
                    maildir::normalize_folder_name(target).map_err(WebmailError::from_mail)?;
                if !store.exists(&target).map_err(WebmailError::from_mail)? {
                    return Err(WebmailError::not_found("target folder not found"));
                }
                store
                    .copy_many(&normalized, &uids, &target)
                    .map_err(WebmailError::from_mail)?;
                if action == "move" {
                    store
                        .expunge(&normalized, &uids)
                        .map_err(WebmailError::from_mail)?;
                }
                Ok(uids.len())
            }
            "delete" => {
                for uid in &uids {
                    let mut flags = available
                        .get(uid)
                        .map(|meta| meta.flags.clone())
                        .unwrap_or_default();
                    flags.insert(Flag::System(SystemFlag::Deleted));
                    store
                        .set_flags(&normalized, *uid, &flags)
                        .map_err(WebmailError::from_mail)?;
                }
                store
                    .expunge(&normalized, &uids)
                    .map_err(WebmailError::from_mail)?;
                Ok(uids.len())
            }
            "mark_seen" | "mark_unseen" | "flag" | "unflag" => {
                for uid in &uids {
                    let Some(meta) = available.get(uid) else {
                        continue;
                    };
                    let mut flags = meta.flags.clone();
                    match action.as_str() {
                        "mark_seen" => {
                            flags.insert(Flag::System(SystemFlag::Seen));
                        }
                        "mark_unseen" => {
                            flags.remove(&Flag::System(SystemFlag::Seen));
                        }
                        "flag" => {
                            flags.insert(Flag::System(SystemFlag::Flagged));
                        }
                        "unflag" => {
                            flags.remove(&Flag::System(SystemFlag::Flagged));
                        }
                        _ => {}
                    }
                    store
                        .set_flags(&normalized, *uid, &flags)
                        .map_err(WebmailError::from_mail)?;
                }
                Ok(uids.len())
            }
            _ => Err(WebmailError::bad_request(
                "INVALID_ACTION",
                "unknown batch action",
            )),
        }
    }

    pub fn quota(&self) -> WebmailResult<QuotaView> {
        let store = self.open_store()?;
        let status = store.quota_status().map_err(WebmailError::from_mail)?;
        Ok(QuotaView {
            messages: status.messages,
            storage_bytes: status.bytes,
            limits: QuotaLimitsView {
                messages: status.limits.messages,
                storage_bytes: status.limits.storage_bytes,
            },
        })
    }

    fn open_store(&self) -> WebmailResult<MailStore> {
        MailStore::new(&self.maildir, Arc::new(SystemClock)).map_err(WebmailError::from_mail)
    }

    fn locate(&self, folder: &str, uid: u32) -> WebmailResult<(String, MailStore, MessageMeta)> {
        let normalized = maildir::normalize_folder_name(folder).map_err(WebmailError::from_mail)?;
        let store = self.open_store()?;
        let state: FolderState = store
            .open_folder(&normalized, false)
            .map_err(WebmailError::from_mail)?;
        let Some(index) = state.position_of_uid(uid) else {
            return Err(WebmailError::not_found("message not found"));
        };
        let meta = state.messages[index].clone();
        Ok((normalized, store, meta))
    }
}

fn special_use_names(name: &str, raw: Option<&[String]>) -> Vec<String> {
    let mut names: Vec<String> = raw
        .map(|attributes| {
            attributes
                .iter()
                .filter_map(|attribute| {
                    let value = attribute.trim_start_matches('\\').to_ascii_lowercase();
                    match value.as_str() {
                        "all" => Some("all".to_string()),
                        "archive" => Some("archive".to_string()),
                        "drafts" => Some("drafts".to_string()),
                        "flagged" => Some("flagged".to_string()),
                        "junk" => Some("junk".to_string()),
                        "sent" => Some("sent".to_string()),
                        "trash" => Some("trash".to_string()),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    if name.eq_ignore_ascii_case(maildir::INBOX) && !names.iter().any(|value| value == "inbox") {
        names.push("inbox".to_string());
    }
    const ORDER: [&str; 8] = [
        "inbox", "sent", "drafts", "trash", "junk", "archive", "flagged", "all",
    ];
    names.sort_by_key(|value| {
        ORDER
            .iter()
            .position(|known| known == value)
            .unwrap_or(ORDER.len())
    });
    names.dedup();
    names
}

pub fn flag_names(flags: &FlagSet) -> Vec<String> {
    let mut names = Vec::with_capacity(flags.len());
    for flag in flags {
        match flag {
            Flag::System(system) => names.push(
                match system {
                    SystemFlag::Seen => "seen",
                    SystemFlag::Flagged => "flagged",
                    SystemFlag::Answered => "answered",
                    SystemFlag::Deleted => "deleted",
                    SystemFlag::Draft => "draft",
                }
                .to_string(),
            ),
            Flag::Keyword(keyword) => names.push(keyword.clone()),
        }
    }
    names
}

fn has_flag(flags: &FlagSet, system: SystemFlag) -> bool {
    flags.contains(&Flag::System(system))
}

fn apply_flag(flags: &mut FlagSet, system: SystemFlag, value: Option<bool>) {
    match value {
        Some(true) => {
            flags.insert(Flag::System(system));
        }
        Some(false) => {
            flags.remove(&Flag::System(system));
        }
        None => {}
    }
}

fn sort_messages(messages: &mut Vec<&MessageMeta>, order: SortOrder) {
    messages.sort_by(|a, b| match order {
        SortOrder::DateDesc => b
            .internal_date
            .cmp(&a.internal_date)
            .then_with(|| b.uid.cmp(&a.uid)),
        SortOrder::DateAsc => a
            .internal_date
            .cmp(&b.internal_date)
            .then_with(|| a.uid.cmp(&b.uid)),
    });
}

fn internal_date_string(timestamp: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()
        .map(mime_view::format_rfc3339_utc)
}

fn part_url(folder: &str, uid: u32, part_id: &str) -> String {
    format!(
        "/mail/api/messages/{}/{}/parts/{}",
        url_encode_segment(folder),
        uid,
        url_encode_segment(part_id)
    )
}

pub fn url_encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn map_folder_create_error(error: mailstack_imappop3::error::MailError) -> WebmailError {
    match error {
        mailstack_imappop3::error::MailError::AlreadyExists(_) => {
            WebmailError::conflict("FOLDER_EXISTS", "folder already exists")
        }
        other => WebmailError::from_mail(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _root: tempfile::TempDir,
        service: MaildirService,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let maildir = root.path().join("Maildir");
            MailStore::new(&maildir, Arc::new(SystemClock)).unwrap();
            let account = crate::account::account_for_test("alice@example.com", maildir);
            Self {
                _root: root,
                service: MaildirService::new(&account),
            }
        }

        fn store(&self) -> MailStore {
            MailStore::new(&self.service.maildir, Arc::new(SystemClock)).unwrap()
        }

        fn append(&self, message: &str) -> u32 {
            let store = self.store();
            let (_, uid) = store
                .append("INBOX", message.as_bytes(), &FlagSet::new(), None)
                .unwrap();
            uid
        }
    }

    fn plain_message(subject: &str, body: &str) -> String {
        format!("From: Bob <bob@example.org>\r\nTo: alice@example.com\r\nSubject: {subject}\r\nDate: Fri, 23 Oct 2026 14:30:00 +0800\r\nMessage-ID: <{subject}@example.org>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n")
    }

    #[test]
    fn folders_are_listed_with_inbox_first_and_special_uses() {
        let fixture = Fixture::new();
        fixture.service.create_folder("Projects").unwrap();
        let store = fixture.store();
        store.create("Sent").unwrap();
        let folders = fixture.service.list_folders().unwrap();
        assert_eq!(folders[0].name, "INBOX");
        assert!(folders[0].special_use.contains(&"inbox".to_string()));
        let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"Projects"));
        let sent = folders.iter().find(|f| f.name == "Sent").unwrap();
        assert_eq!(sent.special_use, vec!["sent".to_string()]);
    }

    #[test]
    fn a_non_empty_folder_cannot_be_deleted_but_an_empty_one_can() {
        let fixture = Fixture::new();
        fixture.service.create_folder("Projects").unwrap();
        fixture.append(&plain_message("hello", "body"));

        let store = fixture.store();
        let inbox = store.open_folder("INBOX", false).unwrap();
        let uid = inbox.messages[0].uid;
        fixture
            .service
            .move_message("INBOX", uid, "Projects", false)
            .unwrap();
        let error = fixture.service.delete_folder("Projects").unwrap_err();
        assert_eq!(error.code, "FOLDER_NOT_EMPTY");
        assert_eq!(error.status, axum::http::StatusCode::CONFLICT);

        let projects = store.open_folder("Projects", false).unwrap();
        fixture
            .service
            .delete_message("Projects", projects.messages[0].uid)
            .unwrap();
        fixture.service.delete_folder("Projects").unwrap();
        assert!(!fixture
            .service
            .list_folders()
            .unwrap()
            .iter()
            .any(|f| f.name == "Projects"));
    }

    #[test]
    fn folder_names_are_normalized_and_path_traversal_is_rejected() {
        let fixture = Fixture::new();
        for bad in ["../etc", "..", "a/b", "a\\b", ".hidden", "", "mailstack-x"] {
            let error = fixture.service.create_folder(bad).unwrap_err();
            assert_eq!(
                error.status,
                axum::http::StatusCode::BAD_REQUEST,
                "{bad:?} 应回 400，实际 {:?}（{}）",
                error.status,
                error.code
            );

            assert!(fixture.service.delete_folder(bad).is_err());
        }
    }

    #[test]
    fn list_is_paginated_and_filters_by_unread_and_flagged() {
        let fixture = Fixture::new();
        for index in 0..5 {
            fixture.append(&plain_message(&format!("m{index}"), "body"));
        }
        let store = fixture.store();
        let state = store.open_folder("INBOX", false).unwrap();
        let uid = state.messages[1].uid;
        let mut flags = state.messages[1].flags.clone();
        flags.insert(Flag::System(SystemFlag::Seen));
        flags.insert(Flag::System(SystemFlag::Flagged));
        store.set_flags("INBOX", uid, &flags).unwrap();

        let page = fixture
            .service
            .list_messages(
                "INBOX",
                &ListOptions {
                    limit: 2,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(page.total, 5);
        assert_eq!(page.messages.len(), 2);
        assert!(!page.truncated);

        let unread = fixture
            .service
            .list_messages(
                "INBOX",
                &ListOptions {
                    unread_only: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(unread.total, 4);

        let flagged = fixture
            .service
            .list_messages(
                "INBOX",
                &ListOptions {
                    flagged_only: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(flagged.total, 1);
        assert_eq!(flagged.messages[0].uid, uid);
    }

    #[test]
    fn search_matches_subject_and_body_case_insensitively() {
        let fixture = Fixture::new();
        fixture.append(&plain_message("Quarterly Report", "unauthorized text"));
        fixture.append(&plain_message("Hello", "the PASSWORD reset link"));
        fixture.append(&plain_message("Other", "nothing here"));

        let by_subject = fixture.service.search("INBOX", "quarterly", 0, 50).unwrap();
        assert_eq!(by_subject.total, 1);
        assert_eq!(by_subject.messages[0].subject, "Quarterly Report");

        let by_body = fixture.service.search("INBOX", "password", 0, 50).unwrap();
        assert_eq!(by_body.total, 1);
        assert_eq!(by_body.messages[0].subject, "Hello");

        assert_eq!(
            fixture
                .service
                .search("INBOX", "   ", 0, 50)
                .unwrap_err()
                .code,
            "INVALID_QUERY"
        );
    }

    #[test]
    fn message_detail_sanitizes_html_and_blocks_remote_images() {
        let fixture = Fixture::new();
        let message = "From: Bob <bob@example.org>\r\nTo: alice@example.com\r\nSubject: xss\r\nDate: Fri, 23 Oct 2026 14:30:00 +0800\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p onclick=\"alert(1)\">hi<script>alert(1)</script><img src=\"https://evil.example/p.png\"></p>\r\n";
        let uid = fixture.append(message);
        let detail = fixture.service.message_detail("INBOX", uid, false).unwrap();
        let html = detail.body.html.expect("HTML 正文必须存在");
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("onclick"), "{html}");
        assert!(
            !html.contains("<img src="),
            "远程图片默认不得有 src：{html}"
        );
        assert!(html.contains("data-blocked-src=\"https://evil.example/p.png\""));
        assert_eq!(detail.remote_images_blocked, 1);

        let allowed = fixture.service.message_detail("INBOX", uid, true).unwrap();
        assert!(allowed
            .body
            .html
            .expect("HTML")
            .contains("src=\"https://evil.example/p.png\""));
    }

    #[test]
    fn parts_are_downloadable_by_imap_style_part_ids() {
        let fixture = Fixture::new();
        let message = "From: Bob <bob@example.org>\r\nSubject: files\r\nDate: Fri, 23 Oct 2026 14:30:00 +0800\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--b--\r\n";
        let uid = fixture.append(message);
        let part = fixture.service.part("INBOX", uid, "2").unwrap();
        assert_eq!(part.data, b"ABC");
        assert_eq!(part.content_type, "application/pdf");
        assert_eq!(part.filename.as_deref(), Some("a.pdf"));
        assert!(fixture.service.part("INBOX", uid, "9").is_err());
        assert!(fixture.service.part("INBOX", uid, "../2").is_err());
    }

    #[test]
    fn moving_copies_then_removes_the_source_and_copy_keeps_it() {
        let fixture = Fixture::new();
        fixture.service.create_folder("Archive").unwrap();
        let uid = fixture.append(&plain_message("move me", "body"));
        let copied = fixture
            .service
            .move_message("INBOX", uid, "Archive", true)
            .unwrap();
        assert_eq!(copied.folder, "Archive");
        let store = fixture.store();
        assert_eq!(store.open_folder("INBOX", false).unwrap().messages.len(), 1);

        let moved = fixture
            .service
            .move_message("INBOX", uid, "Archive", false)
            .unwrap();
        assert_ne!(moved.uid, copied.uid);
        assert_eq!(store.open_folder("INBOX", false).unwrap().messages.len(), 0);
        assert_eq!(
            store.open_folder("Archive", false).unwrap().messages.len(),
            2
        );
    }

    #[test]
    fn unknown_uid_is_not_found_and_never_touches_files() {
        let fixture = Fixture::new();
        let error = fixture
            .service
            .message_detail("INBOX", 9999, false)
            .unwrap_err();
        assert_eq!(error.code, "NOT_FOUND");
        assert_eq!(error.status, axum::http::StatusCode::NOT_FOUND);
        assert!(fixture.service.delete_message("INBOX", 9999).is_err());
        assert!(fixture.service.part("INBOX", 9999, "1").is_err());
    }

    #[test]
    fn batch_actions_apply_to_existing_uids_only() {
        let fixture = Fixture::new();
        fixture.service.create_folder("Archive").unwrap();
        let a = fixture.append(&plain_message("a", "body"));
        let b = fixture.append(&plain_message("b", "body"));
        let affected = fixture
            .service
            .batch(&BatchRequest {
                folder: "INBOX".to_string(),
                uids: vec![a, b, 9999],
                action: "mark_seen".to_string(),
                target: None,
            })
            .unwrap();
        assert_eq!(affected, 2);
        let store = fixture.store();
        let inbox = store.open_folder("INBOX", false).unwrap();
        assert!(inbox
            .messages
            .iter()
            .all(|message| has_flag(&message.flags, SystemFlag::Seen)));

        let unknown_action = fixture
            .service
            .batch(&BatchRequest {
                folder: "INBOX".to_string(),
                uids: vec![a],
                action: "explode".to_string(),
                target: None,
            })
            .unwrap_err();
        assert_eq!(unknown_action.code, "INVALID_ACTION");
    }

    #[test]
    fn quota_view_reports_usage_and_unlimited_limits() {
        let fixture = Fixture::new();
        fixture.append(&plain_message("q", "body"));
        let quota = fixture.service.quota().unwrap();
        assert_eq!(quota.messages, 1);
        assert!(quota.storage_bytes > 0);
        assert!(quota.limits.messages.is_none());
        assert!(quota.limits.storage_bytes.is_none());
    }

    #[test]
    fn raw_message_is_returned_with_a_safe_eml_filename() {
        let fixture = Fixture::new();
        let uid = fixture.append(&plain_message("../../etc/passwd", "body"));
        let raw = fixture.service.raw_message("INBOX", uid).unwrap();
        assert!(raw.data.starts_with(b"From: Bob"));
        assert!(raw.filename.ends_with(".eml"));
        assert!(!raw.filename.contains('/') && !raw.filename.contains('\\'));
    }

    #[test]
    fn special_use_mapping_is_canonical_and_ordered() {
        assert_eq!(special_use_names("INBOX", None), vec!["inbox".to_string()]);
        let sent = vec!["\\Sent".to_string()];
        assert_eq!(
            special_use_names("Sent", Some(sent.as_slice())),
            vec!["sent".to_string()]
        );
        let both = vec!["\\Junk".to_string(), "\\Sent".to_string()];
        assert_eq!(
            special_use_names("x", Some(both.as_slice())),
            vec!["sent".to_string(), "junk".to_string()]
        );
    }
}

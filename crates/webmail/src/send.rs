//! 发信与草稿落盘。
//!
//! ## 两步失败语义（契约 §2.2，冻结）
//!
//! ```text
//! 1. QueueStore::enqueue_new(EntryKind::Outbound)   —— 失败 ⇒ 整封拒绝（什么都没发生）
//! 2. MailStore::append("Sent", …, \Seen)            —— 失败 ⇒ 202 + sentUid:null + warning
//! ```
//!
//! 关键取舍：**宁可 Sent 少一份，不可丢信**。第 2 步失败时绝不回滚第 1 步——
//! 回滚已入队的邮件就是丢信（用户以为发出去了，实际队列里也没有）。因此
//! 队列成功之后返回的一定是 202，Sent 副本问题只作为 warning 如实告知。
//!
//! ## DKIM 不在这里做
//!
//! Webmail 只负责把报文放进队列；DKIM 由队列 runner 出站前统一签名
//! （`mailstack_queue::QueueRunner::new` 无条件套 `SigningTransport`）。在这里
//! 再签一次会产生两条签名路径，而「哪条漏签」是最难发现的邮件伪造面。
//!
//! ## 草稿
//!
//! 草稿只允许落到 `Drafts`（契约 §2）；给出 `draftUid` 时先追加新草稿、成功后
//! 才 expunge 旧草稿——顺序反了会让「保存失败」把用户正在编辑的旧草稿删掉。

use std::sync::Arc;

use mailstack_imappop3::maildir::{Flag, FlagSet, MailStore, SystemClock, SystemFlag};
use mailstack_queue::{EntryKind, QueueEntry, QueueStore};

use crate::account::Account;
use crate::compose::{self, ComposeRequest, DraftRequest, Purpose};
use crate::error::{WebmailError, WebmailResult};
use crate::WebmailConfig;

/// 发信结果（契约 §2 `POST /mail/api/send` → 202）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendOutcome {
    /// 队列条目 id。
    pub queue_id: String,
    /// Sent 副本的 uid；副本保存失败时为 `None`（队列已入队，**不回滚**）。
    pub sent_uid: Option<u32>,
    /// Sent 副本失败时给用户看的如实说明（不得包含内部路径）。
    pub warning: Option<String>,
}

/// 发信：校验 → 构造 → 入队列 → 保存 Sent 副本。
///
/// 同步函数（队列与 Maildir 都是 `std::fs`），调用方必须放在 `spawn_blocking`。
pub fn send(
    config: &WebmailConfig,
    account: &Account,
    request: &ComposeRequest,
) -> WebmailResult<SendOutcome> {
    let built = compose::build_message(account, request, Purpose::Send)?;
    let mut entry = QueueEntry::new(
        EntryKind::Outbound,
        built.envelope_from.clone(),
        built.recipients.clone(),
        built.data.clone(),
        mailstack_queue::now_unix(),
    )
    .map_err(|error| {
        // QueueEntry::new 的校验失败只可能来自我们自己的构造（地址/报文/收件人），
        // 属于「请求数据不合法」而不是队列故障。
        WebmailError::bad_request("INVALID_MESSAGE", error.to_string())
    })?;

    let store = QueueStore::from_paths(&config.paths);
    // 第 1 步：入队。失败 ⇒ 整封拒绝。这里必须回 5xx（可重试）而不是 4xx：
    // 队列落盘失败与服务端故障同义，客户端重试是安全的（此时没有产生任何状态）。
    store.enqueue_new(&mut entry).map_err(|error| {
        tracing::error!(
            target: "mailstack_webmail",
            email = %account.email,
            %error,
            "outbound enqueue failed; nothing was sent"
        );
        WebmailError::service_unavailable(
            "QUEUE_UNAVAILABLE",
            "the outbound queue is unavailable; the message was not sent",
        )
    })?;
    let queue_id = entry.id.clone();
    tracing::info!(
        target: "mailstack_webmail",
        email = %account.email,
        queue_id = %queue_id,
        recipients = entry.recipients.len(),
        "webmail message queued"
    );

    // 第 2 步：Sent 副本。失败只记 warning，绝不回滚队列。
    match append_to_sent(account, built.data.as_bytes()) {
        Ok(sent_uid) => Ok(SendOutcome {
            queue_id,
            sent_uid: Some(sent_uid),
            warning: None,
        }),
        Err(error) => {
            tracing::warn!(
                target: "mailstack_webmail",
                email = %account.email,
                queue_id = %queue_id,
                %error,
                "message queued but the Sent copy could not be saved"
            );
            Ok(SendOutcome {
                queue_id,
                sent_uid: None,
                // 刻意不回显内部错误（路径/OS 细节）：给用户一句能理解、可行动的话。
                warning: Some(
                    "the message was queued for delivery, but a copy could not be saved to Sent"
                        .to_string(),
                ),
            })
        }
    }
}

/// 保存草稿（契约 §2 `POST /mail/api/messages`），返回 `(uid, folder)`。
pub fn save_draft(account: &Account, request: &DraftRequest) -> WebmailResult<(u32, String)> {
    let mailbox = request.mailbox.as_deref().unwrap_or("Drafts").trim();
    let normalized = mailstack_imappop3::maildir::normalize_folder_name(mailbox)
        .map_err(WebmailError::from_mail)?;
    if !normalized.eq_ignore_ascii_case("Drafts") {
        return Err(WebmailError::bad_request(
            "INVALID_MAILBOX",
            "drafts may only be saved to the Drafts mailbox",
        ));
    }

    let built = compose::build_message(account, &request.compose, Purpose::Draft)?;
    let store = open_store(account)?;
    ensure_folder(&store, "Drafts")?;

    let mut flags = FlagSet::new();
    flags.insert(Flag::System(SystemFlag::Draft));
    let (_, uid) = store
        .append("Drafts", built.data.as_bytes(), &flags, None)
        .map_err(WebmailError::from_mail)?;

    // 先落新草稿、再删旧草稿：顺序反了会让一次保存失败把用户正在编辑的旧草稿
    // 删掉。旧草稿删除失败只记录（新草稿已在，多个旧版本比丢内容好）。
    if let Some(old_uid) = request.draft_uid {
        if old_uid != uid {
            match store.expunge("Drafts", &[old_uid]) {
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        target: "mailstack_webmail",
                        email = %account.email,
                        %error,
                        "draft saved but the previous draft could not be removed"
                    );
                }
            }
        }
    }
    Ok((uid, "Drafts".to_string()))
}

/// 把报文追加到 Sent（带 `\Seen`）。
fn append_to_sent(account: &Account, data: &[u8]) -> WebmailResult<u32> {
    let store = open_store(account)?;
    ensure_folder(&store, "Sent")?;
    let mut flags = FlagSet::new();
    flags.insert(Flag::System(SystemFlag::Seen));
    let (_, uid) = store
        .append("Sent", data, &flags, None)
        .map_err(WebmailError::from_mail)?;
    Ok(uid)
}

/// 打开账号的 MailStore。
fn open_store(account: &Account) -> WebmailResult<MailStore> {
    MailStore::new(&account.maildir, Arc::new(SystemClock)).map_err(WebmailError::from_mail)
}

/// 「Sent / Drafts 不存在就创建」。
///
/// 标准文件夹由安装流程创建；这里兜底一次是因为「第一次发信」必须能留下副本。
/// 创建失败不在这里报错（随后 append 会给出真实的失败原因），避免把「已入队」
/// 的邮件因为一个可选的副本目录问题误报成全失败。
fn ensure_folder(store: &MailStore, name: &str) -> WebmailResult<()> {
    match store.exists(name) {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) => return Err(WebmailError::from_mail(error)),
    }
    match store.create(name) {
        Ok(()) => Ok(()),
        // 并发请求同时创建：已存在不是错误。
        Err(mailstack_imappop3::error::MailError::AlreadyExists(_)) => Ok(()),
        Err(error) => {
            tracing::warn!(
                target: "mailstack_webmail",
                folder = name,
                %error,
                "failed to create a standard mailbox; the subsequent append will report the real error"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_core::paths::Paths;
    use mailstack_imappop3::maildir::MailStore;

    struct Fixture {
        root: tempfile::TempDir,
        config: WebmailConfig,
        account: Account,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let paths = Paths::rooted(root.path());
            std::fs::create_dir_all(&paths.var_lib).unwrap();
            let home = root.path().join("home/alice");
            std::fs::create_dir_all(&home).unwrap();
            let maildir = home.join("Maildir");
            MailStore::new(&maildir, Arc::new(SystemClock)).unwrap();
            let config = WebmailConfig::from_paths(paths);
            let account = Account {
                email: "alice@example.com".to_string(),
                account: "alice".to_string(),
                display_name: "Alice".to_string(),
                unix_user: "alice".to_string(),
                maildir,
            };
            Self {
                root,
                config,
                account,
            }
        }

        fn queue_root(&self) -> std::path::PathBuf {
            self.config.queue_root()
        }
    }

    fn request() -> ComposeRequest {
        ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            subject: "hi".to_string(),
            text: Some("hello".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn a_successful_send_queues_the_message_and_saves_a_seen_sent_copy() {
        let fixture = Fixture::new();
        let outcome = send(&fixture.config, &fixture.account, &request()).unwrap();
        assert!(outcome.sent_uid.is_some(), "Sent 副本必须成功");
        assert!(outcome.warning.is_none());
        assert!(!outcome.queue_id.is_empty());

        // 队列里确实有一条出站条目，内容是构造好的 MIME。
        let store = QueueStore::new(fixture.queue_root());
        let entries = store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, EntryKind::Outbound);
        assert_eq!(entries[0].mail_from, "alice@example.com");
        assert_eq!(entries[0].recipients, vec!["bob@example.org".to_string()]);
        assert!(entries[0].data.contains("Subject: hi"));

        // Sent 里有一份带 \Seen 的副本。
        let mail = MailStore::new(&fixture.account.maildir, Arc::new(SystemClock)).unwrap();
        let sent = mail.open_folder("Sent", false).unwrap();
        assert_eq!(sent.messages.len(), 1);
        assert!(
            sent.messages[0]
                .flags
                .iter()
                .any(mailstack_imappop3::maildir::Flag::is_seen),
            "Sent 副本必须带 \\Seen"
        );
    }

    /// 反例守卫：队列入队失败 ⇒ 整封拒绝，且**不得**留下 Sent 副本。
    #[test]
    fn webmail_queue_enqueue_failure_is_reported() {
        let fixture = Fixture::new();
        // 把 entries 目录的位置占成一个普通文件：enqueue_new 必然失败。
        let entries = fixture.queue_root().join("entries");
        std::fs::create_dir_all(entries.parent().unwrap()).unwrap();
        std::fs::write(&entries, b"not a directory").unwrap();

        let error = send(&fixture.config, &fixture.account, &request())
            .expect_err("队列入队失败必须如实报错");
        assert_eq!(error.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "QUEUE_UNAVAILABLE");

        // 关键断言：失败时没有 Sent 副本（否则用户会看到「已发送」的假象）。
        let mail = MailStore::new(&fixture.account.maildir, Arc::new(SystemClock)).unwrap();
        let sent_empty = mail
            .open_folder("Sent", false)
            .map(|folder| folder.messages.is_empty())
            .unwrap_or(true);
        assert!(sent_empty, "入队失败时不得留下 Sent 副本");
    }

    /// 反例守卫：队列成功、Sent 失败 ⇒ 202 语义（warning），**不回滚队列**。
    #[test]
    fn a_sent_copy_failure_keeps_the_queued_message() {
        let fixture = Fixture::new();
        // 让 Sent 无法被创建：在 Maildir 根下占一个同名普通文件。
        std::fs::write(fixture.account.maildir.join(".Sent"), b"not a dir").unwrap();

        let outcome =
            send(&fixture.config, &fixture.account, &request()).expect("队列已成功时不得返回错误");
        assert!(outcome.sent_uid.is_none());
        assert!(outcome.warning.is_some(), "必须如实告知副本保存失败");

        let store = QueueStore::new(fixture.queue_root());
        assert_eq!(
            store.load_all().unwrap().len(),
            1,
            "Sent 副本失败绝不能回滚已入队的邮件（宁可少副本，不可丢信）"
        );
    }

    #[test]
    fn a_draft_is_appended_with_the_draft_flag_and_replaces_the_old_one() {
        let fixture = Fixture::new();
        let draft = DraftRequest {
            compose: request(),
            mailbox: Some("Drafts".to_string()),
            draft_uid: None,
        };
        let (first_uid, folder) = save_draft(&fixture.account, &draft).unwrap();
        assert_eq!(folder, "Drafts");

        let mail = MailStore::new(&fixture.account.maildir, Arc::new(SystemClock)).unwrap();
        let drafts = mail.open_folder("Drafts", false).unwrap();
        assert_eq!(drafts.messages.len(), 1);
        assert!(
            drafts.messages[0]
                .flags
                .iter()
                .any(|flag| matches!(flag, Flag::System(SystemFlag::Draft))),
            "草稿必须带 \\Draft"
        );

        // 用 draftUid 替换旧草稿：新 uid 出现、旧 uid 消失。
        let draft = DraftRequest {
            compose: ComposeRequest {
                subject: "v2".to_string(),
                ..request()
            },
            mailbox: Some("Drafts".to_string()),
            draft_uid: Some(first_uid),
        };
        let (second_uid, _) = save_draft(&fixture.account, &draft).unwrap();
        assert_ne!(second_uid, first_uid);
        let drafts = mail.open_folder("Drafts", false).unwrap();
        assert_eq!(drafts.messages.len(), 1, "旧草稿必须被替换");
        assert_eq!(drafts.messages[0].uid, second_uid);
    }

    #[test]
    fn drafts_can_only_be_saved_to_the_drafts_mailbox() {
        let fixture = Fixture::new();
        let draft = DraftRequest {
            compose: request(),
            mailbox: Some("Sent".to_string()),
            draft_uid: None,
        };
        let error = save_draft(&fixture.account, &draft).unwrap_err();
        assert_eq!(error.code, "INVALID_MAILBOX");
        assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);

        let traversal = DraftRequest {
            compose: request(),
            mailbox: Some("../../etc".to_string()),
            draft_uid: None,
        };
        assert!(save_draft(&fixture.account, &traversal).is_err());
    }

    #[test]
    fn the_queue_entry_holds_the_exact_rfc5322_bytes() {
        let fixture = Fixture::new();
        let request = ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            cc: vec!["carol@example.net".to_string()],
            subject: "queued".to_string(),
            text: Some("body".to_string()),
            ..Default::default()
        };
        send(&fixture.config, &fixture.account, &request).unwrap();
        let store = QueueStore::new(fixture.queue_root());
        let entries = store.load_all().unwrap();
        assert_eq!(entries[0].recipients.len(), 2);
        assert!(entries[0]
            .data
            .starts_with("From: Alice <alice@example.com>\r\n"));
        assert!(entries[0].data.contains("Cc: carol@example.net\r\n"));
        let _ = &fixture.root;
    }
}

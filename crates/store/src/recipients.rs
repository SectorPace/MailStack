//! 本地收件人名录：`RCPT` 阶段判定「这个地址是否真的存在」。
//!
//! ## 为什么需要它（两个后果，不是「更严格」）
//!
//! 1. **目录枚举**：`VRFY` 已经恒回 502（见 `smtpd::session`），但 `RCPT` 逐地址
//!    给 250/550 的差别把**同一个信息面重新打开**了 —— 攻击者在 25 端口就能
//!    摸出全部真实邮箱。
//! 2. **退信垃圾（backscatter）**：伪造 `MAIL FROM:<victim@third.com>` +
//!    `RCPT TO:<nonexistent@ours>` → 本机向第三方发 DSN，成为 backscatter 源，
//!    损害 IP 信誉。RFC 8601 §7.5 明确把「在 SMTP 层就拒收」列为 backscatter
//!    的缓解手段。
//!
//! ## 数据源：**复用**既有注册表，不另立一份
//!
//! 真源只有两处，都已存在且都是契约：
//!
//! * `managed-mailboxes.json`（`{email, unixUser}` 数组）—— 由 `users.add` 写、
//!   `users.delete` 删，是「本机有哪些邮箱」的权威登记；
//! * 别名表 `mailstack_aliases`（`TableStore`）—— 收件人可以是别名，
//!   `alias_add` 写、`alias_del` 删。
//!
//! 刻意**不**去查 `/etc/passwd`：那是系统账号库，包含 `root`、`daemon` 这类
//! 根本不该收信的账号，用它判定「可投递」等于开了一整条枚举面。
//!
//! ## 三态而不是两态：`查不到` ≠ `不存在`
//!
//! [`Lookup`] 有三个取值，因为**把「查不了」当成「不存在」会误拒真邮件**：
//! 注册表读不了（磁盘/权限抖动）时若 fail-closed，全站收信会一起停摆。
//! 因此只有 [`Lookup::Missing`] 才允许回 550，[`Lookup::Unavailable`] 必须
//! 保持现状（只判域）并让调用方记日志。见 [`LocalRecipients::lookup`]。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use mailstack_core::paths::Paths;

use crate::tables::rows_from_text;

/// 本地收件人查询结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// 收件人存在（受管邮箱或别名）。
    Known,
    /// **确认**不存在：注册表可读且其中没有这个地址。
    ///
    /// 只有这一态允许调用方回 550 —— 它是「确认不存在」，不是「查不出来」。
    Missing,
    /// 后端不可用：注册表读不了或内容损坏。调用方**不得**据此拒绝。
    Unavailable(String),
}

/// 本地收件人名录。
#[derive(Debug, Clone)]
pub struct LocalRecipients {
    mailboxes: PathBuf,
    aliases: PathBuf,
}

impl LocalRecipients {
    /// 生产构造：路径来自 [`Paths`]。
    pub fn new(paths: &Paths) -> Self {
        Self {
            mailboxes: paths.managed_mailboxes.clone(),
            aliases: paths.aliases.clone(),
        }
    }

    /// 判定一个地址是否为本机可投递收件人。
    ///
    /// 别名**优先于**邮箱判定：别名表是显式的路由覆盖，`virtual_alias_maps`
    /// 在 Postfix 里也正是先于用户查找生效。两者都不需要 `local-part` 与
    /// `unixUser` 对应 —— 别名可以指向另一个地址。
    ///
    /// 比较一律先归一化到小写：注册表里存的是规范化值，而 SMTP 的
    /// domain-part 大小写不敏感；不归一化会让 `Alice@Example.org` 被误判成
    /// 不存在（误拒真邮件）。
    pub fn lookup(&self, address: &str) -> Lookup {
        let address = address.trim().to_ascii_lowercase();
        if address.is_empty() {
            return Lookup::Missing;
        }

        let aliases = match self.alias_sources() {
            Ok(sources) => sources,
            Err(reason) => return Lookup::Unavailable(reason),
        };
        if aliases.contains(&address) {
            return Lookup::Known;
        }

        match self.mailbox_emails() {
            Err(reason) => Lookup::Unavailable(reason),
            Ok(emails) if emails.contains(&address) => Lookup::Known,
            Ok(_) => Lookup::Missing,
        }
    }

    /// 别名表的**源**地址集合。
    fn alias_sources(&self) -> Result<HashSet<String>, String> {
        let text = read_optional(&self.aliases)?;
        Ok(rows_from_text(&text)
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .map(|source| source.trim().to_ascii_lowercase())
            .filter(|source| !source.is_empty())
            .collect())
    }

    /// `managed-mailboxes.json` 里登记的邮箱集合。
    ///
    /// 解析规则刻意与 `mailstack_priv::users::Users` 保持一致（同样的
    /// `email` 字段、同样的「非字符串当空」），否则会出现「管理台看得到这个
    /// 邮箱、但收信说它不存在」这种极难排查的不一致。
    fn mailbox_emails(&self) -> Result<HashSet<String>, String> {
        let text = read_optional(&self.mailboxes)?;
        if text.trim().is_empty() {
            return Ok(HashSet::new());
        }
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|error| format!("{}: {error}", self.mailboxes.display()))?;
        let items = match parsed {
            Value::Array(items) => items,
            // 结构不符（含损坏）时**不能**当成「空名录」—— 那等于把一份读不懂的
            // 注册表变成「拒绝一切收件人」。按查不了处理。
            _ => return Err(format!("{} is not a JSON array", self.mailboxes.display())),
        };
        Ok(items
            .into_iter()
            .filter_map(|item| {
                // 取值必须 `to_string` 而不是借用：`items` 在这里被消费掉了，
                // 借用它会让返回值挂在一个临时值上。
                item.get("email")
                    .and_then(Value::as_str)
                    .map(|email| email.trim().to_ascii_lowercase())
            })
            .filter(|email| !email.is_empty())
            .collect())
    }
}

/// 读一个**可选**的注册表文件。
///
/// 区分三种情况，因为它们的处置完全不同：
/// * 文件不存在 → `Ok("")`：这是一台还没建过邮箱的新机器，名录为空集，
///   「空 = 没有收件人」是正确的读法（否则每台新装的机器都收不了信）。
/// * 存在但读不了 → `Err`：这是 `Unavailable`，调用方必须保持现状。
/// * 读得了 → `Ok(文本)`。
fn read_optional(path: &Path) -> Result<String, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一个临时的注册表根：只落地两份注册表文件。
    struct Fixture {
        _dir: tempfile::TempDir,
        recipients: LocalRecipients,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::rooted(dir.path());
            std::fs::create_dir_all(&paths.postfix).unwrap();
            std::fs::create_dir_all(paths.managed_mailboxes.parent().unwrap()).unwrap();
            Self {
                recipients: LocalRecipients::new(&paths),
                _dir: dir,
            }
        }

        fn with_mailboxes(self, value: &Value) -> Self {
            std::fs::write(
                &self.recipients.mailboxes,
                serde_json::to_string(value).unwrap(),
            )
            .unwrap();
            self
        }

        fn with_raw_mailboxes(self, text: &str) -> Self {
            std::fs::write(&self.recipients.mailboxes, text).unwrap();
            self
        }

        fn with_aliases(self, text: &str) -> Self {
            std::fs::write(&self.recipients.aliases, text).unwrap();
            self
        }
    }

    fn registered() -> Value {
        serde_json::json!([
            {"email": "alice@example.org", "unixUser": "alice", "displayName": ""},
            {"email": "bob@example.org", "unixUser": "bob", "displayName": ""}
        ])
    }

    #[test]
    fn a_registered_mailbox_is_known_and_an_unregistered_one_is_confirmed_missing() {
        let f = Fixture::new().with_mailboxes(&registered());
        assert_eq!(f.recipients.lookup("alice@example.org"), Lookup::Known);
        assert_eq!(
            f.recipients.lookup("nobody@example.org"),
            Lookup::Missing,
            "可读且不含该地址 ⇒ 确认不存在"
        );
    }

    #[test]
    fn a_missing_registry_reads_as_an_empty_directory_rather_than_unavailable() {
        // 新装的机器还没有任何邮箱。若把「文件不存在」当成「查不了」，
        // `assemble` 之前的所有测试与新装机器都会莫名进入降级分支。
        let f = Fixture::new();
        assert_eq!(f.recipients.lookup("alice@example.org"), Lookup::Missing);
    }

    #[test]
    fn an_alias_source_is_a_valid_recipient_even_without_a_mailbox() {
        let f = Fixture::new()
            .with_mailboxes(&registered())
            .with_aliases("sales@example.org alice\n# comment\ninfo@example.org bob carol\n");
        assert_eq!(f.recipients.lookup("sales@example.org"), Lookup::Known);
        assert_eq!(f.recipients.lookup("info@example.org"), Lookup::Known);
        assert_eq!(f.recipients.lookup("nobody@example.org"), Lookup::Missing);
    }

    #[test]
    fn comparison_is_case_insensitive_so_a_real_mail_is_not_rejected() {
        // SMTP 的 domain-part 大小写不敏感；不归一化就会把
        // `Alice@Example.org` 误判成不存在 —— 那是误拒真邮件。
        let f = Fixture::new()
            .with_mailboxes(&registered())
            .with_aliases("Sales@Example.ORG alice\n");
        assert_eq!(f.recipients.lookup("Alice@Example.org"), Lookup::Known);
        assert_eq!(f.recipients.lookup("ALICE@EXAMPLE.ORG"), Lookup::Known);
        assert_eq!(f.recipients.lookup("SALES@example.org"), Lookup::Known);
    }

    #[test]
    fn a_corrupt_registry_is_unavailable_and_never_missing() {
        // 这是本模块最重要的一条：**读不懂 ≠ 不存在**。若把损坏的 JSON 当成
        // 空名录，一次磁盘写坏就会让全站拒收所有邮件。
        let f = Fixture::new().with_raw_mailboxes("{ this is not json");
        assert!(matches!(
            f.recipients.lookup("alice@example.org"),
            Lookup::Unavailable(_)
        ));

        // 结构不符（不是数组）同样不可用。
        let f = Fixture::new().with_raw_mailboxes(r#"{"email":"alice@example.org"}"#);
        assert!(matches!(
            f.recipients.lookup("alice@example.org"),
            Lookup::Unavailable(_)
        ));
    }

    #[test]
    fn an_empty_registry_file_is_an_empty_directory_not_a_corruption() {
        // `atomic()` 落盘中途的极短窗口里文件可能是空的；那是「还没有邮箱」。
        let f = Fixture::new().with_raw_mailboxes("");
        assert_eq!(f.recipients.lookup("alice@example.org"), Lookup::Missing);
    }

    #[test]
    fn entries_without_a_usable_email_field_are_ignored_not_treated_as_unknowns() {
        let f = Fixture::new().with_raw_mailboxes(
            r#"[{"unixUser":"alice"},{"email":123},{"email":"  "},{"email":"bob@example.org"}]"#,
        );
        assert_eq!(f.recipients.lookup("bob@example.org"), Lookup::Known);
        assert_eq!(f.recipients.lookup("alice@example.org"), Lookup::Missing);
    }

    #[test]
    fn an_alias_pointing_at_another_address_still_makes_the_source_valid() {
        // 别名目标是另一个地址也照样有效 —— 收件人只需要「能被打到」。
        let f = Fixture::new().with_aliases("help@example.org support@other.test\n");
        assert_eq!(f.recipients.lookup("help@example.org"), Lookup::Known);
    }

    #[test]
    fn an_empty_address_is_missing() {
        let f = Fixture::new().with_mailboxes(&registered());
        assert_eq!(f.recipients.lookup("   "), Lookup::Missing);
    }
}

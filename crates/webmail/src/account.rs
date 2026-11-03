//! 账号解析与口令认证。
//!
//! ## 登录名 → Maildir 的解析链（契约 §1.1）
//!
//! ```text
//! 完整邮箱地址
//!   → /etc/mailstack/mailbox-passwords.json   （PBKDF2 记录，唯一口令真相源）
//!   → /var/lib/mailstack/managed-mailboxes.json（email → unixUser 注册表）
//!   → <passwd_root>/passwd                     （unixUser → 家目录）
//!   → <home>/<maildir_name>                    （Maildir，必须已存在）
//! ```
//!
//! ## 为什么整条链都 fail-closed
//!
//! 任何一环读不出来 / 缺条目 / 目录不存在 → **登录失败**，绝不自动创建：
//! 自动 `mkdir` 会让一次「注册表写错」变成「凭空造出一个空邮箱」，用户看到的
//! 是「登录成功但信全没了」——比直接登录失败危险得多。
//!
//! ## 为什么登录失败必须恒跑一次 PBKDF2
//!
//! 「用户不存在」若提前返回，响应时间只有「口令错」的千分之一；攻击者用时间差
//! 就能枚举出哪些邮箱是真的。因此记录缺失时仍对一条**哑记录**做完整
//! PBKDF2 校验，再返回统一的 401。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Deserialize;

use mailstack_core::mailbox_passwords::{self, MailboxPasswords};
use mailstack_core::password::{self, PasswordRecord};

use crate::error::{WebmailError, WebmailResult};
use crate::{WebmailConfig, MAX_EMAIL_LEN};

/// 一个通过认证的邮箱账号（会话里保存的快照）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// 规范化邮箱地址（小写）。
    pub email: String,
    /// 本地部分（登录响应里的 `account`）。
    pub account: String,
    /// 显示名（注册表 `displayName`，缺失时回落为本地部分）。
    pub display_name: String,
    /// unix 账号名（`/etc/passwd` 的主键）。
    pub unix_user: String,
    /// `<home>/<maildir_name>` 的绝对路径。
    pub maildir: PathBuf,
}

/// `managed-mailboxes.json` 的一条记录。
#[derive(Debug, Clone, Deserialize)]
pub struct ManagedMailbox {
    /// 完整邮箱地址（键）。
    pub email: String,
    /// 对应的 unix 账号名。
    #[serde(rename = "unixUser")]
    pub unix_user: String,
    /// 显示名（可选）。
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
}

/// 账号目录：把「登录名 + 口令」解析成一个可读写的 Maildir。
pub struct AccountDirectory {
    /// `mailbox-passwords.json` 的读缓存（由 core 提供，mtime+len 失效）。
    passwords: MailboxPasswords,
    /// `managed-mailboxes.json` 路径。
    registry_path: PathBuf,
    /// `passwd` 文件所在目录。
    passwd_root: PathBuf,
    /// 家目录下的 Maildir 目录名。
    maildir_name: String,
}

impl AccountDirectory {
    /// 按配置构造（路径全部来自 [`WebmailConfig`]）。
    pub fn new(config: &WebmailConfig) -> Self {
        Self {
            passwords: MailboxPasswords::at(&config.paths),
            registry_path: config.paths.managed_mailboxes.clone(),
            passwd_root: config.passwd_root.clone(),
            maildir_name: config.maildir_name.clone(),
        }
    }

    /// 完整的认证流程。`Ok(None)` = 凭据无效（统一 401）；`Err` = 服务器故障。
    pub fn authenticate(&self, login: &str, password: &str) -> WebmailResult<Option<Account>> {
        let login = normalize_login(login);
        if login.is_empty() || login.len() > MAX_EMAIL_LEN || password.is_empty() {
            // 空输入也跑一次 PBKDF2：否则「空口令」与「口令错」在时间上可分。
            let _ = password::verify_password(dummy_record(), password);
            return Ok(None);
        }

        // 契约 §1.1：与 imapd 相同的候选键（完整地址 + 本地部分，但不猜域名）。
        let mut record: Option<PasswordRecord> = None;
        for key in mailbox_passwords::candidate_keys(&login) {
            match self.passwords.get(&key) {
                Ok(Some(found)) => {
                    record = Some(found);
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    // 口令库损坏/不可读是服务器故障：如实 500，而不是伪装成 401
                    // （伪装会让运维以为「用户忘密码了」）。
                    return Err(WebmailError::internal("mailbox passwords", error));
                }
            }
        }

        let verified = match &record {
            Some(record) => password::verify_password(record, password),
            None => {
                // 恒定计时：没有记录时仍然做一次完整的 PBKDF2，忽略结果。
                let _ = password::verify_password(dummy_record(), password);
                false
            }
        };
        if !verified {
            return Ok(None);
        }

        // 口令对了才解析 Maildir；解析失败同样回 401（不区分「邮箱未建」）。
        Ok(self.resolve(&login))
    }

    /// 把邮箱地址解析为账号；任何一环不成立都返回 `None`（fail closed）。
    pub fn resolve(&self, email: &str) -> Option<Account> {
        let email = normalize_login(email);
        if email.is_empty() || email.len() > MAX_EMAIL_LEN || !email.contains('@') {
            return None;
        }
        let mailboxes = self.load_registry().ok()?;
        let mailbox = mailboxes
            .iter()
            .find(|entry| entry.email.eq_ignore_ascii_case(&email))?;
        let canonical_email = mailbox.email.trim().to_ascii_lowercase();
        let local = canonical_email
            .split_once('@')
            .map(|(local, _)| local.to_string())?;
        let unix_user = mailbox.unix_user.trim();
        if unix_user.is_empty() {
            return None;
        }

        let home = self.lookup_home(unix_user)?;
        let maildir = home.join(&self.maildir_name);
        // Maildir 必须**已经存在**：登录成功即承诺「这个目录可读写」。
        if !maildir.is_dir() {
            tracing::warn!(
                target: "mailstack_webmail",
                email = %canonical_email,
                "maildir is missing; refusing login instead of creating it"
            );
            return None;
        }

        let display_name = mailbox
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| local.clone());

        Some(Account {
            email: canonical_email,
            account: local,
            display_name,
            unix_user: unix_user.to_string(),
            maildir,
        })
    }

    /// 读取 `managed-mailboxes.json`（每次登录读一次；文件很小且只有 root 可写）。
    fn load_registry(&self) -> WebmailResult<Vec<ManagedMailbox>> {
        let contents = match std::fs::read_to_string(&self.registry_path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // 注册表缺失 = 尚未创建任何邮箱（合法的空状态）→ 无人能登录。
                return Ok(Vec::new());
            }
            Err(error) => {
                return Err(WebmailError::internal(
                    "managed mailboxes registry",
                    format!("{}: {error}", self.registry_path.display()),
                ))
            }
        };
        if contents.trim().is_empty() {
            return Ok(Vec::new());
        }
        match serde_json::from_str::<Vec<ManagedMailbox>>(&contents) {
            Ok(mailboxes) => Ok(mailboxes),
            Err(error) => Err(WebmailError::internal(
                "managed mailboxes registry",
                format!("{}: {error}", self.registry_path.display()),
            )),
        }
    }

    /// 从 `<passwd_root>/passwd` 查 unix 账号的家目录。
    ///
    /// 解析规则的取舍：只认 `name:passwd:uid:gid:gecos:home:shell` 的字段位置，
    /// 忽略 gecos 里的逗号等。家目录必须是**绝对路径**——相对路径会把 Maildir
    /// 解析到 webmail 进程的 cwd 下，那是不可预测的。
    pub fn lookup_home(&self, unix_user: &str) -> Option<PathBuf> {
        let passwd_path = self.passwd_root.join("passwd");
        let contents = std::fs::read_to_string(&passwd_path).ok()?;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split(':');
            let Some(name) = fields.next() else { continue };
            if name != unix_user {
                continue;
            }
            // passwd, uid, gid, gecos
            let home = fields.nth(4)?;
            let home = home.trim();
            if home.is_empty() || !home.starts_with('/') || home.contains('\0') {
                tracing::warn!(
                    target: "mailstack_webmail",
                    unix_user,
                    "passwd entry has an unusable home directory; refusing login"
                );
                return None;
            }
            return Some(PathBuf::from(home));
        }
        None
    }

    /// 注册表路径（测试与诊断用）。
    pub fn registry_path(&self) -> &std::path::Path {
        &self.registry_path
    }
}

/// 登录名规范化：去空白、转小写。
///
/// 与 `mailbox_passwords::key` 保持一致；邮箱地址大小写不敏感（本项目账号名
/// 一律小写，`users.create` 也按小写建号）。
pub fn normalize_login(login: &str) -> String {
    login.trim().to_ascii_lowercase()
}

/// 恒定计时用的哑口令记录。
///
/// 与真实记录同形状（16 字节盐 / 32 字节摘要 / 同一算法），因此校验成本与
/// 真实账号完全一致。生成一次后进程内复用（PBKDF2 本身要 31 万次迭代）。
fn dummy_record() -> &'static PasswordRecord {
    static DUMMY: OnceLock<PasswordRecord> = OnceLock::new();
    DUMMY.get_or_init(|| {
        match password::password_record("mailstack-dummy", "Dummy-Passphrase-9x") {
            Ok(record) => record,
            Err(_) => {
                // 理论上不可达（常量口令满足策略）；仍然给出形状合法的记录，
                // 让「校验成本恒定」这条性质不因它失败而消失。
                PasswordRecord {
                    username: "mailstack-dummy".to_string(),
                    algorithm: password::PASSWORD_ALGORITHM.to_string(),
                    iterations: password::PBKDF2_ITERATIONS,
                    salt: "00".repeat(password::SALT_LEN),
                    hash: "00".repeat(password::HASH_LEN),
                    updated_at: String::new(),
                }
            }
        }
    })
}

/// 用于测试的会话账号快照构造函数。
#[doc(hidden)]
pub fn account_for_test(email: &str, maildir: PathBuf) -> Account {
    let (local, _) = email.split_once('@').unwrap_or((email, ""));
    Account {
        email: email.to_ascii_lowercase(),
        account: local.to_string(),
        display_name: local.to_string(),
        unix_user: local.to_string(),
        maildir,
    }
}

/// 把注册表条目按邮箱地址索引（诊断/测试用）。
pub fn index_by_email(mailboxes: &[ManagedMailbox]) -> HashMap<String, &ManagedMailbox> {
    mailboxes
        .iter()
        .map(|mailbox| (mailbox.email.trim().to_ascii_lowercase(), mailbox))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_normalization_is_case_and_space_insensitive() {
        assert_eq!(normalize_login("  Alice@Example.COM "), "alice@example.com");
        assert_eq!(normalize_login(""), "");
    }

    #[test]
    fn a_passwd_entry_with_a_relative_home_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("passwd"),
            "alice:x:1000:1000:Alice:relative/Maildir:/bin/sh\n",
        )
        .unwrap();
        let config = WebmailConfig::from_paths(mailstack_core::Paths::rooted(dir.path()))
            .with_passwd_root(dir.path());
        let directory = AccountDirectory::new(&config);
        assert!(
            directory.lookup_home("alice").is_none(),
            "相对家目录必须被拒绝（否则 Maildir 落到进程 cwd）"
        );
    }

    #[test]
    fn a_missing_maildir_fails_closed_instead_of_being_created() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home/alice");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            dir.path().join("passwd"),
            format!("alice:x:1000:1000:Alice:{}:/bin/sh\n", home.display()),
        )
        .unwrap();

        let root = dir.path().join("root");
        let paths = mailstack_core::Paths::rooted(&root);
        std::fs::create_dir_all(paths.managed_mailboxes.parent().unwrap()).unwrap();
        std::fs::write(
            &paths.managed_mailboxes,
            r#"[{"email":"alice@example.com","unixUser":"alice","displayName":"Alice"}]"#,
        )
        .unwrap();
        let config = WebmailConfig::from_paths(paths).with_passwd_root(dir.path());
        let directory = AccountDirectory::new(&config);

        assert!(
            directory.resolve("alice@example.com").is_none(),
            "Maildir 不存在时必须登录失败"
        );
        assert!(
            !home.join("Maildir").exists(),
            "绝不自动创建 Maildir（会把注册表错误变成凭空造邮箱）"
        );
    }

    /// 反例守卫：注册表缺失/损坏时不得放行任何账号。
    #[test]
    fn a_missing_or_corrupt_registry_resolves_nobody() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home/alice");
        std::fs::create_dir_all(home.join("Maildir").join("cur")).unwrap();
        std::fs::create_dir_all(home.join("Maildir").join("new")).unwrap();
        std::fs::create_dir_all(home.join("Maildir").join("tmp")).unwrap();
        std::fs::write(
            dir.path().join("passwd"),
            format!("alice:x:1000:1000:Alice:{}:/bin/sh\n", home.display()),
        )
        .unwrap();

        let root = dir.path().join("root");
        let paths = mailstack_core::Paths::rooted(&root);
        std::fs::create_dir_all(paths.managed_mailboxes.parent().unwrap()).unwrap();
        let config = WebmailConfig::from_paths(paths.clone()).with_passwd_root(dir.path());
        let directory = AccountDirectory::new(&config);

        assert!(
            directory.resolve("alice@example.com").is_none(),
            "注册表缺失时必须 fail closed"
        );

        std::fs::write(&paths.managed_mailboxes, "{not json").unwrap();
        assert!(
            directory.resolve("alice@example.com").is_none(),
            "注册表损坏时同样必须 fail closed"
        );
    }

    #[test]
    fn addresses_are_matched_case_insensitively_via_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home/alice");
        let maildir = home.join("Maildir");
        mailstack_imappop3::maildir::MailStore::new(
            &maildir,
            std::sync::Arc::new(mailstack_imappop3::maildir::SystemClock),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("passwd"),
            format!("alice:x:1000:1000:Alice:{}:/bin/sh\n", home.display()),
        )
        .unwrap();
        let root = dir.path().join("root");
        let paths = mailstack_core::Paths::rooted(&root);
        std::fs::create_dir_all(paths.managed_mailboxes.parent().unwrap()).unwrap();
        std::fs::write(
            &paths.managed_mailboxes,
            r#"[{"email":"Alice@Example.com","unixUser":"alice","displayName":"Alice A."}]"#,
        )
        .unwrap();
        let config = WebmailConfig::from_paths(paths).with_passwd_root(dir.path());
        let directory = AccountDirectory::new(&config);

        let account = directory
            .resolve("ALICE@EXAMPLE.COM")
            .expect("大小写不敏感");
        assert_eq!(account.email, "alice@example.com");
        assert_eq!(account.account, "alice");
        assert_eq!(account.display_name, "Alice A.");
        assert_eq!(account.maildir, maildir);
    }
}

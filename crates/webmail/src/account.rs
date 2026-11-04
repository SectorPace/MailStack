use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Deserialize;

use mailstack_core::mailbox_passwords::{self, MailboxPasswords};
use mailstack_core::password::{self, PasswordRecord};

use crate::error::{WebmailError, WebmailResult};
use crate::{WebmailConfig, MAX_EMAIL_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub email: String,

    pub account: String,

    pub display_name: String,

    pub unix_user: String,

    pub maildir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedMailbox {
    pub email: String,

    #[serde(rename = "unixUser")]
    pub unix_user: String,

    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
}

pub struct AccountDirectory {
    passwords: MailboxPasswords,

    registry_path: PathBuf,

    passwd_root: PathBuf,

    maildir_name: String,
}

impl AccountDirectory {
    pub fn new(config: &WebmailConfig) -> Self {
        Self {
            passwords: MailboxPasswords::at(&config.paths),
            registry_path: config.paths.managed_mailboxes.clone(),
            passwd_root: config.passwd_root.clone(),
            maildir_name: config.maildir_name.clone(),
        }
    }

    pub fn authenticate(&self, login: &str, password: &str) -> WebmailResult<Option<Account>> {
        let login = normalize_login(login);
        if login.is_empty() || login.len() > MAX_EMAIL_LEN || password.is_empty() {
            let _ = password::verify_password(dummy_record(), password);
            return Ok(None);
        }

        let mut record: Option<PasswordRecord> = None;
        for key in mailbox_passwords::candidate_keys(&login) {
            match self.passwords.get(&key) {
                Ok(Some(found)) => {
                    record = Some(found);
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(WebmailError::internal("mailbox passwords", error));
                }
            }
        }

        let verified = match &record {
            Some(record) => password::verify_password(record, password),
            None => {
                let _ = password::verify_password(dummy_record(), password);
                false
            }
        };
        if !verified {
            return Ok(None);
        }

        Ok(self.resolve(&login))
    }

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

    fn load_registry(&self) -> WebmailResult<Vec<ManagedMailbox>> {
        let contents = match std::fs::read_to_string(&self.registry_path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
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

    pub fn registry_path(&self) -> &std::path::Path {
        &self.registry_path
    }
}

pub fn normalize_login(login: &str) -> String {
    login.trim().to_ascii_lowercase()
}

fn dummy_record() -> &'static PasswordRecord {
    static DUMMY: OnceLock<PasswordRecord> = OnceLock::new();
    DUMMY.get_or_init(|| {
        match password::password_record("mailstack-dummy", "Dummy-Passphrase-9x") {
            Ok(record) => record,
            Err(_) => PasswordRecord {
                username: "mailstack-dummy".to_string(),
                algorithm: password::PASSWORD_ALGORITHM.to_string(),
                iterations: password::PBKDF2_ITERATIONS,
                salt: "00".repeat(password::SALT_LEN),
                hash: "00".repeat(password::HASH_LEN),
                updated_at: String::new(),
            },
        }
    })
}

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

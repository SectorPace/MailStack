use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use mailstack_core::mailbox_passwords::MailboxPasswords;
use mailstack_core::password::PasswordRecord;
use mailstack_imappop3::auth::{PasswordDirectory, UserDirectory};

pub struct MailboxDirectory {
    passwords: MailboxPasswords,
}

impl MailboxDirectory {
    pub fn new(passwords: MailboxPasswords) -> Self {
        Self { passwords }
    }

    pub fn at(paths: &mailstack_core::Paths) -> Self {
        Self::new(MailboxPasswords::at(paths))
    }

    fn candidate_keys(user: &str) -> Vec<String> {
        mailstack_core::mailbox_passwords::candidate_keys(user)
    }
}

impl UserDirectory for MailboxDirectory {
    fn lookup<'a>(
        &'a self,
        user: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PasswordRecord>> + Send + 'a>> {
        Box::pin(async move {
            for key in Self::candidate_keys(user) {
                match self.passwords.get(&key) {
                    Ok(Some(record)) => return Some(record),
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            path = %self.passwords.path().display(),
                            "邮箱口令库不可读，拒绝本次认证"
                        );
                        return None;
                    }
                }
            }
            None
        })
    }
}

pub fn backend(directory: MailboxDirectory) -> mailstack_imappop3::auth::AuthBackend {
    mailstack_imappop3::auth::AuthBackend::new(Arc::new(PasswordDirectory::new(directory)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, MailboxDirectory) {
        let dir = tempfile::tempdir().unwrap();
        let passwords = MailboxPasswords::new(dir.path().join("mailbox-passwords.json"));
        (dir, MailboxDirectory::new(passwords))
    }

    fn add(directory: &MailboxDirectory, user: &str, password: &str) {
        let record = if user.contains('@') {
            mailstack_core::password::mailbox_password_record(user, password).unwrap()
        } else {
            mailstack_core::password::password_record(user, password).unwrap()
        };
        directory.passwords.upsert(&record).unwrap();
    }

    #[tokio::test]
    async fn a_full_address_authenticates_by_the_address_key() {
        let (_dir, directory) = fixture();
        add(&directory, "alice@example.com", "Correct-Horse-9");

        let record = directory
            .lookup("alice@example.com")
            .await
            .expect("完整地址应命中");
        assert_eq!(record.username, "alice@example.com");
    }

    #[tokio::test]
    async fn a_bare_account_name_does_not_guess_a_domain() {
        let (_dir, directory) = fixture();
        add(&directory, "alice@example.com", "Correct-Horse-9");

        assert!(
            directory.lookup("ALICE").await.is_none(),
            "裸账号名不得猜测域名去命中某个地址记录"
        );
    }

    #[tokio::test]
    async fn a_bare_record_matches_a_bare_login() {
        let (_dir, directory) = fixture();
        add(&directory, "alice", "Correct-Horse-9");

        let record = directory.lookup("ALICE").await.expect("裸记录应命中");
        assert_eq!(record.username, "alice");
    }

    #[tokio::test]
    async fn an_unknown_user_is_none_not_an_error() {
        let (_dir, directory) = fixture();
        assert!(directory.lookup("nobody@example.com").await.is_none());
    }

    #[tokio::test]
    async fn a_corrupt_store_fails_closed_instead_of_panicking() {
        let (dir, directory) = fixture();
        std::fs::write(dir.path().join("mailbox-passwords.json"), "{broken").unwrap();

        assert!(
            directory.lookup("alice@example.com").await.is_none(),
            "库损坏时必须拒绝认证，而不是 panic 或放行"
        );
    }

    #[test]
    fn candidate_keys_try_the_full_address_then_the_local_part() {
        assert_eq!(
            MailboxDirectory::candidate_keys(" Alice@Example.COM "),
            vec!["alice@example.com".to_string(), "alice".to_string()]
        );
        assert_eq!(
            MailboxDirectory::candidate_keys("alice"),
            vec!["alice".to_string()]
        );
    }
}

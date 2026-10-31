//! 账号目录：把 [`mailstack_core::mailbox_passwords`] 接到 imappop3 的
//! [`UserDirectory`] 上。
//!
//! ## 为什么口令记录在 MailStack 自己手里
//!
//! 重写前 Dovecot 走 PAM（`/etc/shadow` 的 crypt 哈希）。换成自研协议面后若继续
//! 读 shadow，就得在纯 Rust 里实现 yescrypt / `$6$` / `$2b$` 多套算法，而且与
//! **INV-37（PBKDF2-SHA256 记录是口令唯一真相源）** 冲突。因此协议面的口令来源
//! 是 `mailbox-passwords.json`，由 `users.create` / `users.password` 写入。
//!
//! ## 失败语义
//!
//! * 用户不在库里 → `None`（认证失败，正常路径）；
//! * **库文件损坏 / 读不出来 → 也返回 `None`（fail closed）**，并打 `warn`。
//!   绝不能因为存储故障就放行，也不能 panic 掉整个连接任务。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use mailstack_core::mailbox_passwords::MailboxPasswords;
use mailstack_core::password::PasswordRecord;
use mailstack_imappop3::auth::{PasswordDirectory, UserDirectory};

/// 基于 MailStack 口令记录的账号目录。
pub struct MailboxDirectory {
    passwords: MailboxPasswords,
}

impl MailboxDirectory {
    pub fn new(passwords: MailboxPasswords) -> Self {
        Self { passwords }
    }

    /// 生产构造：读 `<Paths::mailbox_passwords>`。
    pub fn at(paths: &mailstack_core::Paths) -> Self {
        Self::new(MailboxPasswords::at(paths))
    }

    /// 登录名 → 可能的记录键，按优先级排列。
    ///
    /// 客户端可能用**完整地址**（`alice@example.com`）或**本地部分**（`alice`）登录：
    /// 前者是 `users.create` 默认写入的键，后者是 unix 账号名。两种都试，
    /// 但都不做跨域名猜测（`bob@other.example` 不会命中 `bob@example.com`）。
    fn candidate_keys(user: &str) -> Vec<String> {
        let normalized = mailstack_core::mailbox_passwords::key(user);
        let mut keys = vec![normalized.clone()];
        if let Some((local, _)) = normalized.split_once('@') {
            if !local.is_empty() && local != normalized {
                keys.push(local.to_string());
            }
        }
        keys
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
                        // fail closed：存储坏了不能变成「没有这个用户」之外的东西，
                        // 更不能放行；但要把原因留在日志里，否则排障会指向认证逻辑。
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

/// 生产用的认证后端：口令记录 → 常量时间校验。
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
        // 带 `@` 的是邮箱地址（走地址校验），否则按裸账号名（管理员/unix 账号）。
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

    /// 裸账号名**不**去猜域名：`alice` 不会命中 `alice@example.com`。
    ///
    /// 这是刻意的。多域名部署下（`alice@a.example` 与 `alice@b.example` 是两个人）
    /// 猜域名等于让一个人用另一个人的邮箱；宁可让客户端填完整地址，
    /// 也不做只能靠"第一个匹配"取胜的猜测。
    #[tokio::test]
    async fn a_bare_account_name_does_not_guess_a_domain() {
        let (_dir, directory) = fixture();
        add(&directory, "alice@example.com", "Correct-Horse-9");

        assert!(
            directory.lookup("ALICE").await.is_none(),
            "裸账号名不得猜测域名去命中某个地址记录"
        );
    }

    /// 但如果管理员确实建的是裸账号名，裸登录照样能过。
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

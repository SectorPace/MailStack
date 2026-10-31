//! 登录名 → Maildir 的解析器。
//!
//! ## 布局（已定死，不是候选）
//!
//! `crates/store` 的文档明确结论：**账号就是系统账号，Maildir 即
//! `<系统用户家目录>/Maildir`**（Dovecot 侧配 `mail_location = maildir:~/Maildir`），
//! 由 `users.*` 的 `useradd -m` + `~/Maildir/{cur,new,tmp}` 固定下来。
//!
//! 因此这里只解析 `/etc/passwd` 拿家目录，不猜 `<vmail>/<domain>/<user>`。
//! （`mailtest` 的令牌探测会并列试多个候选，那是为了兼容历史部署的**只读**探测，
//! 不能反过来当成写入布局的依据。）
//!
//! ## 与 imappop3 的关系
//!
//! `servers` 把它作为 `resolver` 注入会话上下文；imappop3 在**认证成功后**
//! 用它把会话切到登录用户自己的 Maildir（见 `crates/imappop3/src/imap/session.rs`
//! 的 `AuthOutcome::Success` 分支）。解析不到 → 拒绝登录，绝不退回默认邮箱。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mailstack_imappop3::maildir::{MailStore, SystemClock};
use mailstack_imappop3::resolver::MailboxResolver;

/// 从登录名取 unix 账号名：去掉 `@domain`、转小写、去空白。
///
/// `users.create` 建号时也是「取邮箱的本地部分」作为 unix 账号（见
/// `crates/priv/src/users.rs`），两边必须一致。
pub fn account_name(login: &str) -> String {
    let login = login.trim().to_ascii_lowercase();
    match login.split_once('@') {
        Some((local, _)) => local.to_string(),
        None => login,
    }
}

/// 系统账号布局的 Maildir 解析器。
pub struct SystemMaildirResolver {
    passwd_root: PathBuf,
    maildir_name: String,
}

impl SystemMaildirResolver {
    pub fn new(passwd_root: impl Into<PathBuf>, maildir_name: impl Into<String>) -> Self {
        Self {
            passwd_root: passwd_root.into(),
            maildir_name: maildir_name.into(),
        }
    }

    /// 生产布局：`/etc/passwd` + `~/Maildir`。
    pub fn production() -> Self {
        Self::new("/etc", "Maildir")
    }

    pub fn passwd_root(&self) -> &Path {
        &self.passwd_root
    }

    /// 解析 `<passwd_root>/passwd`，返回「账号名 → 家目录」。
    ///
    /// 与 `crates/priv/src/users.rs` 的 `parse_passwd` 同一格式
    /// （`name:passwd:uid:gid:gecos:home:shell`），但不复用实现：那个函数是
    /// `Users` 的私有方法且额外需要 uid/gid。单一真相源是 **passwd 文件格式**，
    /// 不是这段十行解析。
    fn homes(&self) -> Vec<(String, PathBuf)> {
        let Ok(text) = std::fs::read_to_string(self.passwd_root.join("passwd")) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() != 7 {
                    return None;
                }
                Some((fields[0].to_ascii_lowercase(), PathBuf::from(fields[5])))
            })
            .collect()
    }

    fn home_of(&self, account: &str) -> Option<PathBuf> {
        self.homes()
            .into_iter()
            .find(|(name, _)| name == account)
            .map(|(_, home)| home)
    }
}

impl MailboxResolver for SystemMaildirResolver {
    fn resolve(&self, user: &str) -> Option<Arc<MailStore>> {
        let account = account_name(user);
        if account.is_empty() {
            return None;
        }
        let home = self.home_of(&account)?;
        // 家目录不存在 = 账号没建好（或 passwd 里是残留行）：拒绝，别在错误位置
        // 凭空造一个 Maildir 出来，那会让「登录成功但收不到信」变成静默故障。
        if !home.is_dir() {
            tracing::warn!(
                user = %account,
                home = %home.display(),
                "账号家目录不存在，拒绝解析邮箱"
            );
            return None;
        }
        let root = home.join(&self.maildir_name);
        match MailStore::new(root, Arc::new(SystemClock)) {
            Ok(store) => Some(Arc::new(store)),
            Err(error) => {
                tracing::warn!(
                    user = %account,
                    error = %error,
                    "无法打开该账号的 Maildir"
                );
                None
            }
        }
    }

    fn list_users(&self) -> Vec<String> {
        self.homes().into_iter().map(|(name, _)| name).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(passwd: &str, homes: &[(&str, &str)]) -> (tempfile::TempDir, SystemMaildirResolver) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("passwd"), passwd).unwrap();
        for (name, _) in homes {
            std::fs::create_dir_all(dir.path().join("home").join(name)).unwrap();
        }
        let resolver = SystemMaildirResolver::new(dir.path(), "Maildir");
        (dir, resolver)
    }

    #[test]
    fn account_names_strip_the_domain_and_lowercase() {
        assert_eq!(account_name("Alice@Example.COM"), "alice");
        assert_eq!(account_name("  bob "), "bob");
        assert_eq!(account_name(""), "");
    }

    #[test]
    fn resolution_uses_the_passwd_home_and_creates_the_maildir() {
        let (dir, resolver) = fixture(
            "alice:x:1000:1000::/home/alice:/usr/sbin/nologin\n",
            &[("alice", "unused")],
        );
        // 家目录必须在 passwd_root 下真实的 `home/alice`，所以这里改用绝对路径重写。
        let home = dir.path().join("home").join("alice");
        std::fs::write(
            dir.path().join("passwd"),
            format!("alice:x:1000:1000::{}:/usr/sbin/nologin\n", home.display()),
        )
        .unwrap();

        let store = resolver
            .resolve("alice@example.com")
            .expect("完整地址应解析到该账号");
        assert_eq!(store.root(), home.join("Maildir"));
        assert!(store.root().join("cur").is_dir(), "Maildir 结构应被建立");
    }

    #[test]
    fn an_account_missing_from_passwd_is_not_resolved() {
        let (_dir, resolver) = fixture("alice:x:1000:1000::/nonexistent:/usr/sbin/nologin\n", &[]);
        assert!(resolver.resolve("bob@example.com").is_none());
    }

    #[test]
    fn an_account_whose_home_is_missing_is_refused() {
        let (_dir, resolver) = fixture(
            "alice:x:1000:1000::/nonexistent-home-alice:/usr/sbin/nologin\n",
            &[],
        );
        assert!(
            resolver.resolve("alice").is_none(),
            "家目录不存在时不能凭空造 Maildir，否则变成静默故障"
        );
    }

    #[test]
    fn list_users_reports_passwd_accounts() {
        let (dir, resolver) = fixture("alice:x:1:1::/h:/s\nbob:x:2:2::/h:/s\n", &[]);
        let mut users = resolver.list_users();
        users.sort();
        assert_eq!(users, vec!["alice".to_string(), "bob".to_string()]);
        let _ = dir;
    }
}

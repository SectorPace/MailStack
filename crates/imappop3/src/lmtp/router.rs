//! LMTP 收件人路由（替代 Dovecot LMTP 的 `userdb` 查询）。
//!
//! LMTP 只负责「把一封信投进哪个 Maildir」。本模块把这一步抽象成
//! [`LmtpRouter`]：生产装配从 MailStack 的邮箱注册表装载，测试用
//! [`MapRouter`]。路由是同步的（内存表），因为投递路径不应在收信事务里
//! 做网络往返；需要外部目录时，应在启动时把结果缓存进来。

use std::collections::HashMap;
use std::sync::Arc;

use crate::maildir::MailStore;

/// 收件人 → 目标邮箱。
pub trait LmtpRouter: Send + Sync {
    fn route(&self, recipient: &str) -> Option<Arc<MailStore>>;
}

/// 内存路由表（地址大小写不敏感，`<>` 会被剥掉）。
#[derive(Default)]
pub struct MapRouter {
    routes: HashMap<String, Arc<MailStore>>,
}

impl MapRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, address: impl AsRef<str>, store: Arc<MailStore>) {
        self.routes
            .insert(normalize_address(address.as_ref()), store);
    }
}

impl LmtpRouter for MapRouter {
    fn route(&self, recipient: &str) -> Option<Arc<MailStore>> {
        self.routes.get(&normalize_address(recipient)).cloned()
    }
}

fn normalize_address(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch| ch == '<' || ch == '>')
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maildir::SystemClock;

    #[test]
    fn addresses_are_normalised_and_routed() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(MailStore::new(directory.path(), Arc::new(SystemClock)).unwrap());
        let mut router = MapRouter::new();
        router.insert("Bob@Example.com", Arc::clone(&store));
        assert!(router.route("<bob@example.COM>").is_some());
        assert!(router.route("alice@example.com").is_none());
        assert_eq!(normalize_address(" <A@B.C> "), "a@b.c");
    }
}

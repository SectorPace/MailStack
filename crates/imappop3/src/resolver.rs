//! 用户名 → Maildir 存储的解析器。
//!
//! IMAP/POP3 的会话上下文只持有一个用户的 `MailStore`（部署层按用户构造会话）。
//! 但 ManageSieve 是**先认证、后取存储**，且跨用户共享邮箱也需要「按用户名找到别人
//! 的 Maildir」，因此需要一个由部署层注入的解析器。部署层（`mailstackd`）用真实的
//! 用户目录实现；测试与单用户部署用 [`MapResolver`]。

use std::collections::HashMap;
use std::sync::Arc;

use crate::maildir::MailStore;

pub trait MailboxResolver: Send + Sync {
    /// 把认证后的用户名映射到其 Maildir 存储；未知用户返回 `None`。
    fn resolve(&self, user: &str) -> Option<Arc<MailStore>>;

    /// 已知用户名列表（用于 `LIST shared/*` 的发现）。默认不暴露任何用户。
    fn list_users(&self) -> Vec<String> {
        Vec::new()
    }
}

/// 内存映射实现（用户名大小写不敏感）。
#[derive(Default)]
pub struct MapResolver {
    map: HashMap<String, Arc<MailStore>>,
}

impl MapResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, user: &str, store: Arc<MailStore>) {
        self.map.insert(user.to_ascii_lowercase(), store);
    }
}

impl MailboxResolver for MapResolver {
    fn resolve(&self, user: &str) -> Option<Arc<MailStore>> {
        self.map.get(&user.to_ascii_lowercase()).cloned()
    }

    fn list_users(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maildir::SystemClock;

    #[test]
    fn resolver_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MailStore::new(dir.path(), Arc::new(SystemClock)).unwrap());
        let mut resolver = MapResolver::new();
        resolver.insert("Bob@Example.com", Arc::clone(&store));
        assert!(resolver.resolve("bob@example.com").is_some());
        assert!(resolver.resolve("missing@example.com").is_none());
    }
}

use std::collections::HashMap;
use std::sync::Arc;

use crate::maildir::MailStore;

pub trait MailboxResolver: Send + Sync {
    fn resolve(&self, user: &str) -> Option<Arc<MailStore>>;

    fn list_users(&self) -> Vec<String> {
        Vec::new()
    }
}

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

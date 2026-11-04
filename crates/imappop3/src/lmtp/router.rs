use std::collections::HashMap;
use std::sync::Arc;

use crate::maildir::MailStore;

pub trait LmtpRouter: Send + Sync {
    fn route(&self, recipient: &str) -> Option<Arc<MailStore>>;
}

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

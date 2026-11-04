use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use mailstack_core::paths::Paths;

use crate::tables::rows_from_text;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Known,

    Missing,

    Unavailable(String),
}

#[derive(Debug, Clone)]
pub struct LocalRecipients {
    mailboxes: PathBuf,
    aliases: PathBuf,
}

impl LocalRecipients {
    pub fn new(paths: &Paths) -> Self {
        Self {
            mailboxes: paths.managed_mailboxes.clone(),
            aliases: paths.aliases.clone(),
        }
    }

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

    fn alias_sources(&self) -> Result<HashSet<String>, String> {
        let text = read_optional(&self.aliases)?;
        Ok(rows_from_text(&text)
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .map(|source| source.trim().to_ascii_lowercase())
            .filter(|source| !source.is_empty())
            .collect())
    }

    fn mailbox_emails(&self) -> Result<HashSet<String>, String> {
        let text = read_optional(&self.mailboxes)?;
        if text.trim().is_empty() {
            return Ok(HashSet::new());
        }
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|error| format!("{}: {error}", self.mailboxes.display()))?;
        let items = match parsed {
            Value::Array(items) => items,

            _ => return Err(format!("{} is not a JSON array", self.mailboxes.display())),
        };
        Ok(items
            .into_iter()
            .filter_map(|item| {
                item.get("email")
                    .and_then(Value::as_str)
                    .map(|email| email.trim().to_ascii_lowercase())
            })
            .filter(|email| !email.is_empty())
            .collect())
    }
}

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
        let f = Fixture::new()
            .with_mailboxes(&registered())
            .with_aliases("Sales@Example.ORG alice\n");
        assert_eq!(f.recipients.lookup("Alice@Example.org"), Lookup::Known);
        assert_eq!(f.recipients.lookup("ALICE@EXAMPLE.ORG"), Lookup::Known);
        assert_eq!(f.recipients.lookup("SALES@example.org"), Lookup::Known);
    }

    #[test]
    fn a_corrupt_registry_is_unavailable_and_never_missing() {
        let f = Fixture::new().with_raw_mailboxes("{ this is not json");
        assert!(matches!(
            f.recipients.lookup("alice@example.org"),
            Lookup::Unavailable(_)
        ));

        let f = Fixture::new().with_raw_mailboxes(r#"{"email":"alice@example.org"}"#);
        assert!(matches!(
            f.recipients.lookup("alice@example.org"),
            Lookup::Unavailable(_)
        ));
    }

    #[test]
    fn an_empty_registry_file_is_an_empty_directory_not_a_corruption() {
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
        let f = Fixture::new().with_aliases("help@example.org support@other.test\n");
        assert_eq!(f.recipients.lookup("help@example.org"), Lookup::Known);
    }

    #[test]
    fn an_empty_address_is_missing() {
        let f = Fixture::new().with_mailboxes(&registered());
        assert_eq!(f.recipients.lookup("   "), Lookup::Missing);
    }
}

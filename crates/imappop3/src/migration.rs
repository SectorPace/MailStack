use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::error::{MailError, Result};
use crate::maildir::{import_keywords, import_uidlist, MailStore};

const DOVECOT_UIDLIST: &str = "dovecot-uidlist";
const DOVECOT_KEYWORDS: &str = ".dovecot-keywords";

const DOVECOT_UIDLIST_MAX_VERSION: u32 = 3;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub folders: usize,

    pub uidlists_imported: usize,

    pub messages_mapped: usize,

    pub messages_unresolved: usize,

    pub keywords_imported: usize,

    pub rebuilt_from_disk: usize,
}

struct DovecotUidList {
    uidvalidity: u32,
    uidnext: u32,
    records: Vec<(u32, String)>,
}

pub fn migrate_maildir(store: &MailStore) -> Result<MigrationReport> {
    let mut report = MigrationReport::default();
    for folder in store.folders()? {
        let path = store.folder_path(&folder)?;
        report.folders += 1;

        if let Some(map) = parse_dovecot_keywords(&path.join(DOVECOT_KEYWORDS))? {
            match import_keywords(&path, &map) {
                Ok(imported) => report.keywords_imported += imported,
                Err(MailError::AlreadyExists(_)) => {
                    tracing::debug!(folder = %folder, "keywords already native; skipped");
                }
                Err(error) => {
                    tracing::warn!(folder = %folder, %error, "keyword import failed; continuing");
                }
            }
        }

        match parse_dovecot_uidlist(&path.join(DOVECOT_UIDLIST))? {
            Some(parsed) => {
                match import_uidlist(&path, parsed.uidvalidity, parsed.uidnext, &parsed.records) {
                    Ok(import) => {
                        report.messages_unresolved += import.unresolved;
                        if import.mapped > 0 {
                            report.uidlists_imported += 1;
                            report.messages_mapped += import.mapped;
                        } else {
                            report.rebuilt_from_disk += 1;
                            tracing::info!(
                                folder = %folder,
                                "no Dovecot UID matched on-disk mail; rebuilding with fresh UIDVALIDITY"
                            );
                        }
                    }
                    Err(MailError::AlreadyExists(_)) => {
                        tracing::debug!(folder = %folder, "uidlist already native; skipped");
                    }

                    Err(error) => return Err(error),
                }
            }
            None => report.rebuilt_from_disk += 1,
        }
    }
    Ok(report)
}

fn parse_dovecot_uidlist(path: &Path) -> Result<Option<DovecotUidList>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MailError::io(path, error)),
    };
    let mut lines = contents.lines();
    let Some(header) = lines.next() else {
        return Ok(None);
    };
    let mut fields = header.split_whitespace();
    let Some(version) = fields.next().and_then(|token| token.parse::<u32>().ok()) else {
        tracing::warn!(path = %path.display(), "dovecot-uidlist header has no version; rebuilding");
        return Ok(None);
    };
    if version == 0 || version > DOVECOT_UIDLIST_MAX_VERSION {
        tracing::warn!(
            path = %path.display(),
            version,
            "unsupported dovecot-uidlist version; rebuilding"
        );
        return Ok(None);
    }
    let Some(uidvalidity) = fields.next().and_then(|token| token.parse::<u32>().ok()) else {
        return Ok(None);
    };
    let Some(uidnext) = fields.next().and_then(|token| token.parse::<u32>().ok()) else {
        return Ok(None);
    };
    if uidvalidity == 0 {
        return Ok(None);
    }
    let mut records = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((uid_field, rest)) = line.split_once(' ') else {
            continue;
        };
        let Ok(uid) = uid_field.parse::<u32>() else {
            continue;
        };
        let base = dovecot_base(rest);
        if base.is_empty() {
            continue;
        }
        records.push((uid, base.to_string()));
    }
    Ok(Some(DovecotUidList {
        uidvalidity,
        uidnext,
        records,
    }))
}

fn parse_dovecot_keywords(path: &Path) -> Result<Option<BTreeMap<char, String>>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MailError::io(path, error)),
    };
    let mut map = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((index_field, keyword)) = line.split_once(' ') else {
            continue;
        };
        let Ok(index) = index_field.parse::<u32>() else {
            continue;
        };
        if index > 25 {
            continue;
        }
        let letter = (b'a' + index as u8) as char;
        map.insert(letter, keyword.to_string());
    }
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(map))
}

fn dovecot_base(field: &str) -> &str {
    let field = field.strip_prefix(':').unwrap_or(field);
    match field.split_once(":2,") {
        Some((base, _)) => base,
        None => field,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maildir::{Flag, MailStore, SystemClock, SystemFlag};
    use std::sync::Arc;

    fn maildir_dirs(root: &Path) {
        for sub in ["cur", "new", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
    }

    fn write_msg(folder: &Path, dir: &str, name: &str) {
        fs::write(folder.join(dir).join(name), b"Subject: hi\r\n\r\nbody\r\n").unwrap();
    }

    #[test]
    fn dovecot_base_handles_all_record_shapes() {
        assert_eq!(dovecot_base("1234.host"), "1234.host");
        assert_eq!(dovecot_base("1234.host:2,S"), "1234.host");
        assert_eq!(dovecot_base(":1234.host:2,RS"), "1234.host");
        assert_eq!(dovecot_base(":1234.host"), "1234.host");
    }

    #[test]
    fn parse_uidlist_rejects_unknown_version_and_bad_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DOVECOT_UIDLIST);

        fs::write(&path, "9 12345 10\n").unwrap();
        assert!(parse_dovecot_uidlist(&path).unwrap().is_none());

        fs::write(&path, "0 12345 10\n").unwrap();
        assert!(parse_dovecot_uidlist(&path).unwrap().is_none());

        fs::write(&path, "3 0 10\n").unwrap();
        assert!(parse_dovecot_uidlist(&path).unwrap().is_none());

        fs::write(&path, "garbage\n").unwrap();
        assert!(parse_dovecot_uidlist(&path).unwrap().is_none());

        fs::write(&path, "3 12345\n").unwrap();
        assert!(
            parse_dovecot_uidlist(&path).unwrap().is_none(),
            "缺少 next-uid 时不可导入"
        );

        assert!(parse_dovecot_uidlist(&dir.path().join("missing"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn parse_uidlist_reads_v3_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DOVECOT_UIDLIST);
        fs::write(&path, "3 1234567890 7\n5 a.host:2,S\n6 :b.host:2,\n\n").unwrap();
        let parsed = parse_dovecot_uidlist(&path).unwrap().unwrap();
        assert_eq!(parsed.uidvalidity, 1234567890);
        assert_eq!(parsed.uidnext, 7);
        assert_eq!(
            parsed.records,
            vec![(5, "a.host".to_string()), (6, "b.host".to_string())]
        );
    }

    #[test]
    fn parse_keywords_maps_index_to_letter_and_skips_out_of_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DOVECOT_KEYWORDS);
        fs::write(&path, "0 work\n1 receipts\n99 nope\n").unwrap();
        let map = parse_dovecot_keywords(&path).unwrap().unwrap();
        assert_eq!(map.get(&'a').map(String::as_str), Some("work"));
        assert_eq!(map.get(&'b').map(String::as_str), Some("receipts"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn migrate_preserves_dovecot_uids_and_keywords() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        maildir_dirs(root);

        write_msg(root, "cur", "1000.alpha:2,S");
        write_msg(root, "cur", "1001.beta:2,RSa");
        write_msg(root, "new", "1002.gamma");

        fs::write(
            root.join(DOVECOT_UIDLIST),
            "3 1234567890 11\n7 :1000.alpha:2,S\n8 :1001.beta:2,RSa\n9 :1002.gamma\n10 :9999.zeta:2,S\n",
        )
        .unwrap();
        fs::write(root.join(DOVECOT_KEYWORDS), "0 work\n").unwrap();

        let sent = root.join(".Sent");
        maildir_dirs(&sent);
        write_msg(&sent, "cur", "2000.delta:2,S");
        fs::write(sent.join(DOVECOT_UIDLIST), "3 555 43\n42 :2000.delta:2,S\n").unwrap();

        let store = MailStore::new(root, Arc::new(SystemClock)).unwrap();
        let report = migrate_maildir(&store).unwrap();

        assert_eq!(report.folders, 2);
        assert_eq!(report.uidlists_imported, 2);
        assert_eq!(report.messages_mapped, 4);
        assert_eq!(report.messages_unresolved, 1);
        assert_eq!(report.keywords_imported, 1);
        assert_eq!(report.rebuilt_from_disk, 0);

        let inbox = store.open_folder("INBOX", false).unwrap();
        assert_eq!(inbox.uidvalidity, 1234567890);
        assert_eq!(inbox.uidnext, 11);
        let uid_of = |base: &str| {
            inbox
                .messages
                .iter()
                .find(|message| message.base == base)
                .map(|message| message.uid)
        };
        assert_eq!(uid_of("1000.alpha"), Some(7));
        assert_eq!(uid_of("1001.beta"), Some(8));
        assert_eq!(uid_of("1002.gamma"), Some(9));

        let beta = inbox
            .messages
            .iter()
            .find(|message| message.base == "1001.beta")
            .unwrap();
        assert!(beta.flags.contains(&Flag::Keyword("work".to_string())));
        assert!(beta.flags.contains(&Flag::System(SystemFlag::Seen)));
        assert!(beta.flags.contains(&Flag::System(SystemFlag::Answered)));

        let sent_state = store.open_folder("Sent", false).unwrap();
        assert_eq!(sent_state.uidvalidity, 555);
        assert_eq!(sent_state.messages.len(), 1);
        assert_eq!(sent_state.messages[0].uid, 42);
    }

    #[test]
    fn migrate_rebuilds_when_no_dovecot_uid_matches_disk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        maildir_dirs(root);
        write_msg(root, "cur", "1000.alpha:2,S");

        fs::write(
            root.join(DOVECOT_UIDLIST),
            "3 1234567890 5\n3 :7777.gone:2,S\n4 :8888.also_gone:2,\n",
        )
        .unwrap();

        let store = MailStore::new(root, Arc::new(SystemClock)).unwrap();
        let report = migrate_maildir(&store).unwrap();
        assert_eq!(report.uidlists_imported, 0);
        assert_eq!(report.messages_mapped, 0);
        assert_eq!(report.messages_unresolved, 2);
        assert_eq!(report.rebuilt_from_disk, 1);

        assert!(!root.join(".mailstack-uidlist").exists());

        let inbox = store.open_folder("INBOX", false).unwrap();
        assert_ne!(inbox.uidvalidity, 1234567890);
        assert_eq!(inbox.messages.len(), 1);
        assert_eq!(inbox.messages[0].base, "1000.alpha");
    }

    #[test]
    fn migrate_is_idempotent_and_refuses_to_clobber_native_uidlist() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        maildir_dirs(root);
        write_msg(root, "cur", "1000.alpha:2,S");
        fs::write(
            root.join(DOVECOT_UIDLIST),
            "3 1234567890 9\n7 :1000.alpha:2,S\n",
        )
        .unwrap();

        let store = MailStore::new(root, Arc::new(SystemClock)).unwrap();
        let first = migrate_maildir(&store).unwrap();
        assert_eq!(first.uidlists_imported, 1);
        assert_eq!(first.messages_mapped, 1);

        let second = migrate_maildir(&store).unwrap();
        assert_eq!(second.uidlists_imported, 0);
        assert_eq!(second.messages_mapped, 0);
        assert_eq!(second.folders, 1);

        let inbox = store.open_folder("INBOX", false).unwrap();
        assert_eq!(inbox.uidvalidity, 1234567890);
        assert_eq!(inbox.messages[0].uid, 7);
    }
}

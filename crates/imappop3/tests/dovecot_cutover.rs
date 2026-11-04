use std::fs;
use std::path::Path;
use std::sync::Arc;

use mailstack_imappop3::{migrate_maildir, Flag, MailStore, SystemClock, INBOX};

fn maildir_dirs(path: &Path) {
    for sub in ["cur", "new", "tmp"] {
        fs::create_dir_all(path.join(sub)).unwrap();
    }
}

#[test]
fn dovecot_cutover_preserves_uids_keywords_and_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    maildir_dirs(root);

    fs::write(
        root.join("cur/1700000001.M1.host:2,S"),
        b"Subject: one\r\n\r\n1",
    )
    .unwrap();
    fs::write(
        root.join("cur/1700000002.M2.host:2,RSa"),
        b"Subject: two\r\n\r\n2",
    )
    .unwrap();
    fs::write(
        root.join("new/1700000003.M3.host"),
        b"Subject: three\r\n\r\n3",
    )
    .unwrap();
    fs::write(
        root.join("cur/1700000004.M4.host:2,"),
        b"Subject: four\r\n\r\n4",
    )
    .unwrap();
    fs::write(
        root.join("dovecot-uidlist"),
        "3 1700000000 13\n\
         10 :1700000001.M1.host:2,S\n\
         11 1700000002.M2.host:2,RSa\n\
         12 :1700000003.M3.host\n\
         99 :1699999999.Deleted.host:2,S\n",
    )
    .unwrap();
    fs::write(root.join(".dovecot-keywords"), "0 $label1\n1 work\n").unwrap();

    let sent = root.join(".Sent");
    maildir_dirs(&sent);
    fs::write(
        sent.join("cur/1700000005.S1.host:2,S"),
        b"Subject: sent\r\n\r\ns",
    )
    .unwrap();
    fs::write(
        sent.join("dovecot-uidlist"),
        "3 1600000000 8\n5 :1700000005.S1.host:2,S\n",
    )
    .unwrap();

    let store = MailStore::new(root, Arc::new(SystemClock)).unwrap();
    let report = migrate_maildir(&store).unwrap();
    assert_eq!(report.folders, 2);
    assert_eq!(report.uidlists_imported, 2);
    assert_eq!(report.messages_mapped, 4);
    assert_eq!(
        report.messages_unresolved, 1,
        "已删除邮件对应的记录应被丢弃"
    );
    assert_eq!(report.keywords_imported, 2);
    assert_eq!(report.rebuilt_from_disk, 0);

    let inbox = store.open_folder(INBOX, false).unwrap();
    assert_eq!(inbox.uidvalidity, 1_700_000_000, "UIDVALIDITY 必须保留");
    let uid = |base: &str| {
        inbox
            .messages
            .iter()
            .find(|message| message.base == base)
            .map(|message| message.uid)
    };
    assert_eq!(uid("1700000001.M1.host"), Some(10));
    assert_eq!(uid("1700000002.M2.host"), Some(11));
    assert_eq!(uid("1700000003.M3.host"), Some(12));

    assert_eq!(uid("1700000004.M4.host"), Some(13));
    assert!(inbox.uidnext > 13);

    let m2 = inbox
        .messages
        .iter()
        .find(|message| message.base == "1700000002.M2.host")
        .unwrap();
    assert!(m2.flags.contains(&Flag::Keyword("$label1".to_string())));

    let sent_state = store.open_folder("Sent", false).unwrap();
    assert_eq!(sent_state.uidvalidity, 1_600_000_000);
    assert_eq!(sent_state.messages[0].uid, 5);

    let again = migrate_maildir(&store).unwrap();
    assert_eq!(again.folders, 2);
    assert_eq!(again.uidlists_imported, 0);
    assert_eq!(again.messages_mapped, 0);
    let reopened = store.open_folder(INBOX, false).unwrap();
    assert_eq!(reopened.uidvalidity, inbox.uidvalidity);
    assert_eq!(reopened.uidnext, inbox.uidnext);
}

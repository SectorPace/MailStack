//! Dovecot → MailStack 的**离线** Maildir 迁移。
//!
//! ## 为什么需要它
//!
//! MailStack 与 Dovecot 都读写标准 Maildir 本体（`cur/new/tmp` +
//! `<unique>:2,<flags>`），所以邮件文件本身**不需要转换**。需要迁移的是两套实现
//! 各自的私有元数据：
//!
//! | 语义 | Dovecot | MailStack |
//! |------|---------|-----------|
//! | UID 映射 | `dovecot-uidlist` | `.mailstack-uidlist` |
//! | 关键字字母表 | `.dovecot-keywords` | `.mailstack-keywords` |
//!
//! 不迁移直接启动 MailStack 也能工作 —— 首次 `open_folder` 会扫描磁盘重建映射，
//! 但会分配**全新的 UIDVALIDITY**，迫使所有 IMAP 客户端把每个信箱重新同步一遍。
//! 对大信箱这是几分钟到几小时的带宽与 CPU。本模块在切换前把 Dovecot 的 UID 与
//! UIDVALIDITY 原样接管过来，客户端只会看到一次普通刷新。
//!
//! ## 使用约束（务必遵守）
//!
//! * **离线迁移**：调用 [`migrate_maildir`] 时 Dovecot 必须已经停止、且没有任何
//!   MailStack 进程在读写该 Maildir。两套实现同时写一个 Maildir 会产生两套 UID。
//! * **先迁移、后打开**：必须在任何 `open_folder` / SELECT / 投递之前调用。一旦
//!   MailStack 写下了自己的 `.mailstack-uidlist`，本模块会**拒绝**覆盖（该文件夹
//!   按「已是原生格式」跳过），以免破坏已经建立的映射。
//! * **格式需按现场 Dovecot 版本核验**：`dovecot-uidlist` 的精确字节格式随版本
//!   演进，本解析器覆盖常见的 v1–v3 形状并**防御式**处理（见下）。生产切换前，
//!   请先在目标 Dovecot 的真实信箱上跑一遍、核对 [`MigrationReport`] 的计数。
//!
//! ## 防御式与 fail-closed
//!
//! 解析器对任何不认识的形状都**不猜**：
//!
//! * 头部版本不在 `1..=3`、或 `uidvalidity == 0`、或字段缺失 → 整个文件视为
//!   「不可导入」，该文件夹回退到磁盘重建（计入 `rebuilt_from_disk`）。
//! * 逐条记录：UID 解析失败、base 非法、或 base **不在磁盘上** → 丢弃该条
//!   （计入 `messages_unresolved`），其余照常。
//! * 若一个文件夹**没有任何**记录能对上磁盘（`mapped == 0`），则**不写** uidlist，
//!   让 MailStack 用全新 UIDVALIDITY 重建 —— 保留旧 UIDVALIDITY 却换了 UID 会让
//!   客户端把缓存贴错邮件，比强制重同步危险得多。
//!
//! 换句话说：迁移**最多**保留能确证的 UID，**绝不**制造 UID 与消息的错误关联。

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::error::{MailError, Result};
use crate::maildir::{import_keywords, import_uidlist, MailStore};

const DOVECOT_UIDLIST: &str = "dovecot-uidlist";
const DOVECOT_KEYWORDS: &str = ".dovecot-keywords";
/// 接受的 `dovecot-uidlist` 头部版本上限（含）。超出即 fail-closed。
const DOVECOT_UIDLIST_MAX_VERSION: u32 = 3;

/// 一次 [`migrate_maildir`] 的汇总，供运维核对与告警。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// 扫描到的文件夹总数（含 INBOX）。
    pub folders: usize,
    /// 成功接管 Dovecot UID 映射的文件夹数。
    pub uidlists_imported: usize,
    /// 保留了原 Dovecot UID 的消息总数。
    pub messages_mapped: usize,
    /// Dovecot 记录里对不上磁盘而被丢弃的消息总数。
    pub messages_unresolved: usize,
    /// 导入的关键字（字母 → 关键字）总条数。
    pub keywords_imported: usize,
    /// 因无可导入映射而回退到「磁盘重建 + 全新 UIDVALIDITY」的文件夹数。
    pub rebuilt_from_disk: usize,
}

/// 解析出来的 `dovecot-uidlist`。
struct DovecotUidList {
    uidvalidity: u32,
    uidnext: u32,
    records: Vec<(u32, String)>,
}

/// 把一个 Dovecot Maildir 存储原地迁移到 MailStack 的私有元数据格式。
///
/// 见模块级文档：必须**离线**、且在任何 `open_folder` 之前调用。对每个文件夹
/// 先导入关键字字母表、再导入 UID 映射；已经是 MailStack 原生格式的文件夹会被
/// 跳过（幂等）。单个文件夹的元数据缺失或不可解析不会中断整次迁移，只会让它
/// 回退到磁盘重建并计入 [`MigrationReport::rebuilt_from_disk`]。
pub fn migrate_maildir(store: &MailStore) -> Result<MigrationReport> {
    let mut report = MigrationReport::default();
    for folder in store.folders()? {
        let path = store.folder_path(&folder)?;
        report.folders += 1;

        // 关键字先于 uidlist 导入：open_folder 解析文件名里的关键字字母时需要
        // `.mailstack-keywords` 已就位。（base 提取本身不依赖它。）
        if let Some(map) = parse_dovecot_keywords(&path.join(DOVECOT_KEYWORDS))? {
            match import_keywords(&path, &map) {
                Ok(imported) => report.keywords_imported += imported,
                Err(MailError::AlreadyExists(_)) => {
                    tracing::debug!(folder = %folder, "keywords already native; skipped");
                }
                Err(error) => {
                    // 关键字是尽力而为：导入失败只会让 Dovecot 的自定义关键字
                    // 字母暂不被识别，不影响 UID 稳定性，故不中断迁移。
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
                    // 真正的 I/O 故障（磁盘、权限）向上抛：离线工具中途失败后，
                    // 运维修复并重跑即可，已完成的文件夹会被幂等跳过。
                    Err(error) => return Err(error),
                }
            }
            None => report.rebuilt_from_disk += 1,
        }
    }
    Ok(report)
}

/// 解析 `dovecot-uidlist`。返回 `None` 表示「不可导入」（缺失、版本不识别、
/// 头部字段非法），调用方应回退到磁盘重建。
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

/// 解析 `.dovecot-keywords`（`<0-based index> <keyword>`），把索引映射回字母
/// `a`–`z`。返回 `None` 表示文件缺失或没有可用条目。关键字本身的合法性由
/// `import_keywords` 逐条校验。
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

/// 从 `dovecot-uidlist` 记录的文件名字段提取 Maildir unique base。
///
/// 兼容三种常见形状：`<base>`、`<base>:2,<flags>`、以及带前导 `:` 的
/// `:<base>:2,<flags>`（某些 Dovecot 版本的写法）。base 即去掉至多一个前导 `:`、
/// 再截断到 `:2,` 之前的部分 —— 与 `scan_folder` 的 base 提取口径一致，磁盘交叉
/// 核对才能对得上。
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
        write_msg(root, "cur", "1001.beta:2,RSa"); // 'a' → 关键字 work
        write_msg(root, "new", "1002.gamma");

        // UID 7/8/9 对应 alpha/beta/gamma；UID 10 指向已删除的 zeta（应丢弃）。
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
        // uidlist 只提到磁盘上不存在的消息。
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

        // mapped == 0：迁移阶段绝不写 uidlist。
        assert!(!root.join(".mailstack-uidlist").exists());

        // open_folder 用全新 UIDVALIDITY 重建，绝不复用 Dovecot 的。
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

        // 第二次运行：已是原生格式，幂等跳过，不重复计数、不报错。
        let second = migrate_maildir(&store).unwrap();
        assert_eq!(second.uidlists_imported, 0);
        assert_eq!(second.messages_mapped, 0);
        assert_eq!(second.folders, 1);

        let inbox = store.open_folder("INBOX", false).unwrap();
        assert_eq!(inbox.uidvalidity, 1234567890);
        assert_eq!(inbox.messages[0].uid, 7);
    }
}

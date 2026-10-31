//! 邮箱口令记录库 —— IMAP/POP3（`mailstack-imap`）的唯一口令来源。
//!
//! ## 为什么需要它
//!
//! 重写前 IMAP/POP3 由 Dovecot 提供，口令校验走 PAM（读 `/etc/shadow` 的
//! crypt 哈希）。换成自研协议面（`crates/imappop3`）之后有两条路：
//!
//! 1. 继续读 `/etc/shadow` —— 要在纯 Rust 里实现 yescrypt / `$6$` / `$2b$`
//!    多套 crypt 算法，且**违反正本仓库 INV-37**（「PBKDF2-SHA256 记录是口令的
//!    唯一真相源」）；
//! 2. 由 MailStack 自己持有 PBKDF2 记录 —— 本模块。
//!
//! 选了 2。代价是**迁移期两份口令并存**（系统口令供 Postfix/PAM 用，
//! 记录供 IMAP/POP3 用），因此 `users.create` / `users.password` 必须同时写两边；
//! 任何一边写失败都要如实报错，不能只成功一半（见 `crates/priv/src/users.rs`）。
//!
//! ## 文件格式
//!
//! ```json
//! { "version": 1, "records": { "alice@example.com": { ...PasswordRecord } } }
//! ```
//!
//! * 键是**小写**用户名（邮箱地址或 unix 账号名，见 [`key`]）；
//! * 文件权限 `0600 root:root`：口令哈希可离线爆破，不得给组/其他用户读；
//! * 缺失文件 = 合法的空库（尚未创建任何邮箱）；
//! * **损坏/版本不符/非空但读不出来 = 错误**，绝不当作空库 —— 否则一次截断
//!   就会让所有邮箱「找不到口令」，排障方向会被误导到认证逻辑。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{CoreError, CoreResult};
use crate::password::PasswordRecord;

/// 文件格式版本。加字段可以不动它；改变语义或键的含义必须递增。
pub const FORMAT_VERSION: u32 = 1;

/// 口令库文件的权限位：只允许 root 读。
pub const FILE_MODE: u32 = 0o600;

/// 规范化用户名：去空白、转小写。
///
/// 认证输入的地址大小写不敏感（RFC 5321 的 local-part 理论上有大小写，
/// 但本项目的账号名一律小写，`users.*` 也按小写建号），因此键统一小写。
pub fn key(user: &str) -> String {
    user.trim().to_ascii_lowercase()
}

#[derive(Debug, Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    records: BTreeMap<String, PasswordRecord>,
}

/// 邮箱口令记录库（一个 JSON 文件）。
#[derive(Debug, Clone)]
pub struct MailboxPasswords {
    path: PathBuf,
}

impl MailboxPasswords {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// 生产路径：`<Paths::mailbox_passwords>`。
    pub fn at(paths: &crate::paths::Paths) -> Self {
        Self::new(paths.mailbox_passwords.clone())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读取全部记录（键已小写）。
    ///
    /// 文件不存在 → 空表。文件存在但读不出 / JSON 损坏 / 版本不符 → `Err`。
    pub fn load(&self) -> CoreResult<BTreeMap<String, PasswordRecord>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => return Err(CoreError::io(&self.path, error)),
        };
        // 空文件等价于「从未配置」；这在实际运维里出现过（touch 出来的文件）。
        if text.trim().is_empty() {
            return Ok(BTreeMap::new());
        }
        let parsed: FileFormat = serde_json::from_str(&text).map_err(|error| {
            CoreError::invalid(format!(
                "邮箱口令库无法解析（{}）：{error}",
                self.path.display()
            ))
        })?;
        if parsed.version != FORMAT_VERSION {
            return Err(CoreError::invalid(format!(
                "邮箱口令库版本不符（{}）：期望 {FORMAT_VERSION}，实为 {}",
                self.path.display(),
                parsed.version
            )));
        }
        let mut out = BTreeMap::new();
        for (raw, record) in parsed.records {
            out.insert(key(&raw), record);
        }
        Ok(out)
    }

    /// 查一个用户的口令记录。
    pub fn get(&self, user: &str) -> CoreResult<Option<PasswordRecord>> {
        Ok(self.load()?.remove(&key(user)))
    }

    /// 写入（新增或覆盖）一条记录。
    ///
    /// 整个读改写都在 [`atomic::locked`] 的跨进程文件锁里完成，因此并发调用
    /// 不会互相丢记录；落盘走临时文件 + rename（[`atomic::atomic_as`]）。
    pub fn upsert(&self, record: &PasswordRecord) -> CoreResult<()> {
        let user_key = key(&record.username);
        if user_key.is_empty() {
            return Err(CoreError::invalid("邮箱口令记录的用户名不得为空"));
        }
        atomic::locked(&self.path, || {
            let mut records = self.load()?;
            records.insert(user_key.clone(), record.clone());
            self.write_all(&records)
        })
    }

    /// 删除一条记录；返回「是否真的删掉了」。
    pub fn remove(&self, user: &str) -> CoreResult<bool> {
        let user_key = key(user);
        atomic::locked(&self.path, || {
            let mut records = self.load()?;
            let removed = records.remove(&user_key).is_some();
            if removed {
                self.write_all(&records)?;
            }
            Ok(removed)
        })
    }

    fn write_all(&self, records: &BTreeMap<String, PasswordRecord>) -> CoreResult<()> {
        let file = FileFormat {
            version: FORMAT_VERSION,
            records: records.clone(),
        };
        let mut text = serde_json::to_string_pretty(&file)
            .map_err(|error| CoreError::invalid(format!("邮箱口令库序列化失败：{error}")))?;
        text.push('\n');
        atomic::atomic_as(&self.path, text.as_bytes(), FILE_MODE, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, MailboxPasswords) {
        let dir = tempfile::tempdir().unwrap();
        let store = MailboxPasswords::new(dir.path().join("mailbox-passwords.json"));
        (dir, store)
    }

    fn record(user: &str, password: &str) -> PasswordRecord {
        crate::password::password_record(user, password).unwrap()
    }

    #[test]
    fn an_absent_file_is_an_empty_store_not_an_error() {
        let (_dir, store) = fixture();
        assert!(store.load().unwrap().is_empty());
        assert!(store.get("nobody@example.com").unwrap().is_none());
    }

    #[test]
    fn upsert_then_get_roundtrips_and_is_case_insensitive() {
        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();

        let got = store
            .get("  ALICE ")
            .unwrap()
            .expect("应能按大小写不敏感查到");
        assert_eq!(got.username, "alice");
        assert!(
            crate::password::verify_password(&got, "Correct-Horse-9"),
            "写进去的口令必须能验过"
        );
        assert!(!crate::password::verify_password(&got, "wrong-password-1"));
    }

    #[test]
    fn upsert_preserves_records_it_did_not_touch() {
        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();
        store.upsert(&record("bob", "Battery-Staple-7")).unwrap();
        store.upsert(&record("carol", "Tr0ubadour-9x")).unwrap();

        let all = store.load().unwrap();
        assert_eq!(all.len(), 3, "三次 upsert 之后必须三条都在");
        assert!(all.contains_key("alice"));
        assert!(all.contains_key("bob"));
        assert!(all.contains_key("carol"));
    }

    #[test]
    fn upsert_overwrites_the_same_user_instead_of_duplicating() {
        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();
        store.upsert(&record("alice", "Battery-Staple-7")).unwrap();

        let all = store.load().unwrap();
        assert_eq!(all.len(), 1);
        assert!(crate::password::verify_password(
            all.get("alice").unwrap(),
            "Battery-Staple-7"
        ));
    }

    #[test]
    fn removing_a_user_reports_whether_it_existed() {
        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();
        assert!(store.remove("ALICE").unwrap(), "存在则返回 true");
        assert!(!store.remove("alice").unwrap(), "第二次删除返回 false");
        assert!(store.load().unwrap().is_empty());
    }

    #[test]
    fn a_corrupt_file_is_an_error_not_an_empty_store() {
        let (dir, store) = fixture();
        std::fs::write(dir.path().join("mailbox-passwords.json"), "{not json").unwrap();

        let error = store.load().expect_err("损坏的口令库必须报错");
        assert!(
            format!("{error}").contains("无法解析"),
            "错误信息应指出是解析失败：{error}"
        );
        // 关键：损坏时**不能**被当成空库，否则所有邮箱都「查不到口令」。
        assert!(store.get("alice").is_err(), "get 也必须把损坏暴露出来");
    }

    #[test]
    fn a_wrong_format_version_is_rejected() {
        let (dir, store) = fixture();
        std::fs::write(
            dir.path().join("mailbox-passwords.json"),
            r#"{"version":999,"records":{}}"#,
        )
        .unwrap();

        let error = store.load().expect_err("版本不符必须报错");
        assert!(format!("{error}").contains("版本不符"), "{error}");
    }

    #[test]
    fn the_file_is_written_readable_by_root_only() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();

        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, FILE_MODE, "口令哈希不得给组或其他用户读");
    }

    #[test]
    fn an_empty_file_counts_as_never_configured() {
        let (dir, store) = fixture();
        std::fs::write(dir.path().join("mailbox-passwords.json"), "   \n").unwrap();
        assert!(store.load().unwrap().is_empty());
    }

    /// 反例：去掉 `atomic::locked` 后，并发 upsert 会互相覆盖（丢记录）。
    #[test]
    fn concurrent_upserts_do_not_lose_records() {
        let (dir, store) = fixture();
        let path = dir.path().join("mailbox-passwords.json");
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let store = MailboxPasswords::new(path.clone());
                std::thread::spawn(move || {
                    let user = format!("user{i}");
                    store
                        .upsert(&record(&user, "Correct-Horse-9"))
                        .expect("并发写入不得失败");
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        let all = store.load().unwrap();
        assert_eq!(all.len(), 8, "8 个线程各写一条，一条都不能丢：{all:?}");
    }
}

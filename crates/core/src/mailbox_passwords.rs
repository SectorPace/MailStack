use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::error::{CoreError, CoreResult};
use crate::password::PasswordRecord;

pub const FORMAT_VERSION: u32 = 1;

pub const FILE_MODE: u32 = 0o600;

pub fn key(user: &str) -> String {
    user.trim().to_ascii_lowercase()
}

pub fn candidate_keys(user: &str) -> Vec<String> {
    let normalized = key(user);
    let mut keys = vec![normalized.clone()];
    if let Some((local, _)) = normalized.split_once('@') {
        if !local.is_empty() && local != normalized {
            keys.push(local.to_string());
        }
    }
    keys
}

#[derive(Debug, Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    records: BTreeMap<String, PasswordRecord>,
}

#[derive(Debug)]
struct DbCache {
    path: PathBuf,
    mtime: SystemTime,
    len: u64,
    parsed: Arc<BTreeMap<String, PasswordRecord>>,
}

#[derive(Debug, Clone)]
pub struct MailboxPasswords {
    path: PathBuf,
    cache: Arc<Mutex<Option<DbCache>>>,
}

impl MailboxPasswords {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub fn at(paths: &crate::paths::Paths) -> Self {
        Self::new(paths.mailbox_passwords.clone())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> CoreResult<BTreeMap<String, PasswordRecord>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => return Err(CoreError::io(&self.path, error)),
        };

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

    pub fn get(&self, user: &str) -> CoreResult<Option<PasswordRecord>> {
        Ok(self.load_cached()?.get(&key(user)).cloned())
    }

    fn load_cached(&self) -> CoreResult<Arc<BTreeMap<String, PasswordRecord>>> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                *self.lock_cache() = None;
                return Ok(Arc::new(BTreeMap::new()));
            }
            Err(error) => return Err(CoreError::io(&self.path, error)),
        };
        let mtime = meta
            .modified()
            .map_err(|error| CoreError::io(&self.path, error))?;
        let len = meta.len();

        {
            let guard = self.lock_cache();
            if let Some(cached) = guard.as_ref() {
                if cached.path == self.path && cached.mtime == mtime && cached.len == len {
                    return Ok(Arc::clone(&cached.parsed));
                }
            }
        }
        match self.load() {
            Ok(records) => {
                let parsed = Arc::new(records);
                *self.lock_cache() = Some(DbCache {
                    path: self.path.clone(),
                    mtime,
                    len,
                    parsed: Arc::clone(&parsed),
                });
                Ok(parsed)
            }
            Err(error) => {
                *self.lock_cache() = None;
                Err(error)
            }
        }
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, Option<DbCache>> {
        match self.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn upsert(&self, record: &PasswordRecord) -> CoreResult<()> {
        let user_key = key(&record.username);
        if user_key.is_empty() {
            return Err(CoreError::invalid("邮箱口令记录的用户名不得为空"));
        }
        atomic::locked(&self.path, || {
            let mut records = self.load()?;
            records.insert(user_key.clone(), record.clone());
            self.write_all(&records)
        })?;
        *self.lock_cache() = None;
        Ok(())
    }

    pub fn remove(&self, user: &str) -> CoreResult<bool> {
        let user_key = key(user);
        let removed = atomic::locked(&self.path, || {
            let mut records = self.load()?;
            let removed = records.remove(&user_key).is_some();
            if removed {
                self.write_all(&records)?;
            }
            Ok(removed)
        })?;
        if removed {
            *self.lock_cache() = None;
        }
        Ok(removed)
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

    #[test]
    fn upsert_and_remove_are_visible_to_the_next_get() {
        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();
        assert!(store.get("alice").unwrap().is_some(), "预热缓存");
        assert!(store.get("nobody").unwrap().is_none(), "预热负结果");

        store.upsert(&record("nobody", "Battery-Staple-7")).unwrap();
        assert!(
            store.get("nobody").unwrap().is_some(),
            "写入后下一次 get 必须看到新记录（缓存不得掩盖写路径）"
        );

        store.remove("nobody").unwrap();
        assert!(store.get("nobody").unwrap().is_none(), "删除后必须看不到");
    }

    #[test]
    fn get_picks_up_external_modifications() {
        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();
        assert!(store.get("alice").unwrap().is_some(), "预热缓存");

        let mut all = store.load().unwrap();
        all.insert("bob".to_string(), record("bob", "Battery-Staple-7"));
        let file = FileFormat {
            version: FORMAT_VERSION,
            records: all,
        };
        let mut text = serde_json::to_string_pretty(&file).unwrap();
        text.push('\n');
        std::fs::write(store.path(), text).unwrap();

        assert!(
            store.get("bob").unwrap().is_some(),
            "外部新增的记录必须可见：缓存不得掩盖磁盘现状"
        );
        assert!(store.get("alice").unwrap().is_some(), "原有记录不受影响");
    }

    #[test]
    fn a_corrupt_file_is_still_an_error_after_the_cache_is_warm() {
        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();
        assert!(store.get("alice").unwrap().is_some(), "预热缓存");

        std::fs::write(
            store.path(),
            "{\"version\":1,\"records\":{},\"trailing garbage\"",
        )
        .unwrap();
        assert!(store.get("alice").is_err(), "缓存不得掩盖一次真实损坏");
    }

    #[test]
    fn a_deleted_file_reads_as_empty_again() {
        let (_dir, store) = fixture();
        store.upsert(&record("alice", "Correct-Horse-9")).unwrap();
        assert!(store.get("alice").unwrap().is_some(), "预热缓存");

        std::fs::remove_file(store.path()).unwrap();
        assert!(store.get("alice").unwrap().is_none());
    }
}

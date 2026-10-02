//! 磁盘队列（规格书 §5.8「队列落盘用 fsync + 原子重命名」；风险表「队列原子性」）。
//!
//! 布局（`root` = `Paths::var_lib/queue`）：
//!
//! ```text
//! queue/entries/<id>.json   —— 每条消息一个文件
//! queue/corrupt/            —— 解析失败的条目（隔离，绝不静默丢弃）
//! queue/outbound-health.json —— 出站健康状态（重试风暴的结论要跨重启保留）
//! ```
//!
//! 为什么一文件一条消息：写入就是「同目录 rename」，**天然原子**；不需要维护
//! 一个可能半写坏的索引文件。代价是目录项多，但队列规模（数千级）远未到
//! 需要分桶的程度。
//!
//! 所有写入都经 [`mailstack_core::atomic::atomic_as`]：写临时文件 → `fsync` →
//! `chmod 0600` → `rename`。**任何一步都不会让半成品文件出现在 entries/ 下**，
//! 因此断电重启后读到的每个条目要么是完整的旧版本、要么是完整的新版本。

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use mailstack_core::atomic::atomic_as;
use mailstack_core::Paths;

use crate::entry::QueueEntry;
use crate::error::{QueueError, QueueResult};

/// 队列文件权限：报文含用户邮件正文，仅属主可读。
const QUEUE_FILE_MODE: u32 = 0o600;

/// 出站健康状态（持久化）。
///
/// 存在的理由：§5.10.3 R-25-3 要求「出站 25 被封」这类结论必须在管理台给出**明确
/// 结论**。若只放在内存里，进程一重启结论就丢了，运维看到的是「队列莫名其妙在涨」。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundHealthState {
    /// 连续失败次数；任何一次成功投递都清零。
    #[serde(rename = "consecutiveFailures", default)]
    pub consecutive_failures: u32,
    /// 最近一次成功投递时间（ISO 8601 UTC）。
    #[serde(
        rename = "lastSuccessAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_success_at: Option<String>,
    /// 最近一次失败描述。
    #[serde(
        rename = "lastFailure",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_failure: Option<String>,
}

/// 磁盘队列。
#[derive(Debug, Clone)]
pub struct QueueStore {
    root: PathBuf,
}

impl QueueStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// 生产布局：`/var/lib/mailstack/queue`。
    pub fn from_paths(paths: &Paths) -> Self {
        Self::new(paths.var_lib.join("queue"))
    }

    /// 队列根目录。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 条目目录。
    pub fn entries_dir(&self) -> PathBuf {
        self.root.join("entries")
    }

    /// 损坏条目隔离目录。
    pub fn corrupt_dir(&self) -> PathBuf {
        self.root.join("corrupt")
    }

    fn health_path(&self) -> PathBuf {
        self.root.join("outbound-health.json")
    }

    fn entry_path(&self, id: &str) -> QueueResult<PathBuf> {
        if !crate::entry::is_safe_id(id) {
            // 双保险：id 拼进路径前必须复检，否则一个被篡改的 id 就能写到队列目录之外。
            return Err(QueueError::invalid(format!("unsafe queue id: {id:?}")));
        }
        Ok(self.entries_dir().join(format!("{id}.json")))
    }

    /// 写入（或覆盖）一条条目。id 相同即覆盖，因此「更新重试状态」也是本方法。
    pub fn enqueue(&self, entry: &QueueEntry) -> QueueResult<()> {
        entry.validate()?;
        let path = self.entry_path(&entry.id)?;
        let payload = serde_json::to_vec_pretty(entry)?;
        atomic_as(&path, &payload, QUEUE_FILE_MODE, None)?;
        Ok(())
    }

    /// 读取全部条目（按 id 升序 = 入队时间序）。
    ///
    /// 解析失败的条目被**移动到 `corrupt/`** 并 `warn` 一次，而不是丢弃：
    /// 一条读不出来的条目往往正是排查问题的线索，静默删除会让它永久消失。
    pub fn load_all(&self) -> QueueResult<Vec<QueueEntry>> {
        let dir = self.entries_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
        for item in read {
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    mailstack_core::warn::warn_with_detail("queue dir entry", &e.to_string());
                    continue;
                }
            };
            let path = item.path();
            if !is_queue_file(&path) {
                continue;
            }
            match read_entry(&path) {
                Ok(entry) => entries.push(entry),
                Err(reason) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry unreadable",
                        &format!("{}: {reason}", path.display()),
                    );
                    self.quarantine(&path);
                }
            }
        }

        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    }

    /// 删除一条条目（投递完成或已退信后）。返回是否确实删除了文件。
    pub fn remove(&self, id: &str) -> QueueResult<bool> {
        let path = self.entry_path(id)?;
        let existed = match fs::remove_file(&path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(QueueError::io(&path, e)),
        };
        // 顺带清理 `atomic_as` 留下的锁 sidecar（尽力而为）。
        let sidecar = path.with_file_name(format!(
            ".{}.lock",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        let _ = fs::remove_file(sidecar);
        Ok(existed)
    }

    /// 待投递条目数量。
    pub fn len(&self) -> QueueResult<usize> {
        Ok(self.load_all()?.len())
    }

    pub fn is_empty(&self) -> QueueResult<bool> {
        Ok(self.load_all()?.is_empty())
    }

    /// 读出站健康状态。文件缺失或损坏时返回 `None`（并 `warn`），
    /// **不得**因为一个坏掉的状态文件就让整个队列停摆。
    pub fn load_health(&self) -> Option<OutboundHealthState> {
        let path = self.health_path();
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                mailstack_core::warn::warn_with_detail("queue health read", &e.to_string());
                return None;
            }
        };
        match serde_json::from_str(&raw) {
            Ok(state) => Some(state),
            Err(e) => {
                mailstack_core::warn::warn_with_detail(
                    "queue health parse",
                    &format!("{}: {e}", path.display()),
                );
                None
            }
        }
    }

    /// 写出站健康状态。
    pub fn save_health(&self, state: &OutboundHealthState) -> QueueResult<()> {
        let payload = serde_json::to_vec_pretty(state)?;
        atomic_as(&self.health_path(), &payload, QUEUE_FILE_MODE, None)?;
        Ok(())
    }

    /// 把损坏文件移到隔离目录，文件名带上时间戳避免互相覆盖。
    fn quarantine(&self, path: &Path) {
        let dir = self.corrupt_dir();
        if let Err(e) = fs::create_dir_all(&dir) {
            mailstack_core::warn::warn_with_detail("queue corrupt dir", &e.to_string());
            return;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let target = dir.join(format!("{name}.{stamp}.corrupt"));
        if let Err(e) = fs::rename(path, &target) {
            mailstack_core::warn::warn_with_detail("queue quarantine", &e.to_string());
        }
    }
}

/// 该目录项是否是队列条目文件。
///
/// 只认 `<name>.json`：`atomic_as` 的临时文件是 `<name>.json.tmp`、锁 sidecar 是
/// `.<name>.json.lock`，两者都会被这一步过滤掉，因此**不会**把写到一半的文件当成条目。
fn is_queue_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
        return false;
    };
    !name.starts_with('.') && name.ends_with(".json")
}

fn read_entry(path: &Path) -> Result<QueueEntry, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let entry: QueueEntry = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    entry.validate().map_err(|e| e.to_string())?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EntryKind;

    fn temp_store() -> (tempfile::TempDir, QueueStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = QueueStore::new(dir.path().join("queue"));
        (dir, store)
    }

    fn entry(id_suffix: &str) -> QueueEntry {
        let mut e = QueueEntry::new(
            EntryKind::Outbound,
            "s@example.org",
            vec!["r@example.net".to_string()],
            "Subject: t\r\n\r\nbody",
            1_700_000_000,
        )
        .unwrap();
        e.id = format!("00000000001-{id_suffix}");
        e
    }

    #[test]
    fn enqueue_then_load_round_trips() {
        let (_d, store) = temp_store();
        let e = entry("AAAA");
        store.enqueue(&e).unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], e);
    }

    #[test]
    fn queue_survives_restart_without_losing_entries() {
        // 规格书 §5.8 第一条：持久化到磁盘，重启不丢。
        // 「重启」用一个全新的 store 实例指向同一目录来模拟。
        let (dir, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.enqueue(&entry("0002")).unwrap();
        store.enqueue(&entry("0003")).unwrap();
        drop(store);

        let reopened = QueueStore::new(dir.path().join("queue"));
        let loaded = reopened.load_all().unwrap();
        assert_eq!(loaded.len(), 3, "重启后条目不得丢失");
        assert_eq!(loaded[0].id, "00000000001-0001");
        assert_eq!(loaded[2].id, "00000000001-0003");
    }

    #[test]
    fn queue_writes_are_atomic_and_leave_no_partial_files() {
        // 原子性：落盘后不得留下临时文件或半成品；锁 sidecar 必须被读路径忽略。
        let (_d, store) = temp_store();
        store.enqueue(&entry("BEEF")).unwrap();

        let dir = store.entries_dir();
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|i| i.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            names.contains(&"00000000001-BEEF.json".to_string()),
            "条目文件缺失：{names:?}"
        );
        assert!(
            !names.iter().any(|n| n.ends_with(".tmp")),
            "不得留下临时文件：{names:?}"
        );

        // 锁 sidecar 与临时文件都不得被当作队列条目 —— 否则一次「写到一半」会被读成半条消息。
        assert_eq!(store.load_all().unwrap().len(), 1);
        assert!(!is_queue_file(&dir.join("00000000001-BEEF.json.tmp")));
        assert!(!is_queue_file(&dir.join(".00000000001-BEEF.json.lock")));
    }

    #[test]
    fn queue_files_are_owner_only() {
        // 条目含用户邮件正文，必须是 0600。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (_d, store) = temp_store();
            store.enqueue(&entry("CAFE")).unwrap();
            let path = store.entries_dir().join("00000000001-CAFE.json");
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "队列文件实际权限：{mode:o}");
        }
    }

    #[test]
    fn corrupt_queue_files_are_quarantined_not_dropped() {
        // 一条读不出来的条目必须被隔离，而不是被静默删除 —— 它往往是排查线索。
        let (_d, store) = temp_store();
        store.enqueue(&entry("GOOD")).unwrap();

        let dir = store.entries_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("00000000001-BAD0.json"), b"{ not valid json").unwrap();
        // 结构合法但语义非法的条目（空收件人）同样要被隔离。
        fs::write(
            dir.join("00000000001-BAD1.json"),
            br#"{"id":"00000000001-BAD1","kind":"outbound","mailFrom":"s@x","recipients":[],"data":"x","createdAt":"2026-01-01T00:00:00+00:00","attempts":0,"nextAttemptUnix":0}"#,
        )
        .unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1, "只有合法条目应当被读出");
        assert_eq!(loaded[0].id, "00000000001-GOOD");

        let quarantined: Vec<String> = fs::read_dir(store.corrupt_dir())
            .unwrap()
            .map(|i| i.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            quarantined.len(),
            2,
            "两个坏条目都应被隔离：{quarantined:?}"
        );
        assert!(quarantined
            .iter()
            .any(|n| n.starts_with("00000000001-BAD0.json")));
        // 原始文件不应再留在 entries/ 下。
        assert!(!dir.join("00000000001-BAD0.json").exists());
    }

    #[test]
    fn remove_deletes_only_the_targeted_entry() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.enqueue(&entry("0002")).unwrap();

        assert!(store.remove("00000000001-0001").unwrap());
        assert!(
            !store.remove("00000000001-0001").unwrap(),
            "重复删除应返回 false"
        );

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "00000000001-0002");
    }

    #[test]
    fn remove_and_enqueue_reject_unsafe_ids() {
        // 一个被篡改的 id 不得让文件写到队列目录之外。
        let (_d, store) = temp_store();
        assert!(store.remove("../escape").is_err());
        assert!(store
            .enqueue(&{
                let mut e = entry("0001");
                e.id = "../escape".to_string();
                e
            })
            .is_err());
    }

    #[test]
    fn missing_queue_directory_is_an_empty_queue_not_an_error() {
        let (_d, store) = temp_store();
        assert!(store.load_all().unwrap().is_empty());
        assert!(store.is_empty().unwrap());
        assert_eq!(store.len().unwrap(), 0);
    }

    #[test]
    fn health_state_round_trips_and_survives_restart() {
        let (dir, store) = temp_store();
        let state = OutboundHealthState {
            consecutive_failures: 7,
            last_success_at: Some("2026-09-30T00:00:00+00:00".to_string()),
            last_failure: Some("ConnectionError".to_string()),
        };
        store.save_health(&state).unwrap();

        let reopened = QueueStore::new(dir.path().join("queue"));
        assert_eq!(reopened.load_health(), Some(state));
    }

    #[test]
    fn corrupt_health_state_is_tolerated() {
        // 一个坏掉的状态文件不得让队列停摆。
        let (_d, store) = temp_store();
        fs::create_dir_all(store.root()).unwrap();
        fs::write(store.root().join("outbound-health.json"), b"not json").unwrap();
        assert_eq!(store.load_health(), None);
    }

    #[test]
    fn health_file_is_not_mistaken_for_a_queue_entry() {
        // 状态文件与条目同目录，必须靠子目录隔离而不是靠文件名侥幸。
        let (_d, store) = temp_store();
        store
            .save_health(&OutboundHealthState {
                consecutive_failures: 3,
                ..Default::default()
            })
            .unwrap();
        store.enqueue(&entry("0001")).unwrap();
        assert_eq!(store.load_all().unwrap().len(), 1);
    }

    #[test]
    fn load_all_is_sorted_by_id_so_it_is_sorted_by_time() {
        let (_d, store) = temp_store();
        for suffix in ["000C", "000A", "000B"] {
            store.enqueue(&entry(suffix)).unwrap();
        }
        let ids: Vec<String> = store
            .load_all()
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(
            ids,
            vec!["00000000001-000A", "00000000001-000B", "00000000001-000C"]
        );
    }
}

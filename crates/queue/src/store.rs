//! 磁盘队列（规格书 §5.8「队列落盘用 fsync + 原子重命名」；风险表「队列原子性」）。
//!
//! 布局（`root` = `Paths::var_lib/queue`）：
//!
//! ```text
//! queue/entries/<id>.json   —— 每条消息一个文件
//! queue/claims/<id>.claim   —— 投递租约（5.10：标记「这条正在被投递」）
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

/// 投递租约时长（5.10）。
///
/// 一条条目从「开始投递」到「把结果写回磁盘」之间，磁盘上没有它的任何状态变化。
/// 这段窗口里崩溃 / 掉电 / 停机取消，重启后条目仍带全部收件人 —— 下一轮会**整批
/// 重投**，收件人收到重复邮件。
///
/// 租约把这段窗口显式化：开始投递前写一个 claim 文件，结束后删除。重启后
/// 仍在租约内的条目**先跳过**，等租约过期再重试 —— 于是「重启即重投」变成
/// 「只有确实超过了投递时长的条目才会被重试」。
///
/// 取值必须 **大于** 单轮调度的上限（`mailstackd` 的 `ROUND_TIMEOUT = 600s`），
/// 否则还在正常投递的条目会被自己人抢走。这里取 900s（15 分钟）。
pub const CLAIM_TTL_SECONDS: i64 = 900;

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

    /// 投递租约目录（5.10）。
    pub fn claims_dir(&self) -> PathBuf {
        self.root.join("claims")
    }

    fn claim_path(&self, id: &str) -> QueueResult<PathBuf> {
        if !crate::entry::is_safe_id(id) {
            return Err(QueueError::invalid(format!("unsafe queue id: {id:?}")));
        }
        Ok(self.claims_dir().join(format!("{id}.claim")))
    }

    /// 尝试为某条目取得投递租约（5.10）。
    ///
    /// 返回 `true` 表示拿到（可以投递）；`false` 表示已有**未过期**的租约
    /// （别的轮次/进程正在投它以跳过）。
    ///
    /// 用 `create_new`（`O_EXCL`）而不是 `exists()` + 写：判存在与建文件之间
    /// 若有空隙，两个执行者会同时拿到租约 —— 那正是本项要消除的竞态。
    pub fn try_claim(&self, id: &str, now_unix: i64) -> QueueResult<bool> {
        let dir = self.claims_dir();
        fs::create_dir_all(&dir).map_err(|e| QueueError::io(&dir, e))?;
        let path = self.claim_path(id)?;

        // 先清理过期租约：过期即视为「上一个持有者已经没了」。
        if !self.claim_is_fresh(&path, now_unix) {
            let _ = fs::remove_file(&path);
        }

        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                // 内容 = 取得时刻（unix 秒）。写失败也不影响正确性：文件存在本身
                // 就是「已认领」；时间戳只是为了让过期判定不依赖 mtime。
                let _ = writeln!(file, "{now_unix}");
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(QueueError::io(&path, error)),
        }
    }

    /// 释放租约（投递结束，无论成功失败）。
    pub fn release_claim(&self, id: &str) -> QueueResult<()> {
        let path = self.claim_path(id)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(QueueError::io(&path, error)),
        }
    }

    /// 当前仍有效的租约对应的条目 id 集合。
    pub fn claimed_ids(&self, now_unix: i64) -> QueueResult<std::collections::HashSet<String>> {
        let dir = self.claims_dir();
        let mut claimed = std::collections::HashSet::new();
        if !dir.exists() {
            return Ok(claimed);
        }
        let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
        for item in read {
            let Ok(item) = item else { continue };
            let path = item.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(id) = name.strip_suffix(".claim") else {
                continue;
            };
            if self.claim_is_fresh(&path, now_unix) {
                claimed.insert(id.to_string());
            }
        }
        Ok(claimed)
    }

    /// 清理所有过期租约，返回清理数量。
    pub fn prune_claims(&self, now_unix: i64) -> QueueResult<usize> {
        let dir = self.claims_dir();
        if !dir.exists() {
            return Ok(0);
        }
        let mut removed = 0usize;
        let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
        for item in read {
            let Ok(item) = item else { continue };
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("claim") {
                continue;
            }
            if !self.claim_is_fresh(&path, now_unix) && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// 租约是否仍在有效期内。
    ///
    /// 以**文件内容**的时间戳为准（而不是 mtime）：mtime 会被 touch、备份还原、
    /// 文件系统复制改变，而内容是我们自己写的。内容读不出来时退化为 mtime，
    /// 再不行就当作**过期** —— 宁可多投一次，也不要让一条条目被永久卡住。
    fn claim_is_fresh(&self, path: &Path, now_unix: i64) -> bool {
        let claimed_at = match fs::read_to_string(path) {
            Ok(text) => text.trim().parse::<i64>().ok(),
            Err(_) => None,
        };
        let claimed_at = match claimed_at {
            Some(ts) => ts,
            None => match fs::metadata(path).and_then(|m| m.modified()) {
                Ok(modified) => modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                Err(_) => return false,
            },
        };
        // 时间戳来自未来（时钟回拨过）也按「刚取得」处理：宁可多等一个 TTL，
        // 也不要因为时钟问题把正在投递的条目抢过来重投。
        now_unix.saturating_sub(claimed_at) < CLAIM_TTL_SECONDS
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
        // 5.10：条目消失时必须把租约一起清掉，否则 claim 目录会永久留下孤儿文件
        // （它的 id 已经不在了，只会让 `claimed_ids` 越来越大）。
        let _ = self.release_claim(id);
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
    ///
    /// 5.16：原实现是 `load_all()?.len()` —— `backlog` / `len()` 每 2 秒被遥测采样
    /// 调用一次，于是**每 2 秒把全部邮件正文解析一遍**。千条积压时那是每 2 秒
    /// 数百 MB 的解析开销，而且它跑在 tokio worker 上，会直接饿死收信与投递。
    ///
    /// 计数只需要知道「有几个条目文件」，不需要解析内容：这里只 stat 目录项，
    /// 跳过非条目文件（锁 sidecar、健康状态文件等）。坏条目的隔离行为仍由
    /// `load_all` 负责 —— 计数不值得为它做一次全量解析。
    pub fn len(&self) -> QueueResult<usize> {
        let dir = self.entries_dir();
        if !dir.exists() {
            return Ok(0);
        }
        let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
        let mut count = 0usize;
        for item in read {
            let Ok(item) = item else { continue };
            if is_queue_file(&item.path()) {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn is_empty(&self) -> QueueResult<bool> {
        Ok(self.len()? == 0)
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

    /// 5.16：`len()` 只数条目文件，**不解析邮件正文**。
    ///
    /// 原实现是 `load_all()?.len()`。而 `backlog` / `len()` 每 2 秒被遥测采样
    /// 调用一次 —— 千条积压时就是每 2 秒数百 MB 的解析，还跑在 tokio worker 上。
    ///
    /// 判据：一条**内容已损坏**的条目文件仍然被计入数量。`load_all()` 会把它
    /// 移进 `corrupt/`（因此数不到它），而只 stat 目录项的 `len()` 必须数得到 ——
    /// 这正是「不解析」的可观测证据。
    #[test]
    fn len_counts_entry_files_without_parsing_them() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.enqueue(&entry("0002")).unwrap();
        assert_eq!(store.len().unwrap(), 2);

        // 塞一个坏条目进目录。
        let broken = store.entries_dir().join("00000000001-0003.json");
        fs::write(&broken, b"not a queue entry at all").unwrap();

        assert_eq!(store.len().unwrap(), 3, "len() 必须只数文件，不解析内容");

        // 对照：load_all 会隔离坏条目，因此只返回 2 条。
        let parsed = store.load_all().unwrap();
        assert_eq!(parsed.len(), 2, "load_all 应隔离坏条目");
        assert!(!broken.exists(), "坏条目应已移入 corrupt/");
    }

    /// 健康状态文件与锁 sidecar 不得被算进条目数量。
    #[test]
    fn len_ignores_non_entry_files() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.save_health(&OutboundHealthState::default()).unwrap();
        fs::write(store.entries_dir().join(".hidden.lock"), b"").unwrap();
        assert_eq!(store.len().unwrap(), 1);
    }

    // ── 5.10：投递租约 ──

    /// 同一时刻只有一方能拿到租约（`O_EXCL`，不是 `exists()` + 写）。
    #[test]
    fn a_claim_is_exclusive_until_released() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let id = "00000000001-0001";
        let now = 1_700_000_100;

        assert!(store.try_claim(id, now).unwrap(), "首次认领必须成功");
        assert!(
            !store.try_claim(id, now + 1).unwrap(),
            "未释放前第二次认领必须失败 —— 否则两个执行者会同时投递"
        );

        store.release_claim(id).unwrap();
        assert!(store.try_claim(id, now + 2).unwrap(), "释放后应可再次认领");
    }

    /// 过期租约必须能被接管：否则一次崩溃就让条目卡死到 TTL 之后（且无人清理）。
    #[test]
    fn an_expired_claim_can_be_taken_over() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let id = "00000000001-0001";
        let now = 1_700_000_000;

        assert!(store.try_claim(id, now).unwrap());
        // TTL 之内：仍然是别人的。
        assert!(!store.try_claim(id, now + CLAIM_TTL_SECONDS - 1).unwrap());
        // 恰好过期：可接管。
        assert!(
            store.try_claim(id, now + CLAIM_TTL_SECONDS).unwrap(),
            "超过 TTL 的租约必须可被接管"
        );
    }

    /// `claimed_ids` 只返回仍有效的租约；`prune_claims` 清掉过期的。
    #[test]
    fn claimed_ids_reflects_only_live_leases() {
        let (_d, store) = temp_store();
        for suffix in ["0001", "0002"] {
            store.enqueue(&entry(suffix)).unwrap();
        }
        let fresh = "00000000001-0001";
        let stale = "00000000001-0002";
        let now = 1_700_000_000;
        assert!(store.try_claim(fresh, now).unwrap());
        assert!(store
            .try_claim(stale, now - CLAIM_TTL_SECONDS - 10)
            .unwrap());

        let claimed = store.claimed_ids(now).unwrap();
        assert!(claimed.contains(fresh), "未过期的租约必须可见");
        assert!(!claimed.contains(stale), "过期的租约不得把条目挡在队列外");

        let pruned = store.prune_claims(now).unwrap();
        assert_eq!(pruned, 1, "只应清掉那条过期的");
        assert!(
            !store.claim_path(stale).unwrap().exists(),
            "过期租约文件应已被清理"
        );
    }

    /// 条目被删除时租约必须一起消失，否则 claim 目录会留下永久孤儿。
    #[test]
    fn removing_an_entry_releases_its_claim() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let id = "00000000001-0001";
        let now = 1_700_000_000;

        assert!(store.try_claim(id, now).unwrap());
        assert!(store.claim_path(id).unwrap().exists());

        store.remove(id).unwrap();
        assert!(
            !store.claim_path(id).unwrap().exists(),
            "条目已删除，租约必须一并清理"
        );
        assert!(store.claimed_ids(now).unwrap().is_empty());
    }

    /// 租约内容损坏时按 mtime 兜底；mtime 也拿不到则视为过期（宁可多投一次，
    /// 也不要让条目被永久卡住）。
    #[test]
    fn a_corrupt_claim_timestamp_falls_back_to_mtime_not_to_a_deadlock() {
        let (_d, store) = temp_store();
        let id = "00000000001-0001";
        store.enqueue(&entry("0001")).unwrap();
        let now = 1_700_000_000;
        assert!(store.try_claim(id, now).unwrap());

        // 把内容写坏，但文件刚创建 —— mtime 是「现在」，仍应视为有效。
        fs::write(store.claim_path(id).unwrap(), b"garbage").unwrap();
        let fresh = store.claimed_ids(now).unwrap();
        assert!(
            fresh.contains(id),
            "时间戳损坏时应退化为 mtime 判定，而不是立刻放开"
        );
    }
}

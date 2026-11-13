use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use mailstack_core::atomic::atomic_as;
use mailstack_core::Paths;

use crate::entry::QueueEntry;
use crate::error::{QueueError, QueueResult};

const QUEUE_FILE_MODE: u32 = 0o600;

const ENQUEUE_NEW_ATTEMPTS: u32 = 5;

pub const MAX_CORRUPT_FILES: usize = 200;

pub const CLAIM_TTL_SECONDS: i64 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencySample {
    pub at: i64,
    pub ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficMetrics {
    #[serde(rename = "deliveredTotal", default)]
    pub delivered_total: u64,
    #[serde(rename = "bouncedTotal", default)]
    pub bounced_total: u64,
    #[serde(default)]
    pub latency: Vec<LatencySample>,
}

pub const MAX_LATENCY_SAMPLES: usize = 500;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundHealthState {
    #[serde(rename = "consecutiveFailures", default)]
    pub consecutive_failures: u32,

    #[serde(
        rename = "lastSuccessAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_success_at: Option<String>,

    #[serde(
        rename = "lastFailure",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_failure: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QueueStore {
    root: PathBuf,

    #[cfg(test)]
    claim_faults: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}

impl QueueStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            #[cfg(test)]
            claim_faults: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::VecDeque::new(),
            )),
        }
    }

    pub fn from_paths(paths: &Paths) -> Self {
        Self::new(paths.var_lib.join("queue"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn entries_dir(&self) -> PathBuf {
        self.root.join("entries")
    }

    pub fn corrupt_dir(&self) -> PathBuf {
        self.root.join("corrupt")
    }

    pub fn claims_dir(&self) -> PathBuf {
        self.root.join("claims")
    }

    fn claim_path(&self, id: &str) -> QueueResult<PathBuf> {
        if !crate::entry::is_safe_id(id) {
            return Err(QueueError::invalid(format!("unsafe queue id: {id:?}")));
        }
        Ok(self.claims_dir().join(format!("{id}.claim")))
    }

    pub fn try_claim(&self, id: &str, now_unix: i64) -> QueueResult<bool> {
        let path = self.claim_path(id)?;
        #[cfg(test)]
        if self.take_claim_fault(id) {
            return Err(QueueError::io(
                &path,
                std::io::Error::other("injected claim failure"),
            ));
        }
        self.with_claims_lock(|| {
            if !self.claim_is_fresh(&path, now_unix) {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(QueueError::io(&path, error)),
                }
            }

            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write;

                    let _ = writeln!(file, "{now_unix}");
                    Ok(true)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(error) => Err(QueueError::io(&path, error)),
            }
        })
    }

    pub fn release_claim(&self, id: &str) -> QueueResult<()> {
        let path = self.claim_path(id)?;
        self.with_claims_lock(|| match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(QueueError::io(&path, error)),
        })
    }

    fn with_claims_lock<T>(&self, f: impl FnOnce() -> QueueResult<T>) -> QueueResult<T> {
        let dir = self.claims_dir();
        fs::create_dir_all(&dir).map_err(|e| QueueError::io(&dir, e))?;
        mailstack_core::atomic::locked_with(&dir.join(".claims"), f)
    }

    #[cfg(test)]
    fn take_claim_fault(&self, id: &str) -> bool {
        let mut faults = self.claim_faults.lock().unwrap_or_else(|p| p.into_inner());
        match faults.iter().position(|fault| fault == id) {
            Some(index) => {
                faults.remove(index);
                true
            }
            None => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_claim(&self, id: &str) {
        self.claim_faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(id.to_string());
    }

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

    pub fn prune_claims(&self, now_unix: i64) -> QueueResult<usize> {
        let dir = self.claims_dir();
        if !dir.exists() {
            return Ok(0);
        }
        self.with_claims_lock(|| {
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
        })
    }

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

        now_unix.saturating_sub(claimed_at) < CLAIM_TTL_SECONDS
    }

    fn health_path(&self) -> PathBuf {
        self.root.join("outbound-health.json")
    }

    fn entry_path(&self, id: &str) -> QueueResult<PathBuf> {
        if !crate::entry::is_safe_id(id) {
            return Err(QueueError::invalid(format!("unsafe queue id: {id:?}")));
        }
        Ok(self.entries_dir().join(format!("{id}.json")))
    }

    pub fn enqueue(&self, entry: &QueueEntry) -> QueueResult<()> {
        entry.validate()?;
        let path = self.entry_path(&entry.id)?;
        let payload = serde_json::to_vec_pretty(entry)?;
        atomic_as(&path, &payload, QUEUE_FILE_MODE, None)?;
        Ok(())
    }

    pub fn enqueue_new(&self, entry: &mut QueueEntry) -> QueueResult<()> {
        entry.validate()?;
        let dir = self.entries_dir();

        fs::create_dir_all(&dir).map_err(|e| QueueError::io(&dir, e))?;
        for _ in 0..ENQUEUE_NEW_ATTEMPTS {
            let path = self.entry_path(&entry.id)?;
            let reserved_path = self.reservation_path(&entry.id);
            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&reserved_path)
            {
                Ok(file) => drop(file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    entry.id = crate::entry::new_id();
                    continue;
                }
                Err(error) => return Err(QueueError::io(&reserved_path, error)),
            }

            if path.exists() {
                let _ = fs::remove_file(&reserved_path);
                entry.id = crate::entry::new_id();
                continue;
            }
            let payload = serde_json::to_vec_pretty(entry)?;
            let result = atomic_as(&path, &payload, QUEUE_FILE_MODE, None);
            let _ = fs::remove_file(&reserved_path);
            return match result {
                Ok(()) => Ok(()),
                Err(error) => {
                    let _ = fs::remove_file(&path);
                    Err(error.into())
                }
            };
        }
        Err(QueueError::invalid(format!(
            "queue id collision persisted after {ENQUEUE_NEW_ATTEMPTS} attempts (entry {})",
            entry.id
        )))
    }

    fn reservation_path(&self, id: &str) -> PathBuf {
        self.entries_dir().join(format!(".{id}.json.reserve"))
    }

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
            let raw = match fs::read(&path) {
                Ok(raw) => raw,
                Err(error) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry read",
                        &format!("{}: {error}", path.display()),
                    );
                    continue;
                }
            };
            match parse_entry(&raw) {
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

    pub fn load_due(&self, now_unix: i64) -> QueueResult<Vec<QueueEntry>> {
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
            let raw = match fs::read(&path) {
                Ok(raw) => raw,
                Err(error) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry read",
                        &format!("{}: {error}", path.display()),
                    );
                    continue;
                }
            };
            let header: EntryHeader = match serde_json::from_slice(&raw) {
                Ok(header) => header,
                Err(reason) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry unreadable",
                        &format!("{}: {reason}", path.display()),
                    );
                    self.quarantine(&path);
                    continue;
                }
            };

            if header.next_attempt_unix > now_unix {
                continue;
            }
            match parse_entry(&raw) {
                Ok(entry) if entry.is_due(now_unix) => entries.push(entry),
                Ok(_) => {}
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

    pub fn remove(&self, id: &str) -> QueueResult<bool> {
        let path = self.entry_path(id)?;

        let _ = self.release_claim(id);
        let existed = match fs::remove_file(&path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(QueueError::io(&path, e)),
        };

        let sidecar = path.with_file_name(format!(
            ".{}.lock",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        let _ = fs::remove_file(sidecar);
        Ok(existed)
    }

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

    pub fn save_health(&self, state: &OutboundHealthState) -> QueueResult<()> {
        let payload = serde_json::to_vec_pretty(state)?;
        atomic_as(&self.health_path(), &payload, QUEUE_FILE_MODE, None)?;
        Ok(())
    }

    fn traffic_path(&self) -> PathBuf {
        self.root.join("traffic-metrics.json")
    }

    pub fn load_traffic(&self) -> QueueResult<TrafficMetrics> {
        let path = self.traffic_path();
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(TrafficMetrics::default())
            }
            Err(error) => return Err(QueueError::io(&path, error)),
        };
        Ok(serde_json::from_str(&raw).unwrap_or_default())
    }

    pub fn record_delivery(
        &self,
        delivered: usize,
        bounced: usize,
        latency_ms: Option<u64>,
    ) -> QueueResult<()> {
        if delivered == 0 && bounced == 0 {
            return Ok(());
        }
        let mut traffic = self.load_traffic()?;
        traffic.delivered_total = traffic.delivered_total.saturating_add(delivered as u64);
        traffic.bounced_total = traffic.bounced_total.saturating_add(bounced as u64);
        if let Some(ms) = latency_ms {
            traffic.latency.push(LatencySample {
                at: time::OffsetDateTime::now_utc().unix_timestamp(),
                ms,
            });
            if traffic.latency.len() > MAX_LATENCY_SAMPLES {
                let keep_from = traffic.latency.len() - MAX_LATENCY_SAMPLES;
                traffic.latency.drain(..keep_from);
            }
        }
        let payload = serde_json::to_vec_pretty(&traffic)?;
        atomic_as(&self.traffic_path(), &payload, QUEUE_FILE_MODE, None)?;
        Ok(())
    }

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
        self.prune_corrupt_dir();
    }

    fn prune_corrupt_dir(&self) {
        let dir = self.corrupt_dir();
        let Ok(read) = fs::read_dir(&dir) else { return };
        let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        for item in read.flatten() {
            let path = item.path();
            if !path.is_file() {
                continue;
            }
            let modified = item
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            files.push((modified, path));
        }
        if files.len() <= MAX_CORRUPT_FILES {
            return;
        }
        files.sort_by_key(|(modified, _)| *modified);
        let excess = files.len() - MAX_CORRUPT_FILES;
        let mut removed = 0usize;
        for (_, path) in files.into_iter().take(excess) {
            if fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            mailstack_core::warn::warn_with_detail(
                "queue corrupt dir pruned",
                &format!("removed {removed} oldest quarantined entries"),
            );
        }
    }
}

fn is_queue_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
        return false;
    };
    !name.starts_with('.') && name.ends_with(".json")
}

#[derive(Deserialize)]
struct EntryHeader {
    #[serde(rename = "nextAttemptUnix", default)]
    next_attempt_unix: i64,
}

fn parse_entry(raw: &[u8]) -> Result<QueueEntry, String> {
    #[cfg(test)]
    FULL_ENTRY_PARSES.with(|count| count.set(count.get() + 1));
    let entry: QueueEntry = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    entry.validate().map_err(|e| e.to_string())?;
    Ok(entry)
}

#[cfg(test)]
thread_local! {
    static FULL_ENTRY_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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

        assert_eq!(store.load_all().unwrap().len(), 1);
        assert!(!is_queue_file(&dir.join("00000000001-BEEF.json.tmp")));
        assert!(!is_queue_file(&dir.join(".00000000001-BEEF.json.lock")));
    }

    #[test]
    fn queue_files_are_owner_only() {
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
        let (_d, store) = temp_store();
        store.enqueue(&entry("GOOD")).unwrap();

        let dir = store.entries_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("00000000001-BAD0.json"), b"{ not valid json").unwrap();

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

        assert!(!dir.join("00000000001-BAD0.json").exists());
    }

    #[test]
    fn enqueue_new_never_overwrites_an_existing_entry() {
        let (_d, store) = temp_store();
        let first = entry("AAAA");
        store.enqueue(&first).unwrap();

        let mut collided = entry("BBBB");
        collided.id = first.id.clone();

        store.enqueue_new(&mut collided).unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 2, "撞车不得覆盖任何一封邮件");
        let original = loaded
            .iter()
            .find(|e| e.id == first.id)
            .expect("先写的邮件必须原样保留");
        assert_eq!(original.data, first.data);
        assert_ne!(collided.id, first.id, "撞车的一方必须换到新 id");
        assert!(loaded.iter().any(|e| e.id == collided.id));

        let mut fresh = entry("CCCC");
        let before = fresh.id.clone();
        store.enqueue_new(&mut fresh).unwrap();
        assert_eq!(fresh.id, before);
    }

    #[test]
    fn enqueue_new_validates_before_the_collision_loop() {
        let (_d, store) = temp_store();
        let mut invalid = entry("BBBB");
        invalid.id = "../escape".to_string();
        assert!(store.enqueue_new(&mut invalid).is_err());
        assert!(store.load_all().unwrap().is_empty(), "非法条目不得落盘");

        fs::create_dir_all(store.entries_dir()).unwrap();
        let occupied = store.entries_dir().join("00000000001-CCCC.json");
        fs::write(&occupied, b"placeholder").unwrap();
        let mut collided = entry("CCCC");
        collided.id = "00000000001-CCCC".to_string();
        store.enqueue_new(&mut collided).unwrap();

        assert_ne!(collided.id, "00000000001-CCCC", "撞车必须换 id");
        assert_eq!(
            fs::read(&occupied).unwrap(),
            b"placeholder",
            "已占位的名字不得被覆盖"
        );
        assert!(store
            .load_all()
            .unwrap()
            .iter()
            .any(|e| e.id == collided.id));
    }

    #[test]
    fn enqueue_new_creates_the_entries_directory_itself() {
        let (_d, store) = temp_store();
        assert!(!store.entries_dir().exists());
        let mut fresh = entry("AAAA");
        store.enqueue_new(&mut fresh).unwrap();
        assert_eq!(store.load_all().unwrap().len(), 1);
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
        let (_d, store) = temp_store();
        fs::create_dir_all(store.root()).unwrap();
        fs::write(store.root().join("outbound-health.json"), b"not json").unwrap();
        assert_eq!(store.load_health(), None);
    }

    #[test]
    fn health_file_is_not_mistaken_for_a_queue_entry() {
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

    #[test]
    fn len_counts_entry_files_without_parsing_them() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.enqueue(&entry("0002")).unwrap();
        assert_eq!(store.len().unwrap(), 2);

        let broken = store.entries_dir().join("00000000001-0003.json");
        fs::write(&broken, b"not a queue entry at all").unwrap();

        assert_eq!(store.len().unwrap(), 3, "len() 必须只数文件，不解析内容");

        let parsed = store.load_all().unwrap();
        assert_eq!(parsed.len(), 2, "load_all 应隔离坏条目");
        assert!(!broken.exists(), "坏条目应已移入 corrupt/");
    }

    #[test]
    fn len_ignores_non_entry_files() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.save_health(&OutboundHealthState::default()).unwrap();
        fs::write(store.entries_dir().join(".hidden.lock"), b"").unwrap();
        assert_eq!(store.len().unwrap(), 1);
    }

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

    #[test]
    fn an_expired_claim_can_be_taken_over() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let id = "00000000001-0001";
        let now = 1_700_000_000;

        assert!(store.try_claim(id, now).unwrap());

        assert!(!store.try_claim(id, now + CLAIM_TTL_SECONDS - 1).unwrap());

        assert!(
            store.try_claim(id, now + CLAIM_TTL_SECONDS).unwrap(),
            "超过 TTL 的租约必须可被接管"
        );
    }

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

    #[test]
    fn a_corrupt_claim_timestamp_falls_back_to_mtime_not_to_a_deadlock() {
        let (_d, store) = temp_store();
        let id = "00000000001-0001";
        store.enqueue(&entry("0001")).unwrap();
        let now = 1_700_000_000;
        assert!(store.try_claim(id, now).unwrap());

        fs::write(store.claim_path(id).unwrap(), b"garbage").unwrap();
        let fresh = store.claimed_ids(now).unwrap();
        assert!(
            fresh.contains(id),
            "时间戳损坏时应退化为 mtime 判定，而不是立刻放开"
        );
    }

    #[test]
    fn only_one_of_two_concurrent_claimers_wins_the_same_stale_lease() {
        let (_d, store) = temp_store();
        let id = "00000000001-0001";
        let now = 1_700_000_000;
        let claim_path = store.claim_path(id).unwrap();
        fs::create_dir_all(store.claims_dir()).unwrap();

        for round in 0..200 {
            fs::write(&claim_path, format!("{}", now - CLAIM_TTL_SECONDS - 10)).unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let mut handles = Vec::new();
            for _ in 0..2 {
                let store = store.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    store.try_claim(id, now).unwrap()
                }));
            }
            let winners: usize = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|won| *won)
                .count();
            assert_eq!(
                winners, 1,
                "第 {round} 轮：{winners} 个执行者同时拿到同一条条约租约"
            );
        }
    }

    #[test]
    fn claim_mutations_are_serialised_by_a_shared_lock() {
        let (_d, store) = temp_store();
        let id = "00000000001-0001";
        let now = 1_700_000_000;
        fs::create_dir_all(store.claims_dir()).unwrap();

        let holder = store.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            holder
                .with_claims_lock(|| {
                    started_tx.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    Ok(())
                })
                .unwrap();
        });
        started_rx.recv().unwrap();

        let began = std::time::Instant::now();
        assert!(store.try_claim(id, now).unwrap());
        let waited = began.elapsed();
        worker.join().unwrap();

        assert!(
            waited >= std::time::Duration::from_millis(200),
            "try_claim 没有等待 claims 锁（只用了 {waited:?}）—— 判过期与占名又可被插队"
        );
    }

    #[test]
    fn load_due_skips_the_body_of_entries_that_are_not_due() {
        let (_d, store) = temp_store();

        for index in 0..8 {
            let mut e = entry(&format!("FUT{index:01}"));
            e.data = format!("Subject: t\r\n\r\n{}", "x".repeat(256 * 1024));
            e.next_attempt_unix = 9_999_999_999;
            store.enqueue(&e).unwrap();
        }

        for index in 0..2 {
            let mut e = entry(&format!("DUE{index:01}"));
            e.next_attempt_unix = 1_000;
            store.enqueue(&e).unwrap();
        }

        FULL_ENTRY_PARSES.with(|count| count.set(0));
        let due = store.load_due(2_000).unwrap();
        let parsed = FULL_ENTRY_PARSES.with(|count| count.get());

        assert_eq!(due.len(), 2, "只应返回到期条目：{due:?}");
        assert_eq!(
            parsed, 2,
            "完整解析了 {parsed} 条条目（应为 2）—— 未到期条目的正文也被读进了内存"
        );

        FULL_ENTRY_PARSES.with(|count| count.set(0));
        assert_eq!(store.load_all().unwrap().len(), 10);
        assert_eq!(FULL_ENTRY_PARSES.with(|count| count.get()), 10);
    }

    #[test]
    fn load_due_still_rechecks_the_full_entry_before_scheduling_it() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let path = store.entries_dir().join("00000000001-0001.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["nextAttemptUnix"] = serde_json::json!(0);

        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(store.load_due(10).unwrap().len(), 1);
    }

    #[test]
    fn load_due_quarantines_corrupt_entries_instead_of_dropping_them() {
        let (_d, store) = temp_store();
        fs::create_dir_all(store.entries_dir()).unwrap();
        fs::write(
            store.entries_dir().join("00000000001-BAD0.json"),
            b"{ not valid json",
        )
        .unwrap();
        assert!(store.load_due(1_700_000_000).unwrap().is_empty());
        assert_eq!(fs::read_dir(store.corrupt_dir()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_enqueue_and_load_never_quarantine_a_live_entry() {
        let (_d, store) = temp_store();
        let writer = {
            let store = store.clone();
            std::thread::spawn(move || {
                for index in 0..64 {
                    let mut e = entry(&format!("ENQ{index:02}"));
                    e.data = format!("Subject: t\r\n\r\n{}", "y".repeat(256 * 1024));
                    store.enqueue_new(&mut e).unwrap();
                }
            })
        };
        let reader = {
            let store = store.clone();
            std::thread::spawn(move || {
                for _ in 0..400 {
                    let _ = store.load_all().unwrap();
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();

        let corrupt = match fs::read_dir(store.corrupt_dir()) {
            Ok(read) => read.count(),
            Err(_) => 0,
        };
        assert_eq!(
            corrupt, 0,
            "并发读者把 {corrupt} 个正常在途入队当成了损坏条目"
        );
        assert_eq!(store.load_all().unwrap().len(), 64, "64 封邮件都必须在");
    }

    #[test]
    fn the_corrupt_directory_is_bounded() {
        let (_d, store) = temp_store();
        let dir = store.corrupt_dir();
        fs::create_dir_all(&dir).unwrap();
        for index in 0..(MAX_CORRUPT_FILES + 16) {
            fs::write(dir.join(format!("old-{index:04}.corrupt")), b"x").unwrap();
        }
        store.enqueue(&entry("GC00")).unwrap();
        fs::write(store.entries_dir().join("00000000001-GC01.json"), b"bad").unwrap();
        store.load_all().unwrap();

        let count = fs::read_dir(&dir).unwrap().count();
        assert!(
            count <= MAX_CORRUPT_FILES,
            "corrupt/ 长到 {count} 条，超过上限 {MAX_CORRUPT_FILES}"
        );
        let newest_kept = fs::read_dir(&dir).unwrap().flatten().any(|item| {
            item.file_name()
                .to_string_lossy()
                .starts_with("00000000001-GC01")
        });
        assert!(newest_kept, "刚隔离的那一条必须保留（保留最近的）");
    }
}

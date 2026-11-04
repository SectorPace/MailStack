use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::atomic::atomic_as;
use crate::error::{CoreError, CoreResult};
use crate::paths::Paths;

pub const MANUAL_BANS_MODE: u32 = 0o600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualBan {
    pub ip: IpAddr,

    #[serde(rename = "bannedAt")]
    pub banned_at: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum BanStoreError {
    #[error("手工封禁文件无法读写（{}）：{source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("手工封禁文件内容无法解析（{}）：{detail}", .path.display())]
    Corrupt { path: PathBuf, detail: String },
}

#[derive(Debug, Clone)]
pub struct ManualBanStore {
    path: PathBuf,
}

impl ManualBanStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn from_paths(paths: &Paths) -> Self {
        Self::new(paths.manual_bans.clone())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<Vec<ManualBan>>, BanStoreError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(BanStoreError::Io {
                    path: self.path.clone(),
                    source,
                })
            }
        };

        if text.trim().is_empty() {
            return Ok(None);
        }
        let bans: Vec<ManualBan> =
            serde_json::from_str(&text).map_err(|error| BanStoreError::Corrupt {
                path: self.path.clone(),
                detail: error.to_string(),
            })?;
        Ok(Some(bans))
    }

    pub fn add(
        &self,
        ip: IpAddr,
        note: Option<&str>,
        now_iso8601: &str,
    ) -> CoreResult<Vec<ManualBan>> {
        self.update(move |bans| {
            match bans.iter_mut().find(|entry| entry.ip == ip) {
                Some(existing) => {
                    if note.is_some() {
                        existing.note = note.map(str::to_string);
                    }
                }
                None => bans.push(ManualBan {
                    ip,
                    banned_at: now_iso8601.to_string(),
                    note: note.map(str::to_string),
                }),
            }
            bans.sort_by_key(|entry| entry.ip.to_string());
        })
    }

    pub fn remove(&self, ip: IpAddr) -> CoreResult<Vec<ManualBan>> {
        self.update(move |bans| bans.retain(|entry| entry.ip != ip))
    }

    fn update<F>(&self, mutate: F) -> CoreResult<Vec<ManualBan>>
    where
        F: FnOnce(&mut Vec<ManualBan>),
    {
        let lock_path = self.path.clone();
        let write_path = self.path.clone();
        crate::atomic::locked(&lock_path, move || {
            let mut bans = self.load()?.unwrap_or_default();
            mutate(&mut bans);
            let payload = serde_json::to_vec_pretty(&bans)?;
            atomic_as(&write_path, &payload, MANUAL_BANS_MODE, None)?;
            Ok(bans)
        })
    }
}

impl From<BanStoreError> for CoreError {
    fn from(error: BanStoreError) -> Self {
        match error {
            BanStoreError::Io { path, source } => CoreError::io(path, source),

            BanStoreError::Corrupt { path, detail } => CoreError::invalid(format!(
                "手工封禁文件内容无法解析（{}）：{detail}",
                path.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn store(tag: &str) -> ManualBanStore {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "mailstack-bans-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        ManualBanStore::new(dir.join("manual-bans.json"))
    }

    #[test]
    fn a_missing_file_is_not_the_same_as_a_corrupt_one() {
        let store = store("missing");
        assert_eq!(store.load().unwrap(), None, "不存在是初始状态");

        std::fs::write(store.path(), "{ this is not json").unwrap();
        let error = store.load().expect_err("损坏必须报错");
        assert!(
            matches!(error, BanStoreError::Corrupt { .. }),
            "实际: {error:?}"
        );
    }

    #[test]
    fn a_corrupt_file_is_never_treated_as_empty_and_is_never_overwritten() {
        let store = store("corrupt");
        let original = "{ not a ban list";
        std::fs::write(store.path(), original).unwrap();

        assert!(store
            .add(ip("198.51.100.7"), None, "2026-10-02T00:00:00Z")
            .is_err());
        assert!(store.remove(ip("198.51.100.7")).is_err());

        assert_eq!(
            std::fs::read_to_string(store.path()).unwrap(),
            original,
            "拒绝写入时绝不能改动文件内容"
        );
    }

    #[test]
    fn add_and_remove_round_trip_through_the_file() {
        let store = store("roundtrip");
        store
            .add(ip("198.51.100.7"), Some("abuse"), "2026-10-02T00:00:00Z")
            .unwrap();
        store
            .add(ip("2001:db8::1"), None, "2026-10-02T00:00:01Z")
            .unwrap();

        let bans = store.load().unwrap().expect("文件已存在");
        assert_eq!(bans.len(), 2);
        assert_eq!(bans[0].ip, ip("198.51.100.7"));
        assert_eq!(bans[0].note.as_deref(), Some("abuse"));

        store.remove(ip("198.51.100.7")).unwrap();
        let bans = store.load().unwrap().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, ip("2001:db8::1"));

        store.remove(ip("198.51.100.7")).unwrap();
    }

    #[test]
    fn adding_twice_keeps_the_first_timestamp() {
        let store = store("idempotent");
        store
            .add(ip("198.51.100.7"), None, "2026-10-02T00:00:00Z")
            .unwrap();
        let bans = store
            .add(ip("198.51.100.7"), Some("later"), "2026-10-03T12:00:00Z")
            .unwrap();

        assert_eq!(bans.len(), 1, "同一个地址不得变成两条");
        assert_eq!(bans[0].banned_at, "2026-10-02T00:00:00Z");
        assert_eq!(bans[0].note.as_deref(), Some("later"), "备注允许补齐");
    }

    #[test]
    fn equivalent_ipv6_spellings_collapse_to_one_entry() {
        let store = store("ipv6");
        store.add(ip("::1"), None, "2026-10-02T00:00:00Z").unwrap();
        let bans = store
            .add(ip("0:0:0:0:0:0:0:1"), None, "2026-10-02T00:00:00Z")
            .unwrap();
        assert_eq!(bans.len(), 1);

        store.remove(ip("0:0:0:0:0:0:0:1")).unwrap();
        assert_eq!(store.load().unwrap().unwrap().len(), 0);
    }

    #[test]
    fn the_file_is_written_with_the_documented_mode() {
        let store = store("mode");
        store
            .add(ip("198.51.100.7"), None, "2026-10-02T00:00:00Z")
            .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, MANUAL_BANS_MODE, "手工封禁决定谁能连 SMTP，必须 0600");
        }
    }

    #[test]
    fn a_hand_emptied_file_reads_as_no_bans_rather_than_corrupt() {
        let store = store("emptied");
        std::fs::write(store.path(), "\n  \n").unwrap();
        assert_eq!(store.load().unwrap(), None);
    }
}

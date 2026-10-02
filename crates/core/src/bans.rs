//! 管理台手工封禁的持久化（`security.ban` / `security.unban`）。
//!
//! ## 为什么手工封禁必须落盘
//!
//! 自动封禁（失败计数触发的临时 / 永久封禁）活在 `mailstackd` 的内存表里 —— 重启即清空，
//! 这是可以接受的：它们由对端的行为自动重建。
//!
//! **运维手工封禁不是这一类。** 它是人的一次决定。若只存在内存里，一次
//! `systemctl restart` 就会把它悄悄撤掉，而运维看不到任何迹象 —— 那是一种
//! 「看起来还封着、其实已经放行」的状态。因此手工封禁落在本文件里，由守护进程
//! 热重载进内存表（见 `bin/mailstackd/src/bans.rs`），**重启后仍然生效**。
//!
//! ## 单一真相源
//!
//! 本文件是手工封禁的**唯一**真相源：特权助手只改文件，守护进程只读文件，两边都不再
//! 额外维护一份权威的内存副本。代价是生效有一个重载周期的延迟，换来的是「重启不丢」
//! 与「只有一处需要保持一致」。
//!
//! ## 失败关闭：损坏绝不等价于「空」
//!
//! 读取失败**绝不能**当成空列表返回。空列表在守护进程侧的含义是「没有任何手工封禁」，
//! 于是它会去把在册的手工封禁全部解除 —— 一次文件损坏就等于静默放行攻击者。
//! 因此：
//!
//! * 守护进程读到 `Err` 时**保持现状**并告警；
//! * 特权助手读到 `Err` 时**拒绝写入**（不拿一个新文件覆盖运维可能还想抢救的内容）。
//!
//! 「文件不存在」是另一回事，它是初始状态，用 `Ok(None)` 表达，与 `Err` 严格区分。

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::atomic::atomic_as;
use crate::error::{CoreError, CoreResult};
use crate::paths::Paths;

/// 手工封禁文件权限：只有 root 能读写。它决定谁可以访问本机 SMTP，属于安全面配置。
pub const MANUAL_BANS_MODE: u32 = 0o600;

/// 一条手工封禁。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualBan {
    /// 被封禁的地址。
    ///
    /// 用 `IpAddr` 而不是 `String`：解析即规范化，`::1` 与 `0:0:0:0:0:0:0:1`
    /// 不会变成两条互不相干的记录（而它们本该是同一条）。
    pub ip: IpAddr,
    /// 封禁时刻（ISO 8601 UTC）。
    #[serde(rename = "bannedAt")]
    pub banned_at: String,
    /// 运维填写的备注（可空）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// 手工封禁文件的读写失败。
///
/// 刻意与 [`crate::error::CoreError`] 分开：这个错误要区分「读不到」与「读到了但坏了」，
/// 而两者在调用方的处置正好不同（前者可重试，后者必须人工介入）。
#[derive(Debug, thiserror::Error)]
pub enum BanStoreError {
    #[error("手工封禁文件无法读写（{}）：{source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 文件存在但内容不是合法的封禁列表。**调用方不得把它当作空列表**。
    #[error("手工封禁文件内容无法解析（{}）：{detail}", .path.display())]
    Corrupt { path: PathBuf, detail: String },
}

/// 手工封禁文件。
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

    /// 读取全部手工封禁。
    ///
    /// * `Ok(None)` —— 文件不存在。这是初始状态，表示「还没有人手工封禁过任何地址」。
    /// * `Ok(Some(list))` —— 解析成功（空数组也是合法内容）。
    /// * `Err(..)` —— 读不到或内容坏了，**绝不能**当作空列表使用。
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
        // 全空白等同于「什么都没写」，按不存在处理（原子写不会产生这种文件，但人工
        // 用编辑器清空过就可能出现，此时报「损坏」只会让人困惑）。
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

    /// 写入一条手工封禁（幂等）。返回写入后的完整列表。
    ///
    /// 已存在的地址保留**首次**的 `bannedAt`：重复点击「封禁」不该把时间戳刷新成
    /// 「刚刚封的」，那会让运维误判这条封禁已经生效多久。备注则允许补齐。
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

    /// 解除一条手工封禁（幂等）。返回写入后的完整列表。
    ///
    /// 地址不在列表里**不是错误**：运维连点两次「解封」，第二次不该失败。
    pub fn remove(&self, ip: IpAddr) -> CoreResult<Vec<ManualBan>> {
        self.update(move |bans| bans.retain(|entry| entry.ip != ip))
    }

    /// 在**同一把锁内**完成「读 → 改 → 原子写」。
    ///
    /// 少了这把锁，两次并发的手工封禁会各自基于同一份旧内容写入，后写的那次把先写的
    /// 那条悄悄抹掉。
    ///
    /// 返回值刻意用 [`CoreResult`] 而不是 [`BanStoreError`]：唯一的消费者是特权助手，
    /// 它只需要一段能给运维看的消息。真正需要按「读不到 vs 读坏了」分流的只有
    /// 守护进程的热重载，而那条路径走的是 [`ManualBanStore::load`]，不经过这里。
    fn update<F>(&self, mutate: F) -> CoreResult<Vec<ManualBan>>
    where
        F: FnOnce(&mut Vec<ManualBan>),
    {
        let lock_path = self.path.clone();
        let write_path = self.path.clone();
        crate::atomic::locked(&lock_path, move || {
            // 注意：这里必须用 `load()` 而不是 `unwrap_or_default()` —— 损坏的文件
            // 只能报错，不能被当成空列表再覆盖掉。
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
            // 「内容坏了」是配置问题、不是调用方输入问题；CoreError 没有对应变体，
            // 用 Invalid 携带完整原因（消息里已写明「无法解析」与具体路径）。
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

    /// 与 `atomic` / `audit` 的测试同款：`std::env::temp_dir()` 下的唯一目录。
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
        // 这条是本节的核心：把损坏当成空列表，等于把在册的手工封禁全部解除。
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

        // 幂等：再删一次不是错误。
        store.remove(ip("198.51.100.7")).unwrap();
    }

    #[test]
    fn adding_twice_keeps_the_first_timestamp() {
        // 重复点击「封禁」不该把时间戳刷成「刚刚封的」。
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
        // `::1` 与 `0:0:0:0:0:0:0:1` 是同一个地址；按字符串存会变成两条记录，
        // 于是「解封」只解掉其中一条，另一条继续封着。
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

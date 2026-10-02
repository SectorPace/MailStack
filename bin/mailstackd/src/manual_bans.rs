//! 手工封禁的热重载：把管理台写的封禁文件对齐进内存封禁表。
//!
//! ## 为什么是「文件 → 内存」而不是直接改内存
//!
//! 特权助手（`security.ban` / `security.unban`）与守护进程虽然是同一个进程里的两份
//! socket，但**封禁状态的权威副本是文件**：它同时满足两件内存做不到的事 ——
//! 重启后仍然生效，且在任何一侧崩溃后都不会出现「我以为还封着」的错觉。
//!
//! 代价是生效有延迟（一个 [`RELOAD_INTERVAL`]），这一点在 `security.ban` 的响应里
//! 用 `takesEffectAfterReload` 明确告诉了调用方。
//!
//! ## 三条纪律
//!
//! 1. **读取失败一律保持现状**。`Err` 绝不当作空集合：空集合的含义是「没有任何手工
//!    封禁」，于是会去把在册的手工封禁全部解除 —— 一次文件损坏就等于静默放行。
//! 2. **只动手工封禁**。自动封禁（失败计数触发的）由 [`BanList::apply_manual`] 保证
//!    不受影响，这里不额外做任何筛选。
//! 3. **首轮立即执行**。`interval` 的第一次 `tick` 会立刻返回，因此重启后
//!    手工封禁马上恢复，而不是先留出几秒的放行窗口。

use std::sync::Arc;
use std::time::Duration;

use mailstack_core::bans::ManualBanStore;
use mailstack_core::Paths;
use mailstack_smtpd::{BanList, ManualBanDiff};

/// 封禁文件的重载间隔。
///
/// 与队列调度的 10s 同量级：封禁是「运维的一次手动动作」，秒级延迟无实际影响；
/// 更密的轮询只是在反复读一个小文件。
pub const RELOAD_INTERVAL: Duration = Duration::from_secs(5);

/// 执行一次重载。
///
/// 返回 `Some(diff)` 表示已经把文件内容对齐进内存表（`diff` 可能为空 = 无变化）；
/// 返回 `None` 表示**文件读不到或内容坏了，本次没有改动任何封禁** ——
/// 调用方应当告警而不是继续。
pub fn reload_once(store: &ManualBanStore, bans: &BanList) -> Option<ManualBanDiff> {
    let ips = match store.load() {
        // 文件不存在 = 还没有人手工封禁过任何地址，是一个正常的初始状态。
        Ok(None) => Vec::new(),
        Ok(Some(entries)) => entries.into_iter().map(|entry| entry.ip).collect(),
        Err(_) => return None,
    };
    Some(bans.apply_manual(&ips))
}

/// 按固定节奏重载封禁文件，直到收到停机信号。
pub async fn watch(
    paths: Paths,
    bans: Arc<BanList>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let mut shutdown = std::pin::pin!(shutdown);
    let mut ticker = tokio::time::interval(RELOAD_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // 读的是几十字节的小文件，同步读即可 —— 这里不值得为它引入一套异步文件 I/O。
    let store = ManualBanStore::from_paths(&paths);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("手工封禁热重载停止");
                return;
            }
            _ = ticker.tick() => {
                match reload_once(&store, &bans) {
                    Some(diff) if !diff.is_empty() => {
                        tracing::info!(
                            added = ?diff.added,
                            removed = ?diff.removed,
                            "手工封禁已重载"
                        );
                    }
                    Some(_) => {}
                    // 关键：读失败时**什么都不做**。把读失败当空集合，等于一次
                    // 文件损坏就把在册的手工封禁全部解除。
                    None => tracing::error!(
                        path = %store.path().display(),
                        "手工封禁文件读取失败，保持现有封禁不变（本次不解除任何封禁）"
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_smtpd::BanConfig;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    fn fixture() -> (tempfile::TempDir, Paths, ManualBanStore, Arc<BanList>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        let store = ManualBanStore::from_paths(&paths);
        let bans = Arc::new(BanList::new(BanConfig {
            max_failures: 3,
            window_secs: 60,
            temp_ban_secs: 300,
            permanent_after: 3,
            max_entries: 100,
        }));
        (dir, paths, store, bans)
    }

    #[test]
    fn a_missing_file_means_no_manual_bans() {
        let (_dir, _paths, store, bans) = fixture();
        let diff = reload_once(&store, &bans).expect("不存在是正常状态");
        assert!(diff.is_empty());
        assert_eq!(bans.tracked(), 0);
    }

    #[test]
    fn reloading_applies_and_then_lifts_manual_bans() {
        let (_dir, _paths, store, bans) = fixture();
        store.add(ip(7), None, "2026-10-02T00:00:00Z").unwrap();

        reload_once(&store, &bans).unwrap();
        assert!(bans.check(ip(7), 0).is_some(), "重载后必须生效");

        // 管理台解封 → 文件里没有了 → 下一轮重载解除。
        store.remove(ip(7)).unwrap();
        reload_once(&store, &bans).unwrap();
        assert!(bans.check(ip(7), 0).is_none());
    }

    #[test]
    fn a_corrupt_file_leaves_the_current_bans_untouched() {
        // 本组最重要的一条：读失败时保持现状，否则一次文件损坏就静默放行。
        let (_dir, _paths, store, bans) = fixture();
        store.add(ip(7), None, "2026-10-02T00:00:00Z").unwrap();
        reload_once(&store, &bans).unwrap();
        assert!(bans.check(ip(7), 0).is_some());

        std::fs::write(store.path(), "{ not a ban list").unwrap();
        assert!(
            reload_once(&store, &bans).is_none(),
            "读失败必须如实返回 None"
        );
        assert!(bans.check(ip(7), 0).is_some(), "读失败绝不能解除任何封禁");
    }

    #[test]
    fn reloading_never_lifts_an_automatic_ban() {
        let (_dir, _paths, store, bans) = fixture();
        for at in 0..3 {
            bans.record_failure(ip(9), at);
        }
        assert!(bans.check(ip(9), 5).is_some());

        reload_once(&store, &bans).unwrap();

        assert!(
            bans.check(ip(9), 5).is_some(),
            "重载只能动手工封禁，自动封禁必须原样保留"
        );
    }

    #[tokio::test]
    async fn the_watcher_applies_on_the_first_tick_and_stops_on_the_signal() {
        let (_dir, paths, store, bans) = fixture();
        store.add(ip(7), None, "2026-10-02T00:00:00Z").unwrap();

        let shutdown = crate::shutdown::Shutdown::channel();
        let waiter = shutdown.waiter();
        let bans_for_task = Arc::clone(&bans);
        let handle = tokio::spawn(async move { watch(paths, bans_for_task, waiter).await });

        // 首轮 tick 立即执行，不需要等满一个间隔。
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            bans.check(ip(7), 0).is_some(),
            "重启后手工封禁必须马上恢复，而不是留出几秒放行窗口"
        );

        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("停机信号必须让热重载循环退出")
            .expect("任务不得 panic");
    }
}

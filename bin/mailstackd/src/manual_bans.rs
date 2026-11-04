use std::sync::Arc;
use std::time::Duration;

use mailstack_core::bans::ManualBanStore;
use mailstack_core::Paths;
use mailstack_smtpd::{BanList, ManualBanDiff};

pub const RELOAD_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
pub struct ReloadState {
    had_entries: bool,
}

pub fn reload_once(store: &ManualBanStore, bans: &BanList) -> Option<ManualBanDiff> {
    reload_once_with(store, bans, &mut ReloadState::default())
}

pub fn reload_once_with(
    store: &ManualBanStore,
    bans: &BanList,
    state: &mut ReloadState,
) -> Option<ManualBanDiff> {
    let ips = match store.load() {
        Ok(None) => {
            if state.had_entries {
                tracing::error!(
                    path = %store.path().display(),
                    "手工封禁文件在已知有内容的情况下消失，保持现有封禁不变（本次不解除任何封禁）"
                );
                return None;
            }

            Vec::new()
        }
        Ok(Some(entries)) => {
            state.had_entries = !entries.is_empty();
            entries.into_iter().map(|entry| entry.ip).collect()
        }
        Err(_) => return None,
    };
    Some(bans.apply_manual(&ips))
}

pub async fn watch(
    paths: Paths,
    bans: Arc<BanList>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let mut shutdown = std::pin::pin!(shutdown);
    let mut ticker = tokio::time::interval(RELOAD_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let store = ManualBanStore::from_paths(&paths);

    let mut state = ReloadState::default();

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("手工封禁热重载停止");
                return;
            }
            _ = ticker.tick() => {
                match reload_once_with(&store, &bans, &mut state) {
                    Some(diff) if !diff.is_empty() => {
                        tracing::info!(
                            added = ?diff.added,
                            removed = ?diff.removed,
                            "手工封禁已重载"
                        );
                    }
                    Some(_) => {}

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

        store.remove(ip(7)).unwrap();
        reload_once(&store, &bans).unwrap();
        assert!(bans.check(ip(7), 0).is_none());
    }

    #[test]
    fn a_corrupt_file_leaves_the_current_bans_untouched() {
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
    fn a_deleted_ban_file_does_not_silently_lift_every_manual_ban() {
        let (_dir, _paths, store, bans) = fixture();
        store.add(ip(7), None, "2026-10-02T00:00:00Z").unwrap();
        let mut state = ReloadState::default();
        reload_once_with(&store, &bans, &mut state).unwrap();
        assert!(bans.check(ip(7), 0).is_some());

        std::fs::remove_file(store.path()).unwrap();
        assert!(
            reload_once_with(&store, &bans, &mut state).is_none(),
            "文件曾有过内容却消失：必须报异常，而不是当作空集合"
        );
        assert!(
            bans.check(ip(7), 0).is_some(),
            "文件消失绝不能把在册手工封禁全部解除"
        );

        let (_dir2, _p2, store2, bans2) = fixture();
        let mut fresh = ReloadState::default();
        let diff = reload_once_with(&store2, &bans2, &mut fresh).expect("首次运行是正常状态");
        assert!(diff.is_empty());
    }

    #[test]
    fn removing_the_last_ban_through_the_store_still_lifts_it() {
        let (_dir, _paths, store, bans) = fixture();
        store.add(ip(7), None, "2026-10-02T00:00:00Z").unwrap();
        let mut state = ReloadState::default();
        reload_once_with(&store, &bans, &mut state).unwrap();
        assert!(bans.check(ip(7), 0).is_some());

        store.remove(ip(7)).unwrap();
        assert!(store.path().exists(), "remove 写空数组，不删除文件");
        reload_once_with(&store, &bans, &mut state).unwrap();
        assert!(bans.check(ip(7), 0).is_none(), "正常解封路径必须仍然生效");
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

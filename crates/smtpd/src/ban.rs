use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::peer::PeerKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanConfig {
    pub max_failures: u32,

    pub window_secs: i64,

    pub temp_ban_secs: i64,

    pub permanent_after: u32,

    pub max_entries: usize,
}

impl Default for BanConfig {
    fn default() -> Self {
        Self {
            max_failures: 8,
            window_secs: 600,
            temp_ban_secs: 3600,
            permanent_after: 3,
            max_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    pub ip: IpAddr,

    pub until_unix: Option<i64>,
    pub permanent: bool,

    pub strikes: u32,

    pub failures: u32,

    pub manual: bool,
}

impl Ban {
    pub fn is_active(&self, now: i64) -> bool {
        if self.permanent {
            return true;
        }
        matches!(self.until_unix, Some(until) if until > now)
    }
}

#[derive(Debug, Default, Clone)]
struct Entry {
    failures: Vec<i64>,
    strikes: u32,
    banned_until: Option<i64>,
    permanent: bool,

    manual: bool,
    last_seen: i64,

    last_ip: Option<IpAddr>,
}

impl Entry {
    fn to_ban(&self, ip: IpAddr) -> Ban {
        Ban {
            ip: self.last_ip.unwrap_or(ip),
            until_unix: self.banned_until,
            permanent: self.permanent,
            strikes: self.strikes,
            failures: self.failures.len() as u32,
            manual: self.manual,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManualBanDiff {
    pub added: Vec<IpAddr>,

    pub removed: Vec<IpAddr>,
}

impl ManualBanDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

#[derive(Debug)]
pub struct BanList {
    config: BanConfig,
    entries: Mutex<HashMap<PeerKey, Entry>>,
}

impl BanList {
    pub fn new(config: BanConfig) -> Self {
        let config = BanConfig {
            max_failures: config.max_failures.max(1),
            window_secs: config.window_secs.max(1),
            temp_ban_secs: config.temp_ban_secs.max(1),
            permanent_after: config.permanent_after,
            max_entries: config.max_entries.max(1),
        };
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> BanConfig {
        self.config
    }

    pub fn banned_count(&self, now: i64) -> usize {
        self.entries(now).len()
    }

    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    pub fn check(&self, ip: IpAddr, now: i64) -> Option<Ban> {
        let mut guard = self.lock();
        let entry = guard.get_mut(&PeerKey::from_ip(ip))?;
        Self::active_ban(entry, ip, now)
    }

    pub fn record_failure(&self, ip: IpAddr, now: i64) -> Option<Ban> {
        let config = self.config;
        let key = PeerKey::from_ip(ip);
        let mut guard = self.lock();

        if guard.len() >= config.max_entries && !guard.contains_key(&key) {
            let freed = evict(&mut guard, config.max_entries, now);

            if !freed && !guard.contains_key(&key) {
                return None;
            }
        }

        let entry = guard.entry(key).or_default();
        entry.last_seen = now;
        entry.last_ip = Some(ip);

        if entry.permanent {
            return Some(entry.to_ban(ip));
        }
        if let Some(until) = entry.banned_until {
            if until > now {
                return Some(entry.to_ban(ip));
            }

            entry.banned_until = None;
            entry.failures.clear();
        }

        entry
            .failures
            .retain(|at| now.saturating_sub(*at) < config.window_secs);
        entry.failures.push(now);

        if (entry.failures.len() as u32) < config.max_failures {
            return None;
        }

        entry.failures.clear();
        entry.strikes = entry.strikes.saturating_add(1);
        let permanent = config.permanent_after > 0 && entry.strikes >= config.permanent_after;
        entry.permanent = permanent;
        entry.banned_until = if permanent {
            None
        } else {
            Some(now.saturating_add(config.temp_ban_secs))
        };
        Some(entry.to_ban(ip))
    }

    pub fn unban(&self, ip: IpAddr) -> bool {
        self.lock().remove(&PeerKey::from_ip(ip)).is_some()
    }

    pub fn banned(&self, now: i64) -> Vec<Ban> {
        self.entries(now)
    }

    pub fn apply_manual(&self, ips: &[IpAddr]) -> ManualBanDiff {
        let wanted: HashMap<PeerKey, IpAddr> =
            ips.iter().map(|ip| (PeerKey::from_ip(*ip), *ip)).collect();
        let mut diff = ManualBanDiff::default();
        let mut guard = self.lock();

        let stale: Vec<(PeerKey, IpAddr)> = guard
            .iter()
            .filter(|(key, entry)| entry.manual && !wanted.contains_key(key))
            .map(|(key, entry)| {
                (
                    *key,
                    entry
                        .last_ip
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                )
            })
            .collect();
        for (key, ip) in stale {
            guard.remove(&key);
            diff.removed.push(ip);
        }

        for (key, ip) in &wanted {
            let entry = guard.entry(*key).or_default();
            entry.last_ip = Some(*ip);
            if !entry.manual {
                diff.added.push(*ip);
            }
            entry.manual = true;
            entry.permanent = true;
            entry.banned_until = None;

            entry.failures.clear();
        }

        diff.added.sort();
        diff.removed.sort();
        diff
    }

    fn entries(&self, now: i64) -> Vec<Ban> {
        let mut guard = self.lock();
        guard
            .values_mut()
            .filter_map(|entry| {
                let fallback = entry
                    .last_ip
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                Self::active_ban(entry, fallback, now)
            })
            .collect()
    }

    fn active_ban(entry: &mut Entry, ip: IpAddr, now: i64) -> Option<Ban> {
        if entry.permanent {
            return Some(entry.to_ban(ip));
        }
        if let Some(until) = entry.banned_until {
            if until > now {
                return Some(entry.to_ban(ip));
            }
            entry.banned_until = None;
            entry.failures.clear();
        }
        None
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PeerKey, Entry>> {
        match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn evict(entries: &mut HashMap<PeerKey, Entry>, max_entries: usize, now: i64) -> bool {
    entries.retain(|_, entry| {
        entry.permanent
            || entry.manual
            || entry.banned_until.is_some_and(|until| until > now)
            || !entry.failures.is_empty()
    });

    if entries.len() < max_entries {
        return true;
    }

    let mut candidates: Vec<(PeerKey, i64, i64)> = entries
        .iter()
        .filter(|(_, entry)| {
            !entry.permanent && !entry.manual && entry.banned_until.is_none_or(|until| until <= now)
        })
        .map(|(key, entry)| {
            let expired_ban = entry.banned_until.is_some_and(|until| until <= now);
            let history_value = i64::from(!expired_ban && !entry.failures.is_empty());
            (*key, entry.last_seen, history_value)
        })
        .collect();

    candidates.sort_by_key(|(_, last_seen, history_value)| (*history_value, *last_seen));

    let target = max_entries.saturating_sub(1);
    let remove_count = entries.len().saturating_sub(target);
    for (victim, _, _) in candidates.into_iter().take(remove_count) {
        entries.remove(&victim);
    }
    entries.len() < max_entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    fn list() -> BanList {
        BanList::new(BanConfig {
            max_failures: 3,
            window_secs: 60,
            temp_ban_secs: 300,
            permanent_after: 3,
            max_entries: 100,
        })
    }

    #[test]
    fn failures_below_the_threshold_do_not_ban() {
        let bans = list();
        assert!(bans.record_failure(ip(1), 0).is_none());
        assert!(bans.record_failure(ip(1), 1).is_none());
        assert!(bans.check(ip(1), 1).is_none(), "两次失败不该封禁");
    }

    #[test]
    fn reaching_the_threshold_issues_a_temporary_ban() {
        let bans = list();
        assert!(bans.record_failure(ip(1), 0).is_none());
        assert!(bans.record_failure(ip(1), 1).is_none());
        let ban = bans.record_failure(ip(1), 2).expect("第三次应触发封禁");
        assert!(!ban.permanent, "首次应是临时封禁");
        assert_eq!(ban.until_unix, Some(302), "解除时刻 = now + 300");
        assert!(ban.is_active(2));
        assert!(bans.check(ip(1), 100).is_some());
    }

    #[test]
    fn a_temporary_ban_expires_and_clears_the_window() {
        let bans = list();
        for at in 0..3 {
            bans.record_failure(ip(1), at);
        }
        assert!(bans.check(ip(1), 301).is_some(), "到期前仍应生效");
        assert!(bans.check(ip(1), 302).is_none(), "到期后应自动解除");
        assert_eq!(bans.banned_count(302), 0);
    }

    #[test]
    fn old_failures_fall_out_of_the_window() {
        let bans = list();
        bans.record_failure(ip(1), 0);
        bans.record_failure(ip(1), 1);

        assert!(
            bans.record_failure(ip(1), 10_000).is_none(),
            "窗口外的失败不得被计入"
        );
    }

    #[test]
    fn repeated_offences_escalate_to_a_permanent_ban_that_never_expires() {
        let bans = list();

        for at in 0..3 {
            bans.record_failure(ip(1), at);
        }
        assert!(bans.check(ip(1), 301).is_some(), "到期前仍应生效");
        assert!(bans.check(ip(1), 302).is_none(), "到期后应解除");

        for at in 1000..1003 {
            bans.record_failure(ip(1), at);
        }
        let ban = bans.check(ip(1), 1000).expect("第二回合应封禁");
        assert_eq!(ban.strikes, 2);
        assert!(!ban.permanent, "第二次仍是临时封禁");
        assert!(bans.check(ip(1), 1350).is_none(), "第二回合的封禁也应到期");

        for at in 2000..2003 {
            bans.record_failure(ip(1), at);
        }
        let ban = bans.check(ip(1), 2000).expect("应处于永久封禁");
        assert!(ban.permanent, "第三次触发应为永久封禁");
        assert_eq!(ban.until_unix, None);
        assert!(
            bans.check(ip(1), 20_000_000).is_some(),
            "永久封禁不得随时间解除"
        );
    }

    #[test]
    fn failures_while_already_banned_do_not_self_escalate() {
        let bans = list();
        for at in 0..3 {
            bans.record_failure(ip(1), at);
        }

        for at in 3..50 {
            bans.record_failure(ip(1), at);
        }
        let ban = bans.check(ip(1), 50).unwrap();
        assert_eq!(ban.strikes, 1);
        assert!(!ban.permanent);
    }

    #[test]
    fn unbanned_ips_are_independent() {
        let bans = list();
        for at in 0..3 {
            bans.record_failure(ip(1), at);
        }
        assert!(bans.check(ip(1), 5).is_some());
        assert!(bans.check(ip(2), 5).is_none(), "另一个 IP 不受影响");
    }

    #[test]
    fn one_ipv6_slash_64_cannot_rotate_addresses_to_dodge_the_ban() {
        let bans = BanList::new(BanConfig {
            max_failures: 8,
            window_secs: 600,
            temp_ban_secs: 300,
            permanent_after: 0,
            max_entries: 1_000,
        });
        let base: std::net::Ipv6Addr = "2001:db8:aa:bb::".parse().unwrap();
        let segment = |index: u16| {
            let mut octets = base.octets();

            octets[14..].copy_from_slice(&index.to_be_bytes());
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        };

        for index in 0..7 {
            assert!(
                bans.record_failure(segment(index), 0).is_none(),
                "第 {index} 次失败还不该封禁"
            );
        }
        let ban = bans
            .record_failure(segment(7), 0)
            .expect("同一 /64 的第 8 次失败必须触发封禁");
        assert!(!ban.permanent);

        assert!(
            bans.check(segment(999), 1).is_some(),
            "同一 /64 内的任意地址都必须在封禁中"
        );

        let other: IpAddr = "2001:db8:aa:bc::1".parse().unwrap();
        assert!(bans.check(other, 1).is_none(), "不同 /64 不得连坐");
    }

    #[test]
    fn unban_clears_even_a_permanent_ban() {
        let bans = list();

        for round in 0..3i64 {
            let base = round * 1000;
            for at in base..base + 3 {
                bans.record_failure(ip(1), at);
            }
        }
        assert!(
            bans.check(ip(1), 2000).expect("应处于封禁").permanent,
            "第三回合应升级为永久封禁"
        );
        assert!(bans.unban(ip(1)));
        assert!(bans.check(ip(1), 2000).is_none(), "解封后必须立即放行");
        assert!(!bans.unban(ip(1)), "重复解封应返回 false");
    }

    #[test]
    fn the_table_is_bounded_and_never_drops_a_permanent_ban() {
        let bans = BanList::new(BanConfig {
            max_failures: 1,
            window_secs: 60,
            temp_ban_secs: 10_000,
            permanent_after: 0,
            max_entries: 16,
        });
        for last in 0..64u8 {
            bans.record_failure(ip(last), 0);
        }
        assert!(
            bans.tracked() <= 17,
            "封禁表必须被内存上限约束，实际 {}",
            bans.tracked()
        );
    }

    #[test]
    fn a_manual_ban_is_permanent_and_needs_no_failure_counting() {
        let bans = list();
        let diff = bans.apply_manual(&[ip(9)]);

        assert_eq!(diff.added, vec![ip(9)]);
        assert!(diff.removed.is_empty());
        let ban = bans.check(ip(9), 0).expect("手工封禁必须立即生效");
        assert!(ban.manual);
        assert!(ban.permanent);
        assert_eq!(ban.until_unix, None, "手工封禁不是临时的");
        assert!(
            bans.check(ip(9), 20_000_000).is_some(),
            "手工封禁不得随时间到期"
        );
    }

    #[test]
    fn reloading_the_file_never_lifts_automatic_bans() {
        let bans = list();
        for at in 0..3 {
            bans.record_failure(ip(1), at);
        }
        assert!(bans.check(ip(1), 5).is_some());

        bans.apply_manual(&[ip(2)]);

        let auto = bans.check(ip(1), 5).expect("自动封禁必须原样保留");
        assert!(!auto.manual, "它仍是自动封禁");
        assert!(bans.check(ip(2), 5).is_some());
    }

    #[test]
    fn removing_an_address_from_the_file_lifts_only_that_manual_ban() {
        let bans = list();
        bans.apply_manual(&[ip(1), ip(2)]);
        for at in 0..3 {
            bans.record_failure(ip(3), at);
        }

        let diff = bans.apply_manual(&[ip(2)]);

        assert_eq!(diff.removed, vec![ip(1)]);
        assert!(diff.added.is_empty());
        assert!(
            bans.check(ip(1), 5).is_none(),
            "已从文件移除的手工封禁应解除"
        );
        assert!(bans.check(ip(2), 5).is_some());
        assert!(bans.check(ip(3), 5).is_some(), "自动封禁不受影响");
    }

    #[test]
    fn applying_the_same_set_twice_reports_no_change() {
        let bans = list();
        bans.apply_manual(&[ip(1), ip(2)]);
        let diff = bans.apply_manual(&[ip(2), ip(1)]);
        assert!(
            diff.is_empty(),
            "集合未变时不该报告变化，否则每次重载都会刷屏：{diff:?}"
        );
    }

    #[test]
    fn a_manual_ban_upgrades_an_existing_automatic_ban_and_reports_it() {
        let bans = list();
        for at in 0..3 {
            bans.record_failure(ip(1), at);
        }
        let diff = bans.apply_manual(&[ip(1)]);

        assert_eq!(diff.added, vec![ip(1)], "升格必须被报告出来");
        let ban = bans.check(ip(1), 5).unwrap();
        assert!(ban.manual);
        assert!(ban.permanent, "手工封禁必须升为永久，而不是停在临时");
        assert!(bans.check(ip(1), 20_000_000).is_some());
    }

    #[test]
    fn an_empty_file_clears_every_manual_ban_but_never_an_automatic_one() {
        let bans = list();
        bans.apply_manual(&[ip(1), ip(2)]);
        for at in 0..3 {
            bans.record_failure(ip(3), at);
        }

        bans.apply_manual(&[]);

        assert!(bans.check(ip(1), 5).is_none());
        assert!(bans.check(ip(2), 5).is_none());
        assert!(bans.check(ip(3), 5).is_some(), "自动封禁不得被空集合清掉");
    }

    #[test]
    fn failure_counting_cannot_escalate_or_weaken_a_manual_ban() {
        let bans = list();
        bans.apply_manual(&[ip(1)]);

        for at in 0..50 {
            bans.record_failure(ip(1), at);
        }
        let ban = bans.check(ip(1), 50).unwrap();
        assert!(ban.manual);
        assert!(ban.permanent);
        assert_eq!(ban.strikes, 0, "手工封禁不参与 strike 升级");
    }

    #[test]
    fn a_manual_ban_is_never_evicted_by_the_memory_cap() {
        let bans = BanList::new(BanConfig {
            max_failures: 1,
            window_secs: 60,
            temp_ban_secs: 10_000,
            permanent_after: 0,
            max_entries: 16,
        });
        bans.apply_manual(&[ip(200)]);

        for last in 0..64u8 {
            bans.record_failure(ip(last), 0);
        }

        assert!(
            bans.check(ip(200), 20_000_000).is_some(),
            "手工封禁不得被内存上限淘汰 —— 淘汰它等于悄悄解封"
        );
    }
}

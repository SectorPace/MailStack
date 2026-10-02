//! IP 自动封禁：失败计数 → 临时 / 永久封禁（替代 fail2ban 的「封禁」那一半）。
//!
//! ## 触发源有两类，且都是「攻击者主动暴露的行为」
//!
//! 1. **连接建立失败**：TLS 握手失败、会话中途 I/O 出错。
//! 2. **触发限速**：见 [`crate::ratelimit`]。
//!
//! 两者都由 [`BanList::record_failure`] 记录，窗口内的失败次数达到阈值即封禁。
//! 之所以用**滑动窗口**而不是「累计总数」：后者会让一个正常跑了几天的对端因为
//! 几次无关的抖动而被永久拉黑。
//!
//! ## 升级路径：临时 → 永久
//!
//! 每次触发封禁记一次 `strike`。前 `permanent_after - 1` 次是临时封禁（到时间自动
//! 解除），第 `permanent_after` 次转为**永久**。临时封禁到期只清空失败计数，
//! **不清** `strike` —— 否则「屡教不改」永远不会升级为永久。
//!
//! ## 时钟注入
//!
//! 与限速器一样，所有判定都接收 `now`（Unix 秒），因此「临时封禁到期自动解除」这种
//! 时间相关的行为可以在测试里被确定性地验证，而不是靠 `sleep`。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// 封禁策略参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanConfig {
    /// 窗口内失败多少次后封禁。
    pub max_failures: u32,
    /// 失败计数的滑动窗口（秒）。
    pub window_secs: i64,
    /// 单次临时封禁的时长（秒）。
    pub temp_ban_secs: i64,
    /// 第几次触发封禁转为永久（`0` 表示永不永久）。
    pub permanent_after: u32,
    /// 记录表的最大条目数（内存上限）。
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

/// 一条封禁记录（对外视图）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    pub ip: IpAddr,
    /// 临时封禁的解除时刻；永久封禁为 `None`。
    pub until_unix: Option<i64>,
    pub permanent: bool,
    /// 已触发封禁的次数（升级为永久的判据）。
    pub strikes: u32,
    /// 当前窗口内的失败次数。
    pub failures: u32,
    /// 是否来自管理台的**手工**封禁（而不是由失败计数自动触发）。
    ///
    /// 这个区分不是装饰：手工封禁由运维的文件驱动，自动封禁由对端行为驱动，
    /// 两者在「谁有权解除」上完全不同 —— 手工封禁只能由文件变更解除，
    /// 一次失败计数或到期都不该让一条手工封禁消失。
    pub manual: bool,
}

impl Ban {
    /// 该封禁在 `now` 时刻是否仍然生效。
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
    /// 见 [`Ban::manual`]。
    manual: bool,
    last_seen: i64,
}

impl Entry {
    fn to_ban(&self, ip: IpAddr) -> Ban {
        Ban {
            ip,
            until_unix: self.banned_until,
            permanent: self.permanent,
            strikes: self.strikes,
            failures: self.failures.len() as u32,
            manual: self.manual,
        }
    }
}

/// [`BanList::apply_manual`] 的结果，供调用方记日志。
///
/// 之所以要把它返回出来：热重载是一条**静默**的路径 —— 没有它，运维只能看到
/// 「封禁生效了」而看不到「有 5 条手工封禁刚刚被解除」。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManualBanDiff {
    /// 本次开始被手工封禁的地址（新建，或由自动封禁升格为手工）。
    pub added: Vec<IpAddr>,
    /// 本次被解除的手工封禁（文件里已不再列出）。
    pub removed: Vec<IpAddr>,
}

impl ManualBanDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// IP 封禁表。
#[derive(Debug)]
pub struct BanList {
    config: BanConfig,
    entries: Mutex<HashMap<IpAddr, Entry>>,
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

    /// 当前被封禁的 IP 数量。
    pub fn banned_count(&self, now: i64) -> usize {
        self.entries(now).len()
    }

    /// 跟踪的 IP 条目总数（测试内存上界用）。
    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    /// 查询某 IP 当前是否被封禁。
    pub fn check(&self, ip: IpAddr, now: i64) -> Option<Ban> {
        let mut guard = self.lock();
        let entry = guard.get_mut(&ip)?;
        Self::active_ban(entry, ip, now)
    }

    /// 记录一次失败；若本次失败触发了封禁则返回该封禁，否则返回 `None`。
    pub fn record_failure(&self, ip: IpAddr, now: i64) -> Option<Ban> {
        let config = self.config;
        let mut guard = self.lock();

        if guard.len() >= config.max_entries && !guard.contains_key(&ip) {
            evict(&mut guard, config.max_entries);
        }

        let entry = guard.entry(ip).or_default();
        entry.last_seen = now;

        // 已在封禁中：不重复计数（否则单次攻击会自我叠加成永久封禁）。
        if entry.permanent {
            return Some(entry.to_ban(ip));
        }
        if let Some(until) = entry.banned_until {
            if until > now {
                return Some(entry.to_ban(ip));
            }
            // 临时封禁已到期：清空窗口，允许重新计数（strike 保留）。
            entry.banned_until = None;
            entry.failures.clear();
        }

        // 滑动窗口：丢弃窗口之外的旧失败。
        entry
            .failures
            .retain(|at| now.saturating_sub(*at) < config.window_secs);
        entry.failures.push(now);

        if (entry.failures.len() as u32) < config.max_failures {
            return None;
        }

        // 达到阈值：封禁。
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

    /// 解除某 IP 的封禁（含永久封禁），并清空其计数。返回此前是否存在记录。
    pub fn unban(&self, ip: IpAddr) -> bool {
        self.lock().remove(&ip).is_some()
    }

    /// 当前生效的封禁列表。
    pub fn banned(&self, now: i64) -> Vec<Ban> {
        self.entries(now)
    }

    /// 用管理台的**手工封禁集合**对齐内存表，返回本次的变化。
    ///
    /// 这是「封禁文件是唯一真相源」的落地点：每次热重载都拿文件的完整集合来对齐，
    /// 而不是增量地「加一条 / 删一条」—— 增量在丢包、人工编辑文件、回滚文件版本
    /// 这些情况下都会与文件产生分歧。
    ///
    /// 两条必须守住的边界：
    ///
    /// 1. **绝不碰自动封禁**。只有 `manual == true` 的条目才可能被本次调用删除。
    ///    否则一次文件重载就会把正在攻击的地址全部放行 —— 而且不留下任何痕迹。
    /// 2. **手工封禁是永久的，且不受失败计数影响**。它只能由文件变更解除；
    ///    到期与 strike 升级都与它无关。
    pub fn apply_manual(&self, ips: &[IpAddr]) -> ManualBanDiff {
        let wanted: std::collections::HashSet<IpAddr> = ips.iter().copied().collect();
        let mut diff = ManualBanDiff::default();
        let mut guard = self.lock();

        // 先解除：文件里已不再列出的手工封禁。
        let stale: Vec<IpAddr> = guard
            .iter()
            .filter(|(ip, entry)| entry.manual && !wanted.contains(ip))
            .map(|(ip, _)| *ip)
            .collect();
        for ip in stale {
            guard.remove(&ip);
            diff.removed.push(ip);
        }

        // 再新增：文件里列出但尚未是手工封禁的地址。
        for ip in &wanted {
            let entry = guard.entry(*ip).or_default();
            if !entry.manual {
                diff.added.push(*ip);
            }
            entry.manual = true;
            entry.permanent = true;
            entry.banned_until = None;
            // 手工封禁不记账：它不参与 strike 升级，失败计数对它也没有意义。
            entry.failures.clear();
        }

        diff.added.sort();
        diff.removed.sort();
        diff
    }

    fn entries(&self, now: i64) -> Vec<Ban> {
        let mut guard = self.lock();
        guard
            .iter_mut()
            .filter_map(|(ip, entry)| Self::active_ban(entry, *ip, now))
            .collect()
    }

    /// 若封禁生效则返回，否则顺带清理到期的临时封禁状态。
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

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Entry>> {
        match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// 内存上限保护：优先淘汰「未封禁且无计数」的陈旧条目，其次淘汰最久未活动者。
/// 永久封禁的条目**不参与**淘汰 —— 淘汰它等于悄悄解封。
///
/// `manual` 单独再判一次：手工封禁当前必然是永久的，所以这条判断今天不会改变行为；
/// 它存在是为了让「手工封禁不可被淘汰」成为本函数自己的约束，而不是依赖
/// [`BanList::apply_manual`] 恰好把它设成了永久。
fn evict(entries: &mut HashMap<IpAddr, Entry>, max_entries: usize) {
    entries.retain(|_, entry| {
        entry.permanent
            || entry.manual
            || entry.banned_until.is_some()
            || !entry.failures.is_empty()
    });

    if entries.len() < max_entries {
        return;
    }

    let mut ages: Vec<(IpAddr, i64)> = entries
        .iter()
        .filter(|(_, entry)| !entry.permanent && !entry.manual)
        .map(|(ip, entry)| (*ip, entry.last_seen))
        .collect();
    ages.sort_by_key(|(_, last)| *last);

    let target = max_entries.saturating_sub(1);
    let remove_count = entries.len().saturating_sub(target);
    for (victim, _) in ages.into_iter().take(remove_count) {
        entries.remove(&victim);
    }
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
        // 第三次远在窗口之外：前两次应被丢弃，不该凑够阈值。
        assert!(
            bans.record_failure(ip(1), 10_000).is_none(),
            "窗口外的失败不得被计入"
        );
    }

    #[test]
    fn repeated_offences_escalate_to_a_permanent_ban_that_never_expires() {
        let bans = list();
        // 第 1 回合：t=0..2 触发，临时封禁到 302。
        for at in 0..3 {
            bans.record_failure(ip(1), at);
        }
        assert!(bans.check(ip(1), 301).is_some(), "到期前仍应生效");
        assert!(bans.check(ip(1), 302).is_none(), "到期后应解除");

        // 第 2 回合：仍是临时封禁，strike 累加到 2。
        for at in 1000..1003 {
            bans.record_failure(ip(1), at);
        }
        let ban = bans.check(ip(1), 1000).expect("第二回合应封禁");
        assert_eq!(ban.strikes, 2);
        assert!(!ban.permanent, "第二次仍是临时封禁");
        assert!(bans.check(ip(1), 1350).is_none(), "第二回合的封禁也应到期");

        // 第 3 回合：升级为永久。
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
        // 封禁中继续失败：不重复计数，也就不会自己升级成永久。
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
    fn unban_clears_even_a_permanent_ban() {
        let bans = list();
        // 三个回合，各在相隔足够远的时间点触发（每次都超出上一回合的封禁时长）。
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
            permanent_after: 0, // 永不永久，便于制造大量临时条目
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

    // ───────────────────── 手工封禁（管理台文件驱动） ─────────────────────

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
        // 这是本组最重要的一条：若热重载会顺手清掉自动封禁，一次文件重载就等于
        // 把正在攻击的地址全部放行，而且不留痕迹。
        let bans = list();
        for at in 0..3 {
            bans.record_failure(ip(1), at); // 自动（临时）封禁
        }
        assert!(bans.check(ip(1), 5).is_some());

        // 文件里只有另一个地址 —— 与 ip(1) 无关。
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
            bans.record_failure(ip(3), at); // 自动封禁，不该被碰
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

        // 手工封禁期间继续失败：既不重复计数（那会自我升级），也不改变封禁性质。
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

        // 制造大量会自动过期的条目，把表挤到上限之上。
        for last in 0..64u8 {
            bans.record_failure(ip(last), 0);
        }

        assert!(
            bans.check(ip(200), 20_000_000).is_some(),
            "手工封禁不得被内存上限淘汰 —— 淘汰它等于悄悄解封"
        );
    }
}

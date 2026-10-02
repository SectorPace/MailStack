//! 指数退避与重试风暴抑制（规格书 §5.8；风险表「重试风暴」）。
//!
//! 两条设计要求：
//!
//! 1. **指数退避**：失败次数越多等得越久，避免对端长期不可用时的高频重试。
//! 2. **不得共振**：若所有条目用同一条退避曲线，一次网络抖动会让它们在同一个
//!    时刻集体重试（thundering herd），把刚恢复的对端再打垮。因此每次重试时间
//!    加上**由条目 id 派生的确定性抖动** —— 确定性意味着「同一条目的重试时间可
//!    复现、可测试」，而不同条目则不共振。

use crate::entry::QueueEntry;

/// 退避参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// 首次重试的等待秒数。
    pub base_secs: u64,
    /// 每次失败的放大倍数。
    pub factor: u32,
    /// 单次等待的上限（避免退避到「永远不再重试」）。
    pub max_secs: u64,
    /// 最大尝试次数；达到即停止重试并退信。
    pub max_attempts: u32,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        // 5 分钟起步、翻倍、封顶 4 小时、最多 10 次 —— 与 Postfix 的默认节奏
        // （minimal_backoff_time 300s / maximal_backoff_time 4000s）同量级，
        // 总跨度约 1 天，之后退信而不是无限堆积（§5.10.3 R-25-3）。
        Self {
            base_secs: 300,
            factor: 2,
            max_secs: 14400,
            max_attempts: 10,
        }
    }
}

impl BackoffPolicy {
    /// 第 `attempt` 次失败后的等待秒数（`attempt` 从 1 开始）。
    ///
    /// = 名义指数退避 + 抖动。抖动范围 ±10%，上界仍受 `max_secs` 约束。
    pub fn delay_secs(&self, attempt: u32, entry_id: &str) -> u64 {
        let nominal = self.nominal_delay_secs(attempt);
        if nominal == 0 {
            return 0;
        }
        let spread = (nominal / 10).max(1);
        let hash = stable_hash(entry_id);
        // 落在 [nominal - spread, nominal + spread] 内，确定性且与 id 绑定。
        let delta = hash % (2 * spread + 1);
        nominal
            .saturating_sub(spread)
            .saturating_add(delta)
            .min(self.max_secs)
            .max(1)
    }

    /// 不含抖动的名义等待：`base * factor^(attempt-1)`，封顶 `max_secs`。
    ///
    /// 溢出安全：指数部分用 `saturating_mul`，attempt 取到 u32::MAX 也不会 panic，
    /// 只会提前贴到上限。
    pub fn nominal_delay_secs(&self, attempt: u32) -> u64 {
        if attempt == 0 {
            return 0;
        }
        let mut delay = self.base_secs;
        for _ in 1..attempt {
            delay = delay.saturating_mul(self.factor as u64);
            if delay >= self.max_secs {
                return self.max_secs;
            }
        }
        delay.min(self.max_secs)
    }

    /// 尝试次数是否已耗尽（应当停止重试并退信）。
    pub fn exhausted(&self, attempts: u32) -> bool {
        attempts >= self.max_attempts
    }

    /// 应用一次失败：累加计数并写入下次尝试时间与失败原因。
    ///
    /// 返回是否已经耗尽重试预算（真 = 调用方应当退信）。
    pub fn on_failure(
        &self,
        entry: &mut QueueEntry,
        now_unix: i64,
        last_error: Option<String>,
        last_code: Option<u16>,
    ) -> bool {
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_error = last_error;
        entry.last_code = last_code;
        let exhausted = self.exhausted(entry.attempts);
        let delay = self.delay_secs(entry.attempts, &entry.id) as i64;
        entry.next_attempt_unix = now_unix.saturating_add(delay);
        exhausted
    }
}

/// 稳定的字符串哈希（FNV-1a 64）。
///
/// 刻意不用 `DefaultHasher`：它的输出在 Rust 版本间可以变化，而**退避时间必须
/// 可复现**（运维与测试都要能算出「这条消息下次什么时候重试」）。
fn stable_hash(input: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EntryKind;

    fn policy() -> BackoffPolicy {
        BackoffPolicy {
            base_secs: 10,
            factor: 2,
            max_secs: 1000,
            max_attempts: 5,
        }
    }

    fn entry(id: &str) -> QueueEntry {
        let mut e = QueueEntry::new(
            EntryKind::Outbound,
            "s@example.org",
            vec!["r@example.net".to_string()],
            "body",
            0,
        )
        .unwrap();
        e.id = id.to_string();
        e
    }

    #[test]
    fn nominal_delay_grows_exponentially_and_is_capped() {
        let p = policy();
        assert_eq!(p.nominal_delay_secs(0), 0, "尚未失败时不应有等待");
        assert_eq!(p.nominal_delay_secs(1), 10);
        assert_eq!(p.nominal_delay_secs(2), 20);
        assert_eq!(p.nominal_delay_secs(3), 40);
        assert_eq!(p.nominal_delay_secs(4), 80);
        // 封顶后不再增长。
        assert_eq!(p.nominal_delay_secs(20), 1000);
        assert_eq!(
            p.nominal_delay_secs(u32::MAX),
            1000,
            "极大 attempt 不得溢出"
        );
    }

    #[test]
    fn nominal_delay_is_monotonic() {
        // 这一点很关键：退避绝不能出现「重试越多等得越短」。
        let p = BackoffPolicy::default();
        let mut previous = 0;
        for attempt in 1..=30 {
            let current = p.nominal_delay_secs(attempt);
            assert!(current >= previous, "第 {attempt} 次的等待比上一次更短");
            previous = current;
        }
    }

    #[test]
    fn jitter_is_deterministic_for_the_same_entry() {
        let p = policy();
        let a = p.delay_secs(5, "00000000001-0000");
        let b = p.delay_secs(5, "00000000001-0000");
        assert_eq!(a, b, "同一条目的重试时间必须可复现（否则无法解释队列行为）");
    }

    #[test]
    fn jitter_stays_within_ten_percent_and_never_below_one_second() {
        let p = policy();
        for attempt in 1..=8 {
            let nominal = p.nominal_delay_secs(attempt);
            let spread = (nominal / 10).max(1);
            for id in ["AA", "BB-01", "0000ABCD1234", "zzzz"] {
                let delay = p.delay_secs(attempt, id);
                assert!(
                    delay >= nominal.saturating_sub(spread) && delay <= nominal + spread,
                    "抖动越界：attempt={attempt} nominal={nominal} delay={delay}"
                );
                assert!(delay >= 1, "等待不得为 0（否则会变成忙等）");
                assert!(delay <= p.max_secs, "抖动不得突破上限");
            }
        }
    }

    #[test]
    fn different_entries_do_not_retry_in_lockstep() {
        // 反共振：至少要有两条条目落在不同的重试时刻上。
        let p = policy();
        let delays: Vec<u64> = (0..16)
            .map(|i| p.delay_secs(3, &format!("{i:04X}")))
            .collect();
        let distinct: std::collections::HashSet<u64> = delays.iter().copied().collect();
        assert!(
            distinct.len() > 1,
            "所有条目退避时间完全相同 → 重试风暴防护失效：{delays:?}"
        );
    }

    #[test]
    fn on_failure_counts_attempts_and_schedules_next_try() {
        let p = policy();
        let mut e = entry("QQ01");
        assert!(!p.on_failure(&mut e, 1000, Some("450 busy".into()), Some(450)));
        assert_eq!(e.attempts, 1);
        assert_eq!(e.last_code, Some(450));
        assert!(
            e.next_attempt_unix > 1000,
            "失败后必须推到未来，否则会立即重试"
        );
        assert!(!e.is_due(1000));
    }

    #[test]
    fn on_failure_reports_exhausted_at_the_configured_limit() {
        let p = policy();
        let mut e = entry("QQ02");
        for _ in 0..p.max_attempts - 1 {
            assert!(!p.on_failure(&mut e, 0, None, None));
        }
        assert!(
            p.on_failure(&mut e, 0, None, None),
            "达到最大尝试次数时必须报告耗尽（调用方据此退信）"
        );
        assert_eq!(e.attempts, p.max_attempts);
    }

    #[test]
    fn default_policy_matches_the_documented_shape() {
        let p = BackoffPolicy::default();
        assert_eq!(p.base_secs, 300);
        assert_eq!(p.max_secs, 14400);
        assert_eq!(p.max_attempts, 10);
        // 退避跨度应远小于「永远」，否则邮件会在队列里静默躺到天荒地老。
        assert!(p.nominal_delay_secs(p.max_attempts) <= p.max_secs);
    }
}

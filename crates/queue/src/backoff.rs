use crate::entry::QueueEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    pub base_secs: u64,

    pub factor: u32,

    pub max_secs: u64,

    pub max_attempts: u32,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base_secs: 300,
            factor: 2,
            max_secs: 14400,
            max_attempts: 10,
        }
    }
}

const MAX_LAST_ERROR_LEN: usize = 500;

fn sanitize_last_error(text: String) -> String {
    let cleaned = crate::dsn::sanitize_header(&text);
    cleaned.chars().take(MAX_LAST_ERROR_LEN).collect()
}

impl BackoffPolicy {
    pub fn delay_secs(&self, attempt: u32, entry_id: &str) -> u64 {
        let nominal = self.nominal_delay_secs(attempt);
        if nominal == 0 {
            return 0;
        }
        let spread = (nominal / 10).max(1);
        let hash = stable_hash(entry_id);

        let (lower, upper) = if nominal >= self.max_secs {
            (nominal.saturating_sub(spread).max(1), nominal)
        } else {
            (
                nominal.saturating_sub(spread).max(1),
                nominal.saturating_add(spread).min(self.max_secs.max(1)),
            )
        };
        let span = upper.saturating_sub(lower);
        lower.saturating_add(hash % (span + 1)).max(1)
    }

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

    pub fn exhausted(&self, attempts: u32) -> bool {
        attempts >= self.max_attempts
    }

    pub fn on_failure(
        &self,
        entry: &mut QueueEntry,
        now_unix: i64,
        last_error: Option<String>,
        last_code: Option<u16>,
    ) -> bool {
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_error = last_error.map(sanitize_last_error);
        entry.last_code = last_code;
        let exhausted = self.exhausted(entry.attempts);
        let delay = self.delay_secs(entry.attempts, &entry.id) as i64;
        entry.next_attempt_unix = now_unix.saturating_add(delay);
        exhausted
    }
}

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

        assert_eq!(p.nominal_delay_secs(20), 1000);
        assert_eq!(
            p.nominal_delay_secs(u32::MAX),
            1000,
            "极大 attempt 不得溢出"
        );
    }

    #[test]
    fn nominal_delay_is_monotonic() {
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
    fn the_backoff_cap_does_not_collapse_half_of_the_entries_onto_one_instant() {
        let p = BackoffPolicy::default();
        let attempt = p.max_attempts;
        assert_eq!(p.nominal_delay_secs(attempt), p.max_secs, "前提：已封顶");

        let delays: Vec<u64> = (0..64)
            .map(|i| p.delay_secs(attempt, &format!("{i:04X}")))
            .collect();
        let distinct: std::collections::HashSet<u64> = delays.iter().copied().collect();
        assert!(
            distinct.len() >= 60,
            "封顶处大量条目被剪到同一秒（{} / 64 个不同取值）：{delays:?}",
            distinct.len()
        );
        for delay in delays {
            assert!(
                delay <= p.max_secs,
                "抖动不得突破上限：{delay} > {}",
                p.max_secs
            );
            assert!(
                delay >= p.max_secs - p.max_secs / 10,
                "封顶处只应向下抖动（不低于 max - 10%）：{delay}"
            );
        }
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
    fn last_error_is_sanitised_and_capped() {
        let p = policy();
        let mut e = entry("QQ03");
        p.on_failure(
            &mut e,
            0,
            Some("450 busy\r\nBcc: attacker@evil\0more".to_string()),
            Some(450),
        );
        let stored = e.last_error.as_deref().unwrap_or_default();
        assert!(
            !stored.contains(['\r', '\n', '\0']),
            "控制字符必须被净化：{stored:?}"
        );
        assert!(
            stored.contains("Bcc: attacker@evil"),
            "可读文本应保留（行内）"
        );

        let mut e2 = entry("QQ04");
        p.on_failure(&mut e2, 0, Some("x".repeat(10_000)), None);
        assert_eq!(
            e2.last_error.as_deref().map(str::len),
            Some(MAX_LAST_ERROR_LEN),
            "失败描述必须被截断，不得把条目撑大"
        );
    }

    #[test]
    fn default_policy_matches_the_documented_shape() {
        let p = BackoffPolicy::default();
        assert_eq!(p.base_secs, 300);
        assert_eq!(p.max_secs, 14400);
        assert_eq!(p.max_attempts, 10);

        assert!(p.nominal_delay_secs(p.max_attempts) <= p.max_secs);
    }
}

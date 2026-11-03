//! 连接限速：每 IP 令牌桶（替代 fail2ban 的「限速」那一半）。
//!
//! ## 为什么是令牌桶而不是「固定窗口计数」
//!
//! 固定窗口有两个老问题：窗口边界处的双倍突发，以及「窗口一开始就用光额度 ⇒
//! 合法用户被连坐」。令牌桶给出的是**平滑速率 + 有界突发**：平时攒下的额度允许
//! 短时突发（真实客户端重试不会挨打），而长期速率被 `refill_per_second` 钉死。
//!
//! ## 内存必须有界
//!
//! 限速表本身就是一个攻击面：攻击者用大量源地址各连一次，就能让表无限增长。
//! 因此 [`RateLimiter`] 带 `max_entries`，超限时先淘汰「已攒满额度的空闲条目」，
//! 实在不够再淘汰最久未活跃的条目。**绝不**因为表满就放行 —— 那会把限速变成
//! 攻击者可以主动触发失效的东西。
//!
//! 时钟由调用方以毫秒注入（`now_millis`），因此所有行为都可在测试里穷举。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::peer::PeerKey;

/// 令牌桶参数。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitConfig {
    /// 桶容量 = 允许的瞬时突发连接数。
    pub burst: u32,
    /// 每秒补充的令牌数 = 长期允许的连接速率。
    pub refill_per_second: f64,
    /// 表的最大条目数（内存上限）。
    pub max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // 30 次突发、每秒 1 次持续：真实 MTA 的合法重试远低于此，
            // 而扫描器 / 暴力尝试会立刻撞上上限。
            burst: 30,
            refill_per_second: 1.0,
            max_entries: 10_000,
        }
    }
}

/// 一次连接准入判定的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// 放行，并已消耗一个令牌。
    Allowed,
    /// 超速：建议对端在 `retry_after_secs` 秒后重试。
    Limited { retry_after_secs: u64 },
}

impl RateDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateDecision::Allowed)
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_millis: i64,
}

/// 每 IP 令牌桶限速器。
///
/// 键是 [`PeerKey`]：IPv4 /32、IPv6 **/64**。同一个 /64 共享一个令牌桶 ——
/// 否则拥有整段 /64 的攻击者每次连接换地址就能永远待在新桶的满额突发里，
/// 限速对 IPv6 扫描等于不存在（R3-007）。
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<PeerKey, Bucket>>,
}

impl RateLimiter {
    /// 构造限速器；参数被夹到合法范围（`burst ≥ 1`、`refill > 0`、`max_entries ≥ 1`），
    /// 避免出现「零容量」这种把所有人挡在外面的配置错误。
    pub fn new(config: RateLimitConfig) -> Self {
        let config = RateLimitConfig {
            burst: config.burst.max(1),
            refill_per_second: if config.refill_per_second > 0.0 {
                config.refill_per_second
            } else {
                1.0
            },
            max_entries: config.max_entries.max(1),
        };
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> RateLimitConfig {
        self.config
    }

    /// 当前跟踪的 IP 数量（测试内存上界用）。
    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    /// 判定一次连接是否放行。
    pub fn check(&self, ip: IpAddr, now_millis: i64) -> RateDecision {
        let key = PeerKey::from_ip(ip);
        let mut buckets = self.lock();
        let capacity = self.config.burst as f64;

        if let Some(bucket) = buckets.get_mut(&key) {
            refill(bucket, capacity, self.config.refill_per_second, now_millis);
            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return RateDecision::Allowed;
            }
            return RateDecision::Limited {
                retry_after_secs: retry_after(bucket.tokens, self.config.refill_per_second),
            };
        }

        // 新 IP：先建桶（满额），再消耗一个。
        if buckets.len() >= self.config.max_entries {
            evict(
                &mut buckets,
                capacity,
                self.config.refill_per_second,
                now_millis,
                self.config.max_entries,
            );
        }
        let mut bucket = Bucket {
            tokens: capacity,
            last_millis: now_millis,
        };
        refill(
            &mut bucket,
            capacity,
            self.config.refill_per_second,
            now_millis,
        );
        bucket.tokens -= 1.0;
        buckets.insert(key, bucket);
        RateDecision::Allowed
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PeerKey, Bucket>> {
        match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// 按经过的时间补充令牌；时间倒流（NTP 回拨）时不补充，也不把 `last_millis` 往回挪。
fn refill(bucket: &mut Bucket, capacity: f64, rate: f64, now_millis: i64) {
    let elapsed = now_millis.saturating_sub(bucket.last_millis);
    if elapsed > 0 {
        bucket.tokens = (bucket.tokens + elapsed as f64 / 1000.0 * rate).min(capacity);
        bucket.last_millis = now_millis;
    }
}

fn retry_after(tokens: f64, rate: f64) -> u64 {
    let missing = (1.0 - tokens).max(0.0);
    (missing / rate).ceil().max(1.0) as u64
}

/// 内存上限保护：先淘汰已攒满额度的空闲条目，仍超限则淘汰最久未活跃者。
///
/// 调用前提是 `buckets.len() >= max_entries`，因此本函数**保证**至少腾出一个位置，
/// 否则新 IP 的插入会让表持续增长 —— 那正是限速表自身被撑爆的路径。
fn evict(
    buckets: &mut HashMap<PeerKey, Bucket>,
    capacity: f64,
    rate: f64,
    now_millis: i64,
    max_entries: usize,
) {
    // 1) 先遗忘「已攒满额度」的空闲条目：攒满意味着很久没有活动。
    buckets.retain(|_, bucket| {
        let elapsed = now_millis.saturating_sub(bucket.last_millis);
        let projected = (bucket.tokens + elapsed as f64 / 1000.0 * rate).min(capacity);
        projected < capacity
    });

    if buckets.len() < max_entries {
        return;
    }

    // 2) 仍然过多：按最后活跃时间淘汰最旧者，腾出至少 1 个位置。
    let mut ages: Vec<(PeerKey, i64)> = buckets
        .iter()
        .map(|(key, bucket)| (*key, bucket.last_millis))
        .collect();
    ages.sort_by_key(|(_, last)| *last);
    let target = max_entries.saturating_sub(1);
    let remove_count = buckets.len().saturating_sub(target);
    for (victim, _) in ages.into_iter().take(remove_count) {
        buckets.remove(&victim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    fn limiter(burst: u32, rate: f64, max_entries: usize) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            burst,
            refill_per_second: rate,
            max_entries,
        })
    }

    #[test]
    fn a_burst_is_allowed_then_the_bucket_runs_dry() {
        let limiter = limiter(3, 1.0, 100);
        for _ in 0..3 {
            assert!(limiter.check(ip(1), 0).is_allowed(), "突发额度内应放行");
        }
        let decision = limiter.check(ip(1), 0);
        assert!(
            matches!(decision, RateDecision::Limited { .. }),
            "额度用尽后必须限速：{decision:?}"
        );
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = limiter(2, 1.0, 100);
        assert!(limiter.check(ip(1), 0).is_allowed());
        assert!(limiter.check(ip(1), 0).is_allowed());
        assert!(!limiter.check(ip(1), 0).is_allowed());

        // 1 秒后补 1 个令牌。
        assert!(
            limiter.check(ip(1), 1_000).is_allowed(),
            "经过 1 秒后应补充 1 个令牌"
        );
        assert!(!limiter.check(ip(1), 1_000).is_allowed());
    }

    #[test]
    fn retry_after_is_a_bounded_positive_duration() {
        let limiter = limiter(1, 2.0, 100);
        assert!(limiter.check(ip(1), 0).is_allowed());
        let RateDecision::Limited { retry_after_secs } = limiter.check(ip(1), 0) else {
            panic!("应限速");
        };
        // 差 1 个令牌、每秒补 2 个 → 向上取整 1 秒。
        assert_eq!(retry_after_secs, 1);
    }

    #[test]
    fn limits_are_per_ip() {
        let limiter = limiter(1, 1.0, 100);
        assert!(limiter.check(ip(1), 0).is_allowed());
        assert!(!limiter.check(ip(1), 0).is_allowed());
        // 另一个 IP 有自己的桶，不受影响。
        assert!(limiter.check(ip(2), 0).is_allowed());
    }

    /// R3-007 反例：同一 IPv6 /64 内的不同地址共享一个桶，轮换地址拿不到新配额。
    #[test]
    fn one_ipv6_slash_64_shares_a_single_bucket() {
        let limiter = limiter(2, 1.0, 100);
        let base: std::net::Ipv6Addr = "2001:db8:aa:bb::".parse().unwrap();
        let address = |index: u16| {
            let mut octets = base.octets();
            // 只改最后 2 字节：`octets[8..]` 是 8 字节，装不下 `u16::to_be_bytes()`。
            octets[14..].copy_from_slice(&index.to_be_bytes());
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        };

        assert!(limiter.check(address(1), 0).is_allowed());
        assert!(limiter.check(address(2), 0).is_allowed());
        assert!(
            !limiter.check(address(3), 0).is_allowed(),
            "同 /64 第 3 次连接必须限速（不能靠换地址拿新桶）"
        );

        // 不同 /64 仍然是独立配额。
        let other: IpAddr = "2001:db8:aa:bc::1".parse().unwrap();
        assert!(limiter.check(other, 0).is_allowed());
    }

    #[test]
    fn the_table_is_bounded_by_max_entries() {
        let limiter = limiter(5, 1.0, 8);
        // 注入远超上限的 IP；且每个都消耗到「未满」状态以免被当成空闲淘汰。
        for last in 0..64u8 {
            let _ = limiter.check(ip(last), 0);
        }
        assert!(
            limiter.tracked() <= 8 + 1,
            "限速表必须被内存上限约束，实际 {} 条",
            limiter.tracked()
        );
    }

    #[test]
    fn a_backwards_clock_does_not_grant_tokens() {
        let limiter = limiter(1, 1.0, 100);
        assert!(limiter.check(ip(1), 10_000).is_allowed());
        // 时钟回拨：不得被当成「过了很久」而白送令牌。
        assert!(
            !limiter.check(ip(1), 5_000).is_allowed(),
            "时间倒流不得补充令牌"
        );
    }

    #[test]
    fn config_is_clamped_to_usable_values() {
        let limiter = limiter(0, 0.0, 0);
        let config = limiter.config();
        assert_eq!(config.burst, 1);
        assert!(config.refill_per_second > 0.0);
        assert_eq!(config.max_entries, 1);
    }
}

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::peer::PeerKey;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitConfig {
    pub burst: u32,

    pub refill_per_second: f64,

    pub max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst: 30,
            refill_per_second: 1.0,
            max_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Allowed,

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

#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<PeerKey, Bucket>>,
}

impl RateLimiter {
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

    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

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

fn evict(
    buckets: &mut HashMap<PeerKey, Bucket>,
    capacity: f64,
    rate: f64,
    now_millis: i64,
    max_entries: usize,
) {
    buckets.retain(|_, bucket| {
        let elapsed = now_millis.saturating_sub(bucket.last_millis);
        let projected = (bucket.tokens + elapsed as f64 / 1000.0 * rate).min(capacity);
        projected < capacity
    });

    if buckets.len() < max_entries {
        return;
    }

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

        assert_eq!(retry_after_secs, 1);
    }

    #[test]
    fn limits_are_per_ip() {
        let limiter = limiter(1, 1.0, 100);
        assert!(limiter.check(ip(1), 0).is_allowed());
        assert!(!limiter.check(ip(1), 0).is_allowed());

        assert!(limiter.check(ip(2), 0).is_allowed());
    }

    #[test]
    fn one_ipv6_slash_64_shares_a_single_bucket() {
        let limiter = limiter(2, 1.0, 100);
        let base: std::net::Ipv6Addr = "2001:db8:aa:bb::".parse().unwrap();
        let address = |index: u16| {
            let mut octets = base.octets();

            octets[14..].copy_from_slice(&index.to_be_bytes());
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        };

        assert!(limiter.check(address(1), 0).is_allowed());
        assert!(limiter.check(address(2), 0).is_allowed());
        assert!(
            !limiter.check(address(3), 0).is_allowed(),
            "同 /64 第 3 次连接必须限速（不能靠换地址拿新桶）"
        );

        let other: IpAddr = "2001:db8:aa:bc::1".parse().unwrap();
        assert!(limiter.check(other, 0).is_allowed());
    }

    #[test]
    fn the_table_is_bounded_by_max_entries() {
        let limiter = limiter(5, 1.0, 8);

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

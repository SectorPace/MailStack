use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub max_per_window: u32,

    pub window_secs: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_window: 60,
            window_secs: 60,
        }
    }
}

const MAX_TRACKED_IPS: usize = 65_536;

#[derive(Debug, Clone, Copy)]
struct Window {
    start: i64,
    count: u32,
}

pub struct RateLimiter {
    config: RateLimitConfig,
    windows: Mutex<HashMap<IpAddr, Window>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr, now: i64) -> bool {
        if self.config.max_per_window == 0 {
            return false;
        }
        let mut windows = match self.windows.lock() {
            Ok(windows) => windows,

            Err(_) => return false,
        };

        if windows.len() >= MAX_TRACKED_IPS {
            windows.retain(|_, window| now.saturating_sub(window.start) < self.config.window_secs);
            if windows.len() >= MAX_TRACKED_IPS && !windows.contains_key(&ip) {
                return false;
            }
        }

        let window = windows.entry(ip).or_insert(Window {
            start: now,
            count: 0,
        });
        if now.saturating_sub(window.start) >= self.config.window_secs || now < window.start {
            window.start = now;
            window.count = 0;
        }
        if window.count >= self.config.max_per_window {
            return false;
        }
        window.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn the_window_limits_and_then_resets() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_window: 2,
            window_secs: 60,
        });
        let peer = ip("192.0.2.1");
        assert!(limiter.allow(peer, 1000));
        assert!(limiter.allow(peer, 1001));
        assert!(!limiter.allow(peer, 1002), "窗口内第三次必须被拒");
        assert!(limiter.allow(peer, 1060), "窗口结束后应恢复");
        assert!(limiter.allow(ip("192.0.2.2"), 1002), "不同 IP 独立计数");
    }

    #[test]
    fn zero_limit_denies_everything_and_clock_rollback_reopens() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_window: 0,
            window_secs: 60,
        });
        assert!(!limiter.allow(ip("192.0.2.1"), 0));

        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_window: 1,
            window_secs: 60,
        });
        assert!(limiter.allow(ip("192.0.2.1"), 100));
        assert!(!limiter.allow(ip("192.0.2.1"), 101));
        assert!(limiter.allow(ip("192.0.2.1"), 50), "时钟回拨应重开窗口");
    }
}

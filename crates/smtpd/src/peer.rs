//! 准入表的键：IPv4 按 /32、IPv6 按 **/64** 聚合（R3-007）。
//!
//! ## 为什么不能直接用 `IpAddr`
//!
//! `IpAddr` 对 IPv6 是 /128。任何拥有一个 /64 的对手（家宽、云主机默认就是一整段）
//! 只要每次连接换一个地址，令牌桶与失败计数就都是**新条目** —— 限速的 30 次突发、
//! 封禁的 8 次阈值永远攒不满，自动封禁对 IPv6 爆破基本失明；反过来，同一 /64 里
//! 的海量地址还能把 10k 条目的表填满、触发的淘汰等于重置受害者的配额。
//!
//! 聚合到 /64 之后，「同一个宿主」在准入口径上就是同一个键。IPv4 本来就是 /32，
//! 不受影响；IPv4-mapped IPv6（`::ffff:a.b.c.d`）先还原成 IPv4，避免同一个 IPv4
//! 通过两种文本形式拿到两份配额。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 准入表的键：IPv4 /32 或 IPv6 /64 前缀。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum PeerKey {
    V4(Ipv4Addr),
    /// 高 64 位（前 8 个字节）就是前缀，低 64 位一律归零。
    V6(Ipv6Addr),
}

impl PeerKey {
    pub(crate) fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => PeerKey::V4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => PeerKey::V4(v4),
                // `segments()[..4]` 是高 64 位；其余置零表示 /64 前缀。
                None => {
                    let segments = v6.segments();
                    PeerKey::V6(Ipv6Addr::new(
                        segments[0],
                        segments[1],
                        segments[2],
                        segments[3],
                        0,
                        0,
                        0,
                        0,
                    ))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_is_kept_exact() {
        let a: IpAddr = "203.0.113.9".parse().unwrap();
        let b: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(
            PeerKey::from_ip(a),
            PeerKey::V4("203.0.113.9".parse().unwrap())
        );
        assert_ne!(PeerKey::from_ip(a), PeerKey::from_ip(b), "IPv4 是 /32");
    }

    #[test]
    fn the_whole_ipv6_slash_64_shares_one_key() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(PeerKey::from_ip(a), PeerKey::from_ip(b), "同 /64 必须同键");
        assert_ne!(
            PeerKey::from_ip(a),
            PeerKey::from_ip(c),
            "不同 /64 是不同键"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_collapses_to_the_ipv4_key() {
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        let plain: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            PeerKey::from_ip(mapped),
            PeerKey::from_ip(plain),
            "同一个 IPv4 不得因文本形式不同拿到两份配额"
        );
    }
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum PeerKey {
    V4(Ipv4Addr),

    V6(Ipv6Addr),
}

impl PeerKey {
    pub(crate) fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => PeerKey::V4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => PeerKey::V4(v4),

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

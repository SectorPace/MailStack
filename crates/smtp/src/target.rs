use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::SmtpError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTarget {
    pub hostname: String,

    pub addresses: Vec<IpAddr>,

    pub pinned: SocketAddr,
}

pub fn is_private_network_address(ip: IpAddr) -> bool {
    if let IpAddr::V6(v6) = ip {
        let embedded = embedded_ipv4_candidates(v6);
        if !embedded.is_empty() {
            return embedded
                .iter()
                .all(|v4| is_private_network_address(IpAddr::V4(*v4)));
        }
        return (v6.segments()[0] & 0xfe00) == 0xfc00;
    }

    is_private(ip)
}

impl PinnedTarget {
    pub fn dial_addr(&self) -> SocketAddr {
        self.pinned
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressPolicy {
    pub allow_private: bool,
}

impl AddressPolicy {
    pub fn public_only() -> Self {
        Self {
            allow_private: false,
        }
    }

    pub fn allow_private() -> Self {
        Self {
            allow_private: true,
        }
    }

    pub fn accepts(&self, ip: IpAddr) -> bool {
        if let IpAddr::V6(v6) = ip {
            let embedded = embedded_ipv4_candidates(v6);
            if !embedded.is_empty() {
                return embedded.iter().all(|v4| self.accepts(IpAddr::V4(*v4)));
            }
        }
        if self.allow_private {
            return !is_unspecified(ip) && !ip.is_multicast();
        }

        if let IpAddr::V6(v6) = ip {
            if (v6.segments()[0] & 0xe000) != 0x2000 {
                return false;
            }
        }
        !(is_unspecified(ip)
            || ip.is_loopback()
            || ip.is_multicast()
            || is_link_local(ip)
            || is_private(ip)
            || is_special_use(ip))
    }
}

fn is_special_use(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();

            (o[0] == 0)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
                || (o[0] & 0xf0) == 0xf0
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        }

        IpAddr::V6(v6) => {
            let seg = v6.segments();

            (seg[0] == 0x2001 && seg[1] == 0x0db8)
                || (seg[0] == 0x2001 && seg[1] == 0x0000)
                || (seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0)
                || (seg[0] == 0x2001 && (seg[1] & 0xfff0) == 0x0020)
                || (seg[0] & 0xfff0) == 0x3ff0
        }
    }
}

pub fn embedded_ipv4_candidates(ip: Ipv6Addr) -> Vec<Ipv4Addr> {
    let seg = ip.segments();
    let split = |high: u16, low: u16| {
        Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8)
    };

    if seg[..5].iter().all(|s| *s == 0) && seg[5] == 0xffff {
        return vec![split(seg[6], seg[7])];
    }

    if seg[0] == 0x2002 {
        return vec![split(seg[1], seg[2])];
    }

    if seg[0] == 0x2001 && seg[1] == 0x0000 {
        return vec![split(seg[2], seg[3]), split(!seg[6], !seg[7])];
    }
    Vec::new()
}

fn is_unspecified(ip: IpAddr) -> bool {
    ip.is_unspecified()
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

pub const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub async fn resolve_pinned(
    hostname: &str,
    port: u16,
    policy: AddressPolicy,
) -> Result<PinnedTarget, SmtpError> {
    let hostname = hostname.trim().to_ascii_lowercase();
    if hostname.is_empty() {
        return Err(SmtpError::InvalidEndpoint(
            "relay host must not be empty".to_string(),
        ));
    }

    let resolved = tokio::time::timeout(
        RESOLVE_TIMEOUT,
        tokio::net::lookup_host((hostname.as_str(), port)),
    )
    .await
    .map_err(|_| {
        SmtpError::Dns(format!(
            "resolve {hostname}: timed out after {}s",
            RESOLVE_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| SmtpError::Dns(format!("resolve {hostname}: {e}")))?;
    let resolved: Vec<SocketAddr> = resolved.collect();

    let addresses: Vec<IpAddr> = resolved
        .iter()
        .map(|sa| sa.ip())
        .filter(|ip| policy.accepts(*ip))
        .collect();

    if addresses.is_empty() {
        return Err(SmtpError::NoAcceptableAddress(hostname));
    }

    Ok(PinnedTarget {
        hostname,
        pinned: SocketAddr::new(addresses[0], port),
        addresses,
    })
}

pub fn pinned_from_addresses(
    hostname: &str,
    port: u16,
    addresses: Vec<IpAddr>,
    policy: AddressPolicy,
) -> Result<PinnedTarget, SmtpError> {
    let hostname = hostname.trim().to_ascii_lowercase();
    if hostname.is_empty() {
        return Err(SmtpError::InvalidEndpoint(
            "relay host must not be empty".to_string(),
        ));
    }

    let accepted: Vec<IpAddr> = addresses
        .into_iter()
        .filter(|ip| policy.accepts(*ip))
        .collect();
    if accepted.is_empty() {
        return Err(SmtpError::NoAcceptableAddress(hostname));
    }
    Ok(PinnedTarget {
        hostname,
        pinned: SocketAddr::new(accepted[0], port),
        addresses: accepted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_only_policy_rejects_private_and_loopback() {
        let policy = AddressPolicy::public_only();
        for blocked in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "192.0.2.1",
            "203.0.113.9",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(!policy.accepts(ip(blocked)), "{blocked} 应被拒绝");
        }
    }

    #[test]
    fn public_only_policy_accepts_routable_addresses() {
        let policy = AddressPolicy::public_only();
        for allowed in ["8.8.8.8", "203.0.114.1", "2606:4700::1111"] {
            assert!(policy.accepts(ip(allowed)), "{allowed} 应被接受");
        }
    }

    #[test]
    fn an_ipv4_mapped_address_is_screened_as_the_address_it_embeds() {
        let policy = AddressPolicy::public_only();
        for rejected in [
            "::ffff:127.0.0.1",
            "::ffff:192.168.1.5",
            "::ffff:100.64.0.1",
            "::ffff:0.0.0.0",
            "::ffff:169.254.169.254",
        ] {
            assert!(!policy.accepts(ip(rejected)), "{rejected} 必须被拒绝");
        }
        assert!(
            policy.accepts(ip("::ffff:8.8.8.8")),
            "映射后的公网地址仍应被接受"
        );
    }

    #[test]
    fn six_to_four_and_teredo_addresses_are_screened_through_their_embedded_ipv4() {
        let policy = AddressPolicy::public_only();

        assert!(
            !policy.accepts(ip("2002:7f00:0001::")),
            "6to4 内嵌 loopback"
        );

        assert!(
            !policy.accepts(ip("2001:0000:4136:e378:8000:63bf:f5ff:fffe")),
            "Teredo 的客户端地址是私网，整体必须拒绝"
        );

        assert!(policy.accepts(ip("2001:0000:4136:e378:8000:63bf:f7f7:f7f7")));

        assert!(!policy.accepts(ip("2001:0000:4136:e378:8000:63bf:ffff:fffe")));
    }

    #[test]
    fn private_policy_still_rejects_unspecified_and_multicast() {
        let policy = AddressPolicy::allow_private();
        assert!(policy.accepts(ip("127.0.0.1")));
        assert!(policy.accepts(ip("10.0.0.1")));
        assert!(!policy.accepts(ip("0.0.0.0")));
        assert!(!policy.accepts(ip("224.0.0.1")));
    }

    #[test]
    fn private_network_address_policy_excludes_loopback_link_local_and_special_ranges() {
        for allowed in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_private_network_address(ip(allowed)), "{allowed}");
        }

        for blocked in [
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:169.254.169.254",
            "2001:0000:4136:e378:8000:63bf:f5ff:fffe",
        ] {
            assert!(!is_private_network_address(ip(blocked)), "{blocked}");
        }
    }

    #[test]
    fn pinned_target_keeps_hostname_for_sni_and_ip_for_dialing() {
        let target = pinned_from_addresses(
            "relay.example.com",
            587,
            vec![ip("198.51.100.7"), ip("8.8.8.8")],
            AddressPolicy::allow_private(),
        )
        .unwrap();

        assert_eq!(target.hostname, "relay.example.com");

        assert_eq!(target.dial_addr(), "198.51.100.7:587".parse().unwrap());
        assert_eq!(target.dial_addr().ip(), ip("198.51.100.7"));
    }

    #[test]
    fn dial_addr_is_always_ip_based() {
        let target = pinned_from_addresses(
            "smtp.sendgrid.net",
            465,
            vec![ip("1.2.3.4")],
            AddressPolicy::allow_private(),
        )
        .unwrap();
        let dial = target.dial_addr();
        assert!(dial.ip().is_ipv4() || dial.ip().is_ipv6());

        assert!(!dial.to_string().contains("sendgrid"));
    }

    #[test]
    fn resolution_fails_closed_when_every_address_is_rejected() {
        let err = pinned_from_addresses(
            "internal.corp",
            587,
            vec![ip("127.0.0.1"), ip("10.1.2.3")],
            AddressPolicy::public_only(),
        )
        .unwrap_err();
        assert!(matches!(err, SmtpError::NoAcceptableAddress(_)));
    }

    #[test]
    fn rejects_empty_hostname() {
        let err =
            pinned_from_addresses("", 587, vec![ip("8.8.8.8")], AddressPolicy::allow_private());
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn resolve_pinned_handles_ip_literals() {
        let target = resolve_pinned("127.0.0.1", 25, AddressPolicy::allow_private())
            .await
            .unwrap();
        assert_eq!(target.pinned, "127.0.0.1:25".parse().unwrap());
        assert_eq!(target.hostname, "127.0.0.1");
    }

    #[tokio::test]
    async fn resolve_pinned_fails_closed_for_loopback_under_public_policy() {
        let err = resolve_pinned("127.0.0.1", 587, AddressPolicy::public_only())
            .await
            .unwrap_err();
        assert!(
            matches!(err, SmtpError::NoAcceptableAddress(_)),
            "环回地址在公网策略下必须被拒绝，实际: {err:?}"
        );
    }

    #[tokio::test]
    async fn bogus_hostname_never_yields_a_usable_target() {
        let result = resolve_pinned(
            "nonexistent.invalid.example.test",
            587,
            AddressPolicy::public_only(),
        )
        .await;

        match result {
            Err(SmtpError::Dns(_)) | Err(SmtpError::NoAcceptableAddress(_)) => {}
            Err(other) => panic!("意外的错误类型: {other:?}"),
            Ok(target) => panic!(
                "不存在的域名不得得到可用目标，实际 pinned={}",
                target.pinned
            ),
        }
    }

    #[tokio::test]
    async fn transparent_proxy_fake_ip_range_is_not_routable() {
        let policy = AddressPolicy::public_only();
        for fake in ["198.18.0.1", "198.18.255.254", "198.19.0.1"] {
            assert!(
                !policy.accepts(fake.parse().unwrap()),
                "{fake} 属于 fake-IP 段，不得视为可路由"
            );
        }

        assert!(policy.accepts("198.20.0.1".parse().unwrap()));
        assert!(policy.accepts("198.17.0.1".parse().unwrap()));
    }

    #[test]
    fn other_non_routable_ranges_are_rejected() {
        let policy = AddressPolicy::public_only();
        for blocked in ["192.0.0.1", "255.255.255.255", "240.0.0.1", "100.64.0.1"] {
            assert!(
                !policy.accepts(blocked.parse().unwrap()),
                "{blocked} 应被拒绝"
            );
        }

        assert!(policy.accepts("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn documentation_ranges_are_not_routable() {
        let policy = AddressPolicy::public_only();
        for doc in ["192.0.2.1", "198.51.100.5", "203.0.113.200"] {
            assert!(!policy.accepts(ip(doc)), "{doc} 是文档地址段，不可路由");
        }

        assert!(policy.accepts(ip("203.0.114.1")));
        assert!(policy.accepts(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))));
    }

    #[test]
    fn non_global_unicast_ipv6_is_rejected_wholesale() {
        let policy = AddressPolicy::public_only();
        for blocked in [
            "::127.0.0.1",
            "::10.0.0.1",
            "::",
            "::1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::127.0.0.1",
            "fec0::1",
            "192.88.99.1",
            "ff02::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2001:2::1",
            "2001:20::1",
            "3fff::1",
        ] {
            assert!(
                !policy.accepts(ip(blocked)),
                "{blocked} 必须被拒（它把连接导向内网/本机或根本不可路由）"
            );
        }

        for allowed in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(
                policy.accepts(ip(allowed)),
                "{allowed} 是全球单播 IPv6，必须放行"
            );
        }
    }
}

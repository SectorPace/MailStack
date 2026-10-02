//! 解析目标并**固定拨号 IP**（规格书 §5.9.3；INV-14、INV-15）。
//!
//! 攻击窗口：如果「解析用于校验、发送时按域名重连」，两次解析之间的 DNS 应答
//! 可以被调换成内网地址（DNS rebinding / TOCTOU）。IP 固定的做法是：
//!
//! 1. 先解析，得到地址列表与 `pinned`
//! 2. 建立连接时**只连 `pinned`**（不使用域名）
//! 3. TLS 握手时用**原域名**做 SNI 与证书校验
//!
//! 本模块把第 2 步做成**类型上不可绕过**：所有拨号 API 只接受 [`PinnedTarget`]，
//! 而 [`PinnedTarget::pinned`] 是 `SocketAddr`。因此不存在「按域名重连」的代码路径
//! —— 这比「记得别用域名」可靠，因为退化后代码照样能跑、测试照样绿，
//! 防护却是静默消失的。

use std::net::{IpAddr, SocketAddr};

use crate::error::SmtpError;

/// 一次解析的结果，含固定拨号地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTarget {
    /// 原域名：**仅用于** TLS SNI 与证书校验，绝不用于拨号。
    pub hostname: String,
    /// 解析得到的全部地址（已按私网策略筛选）。
    pub addresses: Vec<IpAddr>,
    /// 实际拨号目标：`addresses` 的第一项。
    pub pinned: SocketAddr,
}

impl PinnedTarget {
    /// 拨号字符串形式：`ip:port`。**故意不提供** `host:port` 形式。
    pub fn dial_addr(&self) -> SocketAddr {
        self.pinned
    }
}

/// 地址筛选策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressPolicy {
    /// 是否允许私网/环回/链路本地地址。
    pub allow_private: bool,
}

impl AddressPolicy {
    /// 默认：拒绝一切非公网地址（SSRF 防护基线）。
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

    /// 该地址是否被策略接受。
    pub fn accepts(&self, ip: IpAddr) -> bool {
        if self.allow_private {
            // 即便允许私网，也仍然拒绝「无意义/危险」的几类地址：
            // 未指定地址会连到本机、多播/广播没有意义。
            return !is_unspecified(ip) && !ip.is_multicast();
        }
        !(is_unspecified(ip)
            || ip.is_loopback()
            || ip.is_multicast()
            || is_link_local(ip)
            || is_private(ip)
            || is_special_use(ip))
    }
}

/// 非全球可路由的特殊用途地址段。
///
/// **为什么必须包含 198.18.0.0/15**：有一类透明代理（Clash/mihomo 等）用
/// **fake-IP** 模式工作 —— 任何域名都先解析成 198.18.x.x（RFC 2544 基准测试段），
/// 再由 TUN 设备接受连接并转发。后果是：
///
/// * 一个根本不存在的域名会「解析成功」，得到一个 198.18.x.x
/// * 对它的 TCP 连接也会「连接成功」（其实是 TUN 接下的）
///
/// 于是出站端口探测会**假报「端口开放」**。把该段归入不可路由即可消除这个假阳性。
/// 这类地址段在 RFC 6890 里本来就不是全球可路由的，拒绝它们不损失任何合法能力。
fn is_special_use(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 192.0.0.0/24 —— IETF 协议分配（含 192.0.0.0/29 等）
            (o[0] == 192 && o[1] == 0 && o[2] == 0)
                // 198.18.0.0/15 —— 基准测试（也是透明代理 fake-IP 的常用段）
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                // 100.64.0.0/10 —— 运营商级 NAT（RFC 6598）
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
                // 240.0.0.0/4 —— 保留段（含 255.255.255.255 广播）
                || (o[0] & 0xf0) == 0xf0
                // 文档/示例段（RFC 5737）
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        }
        // IPv6：文档段 2001:db8::/32（唯一本地地址由 is_private 覆盖）
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            seg[0] == 0x2001 && seg[1] == 0x0db8
        }
    }
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
        IpAddr::V6(v6) => {
            // fc00::/7 唯一本地地址
            (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// 解析并固定目标。
///
/// 步骤与 `_resolve_probe_targets` 一致：解析 → 地址筛选 → 取第一个作为固定拨号目标。
/// 解析结果为空或全部被策略拒绝时**失败**（fail-closed），不得回落到「按域名连」。
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

    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((hostname.as_str(), port))
        .await
        .map_err(|e| SmtpError::Dns(format!("resolve {hostname}: {e}")))?
        .collect();

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

/// 从一个**已知**地址清单构造固定目标（用于显式指定 IP 的场景与测试）。
///
/// 同样校验 hostname：空域名会让 TLS SNI 变成空串、证书校验失去依据，
/// 属于必须拒绝的输入。
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
        // INV-15：私网中继在部署策略未开启时一律拒绝。
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
    fn private_policy_still_rejects_unspecified_and_multicast() {
        // 允许私网不等于允许一切：0.0.0.0 会连到本机，多播无意义。
        let policy = AddressPolicy::allow_private();
        assert!(policy.accepts(ip("127.0.0.1")));
        assert!(policy.accepts(ip("10.0.0.1")));
        assert!(!policy.accepts(ip("0.0.0.0")));
        assert!(!policy.accepts(ip("224.0.0.1")));
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

        // 域名只用于 SNI/证书校验。
        assert_eq!(target.hostname, "relay.example.com");
        // 拨号目标是 IP，不是域名。
        assert_eq!(target.dial_addr(), "198.51.100.7:587".parse().unwrap());
        assert_eq!(target.dial_addr().ip(), ip("198.51.100.7"));
    }

    #[test]
    fn dial_addr_is_always_ip_based() {
        // 这条断言是 INV-14 的结构性保证：拨号地址永远由 IP 构成。
        let target = pinned_from_addresses(
            "smtp.sendgrid.net",
            465,
            vec![ip("1.2.3.4")],
            AddressPolicy::allow_private(),
        )
        .unwrap();
        let dial = target.dial_addr();
        assert!(dial.ip().is_ipv4() || dial.ip().is_ipv6());
        // 拨号目标不得包含任何域名信息。
        assert!(!dial.to_string().contains("sendgrid"));
    }

    #[test]
    fn resolution_fails_closed_when_every_address_is_rejected() {
        // 关键：不得因为「全被拒」而回落到按域名连接。
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
        // 显式 IP 也应走同一条路径，且仍受策略约束。
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
        // 断言的是**不变量**而不是具体错误变体：无论解析阶段是 NXDOMAIN，
        // 还是被透明代理的 fake-IP 应答成一个不可路由地址，结果都必须是失败。
        //
        // 这一点在本机尤其重要：Clash 的 fake-IP 模式会把任何域名解析成
        // 198.18.x.x，所以「解析失败」并不会以 Dns 错误的形式出现 ——
        // 但地址策略必须把它挡下来。
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
        // 198.18.0.0/15 是 RFC 2544 基准测试段，也是 Clash/mihomo fake-IP 的常用段。
        // 若不拒绝它，出站探测会把「TUN 接下的连接」误判成「端口开放」。
        let policy = AddressPolicy::public_only();
        for fake in ["198.18.0.1", "198.18.255.254", "198.19.0.1"] {
            assert!(
                !policy.accepts(fake.parse().unwrap()),
                "{fake} 属于 fake-IP 段，不得视为可路由"
            );
        }
        // 相邻但不在该段的地址不受影响。
        assert!(policy.accepts("198.20.0.1".parse().unwrap()));
        assert!(policy.accepts("198.17.0.1".parse().unwrap()));
    }

    #[test]
    fn other_non_routable_ranges_are_rejected() {
        let policy = AddressPolicy::public_only();
        for blocked in [
            "192.0.0.1",       // IETF 协议分配
            "255.255.255.255", // 保留/广播
            "240.0.0.1",       // 保留段
            "100.64.0.1",      // 运营商级 NAT
        ] {
            assert!(
                !policy.accepts(blocked.parse().unwrap()),
                "{blocked} 应被拒绝"
            );
        }
        // 100.128.0.1 已超出 /10（100.64.0.0–100.127.255.255）。
        assert!(policy.accepts("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn documentation_ranges_are_not_routable() {
        let policy = AddressPolicy::public_only();
        for doc in ["192.0.2.1", "198.51.100.5", "203.0.113.200"] {
            assert!(!policy.accepts(ip(doc)), "{doc} 是文档地址段，不可路由");
        }
        // 相邻但不属于文档段，应放行。
        assert!(policy.accepts(ip("203.0.114.1")));
        assert!(policy.accepts(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))));
    }
}

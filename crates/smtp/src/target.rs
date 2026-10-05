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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

/// 判断一个地址是否属于明确的本地私网段（RFC 1918 / IPv6 ULA）。
///
/// 该判定刻意不包含 loopback、link-local、CGNAT、文档段或其他特殊用途地址；
/// 对 IPv4-mapped、6to4 和 Teredo 地址也检查其中嵌入的 IPv4 地址。
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
        // IPv6 里可能**内嵌**着一个 IPv4（mapped / 6to4 / Teredo）。内嵌地址不被接受时
        // 整体就不接受 —— 否则 `::ffff:127.0.0.1` 会绕过下面全部 v4 规则打到本机。
        // 递归调用只可能落在 `IpAddr::V4` 分支上（V4 没有内嵌），不会无限递归。
        if let IpAddr::V6(v6) = ip {
            let embedded = embedded_ipv4_candidates(v6);
            if !embedded.is_empty() {
                return embedded.iter().all(|v4| self.accepts(IpAddr::V4(*v4)));
            }
        }
        if self.allow_private {
            // 即便允许私网，也仍然拒绝「无意义/危险」的几类地址：
            // 未指定地址会连到本机、多播/广播没有意义。
            return !is_unspecified(ip) && !ip.is_multicast();
        }
        // IPv6：全球单播**只在** `2000::/3`（RFC 4291 §2.5）。
        //
        // ## 为什么是白名单而不是继续枚举黑名单
        //
        // 原来的写法是「枚举已知的特殊段并拒绝」，那**必然漏**——漏掉的每一段
        // 都是一条绕过 SSRF 筛选的路径。已被实测漏掉的：
        //
        // * `::127.0.0.1`（IPv4-compatible，`::/96`）—— 不等于 `::1`，
        //   `is_private()` 也不命中，整段穿了过去；
        // * `64:ff9b::127.0.0.1`（NAT64，RFC 6052）与 `64:ff9b:1::`
        //   （local-use NAT64，RFC 8215）—— 在 NAT64 主机上 TCP 会被翻译成
        //   `127.0.0.1:25`；
        // * `fec0::1`（废弃的 site-local）、`192.88.99.1`（废弃的 6to4
        //   relay anycast）。
        //
        // `2000::/3` 这一个判断**一次性消灭上面整类**：它们的首段全都不在
        // `0x2000..=0x3fff` 之内。而 `2000::/3` 内部还有 IANA 特殊登记段
        // （`2001:db8::/32` 等），那些由 [`is_special_use`] 排除。
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
            // 0.0.0.0/8 —— 「本网络」（RFC 1122）。`is_unspecified` 只覆盖 0.0.0.0，
            // 但 0.0.0.1 之类同样不可路由；Teredo 拆出的内嵌 v4 会落到这一段，
            // 必须挡住，否则「连到本机/本网」这一类会绕过筛选。
            (o[0] == 0)
                // 192.0.0.0/24 —— IETF 协议分配（含 192.0.0.0/29 等）
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
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
                // 192.88.99.0/24 —— 废弃的 6to4 relay anycast（RFC 7526）
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        }
        // IPv6：**只判 `2000::/3` 内部**的 IANA 特殊登记段。
        //
        // 为什么不管范围外的：`::1` / `::/96`（IPv4-compatible）/ `64:ff9b::/96`
        // （NAT64）/ `fc00::/7` / `fe80::/10` 这些段已经由 `accepts` 里的
        // `2000::/3` 白名单拒掉了，在这里重复判定只会让两处逻辑各说一半。
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // 2001:db8::/32 —— 文档（RFC 3849）
            (seg[0] == 0x2001 && seg[1] == 0x0db8)
                // 2001::/32 —— IETF 协议分配（Teredo 的内嵌 v4 由另一处单独判定）
                || (seg[0] == 0x2001 && seg[1] == 0x0000)
                // 2001:2::/48 —— 基准测试（RFC 5180）
                || (seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0)
                // 2001:20::/28 —— ORCHIDv2（RFC 7343）
                || (seg[0] == 0x2001 && (seg[1] & 0xfff0) == 0x0020)
                // 3fff::/20 —— 文档（RFC 9637）
                || (seg[0] & 0xfff0) == 0x3ff0
        }
    }
}

/// 拆出 IPv6 里**内嵌的 IPv4**（IPv4-mapped / 6to4 / Teredo）。
///
/// **为什么必须拆**：这些形式里嵌着一个 IPv4 地址，而 IPv6 的属性判定**看不见它**。
/// `::ffff:127.0.0.1` 既不等于 `::1`（v6 的 loopback），`is_private()` 也是 false，
/// 于是它会一路穿过全部 v4 规则、被当成「公网地址」接受 —— 而对它发起连接，
/// 打的就是**本机**。基线在 `ai.py::is_ip_restricted` 里明确写了这件事（逐个尝试
/// `ipv4_mapped` / `sixtofour` / `teredo` 并拆出内嵌地址），Rust 侧此前漏掉了这一步。
///
/// 返回**全部**内嵌候选：Teredo 有**两个**（隧道的服务端与客户端），调用方必须让
/// 每一个都通过筛选。基线在 Teredo 上其实是崩的 —— 它把 Python 返回的二元组直接
/// 赋给 `ip` 再调 `ip.is_private`，会抛 `AttributeError`；这里按 RFC 4380 的编码
/// 正确取出两个地址，属于对基线的**修正**而非照抄。
pub fn embedded_ipv4_candidates(ip: Ipv6Addr) -> Vec<Ipv4Addr> {
    let seg = ip.segments();
    let split = |high: u16, low: u16| {
        Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8)
    };

    // ::ffff:0:0/96 —— IPv4-mapped
    if seg[..5].iter().all(|s| *s == 0) && seg[5] == 0xffff {
        return vec![split(seg[6], seg[7])];
    }
    // 2002::/16 —— 6to4：紧随其后的 32 位就是内嵌的 v4
    if seg[0] == 0x2002 {
        return vec![split(seg[1], seg[2])];
    }
    // 2001:0000::/32 —— Teredo：`seg[2..4]` 是服务端 v4，末 32 位**取反**后是客户端 v4
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
        IpAddr::V6(v6) => {
            // fc00::/7 唯一本地地址
            (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// DNS 解析超时。
///
/// ## 为什么这条路径必须有超时
///
/// 这一步是 **IP 固定拨号的前置条件**，也是全仓最不该卡住的一条路径：
/// 连接超时了、解析却没超时，于是投递任务会一直挂着占住 worker。
///
/// 更糟的是 `tokio::net::lookup_host` 在**阻塞**线程池里做 `getaddrinfo`：
/// 解析慢时占的是 tokio 的 blocking 槽位，高并发下会把整个 worker 池吃干，
/// 连带收信与出站一起卡住。
///
/// 5 秒是「一次投递总共允许多久」的量级：DNS 解析本来就该在毫秒级完成，
/// 超过 5 秒基本可以断定是网络故障或配置错误。
pub const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// 解析并固定目标。
///
/// 步骤与 `_resolve_probe_targets` 一致：解析 → 地址筛选 → 取第一个作为固定拨号目标。
/// 解析结果为空或全部被策略拒绝时**失败**（fail-closed），不得回落到「按域名连」。
///
/// 超时按**可重试失败**返回（[`SmtpError::Dns`]），不是退信信号：DNS 故障是
/// 基础设施问题，等一会儿重试通常就好了。
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
    fn an_ipv4_mapped_address_is_screened_as_the_address_it_embeds() {
        // `::ffff:127.0.0.1` 既不等于 `::1`（v6 loopback），`is_private()` 也是 false；
        // 不拆内嵌 v4 的话它会穿过全部 v4 规则、被当成公网地址接受 —— 连接打的是本机。
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
        // 2002:7f00:0001:: 内嵌 127.0.0.1
        assert!(
            !policy.accepts(ip("2002:7f00:0001::")),
            "6to4 内嵌 loopback"
        );
        // Teredo：服务端 65.54.227.120（公网），客户端 (末 32 位取反) = 10.0.0.1（私网）
        assert!(
            !policy.accepts(ip("2001:0000:4136:e378:8000:63bf:f5ff:fffe")),
            "Teredo 的客户端地址是私网，整体必须拒绝"
        );
        // 两个内嵌地址都是公网时不受影响：服务端 65.54.227.120、客户端 8.8.8.8
        assert!(policy.accepts(ip("2001:0000:4136:e378:8000:63bf:f7f7:f7f7")));
        // Teredo 客户端解出来是 unspecified（0.0.0.1）时仍要拒 —— 那是「连到本机」那一类
        assert!(!policy.accepts(ip("2001:0000:4136:e378:8000:63bf:ffff:fffe")));
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

    /// 反例守卫：IPv4-compatible / NAT64 / 废弃段**一律**拒收。
    ///
    /// ## 为什么原测试漏了它
    ///
    /// 原来的 IPv6 判定是「`seg[0]==0x2001 && seg[1]==0x0db8` 才拒」，
    /// 也就是**只**拒文档段，其余全放。实测下列地址**全部穿过**了
    /// `public_only()` —— 且它们各自都能把连接导向内网或本机：
    ///
    /// * `::127.0.0.1` —— IPv4-compatible（`::/96`）。`is_loopback()` 只认 `::1`，
    ///   `is_private()` 只认 `fc00::/7`，两者都不命中；而内核会按 v4 兼容处理，
    ///   实际连的是本机。
    /// * `64:ff9b::127.0.0.1` / `64:ff9b:1::127.0.0.1` —— NAT64（RFC 6052 /
    ///   RFC 8215）。在 NAT64 主机上 TCP 会被翻译成 `127.0.0.1:25`。
    /// * `fec0::1` —— 废弃的 site-local。
    ///
    /// 修法是反转成 `2000::/3` 白名单。这条测试钉住「白名单确实生效」，
    /// 而不只是「某几个黑名单项还在」。
    #[test]
    fn non_global_unicast_ipv6_is_rejected_wholesale() {
        let policy = AddressPolicy::public_only();
        for blocked in [
            "::127.0.0.1",          // IPv4-compatible（RFC 4291 §2.5.5.1）
            "::10.0.0.1",           // 同上，指向私网
            "::",                   // 未指定
            "::1",                  // loopback
            "64:ff9b::127.0.0.1",   // NAT64（RFC 6052）
            "64:ff9b:1::127.0.0.1", // local-use NAT64（RFC 8215）
            "fec0::1",              // 废弃的 site-local
            "192.88.99.1",          // 废弃的 6to4 relay anycast（RFC 7526）
            "ff02::1",              // 多播
            "fe80::1",              // link-local
            "fc00::1",              // 唯一本地
            "2001:db8::1",          // 文档
            "2001:2::1",            // 基准测试
            "2001:20::1",           // ORCHIDv2
            "3fff::1",              // 文档（RFC 9637）
        ] {
            assert!(
                !policy.accepts(ip(blocked)),
                "{blocked} 必须被拒（它把连接导向内网/本机或根本不可路由）"
            );
        }
        // 反例的**反例**：真正的全球单播必须放行，否则整个 IPv6 投递全废。
        for allowed in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(
                policy.accepts(ip(allowed)),
                "{allowed} 是全球单播 IPv6，必须放行"
            );
        }
    }
}

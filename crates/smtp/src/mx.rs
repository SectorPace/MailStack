//! MX 解析与**直投目标选择**（RFC 5321 §5.1、RFC 7505；INV-14 的直投侧）。
//!
//! ## 直投与中继是两条**不能互相兜底**的路径
//!
//! 有中继配置时，路由一律是 `ViaRelay`（INV-18）；只有**没有**中继配置时才轮到直投
//! （`OutboundRoute::Direct`）。因此本模块只被「本机自己当 MTA」这一种情形用到：
//! 逐域查 MX → 按优先级拨号 25 端口。直投失败就是失败，**不得**回头改用中继 ——
//! 那会绕过 relay、破坏 SPF 对齐，并把邮件直接打到已确认被封的 25 端口（§5.10.10）。
//!
//! ## 三条容易写错的语义
//!
//! 1. **没有 MX ≠ 投不出去**：RFC 5321 §5.1 规定此时退化为「把域本身当 MX」，
//!    也就是查它的 A/AAAA。把「无记录」当成永久失败会拒掉一大批只配 A 记录的域。
//! 2. **`MX 0 .` 是明确拒绝**（RFC 7505 null MX）：该域**声明**不接收任何邮件，
//!    重试没有任何意义 —— 必须判为**永久**失败并立刻退信。
//! 3. **优先级只决定尝试顺序**：同优先级的多台机器不是「任选一台」，而是按顺序
//!    尝试、前面的不可用就换下一台。刻意用「按 (preference, host) 稳定排序」而不是
//!    随机 —— 随机化只影响负载分摊，却让行为不可复现、测试只能靠概率，得不偿失。
//!
//! ## 解析与决策是分开的
//!
//! [`MxResolver`] 只负责「把域名换成记录」，[`classify_mx`] 是**纯函数**。于是排序、
//! null MX、隐式回退这些真正容易出错的规则可以在无网络环境下穷举验证（与
//! `target.rs` 把地址策略做成纯函数是同一个理由）。

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use hickory_resolver::proto::rr::{RData, Record, RecordType};
use hickory_resolver::TokioResolver;

use crate::error::{SmtpError, SmtpResult};
use crate::target::{resolve_pinned, AddressPolicy, PinnedTarget};

/// 直投端口。RFC 5321 §5.1：投递给 MX 一律用 25 端口（提交口不用于 MTA 之间）。
pub const DIRECT_DELIVERY_PORT: u16 = 25;

/// 单个收件域参与尝试的 MX 台数上限。
///
/// 真实的域不会有 10 台 MX；而 MX 记录是对端可控的输入 —— 一个恶意域可以用
/// 几十条 MX 记录把一次投递放大成几十次「解析 + 策略筛选 + 建连」，长时间占用
/// 投递 worker。超出上限的候选被**截断**（不是错误）：上限只收窄尝试范围，
/// 前 10 台全部不可用与第 11 台起全部不可用没有本质区别。
pub const MAX_MX_CANDIDATES: usize = 10;

/// 一条 MX 记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    /// 优先级，越小越先尝试。
    pub preference: u16,
    /// 目标主机名（已小写、已去尾点；空串表示 RFC 7505 的根目标）。
    pub host: String,
}

/// MX 解析结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MxTargets {
    /// 有明确记录：已按优先级升序（同级内按主机名稳定排序）并去重。
    Hosts(Vec<MxRecord>),
    /// 没有 MX 记录 → 按 RFC 5321 §5.1 退化为该域本身。
    Implicit(String),
    /// RFC 7505 null MX：该域明确声明不接收邮件。
    Null(String),
}

/// 把「域名 + MX 记录」折算成投递目标选择（纯函数）。
pub fn classify_mx(domain: &str, records: Vec<MxRecord>) -> MxTargets {
    let domain = normalise_domain(domain);

    // 同一个主机名出现多次时取**最小的** preference（更优的那条），否则会出现
    // 「同一台机器既排第一又排最后」这种自相矛盾的顺序。
    let mut by_host: BTreeMap<String, u16> = BTreeMap::new();
    for record in records {
        let host = normalise_host(&record.host);
        if host.is_empty() {
            // 根/空目标 = null MX。只要出现一条就足够声明「本域不收信」。
            return MxTargets::Null(domain);
        }
        by_host
            .entry(host)
            .and_modify(|existing| *existing = (*existing).min(record.preference))
            .or_insert(record.preference);
    }

    if by_host.is_empty() {
        return MxTargets::Implicit(domain);
    }

    let mut hosts: Vec<MxRecord> = by_host
        .into_iter()
        .map(|(host, preference)| MxRecord { preference, host })
        .collect();
    hosts.sort_by(|a, b| {
        a.preference
            .cmp(&b.preference)
            .then_with(|| a.host.cmp(&b.host))
    });
    MxTargets::Hosts(hosts)
}

fn normalise_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalise_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    // 「.」与空串都表示根目标。
    if host == "." {
        String::new()
    } else {
        host
    }
}

/// MX 查询的异步结果。
pub type MxFuture<'a> = Pin<Box<dyn Future<Output = SmtpResult<Vec<MxRecord>>> + Send + 'a>>;

/// MX 查询后端。
///
/// 做成可注入的，是为了让「优先级顺序、隐式回退、null MX、多台机器逐个失败」这些
/// 规则可以在不碰真实 DNS 的前提下被穷举验证；真实实现见 [`HickoryMxResolver`]。
pub trait MxResolver: Send + Sync {
    /// 查询该域的 MX 记录。**没有记录不是错误** —— 返回空向量，由调用方按 §5.1 处理。
    fn lookup_mx(&self, domain: &str) -> MxFuture<'_>;
}

/// 基于系统 DNS 配置（`/etc/resolv.conf`）的实现。
pub struct HickoryMxResolver {
    resolver: TokioResolver,
}

impl HickoryMxResolver {
    pub fn from_system() -> SmtpResult<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|error| SmtpError::Dns(format!("cannot load DNS configuration: {error}")))?
            .build()
            .map_err(|error| SmtpError::Dns(format!("cannot build the DNS resolver: {error}")))?;
        Ok(Self { resolver })
    }
}

impl MxResolver for HickoryMxResolver {
    fn lookup_mx(&self, domain: &str) -> MxFuture<'_> {
        let domain = normalise_domain(domain);
        Box::pin(async move {
            match self.resolver.lookup(domain.as_str(), RecordType::MX).await {
                Ok(lookup) => Ok(lookup.answers().iter().filter_map(mx_from_record).collect()),
                // 「没有这条记录」与「域名不存在」都不是解析故障：前者要按 §5.1 退化为
                // 域本身，后者会在随后的 A/AAAA 查询里如实失败。
                Err(error) if error.is_no_records_found() || error.is_nx_domain() => Ok(Vec::new()),
                Err(error) => Err(SmtpError::Dns(format!(
                    "MX lookup for {domain} failed: {error}"
                ))),
            }
        })
    }
}

fn mx_from_record(record: &Record) -> Option<MxRecord> {
    // `RData::MX` 的载荷是 `#[non_exhaustive]`，必须按引用取字段而不是解构。
    let RData::MX(mx) = &record.data else {
        return None;
    };
    Some(MxRecord {
        preference: mx.preference,
        // 根目标（`.`）按 RFC 7505 处理成空主机名，由 `classify_mx` 判为 null MX。
        host: if mx.exchange.is_root() {
            String::new()
        } else {
            mx.exchange.to_utf8().to_string()
        },
    })
}

/// 把一个收件域解析成**按优先级排序**的直投目标。
///
/// 单台 MX 解析失败（DNS 抖动、地址全被策略拒绝）**不影响**其余的：依次尝试下一台。
/// 只有全部不可用时才失败 —— 而失败**不会**改用中继。
///
/// 每台目标都经 [`resolve_pinned`]：解析 → 地址策略筛选 → 固定 IP 拨号、原主机名做
/// SNI（INV-14、INV-15 的直投侧落点）。
pub async fn resolve_mx_targets(
    resolver: &dyn MxResolver,
    domain: &str,
    port: u16,
    policy: AddressPolicy,
) -> SmtpResult<Vec<PinnedTarget>> {
    let records = resolver.lookup_mx(domain).await?;

    let mut candidates: Vec<String> = match classify_mx(domain, records) {
        MxTargets::Null(domain) => return Err(SmtpError::NullMx(domain)),
        MxTargets::Implicit(domain) => vec![domain],
        MxTargets::Hosts(hosts) => hosts.into_iter().map(|record| record.host).collect(),
    };
    // 截断放在逐台解析**之前**：否则上限只省掉后面的建连，几十次 DNS 查询照样发生。
    candidates.truncate(MAX_MX_CANDIDATES);

    let mut targets = Vec::with_capacity(candidates.len());
    let mut last_error: Option<SmtpError> = None;
    for host in candidates {
        match resolve_pinned(&host, port, policy).await {
            Ok(target) => targets.push(target),
            Err(error) => last_error = Some(error),
        }
    }

    if targets.is_empty() {
        // 有候选却一台都不可用：如实报出最后一次错误（DNS 故障 → 可重试；
        // 地址全被策略拒绝 → 永久）。**不回落**到中继。
        return Err(last_error
            .unwrap_or_else(|| SmtpError::Dns(format!("no usable MX target for {domain}"))));
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn record(preference: u16, host: &str) -> MxRecord {
        MxRecord {
            preference,
            host: host.to_string(),
        }
    }

    #[test]
    fn records_are_ordered_by_preference_not_left_in_answer_order() {
        let targets = classify_mx(
            "example.com",
            vec![
                record(30, "mx3.example.com"),
                record(10, "mx1.example.com"),
                record(20, "mx2.example.com"),
            ],
        );
        let MxTargets::Hosts(hosts) = targets else {
            panic!("应解析为主机列表：{targets:?}");
        };
        assert_eq!(
            hosts.iter().map(|h| h.host.as_str()).collect::<Vec<_>>(),
            vec!["mx1.example.com", "mx2.example.com", "mx3.example.com"],
            "必须按 preference 升序，而不是 DNS 应答里碰巧的顺序"
        );
    }

    #[test]
    fn equal_preferences_are_ordered_deterministically() {
        // 同优先级用主机名做稳定的次序（而不是随机）。随机只影响负载分摊，
        // 却会让顺序不可复现 —— 那样「先试哪台」就只能靠概率去测。
        let targets = classify_mx(
            "example.com",
            vec![
                record(10, "mx-b.example.com"),
                record(10, "mx-a.example.com"),
            ],
        );
        let MxTargets::Hosts(hosts) = targets else {
            panic!("应解析为主机列表");
        };
        assert_eq!(hosts[0].host, "mx-a.example.com");
        assert_eq!(hosts[1].host, "mx-b.example.com");
    }

    #[test]
    fn a_duplicate_host_keeps_the_better_preference() {
        // 同一台机器出现两次：取更优的那条，否则顺序里会出现自相矛盾的优先级。
        let targets = classify_mx(
            "example.com",
            vec![record(50, "mx1.example.com"), record(5, "mx1.example.com")],
        );
        let MxTargets::Hosts(hosts) = targets else {
            panic!("应解析为主机列表");
        };
        assert_eq!(hosts.len(), 1, "同一主机名只保留一条");
        assert_eq!(hosts[0].preference, 5);
    }

    #[test]
    fn a_null_mx_is_an_explicit_refusal_not_an_implicit_fallback() {
        // RFC 7505：`MX 0 .` 表示「本域不接收邮件」。若按「空主机名 → 无记录 →
        // 退化为域本身」处理，就会反过来往一个明确拒收的域投递。
        for host in [".", "", "   "] {
            let targets = classify_mx("example.com", vec![record(0, host)]);
            assert_eq!(
                targets,
                MxTargets::Null("example.com".to_string()),
                "空/根目标必须判为 null MX（输入 {host:?}）"
            );
        }
    }

    #[test]
    fn a_null_mx_alongside_other_records_still_refuses() {
        // 非法的混合形态（null 与普通记录同时存在）也要按「本域不收信」处理：
        // 宁可拒收，也不能因为存在别的记录就忽略这条明确的拒绝声明。
        let targets = classify_mx(
            "example.com",
            vec![record(10, "mx1.example.com"), record(0, ".")],
        );
        assert_eq!(targets, MxTargets::Null("example.com".to_string()));
    }

    #[test]
    fn no_records_falls_back_to_the_domain_itself() {
        // RFC 5321 §5.1：没有 MX 记录不是投不出去，而是把域本身当作 MX。
        assert_eq!(
            classify_mx("example.com", Vec::new()),
            MxTargets::Implicit("example.com".to_string())
        );
    }

    #[test]
    fn hosts_are_normalised_and_the_domain_is_lowercased() {
        let targets = classify_mx("Example.COM.", vec![record(10, "  MX1.Example.com.  ")]);
        let MxTargets::Hosts(hosts) = targets else {
            panic!("应解析为主机列表");
        };
        assert_eq!(hosts[0].host, "mx1.example.com", "尾点与大小写都要归一化");
    }

    // ── 目标解析：注入的解析器 + 注入的地址策略 ──

    struct StaticMxResolver {
        records: Vec<MxRecord>,
        error: Option<String>,
    }

    impl StaticMxResolver {
        fn with(records: Vec<MxRecord>) -> Self {
            Self {
                records,
                error: None,
            }
        }

        fn failing(message: &str) -> Self {
            Self {
                records: Vec::new(),
                error: Some(message.to_string()),
            }
        }
    }

    impl MxResolver for StaticMxResolver {
        fn lookup_mx(&self, _domain: &str) -> MxFuture<'_> {
            Box::pin(async move {
                match &self.error {
                    Some(message) => Err(SmtpError::Dns(message.clone())),
                    None => Ok(self.records.clone()),
                }
            })
        }
    }

    #[tokio::test]
    async fn a_null_mx_is_permanent_and_reported_as_such() {
        let resolver = StaticMxResolver::with(vec![record(0, ".")]);
        let error = resolve_mx_targets(
            &resolver,
            "example.com",
            DIRECT_DELIVERY_PORT,
            AddressPolicy::allow_private(),
        )
        .await
        .expect_err("null MX 不得产出投递目标");
        assert!(matches!(error, SmtpError::NullMx(_)), "实际：{error:?}");
        assert_eq!(error.kind(), "NullMx");
    }

    #[tokio::test]
    async fn an_unroutable_mx_is_rejected_by_the_address_policy() {
        // INV-15 的直投侧：MX 指向私网/环回时，公网策略必须把它挡下来 ——
        // 否则收件域可以拿 MX 记录把本机变成内网扫描器。
        let resolver = StaticMxResolver::with(vec![record(10, "127.0.0.1")]);
        let error = resolve_mx_targets(
            &resolver,
            "example.com",
            DIRECT_DELIVERY_PORT,
            AddressPolicy::public_only(),
        )
        .await
        .expect_err("环回 MX 必须被拒绝");
        assert!(
            matches!(error, SmtpError::NoAcceptableAddress(_)),
            "实际：{error:?}"
        );
    }

    #[tokio::test]
    async fn one_unusable_mx_does_not_hide_the_next_one() {
        // 第一台解析失败（这里是地址被策略拒绝）不该让整封邮件失败 —— 换下一台。
        let resolver =
            StaticMxResolver::with(vec![record(10, "127.0.0.1"), record(20, "203.0.114.9")]);
        let targets = resolve_mx_targets(
            &resolver,
            "example.com",
            DIRECT_DELIVERY_PORT,
            AddressPolicy::public_only(),
        )
        .await
        .expect("应至少产出一台可用目标");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].hostname, "203.0.114.9");
        assert_eq!(
            targets[0].dial_addr().ip(),
            "203.0.114.9".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn mx_candidates_are_capped_at_ten() {
        // MX 记录是对端可控的输入：恶意域可以用海量记录把一次投递放大成几十次
        // 「解析 + 筛选 + 建连」。15 台候选必须被截断到 [`MAX_MX_CANDIDATES`]，
        // 且保留的是按优先级排在前面的那些。
        let records: Vec<MxRecord> = (1u16..=15)
            .map(|i| record(i, &format!("203.0.113.{i}")))
            .collect();
        let resolver = StaticMxResolver::with(records);
        let targets = resolve_mx_targets(
            &resolver,
            "example.com",
            DIRECT_DELIVERY_PORT,
            AddressPolicy::allow_private(),
        )
        .await
        .expect("候选主机都是 IP 字面量，应全部可用");
        assert_eq!(targets.len(), MAX_MX_CANDIDATES, "必须截断到上限");
        assert_eq!(targets[0].hostname, "203.0.113.1");
        assert_eq!(targets[9].hostname, "203.0.113.10");
    }

    #[tokio::test]
    async fn a_resolver_failure_is_surfaced_as_a_dns_error() {
        let resolver = StaticMxResolver::failing("resolver unreachable");
        let error = resolve_mx_targets(
            &resolver,
            "example.com",
            DIRECT_DELIVERY_PORT,
            AddressPolicy::allow_private(),
        )
        .await
        .expect_err("解析器失败必须上报");
        assert!(matches!(error, SmtpError::Dns(_)), "实际：{error:?}");
    }
}

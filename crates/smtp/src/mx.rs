use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use hickory_resolver::proto::rr::{RData, Record, RecordType};
use hickory_resolver::TokioResolver;

use crate::error::{SmtpError, SmtpResult};
use crate::target::{resolve_pinned, AddressPolicy, PinnedTarget};

pub const DIRECT_DELIVERY_PORT: u16 = 25;

pub const MAX_MX_CANDIDATES: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,

    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MxTargets {
    Hosts(Vec<MxRecord>),

    Implicit(String),

    Null(String),
}

pub fn classify_mx(domain: &str, records: Vec<MxRecord>) -> MxTargets {
    let domain = normalise_domain(domain);

    let mut by_host: BTreeMap<String, u16> = BTreeMap::new();
    for record in records {
        let host = normalise_host(&record.host);
        if host.is_empty() {
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

    if host == "." {
        String::new()
    } else {
        host
    }
}

pub type MxFuture<'a> = Pin<Box<dyn Future<Output = SmtpResult<Vec<MxRecord>>> + Send + 'a>>;

pub trait MxResolver: Send + Sync {
    fn lookup_mx(&self, domain: &str) -> MxFuture<'_>;
}

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

                Err(error) if error.is_no_records_found() || error.is_nx_domain() => Ok(Vec::new()),
                Err(error) => Err(SmtpError::Dns(format!(
                    "MX lookup for {domain} failed: {error}"
                ))),
            }
        })
    }
}

fn mx_from_record(record: &Record) -> Option<MxRecord> {
    let RData::MX(mx) = &record.data else {
        return None;
    };
    Some(MxRecord {
        preference: mx.preference,

        host: if mx.exchange.is_root() {
            String::new()
        } else {
            mx.exchange.to_utf8().to_string()
        },
    })
}

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
        let targets = classify_mx(
            "example.com",
            vec![record(10, "mx1.example.com"), record(0, ".")],
        );
        assert_eq!(targets, MxTargets::Null("example.com".to_string()));
    }

    #[test]
    fn no_records_falls_back_to_the_domain_itself() {
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

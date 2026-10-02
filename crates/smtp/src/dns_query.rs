//! 权威 DNS 查询（`setup.dns.verify` 用）：A / MX / TXT。
//!
//! ## 与 [`crate::mx::MxResolver`] 的分工
//!
//! 后者回答「这封信投到哪里」，形状是**按优先级排序的结构化目标**；本模块回答
//! 「DNS 里到底有什么」，形状是**与 `dig +short` 对齐的文本**。校验向导要把它原样
//! 摊给运维看（响应里的 `observed`），所以不能只给结论 —— 只回一个
//! `verified: false` 会让人无从下手。
//!
//! ## TXT 的分片必须拼接
//!
//! DNS 的 TXT 一个名字下可以有多条记录，每条记录又由多个 ≤255 字节的
//! `<character-string>` 组成。`dig +short TXT` 会把同一条记录的分片印成同一行里的
//! 多个带引号串，而**语义上它们是一个值**。只取第一段会截断长 SPF / DKIM 记录 ——
//! 这与 `keys.rs` 记录的 `opendkim-genkey` 公钥截断事故（`network.py:115`）是同一
//! 类问题：本地看着没问题，对端却读不到完整记录。故这里把分片拼接后再返回。

use std::future::Future;
use std::pin::Pin;

use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

use crate::error::{SmtpError, SmtpResult};

/// A / MX / TXT 查询的异步结果。
pub type DnsFuture<'a> = Pin<Box<dyn Future<Output = SmtpResult<Vec<String>>> + Send + 'a>>;

/// DNS 查询后端。
///
/// 做成可注入的，是为了让 `setup.dns.verify` 的六条判据（A / MX / 单条 SPF /
/// 期望 SPF / DKIM / DMARC）能在**不碰真实 DNS** 的前提下逐条验证 —— 否则这些
/// 断言会随网络抖动随机变红，最终被人忽略（本项目已因同类问题吃过亏，见
/// `docs/TEST_REPORT.md` §4.14）。
///
/// **「没有记录」不是错误**：返回空向量即可，由调用方按「校验不通过」处理；
/// 只有真正的解析故障（超时、SERVFAIL）才返回 `Err`。
pub trait DnsQuery: Send + Sync {
    /// 查询 A 记录，返回点分十进制地址串。
    fn lookup_a(&self, host: &str) -> DnsFuture<'_>;
    /// 查询 MX 记录，返回 `<preference> <exchange>` 形式的文本。
    fn lookup_mx_records(&self, domain: &str) -> DnsFuture<'_>;
    /// 查询 TXT 记录，返回**分片已拼接**的值（不含引号）。
    fn lookup_txt(&self, name: &str) -> DnsFuture<'_>;
}

/// 基于系统 DNS 配置（`/etc/resolv.conf`）的实现。
pub struct HickoryDnsQuery {
    resolver: TokioResolver,
}

impl HickoryDnsQuery {
    pub fn from_system() -> SmtpResult<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|error| SmtpError::Dns(format!("cannot load DNS configuration: {error}")))?
            .build()
            .map_err(|error| SmtpError::Dns(format!("cannot build the DNS resolver: {error}")))?;
        Ok(Self { resolver })
    }

    async fn lookup(&self, name: &str, rtype: RecordType, label: &str) -> SmtpResult<Vec<String>> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        match self.resolver.lookup(name.as_str(), rtype).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| rdata_to_text(&record.data))
                .collect()),
            // 「没有这条记录」与「域名不存在」都不是解析故障：两者都表示
            // 「DNS 里没有」，交给调用方判为校验不通过。
            Err(error) if error.is_no_records_found() || error.is_nx_domain() => Ok(Vec::new()),
            Err(error) => Err(SmtpError::Dns(format!(
                "{label} lookup for {name} failed: {error}"
            ))),
        }
    }
}

impl DnsQuery for HickoryDnsQuery {
    fn lookup_a(&self, host: &str) -> DnsFuture<'_> {
        // 名字先取成 owned：查询 future 只需借用 `self`，生命周期因此只跟
        // `&self` 绑定 —— 否则 `DnsFuture<'_>` 会同时牵住 `&str` 参数。
        let name = host.to_string();
        Box::pin(async move { self.lookup(&name, RecordType::A, "A").await })
    }

    fn lookup_mx_records(&self, domain: &str) -> DnsFuture<'_> {
        let name = domain.to_string();
        Box::pin(async move { self.lookup(&name, RecordType::MX, "MX").await })
    }

    fn lookup_txt(&self, name: &str) -> DnsFuture<'_> {
        let name = name.to_string();
        Box::pin(async move { self.lookup(&name, RecordType::TXT, "TXT").await })
    }
}

/// 把一条记录的 rdata 折算成文本（与 `dig +short` 的形态对齐）。
///
/// 只认这四种：本项目需要的全部查询就是 A / AAAA / MX / TXT，其余一律 `None`
/// （`answers()` 里可能混入 CNAME 等跟随记录，它们不该出现在 `observed` 里）。
fn rdata_to_text(data: &RData) -> Option<String> {
    match data {
        RData::A(a) => Some(a.to_string()),
        RData::AAAA(a) => Some(a.to_string()),
        RData::MX(mx) => Some(mx.to_string()),
        // `TXT` 的 `Display` 按 RFC 1035 把分片顺序拼接（见本模块说明）。
        RData::TXT(txt) => Some(txt.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::rdata::{A, HINFO, MX, TXT};
    use hickory_resolver::proto::rr::Name;

    #[test]
    fn a_record_renders_as_a_dotted_quad() {
        assert_eq!(
            rdata_to_text(&RData::A(A::new(203, 0, 113, 10))),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn mx_record_keeps_the_preference_prefix() {
        // `dig +short MX` 的形态是 `<pref> <exchange>`；校验判据按子串匹配主机名，
        // 因此前缀必须保留（否则 `host in item` 会匹配到别的记录）。
        let mx = MX::new(10, Name::from_utf8("mail.example.com.").unwrap());
        assert_eq!(
            rdata_to_text(&RData::MX(mx)),
            Some("10 mail.example.com.".to_string())
        );
    }

    #[test]
    fn txt_chunks_are_concatenated_not_truncated() {
        // 关键回归：长公钥 / 长 SPF 会被拆成多个 255 字节分片，只取第一段就会截断。
        let txt = TXT::new(vec!["v=DKIM1; k=rsa; ".to_string(), "p=AAAA".to_string()]);
        assert_eq!(
            rdata_to_text(&RData::TXT(txt)),
            Some("v=DKIM1; k=rsa; p=AAAA".to_string())
        );
    }

    #[test]
    fn uninteresting_rdata_is_dropped_rather_than_rendered() {
        // 跟随记录（CNAME 等）与本模块无关，不该出现在 observed 里 —— 否则
        // 界面会把一条别名渲染成「你发布的 A 记录」。
        let hinfo = RData::HINFO(HINFO::new("cpu".to_string(), "os".to_string()));
        assert_eq!(rdata_to_text(&hinfo), None);
    }
}

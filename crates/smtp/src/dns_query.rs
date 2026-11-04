use std::future::Future;
use std::pin::Pin;

use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

use crate::error::{SmtpError, SmtpResult};

pub type DnsFuture<'a> = Pin<Box<dyn Future<Output = SmtpResult<Vec<String>>> + Send + 'a>>;

pub trait DnsQuery: Send + Sync {
    fn lookup_a(&self, host: &str) -> DnsFuture<'_>;

    fn lookup_mx_records(&self, domain: &str) -> DnsFuture<'_>;

    fn lookup_txt(&self, name: &str) -> DnsFuture<'_>;
}

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

            Err(error) if error.is_no_records_found() || error.is_nx_domain() => Ok(Vec::new()),
            Err(error) => Err(SmtpError::Dns(format!(
                "{label} lookup for {name} failed: {error}"
            ))),
        }
    }
}

impl DnsQuery for HickoryDnsQuery {
    fn lookup_a(&self, host: &str) -> DnsFuture<'_> {
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

fn rdata_to_text(data: &RData) -> Option<String> {
    match data {
        RData::A(a) => Some(a.to_string()),
        RData::AAAA(a) => Some(a.to_string()),
        RData::MX(mx) => Some(mx.to_string()),

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
        let mx = MX::new(10, Name::from_utf8("mail.example.com.").unwrap());
        assert_eq!(
            rdata_to_text(&RData::MX(mx)),
            Some("10 mail.example.com.".to_string())
        );
    }

    #[test]
    fn txt_chunks_are_concatenated_not_truncated() {
        let txt = TXT::new(vec!["v=DKIM1; k=rsa; ".to_string(), "p=AAAA".to_string()]);
        assert_eq!(
            rdata_to_text(&RData::TXT(txt)),
            Some("v=DKIM1; k=rsa; p=AAAA".to_string())
        );
    }

    #[test]
    fn uninteresting_rdata_is_dropped_rather_than_rendered() {
        let hinfo = RData::HINFO(HINFO::new("cpu".to_string(), "os".to_string()));
        assert_eq!(rdata_to_text(&hinfo), None);
    }
}

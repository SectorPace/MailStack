#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDecision {
    DeliverLocal,

    RelayAuthenticated,

    Reject { code: u16, message: &'static str },
}

impl RelayDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            RelayDecision::DeliverLocal | RelayDecision::RelayAuthenticated
        )
    }
}

#[derive(Debug, Clone)]
pub struct RelayPolicy {
    managed_domains: Vec<String>,
}

const REJECT_UNAUTH_DESTINATION: &str =
    "Relaying denied: not an authenticated sender and destination is not a local domain";

const REJECT_NO_MANAGED_DOMAINS: &str =
    "Relaying denied: no managed domains are configured (failing closed)";

impl RelayPolicy {
    pub fn new<I, S>(managed_domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut domains: Vec<String> = managed_domains
            .into_iter()
            .map(|d| d.as_ref().trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        domains.sort();
        domains.dedup();
        Self {
            managed_domains: domains,
        }
    }

    pub fn managed_domains(&self) -> &[String] {
        &self.managed_domains
    }

    pub fn evaluate(&self, recipient_domain: &str, authenticated: bool) -> RelayDecision {
        if self.is_managed(recipient_domain) {
            return RelayDecision::DeliverLocal;
        }

        if authenticated {
            return RelayDecision::RelayAuthenticated;
        }

        if self.managed_domains.is_empty() {
            return RelayDecision::Reject {
                code: 554,
                message: REJECT_NO_MANAGED_DOMAINS,
            };
        }

        RelayDecision::Reject {
            code: 554,
            message: REJECT_UNAUTH_DESTINATION,
        }
    }

    pub fn is_managed(&self, domain: &str) -> bool {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return false;
        }
        self.managed_domains.contains(&domain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundRoute {
    Direct,

    ViaRelay {
        host: String,
        port: u16,
        wrappermode: bool,
    },
}

impl OutboundRoute {
    pub fn port(&self) -> u16 {
        match self {
            OutboundRoute::Direct => 25,
            OutboundRoute::ViaRelay { port, .. } => *port,
        }
    }

    pub fn is_relay(&self) -> bool {
        matches!(self, OutboundRoute::ViaRelay { .. })
    }
}

pub fn select_outbound_route(relay: Option<&crate::validate::RelayEndpoint>) -> OutboundRoute {
    match relay {
        Some(endpoint) => OutboundRoute::ViaRelay {
            host: endpoint.host.clone(),
            port: endpoint.port,
            wrappermode: endpoint.requires_wrappermode(),
        },
        None => OutboundRoute::Direct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::{validate_relay, RelayValidationRequest};

    #[test]
    fn local_domain_is_delivered_regardless_of_authentication() {
        let policy = RelayPolicy::new(["example.com", "mail.example.com"]);
        assert_eq!(
            policy.evaluate("example.com", false),
            RelayDecision::DeliverLocal
        );
        assert_eq!(
            policy.evaluate("example.com", true),
            RelayDecision::DeliverLocal
        );
        assert_eq!(
            policy.evaluate("MAIL.EXAMPLE.COM", false),
            RelayDecision::DeliverLocal,
            "域名匹配应大小写不敏感"
        );
    }

    #[test]
    fn unauthenticated_foreign_recipient_is_rejected() {
        let policy = RelayPolicy::new(["example.com"]);
        let decision = policy.evaluate("attacker.test", false);
        assert!(!decision.is_allowed());
        match decision {
            RelayDecision::Reject { code, message } => {
                assert_eq!(code, 554);
                assert!(message.contains("Relaying denied"));
            }
            _ => panic!("应拒绝"),
        }
    }

    #[test]
    fn authenticated_foreign_recipient_is_allowed_to_relay() {
        let policy = RelayPolicy::new(["example.com"]);
        assert_eq!(
            policy.evaluate("gmail.com", true),
            RelayDecision::RelayAuthenticated
        );
    }

    #[test]
    fn empty_domain_table_fails_closed() {
        let policy = RelayPolicy::new(Vec::<String>::new());
        let decision = policy.evaluate("gmail.com", false);
        assert_eq!(
            decision,
            RelayDecision::Reject {
                code: 554,
                message: REJECT_NO_MANAGED_DOMAINS,
            }
        );
        assert!(!decision.is_allowed(), "域名表为空时必须拒绝，不得放行");
    }

    #[test]
    fn empty_domain_table_still_allows_authenticated_submission() {
        let policy = RelayPolicy::new(Vec::<String>::new());
        assert_eq!(
            policy.evaluate("gmail.com", true),
            RelayDecision::RelayAuthenticated
        );
    }

    #[test]
    fn blank_and_duplicate_domains_are_normalised_away() {
        let policy = RelayPolicy::new(["  Example.COM ", "example.com", "", "  "]);
        assert_eq!(policy.managed_domains(), &["example.com".to_string()]);
    }

    #[test]
    fn empty_recipient_domain_is_never_treated_as_managed() {
        let policy = RelayPolicy::new(["example.com"]);
        assert!(!policy.is_managed(""));
        assert!(!policy.is_managed("   "));
        assert!(!policy.is_managed("notexample.com"));
    }

    #[test]
    fn subdomain_is_not_implicitly_managed() {
        let policy = RelayPolicy::new(["example.com"]);
        assert!(!policy.is_managed("a.example.com"));
        assert!(!policy.evaluate("a.example.com", false).is_allowed());
    }

    fn relay_endpoint(port: u16, tls_mode: &str) -> crate::validate::RelayEndpoint {
        validate_relay(
            &RelayValidationRequest {
                host: "smtp.sendgrid.net".to_string(),
                port,
                tls_mode: tls_mode.to_string(),
                username: "apikey".to_string(),
                password: "secret".to_string(),
                allow_private_network: false,
            },
            false,
        )
        .unwrap()
    }

    #[test]
    fn without_relay_configuration_traffic_goes_direct() {
        assert_eq!(select_outbound_route(None), OutboundRoute::Direct);
        assert_eq!(select_outbound_route(None).port(), 25);
    }

    #[test]
    fn with_relay_configuration_every_message_goes_through_the_relay() {
        let endpoint = relay_endpoint(587, "STARTTLS");
        let route = select_outbound_route(Some(&endpoint));
        assert!(route.is_relay());
        assert_eq!(route.port(), 587);
        match route {
            OutboundRoute::ViaRelay {
                host, wrappermode, ..
            } => {
                assert_eq!(host, "smtp.sendgrid.net");
                assert!(!wrappermode, "587 不需要 wrappermode");
            }
            _ => panic!("应走中继"),
        }
    }

    #[test]
    fn port_465_relay_enables_wrappermode_on_the_route() {
        let endpoint = relay_endpoint(465, "SSL/TLS");
        match select_outbound_route(Some(&endpoint)) {
            OutboundRoute::ViaRelay {
                port, wrappermode, ..
            } => {
                assert_eq!(port, 465);
                assert!(wrappermode, "465 必须启用 wrappermode");
            }
            _ => panic!("应走中继"),
        }
    }

    #[test]
    fn direct_route_is_never_used_as_a_fallback_when_relay_exists() {
        let endpoint = relay_endpoint(587, "STARTTLS");
        let route = select_outbound_route(Some(&endpoint));
        assert!(route.is_relay(), "有 relay 配置时任何输入都必须走 relay");
        assert_ne!(route.port(), 25, "不得退回到 25 端口直投");
    }
}

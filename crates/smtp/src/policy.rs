//! 反中继策略（规格书 §5.9.7；INV-17、INV-18、INV-21）。
//!
//! 现状由 Postfix 的 `smtpd_relay_restrictions` 承担；Postfix 移除后必须由 Rust
//! 完整继承。三条语义：
//!
//! 1. 仅允许为本机 **managed 域名**的收件人做入站投递
//! 2. 未认证会话不得向非本域目标中继（`reject_unauth_destination` 语义）
//! 3. 认证会话允许提交（submission）
//!
//! **历史缺陷不得复现**：`managed` 为空时旧实现会整体跳过反中继检查。
//! 域名表为空时必须**拒绝**而非放行（fail-closed）。

/// 中继判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDecision {
    /// 本域收件人 → 允许入站投递。
    DeliverLocal,
    /// 已认证会话 → 允许提交/中继。
    RelayAuthenticated,
    /// 拒绝。
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

/// 反中继策略。
#[derive(Debug, Clone)]
pub struct RelayPolicy {
    /// 本机纳管域名（小写、去重）。
    managed_domains: Vec<String>,
}

/// 未知收件域时使用的拒绝语义（对应 `reject_unauth_destination`）。
const REJECT_UNAUTH_DESTINATION: &str =
    "Relaying denied: not an authenticated sender and destination is not a local domain";

/// 域名表为空时的拒绝语义。
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

    /// 判定一次投递是否被允许。
    ///
    /// * `recipient_domain` —— 收件人域名（小写化由本函数负责）
    /// * `authenticated` —— 当前会话是否已通过 SMTP AUTH
    pub fn evaluate(&self, recipient_domain: &str, authenticated: bool) -> RelayDecision {
        // 1) 本域收件人：始终允许入站投递。
        if self.is_managed(recipient_domain) {
            return RelayDecision::DeliverLocal;
        }

        // 2) 已认证会话：允许提交（含向外部域中继）。
        if authenticated {
            return RelayDecision::RelayAuthenticated;
        }

        // 3) 未认证 + 非本域：拒绝。
        //
        // 域名表为空时给出专门的错误文案，便于运维区分「配置缺失」与「确实不该放行」。
        // 两种情况都是拒绝 —— 这正是 fail-closed。
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

    /// 该域名是否由本机纳管。
    pub fn is_managed(&self, domain: &str) -> bool {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return false;
        }
        self.managed_domains.contains(&domain)
    }
}

/// 出站路径选择（INV-18、INV-21）。
///
/// relay 一旦启用，**全部**外发（含 DSN 退信、系统通知、测试邮件）必须经 relay，
/// **不得存在绕过路径**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundRoute {
    /// 直投：逐域解析 MX 后连 25 端口。
    Direct,
    /// 经配置的中继。`wrappermode` 为真时必须同时启用隐式 TLS 包装。
    ViaRelay {
        host: String,
        port: u16,
        wrappermode: bool,
    },
}

impl OutboundRoute {
    /// 该路由的连接端口。
    pub fn port(&self) -> u16 {
        match self {
            OutboundRoute::Direct => 25,
            OutboundRoute::ViaRelay { port, .. } => *port,
        }
    }

    /// 是否经由中继。
    pub fn is_relay(&self) -> bool {
        matches!(self, OutboundRoute::ViaRelay { .. })
    }
}

/// 决定出站路由。
///
/// **关键约束**：只要有 relay 配置，就一律走 relay —— 不存在「relay 失败就退回直投」
/// 的兜底。规格书 §5.10.10 明确禁止该兜底：它会绕过 relay、破坏 SPF 对齐，
/// 并把邮件直接打到已确认被封的 25 端口。
///
/// `message_kind` 只用于可观测性，**不影响路由选择** —— 这正是 INV-21 要求
/// 「DSN 退信、系统通知、测试邮件与外发用户邮件走完全相同的出站路径」的落点。
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
        // INV-17 的核心：开放中继防护。
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
        // 历史缺陷：managed 为空时旧实现整体跳过检查。重写必须拒绝。
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
        // 认证会话的提交与「本机有没有纳管域名」无关。
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
        // 纳管 example.com 不等于纳管 a.example.com —— 必须逐条列出，
        // 否则「多加一个子域」会变成「自动开放一个域的收信」。
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
        // INV-18 / INV-21：relay 生效后不存在绕过路径，且与消息类型无关
        // （函数签名里根本没有 message_kind —— 结构上不可能按类型分流）。
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
        // INV-20：465 必须带 wrappermode，否则实际以明文连 465、投递卡在队列。
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
        // 规格书 §5.10.10：禁止「relay 失败就退回直投」。
        // 该函数没有失败分支 —— 路由在配置层面一次性决定，不存在运行时回退。
        let endpoint = relay_endpoint(587, "STARTTLS");
        let route = select_outbound_route(Some(&endpoint));
        assert!(route.is_relay(), "有 relay 配置时任何输入都必须走 relay");
        assert_ne!(route.port(), 25, "不得退回到 25 端口直投");
    }
}

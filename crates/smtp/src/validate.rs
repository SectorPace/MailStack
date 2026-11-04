use mailstack_core::validate::is_valid_relay_host;

use crate::dial::TlsMode;
use crate::error::{SmtpError, SmtpResult};
use crate::ALLOWED_RELAY_PORTS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayValidationRequest {
    pub host: String,
    pub port: u16,

    pub tls_mode: String,
    pub username: String,
    pub password: String,

    pub allow_private_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub host: String,
    pub port: u16,
    pub tls_mode: TlsMode,
    pub username: String,
    pub password: String,
}

impl RelayEndpoint {
    pub fn has_credentials(&self) -> bool {
        !self.username.is_empty()
    }

    pub fn relayhost(&self) -> String {
        format!("[{}]:{}", self.host, self.port)
    }

    pub fn requires_wrappermode(&self) -> bool {
        self.tls_mode == TlsMode::Implicit || self.port == 465
    }
}

pub fn validate_relay(
    request: &RelayValidationRequest,
    private_network_enabled: bool,
) -> SmtpResult<RelayEndpoint> {
    let host = request.host.trim().to_string();

    if !is_valid_relay_host(&host) {
        return Err(SmtpError::InvalidEndpoint(format!(
            "invalid relay host: {host}"
        )));
    }

    if !ALLOWED_RELAY_PORTS.contains(&request.port) {
        return Err(SmtpError::InvalidEndpoint(format!(
            "relay port {} is not allowed (permitted: 25, 465, 587, 2525)",
            request.port
        )));
    }

    let tls_mode = match request.tls_mode.trim() {
        "STARTTLS" => TlsMode::StartTls,
        "SSL/TLS" => TlsMode::Implicit,
        _ => return Err(SmtpError::TlsRequired),
    };

    if request.username.len() > 256 {
        return Err(SmtpError::InvalidEndpoint(
            "SMTP username must be at most 256 characters".to_string(),
        ));
    }
    if request.password.len() > 4096 {
        return Err(SmtpError::InvalidEndpoint(
            "SMTP password must be at most 4096 characters".to_string(),
        ));
    }
    for (label, value) in [
        ("username", &request.username),
        ("password", &request.password),
    ] {
        if value.contains(['\r', '\n', '\0', ' ', '\t']) {
            return Err(SmtpError::InvalidEndpoint(format!(
                "SMTP {label} must not contain CR, LF, NUL or whitespace"
            )));
        }
    }

    if request.username.contains(':') {
        return Err(SmtpError::InvalidEndpoint(
            "SMTP username must not contain ':' (it is the sasl_passwd user/password separator)"
                .to_string(),
        ));
    }

    let has_user = !request.username.is_empty();
    let has_pass = !request.password.is_empty();
    if has_user != has_pass {
        return Err(SmtpError::IncompleteCredentials);
    }

    if request.allow_private_network && !private_network_enabled {
        return Err(SmtpError::PrivateRelayDisabled);
    }

    Ok(RelayEndpoint {
        host,
        port: request.port,
        tls_mode,
        username: request.username.clone(),
        password: request.password.clone(),
    })
}

pub fn address_policy_for(
    request: &RelayValidationRequest,
    private_network_enabled: bool,
) -> crate::target::AddressPolicy {
    if request.allow_private_network && private_network_enabled {
        crate::target::AddressPolicy::allow_private()
    } else {
        crate::target::AddressPolicy::public_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> RelayValidationRequest {
        RelayValidationRequest {
            host: "smtp.sendgrid.net".to_string(),
            port: 587,
            tls_mode: "STARTTLS".to_string(),
            username: "apikey".to_string(),
            password: "SG.secret".to_string(),
            allow_private_network: false,
        }
    }

    #[test]
    fn accepts_a_well_formed_endpoint() {
        let endpoint = validate_relay(&base_request(), false).unwrap();
        assert_eq!(endpoint.host, "smtp.sendgrid.net");
        assert_eq!(endpoint.port, 587);
        assert_eq!(endpoint.tls_mode, TlsMode::StartTls);
        assert!(endpoint.has_credentials());
        assert!(endpoint.relayhost() == "[smtp.sendgrid.net]:587");
    }

    #[test]
    fn relayhost_uses_bracket_syntax_to_suppress_mx_lookup() {
        let mut req = base_request();
        req.host = "127.0.0.1".to_string();
        req.port = 587;
        let endpoint = validate_relay(&req, true).unwrap();
        assert_eq!(endpoint.relayhost(), "[127.0.0.1]:587");
    }

    #[test]
    fn rejects_malformed_hosts() {
        for bad in [
            ".example.com",
            "example.com.",
            "exa..mple.com",
            "bad host",
            "",
        ] {
            let mut req = base_request();
            req.host = bad.to_string();
            let err = validate_relay(&req, false).unwrap_err();
            assert!(
                matches!(err, SmtpError::InvalidEndpoint(_)),
                "{bad:?} 应被拒绝，实际: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_ports_outside_the_whitelist() {
        for good in [25u16, 465, 587, 2525] {
            let mut req = base_request();
            req.port = good;
            assert!(validate_relay(&req, false).is_ok(), "端口 {good} 应被接受");
        }
        for bad in [0u16, 22, 80, 443, 8080, 65535] {
            let mut req = base_request();
            req.port = bad;
            let err = validate_relay(&req, false).unwrap_err();
            assert!(
                matches!(err, SmtpError::InvalidEndpoint(_)),
                "端口 {bad} 应被拒绝"
            );
        }
    }

    #[test]
    fn rejects_plaintext_relay_with_the_documented_message() {
        for plaintext in ["none", "", "plain", "NONE", "TLS"] {
            let mut req = base_request();
            req.tls_mode = plaintext.to_string();
            let err = validate_relay(&req, false).unwrap_err();
            assert!(matches!(err, SmtpError::TlsRequired));
            assert_eq!(err.to_string(), "TLS is required for relay endpoint");
        }
    }

    #[test]
    fn accepts_both_tls_modes_and_port_465_maps_to_implicit() {
        let mut req = base_request();
        req.tls_mode = "SSL/TLS".to_string();
        req.port = 465;
        let endpoint = validate_relay(&req, false).unwrap();
        assert_eq!(endpoint.tls_mode, TlsMode::Implicit);
        assert!(endpoint.requires_wrappermode(), "465 必须要求 wrappermode");
    }

    #[test]
    fn port_465_with_starttls_still_requires_wrappermode() {
        let mut req = base_request();
        req.port = 465;
        req.tls_mode = "STARTTLS".to_string();
        let endpoint = validate_relay(&req, false).unwrap();
        assert!(
            endpoint.requires_wrappermode(),
            "INV-20: 端口 465 必须写 smtp_tls_wrappermode"
        );
    }

    #[test]
    fn port_587_with_starttls_does_not_require_wrappermode() {
        let endpoint = validate_relay(&base_request(), false).unwrap();
        assert!(!endpoint.requires_wrappermode());
    }

    #[test]
    fn rejects_credential_injection_via_crlf_and_nul() {
        for (user, pass) in [
            ("api\rkey", "x"),
            ("api\nkey", "x"),
            ("api\0key", "x"),
            ("apikey", "sec\rret"),
            ("apikey", "sec\nret"),
            ("apikey", "sec\0ret"),
        ] {
            let mut req = base_request();
            req.username = user.to_string();
            req.password = pass.to_string();
            let err = validate_relay(&req, false).unwrap_err();
            assert!(
                matches!(err, SmtpError::InvalidEndpoint(_)),
                "含控制字符的凭证必须被拒绝"
            );
        }
    }

    #[test]
    fn rejects_whitespace_in_relay_credentials() {
        for (user, pass) in [
            ("api key", "x"),
            ("apikey", "sec ret"),
            ("apikey", "sec\tret"),
            (" apikey", "x"),
            ("apikey ", "x"),
        ] {
            let mut req = base_request();
            req.username = user.to_string();
            req.password = pass.to_string();
            let err = validate_relay(&req, false).unwrap_err();
            assert!(
                matches!(err, SmtpError::InvalidEndpoint(_)),
                "含空白的凭证必须被拒绝（user={user:?}, pass={pass:?}），实际: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_oversized_credentials() {
        let mut req = base_request();
        req.username = "u".repeat(257);
        req.password = "p".repeat(10);
        assert!(validate_relay(&req, false).is_err());

        let mut req = base_request();
        req.username = "u".repeat(10);
        req.password = "p".repeat(4097);
        assert!(validate_relay(&req, false).is_err());

        let mut req = base_request();
        req.username = "u".repeat(256);
        req.password = "p".repeat(4096);
        assert!(validate_relay(&req, false).is_ok());
    }

    #[test]
    fn requires_username_and_password_together() {
        let mut only_user = base_request();
        only_user.password = String::new();
        let err = validate_relay(&only_user, false).unwrap_err();
        assert!(matches!(err, SmtpError::IncompleteCredentials));
        assert_eq!(
            err.to_string(),
            "SMTP username and password must be provided together"
        );

        let mut only_pass = base_request();
        only_pass.username = String::new();
        assert!(matches!(
            validate_relay(&only_pass, false).unwrap_err(),
            SmtpError::IncompleteCredentials
        ));
    }

    #[test]
    fn credentials_are_optional_as_a_pair() {
        let mut req = base_request();
        req.username = String::new();
        req.password = String::new();
        let endpoint = validate_relay(&req, false).unwrap();
        assert!(!endpoint.has_credentials());
    }

    #[test]
    fn rejects_colon_in_username_but_allows_it_in_password() {
        let mut req = base_request();
        req.username = "svc:mail".to_string();
        req.password = "pw".to_string();
        let err = validate_relay(&req, false).unwrap_err();
        assert!(
            matches!(err, SmtpError::InvalidEndpoint(_)),
            "用户名含冒号必须被拒绝，实际: {err:?}"
        );

        let mut req = base_request();
        req.username = "svc".to_string();
        req.password = "pa:ss:word".to_string();
        let endpoint = validate_relay(&req, false).unwrap();
        assert_eq!(endpoint.password, "pa:ss:word");
    }

    #[test]
    fn address_policy_requires_both_the_request_and_the_deployment_to_opt_in() {
        let mut request = base_request();
        request.allow_private_network = true;

        assert_eq!(
            address_policy_for(&request, false),
            crate::target::AddressPolicy::public_only(),
            "部署未开启时不得放宽（即使请求要求私网）"
        );
        assert_eq!(
            address_policy_for(&request, true),
            crate::target::AddressPolicy::allow_private(),
            "两者都开启才放宽"
        );

        let mut public_request = base_request();
        public_request.allow_private_network = false;
        assert_eq!(
            address_policy_for(&public_request, true),
            crate::target::AddressPolicy::public_only(),
            "请求没要求时不得主动放宽"
        );
        assert_eq!(
            address_policy_for(&public_request, false),
            crate::target::AddressPolicy::public_only()
        );
    }

    #[test]
    fn private_network_requires_deployment_opt_in() {
        let mut req = base_request();
        req.allow_private_network = true;

        let err = validate_relay(&req, false).unwrap_err();
        assert!(matches!(err, SmtpError::PrivateRelayDisabled));
        assert_eq!(
            err.to_string(),
            "Private SMTP relay access is disabled by deployment policy"
        );

        assert!(validate_relay(&req, true).is_ok());
    }

    #[test]
    fn private_policy_does_not_widen_when_not_requested() {
        let endpoint = validate_relay(&base_request(), true).unwrap();
        assert_eq!(endpoint.host, "smtp.sendgrid.net");
    }

    #[test]
    fn host_is_trimmed_but_not_lowercased_into_invalidity() {
        let mut req = base_request();
        req.host = "  smtp.sendgrid.net  ".to_string();
        let endpoint = validate_relay(&req, false).unwrap();
        assert_eq!(endpoint.host, "smtp.sendgrid.net");
    }
}

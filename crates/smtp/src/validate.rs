//! 中继端点校验（规格书 §5.9.2；INV-13、INV-15）。
//!
//! 全部规则逐条保留 —— 中继是重写中最容易被做弱化的安全子系统。

use mailstack_core::validate::is_valid_relay_host;

use crate::dial::TlsMode;
use crate::error::{SmtpError, SmtpResult};
use crate::ALLOWED_RELAY_PORTS;

/// 请求中的中继端点（未校验）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayValidationRequest {
    pub host: String,
    pub port: u16,
    /// 原始 tlsMode 字符串（`STARTTLS` / `SSL/TLS`）。
    pub tls_mode: String,
    pub username: String,
    pub password: String,
    /// 请求方是否要求允许私网目标。
    pub allow_private_network: bool,
}

/// 已校验的中继端点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub host: String,
    pub port: u16,
    pub tls_mode: TlsMode,
    pub username: String,
    pub password: String,
}

impl RelayEndpoint {
    /// 是否有凭证。
    pub fn has_credentials(&self) -> bool {
        !self.username.is_empty()
    }

    /// `relayhost` 形式：`[host]:port`（方括号表示不做 MX 解析，§5.9.5）。
    pub fn relayhost(&self) -> String {
        format!("[{}]:{}", self.host, self.port)
    }

    /// 隐式 TLS 时是否需要 `smtp_tls_wrappermode = yes`（INV-20）。
    ///
    /// 这正是现状已确认的缺陷：`port=465` 时测试通过、界面显示鉴权成功，
    /// 但因为从未写 `smtp_tls_wrappermode`，实际以明文连 465，投递卡在队列。
    pub fn requires_wrappermode(&self) -> bool {
        self.tls_mode == TlsMode::Implicit || self.port == 465
    }
}

/// 校验中继端点。
///
/// `private_network_enabled` 是**部署策略**（不是请求参数）：请求方要求
/// `allowPrivateNetwork` 时，若部署侧未开启，必须拒绝。
pub fn validate_relay(
    request: &RelayValidationRequest,
    private_network_enabled: bool,
) -> SmtpResult<RelayEndpoint> {
    let host = request.host.trim().to_string();

    // host：字符集 + 不得以 `.` 开头/结尾 + 不得含 `..`
    if !is_valid_relay_host(&host) {
        return Err(SmtpError::InvalidEndpoint(format!(
            "invalid relay host: {host}"
        )));
    }

    // port：白名单
    if !ALLOWED_RELAY_PORTS.contains(&request.port) {
        return Err(SmtpError::InvalidEndpoint(format!(
            "relay port {} is not allowed (permitted: 25, 465, 587, 2525)",
            request.port
        )));
    }

    // tlsMode：仅 STARTTLS / SSL/TLS，**明文中继一律拒绝**
    let tls_mode = match request.tls_mode.trim() {
        "STARTTLS" => TlsMode::StartTls,
        "SSL/TLS" => TlsMode::Implicit,
        _ => return Err(SmtpError::TlsRequired),
    };

    // 凭证：长度上限 + 禁止 CR/LF/NUL（SMTP 头注入防护）
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
        if value.contains(['\r', '\n', '\0']) {
            return Err(SmtpError::InvalidEndpoint(format!(
                "SMTP {label} must not contain CR, LF or NUL"
            )));
        }
    }

    // 凭证必须成对提供。
    let has_user = !request.username.is_empty();
    let has_pass = !request.password.is_empty();
    if has_user != has_pass {
        return Err(SmtpError::IncompleteCredentials);
    }

    // 私网策略：请求要求私网但部署未开启 → 拒绝。
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

/// 由请求推导地址筛选策略。
///
/// 只有在请求显式要求私网**且**部署策略已开启时，才放宽到允许私网地址；
/// 其余一律公网策略（不主动放宽）。
pub fn address_policy_for(request: &RelayValidationRequest) -> crate::target::AddressPolicy {
    if request.allow_private_network {
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
        // INV-13：端口限定 25/465/587/2525。
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
        // INV-13：明文中继一律拒绝，文案是契约。
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
        // 现状缺陷的边界：判定依据是「端口 465 **或** tlsMode=SSL/TLS」，
        // 取并集而不是只看 tlsMode。
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
        // INV-15：CRLF 注入 SMTP 头。
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
    fn rejects_oversized_credentials() {
        let mut req = base_request();
        req.username = "u".repeat(257);
        req.password = "p".repeat(10);
        assert!(validate_relay(&req, false).is_err());

        let mut req = base_request();
        req.username = "u".repeat(10);
        req.password = "p".repeat(4097);
        assert!(validate_relay(&req, false).is_err());

        // 边界内应通过。
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
        // 无凭证的中继（如内网 smarthost）应被接受。
        let mut req = base_request();
        req.username = String::new();
        req.password = String::new();
        let endpoint = validate_relay(&req, false).unwrap();
        assert!(!endpoint.has_credentials());
    }

    #[test]
    fn private_network_requires_deployment_opt_in() {
        // INV-15：部署策略未开启时一律拒绝，文案是契约。
        let mut req = base_request();
        req.allow_private_network = true;

        let err = validate_relay(&req, false).unwrap_err();
        assert!(matches!(err, SmtpError::PrivateRelayDisabled));
        assert_eq!(
            err.to_string(),
            "Private SMTP relay access is disabled by deployment policy"
        );

        // 部署侧开启后放行。
        assert!(validate_relay(&req, true).is_ok());
    }

    #[test]
    fn private_policy_does_not_widen_when_not_requested() {
        // 部署开了私网，但请求没要求 → 仍按公网策略（不主动放宽）。
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

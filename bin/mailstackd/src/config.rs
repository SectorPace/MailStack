use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use mailstack_core::config::{read_settings, read_setup_config};
use mailstack_core::{mode, Paths};
use mailstack_queue::QueueConfig;
use mailstack_smtp::relay_apply::{KEY_RELAYHOST, KEY_TLS_SECURITY_LEVEL, KEY_TLS_WRAPPERMODE};
use mailstack_smtp::{
    parse_sasl_passwd, validate_relay, AddressPolicy, NativeRelayStore, RelayConfigStore,
    RelayEndpoint, RelayPolicy, RelayValidationRequest,
};
use mailstack_smtpd::{BanConfig, CertPaths, RateLimitConfig, SessionConfig, TlsMode};
use mailstack_store::{LmtpEndpoint, TableStore};

use crate::error::DaemonError;

pub const DEFAULT_PORTS: &[u16] = &[25, 465, 587];

const ENCRYPTING_SECURITY_LEVELS: &[&str] = &[
    "encrypt",
    "secure",
    "dane",
    "dane-only",
    "fingerprint",
    "verify",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerPlan {
    pub port: u16,

    pub mode: TlsMode,

    pub offer_starttls: bool,

    pub offer_auth: bool,

    pub require_auth_for_submission: bool,
}

impl ListenerPlan {
    pub fn for_port(port: u16) -> Self {
        match port {
            465 => Self {
                port,
                mode: TlsMode::Implicit,
                offer_starttls: false,
                offer_auth: true,

                require_auth_for_submission: true,
            },
            587 => Self {
                port,
                mode: TlsMode::StartTls,
                offer_starttls: true,
                offer_auth: true,
                require_auth_for_submission: true,
            },
            _ => Self {
                port,
                mode: TlsMode::StartTls,
                offer_starttls: true,
                offer_auth: false,
                require_auth_for_submission: false,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub paths: Paths,

    pub mail_host: String,

    pub domain: String,

    pub cert_paths: CertPaths,
    pub listeners: Vec<ListenerPlan>,

    pub session: SessionConfig,
    pub relay_policy: RelayPolicy,
    pub rate_limit: RateLimitConfig,
    pub ban: BanConfig,
    pub queue_config: QueueConfig,
    pub queue_root: PathBuf,
    pub lmtp_endpoint: LmtpEndpoint,

    pub relay_endpoint: Option<RelayEndpoint>,

    pub allow_private_network: bool,
}

pub fn assemble(paths: Paths, ports: &[u16]) -> Result<RuntimeConfig, DaemonError> {
    if ports.is_empty() {
        return Err(DaemonError::NoListeners);
    }

    let setup = read_setup_config(&paths)
        .ok_or_else(|| DaemonError::SetupMissing(paths.setup_config.clone()))?;
    let cert_paths = CertPaths::for_domain(&paths.etc, &setup.domain)?;

    let settings = read_settings(&paths);

    let domains = TableStore::new(paths.clone()).domains();
    if domains.is_empty() {
        return Err(DaemonError::DomainTableEmpty(paths.domains.clone()));
    }

    let queue_root = paths.var_lib.join("queue");
    prepare_queue_dir(&queue_root)?;

    let allow_private_network = !mode::is_public_mode(&paths);
    let relay_endpoint = load_relay(&paths, allow_private_network)?;

    let listeners: Vec<ListenerPlan> = ports.iter().copied().map(ListenerPlan::for_port).collect();

    let session = SessionConfig {
        hostname: settings.hostname.clone(),
        max_message_size: settings.max_message_size_mb as usize * 1024 * 1024,
        postmaster: Some(format!("postmaster@{}", setup.domain)),

        offer_auth: false,
        ..SessionConfig::default()
    };

    let queue_config = QueueConfig {
        relay_concurrency: settings.relay_concurrency,
        reporting_mta: setup.mail_host.clone(),
        managed_domains: domains.clone(),
        ..QueueConfig::default()
    };

    let lmtp_endpoint =
        LmtpEndpoint::from_env_with_default(LmtpEndpoint::unix(paths.run_dir.join("lmtp.sock")));

    Ok(RuntimeConfig {
        paths,
        mail_host: setup.mail_host,
        domain: setup.domain,
        cert_paths,
        listeners,
        session,
        relay_policy: RelayPolicy::new(domains),
        rate_limit: RateLimitConfig::default(),
        ban: BanConfig::default(),
        queue_config,
        queue_root,
        lmtp_endpoint,
        relay_endpoint,
        allow_private_network,
    })
}

fn prepare_queue_dir(dir: &Path) -> Result<(), DaemonError> {
    std::fs::create_dir_all(dir).map_err(|error| DaemonError::QueueDir {
        path: dir.to_path_buf(),
        message: error.to_string(),
    })?;

    let probe = dir.join(".mailstack-write-probe");
    std::fs::write(&probe, b"ok").map_err(|error| DaemonError::QueueDir {
        path: dir.to_path_buf(),
        message: error.to_string(),
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

fn load_relay(
    paths: &Paths,
    deployment_allows_private: bool,
) -> Result<Option<RelayEndpoint>, DaemonError> {
    let mut store = NativeRelayStore::production(paths);

    let relayhost = store
        .read_key(KEY_RELAYHOST)
        .map_err(DaemonError::RelayConfig)?;
    let Some(relayhost) = relayhost else {
        return Ok(None);
    };
    let relayhost = relayhost.trim().to_string();
    if relayhost.is_empty() {
        return Ok(None);
    }

    let (host, port) = parse_relayhost(&relayhost)?;

    let wrappermode = store
        .read_key(KEY_TLS_WRAPPERMODE)
        .map_err(DaemonError::RelayConfig)?
        .unwrap_or_default();
    let security_level = store
        .read_key(KEY_TLS_SECURITY_LEVEL)
        .map_err(DaemonError::RelayConfig)?;
    let tls_mode = relay_tls_mode(&wrappermode, port, security_level.as_deref())?;

    let (username, password) = match store.read_credentials().map_err(DaemonError::RelayConfig)? {
        Some(content) => {
            let matched = match_credentials(&content, &host, port);
            if matched.is_none() {
                tracing::warn!(
                    relay = %relayhost,
                    "凭证映射中没有该中继的条目，将按无凭证连接"
                );
            }
            matched.unwrap_or_default()
        }
        None => (String::new(), String::new()),
    };

    let request = RelayValidationRequest {
        allow_private_network: host_needs_private_network(&host),
        host,
        port,
        tls_mode,
        username,
        password,
    };
    let endpoint = validate_relay(&request, deployment_allows_private).map_err(|error| {
        if matches!(error, mailstack_smtp::SmtpError::PrivateRelayDisabled) {
            tracing::error!(
                relay = %request_host(&request),
                "中继指向私网地址，但当前部署为公网档（ACCESS_MODE=caddy/direct）；\
                 请改用公网可达的中继，或确认 ACCESS_MODE 是否正确"
            );
        }
        DaemonError::Relay(error)
    })?;
    Ok(Some(endpoint))
}

fn host_needs_private_network(host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !AddressPolicy::public_only().accepts(ip),
        Err(_) => false,
    }
}

fn request_host(request: &RelayValidationRequest) -> String {
    format!("[{}]:{}", request.host, request.port)
}

fn parse_relayhost(value: &str) -> Result<(String, u16), DaemonError> {
    let value = value.trim();

    if value.matches(':').count() > 1 && !value.starts_with('[') {
        return Err(DaemonError::RelayHostBareIpv6(value.to_string()));
    }
    let (host_part, port) = match value.rsplit_once(':') {
        Some((head, tail)) if !tail.contains(']') => {
            let port = tail
                .parse::<u16>()
                .map_err(|_| DaemonError::RelayHost(value.to_string()))?;
            (head, port)
        }
        _ => (value, 25u16),
    };

    let host = host_part
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if host.is_empty() {
        return Err(DaemonError::RelayHost(value.to_string()));
    }
    Ok((host, port))
}

fn relay_tls_mode(
    wrappermode: &str,
    port: u16,
    security_level: Option<&str>,
) -> Result<String, DaemonError> {
    if wrappermode.trim().eq_ignore_ascii_case("yes") || port == 465 {
        return Ok("SSL/TLS".to_string());
    }
    let level = security_level.unwrap_or("").trim().to_ascii_lowercase();
    if ENCRYPTING_SECURITY_LEVELS.contains(&level.as_str()) {
        return Ok("STARTTLS".to_string());
    }
    Err(DaemonError::RelayNotEncrypted(port))
}

fn match_credentials(content: &str, host: &str, port: u16) -> Option<(String, String)> {
    parse_sasl_passwd(content).into_iter().find_map(|entry| {
        let (entry_host, entry_port) = parse_relayhost(&entry.relayhost).ok()?;
        if entry_host.eq_ignore_ascii_case(host) && entry_port == port {
            Some((entry.username, entry.password))
        } else {
            None
        }
    })
}

pub fn listen_addr(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETUP: &str = r#"{
  "domain": "example.org",
  "mailHost": "mail.example.org",
  "serverIp": "203.0.113.10",
  "dkimSelector": "mailstack",
  "updatedAt": "2026-10-01T00:00:00Z"
}"#;

    fn root() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        std::fs::create_dir_all(paths.etc.clone()).unwrap();
        std::fs::create_dir_all(paths.postfix.clone()).unwrap();
        std::fs::write(&paths.setup_config, SETUP).unwrap();
        std::fs::write(&paths.domains, "example.org ok\n").unwrap();
        (dir, paths)
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    #[test]
    fn a_minimal_installation_assembles_all_three_default_listeners() {
        let (_dir, paths) = root();
        let config = assemble(paths, DEFAULT_PORTS).expect("装配");

        assert_eq!(config.domain, "example.org");
        assert_eq!(config.mail_host, "mail.example.org");
        assert_eq!(
            config.cert_paths.cert,
            config.paths.etc.join("tls/example.org/fullchain.pem"),
            "证书目录必须取自 setup.json 的 domain"
        );
        assert!(
            !config.session.hostname.is_empty(),
            "问候名必须有值（settings.json 缺失时取 /etc/hostname）"
        );
        assert_eq!(
            config.session.max_message_size,
            50 * 1024 * 1024,
            "默认 50 MiB（settings.json 缺失时回落默认值）"
        );
        assert_eq!(
            config.session.postmaster.as_deref(),
            Some("postmaster@example.org")
        );
        assert!(config.relay_endpoint.is_none(), "未配置中继 → 直投");
        assert_eq!(config.queue_config.managed_domains, vec!["example.org"]);
        assert_eq!(config.queue_config.reporting_mta, "mail.example.org");
    }

    #[test]
    fn ports_map_to_the_right_tls_mode_and_starttls_advertisement() {
        let (_dir, paths) = root();
        let config = assemble(paths, &[25, 465, 587]).expect("装配");

        let by_port = |port: u16| {
            *config
                .listeners
                .iter()
                .find(|plan| plan.port == port)
                .expect("端口应在计划里")
        };
        assert_eq!(
            by_port(465),
            ListenerPlan {
                port: 465,
                mode: TlsMode::Implicit,
                offer_starttls: false,
                offer_auth: true,

                require_auth_for_submission: true
            }
        );
        assert_eq!(
            by_port(587),
            ListenerPlan {
                port: 587,
                mode: TlsMode::StartTls,
                offer_starttls: true,
                offer_auth: true,

                require_auth_for_submission: true
            }
        );
        assert_eq!(
            by_port(25),
            ListenerPlan {
                port: 25,
                mode: TlsMode::StartTls,
                offer_starttls: true,

                offer_auth: false,
                require_auth_for_submission: false
            }
        );
    }

    #[test]
    fn a_missing_setup_file_refuses_to_start_instead_of_guessing_an_identity() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        let error = assemble(paths, &[25]).expect_err("缺少 setup.json 必须拒绝启动");
        assert!(
            matches!(error, DaemonError::SetupMissing(_)),
            "实际：{error:?}"
        );
    }

    #[test]
    fn an_empty_domain_table_refuses_to_start_instead_of_silently_rejecting_everything() {
        let (_dir, paths) = root();
        std::fs::write(&paths.domains, "").unwrap();
        let error = assemble(paths, &[25]).expect_err("空域名表必须拒绝启动");
        assert!(
            matches!(error, DaemonError::DomainTableEmpty(_)),
            "实际：{error:?}"
        );
    }

    #[test]
    fn no_listeners_is_refused() {
        let (_dir, paths) = root();
        let error = assemble(paths, &[]).expect_err("没有监听端口必须拒绝启动");
        assert!(matches!(error, DaemonError::NoListeners), "实际：{error:?}");
    }

    #[test]
    fn a_corrupt_relay_config_is_fatal_and_never_falls_back_to_direct() {
        let (_dir, paths) = root();
        std::fs::write(&paths.relay_config, "{ this is not json").unwrap();

        let error = assemble(paths, &[25]).expect_err("损坏的 relay.json 必须拒绝启动");
        assert!(
            matches!(error, DaemonError::RelayConfig(_)),
            "实际：{error:?}"
        );
    }

    #[test]
    fn an_absent_relay_config_is_a_legitimate_unconfigured_state() {
        let (_dir, paths) = root();
        assert!(!paths.relay_config.exists());
        let config = assemble(paths, &[25]).expect("未配置中继应可启动");
        assert!(config.relay_endpoint.is_none());
    }

    #[test]
    fn a_plaintext_relay_is_refused() {
        let (_dir, paths) = root();
        std::fs::write(
            &paths.relay_config,
            r#"{"relayhost": "[smtp.example.net]:587"}"#,
        )
        .unwrap();

        let error = assemble(paths, &[25]).expect_err("未启用加密的中继必须拒绝启动");
        assert!(
            matches!(error, DaemonError::RelayNotEncrypted(587)),
            "实际：{error:?}"
        );
    }

    #[test]
    fn an_encrypted_relay_with_credentials_is_assembled_and_kept_secret_aware() {
        let (_dir, paths) = root();
        std::fs::write(
            &paths.relay_config,
            r#"{
  "relayhost": "[smtp.example.net]:587",
  "smtp_tls_security_level": "encrypt",
  "saslPasswd": "[smtp.example.net]:587 relay-user:relay-pass\n"
}"#,
        )
        .unwrap();

        let config = assemble(paths, &[25]).expect("装配");
        let relay = config.relay_endpoint.expect("应解析出中继");
        assert_eq!(relay.host, "smtp.example.net");
        assert_eq!(relay.port, 587);
        assert_eq!(relay.username, "relay-user");
        assert_eq!(relay.password, "relay-pass");
        assert!(relay.has_credentials());
    }

    #[test]
    fn port_465_implies_wrappermode_even_without_the_explicit_key() {
        let (_dir, paths) = root();
        std::fs::write(
            &paths.relay_config,
            r#"{"relayhost": "[smtp.example.net]:465"}"#,
        )
        .unwrap();

        let config = assemble(paths, &[25]).expect("装配");
        let relay = config.relay_endpoint.expect("应解析出中继");
        assert_eq!(relay.tls_mode, mailstack_smtp::TlsMode::Implicit);
    }

    #[test]
    fn a_private_relay_is_only_allowed_when_the_deployment_opt_in_is_present() {
        let _env_guard = env_lock();

        std::env::remove_var("MAILSTACK_SECURITY_PROFILE");

        let (_dir, paths) = root();
        std::fs::write(
            &paths.relay_config,
            r#"{
  "relayhost": "[192.168.1.10]:587",
  "smtp_tls_security_level": "encrypt"
}"#,
        )
        .unwrap();

        std::fs::write(&paths.install_args_conf, "ACCESS_MODE=direct\n").unwrap();
        let error = assemble(paths.clone(), &[25]).expect_err("公网档不得使用私网中继");
        assert!(matches!(error, DaemonError::Relay(_)), "实际：{error:?}");

        std::fs::write(&paths.install_args_conf, "ACCESS_MODE=local\n").unwrap();
        let config = assemble(paths, &[25]).expect("本地档应允许私网中继");
        assert!(config.allow_private_network);
        assert!(config.relay_endpoint.is_some());
    }

    #[test]
    fn relayhost_parsing_handles_brackets_ports_and_bare_hosts() {
        assert_eq!(
            parse_relayhost("[smtp.example.net]:587").unwrap(),
            ("smtp.example.net".to_string(), 587)
        );
        assert_eq!(
            parse_relayhost("smtp.example.net:2525").unwrap(),
            ("smtp.example.net".to_string(), 2525)
        );
        assert_eq!(
            parse_relayhost("smtp.example.net").unwrap(),
            ("smtp.example.net".to_string(), 25),
            "裸主机名按 Postfix 惯例取 25"
        );
        assert_eq!(
            parse_relayhost("[::1]:25").unwrap(),
            ("::1".to_string(), 25),
            "IPv6 字面量不得被当成端口"
        );
        assert_eq!(parse_relayhost("[::1]").unwrap(), ("::1".to_string(), 25));

        assert!(
            matches!(
                parse_relayhost("::1"),
                Err(DaemonError::RelayHostBareIpv6(_))
            ),
            "裸 IPv6 必须被拒"
        );
        assert!(parse_relayhost("2001:db8::1").is_err());
        assert!(parse_relayhost("").is_err());
        assert!(parse_relayhost("[host]:not-a-port").is_err());
    }

    #[test]
    fn opportunistic_encryption_is_not_accepted_because_credentials_would_leak() {
        assert!(relay_tls_mode("no", 587, Some("may")).is_err());
        assert!(relay_tls_mode("no", 587, Some("none")).is_err());
        assert!(relay_tls_mode("no", 587, None).is_err());
        assert_eq!(
            relay_tls_mode("no", 587, Some("encrypt")).unwrap(),
            "STARTTLS"
        );
        assert_eq!(relay_tls_mode("yes", 587, None).unwrap(), "SSL/TLS");
        assert_eq!(relay_tls_mode("no", 465, None).unwrap(), "SSL/TLS");
    }
}

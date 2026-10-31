//! 配置装配：`Paths` + CLI → [`RuntimeConfig`]。
//!
//! 本模块是**纯决策**：不绑定 socket、不读取证书内容、不发起网络请求。因此
//! 「什么情况下拒绝启动」可以被完整单测 —— 而这些判定恰恰是最值得测的部分。
//!
//! ## 唯一的组织原则：区分「必须失败」与「安全降级」
//!
//! | 情形 | 处理 | 理由 |
//! |---|---|---|
//! | `setup.json` 缺失/损坏 | **失败** | 它决定问候名、`Reporting-MTA`、证书路径与 postmaster。猜一个等于冒认身份 |
//! | 域名表为空 | **失败** | 库层会 fail-closed 拒收全部收件人（INV-17），但那是「静默变砖」；启动即失败才看得见 |
//! | `relay.json` 损坏 | **失败** | 与「未配置」是两件事。当成未配置就会退回直投，违反 INV-18/INV-21 |
//! | `relay.json` 不存在 | 降级为 `None` | 这是合法的「尚未配置中继」状态 |
//! | `settings.json` 缺失/损坏 | 降级为默认值 | `read_settings` 已内置该语义，且默认值本身是安全的 |
//! | 中继未启用加密 | **失败** | 会以明文投递（INV-13），且可能把 SASL 口令发出去 |

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

/// 默认监听端口：25（MX）、465（隐式 TLS）、587（提交）。
pub const DEFAULT_PORTS: &[u16] = &[25, 465, 587];

/// 被认为「确实启用了加密」的 `smtp_tls_security_level` 取值。
///
/// 刻意**排除** `none` 与 `may`：`may` 是机会性加密，允许在对方不支持时退回明文，
/// 而我们要在这条链路上发送 SASL 口令 —— 退回明文等于把口令交出去。
const ENCRYPTING_SECURITY_LEVELS: &[&str] = &[
    "encrypt",
    "secure",
    "dane",
    "dane-only",
    "fingerprint",
    "verify",
];

/// 一个入站监听的计划。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerPlan {
    pub port: u16,
    /// 465 是隐式 TLS（建连即握手），其余端口用 STARTTLS 升级。
    pub mode: TlsMode,
    /// 是否在 EHLO 里通告 STARTTLS。隐式 TLS 上必须为 `false`。
    pub offer_starttls: bool,
    /// 是否通告 SASL AUTH（§3.5）。
    ///
    /// 只在**提交端口**（465/587）上开：25 是 MX 收信口，客户端提交不该走它，
    /// 在那里开放认证只是白白多出一个口令攻击面。
    pub offer_auth: bool,
}

impl ListenerPlan {
    pub fn for_port(port: u16) -> Self {
        match port {
            465 => Self {
                port,
                mode: TlsMode::Implicit,
                offer_starttls: false,
                offer_auth: true,
            },
            587 => Self {
                port,
                mode: TlsMode::StartTls,
                offer_starttls: true,
                offer_auth: true,
            },
            _ => Self {
                port,
                mode: TlsMode::StartTls,
                offer_starttls: true,
                offer_auth: false,
            },
        }
    }
}

/// 装配完成的运行期配置（纯数据）。
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub paths: Paths,
    /// 本机对外的邮件主机名（`setup.json` 的 `mailHost`）。
    pub mail_host: String,
    /// 主域（`setup.json` 的 `domain`），证书目录名。
    pub domain: String,
    /// 证书/私钥路径（**尚未**装载 —— 装载在监听绑定阶段，见 `listeners`）。
    pub cert_paths: CertPaths,
    pub listeners: Vec<ListenerPlan>,
    /// 会话基底配置；每个监听在其上按端口覆盖 `offer_starttls`/`tls_active`。
    pub session: SessionConfig,
    pub relay_policy: RelayPolicy,
    pub rate_limit: RateLimitConfig,
    pub ban: BanConfig,
    pub queue_config: QueueConfig,
    pub queue_root: PathBuf,
    pub lmtp_endpoint: LmtpEndpoint,
    /// 已校验的中继端点；`None` 表示尚未配置中继（直投）。
    pub relay_endpoint: Option<RelayEndpoint>,
    /// **部署**是否允许私网目标（非公网档才允许）。决定拨号时的地址策略。
    ///
    /// 注意它和 `RelayValidationRequest::allow_private_network` 不是同一件事：后者表达
    /// 「这个中继**本身**需不需要私网许可」。两者一起才构成 INV-15 的判定。
    pub allow_private_network: bool,
}

/// 据 `Paths` 与监听端口装配运行期配置。
///
/// 全部失败都是启动期失败（见模块说明）。
pub fn assemble(paths: Paths, ports: &[u16]) -> Result<RuntimeConfig, DaemonError> {
    if ports.is_empty() {
        return Err(DaemonError::NoListeners);
    }

    // ── 1) 身份：缺失即拒绝启动 ──
    let setup = read_setup_config(&paths)
        .ok_or_else(|| DaemonError::SetupMissing(paths.setup_config.clone()))?;
    let cert_paths = CertPaths::for_domain(&paths.etc, &setup.domain)?;

    // ── 2) 设置：缺失/损坏回落到安全默认值 ──
    let settings = read_settings(&paths);

    // ── 3) 域名表：空表会被库层 fail-closed，但那是静默变砖，这里直接拒绝 ──
    let domains = TableStore::new(paths.clone()).domains();
    if domains.is_empty() {
        return Err(DaemonError::DomainTableEmpty(paths.domains.clone()));
    }

    // ── 4) 队列目录：启动时就把权限问题暴露出来 ──
    let queue_root = paths.var_lib.join("queue");
    prepare_queue_dir(&queue_root)?;

    // ── 5) 中继：区分「未配置」与「配置坏了」 ──
    let allow_private_network = !mode::is_public_mode(&paths);
    let relay_endpoint = load_relay(&paths, allow_private_network)?;

    // ── 6) 派生 ──
    let listeners: Vec<ListenerPlan> = ports.iter().copied().map(ListenerPlan::for_port).collect();

    let session = SessionConfig {
        hostname: settings.hostname.clone(),
        max_message_size: settings.max_message_size_mb as usize * 1024 * 1024,
        postmaster: Some(format!("postmaster@{}", setup.domain)),
        // SASL 是否通告由**监听计划**按端口决定（只有提交端口 465/587 开），
        // 这里只提供基底；`build_server` 会用 `plan.offer_auth` 覆盖。
        offer_auth: false,
        ..SessionConfig::default()
    };

    let queue_config = QueueConfig {
        relay_concurrency: settings.relay_concurrency,
        reporting_mta: setup.mail_host.clone(),
        managed_domains: domains.clone(),
        ..QueueConfig::default()
    };

    // 本地投递默认落箱到**自己的** LMTP 服务端（Sieve 在那里生效）；
    // 显式设置 MAILSTACK_LMTP_SOCKET/ADDR 才指向别的实现（如仍在运行的 Dovecot）。
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

/// 创建队列目录并**实际探测可写性**。
///
/// `QueueStore::enqueue` 内部走 `atomic_as`，它会 `create_dir_all(parent)`，所以缺目录
/// 并不会让写入失败 —— 那样问题要等到第一封来信才暴露。启动时探测一次，让故障早于
/// 「收到信却存不下」出现。
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

/// 读取并校验中继配置。
///
/// 返回 `Ok(None)` **只**在「配置里根本没有 relayhost」时发生。文件损坏、relayhost
/// 存在却无法通过校验，一律是错误 —— 静默退回直投会违反 INV-18/INV-21。
///
/// `deployment_allows_private` 是**部署策略**（非公网档才为真）；而请求里的
/// `allow_private_network` 表达的是「这个中继**本身**需不需要私网许可」。两者一起才
/// 构成 INV-15 的判定：`validate_relay` 只在「需要却没有」时拒绝。
fn load_relay(
    paths: &Paths,
    deployment_allows_private: bool,
) -> Result<Option<RelayEndpoint>, DaemonError> {
    let mut store = NativeRelayStore::production(paths);

    let relayhost = store
        .read_key(KEY_RELAYHOST)
        .map_err(DaemonError::RelayConfig)?;
    let Some(relayhost) = relayhost else {
        // 文件不存在或没有该键 = 尚未配置中继，这是合法状态。
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
                // 凭证映射存在但没有这一项：部分 smarthost 允许匿名，故只告警。
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
        // 请求侧的语义是「本中继需不需要私网许可」，**不是**部署策略。
        allow_private_network: host_needs_private_network(&host),
        host,
        port,
        tls_mode,
        username,
        password,
    };
    let endpoint = validate_relay(&request, deployment_allows_private).map_err(|error| {
        // 私网被拒是配置问题，给一条能直接照做的提示，而不是让运维去猜。
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

/// 该中继主机是否**字面量就落在非公网地址段**。
///
/// 主机名一律返回 `false` —— 它解析成什么地址由拨号时的 [`AddressPolicy`] 约束，
/// 配置阶段无从判断。
///
/// 判定直接复用出站侧的 `AddressPolicy::public_only()`：非公网可路由的地址集合
/// （私网、环回、链路本地、CGNAT、198.18/15 基准段等）在那一处已有唯一定义，
/// 在这里另写一份迟早会与它漂移。
fn host_needs_private_network(host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !AddressPolicy::public_only().accepts(ip),
        Err(_) => false,
    }
}

fn request_host(request: &RelayValidationRequest) -> String {
    format!("[{}]:{}", request.host, request.port)
}

/// 解析 `relayhost`：接受 `[host]:port`、`host:port` 与裸 `host`（裸 host 按 Postfix 惯例取 25）。
///
/// 方括号表示「不做 MX 解析，直接连该主机」（§5.9.5）。
fn parse_relayhost(value: &str) -> Result<(String, u16), DaemonError> {
    let value = value.trim();
    let (host_part, port) = match value.rsplit_once(':') {
        // `[::1]:25` 的最后一段是端口；`[::1]` 的最后一段落在方括号内，须排除。
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

/// 由 Postfix 语义推导中继 TLS 模式字符串（供 `validate_relay` 校验）。
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

/// 在 `sasl_passwd` 内容里找与 `(host, port)` 匹配的凭证。
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

/// 监听地址：全部网卡的 IPv4。
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

    /// 搭一个最小可用的配置根：setup + 非空域名表。
    fn root() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        std::fs::create_dir_all(paths.etc.clone()).unwrap();
        std::fs::create_dir_all(paths.postfix.clone()).unwrap();
        std::fs::write(&paths.setup_config, SETUP).unwrap();
        std::fs::write(&paths.domains, "example.org ok\n").unwrap();
        (dir, paths)
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
                offer_auth: true
            }
        );
        assert_eq!(
            by_port(587),
            ListenerPlan {
                port: 587,
                mode: TlsMode::StartTls,
                offer_starttls: true,
                offer_auth: true
            }
        );
        assert_eq!(
            by_port(25),
            ListenerPlan {
                port: 25,
                mode: TlsMode::StartTls,
                offer_starttls: true,
                // 25 是 MX 收信口，不是提交口：在那里开放认证只是多一个口令攻击面。
                offer_auth: false
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
        // 这是本模块最重要的一条：把「配置坏了」当成「没配置」会导致静默退回直投。
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
        // INV-20：465 必须走隐式 TLS，否则会以明文连 465、投递卡在队列。
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
        // 公网档下私网中继必须被拒（INV-15 的部署策略侧）。
        // 判定只由 ACCESS_MODE 决定：清掉可能影响结果的环境变量，避免测试随开发机漂移。
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

        // `direct`（面向公网）⇒ 不得使用私网中继。
        std::fs::write(&paths.install_args_conf, "ACCESS_MODE=direct\n").unwrap();
        let error = assemble(paths.clone(), &[25]).expect_err("公网档不得使用私网中继");
        assert!(matches!(error, DaemonError::Relay(_)), "实际：{error:?}");

        // `local`（仅内网）⇒ 允许私网 smarthost。
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

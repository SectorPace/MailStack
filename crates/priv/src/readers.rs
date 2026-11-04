use std::collections::BTreeSet;
use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use mailstack_core::exec::{
    is_service_active, CommandRunner, ServiceEnv, ServiceVerb, SystemCommandRunner,
    SystemServiceEnv,
};
use mailstack_core::Paths;
use mailstack_smtp::stages::{run_direct_probe, run_relay_test};
use mailstack_smtp::target::pinned_from_addresses;
use mailstack_smtp::{
    apply_relay, AddressPolicy, DnsFuture, DnsQuery, HickoryDnsQuery, NativeRelayStore,
    PinnedDialer, PinnedTarget, RelayStage, RelayTestFailure, RelayTestResult,
    RelayValidationRequest, SmtpError, StageOutcome,
};
use serde_json::{json, Value};

use crate::acme::{Acme, AcmeProbes};
use crate::handlers::{HandlerError, Registry};
use crate::users::{Users, UsersEnv};

pub const WATCHED_SERVICES: &[&str] = &["postfix", "dovecot", "fail2ban"];

pub const SERVICES: &[(&str, &str)] = &[
    ("postfix", "postfix"),
    ("dovecot", "dovecot"),
    ("opendkim", "opendkim"),
    ("fail2ban", "fail2ban"),
    ("mailstack-web", "mailstack-web"),
    ("mailstack-webmail", "mailstack-webmail"),
    ("rspamd", "rspamd"),
    ("clamav", "clamav-daemon"),
    ("redis", "redis-server"),
];

pub const LOGS_DEFAULT_LINES: usize = 200;
pub const LOGS_MAX_LINES: usize = 1000;

pub const DEFAULT_PROBE_PORT: u16 = 25;

pub const BAN_PROBE_ADDRESS: &str = "192.0.2.1";

pub const SETUP_DEFAULT_DKIM_SELECTOR: &str = "mail";

pub trait RelayProbe: Send + Sync {
    fn test<'a>(
        &'a self,
        request: &'a RelayValidationRequest,
        private_network_enabled: bool,
    ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>>;

    fn direct<'a>(
        &'a self,
        target: PinnedTarget,
    ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>>;
}

pub struct SystemRelayProbe {
    dialer: Option<PinnedDialer>,
    reason: Option<String>,
}

impl SystemRelayProbe {
    pub fn new() -> Self {
        match PinnedDialer::with_webpki_roots(Duration::from_secs(
            mailstack_smtp::CONNECT_TIMEOUT_SECS,
        )) {
            Ok(dialer) => Self {
                dialer: Some(dialer),
                reason: None,
            },
            Err(error) => {
                mailstack_core::warn::warn_with_detail(
                    "build relay TLS configuration",
                    &error.to_string(),
                );
                Self {
                    dialer: None,
                    reason: Some(error.to_string()),
                }
            }
        }
    }

    fn unavailable(&self) -> SmtpError {
        SmtpError::Tls(
            self.reason
                .clone()
                .unwrap_or_else(|| "no TLS backend available".to_string()),
        )
    }
}

impl Default for SystemRelayProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayProbe for SystemRelayProbe {
    fn test<'a>(
        &'a self,
        request: &'a RelayValidationRequest,
        private_network_enabled: bool,
    ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>> {
        match &self.dialer {
            Some(dialer) => {
                let dialer = dialer.clone();
                Box::pin(
                    async move { run_relay_test(&dialer, request, private_network_enabled).await },
                )
            }
            None => {
                let error = self.unavailable();
                Box::pin(async move { Err(probe_unavailable(error)) })
            }
        }
    }

    fn direct<'a>(
        &'a self,
        target: PinnedTarget,
    ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>> {
        match &self.dialer {
            Some(dialer) => {
                let dialer = dialer.clone();
                Box::pin(async move { run_direct_probe(&dialer, &target).await })
            }
            None => {
                let error = self.unavailable();
                Box::pin(async move { Err(probe_unavailable(error)) })
            }
        }
    }
}

struct NoRelayProbe;

impl RelayProbe for NoRelayProbe {
    fn test<'a>(
        &'a self,
        _request: &'a RelayValidationRequest,
        _private_network_enabled: bool,
    ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>> {
        Box::pin(async { Err(probe_unavailable(no_probe_error())) })
    }

    fn direct<'a>(
        &'a self,
        _target: PinnedTarget,
    ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>> {
        Box::pin(async { Err(probe_unavailable(no_probe_error())) })
    }
}

fn no_probe_error() -> SmtpError {
    SmtpError::Config("no relay probe is configured for this helper".to_string())
}

fn probe_unavailable(error: SmtpError) -> RelayTestFailure {
    RelayTestFailure {
        last_ok_stage: None,
        latency_ms: 0,
        stages: vec![StageOutcome::new(
            RelayStage::Failed,
            false,
            json!({ "message": error.kind() }),
        )],
        error,
    }
}

struct UnavailableDns {
    reason: String,
}

impl DnsQuery for UnavailableDns {
    fn lookup_a(&self, _host: &str) -> DnsFuture<'_> {
        let reason = self.reason.clone();
        Box::pin(async move { Err(SmtpError::Dns(reason)) })
    }

    fn lookup_mx_records(&self, _domain: &str) -> DnsFuture<'_> {
        let reason = self.reason.clone();
        Box::pin(async move { Err(SmtpError::Dns(reason)) })
    }

    fn lookup_txt(&self, _name: &str) -> DnsFuture<'_> {
        let reason = self.reason.clone();
        Box::pin(async move { Err(SmtpError::Dns(reason)) })
    }
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct Readers {
    paths: Paths,

    env: Arc<dyn ServiceEnv>,
    runner: Arc<dyn CommandRunner>,

    proc_root: PathBuf,
    clock: Clock,

    probe_targets: Vec<String>,

    backups: BackupEnv,

    dns: Arc<dyn DnsQuery>,

    relay: Arc<dyn RelayProbe>,

    mailtest: MailTestEnv,

    users: Users,

    acme: Acme,
}

#[derive(Clone)]
pub struct BackupEnv {
    pub root: PathBuf,

    pub restore_root: PathBuf,

    pub cipher: Arc<dyn mailstack_core::backup::BackupCipher>,

    pub home_allowlist: BTreeSet<String>,
}

impl Default for BackupEnv {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            restore_root: PathBuf::from("/"),
            cipher: Arc::new(mailstack_core::backup::GpgCipher),
            home_allowlist: BTreeSet::new(),
        }
    }
}

impl std::fmt::Debug for BackupEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupEnv")
            .field("root", &self.root)
            .field("restore_root", &self.restore_root)
            .field("home_allowlist", &self.home_allowlist)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct MailTestEnv {
    pub home_root: PathBuf,

    pub submitter: Arc<dyn crate::mailtest::MailSubmitter>,
}

impl Default for MailTestEnv {
    fn default() -> Self {
        Self {
            home_root: PathBuf::from("/"),
            submitter: Arc::new(crate::mailtest::SystemMailSubmitter::new()),
        }
    }
}

struct NoSubmitter;

impl crate::mailtest::MailSubmitter for NoSubmitter {
    fn submit<'a>(
        &'a self,
        _submission: crate::mailtest::LocalSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<crate::mailtest::SubmissionReport, String>> + Send + 'a>>
    {
        Box::pin(async { Err("no local mail submitter is configured for this helper".to_string()) })
    }
}

impl Readers {
    pub fn system(paths: Paths) -> Self {
        let dns: Arc<dyn DnsQuery> = match HickoryDnsQuery::from_system() {
            Ok(resolver) => Arc::new(resolver),
            Err(error) => {
                mailstack_core::warn::warn_with_detail("build DNS resolver", &error.to_string());
                Arc::new(UnavailableDns {
                    reason: error.to_string(),
                })
            }
        };
        let clock: Clock = Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp());
        let service_env: Arc<dyn ServiceEnv> = Arc::new(SystemServiceEnv);
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        let users = Users::new(
            paths.clone(),
            UsersEnv::default(),
            Arc::clone(&runner),
            Arc::clone(&clock),
        );
        let acme = Acme::new(
            paths.clone(),
            Arc::new(crate::acme::SystemAcmeProbes),
            Arc::clone(&service_env),
            Arc::clone(&runner),
            Arc::clone(&clock),
        );
        Self {
            paths,
            env: service_env,
            runner,
            proc_root: mailstack_core::sysinfo::system_proc_root(),
            clock,
            probe_targets: mailstack_smtp::probe::probe_targets_from_env(),
            backups: BackupEnv::default(),
            dns,
            relay: Arc::new(SystemRelayProbe::new()),
            mailtest: MailTestEnv::default(),
            users,
            acme,
        }
    }

    pub fn with_parts(
        paths: Paths,
        env: Arc<dyn ServiceEnv>,
        runner: Arc<dyn CommandRunner>,
        proc_root: PathBuf,
        clock: Clock,
        probe_targets: Vec<String>,
    ) -> Self {
        let users = Users::new(
            paths.clone(),
            UsersEnv::default(),
            Arc::clone(&runner),
            Arc::clone(&clock),
        );

        let acme = Acme::new(
            paths.clone(),
            Arc::new(crate::acme::SystemAcmeProbes),
            Arc::clone(&env),
            Arc::clone(&runner),
            Arc::clone(&clock),
        );
        Self {
            paths,
            env,
            runner,
            proc_root,
            clock,
            probe_targets,
            backups: BackupEnv::default(),

            dns: Arc::new(UnavailableDns {
                reason: "no DNS backend was injected for this test".to_string(),
            }),
            relay: Arc::new(NoRelayProbe),
            mailtest: MailTestEnv {
                home_root: PathBuf::from("/"),
                submitter: Arc::new(NoSubmitter),
            },
            users,
            acme,
        }
    }

    pub fn with_users_env(mut self, env: UsersEnv) -> Self {
        self.users = self.users.with_env(env);
        self
    }

    pub fn with_acme_probes(mut self, probes: Arc<dyn AcmeProbes>) -> Self {
        self.acme = self.acme.with_probes(probes);
        self
    }

    pub fn with_backup_env(mut self, backups: BackupEnv) -> Self {
        self.backups = backups;
        self
    }

    pub fn with_dns(mut self, dns: Arc<dyn DnsQuery>) -> Self {
        self.dns = dns;
        self
    }

    pub fn with_relay_probe(mut self, relay: Arc<dyn RelayProbe>) -> Self {
        self.relay = relay;
        self
    }

    pub fn with_mailtest_env(mut self, mailtest: MailTestEnv) -> Self {
        self.mailtest = mailtest;
        self
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    fn now_dt(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.now())
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
    }

    fn queue(&self) -> mailstack_queue::QueueStore {
        mailstack_queue::QueueStore::from_paths(&self.paths)
    }

    fn tables(&self) -> mailstack_store::TableStore {
        mailstack_store::TableStore::new(self.paths.clone())
    }

    fn service_items(&self) -> Vec<Value> {
        SERVICES
            .iter()
            .map(|(id, unit)| {
                let mut pid: u64 = 0;
                let mut memory_mb = 0.0_f64;
                let mut uptime = String::new();
                let active = if self.systemd_available() {
                    match self.runner.run(
                        "systemctl",
                        &[
                            "show",
                            unit,
                            "--property=ActiveState,MainPID,MemoryCurrent,ActiveEnterTimestamp",
                            "--no-pager",
                        ],
                    ) {
                        Ok(output) => {
                            pid = parse_u64(systemd_property(&output.stdout, "MainPID"));
                            memory_mb = round1(
                                parse_u64(systemd_property(&output.stdout, "MemoryCurrent")) as f64
                                    / 1_048_576.0,
                            );
                            uptime = systemd_property(&output.stdout, "ActiveEnterTimestamp")
                                .unwrap_or_default()
                                .to_string();
                            systemd_property(&output.stdout, "ActiveState") == Some("active")
                        }
                        Err(_) => is_service_active(self.env.as_ref(), self.runner.as_ref(), unit),
                    }
                } else {
                    is_service_active(self.env.as_ref(), self.runner.as_ref(), unit)
                };

                json!({
                    "id": id,
                    "name": unit,
                    "description": unit,
                    "type": format!("{unit}.service"),
                    "pid": pid,
                    "uptime": uptime,
                    "memoryMb": memory_mb,
                    "cpuPercent": 0,
                    "status": if active { "ACTIVE" } else { "STOPPED" },
                    "ports": [],
                })
            })
            .collect()
    }

    fn systemd_available(&self) -> bool {
        self.env.program_available("systemctl")
            && self.env.path_exists(Path::new("/run/systemd/system"))
    }

    fn queue_items(&self) -> Vec<Value> {
        let now = self.now();
        let mut items: Vec<Value> = self
            .queue()
            .load_all()
            .unwrap_or_default()
            .into_iter()
            .map(|entry| queue_item_json(&entry, now))
            .collect();
        items.sort_by_key(|item| item["id"].as_str().unwrap_or_default().to_string());
        items
    }

    pub fn certs_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let infos = mailstack_core::certs::list_certificates(&self.paths.etc, self.now_dt());

        let expiring: Vec<Value> = infos
            .iter()
            .filter(|c| c.expires_within(EXPIRY_WARNING_DAYS))
            .cloned()
            .map(certificate_to_json)
            .collect();

        Ok(json!({
            "ok": true,
            "generatedAt": mailstack_core::time_fmt::format_iso8601(self.now_dt()),
            "expiryWarningDays": EXPIRY_WARNING_DAYS,
            "certificates": infos.into_iter().map(certificate_to_json).collect::<Vec<_>>(),
            "expiringSoon": expiring,
        }))
    }

    pub fn metrics_realtime(&self, _data: &Value) -> Result<Value, HandlerError> {
        let mut unavailable: Vec<&str> = Vec::new();

        let load = match mailstack_core::sysinfo::read_loadavg(&self.proc_root) {
            Some(l) => json!({ "one": l.one, "five": l.five, "fifteen": l.fifteen }),
            None => {
                unavailable.push("load");
                Value::Null
            }
        };
        let memory = match mailstack_core::sysinfo::read_meminfo(&self.proc_root) {
            Some(m) => json!({
                "totalBytes": m.total_bytes,
                "availableBytes": m.available_bytes,
            }),
            None => {
                unavailable.push("memory");
                Value::Null
            }
        };
        let uptime = mailstack_core::sysinfo::read_uptime_secs(&self.proc_root);
        if uptime.is_none() {
            unavailable.push("uptime");
        }

        let queue = self.queue_summary();

        Ok(json!({
            "ok": true,
            "time": mailstack_core::time_fmt::format_iso8601(self.now_dt()),
            "uptimeSec": uptime,
            "load": load,
            "memory": memory,
            "queue": queue,
            "services": self.service_items(),
            "unavailable": unavailable,
        }))
    }

    fn queue_summary(&self) -> Value {
        let store = self.queue();
        let mut unavailable: Vec<&'static str> = Vec::new();
        let entries = match store.load_all() {
            Ok(entries) => entries,
            Err(error) => {
                mailstack_core::warn::warn_with_detail("read queue entries", &error.to_string());
                unavailable.push("backlog");
                Vec::new()
            }
        };
        let health_state = store.load_health().unwrap_or_default();
        let relay = read_relay_host(&self.paths);
        let health = mailstack_queue::outbound_health_from(
            health_state.consecutive_failures,
            mailstack_queue::DEFAULT_BLOCKED_THRESHOLD,
            relay.as_deref(),
        );

        let corrupt = std::fs::read_dir(store.corrupt_dir())
            .map(|read| read.flatten().count())
            .unwrap_or_else(|error| {
                mailstack_core::warn::warn_with_detail(
                    "read queue corrupt dir",
                    &error.to_string(),
                );
                unavailable.push("corrupt");
                0
            });

        json!({
            "backlog": entries.len(),
            "corrupt": corrupt,
            "relayHost": relay,
            "outboundHealth": {
                "consecutiveFailures": health.consecutive_failures,
                "blocked": health.blocked,
                "needsRelay": health.needs_relay,
                "message": health.message,
                "lastSuccessAt": health_state.last_success_at,
                "lastFailure": health_state.last_failure,
            },

            "unavailable": unavailable,
        })
    }

    pub fn snapshot(&self, _data: &Value) -> Result<Value, HandlerError> {
        let tables = self.tables();

        let domains = mailstack_core::atomic::try_rows(&self.paths.domains)
            .map_err(|error| {
                HandlerError::new(format!("managed domain table is unreadable: {error}"))
            })?
            .into_iter()
            .filter_map(|row| {
                let name = row.first()?.clone();
                Some(json!({ "name": name, "target": row.get(1).cloned().unwrap_or_default() }))
            })
            .collect::<Vec<_>>();
        let aliases: Vec<Value> = tables
            .aliases()
            .into_iter()
            .map(|a| json!({ "source": a.source, "destinations": a.destinations }))
            .collect();

        let setup = mailstack_core::config::read_setup_config(&self.paths);
        let admin = mailstack_core::config::admin_public(&self.paths);

        Ok(json!({
            "ok": true,
            "generatedAt": mailstack_core::time_fmt::format_iso8601(self.now_dt()),
            "version": mailstack_core::VERSION,
            "identity": setup,
            "admin": {
                "passwordConfigured": admin.password_configured,
                "twoFactorEnabled": admin.two_factor_enabled,
                "recoveryCodesRemaining": admin.recovery_codes_remaining,
            },
            "domains": domains,
            "aliases": aliases,
            "queue": self.queue_summary(),
            "queues": self.queue_items(),
            "certificates": mailstack_core::certs::list_certificates(&self.paths.etc, self.now_dt())
                .into_iter()
                .map(certificate_to_json)
                .collect::<Vec<_>>(),
            "services": self.service_items(),

            "unavailable": Vec::<String>::new(),
        }))
    }

    pub fn logs_list(&self, data: &Value) -> Result<Value, HandlerError> {
        let lines = clamp_lines(data);
        let unit = data.get("unit").and_then(Value::as_str).map(str::to_string);

        let mut args: Vec<String> = vec![
            "--no-pager".to_string(),
            "--output=json".to_string(),
            "--lines".to_string(),
            lines.to_string(),
        ];
        if let Some(unit) = &unit {
            args.push("--unit".to_string());
            args.push(unit.clone());
        }
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();

        match self.runner.run("journalctl", &borrowed) {
            Ok(output) if output.success() => {
                let entries: Vec<Value> = output
                    .stdout
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .map(|raw| journal_entry_to_json(&raw))
                    .collect();
                Ok(json!({
                    "ok": true,
                    "available": true,
                    "lines": lines,
                    "unit": unit,
                    "entries": entries,
                }))
            }
            Ok(output) => Ok(json!({
                "ok": true,
                "available": false,
                "reason": output.diagnostic("journalctl"),
                "lines": lines,
                "unit": unit,
                "entries": [],
            })),
            Err(e) => Ok(json!({
                "ok": true,
                "available": false,
                "reason": e.to_string(),
                "lines": lines,
                "unit": unit,
                "entries": [],
            })),
        }
    }

    pub async fn network_check_port(&self, data: &Value) -> Result<Value, HandlerError> {
        let port = match data.get("port") {
            None | Some(Value::Null) => DEFAULT_PROBE_PORT,
            Some(value) => {
                let port = value
                    .as_u64()
                    .filter(|p| (1..=65535).contains(p))
                    .ok_or_else(|| HandlerError::new("port must be an integer in 1..=65535"))?;
                port as u16
            }
        };

        let result =
            mailstack_smtp::probe::probe_outbound_port_with(port, self.probe_targets.clone()).await;
        let verdict = mailstack_smtp::probe::direct_mode_verdict(&result);
        let mut payload = result.to_json();
        payload["ok"] = json!(true);
        payload["verdict"] = json!({
            "mode": verdict.as_str(),
            "recommendsDirect": verdict.recommends_direct(),
        });
        Ok(payload)
    }

    pub fn system_doctor(&self, _data: &Value) -> Result<Value, HandlerError> {
        let mut checks: Vec<Value> = Vec::new();

        let setup = mailstack_core::config::read_setup_config(&self.paths);
        checks.push(match &setup {
            Some(s) => {
                let valid = mailstack_core::config::validate_setup_identity(
                    &s.domain,
                    &s.mail_host,
                    &s.dkim_selector,
                )
                .is_ok();
                check(
                    "identity",
                    valid,
                    if valid {
                        format!("{} ({})", s.domain, s.mail_host)
                    } else {
                        "identity fields are inconsistent".to_string()
                    },
                )
            }
            None => check("identity", false, "setup.json is missing or unreadable"),
        });

        let admin = mailstack_core::config::admin_public(&self.paths);
        checks.push(check(
            "admin_credentials",
            admin.password_configured,
            if admin.password_configured {
                format!(
                    "password set; two-factor {}",
                    if admin.two_factor_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                )
            } else {
                "no administrator password is configured".to_string()
            },
        ));

        let domains = mailstack_core::atomic::try_rows(&self.paths.domains);
        checks.push(match domains {
            Ok(rows) => {
                let names: Vec<String> = rows
                    .into_iter()
                    .filter_map(|row| row.into_iter().next())
                    .collect();
                check(
                    "domain_table",
                    !names.is_empty(),
                    if names.is_empty() {
                        "domain table is empty: every recipient will be refused (INV-17)"
                            .to_string()
                    } else {
                        format!("{} domain(s)", names.len())
                    },
                )
            }
            Err(error) => check(
                "domain_table",
                false,
                format!("domain table is unavailable: {error}"),
            ),
        });

        checks.push(self.relay_check());

        checks.push(self.dkim_check(setup.as_ref()));

        checks.push(self.tls_check());

        let verdict = mailstack_core::audit::audit_verify(&self.paths.audit_log);
        checks.push(check(
            "audit_chain",
            verdict.ok,
            if verdict.ok {
                format!("{} chained entries", verdict.entries)
            } else {
                verdict.error.clone()
            },
        ));

        checks.push(self.ban_probe());

        let healthy = checks.iter().all(|c| c["ok"] == json!(true));
        Ok(json!({ "ok": true, "healthy": healthy, "checks": checks }))
    }

    fn relay_check(&self) -> Value {
        match std::fs::read_to_string(&self.paths.relay_config) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => check(
                "relay_config",
                true,
                "no relay configured (direct delivery)",
            ),
            Err(e) => check(
                "relay_config",
                false,
                format!("cannot read relay.json: {e}"),
            ),
            Ok(text) => match serde_json::from_str::<Value>(&text) {
                Ok(_) => check("relay_config", true, "relay.json is parseable"),
                Err(e) => check("relay_config", false, format!("relay.json is corrupt: {e}")),
            },
        }
    }

    fn dkim_check(&self, setup: Option<&mailstack_core::config::SetupConfig>) -> Value {
        let Some(setup) = setup else {
            return check("dkim_key", false, "cannot check without an identity");
        };
        let path = mailstack_auth::keys::private_key_path(
            &self.paths,
            &setup.domain,
            &setup.dkim_selector,
        );
        if path.is_file() {
            check("dkim_key", true, path.display().to_string())
        } else {
            check(
                "dkim_key",
                false,
                format!(
                    "missing private key for outbound signing: {}",
                    path.display()
                ),
            )
        }
    }

    fn tls_check(&self) -> Value {
        let Some(setup) = &mailstack_core::config::read_setup_config(&self.paths) else {
            return check("tls_certificate", false, "cannot check without an identity");
        };
        let info = mailstack_core::certs::read_certificate(
            &self.paths.etc,
            &setup.mail_host,
            self.now_dt(),
        );
        if !info.cert_present {
            return check(
                "tls_certificate",
                false,
                format!("no certificate for {}", setup.mail_host),
            );
        }
        if let Some(error) = &info.error {
            return check("tls_certificate", false, error.clone());
        }
        match info.days_until_expiry {
            Some(days) if days > 0 => {
                check("tls_certificate", true, format!("expires in {days} day(s)"))
            }
            Some(days) => check(
                "tls_certificate",
                false,
                format!("certificate expired {} day(s) ago", -days),
            ),
            None => check("tls_certificate", false, "expiry could not be determined"),
        }
    }

    fn ban_probe(&self) -> Value {
        let Ok(ip) = BAN_PROBE_ADDRESS.parse::<IpAddr>() else {
            return check("ban_round_trip", false, "probe address is not an IP");
        };

        let config = mailstack_smtpd::ban::BanConfig::default();
        let bans = mailstack_smtpd::ban::BanList::new(config);
        let now = self.now();

        for _ in 0..config.max_failures {
            bans.record_failure(ip, now);
        }
        let banned = bans.check(ip, now).is_some();
        let removed = bans.unban(ip);
        let cleared = bans.check(ip, now).is_none();

        let ok = banned && removed && cleared;
        check(
            "ban_round_trip",
            ok,
            if ok {
                format!("{BAN_PROBE_ADDRESS} banned, observed and unbanned")
            } else {
                format!("banned={banned} unban_removed={removed} cleared={cleared}")
            },
        )
    }

    pub fn security_scan(&self, _data: &Value) -> Result<Value, HandlerError> {
        let report = mailstack_core::security::scan(&self.security_inventory()?);
        let count = |severity| {
            report
                .findings
                .iter()
                .filter(|f| f.severity == severity)
                .count()
        };

        Ok(json!({
            "ok": true,
            "scannedAt": mailstack_core::time_fmt::format_iso8601(self.now_dt()),

            "scanned": report.scanned,
            "absent": report.absent.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "findings": report.findings.iter().map(finding_to_json).collect::<Vec<_>>(),
            "summary": {
                "high": count(mailstack_core::security::Severity::High),
                "medium": count(mailstack_core::security::Severity::Medium),
                "info": count(mailstack_core::security::Severity::Info),
            },
            "highestSeverity": report.highest_severity().map(|s| s.as_str()),

            "bannedIps": self.manual_bans_json(),
            "bannedIpScope": "manual",
        }))
    }

    fn manual_bans_json(&self) -> Value {
        let store = mailstack_core::bans::ManualBanStore::from_paths(&self.paths);
        match store.load() {
            Ok(None) => Value::Array(Vec::new()),
            Ok(Some(bans)) => Value::Array(
                bans.into_iter()
                    .map(|ban| {
                        json!({
                            "ip": ban.ip.to_string(),

                            "jail": "manual",
                            "time": ban.banned_at,
                            "reason": ban.note.unwrap_or_default(),
                        })
                    })
                    .collect(),
            ),
            Err(error) => {
                mailstack_core::warn::warn_with_detail("read manual bans", &error.to_string());
                Value::Null
            }
        }
    }

    fn security_inventory(
        &self,
    ) -> Result<Vec<mailstack_core::security::SensitivePath>, HandlerError> {
        use mailstack_core::security::SensitivePath;

        let p = &self.paths;
        let mut list = vec![
            SensitivePath::new(
                p.etc.clone(),
                0o750,
                false,
                "配置目录：放宽它会让外人看到有哪几个文件，但读不到内容",
            ),
            SensitivePath::new(
                p.admin_config.clone(),
                0o640,
                true,
                "管理员口令哈希与 2FA 信封",
            ),
            SensitivePath::new(p.settings_config.clone(), 0o640, false, "管理台设置"),
            SensitivePath::new(
                p.setup_config.clone(),
                0o600,
                true,
                "身份、DKIM 选择器与公钥",
            ),
            SensitivePath::new(
                p.totp_key.clone(),
                0o600,
                true,
                "TOTP 主密钥：只有特权进程该读到它",
            ),
            SensitivePath::new(p.relay_config.clone(), 0o600, true, "中继凭证"),
            SensitivePath::new(p.audit_log.clone(), 0o600, true, "审计日志"),
            SensitivePath::new(
                p.domains.clone(),
                0o644,
                false,
                "虚拟域名表（Postfix 要读）",
            ),
            SensitivePath::new(p.aliases.clone(), 0o644, false, "别名表（Postfix 要读）"),
            SensitivePath::new(
                p.manual_bans.clone(),
                0o600,
                true,
                "手工封禁表：可写它就能放行已被封禁的主机",
            ),
        ];

        let sasl = mailstack_smtp::relay_store::PostfixRelayStore::production().sasl_passwd;
        list.push(SensitivePath::new(
            sasl,
            0o600,
            true,
            "Postfix sasl_passwd：明文口令",
        ));

        for domain in self.managed_domains()? {
            let dir = mailstack_auth::keys::dkim_key_dir(&self.paths, &domain);
            let Ok(read) = std::fs::read_dir(&dir) else {
                continue;
            };
            for item in read.flatten() {
                let path = item.path();
                if path.extension().and_then(|e| e.to_str()) != Some("private") {
                    continue;
                }
                list.push(SensitivePath::new(
                    path,
                    0o640,
                    true,
                    "DKIM 私钥：签名身份，泄露即可被冒名签发",
                ));
            }
        }

        for info in mailstack_core::certs::list_certificates(&self.paths.etc, self.now_dt()) {
            if info.key_present {
                list.push(SensitivePath::new(info.key_path, 0o600, true, "TLS 私钥"));
            }
        }

        Ok(list)
    }

    pub fn backup_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let store = mailstack_core::backup::BackupStore::from_paths(&self.paths);
        let items = store
            .list()
            .into_iter()
            .map(|metadata| {
                let mut value = serde_json::to_value(&metadata)?;
                if let Value::Object(map) = &mut value {
                    map.insert("empty".to_string(), Value::Bool(metadata.size == 0));
                }
                Ok(value)
            })
            .collect::<Result<Vec<Value>, serde_json::Error>>()?;
        Ok(Value::Array(items))
    }

    pub fn backup_create(&self, data: &Value) -> Result<Value, HandlerError> {
        let include_mails = flag(data, "includeMails");
        let include_secrets = flag(data, "includeSecrets");
        let allow_partial = flag(data, "allowPartial");
        let passphrase = crate::handlers::optional_str(data, "passphrase")
            .unwrap_or("")
            .to_string();

        if mailstack_core::mode::is_public_mode(&self.paths) && passphrase.is_empty() {
            return Err(HandlerError::new(
                "backup.create requires a passphrase in public mode; plaintext backups are local-mode only",
            ));
        }

        let (mail_dirs, mail_warnings) = if include_mails {
            self.users.managed_maildirs()?
        } else {
            (Vec::new(), Vec::new())
        };
        if include_mails && mail_dirs.is_empty() {
            return Err(HandlerError::new(format!(
                "backup.create was asked to include mail, but no managed mailbox Maildir was found ({})",
                if mail_warnings.is_empty() {
                    "no managed mailboxes are registered".to_string()
                } else {
                    mail_warnings.join("; ")
                }
            )));
        }

        let sources =
            mailstack_core::backup::default_sources(&self.backups.root, include_mails, &mail_dirs);
        if sources.is_empty() {
            return Err(HandlerError::new(
                "No configuration sources were found for backup",
            ));
        }

        let store = mailstack_core::backup::BackupStore::from_paths(&self.paths);
        let mut name = format!(
            "mailstack-backup-{}.tar.gz",
            backup_timestamp(self.now_dt())
        );
        if store.dir().join(&name).exists() {
            name = format!(
                "mailstack-backup-{}-{}.tar.gz",
                backup_timestamp(self.now_dt()),
                collision_suffix()
            );
        }
        let target = store.dir().join(&name);
        let excludes: &[&str] = if include_secrets {
            &[]
        } else {
            mailstack_core::backup::SECRET_EXCLUDES
        };
        let partial = match mailstack_core::backup::create_archive(
            &self.backups.root,
            &sources,
            &target,
            excludes,
            allow_partial,
        ) {
            Ok(partial) => partial,
            Err(error) => {
                let _ = std::fs::remove_file(&target);
                return Err(HandlerError::new(error.to_string()));
            }
        };

        let partial = partial || !mail_warnings.is_empty();

        let encrypted = if passphrase.is_empty() {
            false
        } else {
            mailstack_core::backup::encrypt_in_place(
                &target,
                &passphrase,
                self.backups.cipher.as_ref(),
            )?;
            true
        };

        let metadata = mailstack_core::backup::BackupMetadata {
            name: name.clone(),
            filename: name,
            path: target.display().to_string(),
            size: std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0),
            sha256: Some(mailstack_core::backup::file_sha256(&target)?),
            created_at: mailstack_core::time_fmt::format_iso8601(self.now_dt()),
            include_mails,
            include_secrets,
            partial,
            encrypted,
            version: mailstack_core::VERSION.to_string(),
            metadata_missing: false,
        };
        store.write_metadata(&metadata)?;
        Ok(json!({
            "created": true,
            "backup": metadata,

            "warnings": mail_warnings,
        }))
    }

    pub fn backup_restore(&self, data: &Value) -> Result<Value, HandlerError> {
        let name = crate::handlers::first_str(data, &["filename", "name"])?;
        let store = mailstack_core::backup::BackupStore::from_paths(&self.paths);
        let target = store.resolve(name)?;
        let dry_run = flag(data, "dryRun");
        let passphrase = crate::handlers::optional_str(data, "passphrase")
            .unwrap_or("")
            .to_string();

        if !dry_run && data.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Err(HandlerError::new("Explicit confirmation is required"));
        }
        if !dry_run && mailstack_core::mode::is_public_mode(&self.paths) && passphrase.is_empty() {
            return Err(HandlerError::new(
                "backup.restore requires a passphrase in public mode: the pre-restore snapshot is encrypted with it",
            ));
        }

        let options = mailstack_core::backup::RestoreOptions {
            passphrase: Some(passphrase.clone()).filter(|p| !p.is_empty()),
            allow_partial_restore: flag(data, "allowPartialRestore"),
            dry_run,
        };

        let home_allowlist = self.home_allowlist()?;
        let outcome = mailstack_core::backup::restore_archive(
            &store,
            &target,
            &self.backups.restore_root,
            &options,
            &home_allowlist,
            self.backups.cipher.as_ref(),
        )?;

        if dry_run {
            return Ok(json!({
                "dryRun": true,
                "target": target.display().to_string(),
                "filesCount": outcome.files_count,
                "previewFiles": outcome.preview_files,
                "ready": true,
                "sha256": outcome.sha256,
                "encrypted": store.describe(&target).encrypted,
            }));
        }

        let snapshot = self.pre_restore_snapshot(&store, &passphrase, &home_allowlist);
        self.reload_after_restore();
        Ok(json!({
            "restored": true,
            "filename": name,
            "filesCount": outcome.files_count,
            "restoredFiles": outcome
                .restored_files
                .iter()
                .take(20)
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
            "preRestoreSnapshot": snapshot.0,
            "preRestoreSnapshotWarning": snapshot.1,
            "sha256": outcome.sha256,

            "restartRequired": true,
        }))
    }

    pub fn backup_delete(&self, data: &Value) -> Result<Value, HandlerError> {
        if data.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Err(HandlerError::new("Explicit confirmation is required"));
        }
        let name = crate::handlers::first_str(data, &["filename", "name"])?;
        let store = mailstack_core::backup::BackupStore::from_paths(&self.paths);
        store.delete(name)?;
        Ok(json!({ "deleted": true, "filename": name }))
    }

    fn home_allowlist(&self) -> Result<BTreeSet<String>, HandlerError> {
        let mut allow = self.backups.home_allowlist.clone();
        allow.extend(self.users.managed_accounts()?);
        Ok(allow)
    }

    fn pre_restore_snapshot(
        &self,
        store: &mailstack_core::backup::BackupStore,
        passphrase: &str,
        home_allowlist: &BTreeSet<String>,
    ) -> (Option<String>, Option<String>) {
        let sources = mailstack_core::backup::default_sources(&self.backups.root, false, &[]);
        if sources.is_empty() {
            return (
                None,
                Some("no configuration sources to snapshot".to_string()),
            );
        }
        let name = format!(
            "mailstack-backup-{}-pre-restore.tar.gz",
            backup_timestamp(self.now_dt())
        );
        let snapshot = store.dir().join(&name);

        let created = mailstack_core::backup::create_archive(
            &self.backups.root,
            &sources,
            &snapshot,
            &[],
            true,
        );
        let mut warning = match created {
            Ok(_) => None,
            Err(error) => Some(format!("pre-restore snapshot failed: {error}")),
        };
        if warning.is_none() {
            if let Err(error) = mailstack_core::backup::validate_archive(&snapshot, home_allowlist)
            {
                warning = Some(format!(
                    "pre-restore snapshot failed the readability check: {error}"
                ));
            }
        }
        if let Some(warning) = warning {
            let _ = std::fs::remove_file(&snapshot);
            mailstack_core::warn::warn_with_detail("pre-restore snapshot", &warning);
            return (None, Some(warning));
        }

        let encrypted = if passphrase.is_empty() {
            false
        } else if let Err(error) = mailstack_core::backup::encrypt_in_place(
            &snapshot,
            passphrase,
            self.backups.cipher.as_ref(),
        ) {
            let _ = std::fs::remove_file(&snapshot);
            return (
                None,
                Some(format!("pre-restore snapshot encryption failed: {error}")),
            );
        } else {
            true
        };

        let metadata = mailstack_core::backup::BackupMetadata {
            name: name.clone(),
            filename: name,
            path: snapshot.display().to_string(),
            size: std::fs::metadata(&snapshot).map(|m| m.len()).unwrap_or(0),
            sha256: mailstack_core::backup::file_sha256(&snapshot).ok(),
            created_at: mailstack_core::time_fmt::format_iso8601(self.now_dt()),
            include_mails: false,
            include_secrets: true,
            partial: false,
            encrypted,
            version: mailstack_core::VERSION.to_string(),
            metadata_missing: false,
        };
        if let Err(error) = store.write_metadata(&metadata) {
            mailstack_core::warn::warn_with_detail(
                "pre-restore snapshot metadata",
                &error.to_string(),
            );
        }
        (Some(snapshot.display().to_string()), None)
    }

    fn reload_after_restore(&self) {
        for (unit, verb) in [
            ("postfix", ServiceVerb::Reload),
            ("dovecot", ServiceVerb::Reload),
            ("opendkim", ServiceVerb::Restart),
        ] {
            let outcome = mailstack_core::exec::service_ctl(
                self.env.as_ref(),
                self.runner.as_ref(),
                unit,
                verb,
            );
            if !outcome.success() {
                mailstack_core::warn::warn_with_detail(
                    "reload after restore",
                    &format!("{unit} {} did not succeed", verb.as_str()),
                );
            }
        }
    }

    pub fn services_action(&self, data: &Value) -> Result<Value, HandlerError> {
        let ident = crate::handlers::first_str(data, &["id", "name", "service", "key"])?;

        let verb = ["verb", "action", "op"]
            .iter()
            .find_map(|key| crate::handlers::optional_str(data, key))
            .ok_or_else(|| {
                HandlerError::new("missing required field (one of [\"verb\", \"action\", \"op\"])")
            })?
            .trim()
            .to_ascii_lowercase();
        let unit = resolve_service_unit(ident)
            .ok_or_else(|| HandlerError::new(format!("invalid service: {ident}")))?;

        if verb == "status" {
            return Ok(Value::Array(self.service_items()));
        }

        let parsed = ServiceVerb::parse(&verb)
            .ok_or_else(|| HandlerError::new(format!("invalid service verb: {verb}")))?;

        if unit == "mailstack-web" && parsed == ServiceVerb::Stop {
            return Err(HandlerError::new(
                "refusing to stop the admin console from itself; run \"systemctl stop mailstack-web\" from a shell",
            ));
        }

        let outcome = mailstack_core::exec::service_ctl(
            self.env.as_ref(),
            self.runner.as_ref(),
            unit,
            parsed,
        );
        if !outcome.success() {
            let detail = outcome
                .output
                .as_ref()
                .map(|output| output.diagnostic(parsed.as_str()))
                .or_else(|| outcome.failure_reason())
                .unwrap_or_else(|| "command failed".to_string());
            return Err(HandlerError::new(format!(
                "{} {}: {}",
                parsed.as_str(),
                unit,
                detail
            )));
        }

        Ok(Value::Array(self.service_items()))
    }

    pub fn security_ban(&self, data: &Value) -> Result<Value, HandlerError> {
        let ip = ban_target(data)?;
        let note = crate::handlers::optional_str(data, "note")
            .or_else(|| crate::handlers::optional_str(data, "reason"));
        let store = mailstack_core::bans::ManualBanStore::from_paths(&self.paths);
        let now = mailstack_core::time_fmt::format_iso8601(self.now_dt());
        let bans = store.add(ip, note, &now)?;

        Ok(json!({
            "ok": true,
            "banned": ip.to_string(),
            "manual": true,
            "scope": "global",
            "count": bans.len(),
            "takesEffectAfterReload": true,
        }))
    }

    pub fn security_unban(&self, data: &Value) -> Result<Value, HandlerError> {
        let ip = ban_target(data)?;
        let store = mailstack_core::bans::ManualBanStore::from_paths(&self.paths);
        let bans = store.remove(ip)?;

        Ok(json!({
            "ok": true,
            "unbanned": ip.to_string(),
            "count": bans.len(),
            "takesEffectAfterReload": true,
        }))
    }

    pub fn queue_action(&self, data: &Value) -> Result<Value, HandlerError> {
        let store = self.queue();

        let verb = ["verb", "action", "op"]
            .iter()
            .find_map(|key| crate::handlers::optional_str(data, key))
            .ok_or_else(|| {
                HandlerError::new("missing required field (one of [\"verb\", \"action\", \"op\"])")
            })?
            .trim()
            .to_ascii_lowercase();

        let verb = match verb.as_str() {
            "deliver" => "retry".to_string(),

            other => other.to_string(),
        };
        let now = self.now();

        match verb.as_str() {
            "flush" => {
                for mut entry in store.load_all()? {
                    if entry.next_attempt_unix > now {
                        entry.next_attempt_unix = now;
                        store.enqueue(&entry)?;
                    }
                }
                Ok(Value::Array(self.queue_items()))
            }
            "retry" | "delete" => {
                let id = crate::handlers::first_str(data, &["id", "queueId"])?
                    .trim_end_matches(['*', '!']);
                if !mailstack_queue::entry::is_safe_id(id) {
                    return Err(HandlerError::new(format!("invalid queue id: {id:?}")));
                }
                if verb == "delete" {
                    store.remove(id)?;
                } else {
                    let found = store.load_all()?.into_iter().find(|entry| entry.id == id);
                    let Some(mut entry) = found else {
                        return Err(HandlerError::new(format!("no such queue entry: {id}")));
                    };
                    entry.attempts = 0;
                    entry.next_attempt_unix = now;
                    entry.last_error = None;
                    entry.last_code = None;
                    store.enqueue(&entry)?;
                }
                Ok(Value::Array(self.queue_items()))
            }
            other => Err(HandlerError::new(format!("invalid queue action: {other}"))),
        }
    }

    pub fn setup_identity_apply(&self, data: &Value) -> Result<Value, HandlerError> {
        let domain = crate::handlers::first_str(data, &["domain"])?
            .trim()
            .to_ascii_lowercase();
        let mail_host = crate::handlers::first_str(data, &["mailHost", "mail_host"])?
            .trim()
            .to_ascii_lowercase();
        let server_ip = setup_server_ip(data)?;
        let selector = setup_selector(data);

        mailstack_core::config::validate_setup_identity(&domain, &mail_host, &selector)?;

        let rotation = mailstack_auth::keys::rotate(&self.paths, &domain, Some(&selector))?;

        let config = mailstack_core::config::SetupConfig {
            domain,
            mail_host,
            server_ip,
            dkim_selector: rotation.selector.clone(),
            expected_spf: setup_expected_spf(data),
            wizard_completed: false,
            updated_at: mailstack_core::now_iso8601_utc(),
        };
        mailstack_core::config::write_setup_config(&self.paths, &config)?;

        Ok(json!({
            "applied": true,
            "identity": config,
            "dkimPublicKey": rotation.public_key_spki_b64,
        }))
    }

    pub async fn setup_dns_verify(&self, data: &Value) -> Result<Value, HandlerError> {
        let domain = crate::handlers::first_str(data, &["domain"])?
            .trim()
            .to_ascii_lowercase();
        let mail_host = crate::handlers::first_str(data, &["mailHost", "mail_host"])?
            .trim()
            .to_ascii_lowercase();
        let server_ip = setup_server_ip(data)?;
        let selector = setup_selector(data);
        mailstack_core::config::validate_setup_identity(&domain, &mail_host, &selector)?;

        let expected = setup_expected_spf(data);
        let relay = crate::handlers::optional_str(data, "selectedRelay")
            .unwrap_or("direct")
            .trim()
            .to_ascii_lowercase();
        let ses_from = crate::handlers::optional_str(data, "sesMailFrom")
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let ses_region = crate::handlers::optional_str(data, "sesRegion")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("us-east-1")
            .to_string();

        let a = self.dns.lookup_a(&mail_host).await?;
        let mx = self.dns.lookup_mx_records(&domain).await?;
        let spf = self.dns.lookup_txt(&domain).await?;
        let dkim = self
            .dns
            .lookup_txt(&format!("{selector}._domainkey.{domain}"))
            .await?;
        let dmarc = self.dns.lookup_txt(&format!("_dmarc.{domain}")).await?;

        let spf_records: Vec<&String> = spf
            .iter()
            .filter(|item| item.starts_with("v=spf1"))
            .collect();

        let mut checks = serde_json::Map::new();

        checks.insert("a".to_string(), json!(a.iter().any(|ip| ip == &server_ip)));

        checks.insert("mx".to_string(), json!(mx_records_contain(&mx, &mail_host)));

        checks.insert("spfSingle".to_string(), json!(spf_records.len() == 1));

        let expected_spf = expected
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("v=spf1 mx -all");
        checks.insert(
            "spfExpected".to_string(),
            json!(spf_records
                .iter()
                .any(|record| record.trim() == expected_spf)),
        );
        checks.insert(
            "dkim".to_string(),
            json!(dkim.iter().any(|item| has_dkim_public_key(item))),
        );
        checks.insert(
            "dmarc".to_string(),
            json!(dmarc
                .iter()
                .any(|item| item.starts_with("v=DMARC1") && item.contains("rua=mailto:"))),
        );

        let mut observed = json!({
            "a": a,
            "mx": mx,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
        });

        if relay == "ses" {
            let (ses_mx, ses_spf) = if ses_from.is_empty() {
                (Vec::new(), Vec::new())
            } else {
                (
                    self.dns.lookup_mx_records(&ses_from).await?,
                    self.dns.lookup_txt(&ses_from).await?,
                )
            };

            let ses_mx_host = format!("feedback-smtp.{ses_region}.amazonses.com");
            let mx_ok = mx_records_contain(&ses_mx, &ses_mx_host);
            let spf_ok = {
                let records: Vec<&String> = ses_spf
                    .iter()
                    .filter(|item| item.starts_with("v=spf1"))
                    .collect();
                records.len() == 1 && records[0].contains("include:amazonses.com")
            };
            checks.insert("sesMailFromMx".to_string(), json!(mx_ok));
            checks.insert("sesMailFromSpf".to_string(), json!(spf_ok));
            observed["sesMx"] = json!(ses_mx);
            observed["sesSpf"] = json!(ses_spf);
        }

        let verified = checks.values().all(|value| value.as_bool() == Some(true));
        Ok(json!({
            "verified": verified,
            "checks": Value::Object(checks),
            "observed": observed,
            "spfRecordCount": spf_records.len(),
        }))
    }

    pub async fn setup_relay_test(&self, data: &Value) -> Result<Value, HandlerError> {
        if flag(data, "direct") {
            return self.direct_delivery_probe().await;
        }
        let request = relay_request(data)?;
        let private = self.relay_private_network_enabled();

        mailstack_smtp::validate_relay(&request, private)?;
        match self.relay.test(&request, private).await {
            Ok(result) => Ok(result.to_json()),
            Err(failure) => Ok(failure.to_json()),
        }
    }

    pub async fn setup_relay_apply(&self, data: &Value) -> Result<Value, HandlerError> {
        if flag(data, "direct") {
            return self.clear_relay_direct();
        }
        let request = relay_request(data)?;
        let private = self.relay_private_network_enabled();
        let endpoint = mailstack_smtp::validate_relay(&request, private)?;

        let result = match self.relay.test(&request, private).await {
            Ok(result) => result,
            Err(failure) => {
                return Ok(json!({
                    "applied": false,
                    "rolledBack": false,
                    "test": failure.to_json(),
                }));
            }
        };

        let mut store = NativeRelayStore::production(&self.paths);
        match apply_relay(&mut store, &endpoint, &result) {
            Ok(applied) => Ok(applied.to_json(&result)),
            Err(failure) => Ok(failure.to_json()),
        }
    }

    fn clear_relay_direct(&self) -> Result<Value, HandlerError> {
        let mut store = NativeRelayStore::production(&self.paths);
        mailstack_smtp::clear_relay(&mut store).map_err(HandlerError::from)?;

        Ok(json!({
            "applied": true,
            "mode": "direct",
            "relayhost": "",
            "wrappermode": false,
        }))
    }

    pub async fn setup_mail_test(&self, data: &Value) -> Result<Value, HandlerError> {
        let sender = setup_address(data, &["sender"])?;
        let recipient = setup_address(data, &["recipient"])?;

        let username = crate::handlers::optional_str(data, "username").unwrap_or("");
        if !mailstack_core::validate::USER_RE.is_match(username) {
            return Err(HandlerError::new("invalid mailbox or sender"));
        }

        let password = crate::handlers::optional_str(data, "password").unwrap_or("");
        mailstack_core::password::validate_legacy_password_input(password)
            .map_err(|error| HandlerError::new(error.to_string()))?;

        if !self.users.managed_mailbox_matches(username, &sender) {
            return Err(HandlerError::new(
                "mail test requires an explicit managed mailbox matching sender",
            ));
        }
        if self.users.is_locked(username) {
            return Err(HandlerError::new("mailbox is disabled"));
        }

        let body = format!(
            "From: {sender}\r\nTo: {recipient}\r\nSubject: MailStack connectivity test\r\n\r\nThis message was sent by MailStack setup verification.\r\n"
        );
        let report = self
            .mailtest
            .submitter
            .submit(crate::mailtest::LocalSubmission {
                mail_from: sender.clone(),
                recipient: recipient.clone(),
                data: body,
            })
            .await
            .map_err(HandlerError::new)?;

        Ok(json!({
            "queued": true,
            "roundTripVerified": false,
            "scope": "local submission",
            "sender": sender,
            "recipient": recipient,

            "code": report.code,
        }))
    }

    pub async fn mail_test_loopback(&self, data: &Value) -> Result<Value, HandlerError> {
        let domains: Vec<String> = self
            .tables()
            .domains()
            .into_iter()
            .map(|domain| domain.to_lowercase())
            .collect();

        let requested = crate::handlers::optional_str(data, "recipient")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_lowercase());
        let recipient = match requested {
            Some(recipient) => recipient,

            None => match domains.first() {
                Some(domain) => format!("postmaster@{domain}"),
                None => "test@localhost".to_string(),
            },
        };

        if !mailstack_core::validate::ADDRESS_RE.is_match(&recipient) {
            return Err(HandlerError::new("invalid recipient email address"));
        }
        if domains.is_empty() {
            return Err(HandlerError::new(
                "Loopback test requires at least one managed domain",
            ));
        }
        let recipient_domain = recipient
            .split('@')
            .nth(1)
            .unwrap_or("localhost")
            .to_string();
        if recipient_domain != "localhost" && !domains.contains(&recipient_domain) {
            return Err(HandlerError::new(format!(
                "Loopback test recipient must belong to a managed domain ({recipient})"
            )));
        }

        let sender = format!("mailer-daemon@{recipient_domain}");
        let token = crate::mailtest::loopback_token();
        let subject = format!("MailStack Loopback Verification [{token}]");
        let body = format!(
            "From: MailStack Diagnostic <{sender}>\r\n\
             To: <{recipient}>\r\n\
             Subject: {subject}\r\n\
             X-MailStack-Test-Token: {token}\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             This is an automated loopback test message generated by MailStack.\r\n\
             Token: {token}\r\n"
        );

        let started = std::time::Instant::now();
        let report = self
            .mailtest
            .submitter
            .submit(crate::mailtest::LocalSubmission {
                mail_from: sender.clone(),
                recipient: recipient.clone(),
                data: body,
            })
            .await
            .map_err(HandlerError::new)?;
        let maildir_delivered = crate::mailtest::find_loopback_token(
            &self.paths.vmail,
            &self.mailtest.home_root,
            &recipient,
            &token,
        );
        let elapsed_ms = started.elapsed().as_millis().max(1) as u64;

        Ok(json!({
            "success": true,
            "token": token,
            "sender": sender,
            "recipient": recipient,
            "deliveryTimeMs": elapsed_ms,
            "maildirDelivered": maildir_delivered,

            "code": report.code,
            "message": format!("Loopback message submitted to the local MTA ({elapsed_ms}ms)"),
        }))
    }

    async fn direct_delivery_probe(&self) -> Result<Value, HandlerError> {
        let (host, port) = local_submission_endpoint()?;
        let ip: IpAddr = host.parse().map_err(|_| {
            HandlerError::new(format!("local submission endpoint is not an IP: {host}"))
        })?;
        let target = pinned_from_addresses(&host, port, vec![ip], AddressPolicy::allow_private())?;
        match self.relay.direct(target).await {
            Ok(result) => Ok(result.to_json()),
            Err(failure) => Ok(failure.to_json()),
        }
    }

    fn relay_private_network_enabled(&self) -> bool {
        !mailstack_core::mode::is_public_mode(&self.paths)
    }

    pub fn users_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let items: Vec<Value> = self
            .users
            .list()
            .iter()
            .map(|user| {
                json!({
                    "address": user.get("email").cloned().unwrap_or_else(|| json!("")),
                    "name": user.get("displayName").cloned().unwrap_or_else(|| json!("")),

                    "active": user.get("status").and_then(Value::as_str) == Some("enabled"),
                    "quotaUsed": 0,
                    "quotaTotal": 0,
                    "createdAt": "",
                })
            })
            .collect();
        Ok(Value::Array(items))
    }

    pub fn aliases_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let items: Vec<Value> = self
            .tables()
            .aliases()
            .into_iter()
            .map(|entry| {
                let target = entry.destinations.first().cloned().unwrap_or_default();
                json!({
                    "source": entry.source,
                    "target": target,
                    "destinations": entry.destinations,
                    "active": true,
                    "createdAt": "",
                })
            })
            .collect();
        Ok(Value::Array(items))
    }

    pub fn queue_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let items: Vec<Value> = self
            .queue_items()
            .iter()
            .map(|item| {
                let recipient = item
                    .get("recipient")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let domain = recipient.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                let status = match item.get("status").and_then(Value::as_str) {
                    Some("active") => "sending",

                    _ => "pending",
                };
                json!({
                    "id": item.get("id").cloned().unwrap_or(Value::Null),
                    "sender": item.get("sender").cloned().unwrap_or(Value::Null),
                    "recipient": recipient,
                    "domain": domain,
                    "status": status,
                    "retry": item.get("retryCount").cloned().unwrap_or_else(|| json!(0)),
                    "time": item.get("arrivalDate").cloned().unwrap_or(Value::Null),
                    "service": item.get("kind").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
        Ok(Value::Array(items))
    }

    pub fn services_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let items: Vec<Value> = self
            .service_items()
            .iter()
            .map(|item| {
                json!({
                    "key": item.get("id").cloned().unwrap_or(Value::Null),
                    "running": item.get("status").and_then(Value::as_str) == Some("ACTIVE"),
                    "detail": item.get("name").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
        Ok(Value::Array(items))
    }

    pub async fn dkim_keys(&self, _data: &Value) -> Result<Value, HandlerError> {
        let selector = self.setup_dkim_selector();
        let mut items: Vec<Value> = Vec::new();
        for domain in self.managed_domains()? {
            let private = mailstack_auth::keys::private_key_path(&self.paths, &domain, &selector);
            let Ok(meta) = std::fs::metadata(&private) else {
                continue;
            };
            let last_rotated = meta
                .modified()
                .ok()
                .map(|t| format_utc_stamp(time::OffsetDateTime::from(t)))
                .unwrap_or_default();
            let published = match self
                .dns
                .lookup_txt(&dkim_record_name(&selector, &domain))
                .await
            {
                Ok(records) => !records.is_empty(),
                Err(_) => false,
            };
            items.push(json!({
                "domain": domain,
                "selector": selector,
                "keySize": mailstack_auth::keys::DKIM_KEY_BITS,
                "lastRotated": last_rotated,
                "published": published,
            }));
        }
        Ok(Value::Array(items))
    }

    pub async fn dns_records(&self, _data: &Value) -> Result<Value, HandlerError> {
        let setup = mailstack_core::config::read_setup_config(&self.paths);
        let selector = self.setup_dkim_selector();
        let mut items: Vec<Value> = Vec::new();

        if let Some(setup) = &setup {
            let ok = match self.dns.lookup_a(&setup.mail_host).await {
                Ok(ips) => ips.iter().any(|ip| ip == &setup.server_ip),
                Err(_) => false,
            };
            items.push(json!({
                "type": "A", "name": setup.mail_host, "value": setup.server_ip,
                "ttl": DNS_TTL, "required": true, "ok": ok,
            }));
        }

        for domain in self.managed_domains()? {
            let host = setup
                .as_ref()
                .map(|s| s.mail_host.as_str())
                .filter(|host| *host == domain || host.ends_with(&format!(".{domain}")))
                .map(str::to_string)
                .unwrap_or_else(|| format!("mail.{domain}"));

            let mx_ok = self
                .dns
                .lookup_mx_records(&domain)
                .await
                .map(|records| mx_records_contain(&records, &host))
                .unwrap_or(false);
            items.push(json!({
                "type": "MX", "name": domain, "value": host,
                "ttl": DNS_TTL, "required": true, "ok": mx_ok,
            }));

            let spf_value = setup
                .as_ref()
                .and_then(|s| s.expected_spf.clone())
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "v=spf1 mx -all".to_string());
            let spf_ok = self
                .dns
                .lookup_txt(&domain)
                .await
                .map(|records| records.iter().any(|r| r.trim() == spf_value))
                .unwrap_or(false);
            items.push(json!({
                "type": "TXT", "name": domain, "value": spf_value,
                "ttl": DNS_TTL, "required": true, "ok": spf_ok,
            }));

            let dmarc_name = format!("_dmarc.{domain}");
            let dmarc_ok = self
                .dns
                .lookup_txt(&dmarc_name)
                .await
                .map(|records| records.iter().any(|r| r.starts_with("v=DMARC1")))
                .unwrap_or(false);
            items.push(json!({
                "type": "TXT", "name": dmarc_name,
                "value": format!("v=DMARC1; rua=mailto:dmarc@{domain}"),
                "ttl": DNS_TTL, "required": true, "ok": dmarc_ok,
            }));

            if let Some(expected) = std::fs::read_to_string(mailstack_auth::keys::txt_record_path(
                &self.paths,
                &domain,
                &selector,
            ))
            .ok()
            .and_then(|fragment| zone_txt_value(&fragment))
            {
                let name = dkim_record_name(&selector, &domain);
                let dkim_ok = self
                    .dns
                    .lookup_txt(&name)
                    .await
                    .map(|records| records.iter().any(|r| has_dkim_public_key(r)))
                    .unwrap_or(false);
                items.push(json!({
                    "type": "TXT", "name": name, "value": expected,
                    "ttl": DNS_TTL, "required": true, "ok": dkim_ok,
                }));
            }
        }

        Ok(Value::Array(items))
    }

    pub fn metrics_system(&self, _data: &Value) -> Result<Value, HandlerError> {
        Ok(json!({
            "cpu": self.cpu_percent(),
            "memory": self.memory_percent(),
            "disk": self.disk_percent(),
        }))
    }

    fn cpu_percent(&self) -> f64 {
        let Some(prev) = read_cpu_counters(&self.proc_root) else {
            return 0.0;
        };
        std::thread::sleep(Duration::from_millis(CPU_SAMPLE_INTERVAL_MS));
        let Some(now) = read_cpu_counters(&self.proc_root) else {
            return 0.0;
        };
        cpu_busy_percent(&prev, &now)
    }

    fn memory_percent(&self) -> f64 {
        let Some(mem) = mailstack_core::sysinfo::read_meminfo(&self.proc_root) else {
            return 0.0;
        };
        if mem.total_bytes == 0 {
            return 0.0;
        }
        round1(
            mem.total_bytes.saturating_sub(mem.available_bytes) as f64 / mem.total_bytes as f64
                * 100.0,
        )
    }

    fn disk_percent(&self) -> f64 {
        let Ok(output) = self.runner.run("df", &["-kP", "/"]) else {
            return 0.0;
        };
        if output.status != 0 {
            return 0.0;
        }
        parse_df_percent(&output.stdout).unwrap_or(0.0)
    }

    pub fn activity_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        Ok(Value::Array(read_activity(&self.paths.audit_log)?))
    }

    fn managed_domains(&self) -> Result<Vec<String>, HandlerError> {
        mailstack_core::atomic::try_rows(&self.paths.domains)
            .map_err(|error| {
                HandlerError::new(format!("managed domain table is unreadable: {error}"))
            })
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|row| row.into_iter().next())
                    .collect()
            })
    }

    fn setup_dkim_selector(&self) -> String {
        mailstack_core::config::read_setup_config(&self.paths)
            .map(|config| config.dkim_selector)
            .filter(|selector| !selector.trim().is_empty())
            .unwrap_or_else(|| mailstack_auth::keys::DEFAULT_DKIM_SELECTOR.to_string())
    }
}

fn local_submission_endpoint() -> Result<(String, u16), HandlerError> {
    let raw = mailstack_smtp::LOCAL_SUBMISSION_ENDPOINT;
    let invalid = || HandlerError::new(format!("invalid local submission endpoint: {raw}"));
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(invalid());
    };
    let port = port.parse::<u16>().map_err(|_| invalid())?;
    Ok((host.to_string(), port))
}

fn setup_server_ip(data: &Value) -> Result<String, HandlerError> {
    let raw = crate::handlers::first_str(data, &["serverIp", "server_ip"])?;
    raw.trim()
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| HandlerError::new("invalid server IP address"))
}

fn setup_selector(data: &Value) -> String {
    crate::handlers::optional_str(data, "dkimSelector")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(SETUP_DEFAULT_DKIM_SELECTOR)
        .to_ascii_lowercase()
}

fn setup_expected_spf(data: &Value) -> Option<String> {
    crate::handlers::optional_str(data, "expectedSpf")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn setup_address(data: &Value, keys: &[&str]) -> Result<String, HandlerError> {
    let address = crate::handlers::first_str(data, keys)?
        .trim()
        .to_lowercase();
    if !mailstack_core::validate::ADDRESS_RE.is_match(&address) {
        return Err(HandlerError::new("invalid mailbox or sender"));
    }
    Ok(address)
}

fn mx_records_contain(records: &[String], host: &str) -> bool {
    let want = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if want.is_empty() {
        return false;
    }
    records.iter().any(|record| {
        record
            .split_whitespace()
            .last()
            .map(|target| target.trim_end_matches('.').to_ascii_lowercase() == want)
            .unwrap_or(false)
    })
}

fn has_dkim_public_key(record: &str) -> bool {
    if !record.contains("v=DKIM1") {
        return false;
    }
    let Some(index) = record.find("p=") else {
        return false;
    };
    let key: String = record[index + 2..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    key.trim_end_matches('=').len() >= 100
}

const CPU_SAMPLE_INTERVAL_MS: u64 = 100;

const DNS_TTL: u64 = 3600;

const ACTIVITY_MAX_ITEMS: usize = 50;

const ACTIVITY_TAIL_BYTES: u64 = 262_144;

fn dkim_record_name(selector: &str, domain: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

struct CpuCounters {
    idle: u64,
    total: u64,
}

fn read_cpu_counters(proc_root: &Path) -> Option<CpuCounters> {
    let text = std::fs::read_to_string(proc_root.join("stat")).ok()?;
    let line = text.lines().find(|line| line.starts_with("cpu"))?;

    let rest = line.strip_prefix("cpu")?;
    let counters = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    let fields: Vec<u64> = counters
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }

    Some(CpuCounters {
        idle: fields[3].saturating_add(fields.get(4).copied().unwrap_or(0)),
        total: fields.iter().take(8).sum(),
    })
}

fn cpu_busy_percent(prev: &CpuCounters, now: &CpuCounters) -> f64 {
    let total_delta = now.total.saturating_sub(prev.total);
    let idle_delta = now.idle.saturating_sub(prev.idle);
    if total_delta == 0 {
        return 0.0;
    }

    let busy = total_delta.saturating_sub(idle_delta.min(total_delta));
    round1((busy as f64 / total_delta as f64 * 100.0).clamp(0.0, 100.0))
}

fn parse_df_percent(stdout: &str) -> Option<f64> {
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let (Ok(total_kb), Ok(used_kb)) = (parts[1].parse::<u64>(), parts[2].parse::<u64>()) else {
            continue;
        };
        if total_kb == 0 {
            continue;
        }
        return Some(round1(used_kb as f64 / total_kb as f64 * 100.0));
    }
    None
}

fn zone_txt_value(fragment: &str) -> Option<String> {
    let open = fragment.find('(')?;
    let close = fragment.rfind(')')?;
    if close <= open {
        return None;
    }
    let mut value = String::new();
    for chunk in fragment[open + 1..close].split('"').skip(1).step_by(2) {
        value.push_str(chunk);
    }
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn activity_kind(action: &str) -> &'static str {
    if action.starts_with("users.") {
        "user"
    } else if action.starts_with("domains.") {
        "domain"
    } else if action.starts_with("queue.") {
        "queue"
    } else if action.starts_with("services.") {
        "service"
    } else if action.starts_with("certs.") {
        "cert"
    } else {
        "system"
    }
}

fn read_activity(log_path: &Path) -> Result<Vec<Value>, HandlerError> {
    let Some((tail, truncated)) = read_log_tail(log_path, ACTIVITY_TAIL_BYTES)? else {
        return Ok(Vec::new());
    };

    let mut items: Vec<Value> = tail
        .lines()
        .skip(if truncated { 1 } else { 0 })
        .filter_map(|line| serde_json::from_str::<mailstack_core::audit::AuditRecord>(line).ok())
        .map(|record| {
            let kind = activity_kind(&record.action);
            json!({
                "kind": kind,
                "title": record.action,
                "sub": record.target,
                "time": record.time,
            })
        })
        .collect();
    items.reverse();
    items.truncate(ACTIVITY_MAX_ITEMS);
    Ok(items)
}

fn read_log_tail(log_path: &Path, max_bytes: u64) -> Result<Option<(String, bool)>, HandlerError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = match std::fs::File::open(log_path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(HandlerError::new(format!(
                "read audit log {}: {e}",
                log_path.display()
            )))
        }
    };
    let read_error = |e: std::io::Error| {
        HandlerError::new(format!("read audit log {}: {e}", log_path.display()))
    };
    let len = file.metadata().map_err(&read_error)?.len();
    if len <= max_bytes {
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(read_error)?;
        return Ok(Some((text, false)));
    }
    file.seek(SeekFrom::Start(len - max_bytes))
        .map_err(read_error)?;
    let mut bytes = Vec::with_capacity(max_bytes as usize);
    file.take(max_bytes)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;

    Ok(Some((String::from_utf8_lossy(&bytes).into_owned(), true)))
}

fn format_utc_stamp(dt: time::OffsetDateTime) -> String {
    let dt = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

fn relay_request(data: &Value) -> Result<RelayValidationRequest, HandlerError> {
    let host = crate::handlers::first_str(data, &["host", "relayHost"])?.to_string();
    let port = match data.get("port") {
        None | Some(Value::Null) => 587u16,
        Some(value) => {
            let raw = value
                .as_u64()
                .filter(|raw| *raw <= u16::MAX as u64)
                .ok_or_else(|| HandlerError::new("invalid relay port"))?;
            raw as u16
        }
    };

    Ok(RelayValidationRequest {
        host,
        port,
        tls_mode: crate::handlers::optional_str(data, "tlsMode")
            .unwrap_or("STARTTLS")
            .to_string(),
        username: crate::handlers::optional_str(data, "username")
            .unwrap_or("")
            .to_string(),
        password: crate::handlers::optional_str(data, "password")
            .unwrap_or("")
            .to_string(),
        allow_private_network: flag(data, "allowPrivateNetwork"),
    })
}

fn ban_target(data: &Value) -> Result<IpAddr, HandlerError> {
    let raw = crate::handlers::first_str(data, &["ip", "address"])?;
    raw.trim()
        .parse::<IpAddr>()
        .map_err(|_| HandlerError::new(format!("invalid ip address: {raw:?}")))
}

fn resolve_service_unit(ident: &str) -> Option<&'static str> {
    if let Some((_, unit)) = SERVICES.iter().find(|(id, _)| *id == ident) {
        return Some(unit);
    }
    SERVICES
        .iter()
        .find(|(_, unit)| *unit == ident)
        .map(|(_, unit)| *unit)
}

fn systemd_property<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
    stdout.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim())
    })
}

fn parse_u64(value: Option<&str>) -> u64 {
    value.and_then(|v| v.trim().parse().ok()).unwrap_or(0)
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn queue_item_json(entry: &mailstack_queue::QueueEntry, now: i64) -> Value {
    let deferred = entry.next_attempt_unix > now;
    json!({
        "id": entry.id,
        "queueId": entry.id,
        "sender": entry.mail_from,
        "recipient": entry.recipients.first().cloned().unwrap_or_default(),
        "recipients": entry.recipients,
        "sizeBytes": entry.data.len(),
        "arrivalDate": entry.created_at,
        "status": if deferred { "deferred" } else { "active" },
        "errorReason": entry.last_error.clone().unwrap_or_default(),
        "retryCount": entry.attempts,

        "kind": entry.kind.as_str(),
        "nextAttemptUnix": entry.next_attempt_unix,
    })
}

fn flag(data: &Value, key: &str) -> bool {
    data.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn backup_timestamp(dt: time::OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

fn collision_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{nanos:08x}")
}

fn finding_to_json(finding: &mailstack_core::security::Finding) -> Value {
    json!({
        "path": finding.path.display().to_string(),
        "severity": finding.severity.as_str(),
        "issue": finding.issue.as_str(),
        "mode": finding.mode,
        "maxMode": finding.max_mode,
        "note": finding.note,
        "detail": finding.detail,
    })
}

pub const EXPIRY_WARNING_DAYS: i64 = 14;

fn check(name: &str, ok: bool, detail: impl Into<String>) -> Value {
    json!({ "name": name, "ok": ok, "detail": detail.into() })
}

pub(crate) fn certificate_to_json(info: mailstack_core::certs::CertificateInfo) -> Value {
    json!({
        "domain": info.domain,
        "certPath": info.cert_path.display().to_string(),
        "keyPath": info.key_path.display().to_string(),
        "certPresent": info.cert_present,
        "keyPresent": info.key_present,
        "keyMode": info.key_mode.map(|m| format!("{m:o}")),
        "keyGroupOrWorldReadable": info.key_group_or_world_readable,
        "notBefore": info.not_before,
        "notAfter": info.not_after,
        "daysUntilExpiry": info.days_until_expiry,
        "issuer": info.issuer,
        "subject": info.subject,
        "error": info.error,
    })
}

fn read_relay_host(paths: &Paths) -> Option<String> {
    let text = std::fs::read_to_string(&paths.relay_config).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value
        .get("host")
        .or_else(|| value.get("relayhost"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|h| !h.is_empty())
}

fn clamp_lines(data: &Value) -> usize {
    data.get("lines")
        .and_then(Value::as_u64)
        .map(|n| (n as usize).clamp(1, LOGS_MAX_LINES))
        .unwrap_or(LOGS_DEFAULT_LINES)
}

fn journal_entry_to_json(raw: &Value) -> Value {
    let message = raw
        .get("MESSAGE")
        .map(|m| match m {
            Value::String(s) => s.clone(),
            Value::Array(bytes) => {
                let raw_bytes: Vec<u8> = bytes
                    .iter()
                    .filter_map(Value::as_u64)
                    .map(|b| b as u8)
                    .collect();
                String::from_utf8_lossy(&raw_bytes).into_owned()
            }
            other => other.to_string(),
        })
        .unwrap_or_default();

    let priority = raw
        .get("PRIORITY")
        .and_then(Value::as_str)
        .and_then(|p| p.parse::<u8>().ok());

    let time = raw
        .get("__REALTIME_TIMESTAMP")
        .and_then(Value::as_str)
        .and_then(|us| us.parse::<i64>().ok())
        .and_then(|us| time::OffsetDateTime::from_unix_timestamp(us / 1_000_000).ok())
        .map(mailstack_core::time_fmt::format_iso8601);

    json!({
        "time": time,
        "priority": priority,
        "level": priority.map(priority_name),
        "unit": raw.get("_SYSTEMD_UNIT").and_then(Value::as_str),
        "identifier": raw.get("SYSLOG_IDENTIFIER").and_then(Value::as_str),
        "message": message,
    })
}

fn priority_name(priority: u8) -> &'static str {
    match priority {
        0 => "emerg",
        1 => "alert",
        2 => "crit",
        3 => "err",
        4 => "warning",
        5 => "notice",
        6 => "info",
        _ => "debug",
    }
}

pub fn register(registry: &mut Registry, readers: Arc<Readers>) {
    let certs = Arc::clone(&readers);
    registry.register("certs.list", move |data| certs.certs_list(data));

    let metrics = Arc::clone(&readers);
    registry.register("metrics.realtime", move |data| {
        metrics.metrics_realtime(data)
    });

    let snapshot = Arc::clone(&readers);
    registry.register("snapshot", move |data| snapshot.snapshot(data));

    let logs = Arc::clone(&readers);
    registry.register("logs.list", move |data| logs.logs_list(data));

    let doctor = Arc::clone(&readers);
    registry.register("system.doctor", move |data| doctor.system_doctor(data));

    let security = Arc::clone(&readers);
    registry.register("security.scan", move |data| security.security_scan(data));

    let backups = Arc::clone(&readers);
    registry.register("backup.list", move |data| backups.backup_list(data));

    let services = Arc::clone(&readers);
    registry.register("services.action", move |data| {
        services.services_action(data)
    });

    let queue = Arc::clone(&readers);
    registry.register("queue.action", move |data| queue.queue_action(data));

    let ban = Arc::clone(&readers);
    registry.register("security.ban", move |data| ban.security_ban(data));

    let unban = Arc::clone(&readers);
    registry.register("security.unban", move |data| unban.security_unban(data));

    let create = Arc::clone(&readers);
    registry.register("backup.create", move |data| create.backup_create(data));

    let restore = Arc::clone(&readers);
    registry.register("backup.restore", move |data| restore.backup_restore(data));

    let remove = Arc::clone(&readers);
    registry.register("backup.delete", move |data| remove.backup_delete(data));

    let probe = Arc::clone(&readers);
    registry.register_async("network.check_port", move |data| {
        let probe = Arc::clone(&probe);
        let data = data.clone();
        Box::pin(async move { probe.network_check_port(&data).await })
    });

    let identity = Arc::clone(&readers);
    registry.register("setup.identity.apply", move |data| {
        identity.setup_identity_apply(data)
    });

    let dns = Arc::clone(&readers);
    registry.register_async("setup.dns.verify", move |data| {
        let dns = Arc::clone(&dns);
        let data = data.clone();
        Box::pin(async move { dns.setup_dns_verify(&data).await })
    });

    let relay_test = Arc::clone(&readers);
    registry.register_async("setup.relay.test", move |data| {
        let relay_test = Arc::clone(&relay_test);
        let data = data.clone();
        Box::pin(async move { relay_test.setup_relay_test(&data).await })
    });

    let relay_apply = Arc::clone(&readers);
    registry.register_async("setup.relay.apply", move |data| {
        let relay_apply = Arc::clone(&relay_apply);
        let data = data.clone();
        Box::pin(async move { relay_apply.setup_relay_apply(&data).await })
    });

    let mail_test = Arc::clone(&readers);
    registry.register_async("setup.mail.test", move |data| {
        let mail_test = Arc::clone(&mail_test);
        let data = data.clone();
        Box::pin(async move { mail_test.setup_mail_test(&data).await })
    });

    let loopback = Arc::clone(&readers);
    registry.register_async("mail.test_loopback", move |data| {
        let loopback = Arc::clone(&loopback);
        let data = data.clone();
        Box::pin(async move { loopback.mail_test_loopback(&data).await })
    });

    let add = Arc::clone(&readers);
    registry.register("users.add", move |data| add.users.add(data));

    let status = Arc::clone(&readers);
    registry.register("users.status", move |data| status.users.status(data));

    let password = Arc::clone(&readers);
    registry.register("users.password", move |data| password.users.password(data));

    let remove = Arc::clone(&readers);
    registry.register("users.delete", move |data| remove.users.delete(data));

    let renew = Arc::clone(&readers);
    registry.register("certs.renew", move |data| renew.acme.renew(data));

    let issue = Arc::clone(&readers);
    registry.register("setup.cert.issue", move |data| issue.acme.issue(data));

    let users_list = Arc::clone(&readers);
    registry.register("users.list", move |data| users_list.users_list(data));

    let aliases_list = Arc::clone(&readers);
    registry.register("aliases.list", move |data| aliases_list.aliases_list(data));

    let queue_list = Arc::clone(&readers);
    registry.register("queue.list", move |data| queue_list.queue_list(data));

    let services_list = Arc::clone(&readers);
    registry.register("services.list", move |data| {
        services_list.services_list(data)
    });

    let dkim_keys = Arc::clone(&readers);
    registry.register_async("dkim.keys", move |data| {
        let dkim_keys = Arc::clone(&dkim_keys);
        let data = data.clone();
        Box::pin(async move { dkim_keys.dkim_keys(&data).await })
    });

    let dns_records = Arc::clone(&readers);
    registry.register_async("dns.records", move |data| {
        let dns_records = Arc::clone(&dns_records);
        let data = data.clone();
        Box::pin(async move { dns_records.dns_records(&data).await })
    });

    let metrics_system = Arc::clone(&readers);
    registry.register("metrics.system", move |data| {
        metrics_system.metrics_system(data)
    });

    let activity_list = Arc::clone(&readers);
    registry.register("activity.list", move |data| {
        activity_list.activity_list(data)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_core::exec::CommandOutput;
    use std::fs;
    use std::sync::Mutex;

    const NOW: i64 = 1_767_225_600;

    struct FakeRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        output: CommandOutput,
    }

    impl FakeRunner {
        fn returning(status: i32, stdout: &str) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                output: CommandOutput {
                    status,
                    stdout: stdout.to_string(),
                    stderr: "scripted failure".to_string(),
                },
            })
        }

        fn called(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(program, _)| program.clone())
                .collect()
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> mailstack_core::CoreResult<CommandOutput> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|a| a.to_string()).collect(),
            ));
            Ok(self.output.clone())
        }

        fn run_with_timeout(
            &self,
            program: &str,
            args: &[&str],
            _timeout: std::time::Duration,
        ) -> mailstack_core::CoreResult<CommandOutput> {
            self.run(program, args)
        }
    }

    struct NoServices;

    impl ServiceEnv for NoServices {
        fn program_available(&self, _program: &str) -> bool {
            false
        }
        fn path_exists(&self, _path: &std::path::Path) -> bool {
            false
        }
    }

    struct EnvListing {
        programs: Vec<&'static str>,
        paths: Vec<&'static str>,
    }

    impl ServiceEnv for EnvListing {
        fn program_available(&self, program: &str) -> bool {
            self.programs.contains(&program)
        }
        fn path_exists(&self, path: &std::path::Path) -> bool {
            self.paths
                .iter()
                .any(|candidate| std::path::Path::new(candidate) == path)
        }
    }

    struct TestCipher;

    impl mailstack_core::backup::BackupCipher for TestCipher {
        fn available(&self) -> bool {
            true
        }

        fn encrypt(
            &self,
            input: &std::path::Path,
            output: &std::path::Path,
            passphrase: &str,
        ) -> Result<(), mailstack_core::backup::BackupError> {
            use std::io::Write;
            let body = fs::read(input).unwrap();
            let mut file = fs::File::create(output).unwrap();
            file.write_all(passphrase.as_bytes()).unwrap();
            file.write_all(&body).unwrap();
            Ok(())
        }

        fn decrypt(
            &self,
            input: &std::path::Path,
            output: &std::path::Path,
            passphrase: &str,
        ) -> Result<(), mailstack_core::backup::BackupError> {
            use std::io::Write;
            let body = fs::read(input).unwrap();
            assert!(
                body.starts_with(passphrase.as_bytes()),
                "口令不匹配，测试替身拒绝解密"
            );
            let mut file = fs::File::create(output).unwrap();
            file.write_all(&body[passphrase.len()..]).unwrap();
            Ok(())
        }
    }

    struct Fixture {
        root: PathBuf,
        paths: Paths,
        proc_root: PathBuf,

        backup_root: PathBuf,

        restore_root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-readers-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let paths = Paths::rooted(&root);
            fs::create_dir_all(&paths.etc).unwrap();
            fs::create_dir_all(&paths.postfix).unwrap();

            let proc_root = root.join("proc");
            fs::create_dir_all(&proc_root).unwrap();
            fs::write(proc_root.join("loadavg"), "0.10 0.20 0.30 1/10 42\n").unwrap();
            fs::write(proc_root.join("uptime"), "86400.0 100.0\n").unwrap();
            fs::write(
                proc_root.join("meminfo"),
                "MemTotal:       1000 kB\nMemAvailable:    400 kB\n",
            )
            .unwrap();

            let backup_root = root.join("fsroot");
            for relative in ["etc/mailstack", "etc/postfix", "var/lib/mailstack"] {
                fs::create_dir_all(backup_root.join(relative)).unwrap();
            }
            fs::write(backup_root.join("etc/mailstack/settings.json"), "{}").unwrap();
            fs::write(
                backup_root.join("etc/mailstack/admin.json"),
                r#"{"username":"admin"}"#,
            )
            .unwrap();
            fs::write(backup_root.join("var/lib/mailstack/manual-bans.json"), "[]").unwrap();
            fs::write(
                backup_root.join("etc/postfix/main.cf"),
                "myhostname = mx.test\n",
            )
            .unwrap();

            let restore_root = root.join("restore");
            fs::create_dir_all(&restore_root).unwrap();

            Self {
                root,
                paths,
                proc_root,
                backup_root,
                restore_root,
            }
        }

        fn backup_readers(&self, runner: Arc<dyn CommandRunner>) -> Readers {
            self.readers(runner).with_backup_env(BackupEnv {
                root: self.backup_root.clone(),
                restore_root: self.restore_root.clone(),
                cipher: Arc::new(TestCipher),
                home_allowlist: BTreeSet::new(),
            })
        }

        fn backup_readers_with_a_managed_mailbox(&self, runner: Arc<dyn CommandRunner>) -> Readers {
            let home = self.backup_root.join("home/alice");
            fs::create_dir_all(home.join("Maildir/new")).unwrap();
            fs::write(
                home.join("Maildir/new/1712000000.M1P1.mx.eml"),
                "Subject: hi\r\n\r\nbody",
            )
            .unwrap();
            fs::create_dir_all(self.paths.managed_users.parent().unwrap()).unwrap();
            fs::write(&self.paths.managed_users, "[\"alice\"]\n").unwrap();
            fs::create_dir_all(self.paths.managed_mailboxes.parent().unwrap()).unwrap();
            fs::write(
                &self.paths.managed_mailboxes,
                r#"[{"email":"alice@example.com","unixUser":"alice","displayName":""}]"#,
            )
            .unwrap();
            let passwd_root = self.root.join("etcfs");
            fs::create_dir_all(&passwd_root).unwrap();
            fs::write(
                passwd_root.join("passwd"),
                format!("alice:x:1001:1001::{}:/usr/sbin/nologin\n", home.display()),
            )
            .unwrap();
            self.readers(runner)
                .with_users_env(UsersEnv {
                    passwd_root,
                    session_epoch_owner: None,
                    ..UsersEnv::default()
                })
                .with_backup_env(BackupEnv {
                    root: self.backup_root.clone(),
                    restore_root: self.restore_root.clone(),
                    cipher: Arc::new(TestCipher),
                    home_allowlist: BTreeSet::new(),
                })
        }

        fn archive_members(&self, filename: &str) -> Vec<String> {
            let archive = self.paths.backups_dir.join(filename);
            let file = fs::File::open(&archive).unwrap();
            let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
            tar.entries()
                .unwrap()
                .map(|entry| entry.unwrap().path().unwrap().to_string_lossy().to_string())
                .collect()
        }

        fn readers(&self, runner: Arc<dyn CommandRunner>) -> Readers {
            self.readers_with_env(runner, Arc::new(NoServices))
        }

        fn readers_with_env(
            &self,
            runner: Arc<dyn CommandRunner>,
            env: Arc<dyn ServiceEnv>,
        ) -> Readers {
            Readers::with_parts(
                self.paths.clone(),
                env,
                runner,
                self.proc_root.clone(),
                Arc::new(|| NOW),
                Vec::new(),
            )
        }

        fn issue(&self, domain: &str, days: i64) {
            let not_before = time::OffsetDateTime::from_unix_timestamp(NOW).unwrap();
            let not_after = not_before + time::Duration::days(days);
            let ymd = |dt: time::OffsetDateTime| {
                rcgen::date_time_ymd(dt.year(), u8::from(dt.month()), dt.day())
            };
            let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
            params.not_before = ymd(not_before);
            params.not_after = ymd(not_after);
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();

            let dir = mailstack_core::certs::tls_dir(&self.paths.etc).join(domain);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("fullchain.pem"), cert.pem()).unwrap();
            fs::write(dir.join("privkey.pem"), key.serialize_pem()).unwrap();
        }

        fn set_identity(&self) {
            mailstack_core::config::write_setup_config(
                &self.paths,
                &mailstack_core::config::SetupConfig {
                    domain: "example.com".into(),
                    mail_host: "mail.example.com".into(),
                    server_ip: "203.0.113.10".into(),
                    dkim_selector: "mail".into(),
                    expected_spf: None,
                    wizard_completed: false,
                    updated_at: mailstack_core::now_iso8601_utc(),
                },
            )
            .unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn always_ok_runner() -> Arc<dyn CommandRunner> {
        FakeRunner::returning(0, "")
    }

    #[test]
    fn every_read_only_aggregate_action_is_registered() {
        let f = Fixture::new("registered");
        let registry = Registry::new().with_readers(Arc::new(f.readers(always_ok_runner())));
        for action in [
            "snapshot",
            "logs.list",
            "metrics.realtime",
            "certs.list",
            "network.check_port",
            "system.doctor",
            "security.scan",
            "backup.list",
        ] {
            assert!(registry.is_implemented(action), "{action} 必须已接线");
        }
    }

    #[test]
    fn the_write_surface_actions_are_registered_too() {
        let f = Fixture::new("registered-rw");
        let registry = Registry::new().with_readers(Arc::new(f.readers(always_ok_runner())));
        for action in [
            "services.action",
            "queue.action",
            "security.ban",
            "security.unban",
        ] {
            assert!(registry.is_implemented(action), "{action} 必须已接线");
        }
    }

    #[test]
    fn snapshot_reports_what_it_cannot_read_instead_of_omitting_it() {
        let f = Fixture::new("snapshot");
        f.set_identity();
        let readers = f.readers(always_ok_runner());

        let out = readers.snapshot(&json!({})).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["identity"]["domain"], "example.com");
        assert_eq!(out["version"], mailstack_core::VERSION);

        assert_eq!(out["unavailable"], json!([]));
    }

    #[test]
    fn snapshot_surfaces_the_persisted_outbound_verdict() {
        let f = Fixture::new("verdict");
        let store = mailstack_queue::QueueStore::from_paths(&f.paths);
        store
            .save_health(&mailstack_queue::OutboundHealthState {
                consecutive_failures: mailstack_queue::DEFAULT_BLOCKED_THRESHOLD,
                last_failure: Some("ConnectionError".into()),
                ..Default::default()
            })
            .unwrap();

        let readers = f.readers(always_ok_runner());
        let out = readers.snapshot(&json!({})).unwrap();
        let health = &out["queue"]["outboundHealth"];
        assert_eq!(health["blocked"], true);
        assert_eq!(health["needsRelay"], true);
        assert!(
            health["message"]
                .as_str()
                .unwrap()
                .contains("Outbound port 25 is blocked"),
            "结论文案必须明确: {}",
            health["message"]
        );

        fs::write(
            &f.paths.relay_config,
            r#"{"host":"relay.example.net","port":587}"#,
        )
        .unwrap();
        let out = readers.snapshot(&json!({})).unwrap();
        assert_eq!(out["queue"]["outboundHealth"]["blocked"], true);
        assert_eq!(
            out["queue"]["outboundHealth"]["needsRelay"], false,
            "已有中继时不该再让人去配中继"
        );
        assert!(out["queue"]["outboundHealth"]["message"]
            .as_str()
            .unwrap()
            .contains("relay.example.net"));
    }

    #[test]
    fn snapshot_counts_backlog_and_quarantined_entries() {
        let f = Fixture::new("backlog");
        let store = mailstack_queue::QueueStore::from_paths(&f.paths);
        let entry = mailstack_queue::QueueEntry::new(
            mailstack_queue::EntryKind::Outbound,
            "s@example.org",
            vec!["r@example.net".to_string()],
            "Subject: t\r\n\r\nbody",
            NOW,
        )
        .unwrap();
        store.enqueue(&entry).unwrap();

        fs::create_dir_all(store.corrupt_dir()).unwrap();
        fs::write(store.corrupt_dir().join("bad.json.1.corrupt"), b"x").unwrap();

        let out = f.readers(always_ok_runner()).snapshot(&json!({})).unwrap();
        assert_eq!(out["queue"]["backlog"], 1);
        assert_eq!(out["queue"]["corrupt"], 1);
    }

    #[test]
    fn queue_summary_marks_unreadable_state_instead_of_reporting_zero() {
        let f = Fixture::new("queueunreadable");
        let store = mailstack_queue::QueueStore::from_paths(&f.paths);

        fs::create_dir_all(store.corrupt_dir().parent().unwrap()).unwrap();
        fs::write(store.corrupt_dir(), b"not a directory").unwrap();

        let out = f.readers(always_ok_runner()).snapshot(&json!({})).unwrap();
        let unavailable = out["queue"]["unavailable"].as_array().unwrap();
        assert!(
            unavailable.iter().any(|item| item == "corrupt"),
            "实际: {out}"
        );
    }

    #[test]
    fn security_scan_propagates_an_unreadable_domain_table() {
        let f = Fixture::new("scanunreadable");
        fs::create_dir_all(f.paths.domains.parent().unwrap()).unwrap();

        fs::create_dir_all(&f.paths.domains).unwrap();

        let err = f
            .readers(always_ok_runner())
            .security_scan(&json!({}))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("managed domain table is unreadable"),
            "实际: {err}"
        );
    }

    #[test]
    fn metrics_realtime_reads_proc_and_lists_every_managed_service() {
        let f = Fixture::new("metrics");
        let out = f
            .readers(always_ok_runner())
            .metrics_realtime(&json!({}))
            .unwrap();

        assert_eq!(out["uptimeSec"], 86400);
        assert_eq!(out["load"]["one"], 0.10);
        assert_eq!(out["memory"]["totalBytes"], 1000 * 1024);
        assert_eq!(out["memory"]["availableBytes"], 400 * 1024);

        let ids: Vec<&str> = out["services"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap())
            .collect();
        let expected: Vec<&str> = SERVICES.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, expected);
        for item in out["services"].as_array().unwrap() {
            assert!(item["status"].is_string(), "每条都要有 status：{item}");
            assert!(item["type"].is_string(), "每条都要有 type：{item}");
            assert!(item["pid"].is_number(), "每条都要有 pid：{item}");
        }
        assert_eq!(out["unavailable"], json!([]));
    }

    #[test]
    fn metrics_realtime_marks_missing_proc_entries_rather_than_reporting_zero() {
        let f = Fixture::new("noproc");
        fs::remove_file(f.proc_root.join("meminfo")).unwrap();
        let out = f
            .readers(always_ok_runner())
            .metrics_realtime(&json!({}))
            .unwrap();

        assert!(out["memory"].is_null(), "读不到就不能编一个 0 出来");
        assert_eq!(out["unavailable"], json!(["memory"]));

        assert_eq!(out["uptimeSec"], 86400);
    }

    #[test]
    fn certs_list_flags_the_soon_expiring_ones() {
        let f = Fixture::new("certs");
        f.issue("mail.example.com", 7);
        f.issue("other.example.com", 200);

        let out = f
            .readers(always_ok_runner())
            .certs_list(&json!({}))
            .unwrap();
        let certs = out["certificates"].as_array().unwrap();
        assert_eq!(certs.len(), 2, "两张证书都应列出");
        assert_eq!(out["expiringSoon"].as_array().unwrap().len(), 1);
        assert_eq!(out["expiringSoon"][0]["domain"], "mail.example.com");
        assert_eq!(out["expiringSoon"][0]["daysUntilExpiry"], 7);
        assert_eq!(out["expiryWarningDays"], EXPIRY_WARNING_DAYS);
    }

    #[test]
    fn certs_list_is_empty_not_an_error_when_nothing_is_issued() {
        let f = Fixture::new("nocerts");
        let out = f
            .readers(always_ok_runner())
            .certs_list(&json!({}))
            .unwrap();
        assert_eq!(out["ok"], true);
        assert!(out["certificates"].as_array().unwrap().is_empty());
        assert!(out["expiringSoon"].as_array().unwrap().is_empty());
    }

    #[test]
    fn logs_list_says_unavailable_instead_of_returning_an_empty_list() {
        let f = Fixture::new("logsdown");
        let runner = FakeRunner::returning(1, "");
        let readers = f.readers(runner.clone());

        let out = readers.logs_list(&json!({})).unwrap();
        assert_eq!(out["available"], false, "读不到必须明说");
        assert!(out["reason"].as_str().unwrap().contains("journalctl"));
        assert!(out["entries"].as_array().unwrap().is_empty());
        assert_eq!(runner.called(), vec!["journalctl".to_string()]);
    }

    #[test]
    fn logs_list_parses_journal_json_including_binary_messages() {
        let f = Fixture::new("logging");
        let stdout = concat!(
            r#"{"__REALTIME_TIMESTAMP":"1767225600000000","PRIORITY":"3","MESSAGE":"boom","_SYSTEMD_UNIT":"postfix.service","SYSLOG_IDENTIFIER":"postfix/smtpd"}"#,
            "\n",
            r#"{"__REALTIME_TIMESTAMP":"1767225601000000","PRIORITY":"6","MESSAGE":[104,105]}"#,
            "\n",
            "not json at all\n",
        );
        let readers = f.readers(FakeRunner::returning(0, stdout));

        let out = readers.logs_list(&json!({ "lines": 50 })).unwrap();
        assert_eq!(out["available"], true);
        assert_eq!(out["lines"], 50);
        let entries = out["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "非 JSON 行必须被跳过而不是让整条失败");
        assert_eq!(entries[0]["level"], "err");
        assert_eq!(entries[0]["unit"], "postfix.service");
        assert_eq!(entries[0]["time"], "2026-01-01T00:00:00+00:00");
        assert_eq!(
            entries[1]["message"], "hi",
            "字节数组形态的 MESSAGE 也要能读"
        );
        assert_eq!(entries[1]["level"], "info");
    }

    #[test]
    fn journal_binary_messages_are_decoded_as_utf8_lossy_not_latin1() {
        let raw = json!({
            "MESSAGE": [72, 0xE9, 0xFF, 108, 111],
            "__REALTIME_TIMESTAMP": "1767225600000000",
        });
        let out = journal_entry_to_json(&raw);
        assert_eq!(out["message"], "H\u{FFFD}\u{FFFD}lo");
    }

    #[test]
    fn logs_lines_are_clamped_at_both_ends() {
        assert_eq!(clamp_lines(&json!({})), LOGS_DEFAULT_LINES);
        assert_eq!(clamp_lines(&json!({ "lines": 99999 })), LOGS_MAX_LINES);
        assert_eq!(clamp_lines(&json!({ "lines": 0 })), 1);
        assert_eq!(clamp_lines(&json!({ "lines": "abc" })), LOGS_DEFAULT_LINES);
    }

    #[test]
    fn network_check_port_rejects_out_of_range_ports() {
        let f = Fixture::new("probeport");
        let readers = f.readers(always_ok_runner());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for bad in [
            json!({ "port": 0 }),
            json!({ "port": 70000 }),
            json!({ "port": "25" }),
        ] {
            assert!(
                runtime.block_on(readers.network_check_port(&bad)).is_err(),
                "{bad} 必须被拒绝"
            );
        }
    }

    #[test]
    fn network_check_port_never_accepts_targets_from_the_request() {
        let f = Fixture::new("probetargets");
        let readers = f.readers(always_ok_runner());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = runtime
            .block_on(readers.network_check_port(&json!({
                "port": 25,
                "targets": ["169.254.169.254"],
                "target": "127.0.0.1",
            })))
            .unwrap();

        assert_eq!(out["details"].as_array().unwrap().len(), 0);
        assert_eq!(out["port"], 25);
    }

    #[test]
    fn system_doctor_probes_the_ban_list_and_leaves_no_trace() {
        let f = Fixture::new("doctor");
        let readers = f.readers(always_ok_runner());

        let first = readers.system_doctor(&json!({})).unwrap();
        let ban = first["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "ban_round_trip")
            .unwrap()
            .clone();
        assert_eq!(ban["ok"], true, "封禁往返探针必须通过: {ban}");

        let second = readers.system_doctor(&json!({})).unwrap();
        assert_eq!(first, second, "诊断不得留下任何状态");
    }

    #[test]
    fn system_doctor_reports_each_broken_precondition() {
        let f = Fixture::new("doctorbad");

        let out = f
            .readers(always_ok_runner())
            .system_doctor(&json!({}))
            .unwrap();
        assert_eq!(out["healthy"], false);

        let check_of = |name: &str| {
            out["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
                .unwrap_or_else(|| panic!("缺少检查项 {name}"))
                .clone()
        };
        assert_eq!(check_of("identity")["ok"], false);
        assert_eq!(check_of("admin_credentials")["ok"], false);
        assert_eq!(check_of("domain_table")["ok"], false);
        assert!(check_of("domain_table")["detail"]
            .as_str()
            .unwrap()
            .contains("INV-17"));
        assert_eq!(check_of("dkim_key")["ok"], false);
        assert_eq!(check_of("tls_certificate")["ok"], false);

        assert_eq!(check_of("relay_config")["ok"], true);

        assert_eq!(check_of("audit_chain")["ok"], true);

        let names: Vec<&str> = out["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "identity",
                "admin_credentials",
                "domain_table",
                "relay_config",
                "dkim_key",
                "tls_certificate",
                "audit_chain",
                "ban_round_trip",
            ]
        );
    }

    #[test]
    fn system_doctor_passes_when_the_host_is_fully_configured() {
        let f = Fixture::new("doctorok");
        f.set_identity();
        mailstack_core::config::admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        f.issue("mail.example.com", 90);

        let key = mailstack_auth::keys::private_key_path(&f.paths, "example.com", "mail");
        fs::create_dir_all(key.parent().unwrap()).unwrap();
        fs::write(&key, "-----BEGIN RSA PRIVATE KEY-----\nxx\n").unwrap();

        let out = f
            .readers(always_ok_runner())
            .system_doctor(&json!({}))
            .unwrap();
        assert_eq!(out["healthy"], true, "全部检查: {}", out["checks"]);
        assert_eq!(out["checks"].as_array().unwrap().len(), 8);
    }

    #[cfg(unix)]
    fn chmod(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn security_scan_flags_a_world_readable_secret_as_high() {
        let f = Fixture::new("scanbad");
        mailstack_core::config::admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        chmod(&f.paths.etc, 0o750);
        chmod(&f.paths.admin_config, 0o644);

        let out = f
            .readers(always_ok_runner())
            .security_scan(&json!({}))
            .unwrap();
        assert_eq!(out["summary"]["high"], 1, "整份报告: {out}");
        assert_eq!(out["highestSeverity"], "high");
        let finding = &out["findings"][0];
        assert_eq!(finding["issue"], "world_readable");
        assert_eq!(finding["mode"], "644");
        assert_eq!(finding["maxMode"], "640");
        assert!(finding["path"].as_str().unwrap().ends_with("admin.json"));
    }

    #[cfg(unix)]
    #[test]
    fn security_scan_is_clean_when_every_permission_matches_the_policy() {
        let f = Fixture::new("scanclean");
        mailstack_core::config::admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        chmod(&f.paths.etc, 0o750);

        let out = f
            .readers(always_ok_runner())
            .security_scan(&json!({}))
            .unwrap();
        assert_eq!(
            out["findings"].as_array().unwrap().len(),
            0,
            "整份报告: {out}"
        );
        assert_eq!(out["highestSeverity"], Value::Null);

        let absent: Vec<&str> = out["absent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(absent.iter().any(|p| p.ends_with("totp.key")));
        assert!(absent.iter().any(|p| p.ends_with("relay.json")));
    }

    #[cfg(unix)]
    #[test]
    fn security_scan_reports_the_config_directory_itself() {
        let f = Fixture::new("scandir");
        chmod(&f.paths.etc, 0o755);
        let out = f
            .readers(always_ok_runner())
            .security_scan(&json!({}))
            .unwrap();
        let finding = out["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["path"].as_str().unwrap().ends_with("mailstack"))
            .unwrap_or_else(|| panic!("配置目录本身必须被体检: {out}"));
        assert_eq!(finding["issue"], "world_readable");
        assert_eq!(finding["severity"], "medium");
        assert_eq!(finding["maxMode"], "750");
    }

    #[cfg(unix)]
    #[test]
    fn the_inventory_covers_the_plaintext_relay_password_and_every_key_kind() {
        let f = Fixture::new("inventory");
        f.issue("mail.example.com", 90);

        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let dkim = mailstack_auth::keys::private_key_path(&f.paths, "example.com", "mail");
        fs::create_dir_all(dkim.parent().unwrap()).unwrap();
        fs::write(&dkim, "key").unwrap();

        let paths: Vec<String> = f
            .readers(always_ok_runner())
            .security_inventory()
            .unwrap()
            .into_iter()
            .map(|e| e.path.display().to_string())
            .collect();

        assert!(
            paths.iter().any(|p| p.ends_with("sasl_passwd")),
            "清单必须包含 sasl_passwd: {paths:?}"
        );
        assert!(paths.iter().any(|p| p.ends_with("totp.key")));
        assert!(paths.iter().any(|p| p.ends_with("relay.json")));

        assert!(paths
            .iter()
            .any(|p| p.ends_with("mail.example.com/privkey.pem")));
        assert!(paths.iter().any(|p| p.ends_with(".private")));
    }

    #[test]
    fn backup_list_on_a_missing_directory_is_empty_not_an_error() {
        let f = Fixture::new("nobackups");
        let out = f
            .readers(always_ok_runner())
            .backup_list(&json!({}))
            .unwrap();
        assert!(
            out.as_array().expect("必须是数组").is_empty(),
            "目录不存在只是「还没有备份」，不是错误"
        );
    }

    #[test]
    fn backup_list_reports_size_and_flags_an_empty_archive() {
        let f = Fixture::new("backups");
        fs::create_dir_all(&f.paths.backups_dir).unwrap();
        fs::write(
            f.paths
                .backups_dir
                .join("mailstack-backup-20260101-000000.tar.gz"),
            b"payload",
        )
        .unwrap();
        fs::write(
            f.paths
                .backups_dir
                .join("mailstack-backup-20260102-000000.tar.gz"),
            b"",
        )
        .unwrap();

        fs::write(f.paths.backups_dir.join(".hidden.tmp"), b"x").unwrap();
        fs::write(
            f.paths.backups_dir.join("mailstack-2026-01-03.tar.gz"),
            b"x",
        )
        .unwrap();

        let out = f
            .readers(always_ok_runner())
            .backup_list(&json!({}))
            .unwrap();
        let items = out
            .as_array()
            .expect("必须是数组（控制台直接当成备份清单）");
        assert_eq!(items.len(), 2, "只有合规名字的归档才是备份: {out}");

        let by_name = |name: &str| {
            items
                .iter()
                .find(|e| e["filename"] == name)
                .unwrap_or_else(|| panic!("缺少 {name}"))
                .clone()
        };
        assert_eq!(
            by_name("mailstack-backup-20260101-000000.tar.gz")["size"],
            7
        );
        assert_eq!(
            by_name("mailstack-backup-20260101-000000.tar.gz")["empty"],
            false
        );
        assert_eq!(
            by_name("mailstack-backup-20260102-000000.tar.gz")["empty"],
            true,
            "0 字节的归档必须被标出来，否则一次失败的备份看起来是成功的"
        );

        assert_eq!(
            by_name("mailstack-backup-20260101-000000.tar.gz")["metadataMissing"],
            true
        );
    }

    fn systemd_env() -> Arc<dyn ServiceEnv> {
        Arc::new(EnvListing {
            programs: vec!["systemctl"],
            paths: vec!["/run/systemd/system"],
        })
    }

    #[test]
    fn services_action_runs_the_verb_and_returns_the_service_list() {
        let f = Fixture::new("svcaction");
        let runner = FakeRunner::returning(0, "");
        let readers = f.readers_with_env(runner.clone(), systemd_env());

        let out = readers
            .services_action(&json!({ "id": "dovecot", "verb": "restart" }))
            .unwrap();

        let items = out.as_array().expect("必须是数组");
        assert_eq!(items.len(), SERVICES.len());
        assert_eq!(items[0]["id"], SERVICES[0].0);

        let calls = runner.calls();
        assert_eq!(calls[0].0, "systemctl");
        assert_eq!(
            calls[0].1,
            vec!["restart".to_string(), "dovecot".to_string()]
        );
    }

    #[test]
    fn services_action_accepts_a_unit_name_as_well_as_the_console_id() {
        let f = Fixture::new("svcunit");
        let runner = FakeRunner::returning(0, "");
        let readers = f.readers_with_env(runner.clone(), systemd_env());

        readers
            .services_action(&json!({ "id": "clamav-daemon", "verb": "reload" }))
            .unwrap();
        assert_eq!(runner.calls()[0].1[1], "clamav-daemon");
    }

    #[test]
    fn services_action_refuses_to_stop_the_console_from_itself() {
        let f = Fixture::new("svcself");
        let runner = FakeRunner::returning(0, "");
        let readers = f.readers_with_env(runner.clone(), systemd_env());

        let err = readers
            .services_action(&json!({ "id": "mailstack-web", "verb": "stop" }))
            .unwrap_err();
        assert!(err.to_string().contains("refusing to stop"), "实际: {err}");
        assert!(runner.calls().is_empty(), "被拒绝的动作不得产生任何副作用");

        readers
            .services_action(&json!({ "id": "mailstack-web", "verb": "restart" }))
            .unwrap();
        let calls = runner.calls();
        assert_eq!(calls[0].0, "systemctl");
        assert_eq!(
            calls[0].1,
            vec!["restart".to_string(), "mailstack-web".to_string()]
        );
    }

    #[test]
    fn services_action_rejects_unknown_services_and_unknown_verbs() {
        let f = Fixture::new("svcbad");
        let runner = FakeRunner::returning(0, "");
        let readers = f.readers_with_env(runner.clone(), systemd_env());

        let err = readers
            .services_action(&json!({ "id": "not-a-service", "verb": "restart" }))
            .unwrap_err();
        assert!(err.to_string().contains("invalid service"), "实际: {err}");

        let err = readers
            .services_action(&json!({ "id": "dovecot", "verb": "explode" }))
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid service verb"),
            "实际: {err}"
        );
        assert!(runner.calls().is_empty(), "被拒绝的动作不得执行任何命令");

        assert!(readers
            .services_action(&json!({ "verb": "restart" }))
            .is_err());
    }

    #[test]
    fn services_action_without_a_verb_is_an_error_not_a_default_restart() {
        let f = Fixture::new("svcnoverb");
        let runner = FakeRunner::returning(0, "");
        let readers = f.readers_with_env(runner.clone(), systemd_env());

        let err = readers
            .services_action(&json!({ "id": "dovecot" }))
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required field"),
            "实际: {err}"
        );
        assert!(
            runner.calls().is_empty(),
            "缺动词不得执行任何 systemctl 命令"
        );
    }

    #[test]
    fn services_action_reports_a_failing_command_instead_of_a_success_list() {
        let f = Fixture::new("svcfail");
        let runner = FakeRunner::returning(1, "");
        let readers = f.readers_with_env(runner, systemd_env());

        let err = readers
            .services_action(&json!({ "id": "dovecot", "verb": "restart" }))
            .unwrap_err();
        assert!(err.to_string().contains("exited with 1"), "实际: {err}");
    }

    #[test]
    fn services_action_reports_a_runner_without_timeout_support_as_failure() {
        let f = Fixture::new("svctimeoutunsupported");
        struct NoTimeoutRunner;
        impl CommandRunner for NoTimeoutRunner {
            fn run(
                &self,
                _program: &str,
                _args: &[&str],
            ) -> mailstack_core::CoreResult<CommandOutput> {
                Ok(CommandOutput {
                    status: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        }
        let readers = f.readers_with_env(Arc::new(NoTimeoutRunner), systemd_env());

        let error = readers
            .services_action(&json!({ "id": "dovecot", "verb": "restart" }))
            .unwrap_err();

        assert!(
            error.to_string().contains("未实现超时"),
            "实际错误：{error}"
        );
    }

    #[test]
    fn services_action_status_is_a_read_and_runs_no_service_control_verb() {
        let f = Fixture::new("svcstatus");
        let runner = FakeRunner::returning(0, "");
        let readers = f.readers_with_env(runner.clone(), systemd_env());

        let out = readers
            .services_action(&json!({ "id": "dovecot", "verb": "status" }))
            .unwrap();
        assert!(out.is_array());

        for (program, args) in runner.calls() {
            assert_eq!(program, "systemctl");
            assert_eq!(args.first().map(String::as_str), Some("show"), "{args:?}");
        }
        assert!(
            !runner.calls().is_empty(),
            "status 仍应给出真实活性，而不是一份编出来的列表"
        );
    }

    fn enqueue(f: &Fixture, attempts: u32, next_attempt_unix: i64) -> String {
        let store = mailstack_queue::QueueStore::from_paths(&f.paths);
        let mut entry = mailstack_queue::QueueEntry::new(
            mailstack_queue::EntryKind::Outbound,
            "alice@example.test",
            vec!["bob@example.test".to_string()],
            "Subject: q\r\n\r\nbody\r\n",
            NOW,
        )
        .unwrap();
        entry.attempts = attempts;
        entry.next_attempt_unix = next_attempt_unix;
        entry.last_error = Some("connection refused".to_string());
        entry.last_code = Some(421);
        let id = entry.id.clone();
        store.enqueue(&entry).unwrap();
        id
    }

    fn only_entry(f: &Fixture) -> mailstack_queue::QueueEntry {
        mailstack_queue::QueueStore::from_paths(&f.paths)
            .load_all()
            .unwrap()
            .into_iter()
            .next()
            .expect("队列里应恰好有一条")
    }

    #[test]
    fn queue_action_flush_makes_only_the_deferred_entries_due() {
        let f = Fixture::new("qflush");
        let due = enqueue(&f, 1, NOW);
        let deferred = enqueue(&f, 1, NOW + 3600);
        let readers = f.readers(always_ok_runner());

        let out = readers.queue_action(&json!({ "verb": "flush" })).unwrap();
        let items = out.as_array().unwrap();
        assert_eq!(items.len(), 2, "两条都要出现在返回的列表里");

        for entry in mailstack_queue::QueueStore::from_paths(&f.paths)
            .load_all()
            .unwrap()
        {
            assert_eq!(entry.next_attempt_unix, NOW, "冲刷后都应立即到期");
        }
        assert_ne!(due, deferred);
    }

    #[test]
    fn queue_action_retry_restarts_the_attempt_budget() {
        let f = Fixture::new("qretry");
        let id = enqueue(&f, 9, NOW + 7200);
        let readers = f.readers(always_ok_runner());

        let out = readers
            .queue_action(&json!({ "id": id, "verb": "retry" }))
            .unwrap();
        assert!(out.is_array());

        let entry = only_entry(&f);
        assert_eq!(entry.attempts, 0, "重试必须重置重试预算");
        assert_eq!(entry.next_attempt_unix, NOW, "重试后应立即到期");
        assert!(entry.last_error.is_none(), "上一次的失败描述必须被清掉");
        assert!(entry.last_code.is_none());
        assert_eq!(out[0]["status"], "active");
    }

    #[test]
    fn queue_action_accepts_the_frontend_field_names() {
        let f = Fixture::new("qfrontend");
        let id = enqueue(&f, 0, NOW);
        let readers = f.readers(always_ok_runner());

        let out = readers
            .queue_action(&json!({ "id": id, "op": "delete" }))
            .unwrap();
        assert_eq!(
            out.as_array().unwrap().len(),
            0,
            "op=delete 必须真的删除条目，不能退化成重试"
        );
        assert!(mailstack_queue::QueueStore::from_paths(&f.paths)
            .load_all()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn queue_action_maps_deliver_to_retry_and_refuses_hold() {
        let f = Fixture::new("qdeliver");
        let id = enqueue(&f, 3, NOW + 3600);
        let readers = f.readers(always_ok_runner());

        let out = readers
            .queue_action(&json!({ "id": id, "op": "deliver" }))
            .unwrap();
        assert_eq!(out[0]["status"], "active");

        let err = readers
            .queue_action(&json!({ "id": id, "op": "hold" }))
            .unwrap_err();
        assert!(err.to_string().contains("invalid queue action"), "{err}");
    }

    #[test]
    fn services_action_accepts_the_frontend_field_names() {
        let f = Fixture::new("svcfrontend");
        let readers = f.readers(always_ok_runner());

        let out = readers
            .services_action(&json!({ "key": "dovecot", "op": "status" }))
            .unwrap();
        assert!(out.is_array(), "key/op 必须能被识别");
    }

    #[test]
    fn queue_action_delete_removes_the_entry() {
        let f = Fixture::new("qdelete");
        let id = enqueue(&f, 0, NOW);
        let readers = f.readers(always_ok_runner());

        let out = readers
            .queue_action(&json!({ "id": id, "verb": "delete" }))
            .unwrap();
        assert_eq!(out.as_array().unwrap().len(), 0);
        assert!(mailstack_queue::QueueStore::from_paths(&f.paths)
            .load_all()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn queue_action_without_a_verb_is_an_error_not_a_default_retry() {
        let f = Fixture::new("qnoverb");
        let id = enqueue(&f, 0, NOW);
        let readers = f.readers(always_ok_runner());

        let err = readers.queue_action(&json!({ "id": id })).unwrap_err();
        assert!(
            err.to_string().contains("missing required field"),
            "实际: {err}"
        );
        assert_eq!(
            mailstack_queue::QueueStore::from_paths(&f.paths)
                .load_all()
                .unwrap()
                .len(),
            1,
            "缺动词不得触发任何队列变更"
        );
    }

    #[test]
    fn queue_action_rejects_traversing_ids_and_unknown_verbs() {
        let f = Fixture::new("qbad");
        let readers = f.readers(always_ok_runner());

        for bad in ["../../etc/passwd", "a/b", "", "a b"] {
            let err = readers
                .queue_action(&json!({ "id": bad, "verb": "delete" }))
                .unwrap_err();
            assert!(!err.to_string().is_empty(), "{bad:?}");
        }

        let err = readers
            .queue_action(&json!({ "verb": "explode" }))
            .unwrap_err();
        assert!(err.to_string().contains("invalid queue action"), "{err}");

        let err = readers
            .queue_action(&json!({ "id": "DEADBEEF0001", "verb": "retry" }))
            .unwrap_err();
        assert!(err.to_string().contains("no such queue entry"), "{err}");
    }

    #[test]
    fn queue_action_tolerates_the_markers_postfix_prints_in_the_list() {
        let f = Fixture::new("qmarker");
        let id = enqueue(&f, 0, NOW);
        let readers = f.readers(always_ok_runner());

        readers
            .queue_action(&json!({ "id": format!("{id}*"), "verb": "retry" }))
            .unwrap();
        assert_eq!(only_entry(&f).id, id);
    }

    #[test]
    fn snapshot_exposes_the_queue_items_the_console_renders() {
        let f = Fixture::new("qsnapshot");
        let id = enqueue(&f, 3, NOW + 60);
        let out = f.readers(always_ok_runner()).snapshot(&json!({})).unwrap();

        let items = out["queues"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], id.as_str());
        assert_eq!(items[0]["sender"], "alice@example.test");
        assert_eq!(items[0]["recipient"], "bob@example.test");
        assert_eq!(items[0]["status"], "deferred", "未到期的是 deferred");
        assert_eq!(items[0]["retryCount"], 3);
        assert_eq!(items[0]["errorReason"], "connection refused");

        assert_eq!(out["queue"]["backlog"], 1);
    }

    fn manual_bans(f: &Fixture) -> Vec<mailstack_core::bans::ManualBan> {
        mailstack_core::bans::ManualBanStore::from_paths(&f.paths)
            .load()
            .unwrap()
            .unwrap_or_default()
    }

    #[test]
    fn security_ban_writes_the_file_and_says_it_takes_effect_after_reload() {
        let f = Fixture::new("ban");
        let readers = f.readers(always_ok_runner());

        let out = readers
            .security_ban(&json!({ "ip": "198.51.100.7", "note": "abuse" }))
            .unwrap();

        assert_eq!(out["banned"], "198.51.100.7");
        assert_eq!(out["scope"], "global");
        assert_eq!(
            out["takesEffectAfterReload"], true,
            "文件驱动意味着生效有延迟，必须如实告知"
        );

        let bans = manual_bans(&f);
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip.to_string(), "198.51.100.7");
        assert_eq!(bans[0].note.as_deref(), Some("abuse"));
    }

    #[test]
    fn security_ban_normalises_equivalent_addresses() {
        let f = Fixture::new("bannorm");
        let readers = f.readers(always_ok_runner());
        readers.security_ban(&json!({ "ip": "::1" })).unwrap();
        let out = readers
            .security_ban(&json!({ "ip": "0:0:0:0:0:0:0:1" }))
            .unwrap();
        assert_eq!(out["count"], 1, "规范化后必须还是一条");
        assert_eq!(manual_bans(&f).len(), 1);
    }

    #[test]
    fn security_ban_rejects_anything_that_is_not_an_address() {
        let f = Fixture::new("banbad");
        let readers = f.readers(always_ok_runner());

        for bad in [
            "",
            "not-an-ip",
            "198.51.100.7/24",
            "example.com",
            "300.1.1.1",
        ] {
            let err = readers.security_ban(&json!({ "ip": bad })).unwrap_err();
            assert!(
                err.to_string().contains("invalid ip address"),
                "{bad:?} 实际: {err}"
            );
        }

        let err = readers.security_ban(&json!({})).unwrap_err();
        assert!(err.to_string().contains("missing required field"), "{err}");

        assert!(manual_bans(&f).is_empty());
    }

    #[test]
    fn security_unban_removes_only_the_named_address() {
        let f = Fixture::new("unban");
        let readers = f.readers(always_ok_runner());
        readers
            .security_ban(&json!({ "ip": "198.51.100.7" }))
            .unwrap();
        readers
            .security_ban(&json!({ "ip": "198.51.100.8" }))
            .unwrap();

        let out = readers
            .security_unban(&json!({ "ip": "198.51.100.7" }))
            .unwrap();
        assert_eq!(out["unbanned"], "198.51.100.7");
        assert_eq!(out["count"], 1);

        let bans = manual_bans(&f);
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip.to_string(), "198.51.100.8");

        readers
            .security_unban(&json!({ "ip": "198.51.100.7" }))
            .unwrap();
    }

    #[test]
    fn a_manual_ban_is_never_written_over_a_corrupt_file() {
        let f = Fixture::new("bancorrupt");
        fs::create_dir_all(f.paths.manual_bans.parent().unwrap()).unwrap();
        fs::write(&f.paths.manual_bans, "{ not a ban list").unwrap();
        let readers = f.readers(always_ok_runner());

        assert!(readers
            .security_ban(&json!({ "ip": "198.51.100.7" }))
            .is_err());
        assert_eq!(
            fs::read_to_string(&f.paths.manual_bans).unwrap(),
            "{ not a ban list"
        );
    }

    #[test]
    fn security_scan_lists_manual_bans_and_says_what_the_list_covers() {
        let f = Fixture::new("scanbans");
        mailstack_core::config::admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let readers = f.readers(always_ok_runner());
        readers
            .security_ban(&json!({ "ip": "198.51.100.7", "note": "abuse" }))
            .unwrap();

        let out = readers.security_scan(&json!({})).unwrap();
        assert_eq!(
            out["bannedIpScope"], "manual",
            "只列手工封禁就必须标注范围，否则会让人以为「一共就这几条」"
        );
        let banned = out["bannedIps"].as_array().unwrap();
        assert_eq!(banned.len(), 1);
        assert_eq!(banned[0]["ip"], "198.51.100.7");
        assert_eq!(banned[0]["reason"], "abuse");
    }

    #[test]
    fn security_scan_reports_a_null_ban_list_when_the_file_cannot_be_read() {
        let f = Fixture::new("scanbancorrupt");
        mailstack_core::config::admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        fs::create_dir_all(f.paths.manual_bans.parent().unwrap()).unwrap();
        fs::write(&f.paths.manual_bans, "{ not a ban list").unwrap();

        let out = f
            .readers(always_ok_runner())
            .security_scan(&json!({}))
            .unwrap();
        assert!(out["bannedIps"].is_null(), "读不到必须是 null：{out}");
    }

    #[cfg(unix)]
    #[test]
    fn security_scan_flags_a_world_readable_ban_file() {
        let f = Fixture::new("scanbanmode");
        mailstack_core::config::admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        chmod(&f.paths.etc, 0o750);
        f.readers(always_ok_runner())
            .security_ban(&json!({ "ip": "198.51.100.7" }))
            .unwrap();
        chmod(&f.paths.manual_bans, 0o644);

        let out = f
            .readers(always_ok_runner())
            .security_scan(&json!({}))
            .unwrap();
        let finding = out["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["path"].as_str().unwrap().ends_with("manual-bans.json"))
            .unwrap_or_else(|| panic!("必须报出手工封禁表权限过宽：{out}"));
        assert_eq!(finding["issue"], "world_readable");
        assert_eq!(finding["severity"], "high", "它能决定谁可以连 SMTP");
    }

    fn listed<'a>(items: &'a [Value], filename: &str) -> &'a Value {
        items
            .iter()
            .find(|item| item["filename"] == filename)
            .unwrap_or_else(|| panic!("列表里缺少 {filename}"))
    }

    #[test]
    fn backup_create_writes_an_archive_with_metadata_and_flags_its_own_reload_need() {
        let f = Fixture::new("bcreate");
        let readers = f.backup_readers(always_ok_runner());

        let out = readers
            .backup_create(&json!({ "includeSecrets": true }))
            .unwrap();
        assert_eq!(out["created"], true);
        let backup = &out["backup"];
        let filename = backup["filename"].as_str().unwrap();
        assert!(
            mailstack_core::backup::is_backup_filename(filename),
            "文件名必须合规：{filename}"
        );
        assert_eq!(backup["encrypted"], false, "local 模式允许明文");
        assert_eq!(backup["includeSecrets"], true);
        assert!(
            backup["sha256"].as_str().unwrap().len() == 64,
            "必须有校验和：{backup}"
        );

        let listed_items = readers.backup_list(&json!({})).unwrap();
        let items = listed_items.as_array().unwrap().to_vec();
        let entry = listed(&items, filename);

        assert!(
            entry["sha256"].is_string(),
            "刚写完的备份必须带校验和：{entry}"
        );
        assert_ne!(entry["metadataMissing"], true, "元数据应当读得到：{entry}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(f.paths.backups_dir.join(filename))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "归档里有凭证，必须 0600");
        }
    }

    #[test]
    fn backup_create_excludes_secrets_unless_explicitly_asked() {
        let f = Fixture::new("bsecret");
        let readers = f.backup_readers(always_ok_runner());
        let out = readers.backup_create(&json!({})).unwrap();
        let filename = out["backup"]["filename"].as_str().unwrap().to_string();

        let archive = f.paths.backups_dir.join(&filename);
        let file = fs::File::open(&archive).unwrap();
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let names: Vec<String> = tar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(
            !names.iter().any(|n| n.ends_with("admin.json")),
            "没要求含机密时不得打包 admin.json：{names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("settings.json")),
            "{names:?}"
        );
    }

    #[test]
    fn backup_create_says_so_when_there_is_nothing_to_back_up() {
        let f = Fixture::new("bempty");

        fs::remove_dir_all(&f.backup_root).unwrap();
        let err = f
            .backup_readers(always_ok_runner())
            .backup_create(&json!({}))
            .unwrap_err();
        assert!(
            err.to_string().contains("No configuration sources"),
            "{err}"
        );
    }

    #[test]
    fn backup_restore_requires_explicit_confirmation_and_a_known_filename() {
        let f = Fixture::new("bconfirm");
        let readers = f.backup_readers(always_ok_runner());
        let created = readers
            .backup_create(&json!({ "includeSecrets": true }))
            .unwrap();
        let filename = created["backup"]["filename"].as_str().unwrap().to_string();

        let err = readers
            .backup_restore(&json!({ "filename": filename }))
            .unwrap_err();
        assert!(err.to_string().contains("confirmation"), "{err}");
        let restored_count = walk(&f.restore_root).len();
        assert_eq!(restored_count, 0, "被拒绝的恢复不得写任何文件");

        let err = readers
            .backup_restore(&json!({ "filename": "../../etc/passwd", "confirm": true }))
            .unwrap_err();
        assert!(err.to_string().contains("Backup filename"), "{err}");
    }

    #[test]
    fn backup_restore_dry_run_previews_without_touching_the_target_root() {
        let f = Fixture::new("bdry");
        let readers = f.backup_readers(always_ok_runner());
        let created = readers
            .backup_create(&json!({ "includeSecrets": true }))
            .unwrap();
        let filename = created["backup"]["filename"].as_str().unwrap().to_string();

        let out = readers
            .backup_restore(&json!({ "filename": filename, "dryRun": true }))
            .unwrap();
        assert_eq!(out["dryRun"], true);
        assert_eq!(out["ready"], true);
        assert!(out["filesCount"].as_u64().unwrap() > 0);
        assert!(walk(&f.restore_root).is_empty(), "dryRun 不得写落地根");
    }

    #[test]
    fn backup_restore_round_trips_and_leaves_a_readable_rollback_point() {
        let f = Fixture::new("broundtrip");
        let readers = f.backup_readers(always_ok_runner());
        let created = readers
            .backup_create(&json!({ "includeSecrets": true }))
            .unwrap();
        let filename = created["backup"]["filename"].as_str().unwrap().to_string();

        fs::write(f.backup_root.join("etc/mailstack/settings.json"), "{}").unwrap();
        let out = readers
            .backup_restore(&json!({ "filename": filename, "confirm": true }))
            .unwrap();

        assert_eq!(out["restored"], true);
        assert!(out["filesCount"].as_u64().unwrap() > 0);

        assert_eq!(out["restartRequired"], true);
        assert_eq!(
            fs::read_to_string(f.restore_root.join("etc/mailstack/settings.json")).unwrap(),
            "{}"
        );

        assert!(
            out["preRestoreSnapshot"].is_string(),
            "缺少预恢复快照：{out}"
        );
        assert!(out["preRestoreSnapshotWarning"].is_null());
        let snapshot = out["preRestoreSnapshot"].as_str().unwrap();
        assert!(std::path::Path::new(snapshot).is_file());

        let store = mailstack_core::backup::BackupStore::from_paths(&f.paths);
        assert!(store
            .resolve(
                std::path::Path::new(snapshot)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
            .is_ok());
    }

    #[test]
    fn backup_delete_requires_confirmation_and_removes_archive_with_metadata() {
        let f = Fixture::new("bdelete");
        let readers = f.backup_readers(always_ok_runner());
        let created = readers
            .backup_create(&json!({ "includeSecrets": true }))
            .unwrap();
        let filename = created["backup"]["filename"].as_str().unwrap().to_string();
        let archive = f.paths.backups_dir.join(&filename);
        let store = mailstack_core::backup::BackupStore::from_paths(&f.paths);
        let metadata_path = store.metadata_path(&archive);

        let err = readers
            .backup_delete(&json!({ "filename": filename }))
            .unwrap_err();
        assert!(err.to_string().contains("confirmation"), "{err}");
        assert!(archive.is_file(), "被拒绝的删除不得动文件");

        let out = readers
            .backup_delete(&json!({ "filename": filename, "confirm": true }))
            .unwrap();
        assert_eq!(out["deleted"], true);
        assert!(!archive.exists());
        assert!(!metadata_path.exists(), "元数据必须一并删除");
    }

    #[test]
    fn backup_create_includes_the_managed_maildir() {
        let f = Fixture::new("bmail");
        let readers = f.backup_readers_with_a_managed_mailbox(always_ok_runner());

        let out = readers
            .backup_create(&json!({ "includeMails": true, "includeSecrets": true }))
            .unwrap();
        assert_eq!(out["backup"]["includeMails"], true);
        assert_eq!(
            out["backup"]["partial"], false,
            "邮件来源齐全时不该标 partial"
        );
        assert_eq!(out["warnings"], json!([]));

        let filename = out["backup"]["filename"].as_str().unwrap().to_string();
        let members = f.archive_members(&filename);
        assert!(
            members.contains(&"home/alice/Maildir/new/1712000000.M1P1.mx.eml".to_string()),
            "归档必须包含受管邮箱的邮件（权威布局 home/<user>/Maildir）：{members:?}"
        );
    }

    #[test]
    fn backup_restore_puts_a_managed_maildir_back_into_the_target_root() {
        let f = Fixture::new("bmailrestore");
        let readers = f.backup_readers_with_a_managed_mailbox(always_ok_runner());
        let created = readers
            .backup_create(&json!({ "includeMails": true }))
            .unwrap();
        let filename = created["backup"]["filename"].as_str().unwrap().to_string();

        fs::remove_file(
            f.backup_root
                .join("home/alice/Maildir/new/1712000000.M1P1.mx.eml"),
        )
        .unwrap();
        let out = readers
            .backup_restore(&json!({ "filename": filename, "confirm": true }))
            .unwrap();
        assert_eq!(out["restored"], true);

        let restored = f
            .restore_root
            .join("home/alice/Maildir/new/1712000000.M1P1.mx.eml");
        assert_eq!(
            fs::read_to_string(&restored).unwrap(),
            "Subject: hi\r\n\r\nbody",
            "受管邮箱的邮件必须被还原到 {}",
            restored.display()
        );
    }

    #[test]
    fn backup_create_refuses_include_mails_when_no_maildir_is_resolvable() {
        let f = Fixture::new("bmailnone");
        let err = f
            .backup_readers(always_ok_runner())
            .backup_create(&json!({ "includeMails": true }))
            .unwrap_err();
        assert!(
            err.to_string().contains("no managed mailbox Maildir"),
            "必须显式说明没有邮件来源：{err}"
        );
    }

    #[test]
    fn backup_create_fails_closed_when_the_managed_registry_is_corrupt() {
        let f = Fixture::new("bmailcorrupt");
        fs::create_dir_all(f.paths.managed_users.parent().unwrap()).unwrap();
        fs::write(&f.paths.managed_users, "{not a json array").unwrap();
        let err = f
            .backup_readers(always_ok_runner())
            .backup_create(&json!({ "includeMails": true }))
            .unwrap_err();
        assert!(
            err.to_string().contains("managed user registry is corrupt"),
            "{err}"
        );
    }

    #[test]
    fn backup_restore_still_rejects_an_unmanaged_home_member() {
        let f = Fixture::new("bmailunmanaged");

        let bob_maildir = f.backup_root.join("home/bob/Maildir/new");
        fs::create_dir_all(&bob_maildir).unwrap();
        fs::write(bob_maildir.join("1.eml"), "Subject: bob\r\n\r\nx").unwrap();
        fs::create_dir_all(&f.paths.backups_dir).unwrap();
        let filename = "mailstack-backup-20261002-120000.tar.gz";
        let target = f.paths.backups_dir.join(filename);
        mailstack_core::backup::create_archive(
            &f.backup_root,
            &[f.backup_root.join("home/bob/Maildir")],
            &target,
            &[],
            false,
        )
        .unwrap();
        let store = mailstack_core::backup::BackupStore::from_paths(&f.paths);
        store
            .write_metadata(&mailstack_core::backup::BackupMetadata {
                name: filename.to_string(),
                filename: filename.to_string(),
                path: target.display().to_string(),
                size: fs::metadata(&target).unwrap().len(),
                sha256: Some(mailstack_core::backup::file_sha256(&target).unwrap()),
                created_at: "2026-10-02T12:00:00Z".to_string(),
                include_mails: true,
                include_secrets: false,
                partial: false,
                encrypted: false,
                version: mailstack_core::VERSION.to_string(),
                metadata_missing: false,
            })
            .unwrap();

        let readers = f.backup_readers_with_a_managed_mailbox(always_ok_runner());
        let err = readers
            .backup_restore(&json!({ "filename": filename, "confirm": true }))
            .unwrap_err();
        assert!(
            err.to_string().contains("does not manage"),
            "非受管家目录必须被拒：{err}"
        );
        assert!(
            walk(&f.restore_root).is_empty(),
            "被拒的恢复不得落地任何文件"
        );
    }

    fn walk(root: &std::path::Path) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(read) = fs::read_dir(root) else {
            return out;
        };
        for item in read.flatten() {
            let path = item.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path.display().to_string());
            }
        }
        out
    }

    struct StaticDns {
        a: Vec<String>,
        mx: Vec<String>,
        txt: std::collections::HashMap<String, Vec<String>>,

        failure: Option<String>,
    }

    impl StaticDns {
        fn new() -> Self {
            Self {
                a: Vec::new(),
                mx: Vec::new(),
                txt: std::collections::HashMap::new(),
                failure: None,
            }
        }

        fn with_a(mut self, values: &[&str]) -> Self {
            self.a = values.iter().map(|v| v.to_string()).collect();
            self
        }

        fn with_mx(mut self, values: &[&str]) -> Self {
            self.mx = values.iter().map(|v| v.to_string()).collect();
            self
        }

        fn with_txt(mut self, name: &str, values: &[&str]) -> Self {
            self.txt.insert(
                name.to_string(),
                values.iter().map(|v| v.to_string()).collect(),
            );
            self
        }

        fn failing(message: &str) -> Self {
            Self {
                failure: Some(message.to_string()),
                ..Self::new()
            }
        }
    }

    impl DnsQuery for StaticDns {
        fn lookup_a(&self, _host: &str) -> DnsFuture<'_> {
            let out = match &self.failure {
                Some(message) => Err(SmtpError::Dns(message.clone())),
                None => Ok(self.a.clone()),
            };
            Box::pin(async move { out })
        }

        fn lookup_mx_records(&self, _domain: &str) -> DnsFuture<'_> {
            let out = match &self.failure {
                Some(message) => Err(SmtpError::Dns(message.clone())),
                None => Ok(self.mx.clone()),
            };
            Box::pin(async move { out })
        }

        fn lookup_txt(&self, name: &str) -> DnsFuture<'_> {
            let out = match &self.failure {
                Some(message) => Err(SmtpError::Dns(message.clone())),
                None => Ok(self.txt.get(name).cloned().unwrap_or_default()),
            };
            Box::pin(async move { out })
        }
    }

    fn dkim_txt_value() -> String {
        format!("v=DKIM1; k=rsa; p={}", "A".repeat(120))
    }

    fn passed_relay_result() -> RelayTestResult {
        RelayTestResult {
            connected: true,
            stage: RelayStage::Auth,
            latency_ms: 7,
            stages: vec![
                StageOutcome::new(
                    RelayStage::Dns,
                    true,
                    json!({ "addresses": ["203.0.113.9"], "pinnedAddress": "203.0.113.9" }),
                ),
                StageOutcome::new(RelayStage::Connect, true, json!({ "code": 220 })),
                StageOutcome::new(RelayStage::Tls, true, json!({ "implicit": false })),
                StageOutcome::new(RelayStage::Auth, true, json!({ "skipped": true })),
            ],
        }
    }

    struct ScriptedRelayProbe {
        test: Result<RelayTestResult, String>,
        direct: Result<RelayTestResult, String>,

        seen: Mutex<Vec<RelayValidationRequest>>,
    }

    impl ScriptedRelayProbe {
        fn passing() -> Arc<Self> {
            Arc::new(Self {
                test: Ok(passed_relay_result()),
                direct: Ok(passed_relay_result()),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                test: Err("connection refused".to_string()),
                direct: Err("local MTA is down".to_string()),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Vec<RelayValidationRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl RelayProbe for ScriptedRelayProbe {
        fn test<'a>(
            &'a self,
            request: &'a RelayValidationRequest,
            _private_network_enabled: bool,
        ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>>
        {
            self.seen.lock().unwrap().push(request.clone());
            let out = match &self.test {
                Ok(result) => Ok(result.clone()),
                Err(message) => Err(probe_unavailable(SmtpError::Rejected(message.clone()))),
            };
            Box::pin(async move { out })
        }

        fn direct<'a>(
            &'a self,
            _target: PinnedTarget,
        ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>>
        {
            let out = match &self.direct {
                Ok(result) => Ok(result.clone()),
                Err(message) => Err(probe_unavailable(SmtpError::Rejected(message.clone()))),
            };
            Box::pin(async move { out })
        }
    }

    fn readers_with_networks(
        f: &Fixture,
        dns: Arc<dyn DnsQuery>,
        relay: Arc<dyn RelayProbe>,
    ) -> Readers {
        f.readers(always_ok_runner())
            .with_dns(dns)
            .with_relay_probe(relay)
    }

    fn published_dns() -> StaticDns {
        StaticDns::new()
            .with_a(&["203.0.113.10"])
            .with_mx(&["10 mail.example.com."])
            .with_txt("example.com", &["v=spf1 mx -all"])
            .with_txt("mail._domainkey.example.com", &[&dkim_txt_value()])
            .with_txt(
                "_dmarc.example.com",
                &["v=DMARC1; rua=mailto:dmarc@example.com"],
            )
    }

    fn identity_payload() -> Value {
        json!({
            "domain": "example.com",
            "mailHost": "mail.example.com",
            "serverIp": "203.0.113.10",
            "expectedSpf": "v=spf1 mx -all",
        })
    }

    #[test]
    fn the_setup_actions_are_registered() {
        let f = Fixture::new("setupregistered");
        let registry = Registry::new().with_readers(Arc::new(f.readers(always_ok_runner())));
        for action in [
            "setup.identity.apply",
            "setup.dns.verify",
            "setup.relay.test",
            "setup.relay.apply",
        ] {
            assert!(registry.is_implemented(action), "{action} 必须已接线");
        }
    }

    #[test]
    fn setup_identity_apply_writes_setup_json_and_returns_the_publishable_key() {
        let f = Fixture::new("setupidentity");
        let readers = f.readers(always_ok_runner());

        let out = readers.setup_identity_apply(&identity_payload()).unwrap();
        assert_eq!(out["applied"], true);
        assert_eq!(out["identity"]["domain"], "example.com");
        assert_eq!(out["identity"]["mailHost"], "mail.example.com");
        assert_eq!(out["identity"]["serverIp"], "203.0.113.10");
        assert_eq!(out["identity"]["expectedSpf"], "v=spf1 mx -all");

        assert_eq!(out["identity"]["dkimSelector"], "mail");

        let public_key = out["dkimPublicKey"].as_str().unwrap();
        assert!(!public_key.is_empty());
        let txt = fs::read_to_string(mailstack_auth::keys::txt_record_path(
            &f.paths,
            "example.com",
            "mail",
        ))
        .unwrap();
        let flattened: String = txt
            .chars()
            .filter(|c| *c != '"' && !c.is_whitespace())
            .collect();
        assert!(
            flattened.contains(&format!("p={public_key}")),
            "返回的 dkimPublicKey 与 .txt 不一致"
        );

        assert!(f.paths.setup_config.is_file());
        assert!(mailstack_auth::keys::private_key_path(&f.paths, "example.com", "mail").is_file());
        let stored = mailstack_core::config::read_setup_config(&f.paths).unwrap();
        assert_eq!(stored.domain, "example.com");
    }

    #[test]
    fn setup_identity_apply_rejects_bad_input_without_any_side_effect() {
        let f = Fixture::new("setupidentitybad");
        let readers = f.readers(always_ok_runner());

        for bad in [
            json!({ "domain": "not a domain", "mailHost": "mail.example.com", "serverIp": "203.0.113.10" }),
            json!({ "domain": "example.com", "mailHost": "example.com", "serverIp": "203.0.113.10" }),
            json!({ "domain": "example.com", "mailHost": "mail.other.com", "serverIp": "203.0.113.10" }),
            json!({ "domain": "example.com", "mailHost": "mail.example.com", "serverIp": "not-an-ip" }),
            json!({ "domain": "example.com", "mailHost": "mail.example.com", "serverIp": "203.0.113.10", "dkimSelector": "bad selector" }),
        ] {
            assert!(
                readers.setup_identity_apply(&bad).is_err(),
                "{bad} 必须被拒绝"
            );
        }

        assert!(readers.setup_identity_apply(&json!({})).is_err());

        assert!(!f.paths.setup_config.exists());
        assert!(!f.paths.opendkim.exists(), "校验失败不得创建密钥目录");
    }

    #[tokio::test]
    async fn setup_dns_verify_reports_every_predicate_and_the_observed_records() {
        let f = Fixture::new("setupdns");
        let readers =
            readers_with_networks(&f, Arc::new(published_dns()), ScriptedRelayProbe::passing());

        let out = readers.setup_dns_verify(&identity_payload()).await.unwrap();
        assert_eq!(out["verified"], true, "整份结果: {out}");
        for check in ["a", "mx", "spfSingle", "spfExpected", "dkim", "dmarc"] {
            assert_eq!(out["checks"][check], true, "{check} 应为真: {out}");
        }
        assert_eq!(out["spfRecordCount"], 1);

        assert_eq!(out["observed"]["a"][0], "203.0.113.10");
        assert_eq!(out["observed"]["mx"][0], "10 mail.example.com.");
        assert_eq!(out["observed"]["spf"][0], "v=spf1 mx -all");
        assert_eq!(
            out["observed"]["dmarc"][0],
            "v=DMARC1; rua=mailto:dmarc@example.com"
        );
    }

    #[tokio::test]
    async fn setup_dns_verify_reports_missing_records_as_unverified_not_as_an_error() {
        let f = Fixture::new("setupdnsnone");
        let readers = readers_with_networks(
            &f,
            Arc::new(StaticDns::new()),
            ScriptedRelayProbe::passing(),
        );

        let out = readers.setup_dns_verify(&identity_payload()).await.unwrap();
        assert_eq!(out["verified"], false);
        assert_eq!(out["checks"]["a"], false);
        assert_eq!(out["checks"]["dkim"], false);
        assert_eq!(out["spfRecordCount"], 0);
    }

    #[tokio::test]
    async fn setup_dns_verify_surfaces_a_resolver_failure_instead_of_calling_it_unpublished() {
        let f = Fixture::new("setupdnsfail");
        let readers = readers_with_networks(
            &f,
            Arc::new(StaticDns::failing("resolver unreachable")),
            ScriptedRelayProbe::passing(),
        );

        let err = readers
            .setup_dns_verify(&identity_payload())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("resolver unreachable"),
            "解析故障必须上抛: {err}"
        );
    }

    #[tokio::test]
    async fn setup_dns_verify_rejects_a_second_spf_record() {
        let f = Fixture::new("setupdnsspf");
        let dns =
            published_dns().with_txt("example.com", &["v=spf1 mx -all", "v=spf1 include:x -all"]);
        let readers = readers_with_networks(&f, Arc::new(dns), ScriptedRelayProbe::passing());

        let out = readers.setup_dns_verify(&identity_payload()).await.unwrap();
        assert_eq!(out["checks"]["spfSingle"], false);
        assert_eq!(out["spfRecordCount"], 2);
        assert_eq!(out["verified"], false);
    }

    #[tokio::test]
    async fn setup_dns_verify_checks_the_ses_mail_from_records() {
        let f = Fixture::new("setupdnsses");

        let dns =
            published_dns().with_txt("bounce.example.com", &["v=spf1 include:amazonses.com -all"]);
        let readers = readers_with_networks(&f, Arc::new(dns), ScriptedRelayProbe::passing());

        let mut payload = identity_payload();
        payload["selectedRelay"] = json!("ses");
        payload["sesMailFrom"] = json!("bounce.example.com");
        let out = readers.setup_dns_verify(&payload).await.unwrap();
        assert_eq!(
            out["checks"]["sesMailFromMx"], false,
            "未发布 SES MX 应被单独标出: {out}"
        );
        assert_eq!(out["checks"]["sesMailFromSpf"], true);
        assert_eq!(
            out["observed"]["sesSpf"][0],
            "v=spf1 include:amazonses.com -all"
        );
    }

    #[test]
    fn mx_records_contain_requires_an_exact_host_match() {
        let records = vec![
            "10 evilemail.example.com.".to_string(),
            "20 mail.example.com.attacker.net.".to_string(),
        ];
        assert!(
            !mx_records_contain(&records, "mail.example.com"),
            "子串 / 后缀伪装不得命中"
        );

        assert!(mx_records_contain(
            &["10 mail.example.com.".to_string()],
            "mail.example.com"
        ));
        assert!(mx_records_contain(
            &["10 MAIL.EXAMPLE.COM".to_string()],
            "mail.example.com."
        ));

        assert!(!mx_records_contain(&records, "  "));
    }

    #[tokio::test]
    async fn spf_expected_falls_back_to_the_conventional_value_when_absent() {
        let f = Fixture::new("spfdefault");
        let mut payload = identity_payload();
        payload.as_object_mut().unwrap().remove("expectedSpf");
        let readers =
            readers_with_networks(&f, Arc::new(published_dns()), ScriptedRelayProbe::passing());

        let out = readers.setup_dns_verify(&payload).await.unwrap();
        assert_eq!(out["checks"]["spfExpected"], true, "整份结果: {out}");
        assert_eq!(out["checks"]["mx"], true);
    }

    #[tokio::test]
    async fn setup_relay_test_reports_a_failed_probe_as_a_conclusion_with_stages() {
        let f = Fixture::new("setuptestfail");
        let probe = ScriptedRelayProbe::failing();
        let readers = readers_with_networks(&f, Arc::new(published_dns()), probe.clone());

        let out = readers
            .setup_relay_test(&json!({ "host": "smtp.sendgrid.net", "port": 587 }))
            .await
            .unwrap();
        assert_eq!(out["connected"], false);
        assert_eq!(out["stage"], "failed");
        assert_eq!(out["error"]["code"], "SmtpRejected");
        assert_eq!(out["stages"][0]["stage"], "failed");
        assert_eq!(probe.requests().len(), 1, "探针应被调用一次");
    }

    #[tokio::test]
    async fn setup_relay_test_returns_the_full_stage_list_on_success() {
        let f = Fixture::new("setuptestok");
        let readers =
            readers_with_networks(&f, Arc::new(published_dns()), ScriptedRelayProbe::passing());

        let out = readers
            .setup_relay_test(&json!({ "host": "smtp.sendgrid.net", "port": 587 }))
            .await
            .unwrap();
        assert_eq!(out["connected"], true);
        assert_eq!(out["stage"], "auth");
        let order: Vec<&str> = out["stages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["stage"].as_str().unwrap())
            .collect();
        assert_eq!(order, vec!["dns", "connect", "tls", "auth"]);
    }

    #[tokio::test]
    async fn setup_relay_test_rejects_malformed_requests_before_any_probe() {
        let f = Fixture::new("setuptestbad");
        let probe = ScriptedRelayProbe::passing();
        let readers = readers_with_networks(&f, Arc::new(published_dns()), probe.clone());

        for bad in [
            json!({ "host": "bad host", "port": 587 }),
            json!({ "host": "smtp.sendgrid.net", "port": 22 }),
            json!({ "host": "smtp.sendgrid.net", "port": 587, "tlsMode": "none" }),
            json!({ "host": "smtp.sendgrid.net", "port": 587, "username": "u" }),
            json!({ "port": 587 }),
        ] {
            assert!(
                readers.setup_relay_test(&bad).await.is_err(),
                "{bad} 必须被拒绝"
            );
        }
        assert!(
            probe.requests().is_empty(),
            "被拒的请求不得触碰网络：{:?}",
            probe.requests()
        );
    }

    #[tokio::test]
    async fn setup_relay_test_refuses_a_private_relay_when_the_deployment_disallows_it() {
        let f = Fixture::new("setuptestprivate");

        fs::write(&f.paths.install_args_conf, "ACCESS_MODE=caddy\n").unwrap();
        let probe = ScriptedRelayProbe::passing();
        let readers = readers_with_networks(&f, Arc::new(published_dns()), probe.clone());

        let err = readers
            .setup_relay_test(&json!({
                "host": "10.0.0.5",
                "port": 587,
                "allowPrivateNetwork": true,
            }))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Private SMTP relay access is disabled"),
            "实际: {err}"
        );
        assert!(probe.requests().is_empty(), "被拒的请求不得触碰网络");
    }

    #[tokio::test]
    async fn setup_relay_test_direct_probes_the_hardcoded_local_endpoint() {
        let f = Fixture::new("setuptestdirect");
        let readers =
            readers_with_networks(&f, Arc::new(published_dns()), ScriptedRelayProbe::passing());

        let out = readers
            .setup_relay_test(&json!({ "direct": true }))
            .await
            .unwrap();
        assert_eq!(out["connected"], true);

        assert!(!out["stages"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn setup_relay_apply_writes_the_native_relay_config_only_after_a_passing_test() {
        let f = Fixture::new("setupapply");
        let readers =
            readers_with_networks(&f, Arc::new(published_dns()), ScriptedRelayProbe::passing());

        let out = readers
            .setup_relay_apply(&json!({
                "host": "smtp.sendgrid.net",
                "port": 587,
                "username": "apikey",
                "password": "SG.secret",
            }))
            .await
            .unwrap();
        assert_eq!(out["applied"], true);
        assert_eq!(out["relayhost"], "[smtp.sendgrid.net]:587");
        assert_eq!(out["test"]["connected"], true);

        let doc: Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.relay_config).unwrap()).unwrap();
        assert_eq!(doc["relayhost"], "[smtp.sendgrid.net]:587");
        assert_eq!(doc["smtp_sasl_auth_enable"], "yes");
        assert_eq!(doc["smtp_tls_security_level"], "encrypt");
        assert!(doc["saslPasswd"].as_str().unwrap().contains("SG.secret"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&f.paths.relay_config)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "relay.json 含明文口令，必须 0600");
        }
    }

    #[tokio::test]
    async fn setup_relay_apply_leaves_the_config_untouched_when_the_test_fails() {
        let f = Fixture::new("setupapplyfail");
        let readers =
            readers_with_networks(&f, Arc::new(published_dns()), ScriptedRelayProbe::failing());

        let out = readers
            .setup_relay_apply(&json!({ "host": "smtp.sendgrid.net", "port": 587 }))
            .await
            .unwrap();
        assert_eq!(out["applied"], false);
        assert_eq!(out["test"]["connected"], false);
        assert!(
            !f.paths.relay_config.exists(),
            "测试未通过时不得写出 relay.json"
        );
    }

    #[tokio::test]
    async fn setup_relay_apply_never_overwrites_the_previous_config_when_the_test_fails() {
        let f = Fixture::new("setupapplykeep");
        fs::write(
            &f.paths.relay_config,
            r#"{"relayhost":"[old.example.com]:25"}"#,
        )
        .unwrap();
        let readers =
            readers_with_networks(&f, Arc::new(published_dns()), ScriptedRelayProbe::failing());

        readers
            .setup_relay_apply(&json!({ "host": "smtp.sendgrid.net", "port": 587 }))
            .await
            .unwrap();
        assert_eq!(
            fs::read_to_string(&f.paths.relay_config).unwrap(),
            r#"{"relayhost":"[old.example.com]:25"}"#
        );
    }

    #[tokio::test]
    async fn setup_relay_apply_with_direct_clears_a_previously_configured_relay() {
        use mailstack_smtp::RelayConfigStore;

        let f = Fixture::new("setupapplydirect");

        let mut store = NativeRelayStore::production(&f.paths);
        store
            .write_key(
                mailstack_smtp::relay_apply::KEY_RELAYHOST,
                "[smtp.sendgrid.net]:587",
            )
            .unwrap();
        store
            .write_key(mailstack_smtp::relay_apply::KEY_SASL_AUTH_ENABLE, "yes")
            .unwrap();
        store
            .write_key(
                mailstack_smtp::relay_apply::KEY_TLS_SECURITY_LEVEL,
                "encrypt",
            )
            .unwrap();
        store
            .write_credentials("[smtp.sendgrid.net]:587 apikey:SG.secret\n")
            .unwrap();

        let readers = f.readers(always_ok_runner());
        let out = readers
            .setup_relay_apply(&json!({ "direct": true }))
            .await
            .unwrap();

        assert_eq!(out["applied"], true);
        assert_eq!(out["mode"], "direct");
        assert_eq!(out["relayhost"], "");

        let doc: Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.relay_config).unwrap()).unwrap();
        for key in [
            "relayhost",
            "smtp_sasl_auth_enable",
            "smtp_sasl_password_maps",
            "smtp_sasl_security_options",
            "smtp_tls_security_level",
            "smtp_tls_wrappermode",
            "saslPasswd",
        ] {
            assert!(doc.get(key).is_none(), "{key} 必须被清除，实际: {doc}");
        }

        let again = readers
            .setup_relay_apply(&json!({ "direct": true }))
            .await
            .unwrap();
        assert_eq!(again["applied"], true);
        assert_eq!(again["mode"], "direct");
    }

    #[tokio::test]
    async fn setup_relay_apply_with_direct_on_a_fresh_install_is_a_successful_no_op() {
        let f = Fixture::new("setupapplydirectfresh");
        let readers = f.readers(always_ok_runner());
        let out = readers
            .setup_relay_apply(&json!({ "direct": true }))
            .await
            .unwrap();
        assert_eq!(out["applied"], true);
        assert_eq!(out["mode"], "direct");
    }

    #[test]
    fn a_truncated_dkim_key_is_not_accepted_as_published() {
        assert!(has_dkim_public_key(&dkim_txt_value()));
        assert!(!has_dkim_public_key(&format!(
            "v=DKIM1; k=rsa; p={}",
            "A".repeat(99)
        )));

        assert!(!has_dkim_public_key("v=DKIM1; k=rsa;"));

        assert!(!has_dkim_public_key(&"A".repeat(200)));
    }

    #[test]
    fn setup_selector_defaults_to_the_baseline_value_not_the_rotation_default() {
        assert_eq!(setup_selector(&json!({})), SETUP_DEFAULT_DKIM_SELECTOR);
        assert_eq!(setup_selector(&json!({ "dkimSelector": "  " })), "mail");
        assert_eq!(
            setup_selector(&json!({ "dkimSelector": "Mail-2" })),
            "mail-2"
        );
        assert_ne!(
            SETUP_DEFAULT_DKIM_SELECTOR,
            mailstack_auth::keys::DEFAULT_DKIM_SELECTOR
        );
    }

    struct RecordingSubmitter {
        seen: Mutex<Vec<crate::mailtest::LocalSubmission>>,

        outcome: Result<u16, String>,

        deliver_to: Option<PathBuf>,
    }

    impl RecordingSubmitter {
        fn accepting() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
                outcome: Ok(250),
                deliver_to: None,
            })
        }

        fn rejecting(message: &str) -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
                outcome: Err(message.to_string()),
                deliver_to: None,
            })
        }

        fn delivering_to(dir: PathBuf) -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
                outcome: Ok(250),
                deliver_to: Some(dir),
            })
        }

        fn submissions(&self) -> Vec<crate::mailtest::LocalSubmission> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl crate::mailtest::MailSubmitter for RecordingSubmitter {
        fn submit<'a>(
            &'a self,
            submission: crate::mailtest::LocalSubmission,
        ) -> Pin<
            Box<dyn Future<Output = Result<crate::mailtest::SubmissionReport, String>> + Send + 'a>,
        > {
            let index = {
                let mut seen = self.seen.lock().unwrap();
                seen.push(submission.clone());
                seen.len()
            };
            if let Some(dir) = &self.deliver_to {
                fs::create_dir_all(dir).unwrap();
                fs::write(dir.join(format!("{index}.msg")), &submission.data).unwrap();
            }
            let outcome = match &self.outcome {
                Ok(code) => Ok(crate::mailtest::SubmissionReport {
                    code: *code,
                    banner: "250 2.0.0 Ok: queued".to_string(),
                }),
                Err(message) => Err(message.clone()),
            };
            Box::pin(async move { outcome })
        }
    }

    fn readers_with_mailtest(f: &Fixture, submitter: Arc<RecordingSubmitter>) -> Readers {
        f.readers(always_ok_runner())
            .with_mailtest_env(MailTestEnv {
                home_root: f.root.clone(),
                submitter,
            })
    }

    fn register_managed_mailbox(f: &Fixture, unix_user: &str, email: &str) {
        let boxes = json!([{ "email": email, "unixUser": unix_user, "displayName": "" }]);
        fs::create_dir_all(f.paths.managed_mailboxes.parent().unwrap()).unwrap();
        fs::write(
            &f.paths.managed_mailboxes,
            serde_json::to_string_pretty(&boxes).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn the_mail_test_actions_are_registered() {
        let f = Fixture::new("mailregistered");
        let registry = Registry::new().with_readers(Arc::new(f.readers(always_ok_runner())));
        for action in ["setup.mail.test", "mail.test_loopback"] {
            assert!(registry.is_implemented(action), "{action} 必须已接线");
        }
    }

    #[tokio::test]
    async fn setup_mail_test_submits_with_crlf_and_enforces_the_mailbox_checks() {
        let f = Fixture::new("mailtest");

        register_managed_mailbox(&f, "alice", "alice@example.com");
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        let out = readers
            .setup_mail_test(&json!({
                "sender": "alice@example.com",
                "recipient": "bob@example.com",
                "username": "alice",

                "password": "Sup3rSecret!",
            }))
            .await
            .unwrap();

        assert_eq!(out["queued"], true);
        assert_eq!(out["scope"], "local submission");
        assert_eq!(out["sender"], "alice@example.com");
        assert_eq!(out["recipient"], "bob@example.com");
        assert_eq!(out["code"], 250);

        assert!(
            out.get("mailboxChecksSkipped").is_none(),
            "mailboxChecksSkipped 必须已移除: {out}"
        );

        let submissions = submitter.submissions();
        assert_eq!(submissions.len(), 1);
        let submission = &submissions[0];
        assert_eq!(submission.mail_from, "alice@example.com");
        assert_eq!(submission.recipient, "bob@example.com");

        assert!(
            submission.data.contains("\r\n"),
            "正文必须用 CRLF 行尾: {:?}",
            submission.data
        );
        assert!(
            !submission.data.replace("\r\n", "").contains('\n'),
            "正文不得残留裸 LF: {:?}",
            submission.data
        );

        assert!(!submission.data.contains("Sup3rSecret!"));
    }

    #[tokio::test]
    async fn setup_mail_test_rejects_malformed_addresses_before_submitting() {
        let f = Fixture::new("mailtestbad");
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        for bad in [
            json!({ "sender": "not-an-address", "recipient": "bob@example.com" }),
            json!({ "sender": "alice@example.com", "recipient": "nope" }),
        ] {
            let err = readers.setup_mail_test(&bad).await.unwrap_err();
            assert!(
                err.to_string().contains("invalid mailbox or sender"),
                "{bad} 实际: {err}"
            );
        }

        let err = readers
            .setup_mail_test(&json!({ "sender": "alice@example.com" }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required field"), "{err}");
        assert!(
            submitter.submissions().is_empty(),
            "被拒的请求不得发出任何邮件"
        );
    }

    #[tokio::test]
    async fn setup_mail_test_requires_a_managed_mailbox_matching_the_sender() {
        let f = Fixture::new("mailtestnomatch");
        register_managed_mailbox(&f, "alice", "alice@example.com");
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        for payload in [
            json!({
                "sender": "bob@example.com",
                "recipient": "bob@example.com",
                "username": "bob",
                "password": "Sup3rSecret!",
            }),
            json!({
                "sender": "carol@example.com",
                "recipient": "bob@example.com",
                "username": "alice",
                "password": "Sup3rSecret!",
            }),
        ] {
            let err = readers.setup_mail_test(&payload).await.unwrap_err();
            assert_eq!(
                err.to_string(),
                "mail test requires an explicit managed mailbox matching sender",
                "{payload}"
            );
        }
        assert!(
            submitter.submissions().is_empty(),
            "存在性检查必须在提交之前生效"
        );
    }

    #[tokio::test]
    async fn setup_mail_test_refuses_a_locked_mailbox() {
        let f = Fixture::new("mailtestlocked");
        register_managed_mailbox(&f, "alice", "alice@example.com");
        let submitter = RecordingSubmitter::accepting();

        let tracked = Arc::clone(&submitter);
        let readers = f
            .readers(FakeRunner::returning(0, "alice L 01/01/2026 0 99999 7 -1"))
            .with_mailtest_env(MailTestEnv {
                home_root: f.root.clone(),
                submitter,
            });

        let err = readers
            .setup_mail_test(&json!({
                "sender": "alice@example.com",
                "recipient": "bob@example.com",
                "username": "alice",
                "password": "Sup3rSecret!",
            }))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "mailbox is disabled");
        assert!(
            tracked.submissions().is_empty(),
            "锁定检查必须在提交之前生效"
        );
    }

    #[tokio::test]
    async fn setup_mail_test_rejects_an_invalid_username_or_password_shape() {
        let f = Fixture::new("mailtestbadid");
        register_managed_mailbox(&f, "alice", "alice@example.com");
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        let err = readers
            .setup_mail_test(&json!({
                "sender": "alice@example.com",
                "recipient": "bob@example.com",
                "username": "Root",
                "password": "Sup3rSecret!",
            }))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid mailbox or sender");

        let err = readers
            .setup_mail_test(&json!({
                "sender": "alice@example.com",
                "recipient": "bob@example.com",
                "username": "alice",
                "password": "",
            }))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("password must contain"),
            "实际: {err}"
        );

        assert!(
            submitter.submissions().is_empty(),
            "被拒的请求不得发出任何邮件"
        );
    }

    #[tokio::test]
    async fn setup_mail_test_never_reports_queued_when_the_mta_rejects_it() {
        let f = Fixture::new("mailtestreject");
        register_managed_mailbox(&f, "alice", "alice@example.com");
        let submitter = RecordingSubmitter::rejecting("554 5.7.1 Relay access denied");
        let readers = readers_with_mailtest(&f, submitter);

        let err = readers
            .setup_mail_test(&json!({
                "sender": "alice@example.com",
                "recipient": "attacker@external.example",
                "username": "alice",
                "password": "Sup3rSecret!",
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Relay access denied"), "{err}");
    }

    #[tokio::test]
    async fn mail_test_loopback_requires_a_managed_domain() {
        let f = Fixture::new("loopnodomain");
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        let err = readers.mail_test_loopback(&json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("at least one managed domain"),
            "{err}"
        );
        assert!(submitter.submissions().is_empty());
    }

    #[tokio::test]
    async fn mail_test_loopback_refuses_a_foreign_recipient() {
        let f = Fixture::new("loopforeign");
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        let err = readers
            .mail_test_loopback(&json!({ "recipient": "attacker@external.example" }))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("must belong to a managed domain"),
            "{err}"
        );
        assert!(
            submitter.submissions().is_empty(),
            "反中继守卫必须在提交之前生效"
        );
    }

    #[tokio::test]
    async fn mail_test_loopback_defaults_to_postmaster_at_the_first_managed_domain() {
        let f = Fixture::new("loopdefault");
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        let out = readers.mail_test_loopback(&json!({})).await.unwrap();
        assert_eq!(out["recipient"], "postmaster@example.com");
        assert_eq!(out["sender"], "mailer-daemon@example.com");
        assert_eq!(out["success"], true);
    }

    #[tokio::test]
    async fn mail_test_loopback_reports_the_token_and_finds_it_in_the_maildir() {
        let f = Fixture::new("loopfound");
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();

        let maildir_new = f
            .paths
            .vmail
            .join("example.com")
            .join("carol")
            .join("Maildir")
            .join("new");
        let submitter = RecordingSubmitter::delivering_to(maildir_new.clone());
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        let out = readers
            .mail_test_loopback(&json!({ "recipient": "carol@example.com" }))
            .await
            .unwrap();
        assert_eq!(out["success"], true);
        let token = out["token"].as_str().unwrap().to_string();
        assert!(token.starts_with("ms-loopback-"), "{token}");
        assert_eq!(out["code"], 250);
        assert_eq!(
            out["maildirDelivered"], true,
            "注入的 Maildir 根必须真的被扫到: {out}"
        );
        assert!(out["deliveryTimeMs"].as_u64().unwrap() >= 1);

        let submissions = submitter.submissions();
        assert_eq!(submissions.len(), 1);
        assert!(submissions[0].data.contains(&token));
        assert!(submissions[0].data.contains("\r\n"));
        assert_eq!(submissions[0].recipient, "carol@example.com");
    }

    #[tokio::test]
    async fn mail_test_loopback_reports_a_missing_maildir_as_absent_evidence_not_failure() {
        let f = Fixture::new("loopmaildirnone");
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        let out = readers
            .mail_test_loopback(&json!({ "recipient": "ghost@example.com" }))
            .await
            .unwrap();
        assert_eq!(out["success"], true, "找不到 Maildir 不是失败: {out}");
        assert_eq!(out["maildirDelivered"], false);
        assert_eq!(out["code"], 250, "接受码是环路成功的唯一证据");
    }

    #[tokio::test]
    async fn mail_test_loopback_never_reports_success_when_the_submission_fails() {
        let f = Fixture::new("loopsubmitfail");
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let submitter = RecordingSubmitter::rejecting("Connection refused");
        let readers = readers_with_mailtest(&f, submitter);

        let err = readers
            .mail_test_loopback(&json!({ "recipient": "carol@example.com" }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Connection refused"), "{err}");
    }

    #[test]
    fn the_frontend_list_actions_are_registered() {
        let f = Fixture::new("frontregistered");
        let registry = Registry::new().with_readers(Arc::new(f.readers(always_ok_runner())));
        for action in [
            "users.list",
            "aliases.list",
            "queue.list",
            "services.list",
            "dkim.keys",
            "dns.records",
            "metrics.system",
            "activity.list",
        ] {
            assert!(registry.is_implemented(action), "{action} 必须已接线");
        }
    }

    fn users_readers(
        f: &Fixture,
        passwd: &str,
        mailboxes: &[(&str, &str)],
        locked: bool,
    ) -> Readers {
        let etc = f.paths.etc.parent().unwrap();
        fs::write(etc.join("passwd"), passwd).unwrap();
        let boxes: Vec<Value> = mailboxes
            .iter()
            .map(
                |(email, user)| json!({ "email": email, "unixUser": user, "displayName": "Alice" }),
            )
            .collect();
        fs::create_dir_all(f.paths.managed_mailboxes.parent().unwrap()).unwrap();
        fs::write(
            &f.paths.managed_mailboxes,
            serde_json::to_string(&boxes).unwrap(),
        )
        .unwrap();

        let env = UsersEnv {
            passwd_root: etc.to_path_buf(),
            session_epoch_owner: None,
            ..UsersEnv::default()
        };
        let stdout = if locked {
            "alice L 2026-01-01 0 99999 7 -1\n"
        } else {
            ""
        };
        f.readers(FakeRunner::returning(0, stdout))
            .with_users_env(env)
    }

    #[test]
    fn users_list_maps_status_to_active_and_reports_the_absent_quota_as_zero() {
        let f = Fixture::new("userslist");
        let readers = users_readers(
            &f,
            "alice:x:1000:1000::/home/alice:/usr/sbin/nologin\n",
            &[("alice@example.com", "alice")],
            false,
        );

        let out = readers.users_list(&json!({})).unwrap();
        let items = out.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["address"], "alice@example.com");
        assert_eq!(items[0]["name"], "Alice");
        assert_eq!(items[0]["active"], true);

        assert_eq!(items[0]["quotaUsed"], 0);
        assert_eq!(items[0]["quotaTotal"], 0);
        assert_eq!(items[0]["createdAt"], "");
    }

    #[test]
    fn users_list_treats_a_locked_account_as_inactive() {
        let f = Fixture::new("userslocked");
        let readers = users_readers(
            &f,
            "alice:x:1000:1000::/home/alice:/usr/sbin/nologin\n",
            &[("alice@example.com", "alice")],
            true,
        );
        let out = readers.users_list(&json!({})).unwrap();
        assert_eq!(out[0]["active"], false);
    }

    #[test]
    fn aliases_list_exposes_the_first_target_and_keeps_every_destination() {
        let f = Fixture::new("aliaseslist");
        fs::write(
            &f.paths.aliases,
            "team@example.com alice@example.com bob@example.com\n",
        )
        .unwrap();

        let out = f
            .readers(always_ok_runner())
            .aliases_list(&json!({}))
            .unwrap();
        let items = out.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["source"], "team@example.com");
        assert_eq!(items[0]["target"], "alice@example.com");
        assert_eq!(
            items[0]["destinations"],
            json!(["alice@example.com", "bob@example.com"])
        );

        assert_eq!(items[0]["active"], true);
        assert_eq!(items[0]["createdAt"], "");
    }

    #[test]
    fn aliases_list_on_a_missing_table_is_empty_not_error() {
        let f = Fixture::new("aliasesnone");
        let out = f
            .readers(always_ok_runner())
            .aliases_list(&json!({}))
            .unwrap();
        assert!(out.as_array().unwrap().is_empty());
    }

    #[test]
    fn queue_list_maps_only_the_two_real_states_and_derives_the_domain() {
        let f = Fixture::new("queuelist");
        enqueue(&f, 1, NOW);
        enqueue(&f, 3, NOW + 3600);

        let out = f
            .readers(always_ok_runner())
            .queue_list(&json!({}))
            .unwrap();
        let items = out.as_array().unwrap();
        assert_eq!(items.len(), 2);
        let mut statuses: Vec<&str> = items
            .iter()
            .map(|item| item["status"].as_str().unwrap())
            .collect();
        statuses.sort_unstable();

        assert_eq!(statuses, vec!["pending", "sending"]);
        for item in items {
            assert_eq!(item["domain"], "example.test");
            assert_eq!(item["recipient"], "bob@example.test");
            assert_eq!(item["service"], "outbound");

            assert_eq!(item["time"], "2026-01-01T00:00:00+00:00");
            assert!(item["retry"].is_number());
        }
    }

    #[test]
    fn services_list_maps_active_status_to_running_and_reuses_the_service_items() {
        let f = Fixture::new("serviceslist");

        let out = f
            .readers(FakeRunner::returning(1, ""))
            .services_list(&json!({}))
            .unwrap();
        let items = out.as_array().unwrap();
        assert_eq!(items.len(), SERVICES.len());
        assert_eq!(items[0]["key"], SERVICES[0].0);
        assert_eq!(items[0]["detail"], SERVICES[0].1);
        assert_eq!(items[0]["running"], false);

        let stdout =
            "ActiveState=active\nMainPID=42\nMemoryCurrent=1048576\nActiveEnterTimestamp=\n";
        let readers = f.readers_with_env(FakeRunner::returning(0, stdout), systemd_env());
        let out = readers.services_list(&json!({})).unwrap();
        assert_eq!(out[0]["running"], true);
    }

    #[tokio::test]
    async fn dkim_keys_lists_only_domains_with_a_private_key() {
        let f = Fixture::new("dkimkeys");
        f.set_identity();
        fs::write(&f.paths.domains, "example.com OK\nother.test OK\n").unwrap();

        let private = mailstack_auth::keys::private_key_path(&f.paths, "example.com", "mail");
        fs::create_dir_all(private.parent().unwrap()).unwrap();
        fs::write(&private, b"-----BEGIN RSA PRIVATE KEY-----\n").unwrap();

        let dns = StaticDns::new().with_txt("mail._domainkey.example.com", &[&dkim_txt_value()]);
        let readers = readers_with_networks(&f, Arc::new(dns), ScriptedRelayProbe::passing());

        let out = readers.dkim_keys(&json!({})).await.unwrap();
        let items = out.as_array().unwrap();
        assert_eq!(items.len(), 1, "没有密钥的域名不得产出条目: {out}");
        assert_eq!(items[0]["domain"], "example.com");
        assert_eq!(items[0]["selector"], "mail");
        assert_eq!(items[0]["keySize"], 2048, "用常量而不是解析私钥");
        assert_eq!(items[0]["published"], true);
        assert!(
            items[0]["lastRotated"].as_str().unwrap().contains(' '),
            "应是 YYYY-MM-DD HH:MM:SS 形态: {}",
            items[0]["lastRotated"]
        );
    }

    #[tokio::test]
    async fn dkim_keys_reports_unpublished_when_the_resolver_fails() {
        let f = Fixture::new("dkimkeysfail");
        f.set_identity();
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let private = mailstack_auth::keys::private_key_path(&f.paths, "example.com", "mail");
        fs::create_dir_all(private.parent().unwrap()).unwrap();
        fs::write(&private, b"key").unwrap();

        let readers = readers_with_networks(
            &f,
            Arc::new(StaticDns::failing("resolver unreachable")),
            ScriptedRelayProbe::passing(),
        );
        let out = readers.dkim_keys(&json!({})).await.unwrap();

        assert_eq!(out[0]["published"], false);
    }

    #[tokio::test]
    async fn dns_records_covers_a_mx_spf_dmarc_and_dkim() {
        let f = Fixture::new("dnsrecords");
        f.set_identity();
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();

        let txt = mailstack_auth::keys::txt_record_path(&f.paths, "example.com", "mail");
        fs::create_dir_all(txt.parent().unwrap()).unwrap();
        fs::write(
            &txt,
            mailstack_auth::keys::zone_txt_fragment("mail._domainkey", &dkim_txt_value(), "c"),
        )
        .unwrap();

        let dns = StaticDns::new()
            .with_a(&["203.0.113.10"])
            .with_mx(&["10 mail.example.com."])
            .with_txt("example.com", &["v=spf1 mx -all"])
            .with_txt("mail._domainkey.example.com", &[&dkim_txt_value()])
            .with_txt(
                "_dmarc.example.com",
                &["v=DMARC1; rua=mailto:d@example.com"],
            );
        let readers = readers_with_networks(&f, Arc::new(dns), ScriptedRelayProbe::passing());

        let out = readers.dns_records(&json!({})).await.unwrap();
        let items = out.as_array().unwrap();
        let types: Vec<&str> = items.iter().map(|i| i["type"].as_str().unwrap()).collect();
        assert_eq!(types, vec!["A", "MX", "TXT", "TXT", "TXT"]);
        assert_eq!(items[0]["name"], "mail.example.com");
        assert_eq!(items[0]["value"], "203.0.113.10");
        assert_eq!(items[1]["value"], "mail.example.com");
        assert_eq!(items[2]["value"], "v=spf1 mx -all");
        assert_eq!(items[3]["name"], "_dmarc.example.com");
        assert_eq!(items[4]["name"], "mail._domainkey.example.com");
        assert_eq!(items[4]["value"], dkim_txt_value());
        for item in items {
            assert_eq!(item["ttl"], 3600, "TTL 是向导建议值");
            assert_eq!(item["required"], true);
            assert_eq!(item["ok"], true, "记录齐全时应全部匹配: {item}");
        }
    }

    #[tokio::test]
    async fn dns_records_reports_absent_records_as_not_ok_instead_of_failing() {
        let f = Fixture::new("dnsrecordsnone");
        f.set_identity();
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let readers = readers_with_networks(
            &f,
            Arc::new(StaticDns::new()),
            ScriptedRelayProbe::passing(),
        );

        let out = readers.dns_records(&json!({})).await.unwrap();
        let items = out.as_array().unwrap();

        assert_eq!(items.len(), 4, "缺 DKIM 密钥时不编造条目: {out}");
        assert!(items.iter().all(|item| item["ok"] == false));
    }

    #[test]
    fn metrics_system_reports_cpu_memory_and_disk_percentages() {
        let f = Fixture::new("metricssystem");

        fs::write(
            f.proc_root.join("stat"),
            "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\n",
        )
        .unwrap();

        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 10000 2500 7500 25% /\n";
        let out = f
            .readers(FakeRunner::returning(0, df))
            .metrics_system(&json!({}))
            .unwrap();
        assert_eq!(out["cpu"], 0.0);
        assert_eq!(out["memory"], 60.0);
        assert_eq!(out["disk"], 25.0);
    }

    #[test]
    fn metrics_system_reports_zero_when_proc_and_df_are_unavailable() {
        let f = Fixture::new("metricssystemfail");

        let out = f
            .readers(FakeRunner::returning(1, "df: /: Permission denied"))
            .metrics_system(&json!({}))
            .unwrap();
        assert_eq!(out["cpu"], 0.0);
        assert_eq!(out["disk"], 0.0);

        assert_eq!(out["memory"], 60.0);
    }

    #[test]
    fn read_cpu_counters_strips_the_core_index_before_splitting() {
        let root = std::env::temp_dir().join(format!("mailstack-cpustat-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();

        fs::write(root.join("stat"), "cpu  100 0 100 800 0 0 0 0 0 0\n").unwrap();
        let aggregate = read_cpu_counters(&root).unwrap();
        assert_eq!(aggregate.total, 1000);
        assert_eq!(aggregate.idle, 800);

        fs::write(root.join("stat"), "cpu0 100 0 100 700 100 0 0 0 0 0\n").unwrap();
        let core = read_cpu_counters(&root).unwrap();
        assert_eq!(core.total, 1000, "user..steal 八项之和");
        assert_eq!(core.idle, 800, "idle + iowait");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cpu_busy_percent_is_the_non_idle_share_of_the_delta() {
        let prev = CpuCounters {
            idle: 100,
            total: 200,
        };
        let now = CpuCounters {
            idle: 300,
            total: 600,
        };

        assert_eq!(cpu_busy_percent(&prev, &now), 50.0);
        assert_eq!(cpu_busy_percent(&now, &now), 0.0, "零增量不能除零");
    }

    #[test]
    fn parse_df_percent_skips_the_header_and_garbage() {
        let out = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 100 900 10% /\n";
        assert_eq!(parse_df_percent(out), Some(10.0));
        assert_eq!(parse_df_percent(""), None);
        assert_eq!(parse_df_percent("only one column\n"), None);
    }

    #[test]
    fn zone_txt_value_flattens_a_multiline_fragment() {
        let value = format!("v=DKIM1; k=rsa; p={}", "A".repeat(300));
        let fragment = mailstack_auth::keys::zone_txt_fragment("mail._domainkey", &value, "c");
        assert_eq!(zone_txt_value(&fragment).as_deref(), Some(value.as_str()));
        assert_eq!(zone_txt_value("not a zone fragment"), None);
    }

    #[test]
    fn activity_kind_maps_the_action_prefix() {
        assert_eq!(activity_kind("users.add"), "user");
        assert_eq!(activity_kind("domains.delete"), "domain");
        assert_eq!(activity_kind("queue.action"), "queue");
        assert_eq!(activity_kind("services.restart"), "service");
        assert_eq!(activity_kind("certs.renew"), "cert");
        assert_eq!(activity_kind("snapshot"), "system");
    }

    #[test]
    fn read_activity_skips_unparseable_lines_and_orders_newest_first() {
        let f = Fixture::new("activitylist");
        let log = &f.paths.audit_log;
        mailstack_core::audit::audit(log, "users.add", true, "", "alice").unwrap();
        mailstack_core::audit::audit(log, "domains.add", true, "", "example.com").unwrap();
        mailstack_core::audit::audit(log, "services.action", false, "boom", "postfix").unwrap();

        let mut text = fs::read_to_string(log).unwrap();
        text.push_str("{\"action\":\"legacy\"}\n{\"partial\":");
        fs::write(log, text).unwrap();

        let out = f
            .readers(always_ok_runner())
            .activity_list(&json!({}))
            .unwrap();
        let items = out.as_array().unwrap();
        assert_eq!(items.len(), 3, "半行与缺字段的旧记录要跳过");
        assert_eq!(items[0]["title"], "services.action", "最新在前");
        assert_eq!(items[0]["kind"], "service");
        assert_eq!(items[0]["sub"], "postfix");
        assert_eq!(items[1]["kind"], "domain");
        assert_eq!(items[2]["kind"], "user");
        assert!(items[0]["time"].as_str().unwrap().ends_with("+00:00"));
    }

    #[test]
    fn activity_list_on_a_missing_log_is_empty_not_error() {
        let f = Fixture::new("activitynone");
        let out = f
            .readers(always_ok_runner())
            .activity_list(&json!({}))
            .unwrap();
        assert!(out.as_array().unwrap().is_empty());
    }

    #[test]
    fn activity_list_reads_only_the_tail_of_a_large_log() {
        let f = Fixture::new("activitytail");
        let log = &f.paths.audit_log;
        fs::create_dir_all(log.parent().unwrap()).unwrap();
        let mut padding = String::new();
        for _ in 0..1200 {
            padding.push_str(&format!("{{\"padding\":\"{}\"}}\n", "x".repeat(300)));
        }
        fs::write(log, &padding).unwrap();
        mailstack_core::audit::audit(log, "users.add", true, "", "alice").unwrap();
        mailstack_core::audit::audit(log, "domains.add", true, "", "example.com").unwrap();

        let out = f
            .readers(always_ok_runner())
            .activity_list(&json!({}))
            .unwrap();
        let items = out.as_array().unwrap();
        assert_eq!(items.len(), 2, "尾部窗口必须覆盖到最新记录: {items:?}");
        assert_eq!(items[0]["title"], "domains.add", "最新在前");
        assert_eq!(items[0]["sub"], "example.com");
        assert_eq!(items[1]["title"], "users.add");
        assert!(items[0]["time"].as_str().unwrap().ends_with("+00:00"));
    }
}

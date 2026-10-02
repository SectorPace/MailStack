//! 只读聚合面（规格书 §5.4.1 的 RO 动作：`snapshot` / `logs.list` /
//! `metrics.realtime` / `certs.list` / `network.check_port` / `system.doctor`）。
//!
//! ## 三条共同纪律
//!
//! 1. **只读、可重放、无副作用**：这些动作可以在任何时刻被任意次数调用，
//!    因此它们绝不写任何文件（`system.doctor` 的封禁探针用的是**新建的内存表**，
//!    不碰线上那份）。
//! 2. **读不到的部分必须显式出现在结果里**（`unavailable`）。静默省略会把
//!    「没数据」渲染成「没问题」，而这两者对运维的含义正好相反 —— 这正是本项目
//!    反复出现的那类缺陷。
//! 3. **一个子项失败不拖垮整条**：`/proc` 读不到不该让证书列表也拿不到。
//!    每个子项各自降级，并在同一个响应里说清哪一项降级了。

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

use crate::handlers::{HandlerError, Registry};

/// 迁移期受管的服务单元。
///
/// 与 `service_ctl` 的降级链覆盖的是同一批组件：正在被替代的 Postfix / fail2ban，
/// 以及**保留**的 Dovecot（IMAP/POP3 与 SASL 后端）。
///
/// 这是 `metrics.realtime` / `system.doctor` 的**活性探测**集合，刻意比
/// [`SERVICES`] 窄：控制台列的 9 个单元里只有这三个由本项目的安装器负责，
/// 对没装的单元反复探测只会制造噪音。
pub const WATCHED_SERVICES: &[&str] = &["postfix", "dovecot", "fail2ban"];

/// 控制台受管的服务清单：`(id, systemd 单元名)`。
///
/// 与基线 `core.py` 的 `SERVICES` 逐一对应 —— 控制台的「重启服务」按钮把列表里的
/// `id` 原样回传，因此**列出什么就必须能操作什么**，两者不得分叉。
///
/// 迁移期这些单元与新的 `mailstackd` 并存（见 `DEPLOYMENT.md`）；待遗留单元退役时
/// 再把 `mailstackd` 加进来。
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

/// `logs.list` 的默认行数与上限。
pub const LOGS_DEFAULT_LINES: usize = 200;
pub const LOGS_MAX_LINES: usize = 1000;

/// `network.check_port` 只探测 25 端口族的出站可达性；端口号必须落在合法范围。
pub const DEFAULT_PROBE_PORT: u16 = 25;

/// 封禁往返探针使用的地址：TEST-NET-1（RFC 5737），**保证不可路由**，
/// 因此即便探针真的泄漏到线上也不会指向任何真实主机。
pub const BAN_PROBE_ADDRESS: &str = "192.0.2.1";

/// `setup.identity.apply` 未显式给出 selector 时的缺省值。
///
/// 与基线 `network.py:135` 一致：初始化向导固定用 `mail`。注意这与
/// `certs.py` 的 `dkim.rotate` 缺省（`mailstack`）**刻意不同** ——
/// 改这里会让向导已经发布出去的 DNS 记录对不上。
pub const SETUP_DEFAULT_DKIM_SELECTOR: &str = "mail";

/// 中继探针（`setup.relay.test` / `setup.relay.apply` 的可注入接缝）。
///
/// 抽这一层是为了让「先测后写」「测试不过一行配置都不落」这些顺序断言能用
/// 一个**可控**的成功/失败探针来验证，而不是在测试里真的去连一台 SMTP 服务器
/// —— 那样断言会依赖外部网络，最终被人当成噪音忽略（本项目已有前车之鉴，
/// 见 `docs/TEST_REPORT.md` §4.14）。
pub trait RelayProbe: Send + Sync {
    /// 分阶段测试一个中继端点（DNS → connect → TLS → auth）。
    fn test<'a>(
        &'a self,
        request: &'a RelayValidationRequest,
        private_network_enabled: bool,
    ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>>;

    /// 本机提交端点的直投探测。
    ///
    /// 只证明「本地 MTA 活着」，**不证明出站 25 可用**（INV-19）—— 出站可用性由
    /// `network.check_port` 单独判定，两者不可混淆。
    fn direct<'a>(
        &'a self,
        target: PinnedTarget,
    ) -> Pin<Box<dyn Future<Output = Result<RelayTestResult, RelayTestFailure>> + Send + 'a>>;
}

/// 生产中继探针：真实解析、IP 固定拨号、TLS 与认证。
pub struct SystemRelayProbe {
    /// TLS 栈构造失败时留 `None`，由调用如实报错 —— **绝不**静默退回明文连接。
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

/// 未注入探针时的占位：任何调用都**如实报错**，绝不假装成功。
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

/// 「没有可用的探针」这一类故障的**统一**错误。
///
/// 刻意区分「探针没接上」（配置/装配错误）与「中继不可达」（运维结论）：
/// 前者是我们自己的问题，后者是网络/对端的问题。
fn no_probe_error() -> SmtpError {
    SmtpError::Config("no relay probe is configured for this helper".to_string())
}

/// 把「探针本身不可用」折成一个仍带分阶段结构的失败。
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

/// 解析器不可用时的占位：**每次查询都如实报错**，绝不返回空结果。
///
/// 返回空结果会把「解析器坏了」渲染成「DNS 记录没配」—— 后者会让运维去改一条
/// 本来正确的记录，这是最没有价值的排查方向。
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

/// 取样时钟（Unix 秒）。注入是为了让「证书还有几天到期」这类断言不随真实时间漂移。
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// 只读聚合面的取样入口。
///
/// 生产用 [`Readers::system`]；测试注入替身运行器、假 `/proc` 与固定时钟。
pub struct Readers {
    paths: Paths,
    /// 服务活性探测的环境（systemd 运行目录判据等）。
    env: Arc<dyn ServiceEnv>,
    runner: Arc<dyn CommandRunner>,
    /// `/proc` 根目录。
    proc_root: PathBuf,
    clock: Clock,
    /// 出站探测目标。**不接受来自请求体的目标** —— 那等于把管理 API 变成一个
    /// 任意主机的 TCP 探针（SSRF 的一半）；地址策略也只允许公网地址。
    probe_targets: Vec<String>,
    /// 备份动作的运行参数（根目录 / 落地根 / 加密后端 / 家目录白名单）。
    ///
    /// **必须可注入**：备份恢复会往「根」里写文件，测试若用生产默认值就会去写
    /// 真实的 `/`。这条不是便利性设计，是安全边界 —— 和 `probe_targets` 同理。
    backups: BackupEnv,
    /// DNS 查询后端（`setup.dns.verify`）。
    ///
    /// 同样必须可注入：六条判据要能在不碰真实 DNS 的前提下逐条验证，否则断言
    /// 会随网络抖动随机变红（`docs/TEST_REPORT.md` §4.14 的同类教训）。
    dns: Arc<dyn DnsQuery>,
    /// 中继探针（`setup.relay.test` / `setup.relay.apply`）。
    ///
    /// 可注入的理由见 [`RelayProbe`]：让「先测后写」的顺序断言不依赖外部网络。
    relay: Arc<dyn RelayProbe>,
    /// 环路自检的运行参数（家目录根 / 提交器）。
    mailtest: MailTestEnv,
}

/// 备份动作的运行参数。
#[derive(Clone)]
pub struct BackupEnv {
    /// 归档成员名的基准，也是默认来源的根。生产是 `/`。
    pub root: PathBuf,
    /// 恢复的落地根。生产是 `/`。
    pub restore_root: PathBuf,
    /// 加密 / 解密后端。生产是 `gpg`。
    pub cipher: Arc<dyn mailstack_core::backup::BackupCipher>,
    /// 允许被恢复写入家目录的账号集合。
    ///
    /// 用户模型（`users.*`）尚未移植，因此生产是**空集合** —— 任何
    /// `home/<user>/...` 成员都会被拒绝。这是 fail-closed：无法证明某个家目录
    /// 归 MailStack 管，就不该往里面写东西。
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

/// 环路自检（`mail.test_loopback` / `setup.mail.test`）的运行参数。
#[derive(Clone)]
pub struct MailTestEnv {
    /// 系统用户 Maildir 的根。生产是 `/`，于是 `~/Maildir` 就是 `/home/<user>/Maildir`。
    ///
    /// **必须可注入**：自检会去读文件系统里的 Maildir，测试若用生产默认值就会去扫
    /// 真实的 `/home`。和 `BackupEnv::root` 是同一条理由。
    pub home_root: PathBuf,
    /// 提交器。生产是向本机 `127.0.0.1:25` 的 SMTP 提交。
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

/// 未注入提交器时的占位：任何调用都**如实报错**，绝不假装邮件已发出。
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
    /// 生产构造。
    pub fn system(paths: Paths) -> Self {
        // 解析器构造失败不阻断整个助手启动（其余动作仍然可用），但存成
        // 「每次查询都报错」的占位，让 `setup.dns.verify` 如实说出原因。
        let dns: Arc<dyn DnsQuery> = match HickoryDnsQuery::from_system() {
            Ok(resolver) => Arc::new(resolver),
            Err(error) => {
                mailstack_core::warn::warn_with_detail("build DNS resolver", &error.to_string());
                Arc::new(UnavailableDns {
                    reason: error.to_string(),
                })
            }
        };
        Self {
            paths,
            env: Arc::new(SystemServiceEnv),
            runner: Arc::new(SystemCommandRunner),
            proc_root: mailstack_core::sysinfo::system_proc_root(),
            clock: Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp()),
            probe_targets: mailstack_smtp::probe::probe_targets_from_env(),
            backups: BackupEnv::default(),
            dns,
            relay: Arc::new(SystemRelayProbe::new()),
            mailtest: MailTestEnv::default(),
        }
    }

    /// 注入替身（测试用）。
    pub fn with_parts(
        paths: Paths,
        env: Arc<dyn ServiceEnv>,
        runner: Arc<dyn CommandRunner>,
        proc_root: PathBuf,
        clock: Clock,
        probe_targets: Vec<String>,
    ) -> Self {
        Self {
            paths,
            env,
            runner,
            proc_root,
            clock,
            probe_targets,
            backups: BackupEnv::default(),
            // 网络后端**刻意不默认成生产实现**：测试若忘了注入，就必须看到一个
            // 明确的失败，而不是在 CI 里悄悄去打真实 DNS / SMTP。
            dns: Arc::new(UnavailableDns {
                reason: "no DNS backend was injected for this test".to_string(),
            }),
            relay: Arc::new(NoRelayProbe),
            mailtest: MailTestEnv {
                // 家目录根保持 `/`：自检对 Maildir 只做**只读**扫描，默认值不构成
                // 安全边界问题（对比 `BackupEnv::root` 会往根里写）。要断言
                // 「真的在 Maildir 里找到了」的测试必须自己注入一个临时根。
                home_root: PathBuf::from("/"),
                submitter: Arc::new(NoSubmitter),
            },
        }
    }

    /// 覆盖备份动作的运行参数（测试用；生产保持 [`BackupEnv::default`]）。
    pub fn with_backup_env(mut self, backups: BackupEnv) -> Self {
        self.backups = backups;
        self
    }

    /// 覆盖 DNS 后端（测试用；生产用 [`Readers::system`] 的系统解析器）。
    pub fn with_dns(mut self, dns: Arc<dyn DnsQuery>) -> Self {
        self.dns = dns;
        self
    }

    /// 覆盖中继探针（测试用；生产用 [`SystemRelayProbe`]）。
    pub fn with_relay_probe(mut self, relay: Arc<dyn RelayProbe>) -> Self {
        self.relay = relay;
        self
    }

    /// 覆盖环路自检的运行参数（测试用；生产保持 [`MailTestEnv::default`]）。
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

    /// 控制台的服务列表（基线的 `ServiceItem` 形状）。
    ///
    /// 字段名与形状是**冻结契约**：控制台把 `services.action` 的响应直接当成新的
    /// 服务清单，所以这里的每一项都必须带 `id`/`status` 等界面要用的字段，
    /// 而不是一个精简的 `{unit, active}`。
    ///
    /// systemd 可用时用 `systemctl show` 一次取回活性/PID/内存/启动时刻；不可用
    /// （或命令失败）时退化为 [`is_service_active`] 的逐级探测，并把 PID/内存
    /// 留成 0 —— 编一个假数字比留空更糟。
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

    /// systemd 是否是本机的服务管理器（与 `service_ctl` 的首个判据一致）。
    fn systemd_available(&self) -> bool {
        self.env.program_available("systemctl")
            && self.env.path_exists(Path::new("/run/systemd/system"))
    }

    /// 队列条目（基线的 `QueueItem` 形状）。
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

    /// `certs.list`：`<etc>/tls/*/` 下的证书与到期天数。
    pub fn certs_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let infos = mailstack_core::certs::list_certificates(&self.paths.etc, self.now_dt());
        // 「即将到期」单独列一遍：运维看的是这个数，而不是证书总数。
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

    /// `metrics.realtime`：主机 + 服务 + 队列的即时读数。
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

    /// 队列的只读摘要（积压、损坏条目、出站结论）。复用持久化状态，
    /// 因此即便 `mailstackd` 不在跑，管理台看到的也是**磁盘上的真相**。
    fn queue_summary(&self) -> Value {
        let store = self.queue();
        let entries = store.load_all().unwrap_or_default();
        let health_state = store.load_health().unwrap_or_default();
        let relay = read_relay_host(&self.paths);
        let health = mailstack_queue::outbound_health_from(
            health_state.consecutive_failures,
            mailstack_queue::DEFAULT_BLOCKED_THRESHOLD,
            relay.as_deref(),
        );

        let corrupt = std::fs::read_dir(store.corrupt_dir())
            .map(|read| read.flatten().count())
            .unwrap_or(0);

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
        })
    }

    /// `snapshot`：把各只读子项拼成一个响应。
    ///
    /// `status` 与 `snapshot` 是同一个动作（契约里两条路由都映射到 `snapshot`），
    /// 因此这里不能有「轻量版」。**`unavailable` 是响应的一部分**：用户模块
    /// （vmail 用户表）尚未移植，界面必须能区分「没有用户」与「读不到用户」。
    pub fn snapshot(&self, _data: &Value) -> Result<Value, HandlerError> {
        let tables = self.tables();
        let domains = mailstack_core::atomic::rows(&self.paths.domains)
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
            // 尚未移植的只读子项。写成数组而不是省略，是为了让界面能显示
            // 「该部分尚未提供」，而不是把它渲染成「零」。
            "unavailable": ["users"],
        }))
    }

    /// `logs.list`：读 systemd 日志。
    ///
    /// 只读、有上限、不落盘。`journalctl` 不存在或读不到时**明确回
    /// `available: false` + 原因**，而不是回一个空数组 —— 空数组会让界面显示
    /// 「没有日志」，而真相是「读不到日志」。
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

    /// `network.check_port`：出站 TCP 端口可达性（§5.10.2、INV-19）。
    ///
    /// 探测目标**只来自部署配置**（`MAILSTACK_PORT_PROBE_TARGETS`），不接受请求体
    /// 指定的主机：否则这个只读接口就变成了一个任意主机的端口探针。
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

    /// `system.doctor`：把「现在会挡住用户的那些事」逐条查一遍。
    ///
    /// 每一项都是**只读**的检查；唯一的「动作」是封禁表的往返探针，它跑在一张
    /// **新建的内存表**上，因此不改变线上状态。
    pub fn system_doctor(&self, _data: &Value) -> Result<Value, HandlerError> {
        let mut checks: Vec<Value> = Vec::new();

        // 1) 身份：setup.json 存在且 mailHost 是 domain 的子域。
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

        // 2) 管理员凭证。
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

        // 3) 域名表：空表会让库层 fail-closed 拒收全部收件人（INV-17）。
        let domains = self.tables().domains();
        checks.push(check(
            "domain_table",
            !domains.is_empty(),
            if domains.is_empty() {
                "domain table is empty: every recipient will be refused (INV-17)".to_string()
            } else {
                format!("{} domain(s)", domains.len())
            },
        ));

        // 4) 中继配置：不存在是合法的「尚未配置」，存在就必须能解析。
        checks.push(self.relay_check());

        // 5) DKIM 私钥。
        checks.push(self.dkim_check(setup.as_ref()));

        // 6) TLS 证书与到期。
        checks.push(self.tls_check());

        // 7) 审计链。
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

        // 8) 封禁表往返探针。
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

    /// 封禁表往返：ban → 查询命中 → unban → 查询不再命中。
    fn ban_probe(&self) -> Value {
        let Ok(ip) = BAN_PROBE_ADDRESS.parse::<IpAddr>() else {
            return check("ban_round_trip", false, "probe address is not an IP");
        };
        // 全新实例：探针**绝不**触碰线上那份封禁表。
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

    /// `security.scan`：敏感文件权限体检（只 `stat`，不改任何东西）。
    ///
    /// 清单里的每一项都用**写入方实际使用的权限**作为上限（见
    /// [`mailstack_core::security`] 的说明），因此扫描器与写入方不会各说各话。
    pub fn security_scan(&self, _data: &Value) -> Result<Value, HandlerError> {
        let report = mailstack_core::security::scan(&self.security_inventory());
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
            // 查过多少项、哪些项在这台机器上根本不存在 —— 两者都要说清楚，
            // 否则「查了 3 项」与「查了 20 项都干净」看起来是一样的。
            "scanned": report.scanned,
            "absent": report.absent.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "findings": report.findings.iter().map(finding_to_json).collect::<Vec<_>>(),
            "summary": {
                "high": count(mailstack_core::security::Severity::High),
                "medium": count(mailstack_core::security::Severity::Medium),
                "info": count(mailstack_core::security::Severity::Info),
            },
            "highestSeverity": report.highest_severity().map(|s| s.as_str()),
            // 封禁清单。控制台的安全页要用它渲染「解封」按钮，因此必须给出条目本身，
            // 而不是只给一个数量。
            //
            // **只列手工封禁**，并用 `bannedIpScope` 明说这一点：由失败计数触发的
            // 自动封禁活在 `mailstackd` 的内存里，这个只读动作看不到它们。只报手工
            // 封禁而不加标注，会让运维以为「一共就封了这几条」—— 那比不报还糟。
            "bannedIps": self.manual_bans_json(),
            "bannedIpScope": "manual",
        }))
    }

    /// 手工封禁清单（基线的条目形状：`{ip, jail, time, reason}`）。
    ///
    /// 读取失败时返回 `null` 而不是空数组：空数组的含义是「没有任何手工封禁」，
    /// 与「读不到封禁文件」完全不是一回事（见 `mailstack_core::bans`）。
    fn manual_bans_json(&self) -> Value {
        let store = mailstack_core::bans::ManualBanStore::from_paths(&self.paths);
        match store.load() {
            Ok(None) => Value::Array(Vec::new()),
            Ok(Some(bans)) => Value::Array(
                bans.into_iter()
                    .map(|ban| {
                        json!({
                            "ip": ban.ip.to_string(),
                            // 没有 jail 概念；基线的字段位保留成 "manual"，让前端无需分支。
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

    /// 需要体检的敏感路径清单。
    fn security_inventory(&self) -> Vec<mailstack_core::security::SensitivePath> {
        use mailstack_core::security::SensitivePath;

        let p = &self.paths;
        let mut list = vec![
            SensitivePath::new(
                p.etc.clone(),
                0o750,
                // 目录本身不含机密：里面的文件各自是 0600/0640。目录放宽只会泄露
                // 「有哪几个文件」这一层信息，所以按 medium 而不是 high 处理。
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
            SensitivePath::new(
                p.ai_config.clone(),
                0o600,
                true,
                "AI 供应商配置（含 apiKey）",
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
            // 谁能写它就等于谁能决定「哪个地址不许连 SMTP」——与口令同级的安全面配置。
            SensitivePath::new(
                p.manual_bans.clone(),
                0o600,
                true,
                "手工封禁表：可写它就能放行已被封禁的主机",
            ),
        ];

        // 迁移期的明文中继口令。路径取自 smtp 的载体定义（构造本身无副作用），
        // 不在这里另写一份字符串。
        let sasl = mailstack_smtp::relay_store::PostfixRelayStore::production().sasl_passwd;
        list.push(SensitivePath::new(
            sasl,
            0o600,
            true,
            "Postfix sasl_passwd：明文口令",
        ));

        // DKIM 私钥：每个纳管域一把。
        for domain in self.tables().domains() {
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

        // TLS 私钥：每个已签发域一把。域名清单复用证书读取，不另写一遍目录遍历。
        for info in mailstack_core::certs::list_certificates(&self.paths.etc, self.now_dt()) {
            if info.key_present {
                list.push(SensitivePath::new(info.key_path, 0o600, true, "TLS 私钥"));
            }
        }

        list
    }

    /// `backup.list`：列出备份归档。
    ///
    /// 返回的是**元数据数组本身**（与基线一致，控制台直接把它当成备份清单）。
    /// 每条带 `filename` / `size` / `createdAt` / `sha256` / `encrypted` ——
    /// 恢复页要靠 `encrypted` 决定要不要口令框，靠 `sha256` 才有完整性可言。
    /// 读不到元数据的归档会被标 `metadataMissing` 而不是从列表里消失。
    pub fn backup_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let store = mailstack_core::backup::BackupStore::from_paths(&self.paths);
        let items = store
            .list()
            .into_iter()
            .map(|metadata| {
                let mut value = serde_json::to_value(&metadata)?;
                if let Value::Object(map) = &mut value {
                    // 0 字节的归档要么没写完、要么写失败被静默留下了 —— 它必须
                    // 在界面上看得见，否则运维会把一次失败的备份当成一份可用的备份。
                    map.insert("empty".to_string(), Value::Bool(metadata.size == 0));
                }
                Ok(value)
            })
            .collect::<Result<Vec<Value>, serde_json::Error>>()?;
        Ok(Value::Array(items))
    }

    /// `backup.create`：把配置（可选邮件）打成一个归档。
    ///
    /// 三条 fail-closed：
    /// * **公网模式下没有口令就拒绝**。明文归档在公网部署里是医生检查的 FAIL 项，
    ///   「这次先明文」正是要避免的事。local 模式允许明文（历史行为）。
    /// * **加密失败时连明文一起删**（在 `encrypt_in_place` 里）：运维要求了加密，
    ///   留下明文就是静默降级。
    /// * 打包失败时**删掉半成品**，不给运维留一个「看起来有备份」的残档。
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

        let sources = mailstack_core::backup::default_sources(&self.backups.root, include_mails);
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
            // 同一秒内两次创建会撞名；撞了就加一个后缀（文件名正则接受它）。
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
                // 不留半成品：一个读得到但打不开的 `.tar.gz` 比没有备份更危险。
                let _ = std::fs::remove_file(&target);
                return Err(HandlerError::new(error.to_string()));
            }
        };

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
        Ok(json!({ "created": true, "backup": metadata }))
    }

    /// `backup.restore`：校验并恢复一份归档。
    ///
    /// 顺序与判据都在 [`mailstack_core::backup::restore_archive`] 里；这里负责
    /// 三件属于「部署」的事：
    ///
    /// 1. **先做 `dryRun` 与显式确认**：恢复会覆盖 `/etc` 与 `/var/lib`，
    ///    没有确认就不该动。
    /// 2. **先打一个预恢复快照**（回滚点）。快照失败**不中断**恢复 —— 但那意味着
    ///    这次恢复没有回头路，必须让调用方看见（`preRestoreSnapshotWarning`）。
    /// 3. **恢复后重载受管服务**：配置已经换过一轮，不重载等于新配置没生效。
    ///    `mailstackd` 自己则需要重启（它在启动期装配配置，没有热重载）。
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
        let outcome = mailstack_core::backup::restore_archive(
            &store,
            &target,
            &self.backups.restore_root,
            &options,
            &self.backups.home_allowlist,
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

        let snapshot = self.pre_restore_snapshot(&store, &passphrase);
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
        }))
    }

    /// `backup.delete`：删除一份归档及其元数据。
    pub fn backup_delete(&self, data: &Value) -> Result<Value, HandlerError> {
        if data.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Err(HandlerError::new("Explicit confirmation is required"));
        }
        let name = crate::handlers::first_str(data, &["filename", "name"])?;
        let store = mailstack_core::backup::BackupStore::from_paths(&self.paths);
        store.delete(name)?;
        Ok(json!({ "deleted": true, "filename": name }))
    }

    /// 恢复前打一个回滚点。
    ///
    /// 返回 `(快照路径, 告警)`。快照本身**必须可读**才登记：一个截断的快照当成
    /// 回滚点，等于给了运维一条走不通的退路。
    fn pre_restore_snapshot(
        &self,
        store: &mailstack_core::backup::BackupStore,
        passphrase: &str,
    ) -> (Option<String>, Option<String>) {
        let sources = mailstack_core::backup::default_sources(&self.backups.root, false);
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
        // 快照允许部分成功：宁可回滚点少几个文件，也好过没有回滚点。
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
            if let Err(error) =
                mailstack_core::backup::validate_archive(&snapshot, &self.backups.home_allowlist)
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
            // 公网模式下明文快照留在磁盘上正是医生检查的 FAIL 项；
            // 加密失败就把快照删掉，降级成「没有回滚点」并如实说出去。
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
            // 归档在、元数据不在 —— 它仍然可恢复（靠 `describe` 的兜底），
            // 但要如实说明这次降级。
            let _ = &error;
            mailstack_core::warn::warn_with_detail(
                "pre-restore snapshot metadata",
                &error.to_string(),
            );
        }
        (Some(snapshot.display().to_string()), None)
    }

    /// 恢复之后让受管服务重新读取配置。
    ///
    /// 失败只告警：文件已经换好了，一次 `reload` 失败不该让整个恢复动作报错
    /// （那会让运维以为恢复没成功而重做一遍）。
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

    /// `services.action`：启停 / 重启 / 重载受管服务单元。
    ///
    /// 返回**服务列表本身**（与基线一致）：控制台把响应直接当成新的服务清单
    /// （`setServices(data)`），回一个 `{ok:true}` 会让界面在按下按钮后变成空白。
    ///
    /// 两处刻意的判定：
    /// * **动词必须是已知的**：`ServiceVerb::parse` 对未知动词返回 `None`，这里据此报错。
    ///   基线的 `service_ctl` 收到未知动词会一路落到最后的 `true`（成功但什么都没做），
    ///   那正是「点了重启，其实没重启」的来源。
    /// * **不许停掉控制台自己**：请求正是经 `mailstack-web` 的 sudo 包装器下发的，
    ///   停掉它之后没有任何途径再把它拉起来，只能上控制台。重启是允许的
    ///   （systemd 会拉回，不构成自锁）。
    pub fn services_action(&self, data: &Value) -> Result<Value, HandlerError> {
        let ident = crate::handlers::first_str(data, &["id", "name", "service"])?;
        let verb = crate::handlers::optional_str(data, "verb")
            .or_else(|| crate::handlers::optional_str(data, "action"))
            .unwrap_or("restart")
            .trim()
            .to_ascii_lowercase();
        let unit = resolve_service_unit(ident)
            .ok_or_else(|| HandlerError::new(format!("invalid service: {ident}")))?;

        // `status` 是只读动词，没有任何副作用：它的产物就是下面要返回的列表本身
        // （活性取自 `systemctl show`），所以不必再 spawn 一次 `systemctl status`。
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
        if let Some(output) = outcome.output.as_ref().filter(|o| !o.success()) {
            // 命令跑了但返回非零：如实报错，而不是回一个「看起来重启成功」的列表。
            return Err(HandlerError::new(format!(
                "{} {}: {}",
                parsed.as_str(),
                unit,
                output.diagnostic(parsed.as_str())
            )));
        }

        Ok(Value::Array(self.service_items()))
    }

    /// `security.ban`：把地址写进**手工封禁文件**。
    ///
    /// 这里刻意**不**直接改内存里的封禁表：文件才是手工封禁的唯一真相源，
    /// 守护进程按固定节奏把它对齐进内存（见 `bin/mailstackd/src/bans.rs`）。
    /// 直接改内存会多出第二个真相源，而且重启即丢 —— 那正是「看起来还封着、
    /// 其实已经放行」的成因。
    ///
    /// 因此本动作是**立即返回、稍后生效**的。响应里明确写出
    /// `takesEffectAfterReload`，免得运维看到「封禁成功」就去质问为什么对方还能连。
    ///
    /// 兼容性说明：控制台会一并回传 fail2ban 时代的 `jail` 字段。Rust 这套栈没有
    /// jail 概念（封禁作用在全局），该字段**接受但忽略**；响应用 `scope: "global"`
    /// 如实说明作用范围。
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

    /// `security.unban`：从手工封禁文件里移除地址。
    ///
    /// 只解除**手工**封禁。由失败计数触发的自动封禁不在这里 —— 它们由对端行为决定，
    /// 到期自动消失；把它们也纳入这个入口会让「解封」变成一个能绕过自动防护的后门。
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

    /// `queue.action`：重试 / 删除 / 冲刷队列条目。
    ///
    /// 返回**队列列表本身**（与基线一致：控制台直接 `setQueues(data)`）。
    ///
    /// 三处与基线的差异是刻意的：
    /// * 基线把 id 直接交给 `postqueue -i` / `postsuper -d`；这里的 id 同时是文件名，
    ///   因此必须先过 [`mailstack_queue::entry::is_safe_id`]，把路径穿越挡在拼路径之前。
    /// * `retry` **重置重试预算**。只把 `next_attempt_unix` 提前而不清 `attempts`，
    ///   对一条已耗尽预算的条目来说，下一次投递会立刻退信 —— 那等于「点了重试，
    ///   邮件反而被删掉」。运维显式重试是一次人工决定，应当重新给它一轮预算。
    /// * `flush` 只提前「尚未到期」的条目，已到期的条目不动（不做无谓写盘）。
    pub fn queue_action(&self, data: &Value) -> Result<Value, HandlerError> {
        let store = self.queue();
        let verb = crate::handlers::optional_str(data, "verb")
            .or_else(|| crate::handlers::optional_str(data, "action"))
            .unwrap_or("retry")
            .trim()
            .to_ascii_lowercase();
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
                // 基线用 `rstrip('*!')` 容忍 postfix 在列表里附带的标记位。
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

    // ───────────────────── setup（初始化向导，§5.2 的 setup 分组） ─────────────────────

    /// `setup.identity.apply`：校验身份 → 生成 DKIM → 落 `setup.json`。
    ///
    /// ## 与基线的两处刻意偏离
    ///
    /// * **不碰 Postfix / OpenDKIM**。基线在这里跑 `postconf -e`、
    ///   `opendkim-genkey`、写 `key.table` / `signing.table` / `trusted.hosts`，
    ///   最后 reload 两个服务；本栈已按规格书 §3.3 移除它们，密钥由
    ///   [`mailstack_auth::keys::rotate`] 原生生成，签名在出站路径里完成。
    /// * **校验先于一切副作用**。域名 / 主机 / IP / selector 全部验完才动磁盘，
    ///   因此被拒的请求不会留下半个密钥目录。
    ///
    /// `identity` 的形状就是 `setup.json` 本身（与 `snapshot` 读到的是同一份），
    /// 另外把 `p=` 的 base64 单列为 `dkimPublicKey` —— 向导据此展示要粘贴的 DNS
    /// 记录，不必让运维去读磁盘。
    pub fn setup_identity_apply(&self, data: &Value) -> Result<Value, HandlerError> {
        let domain = crate::handlers::first_str(data, &["domain"])?
            .trim()
            .to_ascii_lowercase();
        let mail_host = crate::handlers::first_str(data, &["mailHost", "mail_host"])?
            .trim()
            .to_ascii_lowercase();
        let server_ip = setup_server_ip(data)?;
        let selector = setup_selector(data);

        // 先验后动：不合法就一个字节都不写。
        mailstack_core::config::validate_setup_identity(&domain, &mail_host, &selector)?;

        let rotation = mailstack_auth::keys::rotate(&self.paths, &domain, Some(&selector))?;

        let config = mailstack_core::config::SetupConfig {
            domain,
            mail_host,
            server_ip,
            dkim_selector: rotation.selector.clone(),
            expected_spf: setup_expected_spf(data),
            updated_at: mailstack_core::now_iso8601_utc(),
        };
        mailstack_core::config::write_setup_config(&self.paths, &config)?;

        Ok(json!({
            "applied": true,
            "identity": config,
            "dkimPublicKey": rotation.public_key_spki_b64,
        }))
    }

    /// `setup.dns.verify`：按权威 DNS 的**实际应答**逐条判定发布情况。
    ///
    /// 判据与基线 `network.py:163` 一一对应。`observed` 把每条查询的结果原样摊开
    /// —— 只回一个 `verified: false` 会让运维完全无从下手：是 A 记录没改，还是
    /// 公钥粘贴时被截断了？
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
        // A：登记的 IP 必须逐字出现在 A 记录里。
        checks.insert("a".to_string(), json!(a.iter().any(|ip| ip == &server_ip)));
        // MX：主机名出现在某条 MX 目标里（`dig +short` 的形态带优先级前缀，
        // 故用子串匹配）。
        checks.insert(
            "mx".to_string(),
            json!(mx.iter().any(|item| item.contains(&mail_host))),
        );
        // 恰好一条 SPF：两条 `v=spf1` 会让收信方按 RFC 7208 直接判 permerror。
        checks.insert("spfSingle".to_string(), json!(spf_records.len() == 1));
        checks.insert(
            "spfExpected".to_string(),
            json!(expected
                .as_deref()
                .map(|want| spf_records.iter().any(|record| record.as_str() == want))
                .unwrap_or(false)),
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
            let mx_ok = ses_mx
                .iter()
                .any(|item| item.contains(&format!("feedback-smtp.{ses_region}.amazonses.com")));
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

    /// `setup.relay.test`：分阶段测试中继端点（§5.9.4）。
    ///
    /// 两种「失败」刻意区分：
    ///
    /// * **请求写错了**（主机名非法、端口不在白名单、TLS 缺失、凭证只给一半）→
    ///   返回**错误**。这是我们该指出的输入问题，不该混进「测试结果」里。
    /// * **对端不通**（解析不了、连不上、握手失败、认证被拒）→ 返回
    ///   `{connected: false, stage: "failed", stages: [...]}`，并**保留已完成的
    ///   阶段**。基线在这里抛异常，界面只能看到一句「SMTP relay test failed」——
    ///   那正好把分阶段可观测性的价值丢掉了（`docs/TEST_REPORT.md` §4.4）。
    ///
    /// `direct: true` 走本机提交端点探测，规则见 [`Readers::direct_delivery_probe`]。
    pub async fn setup_relay_test(&self, data: &Value) -> Result<Value, HandlerError> {
        if flag(data, "direct") {
            return self.direct_delivery_probe().await;
        }
        let request = relay_request(data)?;
        let private = self.relay_private_network_enabled();
        // 参数校验在任何网络行为之前：不合法就没有「测试阶段」可言。
        mailstack_smtp::validate_relay(&request, private)?;
        match self.relay.test(&request, private).await {
            Ok(result) => Ok(result.to_json()),
            Err(failure) => Ok(failure.to_json()),
        }
    }

    /// `setup.relay.apply`：**先测后写**，写入原生 `relay.json`。
    ///
    /// 载体差异：基线写 `postconf` 键 + `sasl_passwd`（还要 `postmap`），本栈读的是
    /// `/etc/mailstack/relay.json`（`mailstackd` 的 `config::load_relay`），因此这里
    /// 是「校验 → 测试 → 原子写该文件」，**没有** postconf / postmap。
    ///
    /// 「测试不过一行配置都不写」「写完回读校验」「失败回滚」这三条顺序由
    /// [`mailstack_smtp::apply_relay`] 保证 —— 不在这里重写一遍，否则就有了第二个
    /// 真相源。
    pub async fn setup_relay_apply(&self, data: &Value) -> Result<Value, HandlerError> {
        let request = relay_request(data)?;
        let private = self.relay_private_network_enabled();
        let endpoint = mailstack_smtp::validate_relay(&request, private)?;

        let result = match self.relay.test(&request, private).await {
            Ok(result) => result,
            Err(failure) => {
                // 测试没通过：一行配置都不写。把阶段信息一并回出去，界面能直接
                // 显示「卡在哪一步」，而不是只给一句「应用失败」。
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

    /// `setup.mail.test`：向**本机提交端点**投一封测试信。
    ///
    /// 载体差异：基线走 `sendmail`（本地 Postfix）；本栈向硬编码的
    /// [`mailstack_smtp::LOCAL_SUBMISSION_ENDPOINT`]（`127.0.0.1:25`）做一次真正的
    /// SMTP 提交 —— 那是 `mailstackd` 自己的入站面。目标是常量而非请求体字段，
    /// 否则这个动作就是一个「任意主机的 SMTP 提交器」。
    ///
    /// ## 两处登记偏离（都源于 `users.*` 尚未移植）
    ///
    /// * 基线的「sender 必须对应一个受管邮箱」与「账号未锁定」两条检查**没有执行**
    ///   —— 用户模型不存在。响应里用 `mailboxChecksSkipped` **明说**，而不是让人
    ///   以为查过了。
    /// * `username` / `password` 因此被**接受但忽略**：它们原本只服务于上面两条检查
    ///   （基线的口令只做格式校验，也不参与认证）。把「没做的事」说成做了，正是
    ///   本项目最忌讳的静默降级。
    ///
    /// 替代防线是**入站策略本身**（INV-17）：未认证会话不得投给外域收件人，
    /// 因此这里不需要再写一遍域名判断 —— 写两遍迟早出现「这里放行、那边拒收」。
    pub async fn setup_mail_test(&self, data: &Value) -> Result<Value, HandlerError> {
        let sender = setup_address(data, &["sender"])?;
        let recipient = setup_address(data, &["recipient"])?;

        // 正文用 CRLF：裸 LF 会被入站的走私防护拒收（详见 `mailtest` 模块说明）。
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
            // 入站 MTA 的应答码：250 表示已接受并落盘，而不是「命令发出去了」。
            "code": report.code,
            "mailboxChecksSkipped": true,
            "mailboxChecksSkippedReason": "the mailbox registry (users.*) is not ported yet; sender/mailbox existence and lock state were not checked",
        }))
    }

    /// `mail.test_loopback`：投一封带一次性 token 的环路自检信，并尽力把它找回来。
    ///
    /// ## 反中继守卫（基线 CHANGELOG 记录的 P0 缺口）
    ///
    /// 基线的旧写法是 `if managed and ...`：全新安装上还没有任何邮箱，`managed` 为空，
    /// 守卫被**整个跳过**，于是这个动作可以对任意互联网地址投信。修好后的判据是
    /// 「至少有一个受管域，且收件域是 `localhost` 或受管域之一」—— 它与「有没有邮箱」
    /// 无关，因此不存在那个空集合缺口。这里照该判据实现。
    ///
    /// ## `maildirDelivered` 是证据，不是成败
    ///
    /// 提交被 `250` 接受就说明环路通了。Maildir 只是额外证据，而权威布局尚未定死
    /// （`crates/store/src/lib.rs`），因此找不到时返回 `false` 而不是错误 ——
    /// 把它当成「投递失败」会让人去查一个根本不存在的故障。
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
            // 没有邮箱注册表可查，故基线的「第一个受管邮箱」不可得；
            // 退到 postmaster@<第一个受管域>（与基线 domains 分支一致）。
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
            // 入站 MTA 的应答码；`maildirDelivered: false` 时它是「提交确实被接受」
            // 的唯一证据。
            "code": report.code,
            "message": format!("Loopback message submitted to the local MTA ({elapsed_ms}ms)"),
        }))
    }

    /// 本机提交端点探测（基线 `_direct_delivery_probe` 的等价物）。
    ///
    /// 目标是**硬编码**的本机提交端点，不是请求体里的主机，因此不适用 SSRF 防护
    /// —— 这一点值得写明，否则后来者会以为这里漏了一道校验。
    ///
    /// 只证明「本地 MTA 活着」：**不证明出站 25 可用**（INV-19）。出站可用性由
    /// `network.check_port` 单独判定，界面必须把两者分开呈现。
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

    /// 部署是否允许私网中继目标。
    ///
    /// 与 `mailstackd` 的装配同一判据（`bin/mailstackd/src/config.rs`：非公网档才
    /// 允许）。两者若各写一份，迟早会出现「向导测得过、守护进程连不上」。
    fn relay_private_network_enabled(&self) -> bool {
        !mailstack_core::mode::is_public_mode(&self.paths)
    }
}

/// 拆解本机提交端点常量（`127.0.0.1:25`）。
fn local_submission_endpoint() -> Result<(String, u16), HandlerError> {
    let raw = mailstack_smtp::LOCAL_SUBMISSION_ENDPOINT;
    let invalid = || HandlerError::new(format!("invalid local submission endpoint: {raw}"));
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(invalid());
    };
    let port = port.parse::<u16>().map_err(|_| invalid())?;
    Ok((host.to_string(), port))
}

/// 解析并规范化 `serverIp`。
///
/// 解析成 `IpAddr` 再回写字符串 = 规范化（`::1` 与 `0:0:0:0:0:0:0:1` 落到同一种
/// 写法），避免「界面上是对的、DNS 里却不是」这类假阴性。
fn setup_server_ip(data: &Value) -> Result<String, HandlerError> {
    let raw = crate::handlers::first_str(data, &["serverIp", "server_ip"])?;
    raw.trim()
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| HandlerError::new("invalid server IP address"))
}

/// 向导的 DKIM selector：缺省 [`SETUP_DEFAULT_DKIM_SELECTOR`]（`mail`）。
fn setup_selector(data: &Value) -> String {
    crate::handlers::optional_str(data, "dkimSelector")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(SETUP_DEFAULT_DKIM_SELECTOR)
        .to_ascii_lowercase()
}

/// 期望的 SPF 记录（空串视为「没有填」）。
fn setup_expected_spf(data: &Value) -> Option<String> {
    crate::handlers::optional_str(data, "expectedSpf")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// 解析并校验一个邮件地址（基线用的 `ADDRESS_RE`，失败文案一致）。
fn setup_address(data: &Value, keys: &[&str]) -> Result<String, HandlerError> {
    let address = crate::handlers::first_str(data, keys)?
        .trim()
        .to_lowercase();
    if !mailstack_core::validate::ADDRESS_RE.is_match(&address) {
        return Err(HandlerError::new("invalid mailbox or sender"));
    }
    Ok(address)
}

/// DKIM TXT 记录里是否带一个「看起来是真的」的 RSA 公钥。
///
/// 判据与基线 `network.py:168` 的正则 `p=[A-Za-z0-9+/]{100,}={0,2}` 等价：
/// 含 `v=DKIM1`，且 `p=` 之后的 base64 去掉尾部填充后不少于 100 字节。
/// 2048 位 SPKI 的 base64 约 344 字符，100 是「绝不是空占位」的下界 ——
/// 粘错 / 被截断的公钥会在这里被挡下，而不是等对端拒收。
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

/// 把请求载荷折算成中继端点校验请求。
///
/// 端口从宽到严走 `validate_relay` 的白名单判定；这里只负责把「不是端口的东西」
/// 挡在类型边界外（`as_u64` 之后必须能装进 `u16`，否则强转会**静默回绕**成
/// 一个合法端口）。
fn relay_request(data: &Value) -> Result<RelayValidationRequest, HandlerError> {
    let host = crate::handlers::first_str(data, &["host", "relayHost"])?.to_string();
    let port = match data.get("port") {
        None | Some(Value::Null) => 587u16,
        Some(value) => {
            // `as_u64` 之后必须能装进 `u16`：否则强转会**静默回绕**成一个合法端口。
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

/// 从载荷里解析被封禁的地址。
///
/// 解析成 `IpAddr` 而不是留着字符串：解析即规范化，`::1` 与 `0:0:0:0:0:0:0:1`
/// 会落到同一条记录上。按字符串存的话，「解封」只会解掉运维恰好回传的那一种写法。
fn ban_target(data: &Value) -> Result<IpAddr, HandlerError> {
    let raw = crate::handlers::first_str(data, &["ip", "address"])?;
    raw.trim()
        .parse::<IpAddr>()
        .map_err(|_| HandlerError::new(format!("invalid ip address: {raw:?}")))
}

/// 控制台 id / 单元名 → systemd 单元名。
///
/// 与基线同序：先按 **id** 命中，再按**单元名**命中。因此 `id` 与单元名相同的
/// 条目（如 `postfix`）两条路径结果一致，不会出现「同一入参两种解释」。
fn resolve_service_unit(ident: &str) -> Option<&'static str> {
    if let Some((_, unit)) = SERVICES.iter().find(|(id, _)| *id == ident) {
        return Some(unit);
    }
    SERVICES
        .iter()
        .find(|(_, unit)| *unit == ident)
        .map(|(_, unit)| *unit)
}

/// 解析 `systemctl show` 的 `key=value` 输出中的某个键。
fn systemd_property<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
    stdout.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim())
    })
}

/// 数字属性解析：`[not set]` 之类的非数字一律当作 0（宁可留空也不编）。
fn parse_u64(value: Option<&str>) -> u64 {
    value.and_then(|v| v.trim().parse().ok()).unwrap_or(0)
}

/// 保留一位小数（与基线的 `round(x, 1)` 一致）。
fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

/// 队列条目 → 控制台的 `QueueItem`。
///
/// 字段名沿用基线（`queueId` / `arrivalDate` / `retryCount` ...），因为新前端的
/// 队列页是按这套字段写的。额外多带一个 `recipients` 数组：基线只取第一个收件人，
/// 于是「这一条还有另外两个收件人待投递」在界面上完全看不见 —— 多一个字段比
/// 藏掉信息划算。
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
        // 下面两项是基线没有的：出站退信与用户邮件在界面上长得一样，
        // 运维排查时看不出哪一条是系统自己发的退信。
        "kind": entry.kind.as_str(),
        "nextAttemptUnix": entry.next_attempt_unix,
    })
}

/// 取一个布尔标志；缺失或不是布尔一律当作 `false`。
///
/// 与 `ActionGate` 对 `confirm` 的处理同一口径：**不做真值转换**，字符串 "true"
/// 不是 `true`。「大概是这个意思」在安全开关上不是可以接受的理由。
fn flag(data: &Value, key: &str) -> bool {
    data.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// 备份文件名的时刻部分：`YYYYMMDD-HHMMSS`（UTC）。
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

/// 同一秒内撞名时用的后缀（小写十六进制，符合文件名正则的 `[a-z0-9_-]+`）。
fn collision_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{nanos:08x}")
}

/// 体检结论 → 线上结构（camelCase）。
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

/// 证书到期告警窗口（天）。
pub const EXPIRY_WARNING_DAYS: i64 = 14;

/// 组装一条检查项。
fn check(name: &str, ok: bool, detail: impl Into<String>) -> Value {
    json!({ "name": name, "ok": ok, "detail": detail.into() })
}

/// 把 [`mailstack_core::certs::CertificateInfo`] 转成线上结构（camelCase）。
fn certificate_to_json(info: mailstack_core::certs::CertificateInfo) -> Value {
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

/// 读 `relay.json` 里的 relayhost（只取主机名，不碰凭证）。
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

/// 行数夹取：默认 200，上限 1000。
///
/// 上限是必须的：这是一条可以随时被调用的只读接口，没有任何上限就等于给了
/// 调用方一个「把 journalctl 全量倒出来」的开关。
fn clamp_lines(data: &Value) -> usize {
    data.get("lines")
        .and_then(Value::as_u64)
        .map(|n| (n as usize).clamp(1, LOGS_MAX_LINES))
        .unwrap_or(LOGS_DEFAULT_LINES)
}

/// journald 的 JSON 记录 → 线上结构。
///
/// `MESSAGE` 可能是字符串，也可能是字节数组（非 UTF-8 的日志会有后者）。
/// 两种情况都要能读出来 —— 一条二进制日志不该让整个列表解析失败。
fn journal_entry_to_json(raw: &Value) -> Value {
    let message = raw
        .get("MESSAGE")
        .map(|m| match m {
            Value::String(s) => s.clone(),
            Value::Array(bytes) => bytes
                .iter()
                .filter_map(Value::as_u64)
                .map(|b| b as u8)
                .collect::<Vec<u8>>()
                .into_iter()
                .map(|b| b as char)
                .collect(),
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

/// syslog 优先级 → 名字（RFC 5424 §6.2.1，`0` 最高）。
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

/// 把只读聚合面的处理器注册进注册表。
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

    // ── 变更面（RW）：这两个动作的响应是**列表本身**，控制台直接当成新状态 ──
    // 注册位置不影响通道判定：RO / RW 由 `ActionGate` 在调用之前决定。
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

    // ── 初始化向导（§5.2 的 setup 分组） ──
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

    // ── 邮件环路自检（`setup.mail.test` 与 `mail.test_loopback` 配对） ──
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_core::exec::CommandOutput;
    use std::fs;
    use std::sync::Mutex;

    /// 固定时钟：2026-01-01T00:00:00Z。
    const NOW: i64 = 1_767_225_600;

    /// 记账用的假运行器：任何命令都返回同一份脚本化输出，并记下被调用的参数。
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

        /// 被调用过的程序名（按调用顺序）。
        fn called(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(program, _)| program.clone())
                .collect()
        }

        /// 被调用过的完整命令（程序 + 参数）。
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
    }

    /// 什么都不存在的环境探测：所有服务都判为未运行。
    struct NoServices;

    impl ServiceEnv for NoServices {
        fn program_available(&self, _program: &str) -> bool {
            false
        }
        fn path_exists(&self, _path: &std::path::Path) -> bool {
            false
        }
    }

    /// 只声明给定程序 / 路径存在的环境探测。
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

    /// 备份加密的替身：把口令长度写在头部，好断言「确实走了加密路径」。
    /// 真实实现在 `mailstack_core::backup::GpgCipher`（口令只经 stdin 传给 gpg）。
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
        /// 备份动作的「根」：一棵生产形状的临时文件树（`etc/mailstack/...`）。
        ///
        /// 有了它，备份测试既不会去读生产主机的 `/etc`，更不会往真实的 `/` 里写。
        backup_root: PathBuf,
        /// 恢复的落地根。
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

            // 生产形状的备份源树。
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

        /// 备份动作专用的 Reader：根与落地根都在临时目录里，加密用假后端。
        fn backup_readers(&self, runner: Arc<dyn CommandRunner>) -> Readers {
            self.readers(runner).with_backup_env(BackupEnv {
                root: self.backup_root.clone(),
                restore_root: self.restore_root.clone(),
                cipher: Arc::new(TestCipher),
                home_allowlist: BTreeSet::new(),
            })
        }

        fn readers(&self, runner: Arc<dyn CommandRunner>) -> Readers {
            self.readers_with_env(runner, Arc::new(NoServices))
        }

        /// 与 [`Fixture::readers`] 相同，但可注入「哪些程序/路径存在」的替身环境。
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

        /// 用 rcgen 签一张 `days` 天后到期的自签证书。
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
        // 注册表只负责「已放行动作怎么执行」；通道由 `ActionGate` 判定，
        // 因此这两条必须真的可被分派，否则控制台的按钮会落到 NOT_IMPLEMENTED。
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
        // 用户模块尚未移植 —— 必须显式说出来，否则界面会把「读不到」画成「0 个用户」。
        assert_eq!(out["unavailable"], json!(["users"]));
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

        // 配了中继之后，结论从「请配中继」变成「中继本身在失败」。
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

        // 往隔离目录放一条（坏条目应当被计入「已被隔离」，而不是消失）。
        fs::create_dir_all(store.corrupt_dir()).unwrap();
        fs::write(store.corrupt_dir().join("bad.json.1.corrupt"), b"x").unwrap();

        let out = f.readers(always_ok_runner()).snapshot(&json!({})).unwrap();
        assert_eq!(out["queue"]["backlog"], 1);
        assert_eq!(out["queue"]["corrupt"], 1);
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
        // 控制台列出的服务必须**逐条**出现，且带上界面要用的字段。
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
        // 其余子项不受影响。
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
        // 目标只来自部署配置：否则这个只读接口就是一个任意主机的 TCP 探针。
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
        // 注入的目标清单为空 ⇒ 一个目标都不探测；请求体里的目标不得生效。
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

        // 探针跑在新建的内存表上 ⇒ 再跑一次结果一模一样（没有累积状态）。
        let second = readers.system_doctor(&json!({})).unwrap();
        assert_eq!(first, second, "诊断不得留下任何状态");
    }

    #[test]
    fn system_doctor_reports_each_broken_precondition() {
        let f = Fixture::new("doctorbad");
        // 未设置身份、未设口令、域名表为空、无 DKIM 私钥、无证书。
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
        // 没有任何中继配置是**合法状态**，不是故障。
        assert_eq!(check_of("relay_config")["ok"], true);
        // 不存在的审计日志视为空链，通过。
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
        // DKIM 私钥：放到 keys::private_key_path 指向的位置。
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

    // ── security.scan ──

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
        // 没装的组件不该被报成问题，但要能被区分出来。
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
        // 目录放宽（0755）虽然读不到里面的 0600 文件，但会把「有哪几个文件」
        // 暴露出去，比单个文件更该被看见。
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
        // DKIM 私钥是按**纳管域**枚举的，所以域名表里得先有这个域。
        fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let dkim = mailstack_auth::keys::private_key_path(&f.paths, "example.com", "mail");
        fs::create_dir_all(dkim.parent().unwrap()).unwrap();
        fs::write(&dkim, "key").unwrap();

        let paths: Vec<String> = f
            .readers(always_ok_runner())
            .security_inventory()
            .into_iter()
            .map(|e| e.path.display().to_string())
            .collect();

        // 明文中继口令：基线点名要求扫它。
        assert!(
            paths.iter().any(|p| p.ends_with("sasl_passwd")),
            "清单必须包含 sasl_passwd: {paths:?}"
        );
        assert!(paths.iter().any(|p| p.ends_with("totp.key")));
        assert!(paths.iter().any(|p| p.ends_with("relay.json")));
        assert!(paths.iter().any(|p| p.ends_with("ai-provider.json")));
        // 每个已签发域的 TLS 私钥 + 每个纳管域的 DKIM 私钥。
        assert!(paths
            .iter()
            .any(|p| p.ends_with("mail.example.com/privkey.pem")));
        assert!(paths.iter().any(|p| p.ends_with(".private")));
    }

    // ── backup.list ──

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
        // 点文件与不合规的名字都不是备份，必须被跳过。
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
        // 没有元数据 sidecar 时必须标出来，而不是把这份备份从列表里抹掉。
        assert_eq!(
            by_name("mailstack-backup-20260101-000000.tar.gz")["metadataMissing"],
            true
        );
    }

    // ───────────────────── services.action ─────────────────────

    /// 造一个「systemd 可用」的替身：`systemctl` 存在且 `/run/systemd/system` 是目录。
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

        // 响应必须**是列表本身**：控制台把它直接当成新的服务清单。
        let items = out.as_array().expect("必须是数组");
        assert_eq!(items.len(), SERVICES.len());
        assert_eq!(items[0]["id"], SERVICES[0].0);

        // 降级链首命中 systemctl，动词原样下发。
        let calls = runner.calls();
        assert_eq!(calls[0].0, "systemctl");
        assert_eq!(
            calls[0].1,
            vec!["restart".to_string(), "dovecot".to_string()]
        );
    }

    #[test]
    fn services_action_accepts_a_unit_name_as_well_as_the_console_id() {
        // 控制台传 id（`clamav`），运维习惯传单元名（`clamav-daemon`）—— 两者都要能操作。
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
        // 停掉 mailstack-web 之后没有任何途径再把它拉起来 —— 必须拒绝，且不得执行命令。
        let f = Fixture::new("svcself");
        let runner = FakeRunner::returning(0, "");
        let readers = f.readers_with_env(runner.clone(), systemd_env());

        let err = readers
            .services_action(&json!({ "id": "mailstack-web", "verb": "stop" }))
            .unwrap_err();
        assert!(err.to_string().contains("refusing to stop"), "实际: {err}");
        assert!(runner.calls().is_empty(), "被拒绝的动作不得产生任何副作用");

        // 而 restart 是允许的：systemd 会把它拉回来，不构成自锁。
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

        // 未知动词必须报错。基线的 `service_ctl` 会一路落到 `true`（成功但什么都没做），
        // 那正是「点了重启、其实没重启」的来源。
        let err = readers
            .services_action(&json!({ "id": "dovecot", "verb": "explode" }))
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid service verb"),
            "实际: {err}"
        );
        assert!(runner.calls().is_empty(), "被拒绝的动作不得执行任何命令");

        // 缺 id 是真错误，不得猜一个默认服务。
        assert!(readers
            .services_action(&json!({ "verb": "restart" }))
            .is_err());
    }

    #[test]
    fn services_action_reports_a_failing_command_instead_of_a_success_list() {
        // 命令跑了但返回非零：不能回一个「看起来重启成功」的列表。
        let f = Fixture::new("svcfail");
        let runner = FakeRunner::returning(1, "");
        let readers = f.readers_with_env(runner, systemd_env());

        let err = readers
            .services_action(&json!({ "id": "dovecot", "verb": "restart" }))
            .unwrap_err();
        assert!(err.to_string().contains("exited with 1"), "实际: {err}");
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

        // 只允许 `systemctl show ...` 这类**只读**探测；不得出现 `systemctl status`，
        // 更不得出现 start/stop/restart/reload。
        for (program, args) in runner.calls() {
            assert_eq!(program, "systemctl");
            assert_eq!(args.first().map(String::as_str), Some("show"), "{args:?}");
        }
        assert!(
            !runner.calls().is_empty(),
            "status 仍应给出真实活性，而不是一份编出来的列表"
        );
    }

    // ───────────────────── queue.action ─────────────────────

    /// 往队列里放一条条目并返回它的 id。
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
        let due = enqueue(&f, 1, NOW); // 已到期
        let deferred = enqueue(&f, 1, NOW + 3600); // 退避中
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
        // 只把时间提前而不清 `attempts`，对一条已耗尽预算的条目来说下一次投递会立刻退信 ——
        // 那等于「点了重试，邮件反而被删掉」。所以重试必须重新给一轮预算。
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
    fn queue_action_rejects_traversing_ids_and_unknown_verbs() {
        let f = Fixture::new("qbad");
        let readers = f.readers(always_ok_runner());

        // id 同时是文件名：路径穿越必须在拼路径**之前**就被挡死。
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

        // 合法但不存在的 id：报「没有这条」，而不是静默成功。
        let err = readers
            .queue_action(&json!({ "id": "DEADBEEF0001", "verb": "retry" }))
            .unwrap_err();
        assert!(err.to_string().contains("no such queue entry"), "{err}");
    }

    #[test]
    fn queue_action_tolerates_the_markers_postfix_prints_in_the_list() {
        // 基线用 `rstrip('*!')` 去掉列表里的标记位；控制台可能把带标记的字符串回传。
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
        // 积压摘要仍然在（两个字段并存：摘要给仪表盘，明细给队列页）。
        assert_eq!(out["queue"]["backlog"], 1);
    }

    // ───────────────────── security.ban / security.unban ─────────────────────

    /// 读出测试夹具里的手工封禁文件。
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
        // 同一个 IPv6 地址的两种写法必须落到同一条记录，否则「解封」只解掉一半。
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
        // 缺字段是真错误，不得猜一个「全部封禁」之类的默认值。
        let err = readers.security_ban(&json!({})).unwrap_err();
        assert!(err.to_string().contains("missing required field"), "{err}");
        // 一次都不该落盘。
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

        // 幂等：再解封一次不是错误（运维会连点）。
        readers
            .security_unban(&json!({ "ip": "198.51.100.7" }))
            .unwrap();
    }

    #[test]
    fn a_manual_ban_is_never_written_over_a_corrupt_file() {
        // 损坏时拒绝写入：新写一份会把运维可能还想抢救的旧内容彻底抹掉。
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
        // null（读不到）与 []（确实没有）在运维眼里是两件完全不同的事。
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

    // ───────────────────── backup.create / restore / delete ─────────────────────

    /// 从列表里按文件名取一条。
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
        // `metadataMissing` 只在为真时出现；元数据齐全时它就该缺席，
        // 因此这里断言「元数据确实读到了」——即校验和在场。
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

        // 直接读归档，确认 admin.json 真的不在里面。
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
        // 把源树清空：没有来源时不许产出一个空归档假装成功。
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

        // 没有 confirm：拒绝，且**不得**动落地根。
        let err = readers
            .backup_restore(&json!({ "filename": filename }))
            .unwrap_err();
        assert!(err.to_string().contains("confirmation"), "{err}");
        let restored_count = walk(&f.restore_root).len();
        assert_eq!(restored_count, 0, "被拒绝的恢复不得写任何文件");

        // 路径穿越的文件名：必须在进入核心之前就被挡掉。
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

        // 先破坏现场：恢复之后必须能把内容还原回来。
        fs::write(f.backup_root.join("etc/mailstack/settings.json"), "{}").unwrap();
        let out = readers
            .backup_restore(&json!({ "filename": filename, "confirm": true }))
            .unwrap();

        assert_eq!(out["restored"], true);
        assert!(out["filesCount"].as_u64().unwrap() > 0);
        assert_eq!(
            fs::read_to_string(f.restore_root.join("etc/mailstack/settings.json")).unwrap(),
            "{}"
        );
        // 回滚点必须真的登记上了，否则这次恢复没有回头路。
        assert!(
            out["preRestoreSnapshot"].is_string(),
            "缺少预恢复快照：{out}"
        );
        assert!(out["preRestoreSnapshotWarning"].is_null());
        let snapshot = out["preRestoreSnapshot"].as_str().unwrap();
        assert!(std::path::Path::new(snapshot).is_file());

        // 回滚点自身也要能被解析回一个合法归档名。
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

    /// 递归列出一个目录下的全部文件（相对路径）。
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

    // ───────────────────── setup（初始化向导） ─────────────────────

    /// 可编程的 DNS 替身：按记录类型返回预设值。
    ///
    /// 必须完全离线：`setup.dns.verify` 的判据只能靠**受控的应答**来验证，
    /// 打真实 DNS 的断言会随网络抖动随机变红（`docs/TEST_REPORT.md` §4.14）。
    struct StaticDns {
        a: Vec<String>,
        mx: Vec<String>,
        txt: std::collections::HashMap<String, Vec<String>>,
        /// 非空时每次查询都失败（用于断言「解析故障必须上抛，而不是判为未发布」）。
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

    /// 一段「看起来是真的」的 DKIM 公钥体。
    fn dkim_txt_value() -> String {
        format!("v=DKIM1; k=rsa; p={}", "A".repeat(120))
    }

    /// 分阶段成功结果（形状与 `stages::run_relay_test` 的产物一致）。
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

    /// 脚本化的中继探针。
    struct ScriptedRelayProbe {
        test: Result<RelayTestResult, String>,
        direct: Result<RelayTestResult, String>,
        /// 收到的请求 —— 用于断言「参数校验发生在任何网络行为之前」。
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

    /// 换掉网络后端的 Reader：DNS 与中继探针都由替身接管。
    fn readers_with_networks(
        f: &Fixture,
        dns: Arc<dyn DnsQuery>,
        relay: Arc<dyn RelayProbe>,
    ) -> Readers {
        f.readers(always_ok_runner())
            .with_dns(dns)
            .with_relay_probe(relay)
    }

    /// 一份「已经正确发布」的 DNS 应答。
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
        // 缺省 selector 与基线一致（`mail`，不是 dkim.rotate 的 `mailstack`）。
        assert_eq!(out["identity"]["dkimSelector"], "mail");

        // 返回的公钥必须与落盘的 zone 片段里的 p= 一致 —— 否则向导会把一份
        // 对不上号的公钥展示给运维。
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

        // setup.json 与私钥都真的落盘了。
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
            // mailHost 必须是 domain 的子域。
            json!({ "domain": "example.com", "mailHost": "example.com", "serverIp": "203.0.113.10" }),
            json!({ "domain": "example.com", "mailHost": "mail.other.com", "serverIp": "203.0.113.10" }),
            // IP 不是地址。
            json!({ "domain": "example.com", "mailHost": "mail.example.com", "serverIp": "not-an-ip" }),
            // selector 非法。
            json!({ "domain": "example.com", "mailHost": "mail.example.com", "serverIp": "203.0.113.10", "dkimSelector": "bad selector" }),
        ] {
            assert!(
                readers.setup_identity_apply(&bad).is_err(),
                "{bad} 必须被拒绝"
            );
        }
        // 缺字段也是错误，不得猜默认值。
        assert!(readers.setup_identity_apply(&json!({})).is_err());

        // 被拒的请求不得留下任何痕迹：没有 setup.json，也没有密钥目录。
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
        // observed 原样摊开每条查询：只回 false 会让运维无从下手。
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
        // 「DNS 里没有」与「查询故障」是两件事：前者是结论，后者才是错误。
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
        // 两条 `v=spf1` 会让收信方按 RFC 7208 直接判 permerror。
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
        // 主域记录齐全；SES 的 Mail-From 域只发布了 SPF、没有反馈 MX（真实里常见）。
        // 判据必须能分别说清哪一条没配好，而不是笼统地「没通过」。
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

    #[tokio::test]
    async fn setup_relay_test_reports_a_failed_probe_as_a_conclusion_with_stages() {
        // 对端不通是**结论**，不是「服务器出错」：返回 200 + connected:false +
        // 已完成的阶段，界面才能显示卡在哪一步。
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
        // 公网档：私网中继一律拒绝（INV-15）。
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
        // 直投探测只证明本机 MTA 活着（INV-19），故不涉及出站端口判定。
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

        // 落在守护进程真正会读的那份文件上（`config::load_relay`）。
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
        // 「先测后写」的字面含义：测试不过就一行配置都不写。
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
        // 已有中继配置时失败，旧配置必须原样保留（不能因为一次失败测试而清掉）。
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

    #[test]
    fn a_truncated_dkim_key_is_not_accepted_as_published() {
        // 回归守卫：`network.py:115` 记录过一次公钥被截断的真实事故 ——
        // 截断的公钥在本地看着像「记录已发布」，对端却验不过。
        assert!(has_dkim_public_key(&dkim_txt_value()));
        assert!(!has_dkim_public_key(&format!(
            "v=DKIM1; k=rsa; p={}",
            "A".repeat(99)
        )));
        // 只有 `v=` 没有 `p=`。
        assert!(!has_dkim_public_key("v=DKIM1; k=rsa;"));
        // 完全不是 DKIM 记录。
        assert!(!has_dkim_public_key(&"A".repeat(200)));
    }

    #[test]
    fn setup_selector_defaults_to_the_baseline_value_not_the_rotation_default() {
        // 两个缺省刻意不同：向导用 `mail`，dkim.rotate 用 `mailstack`。
        // 混用会让已发布的 DNS 记录对不上。
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

    // ───────────────────── 邮件环路自检 ─────────────────────

    /// 脚本化的本机提交器。
    struct RecordingSubmitter {
        seen: Mutex<Vec<crate::mailtest::LocalSubmission>>,
        /// `Ok(code)` = 入站 MTA 接受；`Err(说明)` = 被拒或连接失败。
        outcome: Result<u16, String>,
        /// 非空时把收到的报文写进这个目录（模拟 MTA 已投递到 Maildir）。
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

        /// 与 [`RecordingSubmitter::accepting`] 相同，但会把报文落进给定目录。
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

    /// 换掉提交器的 Reader：家目录根指向夹具临时目录，绝不扫真实 `/home`。
    fn readers_with_mailtest(f: &Fixture, submitter: Arc<RecordingSubmitter>) -> Readers {
        f.readers(always_ok_runner())
            .with_mailtest_env(MailTestEnv {
                home_root: f.root.clone(),
                submitter,
            })
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
    async fn setup_mail_test_submits_with_crlf_and_says_what_it_could_not_check() {
        let f = Fixture::new("mailtest");
        let submitter = RecordingSubmitter::accepting();
        let readers = readers_with_mailtest(&f, Arc::clone(&submitter));

        let out = readers
            .setup_mail_test(&json!({
                "sender": "alice@example.com",
                "recipient": "bob@example.com",
                // 这两个字段本栈没有模型可查，必须被**忽略**而不是假装校验过。
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
        assert_eq!(
            out["mailboxChecksSkipped"], true,
            "没做的检查必须明说: {out}"
        );

        let submissions = submitter.submissions();
        assert_eq!(submissions.len(), 1);
        let submission = &submissions[0];
        assert_eq!(submission.mail_from, "alice@example.com");
        assert_eq!(submission.recipient, "bob@example.com");
        // 裸 LF 会被入站的走私防护拒收，正文必须已是 CRLF。
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
        // 口令不得被带进报文。
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
        // 缺字段是另一类错误，且必须比「格式不对」更精确 —— 否则调用方会把
        // 「字段名写错了」误当成「地址非法」。
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
    async fn setup_mail_test_never_reports_queued_when_the_mta_rejects_it() {
        let f = Fixture::new("mailtestreject");
        let submitter = RecordingSubmitter::rejecting("554 5.7.1 Relay access denied");
        let readers = readers_with_mailtest(&f, submitter);

        let err = readers
            .setup_mail_test(&json!({
                "sender": "alice@example.com",
                "recipient": "attacker@external.example",
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Relay access denied"), "{err}");
    }

    #[tokio::test]
    async fn mail_test_loopback_requires_a_managed_domain() {
        // 空域名表 = 全新安装：基线曾被 `if managed and ...` 整个跳过守卫，
        // 这里必须直接拒绝，绝不能对互联网地址投信。
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
        // 提交器把报文落进 vmail 布局里的一处候选位置。
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

        // 报文里确实带着那个 token，且用 CRLF 行尾。
        let submissions = submitter.submissions();
        assert_eq!(submissions.len(), 1);
        assert!(submissions[0].data.contains(&token));
        assert!(submissions[0].data.contains("\r\n"));
        assert_eq!(submissions[0].recipient, "carol@example.com");
    }

    #[tokio::test]
    async fn mail_test_loopback_reports_a_missing_maildir_as_absent_evidence_not_failure() {
        // 提交被 250 接受就说明环路通了；Maildir 只是额外证据。
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
}

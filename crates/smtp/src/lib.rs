//! MailStack SMTP 核心 —— 替代 Postfix 的第一步（规格书 §5.8、§5.9）。
//!
//! 本 crate 的**最高优先级**是 §5.9.3 的中继 SSRF 防护。规格书把它列为最高风险，
//! 并特别指出退化后的隐蔽性：「退化后代码照样能跑、测试照样绿，但防护已静默消失」。
//! 因此这里的做法不是「记得别用域名重连」，而是让拨号 API **在类型上**只接受
//! 已固定的 IP（[`target::PinnedTarget::dial_addr`] 返回 `SocketAddr`）。
//!
//! 模块划分：
//!
//! * [`target`] —— 解析 + 地址策略 + IP 固定（INV-14、INV-15）
//! * [`dial`] —— IP 固定拨号与 TLS（STARTTLS / 隐式 TLS）
//! * [`validate`] —— 中继端点校验（INV-13、INV-15）
//! * [`client`] —— 最小 SMTP 客户端（供分阶段测试与队列投递复用）
//! * [`stages`] —— 分阶段中继测试（§5.9.4）
//! * [`relay_apply`] —— 先测后写、回读校验、失败回滚（§5.9.5、INV-16、INV-20）
//! * [`relay_store`] —— 配置载体的真实落盘实现：Postfix（迁移期）与原生 relay.json
//! * [`probe`] —— 出站端口探测与 direct 可用性判据（§5.10.2、INV-19）
//! * [`mx`] —— MX 解析与直投目标选择（RFC 5321 §5.1、RFC 7505）
//! * [`policy`] —— 反中继 fail-closed 与出站路径选择（INV-17、INV-18、INV-21）

pub mod client;
pub mod dial;
pub mod dns_query;
pub mod error;
pub mod mx;
pub mod policy;
pub mod probe;
pub mod relay_apply;
pub mod relay_store;
pub mod stages;
pub mod target;
pub mod validate;

pub use dial::{EstablishedStream, PinnedDialer, TlsMode};
pub use dns_query::{DnsFuture, DnsQuery, HickoryDnsQuery};
pub use error::{SmtpError, SmtpResult};
pub use mx::{
    classify_mx, resolve_mx_targets, HickoryMxResolver, MxFuture, MxRecord, MxResolver, MxTargets,
    DIRECT_DELIVERY_PORT,
};
pub use policy::{select_outbound_route, OutboundRoute, RelayDecision, RelayPolicy};
pub use probe::{direct_mode_verdict, DirectModeVerdict, PortProbeResult, PortStatus};
pub use relay_apply::{
    apply_relay, plan_relay_apply, RelayApplyFailure, RelayApplyResult, RelayConfigStore,
    RelayPlan, ERR_RELAYHOST_VERIFY_FAILED,
};
pub use relay_store::{
    parse_sasl_passwd, CommandOutput, CommandRunner, NativeRelayStore, PostfixRelayStore,
    SaslEntry, SystemCommandRunner,
};
pub use stages::{RelayStage, RelayTestFailure, RelayTestResult, StageOutcome};
pub use target::{resolve_pinned, AddressPolicy, PinnedTarget};
pub use validate::{validate_relay, RelayEndpoint, RelayValidationRequest};

/// 连接超时（§5.9.4：连接 20s）。
pub const CONNECT_TIMEOUT_SECS: u64 = 20;

/// 直投探测超时（§5.9.4：10s）。
pub const DIRECT_PROBE_TIMEOUT_SECS: u64 = 10;

/// 出站端口探测的目标与超时（§5.10.2）。
pub const PORT_PROBE_TIMEOUT_SECS: u64 = 3;

/// 出站端口探测的默认目标（可用 `MAILSTACK_PORT_PROBE_TARGETS` 覆盖）。
pub const DEFAULT_PORT_PROBE_TARGETS: &[&str] = &[
    "smtp.gmail.com",
    "smtp.qq.com",
    "outlook-com.olc.protection.outlook.com",
];

/// 允许的中继端口白名单（§5.9.2）。
pub const ALLOWED_RELAY_PORTS: &[u16] = &[25, 465, 587, 2525];

/// 本机 SMTP 提交端点（direct 模式探测用，§5.9.1）。
pub const LOCAL_SUBMISSION_ENDPOINT: &str = "127.0.0.1:25";

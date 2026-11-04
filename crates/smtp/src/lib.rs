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
    apply_relay, clear_relay, plan_relay_apply, RelayApplyFailure, RelayApplyResult,
    RelayConfigStore, RelayPlan, ERR_RELAYHOST_VERIFY_FAILED,
};
pub use relay_store::{
    parse_sasl_passwd, CommandOutput, CommandRunner, NativeRelayStore, PostfixRelayStore,
    SaslEntry, SystemCommandRunner,
};
pub use stages::{RelayStage, RelayTestFailure, RelayTestResult, StageOutcome};
pub use target::{is_private_network_address, resolve_pinned, AddressPolicy, PinnedTarget};
pub use validate::{validate_relay, RelayEndpoint, RelayValidationRequest};

pub const CONNECT_TIMEOUT_SECS: u64 = 20;

pub const DIRECT_PROBE_TIMEOUT_SECS: u64 = 10;

pub const PORT_PROBE_TIMEOUT_SECS: u64 = 3;

pub const DEFAULT_PORT_PROBE_TARGETS: &[&str] = &[
    "smtp.gmail.com",
    "smtp.qq.com",
    "outlook-com.olc.protection.outlook.com",
];

pub const ALLOWED_RELAY_PORTS: &[u16] = &[25, 465, 587, 2525];

pub const LOCAL_SUBMISSION_ENDPOINT: &str = "127.0.0.1:25";

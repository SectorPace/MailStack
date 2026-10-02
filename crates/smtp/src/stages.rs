//! 分阶段中继测试（规格书 §5.9.4）。
//!
//! **必须保留分阶段可观测性** —— 前端 `SmtpRelayView` 逐阶段渲染。成功时的结构：
//!
//! ```text
//! stages[0] dns      → { ok, addresses: [...最多 8 条], pinnedAddress }
//! stages[1] connect  → { ok, code, banner: 前 200 字符 }
//! stages[2] tls      → { ok, code } 或 { ok: true, implicit: true }
//! stages[3] auth     → { ok: true } 或 { ok: true, skipped: true }（无凭证时跳过）
//! ```
//!
//! 失败时追加 `{ stage: 'failed', ok: false, message: <类别名> }`。
//! 整体结果含 `connected`、`stage`（最后执行到的阶段）、`latencyMs`、`stages`。

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::client::SmtpSession;
use crate::dial::{PinnedDialer, TlsMode};
use crate::error::SmtpError;
use crate::target::PinnedTarget;
use crate::validate::{address_policy_for, validate_relay, RelayValidationRequest};
use crate::{CONNECT_TIMEOUT_SECS, DIRECT_PROBE_TIMEOUT_SECS};

/// dns 阶段最多展示的地址数。
pub const MAX_REPORTED_ADDRESSES: usize = 8;

/// 阶段标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStage {
    Dns,
    Connect,
    Tls,
    Auth,
    Failed,
}

impl RelayStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelayStage::Dns => "dns",
            RelayStage::Connect => "connect",
            RelayStage::Tls => "tls",
            RelayStage::Auth => "auth",
            RelayStage::Failed => "failed",
        }
    }
}

/// 单个阶段的产出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageOutcome {
    pub stage: RelayStage,
    pub ok: bool,
    pub detail: Value,
}

impl StageOutcome {
    /// 构造一个阶段产出。`detail` 的键会被并入 [`StageOutcome::to_json`] 的顶层。
    pub fn new(stage: RelayStage, ok: bool, detail: Value) -> Self {
        Self { stage, ok, detail }
    }

    /// 线上结构：`{ stage, ok, ...detail }`。
    pub fn to_json(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("stage".to_string(), json!(self.stage.as_str()));
        object.insert("ok".to_string(), json!(self.ok));
        if let Value::Object(extra) = &self.detail {
            for (k, v) in extra {
                object.insert(k.clone(), v.clone());
            }
        }
        Value::Object(object)
    }
}

/// 成功结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTestResult {
    pub connected: bool,
    /// 最后完成（成功）的阶段。
    pub stage: RelayStage,
    pub latency_ms: u64,
    pub stages: Vec<StageOutcome>,
}

impl RelayTestResult {
    pub fn to_json(&self) -> Value {
        json!({
            "connected": self.connected,
            "stage": self.stage.as_str(),
            "latencyMs": self.latency_ms,
            "stages": self.stages.iter().map(StageOutcome::to_json).collect::<Vec<_>>(),
        })
    }

    /// 取某一阶段的产出。
    pub fn stage(&self, stage: RelayStage) -> Option<&StageOutcome> {
        self.stages.iter().find(|s| s.stage == stage)
    }
}

/// 失败结果。
///
/// **刻意不是裸 `SmtpError`**：分阶段测试的全部价值就在于「失败时仍能告诉运维
/// 卡在哪一步、前面几步已经成功」。把 stages 丢在错误里，界面就只能显示一个
/// 「连接失败」，无法区分「DNS 就没解析出来」与「TLS 握手失败」。
#[derive(Debug)]
pub struct RelayTestFailure {
    pub error: SmtpError,
    /// 失败前最后成功完成的阶段；参数校验就失败时为 `None`。
    pub last_ok_stage: Option<RelayStage>,
    pub latency_ms: u64,
    pub stages: Vec<StageOutcome>,
}

impl RelayTestFailure {
    /// 线上结构：与成功结果同形，`connected=false` 且含 failed 阶段。
    pub fn to_json(&self) -> Value {
        json!({
            "connected": false,
            "stage": RelayStage::Failed.as_str(),
            "lastOkStage": self.last_ok_stage.map(|s| s.as_str()),
            "latencyMs": self.latency_ms,
            "error": { "code": self.error.kind(), "message": self.error.to_string() },
            "stages": self.stages.iter().map(StageOutcome::to_json).collect::<Vec<_>>(),
        })
    }
}

/// 阶段记录器。
struct StageRecorder {
    stages: Vec<StageOutcome>,
    started: Instant,
}

impl StageRecorder {
    fn new() -> Self {
        Self {
            stages: Vec::new(),
            started: Instant::now(),
        }
    }

    fn push(&mut self, stage: RelayStage, detail: Value) {
        self.stages.push(StageOutcome::new(stage, true, detail));
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn succeed(self, stage: RelayStage) -> RelayTestResult {
        RelayTestResult {
            connected: true,
            stage,
            latency_ms: self.elapsed_ms(),
            stages: self.stages,
        }
    }

    /// 追加 failed 阶段并产出失败结构。
    fn fail(mut self, error: SmtpError) -> RelayTestFailure {
        let last_ok_stage = self.stages.last().map(|s| s.stage);
        tracing::debug!(
            completed_stages = self.stages.len(),
            elapsed_ms = self.elapsed_ms(),
            kind = error.kind(),
            "relay test stage failed"
        );
        self.stages.push(StageOutcome::new(
            RelayStage::Failed,
            false,
            json!({ "message": error.kind() }),
        ));
        RelayTestFailure {
            error,
            last_ok_stage,
            latency_ms: self.elapsed_ms(),
            stages: self.stages,
        }
    }
}

/// 执行分阶段中继测试。
///
/// 参数校验失败发生在**任何网络行为之前**，此时没有任何已完成的阶段，
/// 但同样以 [`RelayTestFailure`] 返回，保持调用方处理路径统一。
pub async fn run_relay_test(
    dialer: &PinnedDialer,
    request: &RelayValidationRequest,
    private_network_enabled: bool,
) -> Result<RelayTestResult, RelayTestFailure> {
    let mut rec = StageRecorder::new();

    // ── 校验（不合法就没有后续阶段）──
    let endpoint = match validate_relay(request, private_network_enabled) {
        Ok(e) => e,
        Err(e) => return Err(rec.fail(e)),
    };

    // ── 阶段 dns：解析 + IP 固定 ──
    let policy = address_policy_for(request);
    let target = match crate::resolve_pinned(&endpoint.host, endpoint.port, policy).await {
        Ok(t) => t,
        Err(e) => return Err(rec.fail(e)),
    };

    rec.push(
        RelayStage::Dns,
        json!({
            "addresses": target.addresses.iter().take(MAX_REPORTED_ADDRESSES)
                .map(|ip| ip.to_string()).collect::<Vec<_>>(),
            "pinnedAddress": target.pinned.ip().to_string(),
        }),
    );

    // ── 阶段 connect（隐式 TLS 时同时完成握手）──
    let timeout = Duration::from_secs(CONNECT_TIMEOUT_SECS);
    let implicit = endpoint.tls_mode == TlsMode::Implicit;

    let (mut session, banner) =
        match SmtpSession::connect(dialer, &target, endpoint.tls_mode, timeout).await {
            Ok(v) => v,
            Err(e) => return Err(rec.fail(e)),
        };
    rec.push(
        RelayStage::Connect,
        json!({ "code": banner.code, "banner": banner.banner() }),
    );

    // ── 阶段 tls ──
    if implicit {
        rec.push(RelayStage::Tls, json!({ "implicit": true }));
    } else {
        // STARTTLS：先 EHLO，确认服务端声明了 STARTTLS 再升级。
        match session.ehlo("mailstack").await {
            Ok(ehlo) if !ehlo.is_positive_completion() => {
                return Err(rec.fail(SmtpError::Rejected(ehlo.banner())))
            }
            Ok(_) => {}
            Err(e) => return Err(rec.fail(e)),
        }

        if !session.capabilities().starttls {
            // 服务端未声明 STARTTLS：强制 TLS 的中继策略下不得明文继续。
            return Err(rec.fail(SmtpError::TlsRequired));
        }

        let (upgraded, tls_response) = match session.starttls(dialer, &target).await {
            Ok(v) => v,
            Err(e) => return Err(rec.fail(e)),
        };
        session = upgraded;
        rec.push(RelayStage::Tls, json!({ "code": tls_response.code }));

        // STARTTLS 之后必须重新 EHLO（能力集已变化）。
        if let Err(e) = session.ehlo("mailstack").await {
            return Err(rec.fail(e));
        }
    }

    // ── 阶段 auth（无凭证则跳过）──
    if endpoint.has_credentials() {
        let auth = match session
            .authenticate(&endpoint.username, &endpoint.password)
            .await
        {
            Ok(response) => response,
            Err(e) => return Err(rec.fail(e)),
        };
        if !auth.is_positive_completion() {
            return Err(rec.fail(SmtpError::Rejected(auth.banner())));
        }
        rec.push(RelayStage::Auth, json!({}));
    } else {
        rec.push(RelayStage::Auth, json!({ "skipped": true }));
    }

    let _ = session.quit().await;
    Ok(rec.succeed(RelayStage::Auth))
}

/// 直投模式探测（§5.9.1、§5.10.2）。
///
/// 连本机 SMTP 固定端点，**仅 EHLO** —— 刻意不做 TLS，因为向导顺序中证书可能
/// 尚未签发。
///
/// **已知盲区（重写必须修）**：本探测只证明「本地 MTA 存活」，
/// **不证明出站 25 可用**（INV-19）。调用方不得把本结果当作直投可用性的判据；
/// 出站可用性必须由 [`crate::probe::probe_outbound_port`] 单独判定。
pub async fn run_direct_probe(
    dialer: &PinnedDialer,
    target: &PinnedTarget,
) -> Result<RelayTestResult, RelayTestFailure> {
    let mut rec = StageRecorder::new();

    rec.push(
        RelayStage::Dns,
        json!({
            "addresses": target.addresses.iter().take(MAX_REPORTED_ADDRESSES)
                .map(|ip| ip.to_string()).collect::<Vec<_>>(),
            "pinnedAddress": target.pinned.ip().to_string(),
            "localSubmission": true,
        }),
    );

    let timeout = Duration::from_secs(DIRECT_PROBE_TIMEOUT_SECS);
    let (mut session, banner) =
        match SmtpSession::connect(dialer, target, TlsMode::StartTls, timeout).await {
            Ok(v) => v,
            Err(e) => return Err(rec.fail(e)),
        };

    rec.push(
        RelayStage::Connect,
        json!({ "code": banner.code, "banner": banner.banner() }),
    );

    if let Err(e) = session.ehlo("mailstack").await {
        return Err(rec.fail(e));
    }
    let _ = session.quit().await;

    Ok(rec.succeed(RelayStage::Connect))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_stage(stage: RelayStage, detail: Value) -> StageOutcome {
        StageOutcome::new(stage, true, detail)
    }

    #[test]
    fn stage_json_shape_matches_the_contract() {
        let dns = ok_stage(
            RelayStage::Dns,
            json!({ "addresses": ["1.2.3.4"], "pinnedAddress": "1.2.3.4" }),
        );
        assert_eq!(
            dns.to_json(),
            json!({
                "stage": "dns", "ok": true,
                "addresses": ["1.2.3.4"], "pinnedAddress": "1.2.3.4"
            })
        );
    }

    #[test]
    fn failed_stage_carries_the_error_class_name() {
        let failed = StageOutcome::new(RelayStage::Failed, false, json!({ "message": "TlsError" }));
        let value = failed.to_json();
        assert_eq!(value["stage"], "failed");
        assert_eq!(value["ok"], false);
        assert_eq!(value["message"], "TlsError");
    }

    #[test]
    fn implicit_tls_stage_reports_the_implicit_flag_without_a_code() {
        let tls = ok_stage(RelayStage::Tls, json!({ "implicit": true })).to_json();
        assert_eq!(tls["implicit"], true);
        assert!(tls.get("code").is_none(), "隐式 TLS 没有 STARTTLS 响应码");
    }

    #[test]
    fn auth_skip_is_represented_explicitly_not_omitted() {
        // 无凭证时必须出现 auth 阶段且带 skipped 标记，而不是缺一个阶段
        // —— 否则前端会以为测试没跑完。
        let auth = ok_stage(RelayStage::Auth, json!({ "skipped": true })).to_json();
        assert_eq!(auth["skipped"], true);
        assert_eq!(auth["ok"], true);
    }

    #[test]
    fn success_json_has_the_documented_top_level_fields_and_stage_order() {
        let result = RelayTestResult {
            connected: true,
            stage: RelayStage::Auth,
            latency_ms: 123,
            stages: vec![
                ok_stage(RelayStage::Dns, json!({ "addresses": [] })),
                ok_stage(
                    RelayStage::Connect,
                    json!({ "code": 220, "banner": "ready" }),
                ),
                ok_stage(RelayStage::Tls, json!({ "implicit": true })),
                ok_stage(RelayStage::Auth, json!({ "skipped": true })),
            ],
        };
        let value = result.to_json();
        assert_eq!(value["connected"], true);
        assert_eq!(value["stage"], "auth");
        assert_eq!(value["latencyMs"], 123);

        let order: Vec<&str> = value["stages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["stage"].as_str().unwrap())
            .collect();
        assert_eq!(order, vec!["dns", "connect", "tls", "auth"]);
    }

    #[test]
    fn failure_json_preserves_completed_stages() {
        // 这是本模块存在的理由：失败也要能看出卡在哪一步。
        let failure = RelayTestFailure {
            error: SmtpError::Tls("handshake failed".into()),
            last_ok_stage: Some(RelayStage::Connect),
            latency_ms: 42,
            stages: vec![
                ok_stage(RelayStage::Dns, json!({ "addresses": ["1.2.3.4"] })),
                ok_stage(RelayStage::Connect, json!({ "code": 220 })),
                StageOutcome::new(RelayStage::Failed, false, json!({ "message": "TlsError" })),
            ],
        };
        let value = failure.to_json();

        assert_eq!(value["connected"], false);
        assert_eq!(value["stage"], "failed");
        assert_eq!(value["lastOkStage"], "connect");
        assert_eq!(value["error"]["code"], "TlsError");
        assert_eq!(
            value["stages"].as_array().unwrap().len(),
            3,
            "已完成阶段必须保留"
        );
        assert_eq!(value["stages"][2]["stage"], "failed");
    }

    #[test]
    fn validation_failure_reports_no_completed_stages() {
        let failure = RelayTestFailure {
            error: SmtpError::TlsRequired,
            last_ok_stage: None,
            latency_ms: 0,
            stages: vec![StageOutcome::new(
                RelayStage::Failed,
                false,
                json!({ "message": "TlsRequired" }),
            )],
        };
        let value = failure.to_json();
        assert!(value["lastOkStage"].is_null());
        assert_eq!(value["stages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn stage_lookup_finds_completed_stages_only() {
        let result = RelayTestResult {
            connected: true,
            stage: RelayStage::Auth,
            latency_ms: 5,
            stages: vec![
                ok_stage(RelayStage::Dns, json!({ "addresses": [] })),
                ok_stage(RelayStage::Auth, json!({ "skipped": true })),
            ],
        };
        assert!(result.stage(RelayStage::Dns).is_some());
        assert!(result.stage(RelayStage::Tls).is_none());
    }

    #[test]
    fn addresses_are_capped_at_eight() {
        // §5.9.4 明确规定最多 8 条。
        assert_eq!(MAX_REPORTED_ADDRESSES, 8);
    }

    fn dialer() -> PinnedDialer {
        PinnedDialer::with_roots(rustls::RootCertStore::empty(), Duration::from_secs(1))
    }

    fn request(host: &str, port: u16, tls: &str, user: &str, pass: &str) -> RelayValidationRequest {
        RelayValidationRequest {
            host: host.to_string(),
            port,
            tls_mode: tls.to_string(),
            username: user.to_string(),
            password: pass.to_string(),
            allow_private_network: false,
        }
    }

    #[tokio::test]
    async fn invalid_endpoint_fails_before_any_network_activity() {
        let err = run_relay_test(
            &dialer(),
            &request("bad host", 587, "STARTTLS", "", ""),
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err.error, SmtpError::InvalidEndpoint(_)));
        assert_eq!(err.stages.len(), 1, "只应有 failed 阶段");
        assert_eq!(err.last_ok_stage, None);
    }

    #[tokio::test]
    async fn plaintext_relay_is_rejected_before_connecting() {
        let err = run_relay_test(
            &dialer(),
            &request("smtp.sendgrid.net", 587, "none", "", ""),
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err.error, SmtpError::TlsRequired));
        assert_eq!(err.error.to_string(), "TLS is required for relay endpoint");
    }

    #[tokio::test]
    async fn private_relay_is_rejected_when_policy_is_off() {
        let mut req = request("smtp.sendgrid.net", 587, "STARTTLS", "", "");
        req.allow_private_network = true;
        let err = run_relay_test(&dialer(), &req, false).await.unwrap_err();
        assert!(matches!(err.error, SmtpError::PrivateRelayDisabled));
    }

    #[tokio::test]
    async fn incomplete_credentials_are_rejected_before_connecting() {
        let err = run_relay_test(
            &dialer(),
            &request("smtp.sendgrid.net", 587, "STARTTLS", "apikey", ""),
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err.error, SmtpError::IncompleteCredentials));
    }

    #[test]
    fn error_kinds_are_stable_class_names() {
        // 这些名字会出现在 Failed 阶段的 message 里，属于对外契约。
        assert_eq!(SmtpError::TlsRequired.kind(), "TlsRequired");
        assert_eq!(
            SmtpError::PrivateRelayDisabled.kind(),
            "PrivateRelayDisabled"
        );
        assert_eq!(
            SmtpError::IncompleteCredentials.kind(),
            "IncompleteCredentials"
        );
        assert_eq!(SmtpError::Dns("x".into()).kind(), "DnsError");
        assert_eq!(SmtpError::Tls("x".into()).kind(), "TlsError");
        assert_eq!(SmtpError::Protocol("x".into()).kind(), "ProtocolError");
        assert_eq!(SmtpError::Rejected("x".into()).kind(), "SmtpRejected");
        assert_eq!(
            SmtpError::NoAcceptableAddress("h".into()).kind(),
            "NoAcceptableAddress"
        );
    }
}

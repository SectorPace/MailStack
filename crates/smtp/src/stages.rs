use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::client::SmtpSession;
use crate::dial::{PinnedDialer, TlsMode};
use crate::error::SmtpError;
use crate::target::PinnedTarget;
use crate::validate::{address_policy_for, validate_relay, RelayValidationRequest};
use crate::{CONNECT_TIMEOUT_SECS, DIRECT_PROBE_TIMEOUT_SECS};

pub const MAX_REPORTED_ADDRESSES: usize = 8;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageOutcome {
    pub stage: RelayStage,
    pub ok: bool,
    pub detail: Value,
}

impl StageOutcome {
    pub fn new(stage: RelayStage, ok: bool, detail: Value) -> Self {
        Self { stage, ok, detail }
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTestResult {
    pub connected: bool,

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

    pub fn stage(&self, stage: RelayStage) -> Option<&StageOutcome> {
        self.stages.iter().find(|s| s.stage == stage)
    }
}

#[derive(Debug)]
pub struct RelayTestFailure {
    pub error: SmtpError,

    pub last_ok_stage: Option<RelayStage>,
    pub latency_ms: u64,
    pub stages: Vec<StageOutcome>,
}

impl RelayTestFailure {
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

pub async fn run_relay_test(
    dialer: &PinnedDialer,
    request: &RelayValidationRequest,
    private_network_enabled: bool,
) -> Result<RelayTestResult, RelayTestFailure> {
    let mut rec = StageRecorder::new();

    let endpoint = match validate_relay(request, private_network_enabled) {
        Ok(e) => e,
        Err(e) => return Err(rec.fail(e)),
    };

    let policy = address_policy_for(request, private_network_enabled);
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

    if implicit {
        rec.push(RelayStage::Tls, json!({ "implicit": true }));
    } else {
        match session.ehlo("mailstack").await {
            Ok(ehlo) if !ehlo.is_positive_completion() => {
                return Err(rec.fail(SmtpError::Rejected(ehlo.banner())))
            }
            Ok(_) => {}
            Err(e) => return Err(rec.fail(e)),
        }

        if !session.capabilities().starttls {
            return Err(rec.fail(SmtpError::TlsRequired));
        }

        let (upgraded, tls_response) = match session.starttls(dialer, &target).await {
            Ok(v) => v,
            Err(e) => return Err(rec.fail(e)),
        };
        session = upgraded;
        rec.push(RelayStage::Tls, json!({ "code": tls_response.code }));

        match session.ehlo("mailstack").await {
            Ok(ehlo) if !ehlo.is_positive_completion() => {
                return Err(rec.fail(SmtpError::Rejected(ehlo.banner())))
            }
            Ok(_) => {}
            Err(e) => return Err(rec.fail(e)),
        }
    }

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

    match session.ehlo("mailstack").await {
        Ok(ehlo) if !ehlo.is_positive_completion() => {
            return Err(rec.fail(SmtpError::Rejected(ehlo.banner())))
        }
        Ok(_) => {}
        Err(e) => return Err(rec.fail(e)),
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

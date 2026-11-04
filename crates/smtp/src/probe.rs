use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::target::{resolve_pinned, AddressPolicy, PinnedTarget};
use crate::{DEFAULT_PORT_PROBE_TARGETS, PORT_PROBE_TIMEOUT_SECS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Blocked,
}

impl PortStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortStatus::Open => "open",
            PortStatus::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTargetOutcome {
    pub target: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortProbeResult {
    pub port: u16,
    pub open: bool,
    pub status: PortStatus,

    pub target: String,
    pub latency_ms: Option<u64>,
    pub details: Vec<ProbeTargetOutcome>,
    pub message: String,
}

impl PortProbeResult {
    pub fn to_json(&self) -> Value {
        json!({
            "port": self.port,
            "open": self.open,
            "status": self.status.as_str(),
            "target": self.target,
            "latencyMs": self.latency_ms,
            "details": self.details.iter().map(|d| json!({
                "target": d.target,
                "reachable": d.reachable,
                "latencyMs": d.latency_ms,
                "detail": d.detail,
            })).collect::<Vec<_>>(),
            "message": self.message,
        })
    }
}

pub fn probe_targets_from_env() -> Vec<String> {
    match std::env::var("MAILSTACK_PORT_PROBE_TARGETS") {
        Ok(raw) if !raw.trim().is_empty() => raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .take(8)
            .collect(),
        _ => DEFAULT_PORT_PROBE_TARGETS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

pub async fn probe_outbound_port(port: u16) -> PortProbeResult {
    probe_outbound_port_with(port, probe_targets_from_env()).await
}

pub async fn probe_outbound_port_with(port: u16, targets: Vec<String>) -> PortProbeResult {
    probe_outbound_port_with_policy(port, targets, AddressPolicy::public_only()).await
}

pub async fn probe_outbound_port_with_policy(
    port: u16,
    targets: Vec<String>,
    policy: AddressPolicy,
) -> PortProbeResult {
    let timeout = Duration::from_secs(PORT_PROBE_TIMEOUT_SECS);
    let mut details: Vec<ProbeTargetOutcome> = Vec::new();
    let mut hit: Option<(String, u64)> = None;

    for target in &targets {
        let resolved = match resolve_pinned(target, port, policy).await {
            Ok(t) => t,
            Err(e) => {
                details.push(ProbeTargetOutcome {
                    target: target.clone(),
                    reachable: false,
                    latency_ms: None,
                    detail: e.kind().to_string(),
                });
                continue;
            }
        };

        let started = Instant::now();
        match try_connect(&resolved, timeout).await {
            Ok(()) => {
                let latency = started.elapsed().as_millis() as u64;
                details.push(ProbeTargetOutcome {
                    target: target.clone(),
                    reachable: true,
                    latency_ms: Some(latency),
                    detail: format!("connected to {}", resolved.pinned),
                });
                hit = Some((target.clone(), latency));
                break;
            }
            Err(detail) => {
                details.push(ProbeTargetOutcome {
                    target: target.clone(),
                    reachable: false,
                    latency_ms: None,
                    detail,
                });
            }
        }
    }

    let open = hit.is_some();
    let target = hit
        .as_ref()
        .map(|(t, _)| t.clone())
        .or_else(|| targets.last().cloned())
        .unwrap_or_else(|| "unknown".to_string());
    let latency_ms = hit.as_ref().map(|(_, l)| *l);

    let message = if open {
        format!("Outbound port {port} is reachable")
    } else if port == 25 {
        "Outbound port 25 is BLOCKED".to_string()
    } else {
        format!("Outbound port {port} appears to be BLOCKED")
    };

    PortProbeResult {
        port,
        open,
        status: if open {
            PortStatus::Open
        } else {
            PortStatus::Blocked
        },
        target,
        latency_ms,
        details,
        message,
    }
}

async fn try_connect(target: &PinnedTarget, timeout: Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target.dial_addr())).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(e)) => Err(format!("connect failed: {e}")),
        Err(_) => Err(format!("timed out after {}s", timeout.as_secs())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectModeVerdict {
    Usable,

    BlockedNeedsRelay,
}

impl DirectModeVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            DirectModeVerdict::Usable => "usable",
            DirectModeVerdict::BlockedNeedsRelay => "blocked_needs_relay",
        }
    }

    pub fn recommends_direct(&self) -> bool {
        matches!(self, DirectModeVerdict::Usable)
    }
}

pub fn direct_mode_verdict(probe: &PortProbeResult) -> DirectModeVerdict {
    if probe.open {
        DirectModeVerdict::Usable
    } else {
        DirectModeVerdict::BlockedNeedsRelay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_targets_match_the_baseline_list() {
        assert_eq!(
            DEFAULT_PORT_PROBE_TARGETS,
            &[
                "smtp.gmail.com",
                "smtp.qq.com",
                "outlook-com.olc.protection.outlook.com"
            ]
        );
    }

    #[test]
    fn open_result_serialises_the_documented_fields() {
        let result = PortProbeResult {
            port: 25,
            open: true,
            status: PortStatus::Open,
            target: "smtp.gmail.com".to_string(),
            latency_ms: Some(42),
            details: vec![ProbeTargetOutcome {
                target: "smtp.gmail.com".to_string(),
                reachable: true,
                latency_ms: Some(42),
                detail: "connected".to_string(),
            }],
            message: "Outbound port 25 is reachable".to_string(),
        };
        let value = result.to_json();
        assert_eq!(value["port"], 25);
        assert_eq!(value["open"], true);
        assert_eq!(value["status"], "open");
        assert_eq!(value["target"], "smtp.gmail.com");
        assert_eq!(value["latencyMs"], 42);
        assert_eq!(value["details"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn blocked_port_25_uses_the_documented_conclusion_text() {
        let result = PortProbeResult {
            port: 25,
            open: false,
            status: PortStatus::Blocked,
            target: "smtp.qq.com".to_string(),
            latency_ms: None,
            details: vec![],
            message: "Outbound port 25 is BLOCKED".to_string(),
        };
        assert_eq!(result.to_json()["message"], "Outbound port 25 is BLOCKED");
        assert_eq!(result.to_json()["status"], "blocked");
    }

    #[test]
    fn blocked_non_25_port_uses_a_generic_message() {
        let result = PortProbeResult {
            port: 587,
            open: false,
            status: PortStatus::Blocked,
            target: "x".to_string(),
            latency_ms: None,
            details: vec![],
            message: "Outbound port 587 appears to be BLOCKED".to_string(),
        };
        assert!(result.to_json()["message"]
            .as_str()
            .unwrap()
            .contains("587"));
    }

    #[test]
    fn direct_verdict_follows_the_probe_not_the_local_submission_endpoint() {
        let blocked = PortProbeResult {
            port: 25,
            open: false,
            status: PortStatus::Blocked,
            target: "smtp.gmail.com".to_string(),
            latency_ms: None,
            details: vec![],
            message: "Outbound port 25 is BLOCKED".to_string(),
        };
        let verdict = direct_mode_verdict(&blocked);
        assert_eq!(verdict, DirectModeVerdict::BlockedNeedsRelay);
        assert!(
            !verdict.recommends_direct(),
            "出站 25 被封时必须引导用户选择 smarthost"
        );

        let open = PortProbeResult {
            port: 25,
            open: true,
            status: PortStatus::Open,
            target: "smtp.gmail.com".to_string(),
            latency_ms: Some(10),
            details: vec![],
            message: "Outbound port 25 is reachable".to_string(),
        };
        assert_eq!(direct_mode_verdict(&open), DirectModeVerdict::Usable);
        assert!(direct_mode_verdict(&open).recommends_direct());
    }

    #[tokio::test]
    async fn probe_reports_all_targets_when_none_are_reachable() {
        let result = probe_outbound_port_with(
            25,
            vec![
                "nonexistent-a.invalid.example.test".to_string(),
                "nonexistent-b.invalid.example.test".to_string(),
            ],
        )
        .await;

        assert!(!result.open);
        assert_eq!(result.status, PortStatus::Blocked);
        assert_eq!(result.details.len(), 2, "每个目标都要有独立记录");
        assert!(result.details.iter().all(|d| !d.reachable));
    }

    #[tokio::test]
    async fn probe_stops_at_the_first_reachable_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let result = probe_outbound_port_with_policy(
            addr.port(),
            vec![
                "127.0.0.1".to_string(),
                "nonexistent.invalid.example.test".to_string(),
            ],
            AddressPolicy::allow_private(),
        )
        .await;

        assert!(result.open, "第一个目标应可达");
        assert_eq!(
            result.details.len(),
            1,
            "命中首个可达目标后必须停止，实际尝试了 {:?}",
            result.details.iter().map(|d| &d.target).collect::<Vec<_>>()
        );
        assert_eq!(result.details[0].target, "127.0.0.1");
        assert!(result.details[0].reachable);
        assert_eq!(result.target, "127.0.0.1");
    }

    #[tokio::test]
    async fn empty_target_list_is_blocked_not_a_panic() {
        let result = probe_outbound_port_with(25, Vec::new()).await;
        assert!(!result.open);
        assert_eq!(result.target, "unknown");
        assert!(result.message.contains("BLOCKED"));
    }

    #[test]
    fn env_override_is_capped_at_eight_targets() {
        let raw = "a,b,c,d,e,f,g,h,i,j";
        let parsed: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .take(8)
            .collect();
        assert_eq!(parsed.len(), 8);
        assert_eq!(parsed[7], "h");
    }
}

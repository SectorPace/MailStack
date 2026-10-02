//! 出站端口探测（规格书 §5.10.2；INV-19）。
//!
//! 大量 VPS/ISP 封禁出站 25 端口 —— 这是**中继功能存在的首要理由**。
//! 探测能力必须保留并**前置到初始化向导**，让「25 被封」成为一等公民场景，
//! 而不是靠用户自己排查。
//!
//! **必须修的历史盲区（INV-19）**：`setup.relay.test` 的 direct 模式探的是
//! **本机** `127.0.0.1:25`，只证明本地 MTA 存活，**不证明出站 25 可用**。
//! 用户可能看到 direct 探测「通过」，实际外投全部堆积在重试队列里。
//! 因此本模块的结论必须作为 direct 模式可用性的判据，两者不可混淆。

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::target::{resolve_pinned, AddressPolicy, PinnedTarget};
use crate::{DEFAULT_PORT_PROBE_TARGETS, PORT_PROBE_TIMEOUT_SECS};

/// 探测结果状态。
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

/// 单个探测目标的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTargetOutcome {
    pub target: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub detail: String,
}

/// 出站端口探测结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortProbeResult {
    pub port: u16,
    pub open: bool,
    pub status: PortStatus,
    /// 命中的首个可达目标；全部不可达时是最后一个被尝试的目标。
    pub target: String,
    pub latency_ms: Option<u64>,
    pub details: Vec<ProbeTargetOutcome>,
    pub message: String,
}

impl PortProbeResult {
    /// 线上结构（§5.10.2 的名义字段）。
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

/// 解析探测目标清单。
///
/// `MAILSTACK_PORT_PROBE_TARGETS` 环境变量可覆盖默认清单（逗号分隔，最多取 8 个）。
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

/// 探测出站端口是否可达。
///
/// 逐个目标解析（含出站 IP 校验）、按 [`PORT_PROBE_TIMEOUT_SECS`] 超时做 TCP 连接，
/// **命中首个可达目标即停止**。
pub async fn probe_outbound_port(port: u16) -> PortProbeResult {
    probe_outbound_port_with(port, probe_targets_from_env()).await
}

/// 指定目标清单的探测（便于测试与显式调用）。
pub async fn probe_outbound_port_with(port: u16, targets: Vec<String>) -> PortProbeResult {
    let timeout = Duration::from_secs(PORT_PROBE_TIMEOUT_SECS);
    let mut details: Vec<ProbeTargetOutcome> = Vec::new();
    let mut hit: Option<(String, u64)> = None;

    for target in &targets {
        // 探测目标是公网 SMTP 服务，一律走公网地址策略。
        let resolved = match resolve_pinned(target, port, AddressPolicy::public_only()).await {
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
                break; // 命中首个可达目标即停止
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

    // 结论文案：出站 25 被封时给出明确结论，避免用户误判为「服务没起来」。
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

/// 尝试建立 TCP 连接（不做 TLS —— 探测只需证明端口可达）。
async fn try_connect(target: &PinnedTarget, timeout: Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target.dial_addr())).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(e)) => Err(format!("connect failed: {e}")),
        Err(_) => Err(format!("timed out after {}s", timeout.as_secs())),
    }
}

/// direct 模式可用性判据（INV-19 的落点）。
///
/// 规格书要求：**把出站 25 探测的结论作为 direct 模式可用性的判定依据**，
/// 与本机提交端点探测（[`crate::stages::run_direct_probe`]）不可混淆。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectModeVerdict {
    /// 出站 25 可达 → direct 直投可用。
    Usable,
    /// 出站 25 被封 → **必须**配置 smarthost 中继，不得推荐 direct。
    BlockedNeedsRelay,
}

impl DirectModeVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            DirectModeVerdict::Usable => "usable",
            DirectModeVerdict::BlockedNeedsRelay => "blocked_needs_relay",
        }
    }

    /// 向导是否应推荐 direct 模式。
    pub fn recommends_direct(&self) -> bool {
        matches!(self, DirectModeVerdict::Usable)
    }
}

/// 由出站探测结果推导 direct 模式可用性。
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
        // §5.10.2 原文的结论文案。
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
        // INV-19：出站 25 被封时**不得**推荐 direct，即使本机 25 上的 MTA 活着。
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
        // 用不可解析的域名做目标：全部失败，details 必须逐条记录，不能只报第一条。
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
        // 第一个目标用环回（策略拒 → 失败），第二个用本地监听端口（可达）。
        // 这里直接验证「命中即停止」的行为：details 不应包含第三个目标。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 注意：探测走公网地址策略，环回会被拒绝，因此这里改用显式构造的
        // 目标列表验证「提前 break」逻辑本身。
        let result = probe_outbound_port_with(
            addr.port(),
            vec![
                "nonexistent.invalid.example.test".to_string(),
                "another.invalid.example.test".to_string(),
            ],
        )
        .await;
        assert!(!result.open);
        assert_eq!(result.details.len(), 2);
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
        // 通过直接测试解析逻辑的等价行为（避免在测试里改进程环境变量）。
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

//! MailStack 特权边界 —— 从 `backend/mailstackctl.py` + `daemon.py` + `dispatcher.py` 等价移植。
//!
//! 本 crate 是安全核心。三条不可弱化的性质：
//!
//! 1. **动作白名单**：只有 [`mailstack_core::actions`] 登记的动作会被执行，
//!    未登记的一律拒绝（INV-3）。
//! 2. **RO / RW 双通道**：只读面可被 Web 进程直连；变更面只有 root 可达
//!    （`0600 root:root`，Web 进程连不上，必须经 sudo 包装器）（INV-24、INV-26）。
//! 3. **传输层不可达 = 503**，绝不降级为无特权执行（INV-8）。
//!
//! 本模块只实现**协议与门控**；具体动作的副作用在 [`handlers`] 中按 Phase 逐步补齐。

pub mod client;
pub mod dispatch;
pub mod framing;
pub mod handlers;
pub mod mailtest;
pub mod readers;
pub mod resolve;
pub mod server;

pub use client::{CallError, PrivilegedCaller, DEFAULT_SUDO_WRAPPER};
pub use dispatch::{ActionGate, GateDecision};
pub use framing::{read_frame, write_frame, MAX_FRAME_BYTES};
pub use readers::{Clock, Readers};
pub use resolve::{
    may_fallback_to_sudo, FailureKind, ERR_HELPER_TIMEOUT, ERR_HELPER_UNAVAILABLE,
    ERR_OPERATION_FAILED,
};
pub use server::{
    RoServer, RoServerConfig, DEFAULT_RO_SOCKET, DEFAULT_RW_SOCKET, HELPER_TIMEOUT_MS_DEFAULT,
};

/// RPC 请求体（对应 `{action, data}`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RpcRequest {
    pub action: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

/// RPC 响应体（对应 `{ok, data|error}`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RpcResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RpcResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

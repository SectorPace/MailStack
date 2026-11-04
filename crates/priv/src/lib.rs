pub mod acme;
pub mod client;
pub mod dispatch;
pub mod framing;
pub mod handlers;
pub mod mailtest;
pub mod readers;
pub mod resolve;
pub mod server;
pub mod users;

pub use acme::{Acme, AcmeProbes};
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
pub use users::{Users, UsersEnv};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RpcRequest {
    pub action: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

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

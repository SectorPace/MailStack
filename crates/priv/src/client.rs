use std::path::PathBuf;
use std::time::Duration;

use mailstack_core::actions::{self, Channel};
use serde_json::Value;

use crate::resolve::{
    may_fallback_to_sudo, FailureKind, ERR_HELPER_TIMEOUT, ERR_HELPER_UNAVAILABLE,
    ERR_OPERATION_FAILED,
};
use crate::server::HELPER_TIMEOUT_MS_DEFAULT;
use crate::{RpcRequest, RpcResponse};

pub const DEFAULT_SUDO_WRAPPER: &str = "/usr/local/libexec/mailstack-privileged";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallError {
    pub kind: FailureKind,
    pub code: &'static str,
    pub message: String,
}

impl CallError {
    fn new(kind: FailureKind, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            code,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(
            FailureKind::TransportUnavailable,
            ERR_HELPER_UNAVAILABLE,
            message,
        )
    }

    fn business(message: impl Into<String>) -> Self {
        Self::new(FailureKind::BusinessError, ERR_OPERATION_FAILED, message)
    }

    fn mid_timeout(message: impl Into<String>) -> Self {
        Self::new(
            FailureKind::MidOperationTimeout,
            ERR_HELPER_TIMEOUT,
            message,
        )
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CallError {}

async fn kill_and_reap(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[derive(Debug, Clone)]
pub struct PrivilegedCaller {
    pub ro_socket: PathBuf,

    pub sudo_wrapper: PathBuf,
    pub timeout: Duration,

    pub public_mode: bool,
}

impl PrivilegedCaller {
    pub fn new(public_mode: bool) -> Self {
        Self {
            ro_socket: std::env::var("MAILSTACK_HELPER_RO_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(crate::DEFAULT_RO_SOCKET)),
            sudo_wrapper: PathBuf::from(DEFAULT_SUDO_WRAPPER),
            timeout: std::env::var("MAILSTACK_HELPER_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .map(Duration::from_millis)
                .unwrap_or_else(|| Duration::from_millis(HELPER_TIMEOUT_MS_DEFAULT)),
            public_mode,
        }
    }

    pub fn channel_for(action: &str) -> Channel {
        actions::classify(action)
    }

    pub async fn call(&self, action: &str, data: &Value) -> Result<Value, CallError> {
        match Self::channel_for(action) {
            Channel::Rw => self.call_via_sudo(action, data).await,
            Channel::Ro => self.call_read_only(action, data).await,
        }
    }

    async fn call_read_only(&self, action: &str, data: &Value) -> Result<Value, CallError> {
        match self.call_via_socket(action, data).await {
            Ok(value) => Ok(value),
            Err(error) => {
                if may_fallback_to_sudo(error.kind, self.public_mode) {
                    self.call_via_sudo(action, data).await
                } else {
                    Err(error)
                }
            }
        }
    }

    #[cfg(unix)]
    async fn call_via_socket(&self, action: &str, data: &Value) -> Result<Value, CallError> {
        use tokio::net::UnixStream;

        let stream =
            match tokio::time::timeout(self.timeout, UnixStream::connect(&self.ro_socket)).await {
                Ok(Ok(stream)) => stream,

                Ok(Err(error)) => {
                    return Err(CallError::unavailable(format!(
                        "privileged helper unreachable at {}: {error}",
                        self.ro_socket.display()
                    )))
                }
                Err(_) => {
                    return Err(CallError::unavailable(
                        "connecting to the privileged helper timed out",
                    ))
                }
            };

        self.exchange(stream, action, data).await
    }

    #[cfg(not(unix))]
    async fn call_via_socket(&self, _action: &str, _data: &Value) -> Result<Value, CallError> {
        Err(CallError::unavailable(
            "Unix domain sockets are only available on Unix targets",
        ))
    }

    #[cfg(unix)]
    async fn exchange(
        &self,
        mut stream: tokio::net::UnixStream,
        action: &str,
        data: &Value,
    ) -> Result<Value, CallError> {
        let request = RpcRequest {
            action: action.to_string(),
            data: data.clone(),
        };

        let exchange = async {
            crate::framing::write_json_frame(&mut stream, &request)
                .await
                .map_err(|error| error.to_string())?;
            let response: RpcResponse = crate::framing::read_json_frame(&mut stream)
                .await
                .map_err(|error| error.to_string())?;
            Ok::<RpcResponse, String>(response)
        };

        match tokio::time::timeout(self.timeout, exchange).await {
            Ok(Ok(response)) => {
                if response.ok {
                    Ok(response.data.unwrap_or(Value::Null))
                } else {
                    Err(CallError::business(response.error.unwrap_or_else(|| {
                        "privileged operation failed".to_string()
                    })))
                }
            }
            Ok(Err(message)) => Err(CallError::business(message)),

            Err(_) => Err(CallError::mid_timeout(
                "privileged operation timed out mid-flight",
            )),
        }
    }

    async fn call_via_sudo(&self, action: &str, data: &Value) -> Result<Value, CallError> {
        let request = serde_json::json!({ "action": action, "data": data });
        let payload =
            serde_json::to_vec(&request).map_err(|error| CallError::business(error.to_string()))?;

        let mut child = tokio::process::Command::new("sudo")
            .arg(&self.sudo_wrapper)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                CallError::unavailable(format!(
                    "cannot spawn {}: {error}",
                    self.sudo_wrapper.display()
                ))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let write = tokio::time::timeout(self.timeout, stdin.write_all(&payload)).await;
            match write {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    kill_and_reap(&mut child).await;
                    return Err(CallError::business(format!(
                        "writing request to privileged helper failed: {error}"
                    )));
                }
                Err(_) => {
                    kill_and_reap(&mut child).await;
                    return Err(CallError::mid_timeout(
                        "writing request to the privileged helper timed out",
                    ));
                }
            }

            drop(stdin);
        }

        let output = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                return Err(CallError::business(format!(
                    "privileged helper failed: {error}"
                )))
            }
            Err(_) => {
                return Err(CallError::mid_timeout(
                    "privileged helper timed out mid-flight",
                ));
            }
        };

        if !output.status.success() {
            return Err(CallError::business(format!(
                "privileged helper exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        if output.stdout.len() > crate::MAX_FRAME_BYTES as usize {
            return Err(CallError::business(
                "privileged helper response exceeded the 16 MB limit",
            ));
        }

        let response: RpcResponse = serde_json::from_slice(&output.stdout).map_err(|error| {
            CallError::business(format!(
                "privileged helper returned malformed JSON: {error}"
            ))
        })?;

        if response.ok {
            Ok(response.data.unwrap_or(Value::Null))
        } else {
            Err(CallError::business(response.error.unwrap_or_else(|| {
                "privileged operation failed".to_string()
            })))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_only_actions_are_routed_to_the_ro_channel() {
        assert_eq!(PrivilegedCaller::channel_for("domains.list"), Channel::Ro);
        assert_eq!(PrivilegedCaller::channel_for("snapshot"), Channel::Ro);
    }

    #[test]
    fn mutating_actions_are_routed_to_sudo() {
        assert_eq!(PrivilegedCaller::channel_for("domains.add"), Channel::Rw);
        assert_eq!(PrivilegedCaller::channel_for("admin.set"), Channel::Rw);
        assert_eq!(PrivilegedCaller::channel_for("settings.set"), Channel::Rw);
    }

    #[test]
    fn unknown_actions_default_to_the_read_only_channel() {
        assert_eq!(
            PrivilegedCaller::channel_for("totally.unknown"),
            Channel::Ro
        );
        assert_eq!(PrivilegedCaller::channel_for(""), Channel::Ro);
    }

    #[test]
    fn every_destructive_action_goes_through_sudo() {
        for action in mailstack_core::actions::DESTRUCTIVE_ACTIONS {
            assert_eq!(
                PrivilegedCaller::channel_for(action),
                Channel::Rw,
                "{action} 必须走变更面"
            );
        }
    }

    #[test]
    fn channel_derivation_uses_the_core_allowlist_as_single_source_of_truth() {
        for action in mailstack_core::actions::ALLOWED_ACTIONS_RW {
            assert_eq!(PrivilegedCaller::channel_for(action), Channel::Rw);
        }
        for action in mailstack_core::actions::ALLOWED_ACTIONS_RO {
            assert_eq!(PrivilegedCaller::channel_for(action), Channel::Ro);
        }
    }

    #[tokio::test]
    async fn an_unreachable_socket_is_classified_as_a_transport_failure() {
        let mut caller = PrivilegedCaller::new(false);
        caller.ro_socket = PathBuf::from("/nonexistent/mailstack/helper-ro.sock");

        let error = caller
            .call_via_socket("domains.list", &json!({}))
            .await
            .expect_err("socket 不存在时必须失败");
        assert_eq!(error.kind, FailureKind::TransportUnavailable);
        assert_eq!(error.code, ERR_HELPER_UNAVAILABLE);
    }

    #[test]
    fn public_mode_refuses_to_fall_back_even_when_the_socket_is_unreachable() {
        let mut caller = PrivilegedCaller::new(true);
        caller.ro_socket = PathBuf::from("/nonexistent/mailstack/helper-ro.sock");
        assert!(!may_fallback_to_sudo(
            FailureKind::TransportUnavailable,
            caller.public_mode
        ));
    }
}

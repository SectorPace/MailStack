//! 特权调用客户端：把「一个动作」翻译成对只读 socket 或 `sudo` 包装器的调用。
//!
//! ## 为什么它在 `crates/priv` 而不是 `crates/web`
//!
//! 它用的是**特权协议**（帧格式 + 通道语义），并实现**特权通道的失败策略**
//! （INV-25 / INV-26）—— 与协议本身同源。管理 API 与 `mailstackctl`
//! 都要用它；把实现留在 `crates/web` 里，第二个调用方（CLI）就只能复制一份，
//! 而「复制一份特权判定」正是这个项目一直在避免的事。
//!
//! ## 通道推导只有一份实现
//!
//! [`PrivilegedCaller::channel_for`] 直接委托 [`mailstack_core::actions::classify`]。
//! 未知动作**默认走只读面**（静默提权防护，INV-24），因此这条规则不可能在某个
//! 调用方手里被写成别的样子。
//!
//! ## fallback 规则
//!
//! 逐条见 [`crate::resolve`] 的模块说明。判定函数 [`may_fallback_to_sudo`] 在
//! **本模块被唯一调用** —— 调用方只消费 [`CallError::kind`]，不必自己判断。

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

/// `sudo` 包装器的默认路径（变更面唯一入口）。
pub const DEFAULT_SUDO_WRAPPER: &str = "/usr/local/libexec/mailstack-privileged";

/// 一次特权调用的失败。
///
/// 带上 [`FailureKind`] 而不是只给文案：调用方据此决定能否回退，**不必**去匹配
/// 错误字符串 —— 文案是给人看的，判定必须基于类型。
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

    /// 传输层不可达（daemon 未起、socket 不存在、连接被拒、连接超时）。
    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(
            FailureKind::TransportUnavailable,
            ERR_HELPER_UNAVAILABLE,
            message,
        )
    }

    /// 业务错误（动作执行了但失败，或应答无法解析）。**不得**回退、**不得**重试。
    fn business(message: impl Into<String>) -> Self {
        Self::new(FailureKind::BusinessError, ERR_OPERATION_FAILED, message)
    }

    /// 操作中途超时：请求可能已被执行。**不得**回退、**不得**重试。
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

/// 显式杀掉 sudo 子进程并等待退出（尽力而为）。
///
/// `kill_on_drop` 只覆盖「Child 被 drop」的路径；stdin 写入失败时 child 仍在
/// 我们手里，必须 start_kill + wait，否则一个卡住的 root 子进程会一直活着。
async fn kill_and_reap(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// 特权调用客户端。
#[derive(Debug, Clone)]
pub struct PrivilegedCaller {
    /// 只读面 socket（`MAILSTACK_HELPER_RO_SOCKET`）。
    pub ro_socket: PathBuf,
    /// `sudo` 包装器路径。
    pub sudo_wrapper: PathBuf,
    pub timeout: Duration,
    /// 公网模式：只读面**不得**回退到 sudo（INV-26）。
    pub public_mode: bool,
}

impl PrivilegedCaller {
    /// 从环境变量装配（与基线同名同义）。
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

    /// 推导某动作应走的通道。
    ///
    /// **未知 action 默认走只读面**（静默提权防护，INV-24）。
    pub fn channel_for(action: &str) -> Channel {
        actions::classify(action)
    }

    /// 按动作推导通道后调用。
    pub async fn call(&self, action: &str, data: &Value) -> Result<Value, CallError> {
        match Self::channel_for(action) {
            // RW 恒走 sudo：变更面 socket 是 0600 root:root，本进程连不上也不该连。
            Channel::Rw => self.call_via_sudo(action, data).await,
            Channel::Ro => self.call_read_only(action, data).await,
        }
    }

    /// 只读调用：先 socket；仅在**传输层**失败且判定允许时才回退到 sudo。
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

    /// 经只读 socket 调用。
    #[cfg(unix)]
    async fn call_via_socket(&self, action: &str, data: &Value) -> Result<Value, CallError> {
        use tokio::net::UnixStream;

        let stream =
            match tokio::time::timeout(self.timeout, UnixStream::connect(&self.ro_socket)).await {
                Ok(Ok(stream)) => stream,
                // 连接失败 = 传输层不可达 → 可能允许回退。
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

    /// 在一次已建立的连接上完成请求/响应交换。
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
                    // 业务错误：**不得** fallback、**不得**重试（INV-25）。
                    Err(CallError::business(response.error.unwrap_or_else(|| {
                        "privileged operation failed".to_string()
                    })))
                }
            }
            Ok(Err(message)) => Err(CallError::business(message)),
            // 操作中途超时：请求可能已执行，**不得**重试（INV-25）。
            Err(_) => Err(CallError::mid_timeout(
                "privileged operation timed out mid-flight",
            )),
        }
    }

    /// 经 `sudo` 包装器调用变更面。
    async fn call_via_sudo(&self, action: &str, data: &Value) -> Result<Value, CallError> {
        let request = serde_json::json!({ "action": action, "data": data });
        let payload =
            serde_json::to_vec(&request).map_err(|error| CallError::business(error.to_string()))?;

        let mut child = tokio::process::Command::new("sudo")
            .arg(&self.sudo_wrapper)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // 兜底：future 被丢弃的所有路径（客户端取消、wait 超时）都会连带
            // drop 掉 Child —— 显式 kill 覆盖不到的那些路径由它收尾。
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                CallError::unavailable(format!(
                    "cannot spawn {}: {error}",
                    self.sudo_wrapper.display()
                ))
            })?;

        // 写 stdin 必须有自己的超时：包装器卡在读请求上时不能把调用方钉死。
        // 失败 / 超时路径必须**显式**杀掉子进程并等待退出 —— 一个卡住的
        // sudo 子进程是 root 进程泄漏（kill_on_drop 只兜 future 被 drop 的路）。
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
            // 写完必须 drop 句柄，否则子进程会一直等 EOF。
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
                // 超时路径拿不回 Child（已被 future 持有并随超时 drop），
                // kill_on_drop(true) 负责在这里把 root 子进程杀掉。
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

        // 响应上限 16 MB。
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
        // INV-24：未知动作绝不能默认走变更面。
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
        // 只测 **socket 路径的分类**，刻意不经过 `call_read_only` 的 fallback：
        // 本机可能恰好装着真实的 `mailstack-privileged` 包装器（开发用 WSL 上就有
        // 一个，是早先安装留下的），那样 fallback 会「成功」，断言就假失败了。
        // 断言的是**分类结果**而不是文案 —— 文案会变，分类是契约。
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
        // INV-26：公网模式下只读面不可达就是 503，绝不改用 sudo。
        let mut caller = PrivilegedCaller::new(true);
        caller.ro_socket = PathBuf::from("/nonexistent/mailstack/helper-ro.sock");
        assert!(!may_fallback_to_sudo(
            FailureKind::TransportUnavailable,
            caller.public_mode
        ));
    }
}

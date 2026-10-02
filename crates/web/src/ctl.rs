//! 特权通道调用（规格书 §5.4.2 的 `ctl()`）。
//!
//! ```text
//! RO action  → 直连 /run/mailstack/helper-ro.sock（0660 root:mailstack-admin）
//! RW action  → sudo /usr/local/libexec/mailstack-privileged
//!              （helper.sock 是 0600 root:root，本进程连不上）
//! ```
//!
//! ## 本模块只剩「把失败翻译成 HTTP」
//!
//! 通道推导、socket/`sudo` 两条路径、以及 fallback 规则（INV-25 / INV-26）都在
//! [`mailstack_priv::PrivilegedCaller`] 里 —— 那是它与协议同源的地方，`mailstackctl`
//! 也用同一份实现。这里唯一要做的是把 [`CallError`] 映射成正确的 **HTTP 状态码**。
//!
//! **这一步不能省**：若统一按 400 返回，助手不可达就与「你的请求有问题」混淆了，
//! 而 INV-8 要求前者是 **503** —— 前端与监控靠状态码区分这两种情况。

use std::path::PathBuf;
use std::time::Duration;

use mailstack_core::actions::Channel;
use mailstack_priv::{CallError, PrivilegedCaller};

use crate::error::ApiError;

/// 助手调用超时默认值（毫秒）。
pub const HELPER_TIMEOUT_MS_DEFAULT: u64 = mailstack_priv::server::HELPER_TIMEOUT_MS_DEFAULT;

/// 特权调用客户端。
#[derive(Debug, Clone)]
pub struct PrivilegedClient {
    caller: PrivilegedCaller,
}

impl PrivilegedClient {
    pub fn new(public_mode: bool) -> Self {
        Self {
            caller: PrivilegedCaller::new(public_mode),
        }
    }

    /// 只读面 socket 路径（测试与排障用）。
    pub fn ro_socket(&self) -> &PathBuf {
        &self.caller.ro_socket
    }

    /// `sudo` 包装器路径。
    pub fn sudo_wrapper(&self) -> &PathBuf {
        &self.caller.sudo_wrapper
    }

    pub fn timeout(&self) -> Duration {
        self.caller.timeout
    }

    pub fn public_mode(&self) -> bool {
        self.caller.public_mode
    }

    /// 覆盖只读面 socket 路径（测试用；生产走环境变量）。
    pub fn with_ro_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.caller.ro_socket = path.into();
        self
    }

    /// 推导某动作应走的通道。
    ///
    /// **未知 action 默认走只读面**（静默提权防护，INV-24）。
    pub fn channel_for(action: &str) -> Channel {
        PrivilegedCaller::channel_for(action)
    }

    /// 按动作推导通道后调用。
    pub async fn call(
        &self,
        action: &str,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.caller.call(action, data).await.map_err(api_error_for)
    }
}

/// 把助手侧的失败映射为正确的 HTTP 状态。
///
/// 分类依据是 [`CallError::kind`]（类型），**不是**错误文案 —— 文案会变，分类是契约。
fn api_error_for(error: CallError) -> ApiError {
    use axum::http::StatusCode;
    use mailstack_priv::FailureKind;

    match error.kind {
        // INV-8：传输层不可达 ⇒ 503，绝不降级为无特权执行。
        FailureKind::TransportUnavailable => ApiError::helper_unavailable(error.message),
        // 中途超时：请求可能已执行 ⇒ 504，且调用方**不得**重试（INV-25）。
        FailureKind::MidOperationTimeout => ApiError::with_status(
            ApiError::new(error.code, error.message),
            StatusCode::GATEWAY_TIMEOUT,
        ),
        // 业务错误 ⇒ 500（不是客户端的错）。
        FailureKind::BusinessError => ApiError::with_status(
            ApiError::new(error.code, error.message),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use mailstack_priv::FailureKind;

    use crate::ratelimit::{ERR_PRIVILEGED_HELPER_UNAVAILABLE, ERR_PRIVILEGED_OPERATION_FAILED};

    #[test]
    fn read_only_actions_are_routed_to_the_ro_channel() {
        assert_eq!(PrivilegedClient::channel_for("domains.list"), Channel::Ro);
        assert_eq!(PrivilegedClient::channel_for("snapshot"), Channel::Ro);
    }

    #[test]
    fn mutating_actions_are_routed_to_sudo() {
        // RW 恒走 sudo：helper.sock 是 0600，本进程连不上。
        assert_eq!(PrivilegedClient::channel_for("domains.add"), Channel::Rw);
        assert_eq!(PrivilegedClient::channel_for("admin.set"), Channel::Rw);
        assert_eq!(PrivilegedClient::channel_for("settings.set"), Channel::Rw);
    }

    #[test]
    fn unknown_actions_default_to_the_read_only_channel() {
        // INV-24 静默提权防护：未知动作绝不能默认走变更面。
        assert_eq!(
            PrivilegedClient::channel_for("totally.unknown"),
            Channel::Ro
        );
        assert_eq!(PrivilegedClient::channel_for(""), Channel::Ro);
    }

    #[test]
    fn every_destructive_action_goes_through_sudo() {
        for action in mailstack_core::actions::DESTRUCTIVE_ACTIONS {
            assert_eq!(
                PrivilegedClient::channel_for(action),
                Channel::Rw,
                "{action} 必须走变更面"
            );
        }
    }

    #[test]
    fn channel_derivation_uses_the_core_allowlist_as_single_source_of_truth() {
        // 规格书要求 RW_ACTIONS 与 ALLOWED_ACTIONS_RW 逐项一致。
        // Rust 侧两侧共用 mailstack-core，故此断言保证没有任何动作被漏判。
        for action in mailstack_core::actions::ALLOWED_ACTIONS_RW {
            assert_eq!(PrivilegedClient::channel_for(action), Channel::Rw);
        }
        for action in mailstack_core::actions::ALLOWED_ACTIONS_RO {
            assert_eq!(PrivilegedClient::channel_for(action), Channel::Ro);
        }
    }

    #[test]
    fn default_timeout_matches_baseline() {
        assert_eq!(HELPER_TIMEOUT_MS_DEFAULT, 120_000);
    }

    #[test]
    fn public_mode_client_still_routes_ro_to_the_socket_first() {
        // 公网模式下 RO 仍先走 socket；只是不允许 fallback（由 may_fallback_to_sudo 判定）。
        let client = PrivilegedClient::new(true);
        assert!(client.public_mode());
        assert_eq!(PrivilegedClient::channel_for("logs.list"), Channel::Ro);
        assert!(!mailstack_priv::may_fallback_to_sudo(
            FailureKind::TransportUnavailable,
            true
        ));
    }

    #[test]
    fn every_failure_kind_maps_to_a_distinguishable_status() {
        // 三种失败必须给出三个不同的状态码，否则监控无法区分「助手没了」与「动作失败」。
        let error = |kind, code: &'static str| CallError {
            kind,
            code,
            message: "x".into(),
        };

        assert_eq!(
            api_error_for(error(
                FailureKind::TransportUnavailable,
                ERR_PRIVILEGED_HELPER_UNAVAILABLE
            ))
            .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            api_error_for(error(
                FailureKind::MidOperationTimeout,
                mailstack_priv::ERR_HELPER_TIMEOUT
            ))
            .status,
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            api_error_for(error(
                FailureKind::BusinessError,
                ERR_PRIVILEGED_OPERATION_FAILED
            ))
            .status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}

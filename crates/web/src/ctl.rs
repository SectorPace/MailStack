use std::path::PathBuf;
use std::time::Duration;

use mailstack_core::actions::Channel;
use mailstack_priv::{CallError, PrivilegedCaller};

use crate::error::ApiError;

pub const HELPER_TIMEOUT_MS_DEFAULT: u64 = mailstack_priv::server::HELPER_TIMEOUT_MS_DEFAULT;

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

    pub fn ro_socket(&self) -> &PathBuf {
        &self.caller.ro_socket
    }

    pub fn sudo_wrapper(&self) -> &PathBuf {
        &self.caller.sudo_wrapper
    }

    pub fn timeout(&self) -> Duration {
        self.caller.timeout
    }

    pub fn public_mode(&self) -> bool {
        self.caller.public_mode
    }

    pub fn with_ro_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.caller.ro_socket = path.into();
        self
    }

    pub fn channel_for(action: &str) -> Channel {
        PrivilegedCaller::channel_for(action)
    }

    pub async fn call(
        &self,
        action: &str,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.caller.call(action, data).await.map_err(api_error_for)
    }
}

fn api_error_for(error: CallError) -> ApiError {
    use axum::http::StatusCode;
    use mailstack_priv::FailureKind;

    match error.kind {
        FailureKind::TransportUnavailable => ApiError::helper_unavailable(error.message),

        FailureKind::MidOperationTimeout => ApiError::with_status(
            ApiError::new(error.code, error.message),
            StatusCode::GATEWAY_TIMEOUT,
        ),

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
        assert_eq!(PrivilegedClient::channel_for("domains.add"), Channel::Rw);
        assert_eq!(PrivilegedClient::channel_for("admin.set"), Channel::Rw);
        assert_eq!(PrivilegedClient::channel_for("settings.set"), Channel::Rw);
    }

    #[test]
    fn unknown_actions_default_to_the_read_only_channel() {
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

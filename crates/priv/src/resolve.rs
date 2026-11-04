#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    TransportUnavailable,

    BusinessError,

    MidOperationTimeout,
}

pub fn may_fallback_to_sudo(failure: FailureKind, public_mode: bool) -> bool {
    match failure {
        FailureKind::TransportUnavailable => !public_mode,

        FailureKind::BusinessError | FailureKind::MidOperationTimeout => false,
    }
}

pub const ERR_HELPER_UNAVAILABLE: &str = "PRIVILEGED_HELPER_UNAVAILABLE";

pub const ERR_HELPER_TIMEOUT: &str = "PRIVILEGED_HELPER_TIMEOUT";

pub const ERR_OPERATION_FAILED: &str = "PRIVILEGED_OPERATION_FAILED";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_failure_may_fallback_in_local_mode() {
        assert!(may_fallback_to_sudo(
            FailureKind::TransportUnavailable,
            false
        ));
    }

    #[test]
    fn transport_failure_must_not_fallback_in_public_mode() {
        assert!(!may_fallback_to_sudo(
            FailureKind::TransportUnavailable,
            true
        ));
    }

    #[test]
    fn business_error_never_falls_back() {
        assert!(!may_fallback_to_sudo(FailureKind::BusinessError, false));
        assert!(!may_fallback_to_sudo(FailureKind::BusinessError, true));
    }

    #[test]
    fn mid_operation_timeout_never_falls_back() {
        assert!(!may_fallback_to_sudo(
            FailureKind::MidOperationTimeout,
            false
        ));
        assert!(!may_fallback_to_sudo(
            FailureKind::MidOperationTimeout,
            true
        ));
    }
}

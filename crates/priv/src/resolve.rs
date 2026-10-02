//! 调用通道解析（规格书 §5.4.2 的 fallback 规则）。
//!
//! **fallback 规则极精细，必须逐条保留**：
//!
//! | 情形 | 行为 |
//! |---|---|
//! | RO 走 socket 时**传输层**失败（daemon 未起 / socket 不存在） | 允许 fallback 到一次性 sudo 路径 |
//! | RO 走 socket 时**业务错误**或**操作中途超时** | **不得** fallback、**不得**重试 |
//! | `PUBLIC_MODE` 下的 RO 动作 | **不得** fallback 到 sudo，直接以 503 失败 |
//! | 任何 RW 动作 | 从不尝试 socket，恒走 sudo |
//!
//! 「业务错误不得重试」的理由（原文）："retrying a half-finished ACME issuance or
//! a backup restore would execute it twice"。

/// 失败性质：决定是否允许 fallback。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// 传输层失败：daemon 未起、socket 不存在、连接被拒。
    /// 这类失败**可以** fallback 到 sudo 路径。
    TransportUnavailable,
    /// 业务错误：动作执行了但失败了。
    /// **不得** fallback、**不得**重试（可能造成重复执行）。
    BusinessError,
    /// 操作中途超时：请求可能已被执行。
    /// **不得** fallback、**不得**重试。
    MidOperationTimeout,
}

/// 是否允许回退到一次性 sudo 路径。
pub fn may_fallback_to_sudo(failure: FailureKind, public_mode: bool) -> bool {
    match failure {
        // 传输层失败可以回退——但对公网模式例外：RO socket 是唯一的特权读通道。
        FailureKind::TransportUnavailable => !public_mode,
        // 业务错误与中途超时一律不得回退（INV-25）。
        FailureKind::BusinessError | FailureKind::MidOperationTimeout => false,
    }
}

/// 传输层失败对应的对外错误码（INV-8：不得降级为无特权执行）。
pub const ERR_HELPER_UNAVAILABLE: &str = "PRIVILEGED_HELPER_UNAVAILABLE";
/// 超时错误码。
pub const ERR_HELPER_TIMEOUT: &str = "PRIVILEGED_HELPER_TIMEOUT";
/// 特权操作失败错误码（含响应超限）。
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
        // INV-26：公网模式下 RO socket 是唯一的特权读通道。
        assert!(!may_fallback_to_sudo(
            FailureKind::TransportUnavailable,
            true
        ));
    }

    #[test]
    fn business_error_never_falls_back() {
        // INV-25：二次签发 ACME 证书或二次恢复备份会重复执行。
        assert!(!may_fallback_to_sudo(FailureKind::BusinessError, false));
        assert!(!may_fallback_to_sudo(FailureKind::BusinessError, true));
    }

    #[test]
    fn mid_operation_timeout_never_falls_back() {
        // 这是最隐蔽的一条：请求可能已经执行，重试即重复执行。
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

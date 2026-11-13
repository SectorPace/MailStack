pub mod backoff;
pub mod delivery;
pub mod dsn;
pub mod entry;
pub mod error;
pub mod runner;
pub mod signing;
pub mod store;

pub use backoff::BackoffPolicy;
pub use delivery::{
    classify_code, classify_response, classify_smtp_error, DeliveryFailure, DeliveryFuture,
    DeliveryReceipt, DeliveryTarget, FailureClass, SmtpRemoteTransport, Transport,
};
pub use dsn::{build_dsn, dsn_envelope_from, dsn_recipient, DsnRequest};
pub use entry::{EntryKind, QueueEntry};
pub use error::{QueueError, QueueResult};
pub use runner::{
    outbound_health_from, OutboundHealth, QueueConfig, QueueMetrics, QueueRunReport, QueueRunner,
    DEFAULT_BLOCKED_THRESHOLD,
};
pub use signing::{
    DkimSigner, MessageSigner, SigningOutcome, SigningTransport, SIGNING_FAILURE_KIND,
};
pub use store::{LatencySample, OutboundHealthState, QueueStore, TrafficMetrics};

pub use mailstack_smtp::OutboundRoute;

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_unix_is_a_plausible_wall_clock() {
        let now = now_unix();
        assert!(now > 1_577_836_800, "时钟基准异常：{now}");
        assert!(now < 4_102_444_800, "时钟基准异常：{now}");
    }
}

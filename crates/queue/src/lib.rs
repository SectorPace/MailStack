//! MailStack 出站队列（规格书 §5.8；INV-18、INV-21；风险表「投递可靠性」）。
//!
//! 队列是 Postfix 移除后最容易「看起来能跑、实际不可靠」的一环（规格书把
//! 「队列原子性 / 重试风暴 / 退信语义」列为高风险）。因此这里把三个风险点
//! 各自固化成一个可测试的性质：
//!
//! | 风险 | 落点 | 不变量测试 |
//! |---|---|---|
//! | 队列原子性 | [`store`]（fsync + 同目录 rename） | `queue_writes_are_atomic_and_leave_no_partial_files`、`queue_survives_restart_without_losing_entries` |
//! | 重试风暴 | [`backoff`]（指数退避 + 按 id 抖动）、[`runner`]（快速失败 + 半开探测） | `different_entries_do_not_retry_in_lockstep`、`blocked_queue_fast_fails_instead_of_hammering` |
//! | 退信语义 | [`dsn`]（RFC 3464 + 头注入防护 + 防回环） | `dsn_sanitises_server_text_against_header_injection`、`bounce_is_never_generated_for_a_null_sender` |
//!
//! ## 外发邮件必签：不是「记得签」，而是没有不签的入口
//!
//! [`QueueRunner::new`] 会把传进来的远端传输**无条件**套上 [`SigningTransport`]，
//! 因此「一条未签名的出站路径」在本 crate 里不可表达。签名失败按**失败关闭**处理
//! （退回队列重试），且被标记为本机故障，**不**计入出站健康 —— 详见 [`signing`]。
//! 本地投递（LMTP）刻意不套：DKIM 的意义在于向**外部**接收方证明身份。
//!
//! ## 路由：只有一个来源
//!
//! 远端投递的路由**只能**来自 [`QueueRunner::outbound_route`]，它直接调用
//! `mailstack_smtp::select_outbound_route`。DSN 退信与用户邮件走的就是同一条路
//! —— 不是「记得让它们一样」，而是**代码里根本没有第二条路**（INV-18 / INV-21）。
//!
//! ## 直投（MX）与中继
//!
//! 两条路径都由 [`SmtpRemoteTransport`] 承担，但**互不兜底**：路由由配置唯一决定
//! （`ViaRelay` 或 `Direct`），任何一条都不包含「改用另一条」的分支
//! （INV-18 / INV-21）。直投需要注入 MX 解析后端（`with_mx`）；未注入时直投
//! **明确失败**而不是假装成功。
//!
//! ## 尚未实现（诚实披露）
//!
//! * **直投不做机会式 TLS**：直投链路上没有凭证（与中继相反），当前按 SMTP 默认
//!   行为走明文 25 端口。机会式加密必须「加密但不校验证书」，那是一条独立的安全
//!   策略决定，见 [`delivery`] 的模块说明。
//! * **本地投递（LMTP）**：由 [`Transport`] 注入，实现来自 `crates/store`。

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
pub use store::{OutboundHealthState, QueueStore};

/// 出站路由类型。
///
/// 它出现在 [`DeliveryTarget`] 的公开定义里，因此在这里再导出 —— 否则调用方为了
/// 构造一个投递目标，还得单独依赖 `mailstack-smtp`。路由**只能**由
/// [`QueueRunner::outbound_route`] 产出，本 crate 不提供任何自行拼装路由的入口。
pub use mailstack_smtp::OutboundRoute;

/// 当前 Unix 秒（队列调度的时间基准，注入而不是内部取时钟，便于测试）。
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
        // 2020-01-01 之后、2100 之前；防止有人误接了一个从 0 开始的计数器。
        let now = now_unix();
        assert!(now > 1_577_836_800, "时钟基准异常：{now}");
        assert!(now < 4_102_444_800, "时钟基准异常：{now}");
    }
}

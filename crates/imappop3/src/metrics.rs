//! 传输层指标：连接、TLS、会话与 LMTP 投递的计数器，以及活动连接量表。
//!
//! ## 设计取舍
//!
//! * **无外部依赖**：只用 `std::sync::atomic`。热路径是一次原子加减，零分配、零
//!   锁，不会给 accept/serve 引入背压。
//! * **`Arc<Metrics>` 共享**：同一协议的多个监听器（如 IMAP 的 143 与 993）可以
//!   通过 [`crate::imap::ImapServer::with_metrics`] 共享一份注册表，汇总成一组
//!   序列。不共享时每个监听器各自持有一份，互不干扰 —— 单监听器部署与测试都简单。
//! * **可被 Prometheus 抓取**：[`Metrics::render_prometheus`] 输出标准文本格式，
//!   由部署层的 HTTP 端点（`mailstack-web`）负责暴露；本 crate 不自带 HTTP 服务，
//!   以免把「协议实现」和「运维面」耦合在一起。
//! * **`protocol` 标签**：所有序列带 `protocol="imap|pop3|lmtp"`，多协议部署可
//!   用同一套抓取配置。
//!
//! ## 覆盖范围（诚实披露）
//!
//! * **连接与传输层**（三种协议）：accept、限速、容量、TLS 握手、会话结束；
//! * **IMAP 命令与认证**：[`Metrics::command_completed`] / [`Metrics::command_failed`]
//!   （对应 `NO [SERVERBUG]`）与 [`Metrics::auth_success`] / [`Metrics::auth_failed`]。
//!
//! LMTP 每收件人的交付结果尚未埋点（投递循环在 `lmtp/session`）。交付结果已有结构化
//! 日志（`LMTP delivered` / `LMTP rejected by Sieve`），运维可先用日志管道观测。

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

const METRIC_PREFIX: &str = "mailstack_imappop3";

/// 一份进程内指标注册表。所有操作都是无锁原子操作。
#[derive(Debug)]
pub struct Metrics {
    protocol: &'static str,
    connections_accepted: AtomicU64,
    connections_rate_limited: AtomicU64,
    connections_busy: AtomicU64,
    connections_active: AtomicI64,
    tls_handshake_failed: AtomicU64,
    tls_handshake_timeout: AtomicU64,
    sessions_completed: AtomicU64,
    sessions_server_error: AtomicU64,
    commands_total: AtomicU64,
    commands_failed: AtomicU64,
    auth_success: AtomicU64,
    auth_failed: AtomicU64,
}

impl Metrics {
    /// 为某个协议（`"imap"` / `"pop3"` / `"lmtp"`）创建一份空注册表。
    pub fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            connections_accepted: AtomicU64::new(0),
            connections_rate_limited: AtomicU64::new(0),
            connections_busy: AtomicU64::new(0),
            connections_active: AtomicI64::new(0),
            tls_handshake_failed: AtomicU64::new(0),
            tls_handshake_timeout: AtomicU64::new(0),
            sessions_completed: AtomicU64::new(0),
            sessions_server_error: AtomicU64::new(0),
            commands_total: AtomicU64::new(0),
            commands_failed: AtomicU64::new(0),
            auth_success: AtomicU64::new(0),
            auth_failed: AtomicU64::new(0),
        }
    }

    pub fn protocol(&self) -> &'static str {
        self.protocol
    }

    /// 通过限速与容量检查、已交给会话处理的连接。
    pub fn connection_accepted(&self) {
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_rate_limited(&self) {
        self.connections_rate_limited
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_busy(&self) {
        self.connections_busy.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tls_handshake_failed(&self) {
        self.tls_handshake_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tls_handshake_timeout(&self) {
        self.tls_handshake_timeout.fetch_add(1, Ordering::Relaxed);
    }

    /// 会话正常结束（客户端注销/断开，或协议错误等非服务器故障）。
    pub fn session_completed(&self) {
        self.sessions_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 会话因服务器自身故障（磁盘、锁、后端）结束。
    pub fn session_server_error(&self) {
        self.sessions_server_error.fetch_add(1, Ordering::Relaxed);
    }

    /// 一条 IMAP 命令处理完成（正常应答，含 NO/BAD 这类协议层拒绝）。
    pub fn command_completed(&self) {
        self.commands_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 一条 IMAP 命令因服务器故障结束（对应 `NO [SERVERBUG]`）。
    pub fn command_failed(&self) {
        self.commands_total.fetch_add(1, Ordering::Relaxed);
        self.commands_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// 认证成功。
    pub fn auth_success(&self) {
        self.auth_success.fetch_add(1, Ordering::Relaxed);
    }

    /// 认证失败（口令错或后端不可用）。
    pub fn auth_failed(&self) {
        self.auth_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// 进入一个活动会话；返回的 [`ActiveGuard`] 在 Drop 时把量表减回去（含 panic
    /// 与提前返回，不会漏减）。
    pub fn track_active(metrics: &Arc<Self>) -> ActiveGuard {
        metrics.connections_active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(Arc::clone(metrics))
    }

    /// 当前活动连接数。
    pub fn active(&self) -> i64 {
        self.connections_active.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_rate_limited: self.connections_rate_limited.load(Ordering::Relaxed),
            connections_busy: self.connections_busy.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            tls_handshake_failed: self.tls_handshake_failed.load(Ordering::Relaxed),
            tls_handshake_timeout: self.tls_handshake_timeout.load(Ordering::Relaxed),
            sessions_completed: self.sessions_completed.load(Ordering::Relaxed),
            sessions_server_error: self.sessions_server_error.load(Ordering::Relaxed),
            commands_total: self.commands_total.load(Ordering::Relaxed),
            commands_failed: self.commands_failed.load(Ordering::Relaxed),
            auth_success: self.auth_success.load(Ordering::Relaxed),
            auth_failed: self.auth_failed.load(Ordering::Relaxed),
        }
    }

    /// 渲染成 Prometheus 文本格式（`text/plain; version=0.0.4`）。
    pub fn render_prometheus(&self) -> String {
        let s = self.snapshot();
        let protocol = self.protocol;
        let mut out = String::new();
        render_counter(
            &mut out,
            "connections_accepted",
            "Connections accepted past rate-limit and capacity checks.",
            protocol,
            s.connections_accepted,
        );
        render_counter(
            &mut out,
            "connections_rate_limited",
            "Connections refused by the per-IP rate limiter.",
            protocol,
            s.connections_rate_limited,
        );
        render_counter(
            &mut out,
            "connections_busy",
            "Connections refused because the connection limit was reached.",
            protocol,
            s.connections_busy,
        );
        render_gauge(
            &mut out,
            "connections_active",
            "Connections currently being served.",
            protocol,
            s.connections_active,
        );
        render_counter(
            &mut out,
            "tls_handshake_failed",
            "TLS handshakes that failed (bad certificate, protocol mismatch, I/O).",
            protocol,
            s.tls_handshake_failed,
        );
        render_counter(
            &mut out,
            "tls_handshake_timeout",
            "TLS handshakes that exceeded the handshake timeout.",
            protocol,
            s.tls_handshake_timeout,
        );
        render_counter(
            &mut out,
            "sessions_completed",
            "Sessions that ended without a server-side failure.",
            protocol,
            s.sessions_completed,
        );
        render_counter(
            &mut out,
            "sessions_server_error",
            "Sessions that ended with a server-side failure.",
            protocol,
            s.sessions_server_error,
        );
        // 命令级与认证级指标目前只在 IMAP 会话里埋点。
        if protocol == "imap" {
            render_counter(
                &mut out,
                "commands",
                "IMAP commands processed (OK/NO/BAD).",
                protocol,
                s.commands_total,
            );
            render_counter(
                &mut out,
                "commands_failed",
                "IMAP commands that ended with a server-side failure.",
                protocol,
                s.commands_failed,
            );
            render_counter(
                &mut out,
                "auth_success",
                "Successful authentications.",
                protocol,
                s.auth_success,
            );
            render_counter(
                &mut out,
                "auth_failed",
                "Failed authentications.",
                protocol,
                s.auth_failed,
            );
        }
        out
    }
}

/// [`Metrics`] 某一时刻的快照，供程序化读取与测试使用。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub connections_accepted: u64,
    pub connections_rate_limited: u64,
    pub connections_busy: u64,
    pub connections_active: i64,
    pub tls_handshake_failed: u64,
    pub tls_handshake_timeout: u64,
    pub sessions_completed: u64,
    pub sessions_server_error: u64,
    pub commands_total: u64,
    pub commands_failed: u64,
    pub auth_success: u64,
    pub auth_failed: u64,
}

/// 活动连接量表的 RAII 句柄：构造时已 +1，Drop 时 -1。
#[derive(Debug)]
pub struct ActiveGuard(Arc<Metrics>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.connections_active.fetch_sub(1, Ordering::Relaxed);
    }
}

fn render_counter(out: &mut String, name: &str, help: &str, protocol: &str, value: u64) {
    emit(out, name, help, "counter", protocol, &value.to_string());
}

fn render_gauge(out: &mut String, name: &str, help: &str, protocol: &str, value: i64) {
    emit(out, name, help, "gauge", protocol, &value.to_string());
}

fn emit(out: &mut String, name: &str, help: &str, kind: &str, protocol: &str, value: &str) {
    let suffix = if kind == "counter" { "_total" } else { "" };
    let metric = format!("{METRIC_PREFIX}_{name}{suffix}");
    out.push_str(&format!("# HELP {metric} {help}\n"));
    out.push_str(&format!("# TYPE {metric} {kind}\n"));
    out.push_str(&format!("{metric}{{protocol=\"{protocol}\"}} {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_active_gauge_move_independently() {
        let metrics = Arc::new(Metrics::new("imap"));
        metrics.connection_accepted();
        metrics.connection_accepted();
        metrics.connection_rate_limited();
        metrics.connection_busy();
        metrics.tls_handshake_failed();
        metrics.tls_handshake_timeout();
        metrics.session_completed();
        metrics.session_server_error();

        {
            let _a = Metrics::track_active(&metrics);
            let _b = Metrics::track_active(&metrics);
            assert_eq!(metrics.active(), 2);
            assert_eq!(metrics.snapshot().connections_active, 2);
        }
        assert_eq!(metrics.active(), 0, "guard 必须在 Drop 时减回去");

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.connections_accepted, 2);
        assert_eq!(snapshot.connections_rate_limited, 1);
        assert_eq!(snapshot.connections_busy, 1);
        assert_eq!(snapshot.tls_handshake_failed, 1);
        assert_eq!(snapshot.tls_handshake_timeout, 1);
        assert_eq!(snapshot.sessions_completed, 1);
        assert_eq!(snapshot.sessions_server_error, 1);
    }

    #[test]
    fn prometheus_render_has_help_type_and_labels() {
        let metrics = Metrics::new("imap");
        metrics.connection_accepted();
        metrics.command_completed();
        metrics.command_failed();
        metrics.auth_success();
        metrics.auth_failed();
        let text = metrics.render_prometheus();

        assert!(text.contains("# TYPE mailstack_imappop3_connections_accepted_total counter"));
        assert!(text.contains("mailstack_imappop3_connections_accepted_total{protocol=\"imap\"} 1"));
        assert!(text.contains("# TYPE mailstack_imappop3_connections_active gauge"));
        assert!(text.contains("mailstack_imappop3_connections_active{protocol=\"imap\"} 0"));
        assert!(text.contains("mailstack_imappop3_commands_total{protocol=\"imap\"} 2"));
        assert!(text.contains("mailstack_imappop3_commands_failed_total{protocol=\"imap\"} 1"));
        assert!(text.contains("mailstack_imappop3_auth_success_total{protocol=\"imap\"} 1"));
        // 交付类指标未埋点，不应出现。
        assert!(!text.contains("deliveries_accepted"));

        // 命令级指标只在 IMAP 上渲染。
        let pop3 = Metrics::new("pop3");
        pop3.command_completed();
        assert!(!pop3.render_prometheus().contains("commands_total"));
    }

    #[test]
    fn a_shared_registry_aggregates_across_clones() {
        let shared = Arc::new(Metrics::new("imap"));
        let second = Arc::clone(&shared);
        shared.connection_accepted();
        second.connection_accepted();
        assert_eq!(shared.snapshot().connections_accepted, 2);
    }
}

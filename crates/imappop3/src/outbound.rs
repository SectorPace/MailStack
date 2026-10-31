//! 外发投递接缝（Sieve `redirect` / `vacation` 等动作的出口）。
//!
//! 本 crate 只负责「决定要发什么」，真正的外发交给部署层注入的 [`OutboundSink`]：
//! 生产环境用 [`QueueOutboundSink`] 投递到 `mailstack-queue` 外发队列（由队列 runner
//! 负责 MX 直投/中继、重试、退避与 DSN）；这样 LMTP 交付不会因为一次远端超时而阻塞。
//!
//! `submit` 是**同步**的（在 blocking 线程里调用），实现方不应做长阻塞等待。

use crate::error::{MailError, Result};

pub trait OutboundSink: Send + Sync {
    /// 提交一封外发邮件：`from` 为信封发件人（空串表示 `<>`），`data` 为 RFC 5322 报文。
    fn submit(&self, from: &str, to: &str, data: &[u8]) -> Result<()>;
}

/// 基于 `mailstack-queue` 外发队列的实现。
pub struct QueueOutboundSink {
    store: mailstack_queue::QueueStore,
}

impl QueueOutboundSink {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            store: mailstack_queue::QueueStore::new(root),
        }
    }
}

impl OutboundSink for QueueOutboundSink {
    fn submit(&self, from: &str, to: &str, data: &[u8]) -> Result<()> {
        let entry = mailstack_queue::QueueEntry::new(
            mailstack_queue::EntryKind::Outbound,
            from,
            vec![to.to_string()],
            String::from_utf8_lossy(data).to_string(),
            mailstack_queue::now_unix(),
        )
        .map_err(|error| MailError::storage(format!("outbound enqueue failed: {error}")))?;
        self.store
            .enqueue(&entry)
            .map_err(|error| MailError::storage(format!("outbound enqueue failed: {error}")))
    }
}

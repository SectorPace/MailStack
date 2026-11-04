use crate::error::{MailError, Result};

pub trait OutboundSink: Send + Sync {
    fn submit(&self, from: &str, to: &str, data: &[u8]) -> Result<()>;
}

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
        let Ok(text) = std::str::from_utf8(data) else {
            tracing::warn!(
                from = %from,
                to = %to,
                "Sieve redirect skipped: message is not valid UTF-8 and would be corrupted"
            );
            return Ok(());
        };
        let mut entry = mailstack_queue::QueueEntry::new(
            mailstack_queue::EntryKind::Outbound,
            from,
            vec![to.to_string()],
            text.to_string(),
            mailstack_queue::now_unix(),
        )
        .map_err(|error| MailError::storage(format!("outbound enqueue failed: {error}")))?;

        self.store
            .enqueue_new(&mut entry)
            .map_err(|error| MailError::storage(format!("outbound enqueue failed: {error}")))
    }
}

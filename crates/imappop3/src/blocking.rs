use std::sync::Arc;

use crate::error::{MailError, Result};
use crate::maildir::MailStore;

pub async fn maildir<T, F>(store: &Arc<MailStore>, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&MailStore) -> Result<T> + Send + 'static,
{
    let store = Arc::clone(store);
    match tokio::task::spawn_blocking(move || operation(&store)).await {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(%error, "maildir blocking task failed");
            Err(MailError::storage(format!(
                "maildir worker failed: {error}"
            )))
        }
    }
}

use crate::lmtp::LmtpClient;

use mailstack_queue::{
    DeliveryFailure, DeliveryFuture, DeliveryReceipt, DeliveryTarget, Transport,
};

use crate::error::StoreError;

pub fn classify_partial(
    accepted: Vec<String>,
    failed: &[(String, u16, String)],
) -> Option<DeliveryFailure> {
    if failed.is_empty() {
        return None;
    }

    let any_transient = failed.iter().any(|(_, code, _)| *code < 500);
    let first_code = failed.first().map(|(_, code, _)| *code).unwrap_or(0);
    let detail = failed
        .iter()
        .map(|(recipient, code, message)| format!("{recipient}: {code} {message}"))
        .collect::<Vec<_>>()
        .join("; ");

    let failure = if any_transient {
        DeliveryFailure::transient("LmtpRejected", detail)
    } else {
        DeliveryFailure::permanent("LmtpRejected", detail)
    };

    Some(failure.with_code(first_code).with_accepted(accepted))
}

pub struct LmtpTransport {
    client: LmtpClient,
}

impl LmtpTransport {
    pub fn new(client: LmtpClient) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &LmtpClient {
        &self.client
    }
}

impl Transport for LmtpTransport {
    fn deliver<'a>(
        &'a self,
        entry: &'a mailstack_queue::QueueEntry,
        target: DeliveryTarget,
        recipients: &'a [String],
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            if !matches!(target, DeliveryTarget::Local) {
                return Err(DeliveryFailure::permanent(
                    "WrongTransport",
                    "LMTP transport only handles local recipients",
                ));
            }

            let delivery = match self
                .client
                .deliver(&entry.mail_from, recipients, &entry.data)
                .await
            {
                Ok(delivery) => delivery,
                Err(e) => return Err(classify_lmtp_error(&e)),
            };

            let accepted: Vec<String> = delivery
                .accepted()
                .into_iter()
                .map(str::to_string)
                .collect();
            if delivery.all_accepted() {
                return Ok(DeliveryReceipt {
                    accepted: accepted.len(),
                });
            }

            let failed: Vec<(String, u16, String)> = delivery
                .failed()
                .into_iter()
                .map(|result| {
                    (
                        result.recipient.clone(),
                        result.code,
                        result.message.clone(),
                    )
                })
                .collect();

            match classify_partial(accepted, &failed) {
                None => Ok(DeliveryReceipt {
                    accepted: recipients.len(),
                }),
                Some(failure) => Err(failure),
            }
        })
    }
}

pub fn classify_lmtp_error(error: &StoreError) -> DeliveryFailure {
    DeliveryFailure::transient("LmtpUnavailable", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_queue::FailureClass;

    #[test]
    fn all_accepted_yields_no_failure() {
        assert!(classify_partial(vec!["a@x.test".to_string()], &[]).is_none());
    }

    #[test]
    fn a_single_transient_failure_makes_the_whole_batch_retryable() {
        let failure = classify_partial(
            vec!["ok@x.test".to_string()],
            &[
                (
                    "quota@x.test".to_string(),
                    452,
                    "4.2.2 over quota".to_string(),
                ),
                ("gone@x.test".to_string(), 550, "5.1.1 unknown".to_string()),
            ],
        )
        .expect("有失败就应产出失败");

        assert_eq!(failure.class, FailureClass::Transient);
        assert_eq!(failure.kind, "LmtpRejected");
        assert_eq!(
            failure.accepted,
            vec!["ok@x.test".to_string()],
            "已落箱的收件人必须带回去，否则重试会重复投递"
        );
        assert!(failure.message.contains("quota@x.test"));
        assert!(
            failure.message.contains("gone@x.test"),
            "每个失败都要有记录"
        );
    }

    #[test]
    fn all_permanent_failures_are_permanent() {
        let failure = classify_partial(
            Vec::new(),
            &[("gone@x.test".to_string(), 550, "5.1.1 unknown".to_string())],
        )
        .unwrap();
        assert_eq!(failure.class, FailureClass::Permanent);
        assert_eq!(failure.code, Some(550));
        assert!(failure.accepted.is_empty());
    }

    #[test]
    fn connection_failures_are_retryable_never_bounces() {
        let failure = classify_lmtp_error(&StoreError::Lmtp("cannot connect".to_string()));
        assert_eq!(failure.class, FailureClass::Transient);
        assert_eq!(failure.kind, "LmtpUnavailable");
        assert!(failure.accepted.is_empty());
    }

    #[tokio::test]
    async fn lmtp_transport_refuses_remote_targets() {
        use mailstack_queue::{OutboundRoute, QueueEntry};
        use std::time::Duration;

        let client = LmtpClient::new(
            crate::lmtp::LmtpEndpoint::unix("/nonexistent/socket"),
            "mail.example.org",
            Duration::from_millis(50),
        );
        let transport = LmtpTransport::new(client);
        let entry = QueueEntry::new(
            mailstack_queue::EntryKind::Outbound,
            "s@example.org",
            vec!["r@example.net".to_string()],
            "body",
            0,
        )
        .unwrap();

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();
        assert_eq!(failure.kind, "WrongTransport");
        assert!(failure.is_permanent());
    }
}

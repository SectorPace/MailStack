//! LMTP 投递的队列适配（把 [`LmtpClient`] 接到 `mailstack_queue::Transport` 上）。
//!
//! 关键语义：
//!
//! * 只处理 [`DeliveryTarget::Local`]；外域收件人走 SMTP 传输，不得混用
//!   （否则本地收件人会被推到公网 SMTP）。
//! * **部分成功必须如实上报**：把已落箱的收件人放进
//!   [`DeliveryFailure::accepted`]，队列才不会在重试时重复投递。
//! * 分类规则：失败集合里**只要有一个 4xx 就判可重试**，只有全部为 5xx 才判永久。
//!   反过来会把临时失败（如超配额）当成永久失败退掉用户的邮件 —— 丢信比多试几次严重。

use crate::lmtp::LmtpClient;

use mailstack_queue::{
    DeliveryFailure, DeliveryFuture, DeliveryReceipt, DeliveryTarget, Transport,
};

use crate::error::StoreError;

/// 把逐收件人的 LMTP 结果折算成队列的失败分类。
///
/// `pub` 是为了让分类规则本身可被直接测试 —— 它是「丢信还是重试」的唯一判据。
/// 返回 `None` 表示全部收件人都已投递成功。
pub fn classify_partial(
    accepted: Vec<String>,
    failed: &[(String, u16, String)],
) -> Option<DeliveryFailure> {
    if failed.is_empty() {
        return None;
    }

    // 只要有一个可重试的就整批可重试（保守方向：宁可多试，不可丢信）。
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

/// 把 [`LmtpClient`] 适配成队列可用的本地投递传输。
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
                // 结构性守卫：本地传输绝不能用来投外域收件人。
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

/// 连接层失败（连不上 Dovecot、超时、协议错乱）→ **可重试**。
///
/// 这类错误的共同点是「结果未知」：邮件可能已落箱也可能没有。据此退信会让发件人
/// 重复发送，所以只能重试。
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
        // 一个 5xx 一个 4xx：必须整体判可重试。反过来会把超配额这类临时问题
        // 当成永久失败，直接退掉本可投递的邮件 —— 丢信比多试几次严重。
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
        // 结果未知 → 只能重试。据此退信会造成重复发送。
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

use time::OffsetDateTime;

use crate::entry::QueueEntry;

#[derive(Debug, Clone)]
pub struct DsnRequest<'a> {
    pub reporting_mta: &'a str,

    pub original: &'a QueueEntry,

    pub failed_recipients: &'a [String],

    pub diagnostic: &'a str,

    pub status_code: Option<u16>,
}

pub fn dsn_recipient(original: &QueueEntry) -> Option<&str> {
    if original.is_null_sender() {
        return None;
    }
    let recipient = original.mail_from.trim();
    if recipient.is_empty() || recipient.contains(['\r', '\n', '\0', ' ']) {
        return None;
    }
    Some(recipient)
}

pub fn dsn_envelope_from() -> &'static str {
    ""
}

pub fn build_dsn(req: &DsnRequest<'_>) -> String {
    let mta = sanitize_header(req.reporting_mta);
    let to = sanitize_header(dsn_recipient(req.original).unwrap_or_default());
    let subject = "Undelivered Mail Returned to Sender";
    let now = OffsetDateTime::now_utc();
    let boundary = fresh_boundary(&[req.original.data.as_str(), req.diagnostic]);

    let mut out = String::new();
    push(
        &mut out,
        &format!("From: Mail Delivery System <MAILER-DAEMON@{mta}>"),
    );
    push(&mut out, &format!("To: <{to}>"));
    push(&mut out, &format!("Subject: {subject}"));
    push(&mut out, &format!("Date: {}", rfc2822(now)));
    push(
        &mut out,
        &format!("Message-ID: <dsn-{}@{}>", req.original.id, mta),
    );

    push(&mut out, "Auto-Submitted: auto-replied");
    push(&mut out, "MIME-Version: 1.0");
    push(
        &mut out,
        &format!(
            "Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\""
        ),
    );
    push(&mut out, "");

    push(&mut out, &format!("--{boundary}"));
    push(&mut out, "Content-Type: text/plain; charset=utf-8");

    push(&mut out, "Content-Transfer-Encoding: 7bit");
    push(&mut out, "");
    push(&mut out, &format!("This is the mail system at host {mta}."));
    push(&mut out, "");
    push(
        &mut out,
        "I'm sorry to have to inform you that your message could not be delivered to one",
    );
    push(
        &mut out,
        "or more recipients. The original message is attached below.",
    );
    push(&mut out, "");
    for recipient in req.failed_recipients {
        push(
            &mut out,
            &format!(
                "    {}: {}",
                sanitize_header(recipient),
                sanitize_header(req.diagnostic)
            ),
        );
    }
    push(&mut out, "");

    push(&mut out, &format!("--{boundary}"));
    push(&mut out, "Content-Type: message/delivery-status");
    push(&mut out, "");
    push(&mut out, &format!("Reporting-MTA: dns; {mta}"));
    push(&mut out, "");
    for recipient in req.failed_recipients {
        push(
            &mut out,
            &format!("Final-Recipient: rfc822; {}", sanitize_header(recipient)),
        );
        push(&mut out, "Action: failed");
        push(
            &mut out,
            &format!("Status: {}", extended_status(req.status_code)),
        );
        push(
            &mut out,
            &format!("Diagnostic-Code: smtp; {}", sanitize_header(req.diagnostic)),
        );
        push(&mut out, "");
    }

    push(&mut out, &format!("--{boundary}"));
    push(&mut out, "Content-Type: message/rfc822");

    let original_cte = cte_for(req.original.data.as_bytes());
    push(
        &mut out,
        &format!("Content-Transfer-Encoding: {original_cte}"),
    );
    push(&mut out, "");
    out.push_str(&normalize_crlf(&req.original.data));
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }

    push(&mut out, &format!("--{boundary}--"));
    out
}

fn extended_status(code: Option<u16>) -> &'static str {
    match code {
        Some(550) => "5.1.1",
        Some(551) => "5.1.6",
        Some(552) => "5.2.2",
        Some(553) => "5.1.3",
        Some(554) => "5.0.0",

        _ => "5.0.0",
    }
}

pub fn sanitize_header(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

fn fresh_boundary(parts: &[&str]) -> String {
    for _ in 0..16 {
        let candidate = format!("=_MailStack_{}", random_hex(16));
        if !parts.iter().any(|part| part.contains(&candidate)) {
            return candidate;
        }
    }

    loop {
        let candidate = format!("=_MailStack_{}", random_hex(32));
        if !parts.iter().any(|part| part.contains(&candidate)) {
            return candidate;
        }
    }
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(bytes * 2);
    for byte in buf {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn is_7bit_clean(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte < 0x80)
}

fn cte_for(bytes: &[u8]) -> &'static str {
    if is_7bit_clean(bytes) {
        "7bit"
    } else {
        "8bit"
    }
}

fn push(out: &mut String, line: &str) {
    out.push_str(line);
    out.push_str("\r\n");
}

pub fn normalize_crlf(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

fn rfc2822(dt: OffsetDateTime) -> String {
    const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let weekday = WEEKDAYS[dt.weekday().number_days_from_monday() as usize];
    let month = MONTHS[(u8::from(dt.month()) - 1) as usize];
    let offset = dt.offset();
    let minutes = offset.whole_minutes();
    let (sign, minutes) = if minutes < 0 {
        ('-', -minutes)
    } else {
        ('+', minutes)
    };

    format!(
        "{weekday}, {:02} {month} {} {:02}:{:02}:{:02} {sign}{:02}{:02}",
        dt.day(),
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        minutes / 60,
        minutes % 60
    )
}

#[cfg(test)]
fn rfc2822_in(dt: OffsetDateTime, offset: time::UtcOffset) -> String {
    rfc2822(dt.to_offset(offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EntryKind;

    fn original() -> QueueEntry {
        QueueEntry::new(
            EntryKind::Outbound,
            "sender@example.org",
            vec!["missing@example.net".to_string()],
            "Subject: hello\r\n\r\noriginal body\r\n",
            1_700_000_000,
        )
        .unwrap()
    }

    fn dsn(original: &QueueEntry, diagnostic: &str, code: Option<u16>) -> String {
        build_dsn(&DsnRequest {
            reporting_mta: "mail.example.org",
            original,
            failed_recipients: &["missing@example.net".to_string()],
            diagnostic,
            status_code: code,
        })
    }

    #[test]
    fn dsn_is_a_multipart_report_with_delivery_status_fields() {
        let original = original();
        let message = dsn(&original, "550 5.1.1 user unknown", Some(550));

        assert!(message.contains("multipart/report"));
        assert!(message.contains("report-type=delivery-status"));
        assert!(message.contains("Content-Type: message/delivery-status"));
        assert!(message.contains("Reporting-MTA: dns; mail.example.org"));
        assert!(message.contains("Final-Recipient: rfc822; missing@example.net"));
        assert!(message.contains("Action: failed"));
        assert!(message.contains("Status: 5.1.1"));
        assert!(message.contains("Diagnostic-Code: smtp; 550 5.1.1 user unknown"));
        assert!(
            message.contains("Content-Type: message/rfc822"),
            "退信必须回附原邮件，否则收件人无法重发"
        );
        assert!(message.contains("original body"));
    }

    #[test]
    fn dsn_targets_the_original_envelope_sender() {
        let original = original();
        assert_eq!(dsn_recipient(&original), Some("sender@example.org"));
        let message = dsn(&original, "550 nope", Some(550));
        assert!(message.contains("To: <sender@example.org>"));
        assert!(
            message.contains("Auto-Submitted: auto-replied"),
            "退信必须声明 auto-replied，避免触发对方的自动回复回环"
        );
    }

    #[test]
    fn mime_boundary_is_unpredictable_and_never_collides_with_the_original() {
        let original = original();
        let first = dsn(&original, "550 nope", Some(550));
        let second = dsn(&original, "550 nope", Some(550));

        let boundary_of = |message: &str| -> String {
            message
                .lines()
                .find(|line| line.starts_with("Content-Type: multipart/report"))
                .and_then(|line| line.split("boundary=\"").nth(1))
                .and_then(|rest| rest.split('"').next())
                .expect("必须声明 boundary")
                .to_string()
        };

        let a = boundary_of(&first);
        let b = boundary_of(&second);
        assert_ne!(
            a, b,
            "同一封邮件两次退信必须用不同边界 —— 否则正文可预置注入"
        );
        assert!(
            !a.contains("missing@example.net") && !a.contains(&original.id),
            "边界不得由条目身份派生：{a}"
        );
        assert!(a.len() >= 32, "边界应有足够随机性：{a}");

        let poisoned = original
            .data
            .replace("original body", "original body\r\n--=_MailStack_deadbeef");
        let mut entry = original.clone();
        entry.data = poisoned.clone();
        let message = dsn(&entry, "550 nope", Some(550));
        let chosen = boundary_of(&message);
        assert!(
            !poisoned.contains(&chosen),
            "生成的边界出现在原邮件正文里，可被用来提前结束 multipart"
        );
    }

    #[test]
    fn content_transfer_encoding_matches_the_actual_bytes() {
        let ascii = original();
        let message = dsn(&ascii, "550 nope", Some(550));
        assert!(
            !message.contains("Content-Transfer-Encoding: 8bit"),
            "纯 ASCII 退信不得声明 8bit（对只通告 7BIT 的对端是违规）：\n{message}"
        );
        assert!(message.contains("Content-Transfer-Encoding: 7bit"));

        let mut binary = original();
        binary.data = "Subject: hello\r\n\r\n正文含 8 位字节\r\n".to_string();
        let message = dsn(&binary, "550 nope", Some(550));
        assert!(
            message.contains("Content-Transfer-Encoding: 8bit"),
            "原邮件含 8 位字节时必须声明 8bit：\n{message}"
        );
    }

    #[test]
    fn dsn_never_targets_a_null_sender() {
        let mut original = original();
        original.mail_from = String::new();
        assert_eq!(dsn_recipient(&original), None);
        assert_eq!(dsn_envelope_from(), "", "DSN 自身必须是 null sender");
    }

    fn assert_no_injected_header(message: &str, header: &str) {
        for line in message.split("\r\n") {
            assert!(
                !line.starts_with(header),
                "注入产生了新的头字段 {header:?}：\n{message}"
            );
        }
    }

    #[test]
    fn dsn_sanitises_server_text_against_header_injection() {
        let original = original();
        let message = dsn(
            &original,
            "550 nope\r\nBcc: attacker@evil.example\r\n\r\ninjected body",
            Some(550),
        );

        assert_no_injected_header(&message, "Bcc:");

        assert!(
            message.contains("Diagnostic-Code: smtp; 550 nope  Bcc: attacker@evil.example"),
            "诊断信息应保留在**行内**，而不是被静默篡改：\n{message}"
        );
    }

    #[test]
    fn dsn_sanitises_recipient_and_mta_against_injection() {
        let mut original = original();
        original.recipients = vec!["x@example.net".to_string()];

        let message = build_dsn(&DsnRequest {
            reporting_mta: "mail.example.org\r\nX-Evil: yes",
            original: &original,
            failed_recipients: &["r@example.net\r\nX-Evil: yes".to_string()],
            diagnostic: "550 nope",
            status_code: Some(550),
        });
        assert_no_injected_header(&message, "X-Evil:");

        let header_block = message.split("\r\n\r\n").next().unwrap();
        assert_eq!(
            header_block.lines().count(),
            8,
            "头区行数被注入改变了：\n{header_block}"
        );
    }

    #[test]
    fn dsn_uses_crlf_line_endings_only() {
        let original = original();
        let message = dsn(&original, "450 busy", Some(450));
        let stripped = message.replace("\r\n", "");
        assert!(!stripped.contains('\n'), "报文里存在裸 LF");
        assert!(!stripped.contains('\r'), "报文里存在裸 CR");
    }

    #[test]
    fn dsn_normalises_a_bare_lf_original_message() {
        assert_eq!(normalize_crlf("a\nb\r\nc\rd"), "a\r\nb\r\nc\r\nd");

        let mut original = original();
        original.data = "Subject: x\n\nbody\n".to_string();
        let message = dsn(&original, "550 nope", Some(550));
        let stripped = message.replace("\r\n", "");
        assert!(!stripped.contains('\n'), "原邮件里的裸 LF 未被归一化");
    }

    #[test]
    fn extended_status_covers_the_common_codes() {
        assert_eq!(extended_status(Some(550)), "5.1.1");
        assert_eq!(extended_status(Some(552)), "5.2.2");
        assert_eq!(extended_status(None), "5.0.0", "未知状态码按最终失败处理");
    }

    #[test]
    fn an_exhausted_transient_failure_gets_a_permanent_status_not_4xx() {
        let original = original();
        let message = dsn(&original, "452 4.2.2 over quota (last attempt)", Some(452));

        assert!(
            message.contains("Status: 5.0.0"),
            "最终退信不得写 4.x.x 状态（与 Action: failed 自相矛盾）：\n{message}"
        );
        assert!(message.contains("Action: failed"));
        assert!(
            message.contains("452 4.2.2 over quota (last attempt)"),
            "最后一次失败的原因必须仍可读：\n{message}"
        );
    }

    #[test]
    fn rfc2822_date_matches_the_expected_shape() {
        let dt = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let rendered = rfc2822_in(dt, time::UtcOffset::UTC);
        assert_eq!(rendered, "Tue, 14 Nov 2023 22:13:20 +0000");
    }

    #[test]
    fn sanitize_header_collapses_control_characters() {
        assert_eq!(sanitize_header("a\r\nb"), "a  b");
        assert_eq!(sanitize_header("  spaced  "), "spaced");
        assert_eq!(sanitize_header("tab\there"), "tab here");
        assert_eq!(sanitize_header("nul\0here"), "nul here");
    }

    #[test]
    fn multiple_failed_recipients_each_get_a_status_block() {
        let original = original();
        let failed = vec!["a@example.net".to_string(), "b@example.net".to_string()];
        let message = build_dsn(&DsnRequest {
            reporting_mta: "mail.example.org",
            original: &original,
            failed_recipients: &failed,
            diagnostic: "550 nope",
            status_code: Some(550),
        });
        assert_eq!(message.matches("Final-Recipient: rfc822;").count(), 2);
        assert_eq!(message.matches("Action: failed").count(), 2);
    }
}

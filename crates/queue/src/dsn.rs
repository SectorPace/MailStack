//! DSN 退信生成（RFC 3464，规格书 §5.8「超过阈值的失败生成 DSN 退信」）。
//!
//! **与规格书的偏离（已登记，待裁决）**：§3.4 的依赖清单把「生成 DSN/退信」
//! 推荐给 `mail-builder`。本模块先自研，理由仅限于工程取舍：这里只产出**一种
//! 固定结构**的报文，而 DSN 的两个关键部分（`message/delivery-status` 的逐收件人
//! 状态块、`message/rfc822` 原邮件回附）在高层构建器里反而需要绕开其封装。
//! **不构成正当理由的是**「依赖链/离线可复现」——`mail-builder` 是纯 Rust，
//! 不违反 §3.4 的硬约束。若裁决为改用该 crate，只需替换本模块内部实现，
//! 对外接口 [`build_dsn`] 不变。
//!
//! 两个安全要点：
//!
//! 1. **头注入**：`Diagnostic-Code` 里放的是对端服务器返回的**任意文本**。若直接
//!    拼进头，一段 `\r\nBcc: attacker@evil` 就能往退信里塞收件人（甚至改变报文
//!    结构）。因此所有插入头的动态值都经 [`sanitize_header`]。
//! 2. **退信回环**：null sender（`<>`）的消息**绝不能**触发退信（RFC 5321 §4.5.5），
//!    否则双退信会互相触发、无限增殖。由 [`dsn_recipient`] 返回 `None` 强制表达。

use time::OffsetDateTime;

use crate::entry::QueueEntry;

/// 生成一封 DSN 所需的输入。
#[derive(Debug, Clone)]
pub struct DsnRequest<'a> {
    /// 本机 MTA 名称（`Reporting-MTA` 与 `MAILER-DAEMON@` 的域名）。
    pub reporting_mta: &'a str,
    /// 无法投递的原邮件。
    pub original: &'a QueueEntry,
    /// 投递失败的收件人（可能是原收件人的子集）。
    pub failed_recipients: &'a [String],
    /// 失败原因（可能来自对端服务器，**必须**当作不可信文本）。
    pub diagnostic: &'a str,
    /// 对端状态码（若有）。
    pub status_code: Option<u16>,
}

/// DSN 的收件人：原邮件信封发件人。
///
/// 返回 `None` 表示**不得退信**（原发件人是 null sender，或地址非法）。
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

/// DSN 的信封发件人：必须是 `<>`（null sender），这样它自己失败时不会再退信。
pub fn dsn_envelope_from() -> &'static str {
    ""
}

/// 构造 DSN 报文。
///
/// 调用方负责保证 `req.original` 的信封发件人非空（见 [`dsn_recipient`]）。
pub fn build_dsn(req: &DsnRequest<'_>) -> String {
    let mta = sanitize_header(req.reporting_mta);
    let to = sanitize_header(dsn_recipient(req.original).unwrap_or_default());
    let subject = "Undelivered Mail Returned to Sender";
    let now = OffsetDateTime::now_utc();
    let boundary = format!(
        "=_MailStack_{}",
        sanitize_boundary(&format!(
            "{}-{}",
            req.original.id,
            req.failed_recipients.len()
        ))
    );

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
    // 退信自身不得再触发自动回复（RFC 3834）。
    push(&mut out, "Auto-Submitted: auto-replied");
    push(&mut out, "MIME-Version: 1.0");
    push(
        &mut out,
        &format!(
            "Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\""
        ),
    );
    push(&mut out, "");

    // 第 1 部分：人类可读说明。
    push(&mut out, &format!("--{boundary}"));
    push(&mut out, "Content-Type: text/plain; charset=utf-8");
    push(&mut out, "Content-Transfer-Encoding: 8bit");
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

    // 第 2 部分：机器可读的投递状态（RFC 3464 §2.3）。
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

    // 第 3 部分：原邮件（便于收件人重发或排查）。
    push(&mut out, &format!("--{boundary}"));
    push(&mut out, "Content-Type: message/rfc822");
    push(&mut out, "");
    out.push_str(&normalize_crlf(&req.original.data));
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }

    push(&mut out, &format!("--{boundary}--"));
    out
}

/// 由状态码推导 RFC 3463 的扩展状态码（`X.Y.Z`）。
///
/// 只对 4xx/5xx 给出诚实映射；未知一律回落到 `5.0.0`（本函数只在退信时调用，
/// 而退信意味着已判定为最终失败）。
fn extended_status(code: Option<u16>) -> &'static str {
    match code {
        Some(421) | Some(451) => "4.0.0",
        Some(450) | Some(452) => "4.0.0",
        Some(550) => "5.1.1",
        Some(551) => "5.1.6",
        Some(552) => "5.2.2",
        Some(553) => "5.1.3",
        Some(554) => "5.0.0",
        _ => "5.0.0",
    }
}

/// 头字段值净化：去掉 CR/LF/NUL，并把其余控制字符替换为空格。
///
/// 对端服务器返回的文本可能含换行或 NUL，直接拼进头即可注入新头字段或提前
/// 结束头区。这里把「不可打印」一律降级为空格，宁可显示难看，也不能让报文
/// 结构被外部输入改变。
pub fn sanitize_header(value: &str) -> String {
    value
        .chars()
        // `is_control()` 覆盖 CR / LF / NUL 以及其余不可打印控制字符。
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// 边界串净化：只保留 ASCII 字母数字与 `-_.`。
fn sanitize_boundary(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// 追加一行（CRLF 结束）。
fn push(out: &mut String, line: &str) {
    out.push_str(line);
    out.push_str("\r\n");
}

/// 把任意行尾统一成 CRLF。
///
/// 原邮件来自外部（可能是 Python 工具、编辑器或另一台 MTA），行尾可能是 LF 或
/// 混合。SMTP 的 DATA 阶段要求 CRLF，混入裸 LF 会被部分对端判为协议错误。
pub fn normalize_crlf(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

/// RFC 5322 的日期格式：`Tue, 30 Sep 2026 08:00:00 +0000`。
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

/// 便于测试固定时区输出。
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
        // RFC 3464 §2 的必备结构：multipart/report + report-type=delivery-status。
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
    fn dsn_never_targets_a_null_sender() {
        // 防双退信回环：null sender 的消息不得退信。
        let mut original = original();
        original.mail_from = String::new();
        assert_eq!(dsn_recipient(&original), None);
        assert_eq!(dsn_envelope_from(), "", "DSN 自身必须是 null sender");
    }

    /// 头注入的正确判据：报文里**不得出现以该名字开头的新行**。
    ///
    /// 仅仅「文本中包含 `Bcc:`」并不构成注入 —— 只要它还在某一行的行内，
    /// 就仍是原头字段值的一部分。用行首判定才是在验证真正的不变量。
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
        // 这条是安全回归：对端返回的文本是**不可信输入**。
        let original = original();
        let message = dsn(
            &original,
            "550 nope\r\nBcc: attacker@evil.example\r\n\r\ninjected body",
            Some(550),
        );

        assert_no_injected_header(&message, "Bcc:");
        // 注入的换行必须退化为空格而不是被删掉：否则两段文本会粘连，
        // 运维看到的诊断信息会变成误导性的内容。
        assert!(
            message.contains("Diagnostic-Code: smtp; 550 nope  Bcc: attacker@evil.example"),
            "诊断信息应保留在**行内**，而不是被静默篡改：\n{message}"
        );
    }

    #[test]
    fn dsn_sanitises_recipient_and_mta_against_injection() {
        let mut original = original();
        original.recipients = vec!["x@example.net".to_string()];
        // 直接构造：模拟一个被污染的 reporting_mta（配置来自管理员输入）。
        let message = build_dsn(&DsnRequest {
            reporting_mta: "mail.example.org\r\nX-Evil: yes",
            original: &original,
            failed_recipients: &["r@example.net\r\nX-Evil: yes".to_string()],
            diagnostic: "550 nope",
            status_code: Some(550),
        });
        assert_no_injected_header(&message, "X-Evil:");
        // 头区必须仍是固定的 8 行（From / To / Subject / Date / Message-ID /
        // Auto-Submitted / MIME-Version / Content-Type），没有因注入而增加。
        let header_block = message.split("\r\n\r\n").next().unwrap();
        assert_eq!(
            header_block.lines().count(),
            8,
            "头区行数被注入改变了：\n{header_block}"
        );
    }

    #[test]
    fn dsn_uses_crlf_line_endings_only() {
        // 混入裸 LF 会被部分对端判为协议错误。
        let original = original();
        let message = dsn(&original, "450 busy", Some(450));
        let stripped = message.replace("\r\n", "");
        assert!(!stripped.contains('\n'), "报文里存在裸 LF");
        assert!(!stripped.contains('\r'), "报文里存在裸 CR");
    }

    #[test]
    fn dsn_normalises_a_bare_lf_original_message() {
        // 原邮件来自外部工具，行尾可能是裸 LF。
        assert_eq!(normalize_crlf("a\nb\r\nc\rd"), "a\r\nb\r\nc\r\nd");

        let mut original = original();
        original.data = "Subject: x\n\nbody\n".to_string();
        let message = dsn(&original, "550 nope", Some(550));
        let stripped = message.replace("\r\n", "");
        assert!(!stripped.contains('\n'), "原邮件里的裸 LF 未被归一化");
    }

    #[test]
    fn extended_status_covers_the_common_codes() {
        assert_eq!(extended_status(Some(450)), "4.0.0");
        assert_eq!(extended_status(Some(550)), "5.1.1");
        assert_eq!(extended_status(Some(552)), "5.2.2");
        assert_eq!(extended_status(None), "5.0.0", "未知状态码按最终失败处理");
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

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
    // 5.17：这一部分由我们自己生成、恒为 ASCII，因此**恒为 7bit**。
    // 原先无条件写 `8bit`，把一封纯 ASCII 的退信升格成 8 位报文，
    // 对只通告 7BIT 的对端是 RFC 4155/6152 意义上的违规。
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
    // 5.17：原邮件原样转发（不能转码 —— 那会破坏它的 DKIM 签名与正文字节）。
    // 因此这里的声明必须如实反映原邮件是不是 7-bit 干净：
    // 干净就声明 7bit，含 8 位字节才声明 8bit。
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

/// 由状态码推导 RFC 3463 的扩展状态码（`X.Y.Z`）。
///
/// **本函数只服务于最终失败退信**（`Action: failed`），因此映射结果必须是
/// 永久类（5.x.x）：退信意味着重试预算已经耗尽、不再重试 —— 这时给 4xx 的
/// 最后一次应答安一个 `4.0.0`，就会产出「`Status: 4.0.0`（临时）+ `Action: failed`
/// （永久）」的自相矛盾，下游按 Status 分类的系统会把这封退信当成「还会重试」。
///
/// 所以：5xx 保留诚实映射（诊断价值更高）；4xx 与未知一律回落 `5.0.0` ——
/// 最后一次是临时失败这一事实保留在 `Diagnostic-Code` 的人类可读文本里，
/// 不进机器可读的 `Status`。
fn extended_status(code: Option<u16>) -> &'static str {
    match code {
        Some(550) => "5.1.1",
        Some(551) => "5.1.6",
        Some(552) => "5.2.2",
        Some(553) => "5.1.3",
        Some(554) => "5.0.0",
        // 4xx（重试耗尽的临时失败）与未知码：最终状态是永久失败。
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

/// 生成一个 MIME 边界：128 位随机，并保证**不出现在**报文任何部分里。
///
/// ## 5.14：为什么不能用「条目 ID + 失败数」派生
///
/// 原实现的边界是 `entry.id + 失败数` 拼出来的：确定、可复现，而且
/// **从不检查原邮件正文是否含同一串**。原邮件正文是发件人完全可控的，
/// 只要他在正文里放一行 `--<边界>`，就能提前结束真正的 multipart，
/// 让后面所有内容被解析成**额外的 MIME 部件** —— 而这封退信的
/// `From:` 是 `Mail Delivery System <MAILER-DAEMON@…>`。
/// 也就是说，攻击者可以借退信通道以系统退信人的名义向受害者投递伪造部件。
///
/// 随机边界让「猜中」不可行；再显式校验不冲突，则连「事先把常见边界写进正文」
/// 这类预置攻击也一并关掉。
fn fresh_boundary(parts: &[&str]) -> String {
    for _ in 0..16 {
        let candidate = format!("=_MailStack_{}", random_hex(16));
        if !parts.iter().any(|part| part.contains(&candidate)) {
            return candidate;
        }
    }
    // 128 位随机连续撞 16 次只可能是被刻意构造的输入。此时把随机段加长到
    // 256 位再取一次 —— 仍然校验，绝不复用已知会冲突的串。
    loop {
        let candidate = format!("=_MailStack_{}", random_hex(32));
        if !parts.iter().any(|part| part.contains(&candidate)) {
            return candidate;
        }
    }
}

/// 生成 `bytes` 字节的随机 hex 串。
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

/// 内容是否 7-bit 干净（全部字节 < 0x80 且不含 NUL）。
///
/// 5.17：DSN 原先无条件声明 `Content-Transfer-Encoding: 8bit`。
/// 对只通告 7BIT 的 MX，这是 RFC 6152 违规；而对**本来就是 7-bit** 的内容
/// 声明 8bit 更是无谓地把报文升格成 8 位。这里按实际字节判定。
fn is_7bit_clean(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte < 0x80)
}

/// 按内容选 `Content-Transfer-Encoding` 声明。
fn cte_for(bytes: &[u8]) -> &'static str {
    if is_7bit_clean(bytes) {
        "7bit"
    } else {
        "8bit"
    }
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

    /// 5.14：MIME 边界不得由可预测的输入派生，也不得与原邮件内容冲突。
    ///
    /// 原实现是 `=_MailStack_<entry.id>-<失败数>`：确定、可复现，且从不检查
    /// 原邮件正文。发件人只要在正文里放一行 `--<边界>`，就能提前结束真正的
    /// multipart，让后续内容变成额外的 MIME 部件 —— 而这封退信由
    /// `Mail Delivery System <MAILER-DAEMON@…>` 署名。
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

        // 正文里预置候选边界时，生成的边界必须避开它。
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

    /// 5.17：CTE 声明必须反映**实际字节**，不能一律写 8bit。
    #[test]
    fn content_transfer_encoding_matches_the_actual_bytes() {
        // 纯 ASCII 的原邮件 → 两个部分都必须是 7bit。
        let ascii = original();
        let message = dsn(&ascii, "550 nope", Some(550));
        assert!(
            !message.contains("Content-Transfer-Encoding: 8bit"),
            "纯 ASCII 退信不得声明 8bit（对只通告 7BIT 的对端是违规）：\n{message}"
        );
        assert!(message.contains("Content-Transfer-Encoding: 7bit"));

        // 含 8 位字节的原邮件 → message/rfc822 部分必须如实声明 8bit。
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
        assert_eq!(extended_status(Some(550)), "5.1.1");
        assert_eq!(extended_status(Some(552)), "5.2.2");
        assert_eq!(extended_status(None), "5.0.0", "未知状态码按最终失败处理");
    }

    /// 重试预算耗尽的退信往往带着**最后一次**临时失败（4xx）的状态码。
    /// 机器可读的 `Status` 必须与 `Action: failed` 一致（永久类）；
    /// 「最后一次是临时失败」这一事实保留在人类可读的诊断文本里。
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

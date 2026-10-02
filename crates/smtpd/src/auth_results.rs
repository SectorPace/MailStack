//! `Authentication-Results` 头的渲染（RFC 8601）。
//!
//! ## 为什么必须在这里净化
//!
//! 这个头里要塞进**对端可控**的字符串（信封发件人、DKIM 的 `d=` 域、DMARC 的域）。
//! 如果其中混进 `\r\n`，接收方读到的就是**两个头** —— 攻击者可以让自己的报文带上
//! 一条伪造的 `Authentication-Results: ...; dmarc=pass`。这与应答注入同源，防线
//! 必须放在**唯一的渲染入口**上。
//!
//! 因此本模块只做两件事：把判定结果映射成 RFC 8601 关键字，并把所有插入值过滤成
//! 「不含控制字符」的字符串。**不**把 fail 的具体原因写进去 —— 那些文本来自解析器，
//! 既没有标准形态、也没有净化过。

use mailstack_auth::{ArcVerdict, DkimStatus, DmarcCheck};

/// 渲染一条完整的 `Authentication-Results` 头（含头名与结尾 CRLF，已按 RFC 5322 折行）。
///
/// `arc` 为 `None` 时**不**输出 `arc=` 方法 —— 没有结论就不要写结论，
/// 写一个 `arc=none` 会与「确实校验过、结论是 none」混淆。
pub fn render(
    hostname: &str,
    mail_from: &str,
    check: &DmarcCheck,
    arc: Option<&ArcVerdict>,
) -> String {
    let mut methods: Vec<String> = Vec::new();

    // ── SPF ──
    let mut spf = format!("spf={}", check.spf.status.keyword());
    if !mail_from.is_empty() {
        spf.push_str(" smtp.mailfrom=");
        spf.push_str(&sanitize(mail_from));
    }
    methods.push(spf);

    // ── DKIM：每一条签名一行 ──
    for verdict in &check.dkim {
        if verdict.status == DkimStatus::None {
            continue;
        }
        let mut line = format!("dkim={}", verdict.status.keyword());
        if !verdict.domain.is_empty() {
            line.push_str(" header.d=");
            line.push_str(&sanitize(&verdict.domain));
        }
        methods.push(line);
    }

    // ── DMARC ──
    let mut dmarc = format!("dmarc={}", check.status.keyword());
    if !check.domain.is_empty() {
        dmarc.push_str(" header.from=");
        dmarc.push_str(&sanitize(&check.domain));
    }
    if let Some(policy) = dmarc_policy(&check.policy) {
        dmarc.push_str(" policy=");
        dmarc.push_str(policy);
    }
    methods.push(dmarc);

    // ── ARC ──
    if let Some(arc) = arc {
        methods.push(format!("arc={}", arc.status.keyword()));
    }

    let mut out = String::with_capacity(128);
    out.push_str("Authentication-Results: ");
    out.push_str(&sanitize(hostname));
    for method in &methods {
        out.push(';');
        // RFC 5322 折行：CRLF + WSP（制表符）。
        out.push_str("\r\n\t");
        out.push_str(method);
    }
    out.push_str("\r\n");
    out
}

/// 只接受标准的三种 DMARC 策略；其余（含空串与 `{:?}` 出来的怪值）一律不输出。
fn dmarc_policy(policy: &str) -> Option<&'static str> {
    match policy {
        "none" => Some("none"),
        "quarantine" => Some("quarantine"),
        "reject" => Some("reject"),
        _ => None,
    }
}

/// 去掉会破坏头分帧的字符（CR / LF / NUL 及其它控制字符）。
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_auth::{ArcStatus, DkimVerdict, DmarcStatus, SpfCheck, SpfStatus};

    fn check(spf: SpfStatus, dmarc: DmarcStatus, dkim: Vec<DkimVerdict>) -> DmarcCheck {
        DmarcCheck {
            status: dmarc,
            domain: "example.com".to_string(),
            policy: "reject".to_string(),
            spf: SpfCheck {
                status: spf,
                domain: "example.com".to_string(),
                explanation: None,
            },
            dkim,
        }
    }

    #[test]
    fn a_passing_message_renders_all_methods() {
        let check = check(
            SpfStatus::Pass,
            DmarcStatus::Pass,
            vec![DkimVerdict {
                domain: "example.com".to_string(),
                selector: "mailstack".to_string(),
                status: DkimStatus::Pass,
            }],
        );
        let header = render("mail.example.org", "alice@example.com", &check, None);
        assert!(header.starts_with("Authentication-Results: mail.example.org;"));
        assert!(header.contains("spf=pass smtp.mailfrom=alice@example.com"));
        assert!(header.contains("dkim=pass header.d=example.com"));
        assert!(header.contains("dmarc=pass header.from=example.com policy=reject"));
        assert!(header.ends_with("\r\n"));
    }

    #[test]
    fn crlf_in_injected_values_cannot_forge_a_new_header() {
        // 头注入：发件人里带 CRLF 时必须被压成同一行的普通字符。
        let check = check(SpfStatus::Fail, DmarcStatus::Fail("x".into()), Vec::new());
        let header = render(
            "mail.example.org",
            "alice@example.com\r\nAuthentication-Results: forged; dmarc=pass",
            &check,
            None,
        );
        // 除折行（CRLF + TAB）外，不得出现任何「CRLF 后直接跟非空白」的情况。
        for (index, line) in header.split("\r\n").enumerate() {
            if index == 0 {
                continue;
            }
            assert!(
                line.starts_with('\t') || line.is_empty(),
                "折行后必须是空白续行，实际：{line:?}"
            );
        }
        assert!(
            !header.contains("\r\nAuthentication-Results: forged"),
            "对端注入的第二条头不得出现：{header:?}"
        );
    }

    #[test]
    fn a_control_character_in_the_hostname_cannot_break_framing() {
        let check = check(SpfStatus::None, DmarcStatus::None, Vec::new());
        let header = render("mail\r\nevil", "a@b.test", &check, None);
        assert!(!header.contains("\r\nevil"));
    }

    #[test]
    fn non_standard_policies_are_not_echoed() {
        let mut check = check(SpfStatus::None, DmarcStatus::None, Vec::new());
        check.policy = "something-weird".to_string();
        let header = render("mail.example.org", "a@b.test", &check, None);
        assert!(
            !header.contains("policy="),
            "非标准策略不得回显：{header:?}"
        );
    }

    #[test]
    fn arc_is_omitted_when_there_is_no_verdict() {
        let check = check(SpfStatus::None, DmarcStatus::None, Vec::new());
        let header = render("mail.example.org", "a@b.test", &check, None);
        // 注意不能用 `contains("arc=")`：`dmarc=` 里就含 `arc=` 这个子串。
        assert!(
            !header.contains("\tarc="),
            "没有 ARC 结论时不应写 arc=：{header:?}"
        );

        let with_arc = render(
            "mail.example.org",
            "a@b.test",
            &check,
            Some(&ArcVerdict {
                status: ArcStatus::Pass,
                sets: 1,
            }),
        );
        assert!(with_arc.contains("arc=pass"));
    }

    #[test]
    fn a_null_sender_omits_the_smtp_mailfrom_property() {
        let check = check(SpfStatus::None, DmarcStatus::None, Vec::new());
        let header = render("mail.example.org", "", &check, None);
        assert!(header.contains("spf=none;"), "{header:?}");
        assert!(!header.contains("smtp.mailfrom="));
    }
}

use mailstack_auth::{ArcVerdict, DkimStatus, DmarcCheck};

pub fn render(
    hostname: &str,
    mail_from: &str,
    check: &DmarcCheck,
    arc: Option<&ArcVerdict>,
) -> String {
    let mut methods: Vec<String> = Vec::new();

    let mut spf = format!("spf={}", check.spf.status.keyword());
    if !mail_from.is_empty() {
        spf.push_str(" smtp.mailfrom=");
        spf.push_str(&quoted_value(mail_from));
    }
    methods.push(spf);

    for verdict in &check.dkim {
        if verdict.status == DkimStatus::None {
            continue;
        }
        let mut line = format!("dkim={}", verdict.status.keyword());
        if !verdict.domain.is_empty() {
            line.push_str(" header.d=");
            line.push_str(&quoted_value(&verdict.domain));
        }
        methods.push(line);
    }

    let mut dmarc = format!("dmarc={}", check.status.keyword());
    if !check.domain.is_empty() {
        dmarc.push_str(" header.from=");
        dmarc.push_str(&quoted_value(&check.domain));
    }
    if let Some(policy) = dmarc_policy(&check.policy) {
        dmarc.push_str(" policy=");
        dmarc.push_str(policy);
    }
    methods.push(dmarc);

    if let Some(arc) = arc {
        methods.push(format!("arc={}", arc.status.keyword()));
    }

    let mut out = String::with_capacity(128);
    out.push_str("Authentication-Results: ");
    out.push_str(&sanitize(hostname));
    for method in &methods {
        out.push(';');

        out.push_str("\r\n\t");
        out.push_str(method);
    }
    out.push_str("\r\n");
    out
}

fn dmarc_policy(policy: &str) -> Option<&'static str> {
    match policy {
        "none" => Some("none"),
        "quarantine" => Some("quarantine"),
        "reject" => Some("reject"),
        _ => None,
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn quoted_value(value: &str) -> String {
    let sanitized = sanitize(value);
    if !sanitized.chars().any(|c| matches!(c, ';' | '"' | '\\')) {
        return sanitized;
    }
    let mut out = String::with_capacity(sanitized.len() + 2);
    out.push('"');
    for c in sanitized.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_auth::{ArcStatus, DkimVerdict, DmarcPolicy, DmarcStatus, SpfCheck, SpfStatus};

    fn check(spf: SpfStatus, dmarc: DmarcStatus, dkim: Vec<DkimVerdict>) -> DmarcCheck {
        DmarcCheck {
            status: dmarc,
            domain: "example.com".to_string(),
            policy: "reject".to_string(),
            policy_value: DmarcPolicy::Reject,
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
        let check = check(SpfStatus::Fail, DmarcStatus::Fail("x".into()), Vec::new());
        let header = render(
            "mail.example.org",
            "alice@example.com\r\nAuthentication-Results: forged; dmarc=pass",
            &check,
            None,
        );

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

    fn parse_sections(header: &str) -> Vec<String> {
        let value = header
            .trim_end_matches("\r\n")
            .trim_start_matches("Authentication-Results: ");
        let mut sections = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = value.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' if in_quotes => {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                }
                '"' => {
                    in_quotes = !in_quotes;
                }
                ';' if !in_quotes => sections.push(std::mem::take(&mut current)),
                other => current.push(other),
            }
        }
        sections.push(current);
        sections
    }

    fn property(header: &str, ptype: &str) -> Option<String> {
        let prefix = format!("{ptype}=");
        let mut from = 0;
        while let Some(at) = header[from..].find(&prefix) {
            let start = from + at + prefix.len();

            let preceded_by_space = start == prefix.len()
                || header[..start - prefix.len()]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace);
            if !preceded_by_space {
                from = start;
                continue;
            }
            let mut chars = header[start..].chars();
            if chars.next() != Some('"') {
                return Some(chars.take_while(|c| !c.is_whitespace()).collect::<String>());
            }
            let mut value = String::new();
            let mut escaped = false;
            for c in chars {
                if escaped {
                    value.push(c);
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    return Some(value);
                } else {
                    value.push(c);
                }
            }
            return None;
        }
        None
    }

    #[test]
    fn a_semicolon_in_the_envelope_sender_cannot_forge_a_method_section() {
        let check = check(SpfStatus::Fail, DmarcStatus::Fail("x".into()), Vec::new());
        let header = render("mail.example.org", "a;dmarc=pass@evil.com", &check, None);

        let sections = parse_sections(&header);
        assert_eq!(
            sections.len(),
            3,
            "发件人不得凭空多出方法段（实际 {sections:?}）"
        );
        assert!(
            sections[0].trim() == "mail.example.org",
            "首段是 authserv-id：{sections:?}"
        );
        assert!(
            sections[1].contains("spf=fail") && sections[2].contains("dmarc=fail"),
            "本机的结论必须仍在原处：{sections:?}"
        );

        assert!(
            !sections
                .iter()
                .any(|section| section.trim_start().starts_with("dmarc=pass")),
            "伪造的 dmarc=pass 段独立存在：{sections:?}"
        );

        assert_eq!(
            property(&header, "smtp.mailfrom").as_deref(),
            Some("a;dmarc=pass@evil.com"),
            "加引号不得改变地址语义"
        );
    }

    #[test]
    fn a_semicolon_in_a_dkim_domain_cannot_forge_a_method_section() {
        let mut check = check(
            SpfStatus::None,
            DmarcStatus::None,
            vec![DkimVerdict {
                domain: "d;spf=pass".to_string(),
                selector: "mailstack".to_string(),
                status: DkimStatus::Pass,
            }],
        );
        check.domain.clear();
        let header = render("mail.example.org", "a@b.test", &check, None);
        let sections = parse_sections(&header);

        assert_eq!(sections.len(), 4, "{sections:?}");
        assert!(
            !sections
                .iter()
                .any(|section| section.trim_start().starts_with("spf=pass")),
            "伪造的 spf=pass 段独立存在：{sections:?}"
        );
        assert_eq!(
            property(&header, "header.d").as_deref(),
            Some("d;spf=pass"),
            "DKIM 域的引号内容必须能还原为原值"
        );
    }

    #[test]
    fn a_special_character_in_a_value_is_quoted_rather_than_deleted() {
        let check = check(SpfStatus::None, DmarcStatus::None, Vec::new());
        let header = render("mail.example.org", "a;b@example.com", &check, None);
        assert!(
            header.contains("smtp.mailfrom=\"a;b@example.com\""),
            "含 `;` 的发件人必须被引号包住：{header:?}"
        );

        assert!(
            header.contains("a;b@example.com"),
            "不得删掉 `;`：{header:?}"
        );
    }

    #[test]
    fn an_ordinary_sender_and_display_name_form_are_rendered_unchanged() {
        let check = check(SpfStatus::Pass, DmarcStatus::Pass, Vec::new());
        for sender in [
            "alice@example.com",
            "alice.smith+tag@example.com",
            "Display Name <alice@example.com>",
            "a!#$%&'*+-/=?^_`{|}~b@example.com",
        ] {
            let header = render("mail.example.org", sender, &check, None);
            assert!(
                header.contains(&format!("smtp.mailfrom={sender}")),
                "{sender:?} 的渲染结果被改动了：{header:?}"
            );
            assert!(
                !header.contains("smtp.mailfrom=\""),
                "{sender:?} 不该被加引号：{header:?}"
            );
        }
    }

    #[test]
    fn a_bare_quote_in_a_value_is_quoted_rather_than_left_illegal() {
        let check = check(SpfStatus::None, DmarcStatus::None, Vec::new());
        let header = render(
            "mail.example.org",
            "\"Quoted Name\" <bob@example.com>",
            &check,
            None,
        );
        assert!(
            header.contains(r#"smtp.mailfrom="\"Quoted Name\" <bob@example.com>""#),
            "裸引号必须被转义并加引号：{header:?}"
        );
        let sections = parse_sections(&header);
        assert_eq!(sections.len(), 3, "{sections:?}");
        assert_eq!(
            property(&header, "smtp.mailfrom").as_deref(),
            Some("\"Quoted Name\" <bob@example.com>"),
            "转义后必须能还原为原值"
        );
    }

    #[test]
    fn a_quote_or_backslash_in_a_value_cannot_break_out_of_the_quoting() {
        let check = check(SpfStatus::None, DmarcStatus::None, Vec::new());
        for sender in [
            "a\";dmarc=pass@evil.com",
            "a\\@evil.com",
            "a\\\";dmarc=pass@evil.com",
        ] {
            let header = render("mail.example.org", sender, &check, None);
            let sections = parse_sections(&header);
            assert_eq!(
                sections.len(),
                3,
                "{sender:?} 不得改变分词结果（实际 {sections:?}）"
            );
            assert!(
                !sections
                    .iter()
                    .any(|section| section.trim_start().starts_with("dmarc=pass")),
                "{sender:?} 伪造的段独立存在：{sections:?}"
            );
            assert_eq!(
                property(&header, "smtp.mailfrom").as_deref(),
                Some(sender),
                "{sender:?} 转义后必须能还原为原值"
            );
        }
    }
}

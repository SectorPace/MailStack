//! `Authentication-Results` 头的渲染（RFC 8601）。
//!
//! ## 为什么必须在这里净化
//!
//! 这个头里要塞进**对端可控**的字符串（信封发件人、DKIM 的 `d=` 域、DMARC 的域）。
//! 如果其中混进 `\r\n`，接收方读到的就是**两个头** —— 攻击者可以让自己的报文带上
//! 一条伪造的 `Authentication-Results: ...; dmarc=pass`。这与应答注入同源，防线
//! 必须放在**唯一的渲染入口**上。
//!
//! 因此本模块只做三件事：把判定结果映射成 RFC 8601 关键字、把所有插入值过滤成
//! 「不含控制字符」的字符串、并对**值**按 RFC 8601 §2.4 加引号。
//! **不**把 fail 的具体原因写进去 —— 那些文本来自解析器，既没有标准形态、
//! 也没有净化过。
//!
//! ## 为什么 `sanitize` 单独不够：`;` 是分词符，不是控制字符
//!
//! 下游普遍按 `;` 切分这个头来取方法与结论（`;` 是 RFC 8601 的 special 字符）。
//! `sanitize` 只处理控制字符，而 `;` 不是控制字符 —— 于是
//! `MAIL FROM:<a;dmarc=pass;x@evil.com>` 会让接收方**以为**本机在真实的
//! authserv-id 下给出了一个 `dmarc=pass` 结论，直接污染下游判定。
//!
//! 防线因此是 RFC 8601 规定的手段：含 special 的值加**引号**。不用「删字符」——
//! 删掉 `;` 会改变地址语义、还可能让地址解析失败，属于用破坏数据换安全。

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
        spf.push_str(&quoted_value(mail_from));
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
            line.push_str(&quoted_value(&verdict.domain));
        }
        methods.push(line);
    }

    // ── DMARC ──
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

/// 净化**并**按 RFC 8601 §2.4 加引号：值里含 special 字符就整段包进双引号。
///
/// ## 为什么不能只 sanitize
///
/// `;` 是这个头的分词符。不带引号的 `a;dmarc=pass@evil.com` 会被下游 split 出
/// 一个看似合法的 `dmarc=pass` 段 —— 伪造的是「本机的结论」，不是垃圾内容。
///
/// ## 为什么是加引号而不是删字符
///
/// RFC 8601 把「用引号把值包起来」列为 special 字符的处理手段。删 `;`
/// 会把地址改成另一个地址（还可能让地址解析直接失败），那是**改变语义**；
/// 而引号只影响「怎么分词」，不改变值本身 —— 合法地址里的 `;` 依然原样保留，
/// 下游按引号规则 unquote 后拿到的仍是原地址。
///
/// ## 为什么触发集只有这三个字符
///
/// RFC 8601 §2.2 自带的 `token` 允许 `@ : % = / ?` 等字符（这正是真实 MTAs
/// 写出 `smtp.mailfrom=alice@example.com` 这种**不带引号**地址的依据）。
/// 真正会改变解析的只有三类：`;`（段分隔符）、`"` 与 `\`（quoted-string 自身的
/// special）。把它们合起来就是「能让分词器把值当成别的东西」的全部字符。
///
/// 引号与反斜杠按 RFC 5322 quoted-string 规则转义（`\"` / `\\`）—— 不转义的话，
/// 一个尾随的反斜杠会把闭合引号吃掉，帧结构就散了。
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

    /// 一个**符合 RFC 8601** 的分词器：按 `;` 切段，但引号内的 `;` 不切，
    /// 并把 quoted-string 还原成原值。
    ///
    /// ## 为什么要自己写一个而不是 `split(';')`
    ///
    /// RFC 8601 之所以规定「含 special 的值加引号」，前提就是**解析方按引号
    /// 规则切**。用 naive 的 `split(';')` 去断言「段数不变」，等于要求「值里干脆
    /// 不许出现 `;`」—— 那不是 RFC 的要求，且会逼我们删字符（改变地址语义）。
    /// 正确的判据是：**按标准解析时**段结构不变、且引号内内容能还原成原值。
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
                    // quoted-pair：反斜杠吞掉下一个字符，原样输出。
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

    /// 取出某个 ptype 的值（从**原始头**里按 RFC 8601 解析），已还原引号与转义。
    ///
    /// 这一段刻意写成「一个真实下游会做的解析」：找到 `ptype=`，若下一个字符是
    /// `"` 就按 quoted-string 读到闭合引号（并处理 `\\` / `\"`），否则读到空白。
    /// 断言「解析回来的值 == 原值」因此是在验证**互操作性**，而不是在验证
    /// 我们自己的输出长相。
    fn property(header: &str, ptype: &str) -> Option<String> {
        let prefix = format!("{ptype}=");
        let mut from = 0;
        while let Some(at) = header[from..].find(&prefix) {
            let start = from + at + prefix.len();
            // 只接受「前面是空白或行首」的那一处，避免 `xheader.d=` 之类误命中。
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

    /// 反例守卫：信封发件人里的 `;` **不得**变成一个新方法段。
    ///
    /// 这条断言写的是「下游按 RFC 解析会看到什么」。`MAIL FROM:<a;dmarc=pass@…>`
    /// 若原样进入头里，下游就会数出一个独立的 `dmarc=pass` 段 —— 那是**伪造
    /// 本机的结论**，会污染接收方的判定，而不只是多了几个字符。
    #[test]
    fn a_semicolon_in_the_envelope_sender_cannot_forge_a_method_section() {
        let check = check(SpfStatus::Fail, DmarcStatus::Fail("x".into()), Vec::new());
        let header = render("mail.example.org", "a;dmarc=pass@evil.com", &check, None);

        // authserv-id + spf + dmarc：三段，与不加引号时完全一致。
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
        // 关键：没有任何一段是伪造的 `dmarc=pass`。
        assert!(
            !sections
                .iter()
                .any(|section| section.trim_start().starts_with("dmarc=pass")),
            "伪造的 dmarc=pass 段独立存在：{sections:?}"
        );
        // 而且引号内的内容还原后**就是原地址** —— 没有被删改。
        assert_eq!(
            property(&header, "smtp.mailfrom").as_deref(),
            Some("a;dmarc=pass@evil.com"),
            "加引号不得改变地址语义"
        );
    }

    /// 同一条防线在 DKIM `header.d=` 上也成立 —— DKIM 域来自签名，同样是对端可控。
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
        // authserv-id + spf + dkim + dmarc。
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

    /// 值里含 `;` 时必须**加引号**，而不是把字符删掉。
    ///
    /// 删字符是把 `a;b@c` 改成 `ab@c` —— 收件人读到的是另一个地址，
    /// 且解析可能直接失败。加引号只影响分词，unquote 后仍是原值。
    #[test]
    fn a_special_character_in_a_value_is_quoted_rather_than_deleted() {
        let check = check(SpfStatus::None, DmarcStatus::None, Vec::new());
        let header = render("mail.example.org", "a;b@example.com", &check, None);
        assert!(
            header.contains("smtp.mailfrom=\"a;b@example.com\""),
            "含 `;` 的发件人必须被引号包住：{header:?}"
        );
        // 引号内的 `;` 仍是原值的一部分：地址语义没有被改写。
        assert!(
            header.contains("a;b@example.com"),
            "不得删掉 `;`：{header:?}"
        );
    }

    /// 回归守卫：**正常发件人渲染结果一字不变**。
    ///
    /// 加引号最容易出的错是「顺手给所有值都加了引号」—— 那会让所有下游的
    /// 精确匹配（`smtp.mailfrom=alice@example.com`）全部失配。
    ///
    /// 注意 `Display Name <a@b>` 这种带空格的形态：RFC 8601 §2.2 的 `token`
    /// 不含 `@`，但真实 MTA（含本项目）一直是不加引号写裸地址的，因此
    /// **不得**因为出现了 `@` 或空格就去加引号。
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

    /// 值里的**裸引号**必须被转义 —— RFC 8601 §2.2 的 `qtextSMTP` 明确不含
    /// DQUOTE 与反斜杠，裸着出现在值里就是不合法的帧。
    ///
    /// `Display Name` 带引号的写法（RFC 5322 的 display-name）因此**会**被加引号，
    /// 这不是过度处理：信封发件人里带引号的形态本身就能让引号配平失效。
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

    /// 引号本身与反斜杠必须转义，否则会「吃掉闭合引号」让引号配平失效 ——
    /// 一旦引号没闭合，后面的 `;` 就重新变成活的分隔符。
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

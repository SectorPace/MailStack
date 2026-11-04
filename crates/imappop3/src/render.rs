pub fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\r' | '\n' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub fn string(value: &str) -> String {
    let needs_literal = value
        .chars()
        .any(|ch| ch as u32 > 0x7f || (ch.is_control() && ch != '\t'));
    if needs_literal {
        format!("{{{}}}\r\n{}", value.len(), value)
    } else {
        quoted(value)
    }
}

pub fn nstring(value: Option<&str>) -> String {
    match value {
        Some(value) => string(value),
        None => "NIL".to_string(),
    }
}

pub fn push_nstring(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => out.extend_from_slice(b"NIL"),
        Some(value) => {
            let needs_literal = value
                .chars()
                .any(|ch| ch as u32 > 0x7f || (ch.is_control() && ch != '\t'));
            if needs_literal {
                out.extend_from_slice(format!("{{{}}}\r\n", value.len()).as_bytes());
                out.extend_from_slice(value.as_bytes());
            } else {
                out.extend_from_slice(quoted(value).as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_escapes_backslash_and_quote() {
        assert_eq!(quoted(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quoted("plain"), "\"plain\"");
    }

    #[test]
    fn crlf_is_replaced_not_escaped() {
        assert_eq!(quoted("a\r\nb"), "\"a  b\"");
    }

    #[test]
    fn non_ascii_uses_a_literal() {
        assert_eq!(string("主题"), "{6}\r\n主题");
        assert_eq!(nstring(None), "NIL");
        assert_eq!(nstring(Some("x")), "\"x\"");
    }

    #[test]
    fn push_keeps_literal_bytes_intact() {
        let mut out = Vec::new();
        push_nstring(&mut out, Some("a\u{7f}b"));
        assert!(out.starts_with(b"{3}\r\n"));
        assert_eq!(&out[5..], "a\u{7f}b".as_bytes());
    }
}

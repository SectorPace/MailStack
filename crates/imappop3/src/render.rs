//! IMAP 应答里的字符串渲染（quoted string / literal / NIL）。
//!
//! 规则来自 RFC 3501 §4.3：
//!
//! * quoted string 只能是 **7 位**字符，且不能含 CR/LF；`\` 与 `"` 必须转义；
//! * 非 ASCII（邮箱名、主题、地址）只能走 literal（`{n}\r\n<bytes>`）；
//! * `NIL` 与 `""` 语义不同，缺值必须渲染成 `NIL`。
//!
//! 把这三件事收敛到一处，是因为它们同时出现在 ENVELOPE、LIST、STATUS、FETCH
//! 与邮箱名回显里。分散实现时最典型的缺陷是「非 ASCII 主题直接塞进 quoted
//! string」—— 大多数客户端能忍，但严格解析器会在第一个非 ASCII 字节处报错。

/// quoted string。含 CR/LF 时替换为空格：协议不允许这两个字节，而 `NIL` 又会
/// 把「有值但不可渲染」伪装成「没有值」。
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

/// 非 ASCII 或含控制字符时改用 literal；否则用 quoted。
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

/// 写进字节缓冲的版本：literal 会先写标签，再把原始字节追加进去。
///
/// `string(value)` 的返回值已经是「标签 + 内容」的拼接，对纯 ASCII 值没问题；
/// 对 literal 值，内容里的任意字节（包括 NUL）都必须原样保留 —— 因此这里用
/// `extend_from_slice` 而不是 `format!` 到一个 `String`。
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
        // quoted string 不得含 CR/LF；替换成空格而不是让应答跨行。
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

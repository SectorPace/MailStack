//! 输入校验正则 —— 与 `core.py:12-16` 逐字一致。
//!
//! 任何改动都会改变对外契约（域名/邮箱/队列 ID 的接受面），故必须保持等价。

use std::sync::LazyLock;

use regex::Regex;

/// `^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`
pub static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$").unwrap()
});

/// `^[a-z_][a-z0-9_-]{0,30}$`
pub static USER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z_][a-z0-9_-]{0,30}$").unwrap());

/// `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@[A-Za-z0-9.-]+$`
pub static ADDRESS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@[A-Za-z0-9.-]+$").unwrap());

/// `^[A-F0-9]{5,20}[*!]?$`
pub static QUEUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-F0-9]{5,20}[*!]?$").unwrap());

/// `^[A-Za-z][A-Za-z0-9_.-]{2,31}$` —— 管理员名 3–32 字符。
pub static ADMIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$").unwrap());

/// `^[A-Za-z0-9_-]{1,63}$` —— DKIM selector。
pub static DKIM_SELECTOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,63}$").unwrap());

/// 中继主机名：`[A-Za-z0-9.-]{1,253}`，且不得以 `.` 开头/结尾、不得含 `..`。
pub fn is_valid_relay_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return false;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_regex_accepts_and_rejects_like_python() {
        for ok in [
            "example.com",
            "mail.example.co.uk",
            "a.io",
            "sub-domain.example.org",
        ] {
            assert!(DOMAIN_RE.is_match(ok), "{ok} 应被接受");
        }
        for bad in [
            "example",
            "example.",
            "-bad.com",
            "bad-.com",
            "exa mple.com",
            "",
        ] {
            assert!(!DOMAIN_RE.is_match(bad), "{bad} 应被拒绝");
        }
    }

    #[test]
    fn admin_regex_requires_three_to_thirty_two_chars() {
        assert!(ADMIN_RE.is_match("admin"));
        assert!(ADMIN_RE.is_match("a.b-c_d"));
        assert!(!ADMIN_RE.is_match("ab"), "2 字符应被拒绝");
        assert!(!ADMIN_RE.is_match("1admin"), "不得以数字开头");
        assert!(!ADMIN_RE.is_match(&"a".repeat(33)), "33 字符应被拒绝");
    }

    #[test]
    fn user_regex_is_lowercase_local_part() {
        assert!(USER_RE.is_match("alice"));
        assert!(USER_RE.is_match("_svc"));
        assert!(!USER_RE.is_match("Alice"));
        assert!(!USER_RE.is_match("1alice"));
    }

    #[test]
    fn queue_regex_accepts_hex_with_optional_marker() {
        assert!(QUEUE_RE.is_match("1A2B3"));
        assert!(QUEUE_RE.is_match("ABCDEF1234!"));
        assert!(QUEUE_RE.is_match("ABCDEF1234*"));
        assert!(!QUEUE_RE.is_match("abcdef1"), "小写应被拒绝");
        assert!(!QUEUE_RE.is_match("1A2"), "过短应被拒绝");
    }

    #[test]
    fn relay_host_rejects_dot_edges_and_double_dots() {
        assert!(is_valid_relay_host("smtp.sendgrid.net"));
        assert!(is_valid_relay_host("127.0.0.1"));
        assert!(!is_valid_relay_host(".example.com"));
        assert!(!is_valid_relay_host("example.com."));
        assert!(!is_valid_relay_host("exa..mple.com"));
        assert!(!is_valid_relay_host("bad host"));
        assert!(!is_valid_relay_host(""));
    }
}

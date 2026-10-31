//! SORT（RFC 5256）排序键与比较器。
//!
//! 与 SEARCH 共用条件解析；这里只负责把命中的邮件按 `(SORT criteria)` 排序。
//! 头字段类排序（FROM/TO/CC/SUBJECT/DATE）需要读取邮件头；调用方按
//! [`needs_headers`] 决定是否读文件。

use crate::date;
use crate::error::{MailError, Result};
use crate::imap::parser::Token;
use crate::maildir::MessageMeta;
use crate::mime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Arrival,
    Cc,
    Date,
    /// RFC 5957：按 From 的显示名（无显示名时用地址）排序。
    Display,
    From,
    Size,
    Subject,
    To,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortKey {
    pub field: SortField,
    pub reverse: bool,
}

pub fn parse_criteria(tokens: &[Token]) -> Result<Vec<SortKey>> {
    let mut keys = Vec::new();
    let mut reverse = false;
    for token in tokens {
        let atom = token
            .as_atom()
            .ok_or_else(|| MailError::invalid("SORT criteria must be atoms"))?;
        if atom.eq_ignore_ascii_case("REVERSE") {
            if reverse {
                return Err(MailError::invalid("REVERSE cannot be repeated"));
            }
            reverse = true;
            continue;
        }
        let field = match atom.to_ascii_uppercase().as_str() {
            "ARRIVAL" => SortField::Arrival,
            "CC" => SortField::Cc,
            "DATE" => SortField::Date,
            "DISPLAY" => SortField::Display,
            "FROM" => SortField::From,
            "SIZE" => SortField::Size,
            "SUBJECT" => SortField::Subject,
            "TO" => SortField::To,
            _ => {
                return Err(MailError::invalid(format!(
                    "unsupported SORT criterion: {atom}"
                )))
            }
        };
        keys.push(SortKey { field, reverse });
        reverse = false;
    }
    if reverse {
        return Err(MailError::invalid(
            "REVERSE must be followed by a criterion",
        ));
    }
    if keys.is_empty() {
        return Err(MailError::invalid("SORT requires at least one criterion"));
    }
    Ok(keys)
}

pub fn needs_headers(keys: &[SortKey]) -> bool {
    keys.iter()
        .any(|key| !matches!(key.field, SortField::Arrival | SortField::Size))
}

#[derive(Debug, Default)]
pub struct SortValues {
    pub arrival: i64,
    pub date: i64,
    pub size: u64,
    pub cc: String,
    pub display: String,
    pub from: String,
    pub subject: String,
    pub to: String,
}

pub fn values(meta: &MessageMeta, message: &[u8], keys: &[SortKey]) -> SortValues {
    let mut values = SortValues {
        arrival: meta.internal_date,
        size: meta.size,
        ..SortValues::default()
    };
    if !needs_headers(keys) {
        return values;
    }
    let headers = mime::parse_headers(message);
    values.date = headers
        .get("date")
        .and_then(date::parse_header_date)
        .unwrap_or(0);
    values.cc = headers.get("cc").unwrap_or("").to_ascii_lowercase();
    values.from = headers.get("from").unwrap_or("").to_ascii_lowercase();
    values.subject = headers.get("subject").unwrap_or("").to_ascii_lowercase();
    values.to = headers.get("to").unwrap_or("").to_ascii_lowercase();
    // RFC 5957：DISPLAY 用第一个 From 地址的显示名，缺省用地址本身。
    values.display = mime::parse_addresses(headers.get("from").unwrap_or(""))
        .first()
        .map(|address| {
            if address.name.is_empty() {
                address.mailbox.clone()
            } else {
                address.name.clone()
            }
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    values
}

fn compare_key(key: &SortKey, a: &SortValues, b: &SortValues) -> std::cmp::Ordering {
    let ordering = match key.field {
        SortField::Arrival => a.arrival.cmp(&b.arrival),
        SortField::Date => a.date.cmp(&b.date),
        SortField::Size => a.size.cmp(&b.size),
        SortField::Cc => a.cc.cmp(&b.cc),
        SortField::Display => a.display.cmp(&b.display),
        SortField::From => a.from.cmp(&b.from),
        SortField::Subject => a.subject.cmp(&b.subject),
        SortField::To => a.to.cmp(&b.to),
    };
    if key.reverse {
        ordering.reverse()
    } else {
        ordering
    }
}

/// 排序并返回编号（序号或 UID，由调用方决定）。同键时按编号升序稳定。
pub fn sort(mut items: Vec<(u32, SortValues)>, keys: &[SortKey]) -> Vec<u32> {
    items.sort_by(|(a_number, a), (b_number, b)| {
        for key in keys {
            let ordering = compare_key(key, a, b);
            if ordering != std::cmp::Ordering::Equal {
                return ordering;
            }
        }
        a_number.cmp(b_number)
    });
    items.into_iter().map(|(number, _)| number).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap::parser::Token;

    fn atom(value: &str) -> Token {
        Token::Atom(value.to_string())
    }

    fn meta(uid: u32, size: u64, date: i64) -> MessageMeta {
        MessageMeta {
            uid,
            base: format!("base{uid}"),
            filename: format!("base{uid}:2,"),
            path: std::path::PathBuf::from("/x"),
            size,
            internal_date: date,
            modseq: 1,
            flags: Default::default(),
            recent: false,
        }
    }

    #[test]
    fn criteria_parse_reverse_and_reject_bad_input() {
        let keys = parse_criteria(&[atom("REVERSE"), atom("DATE"), atom("SUBJECT")]).unwrap();
        assert_eq!(
            keys,
            vec![
                SortKey {
                    field: SortField::Date,
                    reverse: true
                },
                SortKey {
                    field: SortField::Subject,
                    reverse: false
                }
            ]
        );
        assert!(parse_criteria(&[atom("REVERSE")]).is_err());
        assert!(parse_criteria(&[atom("BOGUS")]).is_err());
        assert!(parse_criteria(&[]).is_err());
    }

    #[test]
    fn sorting_uses_headers_and_stable_ties() {
        let messages = [
            (
                meta(1, 10, 100),
                b"Subject: Zebra\r\nDate: Fri, 23 Oct 2026 14:30:00 +0000\r\n\r\nx".to_vec(),
            ),
            (
                meta(2, 10, 200),
                b"Subject: alpha\r\nDate: Fri, 20 Oct 2026 14:30:00 +0000\r\n\r\nx".to_vec(),
            ),
            (
                meta(3, 20, 300),
                b"Subject: Alpha\r\nDate: Fri, 19 Oct 2026 14:30:00 +0000\r\n\r\nx".to_vec(),
            ),
        ];
        let keys = parse_criteria(&[atom("SUBJECT")]).unwrap();
        let items: Vec<(u32, SortValues)> = messages
            .iter()
            .map(|(meta, message)| (meta.uid, values(meta, message, &keys)))
            .collect();
        assert_eq!(sort(items, &keys), vec![2, 3, 1]);

        let keys = parse_criteria(&[atom("REVERSE"), atom("DATE")]).unwrap();
        let items: Vec<(u32, SortValues)> = messages
            .iter()
            .map(|(meta, message)| (meta.uid, values(meta, message, &keys)))
            .collect();
        assert_eq!(sort(items, &keys), vec![1, 2, 3]);

        let keys = parse_criteria(&[atom("SIZE")]).unwrap();
        let items: Vec<(u32, SortValues)> = messages
            .iter()
            .map(|(meta, message)| (meta.uid, values(meta, message, &keys)))
            .collect();
        assert_eq!(sort(items, &keys), vec![1, 2, 3]);
    }

    #[test]
    fn display_sorts_by_from_display_name_with_address_fallback() {
        let messages = [
            (
                meta(1, 10, 100),
                b"From: \"Zoe\" <zoe@example.com>\r\n\r\nx".to_vec(),
            ),
            (
                meta(2, 10, 200),
                b"From: alice@example.com\r\n\r\nx".to_vec(),
            ),
            (
                meta(3, 10, 300),
                b"From: Bob <bob@example.com>\r\n\r\nx".to_vec(),
            ),
        ];
        let keys = parse_criteria(&[atom("DISPLAY")]).unwrap();
        let items: Vec<(u32, SortValues)> = messages
            .iter()
            .map(|(meta, message)| (meta.uid, values(meta, message, &keys)))
            .collect();
        // alice（无显示名 → 地址）、bob、zoe 升序。
        assert_eq!(sort(items, &keys), vec![2, 3, 1]);
        assert!(matches!(keys[0].field, SortField::Display));
    }
}

//! SEARCH 条件解析与匹配（RFC 3501 §6.4.4）。
//!
//! ## 语义要点
//!
//! * 同一层级的多个 key 是 **AND**；`NOT` / `OR` 递归；
//! * 括号里的 key 列表也是 AND（与顶层相同）；
//! * `NEW` = `RECENT` 且未 `\Seen`；`OLD` = 非 `RECENT`；
//! * `BEFORE` / `ON` / `SINCE` 比较 **INTERNALDATE**（服务器收到的时间），
//!   `SENT*` 比较 `Date:` 头 —— 两者不是一回事，混用会让「按收件日期搜索」
//!   在跨时区邮件上返回错误结果；
//! * 文本搜索不区分大小写（ASCII 折叠；UTF-8 非 ASCII 部分按字节比较），
//!   并且**不做 MIME 解码**：`=?UTF-8?B?...?=` 按原文匹配。
//!
//! ## 不支持 CHARSET 时的应答
//!
//! 只接受 `US-ASCII` / `UTF-8`。其它 charset 返回
//! [`SearchError::BadCharset`]，会话层据此回 `NO [BADCHARSET (US-ASCII UTF-8)]`
//! —— 这个专用错误类型存在的唯一理由，就是不要在协议层靠字符串前缀反推错误类别。

use crate::date;
use crate::imap::parser::Token;
use crate::maildir::{Flag, MessageMeta, SystemFlag};
use crate::mime;
use crate::seqset::SequenceSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchError {
    BadCharset(String),
    Invalid(String),
}

impl SearchError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
    And(Vec<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    Not(Box<SearchKey>),
    All,
    System {
        flag: SystemFlag,
        present: bool,
    },
    Keyword {
        keyword: String,
        present: bool,
    },
    Recent,
    New,
    Old,
    Header {
        field: String,
        value: Vec<u8>,
    },
    Body(Vec<u8>),
    Text(Vec<u8>),
    InternalDate {
        kind: DateKind,
        days: i64,
    },
    SentDate {
        kind: DateKind,
        days: i64,
    },
    Larger(u64),
    Smaller(u64),
    /// CONDSTORE：modseq 大于等于给定值的邮件。
    ModSeq(u64),
    Uid(SequenceSet),
    Sequence(SequenceSet),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateKind {
    Before,
    On,
    Since,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchReturn {
    pub min: bool,
    pub max: bool,
    pub all: bool,
    pub count: bool,
    pub save: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSearch {
    pub charset: Option<String>,
    pub key: SearchKey,
    /// RFC 4731 `RETURN (...)`；`None` 表示普通 SEARCH。
    pub options: Option<SearchReturn>,
}

pub fn parse(tokens: &[Token]) -> Result<ParsedSearch, SearchError> {
    if tokens.is_empty() {
        return Err(SearchError::invalid("SEARCH requires at least one key"));
    }
    let mut position = 0usize;
    let mut options = None;
    if let Some(Token::Atom(atom)) = tokens.first() {
        if atom.eq_ignore_ascii_case("RETURN") {
            let list = tokens
                .get(1)
                .and_then(Token::list)
                .ok_or_else(|| SearchError::invalid("RETURN requires an option list"))?;
            if list.is_empty() {
                return Err(SearchError::invalid("RETURN requires at least one option"));
            }
            let mut parsed = SearchReturn::default();
            for option in list {
                let name = token_text(option)?.to_ascii_uppercase();
                match name.as_str() {
                    "MIN" => parsed.min = true,
                    "MAX" => parsed.max = true,
                    "ALL" => parsed.all = true,
                    "COUNT" => parsed.count = true,
                    "SAVE" => parsed.save = true,
                    _ => {
                        return Err(SearchError::invalid(format!(
                            "unknown RETURN option: {name}"
                        )))
                    }
                }
            }
            options = Some(parsed);
            position = 2;
        }
    }

    let mut charset = None;
    if let Some(Token::Atom(atom)) = tokens.get(position) {
        if atom.eq_ignore_ascii_case("CHARSET") {
            let token = tokens
                .get(position + 1)
                .ok_or_else(|| SearchError::invalid("CHARSET requires a value"))?;
            let value = token_text(token)?;
            let normalized = value.to_ascii_uppercase();
            if normalized != "US-ASCII" && normalized != "UTF-8" {
                return Err(SearchError::BadCharset(value));
            }
            charset = Some(value);
            position += 2;
        }
    }
    if position >= tokens.len() {
        return Err(SearchError::invalid("SEARCH requires at least one key"));
    }
    let mut parser = KeyParser { tokens, position };
    let mut keys = Vec::new();
    while parser.position < tokens.len() {
        keys.push(parser.parse_key()?);
    }
    let key = if keys.len() == 1 {
        keys.pop().unwrap_or(SearchKey::All)
    } else {
        SearchKey::And(keys)
    };
    Ok(ParsedSearch {
        charset,
        key,
        options,
    })
}

struct KeyParser<'a> {
    tokens: &'a [Token],
    position: usize,
}

impl<'a> KeyParser<'a> {
    fn next(&mut self) -> Result<&'a Token, SearchError> {
        let token = self
            .tokens
            .get(self.position)
            .ok_or_else(|| SearchError::invalid("SEARCH key is incomplete"))?;
        self.position += 1;
        Ok(token)
    }

    fn string(&mut self) -> Result<Vec<u8>, SearchError> {
        let token = self.next()?;
        token_bytes(token)
    }

    fn number(&mut self) -> Result<u64, SearchError> {
        let text = token_text(self.next()?)?;
        text.parse::<u64>()
            .map_err(|_| SearchError::invalid(format!("invalid number: {text}")))
    }

    fn date(&mut self) -> Result<i64, SearchError> {
        let text = token_text(self.next()?)?;
        date::parse_date_only(&text).map_err(|error| SearchError::invalid(error.to_string()))
    }

    fn parse_key(&mut self) -> Result<SearchKey, SearchError> {
        let token = self.next()?;
        match token {
            Token::List(items) => {
                if items.is_empty() {
                    return Ok(SearchKey::All);
                }
                let mut parser = KeyParser {
                    tokens: items,
                    position: 0,
                };
                let mut keys = Vec::new();
                while parser.position < items.len() {
                    keys.push(parser.parse_key()?);
                }
                Ok(SearchKey::And(keys))
            }
            Token::Atom(atom) => {
                let upper = atom.to_ascii_uppercase();
                match upper.as_str() {
                    "ALL" => Ok(SearchKey::All),
                    "ANSWERED" => Ok(system(SystemFlag::Answered, true)),
                    "UNANSWERED" => Ok(system(SystemFlag::Answered, false)),
                    "DELETED" => Ok(system(SystemFlag::Deleted, true)),
                    "UNDELETED" => Ok(system(SystemFlag::Deleted, false)),
                    "DRAFT" => Ok(system(SystemFlag::Draft, true)),
                    "UNDRAFT" => Ok(system(SystemFlag::Draft, false)),
                    "FLAGGED" => Ok(system(SystemFlag::Flagged, true)),
                    "UNFLAGGED" => Ok(system(SystemFlag::Flagged, false)),
                    "SEEN" => Ok(system(SystemFlag::Seen, true)),
                    "UNSEEN" => Ok(system(SystemFlag::Seen, false)),
                    "NEW" => Ok(SearchKey::New),
                    "OLD" => Ok(SearchKey::Old),
                    "RECENT" => Ok(SearchKey::Recent),
                    "KEYWORD" | "UNKEYWORD" => {
                        let keyword = token_text(self.next()?)?;
                        Ok(SearchKey::Keyword {
                            keyword: keyword.to_ascii_lowercase(),
                            present: upper == "KEYWORD",
                        })
                    }
                    "HEADER" => {
                        let field = token_text(self.next()?)?;
                        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_graphic()) {
                            return Err(SearchError::invalid("invalid header field name"));
                        }
                        let value = self.string()?;
                        Ok(SearchKey::Header {
                            field: field.to_ascii_lowercase(),
                            value,
                        })
                    }
                    "BCC" | "CC" | "FROM" | "SUBJECT" | "TO" => {
                        let value = self.string()?;
                        Ok(SearchKey::Header {
                            field: upper.to_ascii_lowercase(),
                            value,
                        })
                    }
                    "BODY" => Ok(SearchKey::Body(self.string()?)),
                    "TEXT" => Ok(SearchKey::Text(self.string()?)),
                    "BEFORE" | "ON" | "SINCE" => Ok(SearchKey::InternalDate {
                        kind: date_kind(&upper),
                        days: self.date()?,
                    }),
                    "SENTBEFORE" | "SENTON" | "SENTSINCE" => {
                        let kind = match upper.as_str() {
                            "SENTBEFORE" => DateKind::Before,
                            "SENTON" => DateKind::On,
                            _ => DateKind::Since,
                        };
                        Ok(SearchKey::SentDate {
                            kind,
                            days: self.date()?,
                        })
                    }
                    "LARGER" => Ok(SearchKey::Larger(self.number()?)),
                    "SMALLER" => Ok(SearchKey::Smaller(self.number()?)),
                    "MODSEQ" => Ok(SearchKey::ModSeq(self.number()?)),
                    "UID" => {
                        let text = token_text(self.next()?)?;
                        let set = SequenceSet::parse(&text)
                            .map_err(|error| SearchError::invalid(error.to_string()))?;
                        Ok(SearchKey::Uid(set))
                    }
                    "NOT" => Ok(SearchKey::Not(Box::new(self.parse_key()?))),
                    "OR" => {
                        let first = self.parse_key()?;
                        let second = self.parse_key()?;
                        Ok(SearchKey::Or(Box::new(first), Box::new(second)))
                    }
                    "CHARSET" => Err(SearchError::invalid("CHARSET must precede the key list")),
                    _ => {
                        let set = SequenceSet::parse(atom).map_err(|_| {
                            SearchError::invalid(format!("unknown SEARCH key: {atom}"))
                        })?;
                        Ok(SearchKey::Sequence(set))
                    }
                }
            }
            Token::Quoted(value) => {
                let set = SequenceSet::parse(value)
                    .map_err(|_| SearchError::invalid(format!("unknown SEARCH key: {value}")))?;
                Ok(SearchKey::Sequence(set))
            }
            Token::Literal(bytes) => {
                let value = String::from_utf8_lossy(bytes).to_string();
                let set = SequenceSet::parse(&value)
                    .map_err(|_| SearchError::invalid("unknown SEARCH key"))?;
                Ok(SearchKey::Sequence(set))
            }
        }
    }
}

fn system(flag: SystemFlag, present: bool) -> SearchKey {
    SearchKey::System { flag, present }
}

fn date_kind(upper: &str) -> DateKind {
    match upper {
        "BEFORE" => DateKind::Before,
        "ON" => DateKind::On,
        _ => DateKind::Since,
    }
}

fn token_text(token: &Token) -> Result<String, SearchError> {
    token
        .text()
        .ok_or_else(|| SearchError::invalid("expected a string argument"))
}

fn token_bytes(token: &Token) -> Result<Vec<u8>, SearchError> {
    match token {
        Token::Atom(value) | Token::Quoted(value) => Ok(value.as_bytes().to_vec()),
        Token::Literal(bytes) => Ok(bytes.clone()),
        Token::List(_) => Err(SearchError::invalid("expected a string argument")),
    }
}

/// 判断一个条件是否需要读取正文（调用方据此避免无谓的磁盘 I/O）。
pub fn needs_message(key: &SearchKey) -> bool {
    match key {
        SearchKey::And(keys) => keys.iter().any(needs_message),
        SearchKey::Or(first, second) => needs_message(first) || needs_message(second),
        SearchKey::Not(key) => needs_message(key),
        SearchKey::Header { .. }
        | SearchKey::Body(_)
        | SearchKey::Text(_)
        | SearchKey::SentDate { .. } => true,
        _ => false,
    }
}

pub struct SearchContext<'a> {
    pub meta: &'a MessageMeta,
    /// 当前序号（1 起）。
    pub sequence: u32,
    pub max_sequence: u32,
    pub max_uid: u32,
    /// 仅在 [`needs_message`] 为真时被使用；否则可以是空切片。
    pub message: &'a [u8],
}

pub fn matches(key: &SearchKey, context: &SearchContext<'_>) -> bool {
    match key {
        SearchKey::And(keys) => keys.iter().all(|key| matches(key, context)),
        SearchKey::Or(first, second) => matches(first, context) || matches(second, context),
        SearchKey::Not(inner) => !matches(inner, context),
        SearchKey::All => true,
        SearchKey::System { flag, present } => {
            let has = context
                .meta
                .flags
                .iter()
                .any(|candidate| matches!(candidate, Flag::System(system) if system == flag));
            has == *present
        }
        SearchKey::Keyword { keyword, present } => {
            let has = context
                .meta
                .flags
                .iter()
                .any(|candidate| matches!(candidate, Flag::Keyword(name) if name == keyword));
            has == *present
        }
        SearchKey::Recent => context.meta.recent,
        SearchKey::New => context.meta.recent && !context.meta.flags.iter().any(Flag::is_seen),
        SearchKey::Old => !context.meta.recent,
        SearchKey::Header { field, value } => {
            let headers = mime::parse_headers(context.message);
            let matched = headers
                .get_all(field)
                .any(|candidate| contains_ci(candidate.as_bytes(), value));
            matched
        }
        SearchKey::Body(value) => {
            let (_, body) = mime::split_headers_body(context.message);
            contains_ci(body, value)
        }
        SearchKey::Text(value) => contains_ci(context.message, value),
        SearchKey::InternalDate { kind, days } => {
            compare_day(day_of(context.meta.internal_date), *kind, *days)
        }
        SearchKey::SentDate { kind, days } => {
            let headers = mime::parse_headers(context.message);
            let Some(date) = headers.get("date") else {
                return false;
            };
            let Some(timestamp) = date::parse_header_date(date) else {
                return false;
            };
            compare_day(day_of(timestamp), *kind, *days)
        }
        SearchKey::Larger(size) => context.meta.size > *size,
        SearchKey::Smaller(size) => context.meta.size < *size,
        SearchKey::ModSeq(modseq) => context.meta.modseq >= *modseq,
        SearchKey::Uid(set) => set.contains(context.meta.uid, context.max_uid),
        SearchKey::Sequence(set) => set.contains(context.sequence, context.max_sequence),
    }
}

fn day_of(timestamp: i64) -> i64 {
    timestamp.div_euclid(86_400)
}

fn compare_day(day: i64, kind: DateKind, target: i64) -> bool {
    match kind {
        DateKind::Before => day < target,
        DateKind::On => day == target,
        DateKind::Since => day >= target,
    }
}

fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap::parser::Token;
    use crate::maildir::{FlagSet, MessageMeta};
    use std::path::PathBuf;

    fn atom(value: &str) -> Token {
        Token::Atom(value.to_string())
    }

    fn quoted(value: &str) -> Token {
        Token::Quoted(value.to_string())
    }

    fn meta(flags: &[Flag], recent: bool, size: u64, internal_date: i64) -> MessageMeta {
        MessageMeta {
            uid: 9,
            base: "b".into(),
            filename: "b:2,".into(),
            path: PathBuf::from("/x"),
            size,
            internal_date,
            modseq: 1,
            flags: flags.iter().cloned().collect::<FlagSet>(),
            recent,
        }
    }

    const MESSAGE: &[u8] = b"Date: Fri, 23 Oct 2026 14:30:00 +0800\r\n\
Subject: Quarterly Report\r\n\
From: alice@example.com\r\n\
\r\n\
Hello Bob,\r\nattachment inside\r\n";

    fn context<'a>(meta: &'a MessageMeta, message: &'a [u8]) -> SearchContext<'a> {
        SearchContext {
            meta,
            sequence: 3,
            max_sequence: 10,
            max_uid: 100,
            message,
        }
    }

    #[test]
    fn flags_and_date_conditions_match() {
        let meta = meta(&[Flag::System(SystemFlag::Seen)], false, 500, 1_700_000_000);
        let context = context(&meta, MESSAGE);
        assert!(matches(&SearchKey::All, &context));
        assert!(matches(
            &SearchKey::System {
                flag: SystemFlag::Seen,
                present: true
            },
            &context
        ));
        assert!(!matches(
            &SearchKey::System {
                flag: SystemFlag::Seen,
                present: false
            },
            &context
        ));
        assert!(matches(&SearchKey::Old, &context));
        assert!(!matches(&SearchKey::Recent, &context));
        assert!(matches(&SearchKey::Larger(100), &context));
        assert!(matches(&SearchKey::Smaller(600), &context));

        let days = day_of(meta.internal_date);
        assert!(matches(
            &SearchKey::InternalDate {
                kind: DateKind::On,
                days
            },
            &context
        ));
        assert!(matches(
            &SearchKey::InternalDate {
                kind: DateKind::Before,
                days: days + 1
            },
            &context
        ));
    }

    #[test]
    fn header_body_and_text_search_is_case_insensitive() {
        let meta = meta(&[], true, 10, 0);
        let context = context(&meta, MESSAGE);
        for key in [
            SearchKey::Header {
                field: "subject".into(),
                value: b"quarterly".to_vec(),
            },
            SearchKey::Body(b"ATTACHMENT".to_vec()),
            SearchKey::Text(b"alice@example.com".to_vec()),
        ] {
            assert!(matches(&key, &context), "{key:?}");
        }
        assert!(matches(
            &SearchKey::SentDate {
                kind: DateKind::On,
                days: day_of(date::parse_header_date("Fri, 23 Oct 2026 14:30:00 +0800").unwrap())
            },
            &context
        ));
        assert!(!matches(
            &SearchKey::SentDate {
                kind: DateKind::On,
                days: 0
            },
            &context
        ));
    }

    #[test]
    fn uid_and_sequence_sets_resolve_against_the_right_maximum() {
        let meta = meta(&[], false, 10, 0);
        let context = context(&meta, MESSAGE);
        assert!(matches(
            &SearchKey::Uid(SequenceSet::parse("1:99").unwrap()),
            &context
        ));
        assert!(!matches(
            &SearchKey::Uid(SequenceSet::parse("10:20").unwrap()),
            &context
        ));
        assert!(matches(
            &SearchKey::Uid(SequenceSet::parse("1:*").unwrap()),
            &context
        ));
        assert!(matches(
            &SearchKey::Sequence(SequenceSet::parse("3").unwrap()),
            &context
        ));
        assert!(!matches(
            &SearchKey::Sequence(SequenceSet::parse("4").unwrap()),
            &context
        ));
    }

    #[test]
    fn parse_handles_charset_not_or_and_parentheses() {
        let parsed = parse(&[
            atom("CHARSET"),
            quoted("UTF-8"),
            atom("UNSEEN"),
            atom("OR"),
            atom("FROM"),
            quoted("a@b"),
            Token::List(vec![
                atom("LARGER"),
                atom("10"),
                atom("NOT"),
                atom("DELETED"),
            ]),
        ])
        .unwrap();
        assert_eq!(parsed.charset.as_deref(), Some("UTF-8"));
        let SearchKey::And(keys) = parsed.key else {
            panic!("应解析为 AND");
        };
        assert_eq!(keys.len(), 2, "OR 的两个 key 属于同一个顶层条件");
        assert!(matches!(keys[0], SearchKey::System { .. }));
        let SearchKey::Or(_, second) = &keys[1] else {
            panic!("第二个条件应是 OR");
        };
        assert!(matches!(**second, SearchKey::And(_)));

        assert_eq!(
            parse(&[atom("CHARSET"), quoted("KOI8-R"), atom("ALL")]),
            Err(SearchError::BadCharset("KOI8-R".into()))
        );
        assert!(parse(&[atom("HEADER"), quoted("Subject")]).is_err());
        assert!(parse(&[atom("1:")]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn esearch_return_options_are_parsed() {
        let parsed = parse(&[
            atom("RETURN"),
            Token::List(vec![atom("MIN"), atom("COUNT"), atom("ALL")]),
            atom("ALL"),
        ])
        .unwrap();
        assert_eq!(
            parsed.options,
            Some(SearchReturn {
                min: true,
                max: false,
                all: true,
                count: true,
                save: false,
            })
        );
        let saved = parse(&[
            atom("RETURN"),
            Token::List(vec![atom("SAVE")]),
            atom("UNSEEN"),
        ])
        .unwrap();
        assert!(saved.options.unwrap().save);
        assert!(parse(&[atom("RETURN"), atom("ALL")]).is_err());
        assert!(parse(&[
            atom("RETURN"),
            Token::List(vec![atom("BOGUS")]),
            atom("ALL")
        ])
        .is_err());
    }

    #[test]
    fn modseq_search_matches_greater_or_equal() {
        let meta = meta(&[], false, 10, 0);
        let context = context(&meta, MESSAGE);
        assert!(matches(&SearchKey::ModSeq(1), &context));
        assert!(!matches(&SearchKey::ModSeq(2), &context));
    }

    #[test]
    fn needs_message_covers_header_and_body_criteria() {
        assert!(!needs_message(&SearchKey::All));
        assert!(!needs_message(&SearchKey::Larger(1)));
        assert!(needs_message(&SearchKey::Header {
            field: "subject".into(),
            value: b"x".to_vec()
        }));
        assert!(needs_message(&SearchKey::Not(Box::new(SearchKey::Body(
            b"x".to_vec()
        )))));
        assert!(!needs_message(&SearchKey::Not(Box::new(SearchKey::All))));
    }
}

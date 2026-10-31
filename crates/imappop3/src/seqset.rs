//! IMAP `sequence-set`（RFC 3501 §9）。
//!
//! 同一份语法承载两种语义：未加 `UID` 时是**序号**（1..=邮件数，随 EXPUNGE 漂移），
//! `UID` 命令里是**UID**（服务端分配的稳定值）。本模块只负责解析与集合判定，
//! 两种语义由调用方选择 `max` 并决定拿 UID 还是序号去比对。
//!
//! ## `*` 的两种含义
//!
//! * 非 UID：最后一条邮件的序号（信箱空时为 0，任何集合都不命中）；
//! * UID：当前最大 UID（信箱空时为 0）。
//!
//! 因此 [`SequenceSet::contains`] 必须接收 `max`，不能把 `*` 事先折叠成常量。

use crate::error::{MailError, Result};

/// `*` 的内部哨兵。0 不是合法序号/UID，因此不会与真实值冲突。
pub const STAR: u32 = u32::MAX;

/// 解析后的一段闭区间。`from > to` 的写法（如 `5:2`）按 RFC 归一化。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqRange {
    pub from: u32,
    pub to: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SequenceSet {
    ranges: Vec<SeqRange>,
}

/// 防御「一个集合把所有消息都列一遍」的内存放大：`1:4294967295` 是合法的
/// 6 个字符，却代表 40 亿个序号。范围数与输入长度都要设上限。
const MAX_RANGES: usize = 1024;
const MAX_INPUT: usize = 8192;

impl SequenceSet {
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(MailError::invalid("empty sequence set"));
        }
        if trimmed.len() > MAX_INPUT {
            return Err(MailError::invalid("sequence set too long"));
        }

        let mut ranges = Vec::new();
        for element in trimmed.split(',') {
            let element = element.trim();
            if element.is_empty() {
                return Err(MailError::invalid(format!(
                    "invalid sequence set: {input:?}"
                )));
            }
            let (from, to) = match element.split_once(':') {
                Some((left, right)) => (parse_number(left)?, parse_number(right)?),
                None => {
                    let value = parse_number(element)?;
                    (value, value)
                }
            };
            let (from, to) = if from <= to { (from, to) } else { (to, from) };
            ranges.push(SeqRange { from, to });
            if ranges.len() > MAX_RANGES {
                return Err(MailError::invalid("sequence set has too many ranges"));
            }
        }
        Ok(Self { ranges })
    }

    /// 单值集合（内部使用，例如 `UID EXPUNGE` 的单封邮件）。
    pub fn single(value: u32) -> Self {
        Self {
            ranges: vec![SeqRange {
                from: value,
                to: value,
            }],
        }
    }

    pub fn ranges(&self) -> &[SeqRange] {
        &self.ranges
    }

    /// 给定「当前最大值」，判断 `value` 是否落在集合内。
    pub fn contains(&self, value: u32, max: u32) -> bool {
        if max == 0 {
            // 空邮箱没有序号、也没有 UID；`*` 解析成 0 会把 `1:*` 变成 `0:1`，
            // 那样会让「空文件夹里也没东西可匹配」这条不变量失效。
            return false;
        }
        self.ranges.iter().any(|range| {
            let from = resolve(range.from, max);
            let to = resolve(range.to, max);
            // `*` 解析后可能出现 from > to（例如 `*:4` 且 max=2），统一归一化。
            let (low, high) = if from <= to { (from, to) } else { (to, from) };
            low <= value && value <= high
        })
    }

    /// 是否包含 `*`。`UID SEARCH` 的判定需要知道这一点吗？不需要，但调试输出需要。
    pub fn has_star(&self) -> bool {
        self.ranges
            .iter()
            .any(|range| range.from == STAR || range.to == STAR)
    }

    /// 把一组升序值压成紧凑的集合字符串（`COPYUID` 用）。
    pub fn from_values(values: &[u32]) -> String {
        let mut sorted: Vec<u32> = values.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut parts: Vec<String> = Vec::new();
        let mut index = 0;
        while index < sorted.len() {
            let start = sorted[index];
            let mut end = start;
            while index + 1 < sorted.len() && sorted[index + 1] == end.saturating_add(1) {
                index += 1;
                end = sorted[index];
            }
            if start == end {
                parts.push(start.to_string());
            } else {
                parts.push(format!("{start}:{end}"));
            }
            index += 1;
        }
        parts.join(",")
    }
}

fn parse_number(token: &str) -> Result<u32> {
    let token = token.trim();
    if token == "*" {
        return Ok(STAR);
    }
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MailError::invalid(format!(
            "invalid sequence number: {token:?}"
        )));
    }
    let value: u32 = token
        .parse()
        .map_err(|_| MailError::invalid(format!("sequence number out of range: {token:?}")))?;
    if value == 0 {
        // RFC 3501：seq-number 从 1 开始。0 不是「空」，是语法错。
        return Err(MailError::invalid("sequence number 0 is invalid"));
    }
    Ok(value)
}

fn resolve(value: u32, max: u32) -> u32 {
    if value == STAR {
        max
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ranges_and_singles() {
        let set = SequenceSet::parse("1:3,5,7:9").unwrap();
        for value in [1, 2, 3, 5, 7, 8, 9] {
            assert!(set.contains(value, 100), "{value}");
        }
        for value in [0, 4, 6, 10] {
            assert!(!set.contains(value, 100), "{value}");
        }
    }

    #[test]
    fn star_means_the_current_max() {
        let set = SequenceSet::parse("1:*").unwrap();
        assert!(set.contains(10, 10));
        assert!(!set.contains(11, 10));
        let tail = SequenceSet::parse("3:*").unwrap();
        assert!(tail.contains(3, 10));
        assert!(!tail.contains(2, 10));
        let reversed = SequenceSet::parse("*:8").unwrap();
        assert!(reversed.contains(8, 10));
        assert!(reversed.contains(10, 10));
        assert!(!reversed.contains(7, 10));
    }

    #[test]
    fn empty_mailbox_makes_star_match_nothing() {
        let set = SequenceSet::parse("1:*").unwrap();
        assert!(!set.contains(1, 0));
        let star = SequenceSet::parse("*").unwrap();
        assert!(!star.contains(0, 0));
    }

    #[test]
    fn descending_ranges_are_normalized() {
        let set = SequenceSet::parse("5:2").unwrap();
        for value in 2..=5 {
            assert!(set.contains(value, 10));
        }
        assert!(!set.contains(1, 10));
        assert!(!set.contains(6, 10));
    }

    #[test]
    fn zero_and_garbage_are_rejected() {
        assert!(SequenceSet::parse("").is_err());
        assert!(SequenceSet::parse("0").is_err());
        assert!(SequenceSet::parse("1,0").is_err());
        assert!(SequenceSet::parse("a").is_err());
        assert!(SequenceSet::parse("1:").is_err());
        assert!(SequenceSet::parse(":3").is_err());
        assert!(SequenceSet::parse("1,,2").is_err());
        assert!(
            SequenceSet::parse("4294967296").is_err(),
            "u32 溢出必须拒绝"
        );
    }

    #[test]
    fn star_only_is_detected_and_values_render_compactly() {
        assert!(SequenceSet::parse("*").unwrap().has_star());
        assert!(!SequenceSet::parse("1:2").unwrap().has_star());
        assert_eq!(SequenceSet::from_values(&[3, 1, 2, 5, 7, 8]), "1:3,5,7:8");
        assert_eq!(SequenceSet::from_values(&[]), "");
    }
}

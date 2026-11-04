use crate::error::{MailError, Result};

pub const STAR: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqRange {
    pub from: u32,
    pub to: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SequenceSet {
    ranges: Vec<SeqRange>,
}

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

    pub fn contains(&self, value: u32, max: u32) -> bool {
        if max == 0 {
            return false;
        }
        self.ranges.iter().any(|range| {
            let from = resolve(range.from, max);
            let to = resolve(range.to, max);

            let (low, high) = if from <= to { (from, to) } else { (to, from) };
            low <= value && value <= high
        })
    }

    pub fn has_star(&self) -> bool {
        self.ranges
            .iter()
            .any(|range| range.from == STAR || range.to == STAR)
    }

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

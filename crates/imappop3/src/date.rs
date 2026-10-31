//! IMAP 日期语法（RFC 3501 §9）与 civil calendar 换算。
//!
//! 刻意不引入 `chrono` / `time` 的格式化路径：IMAP 的 INTERNALDATE 与 SEARCH 日期
//! 格式**只有一种**，而本地时区参与会让「同一天的边界」随服务器 TZ 漂移。这里的
//! 换算全部是整数运算，输入相同则输出相同，测试不需要设置 `TZ`。
//!
//! 公历换算采用 Howard Hinnant 的 `days_from_civil` / `civil_from_days`
//! （proleptic Gregorian，1970-01-01 为第 0 天）。

use crate::error::{MailError, Result};

pub const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// 公历年月日 → Unix 天数（1970-01-01 = 0）。不做范围校验，调用方先校验。
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Unix 天数 → 公历年月日。
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { y + 1 } else { y }, month, day)
}

fn month_number(name: &str) -> Option<u32> {
    if name.len() != 3 {
        return None;
    }
    MONTHS
        .iter()
        .position(|candidate| candidate.eq_ignore_ascii_case(name))
        .map(|index| index as u32 + 1)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// 解析 `d-Mon-yyyy`（允许 1–2 位日、允许前后空白），返回 Unix 天数。
pub fn parse_date_only(value: &str) -> Result<i64> {
    let trimmed = value.trim();
    let mut parts = trimmed.split('-');
    let day = parts
        .next()
        .and_then(|part| part.trim().parse::<u32>().ok())
        .ok_or_else(|| MailError::invalid(format!("invalid date: {value:?}")))?;
    let month = parts
        .next()
        .and_then(month_number)
        .ok_or_else(|| MailError::invalid(format!("invalid date: {value:?}")))?;
    let year = parts
        .next()
        .and_then(|part| part.trim().parse::<i64>().ok())
        .ok_or_else(|| MailError::invalid(format!("invalid date: {value:?}")))?;
    if parts.next().is_some() {
        return Err(MailError::invalid(format!("invalid date: {value:?}")));
    }
    validate_date(year, month, day, value)?;
    Ok(days_from_civil(year, month, day))
}

fn validate_date(year: i64, month: u32, day: u32, original: &str) -> Result<()> {
    if !(1..=9999).contains(&year) || day == 0 || day > days_in_month(year, month) {
        return Err(MailError::invalid(format!("invalid date: {original:?}")));
    }
    Ok(())
}

/// 解析 IMAP `date-time`：`d-Mon-yyyy HH:MM:SS +ZZZZ`（时区缺省按 UTC 处理，
/// 这是对不守规矩客户端的宽容，而不是规范允许的省略）。
pub fn parse_date_time(value: &str) -> Result<i64> {
    let trimmed = value.trim().trim_matches('"').trim();
    let mut fields = trimmed.split_whitespace();
    let date_field = fields
        .next()
        .ok_or_else(|| MailError::invalid(format!("invalid date-time: {value:?}")))?;
    let days = parse_date_only(date_field)?;
    let time_field = fields
        .next()
        .ok_or_else(|| MailError::invalid(format!("invalid date-time: {value:?}")))?;

    let mut clock = time_field.split(':');
    let hour = clock
        .next()
        .and_then(|part| part.parse::<i64>().ok())
        .ok_or_else(|| MailError::invalid(format!("invalid date-time: {value:?}")))?;
    let minute = clock
        .next()
        .and_then(|part| part.parse::<i64>().ok())
        .ok_or_else(|| MailError::invalid(format!("invalid date-time: {value:?}")))?;
    let second = clock
        .next()
        .and_then(|part| part.parse::<i64>().ok())
        .ok_or_else(|| MailError::invalid(format!("invalid date-time: {value:?}")))?;
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..=60).contains(&second) {
        return Err(MailError::invalid(format!("invalid date-time: {value:?}")));
    }

    let mut offset = 0i64;
    if let Some(zone) = fields.next() {
        offset = parse_zone(zone)
            .ok_or_else(|| MailError::invalid(format!("invalid date-time zone: {zone:?}")))?;
    }
    if fields.next().is_some() {
        return Err(MailError::invalid(format!("invalid date-time: {value:?}")));
    }

    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second - offset)
}

fn parse_zone(zone: &str) -> Option<i64> {
    let bytes = zone.as_bytes();
    if bytes.len() != 5 {
        return None;
    }
    let sign = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    if !bytes[1..].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let hours: i64 = zone[1..3].parse().ok()?;
    let minutes: i64 = zone[3..5].parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3_600 + minutes * 60))
}

/// `INTERNALDATE` 的规范渲染（RFC 3501 §7.3.3）。始终用 `+0000`。
///
/// 为什么固定 UTC：INTERNALDATE 允许带服务器本地时区，但同一封邮件在不同 TZ 的
/// 服务器间迁移时，「本地时间」会变、绝对时刻不变。固定 UTC 让这个字段成为
/// 绝对时刻的稳定投影，客户端只是展示它。
pub fn format_date_time(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let month_name = MONTHS
        .get(month.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    format!(
        "{day:02}-{month_name}-{year:04} {:02}:{:02}:{:02} +0000",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

/// `d-Mon-yyyy`（SEARCH 的日期字面量格式）。
pub fn format_date(timestamp: i64) -> String {
    let (year, month, day) = civil_from_days(timestamp.div_euclid(86_400));
    let month_name = MONTHS
        .get(month.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    format!("{day:02}-{month_name}-{year:04}")
}

/// 从 Date 头里宽松地抠出 `d Mon yyyy HH:MM:SS`（允许前导星期与末尾时区/注释）。
///
/// SENTBEFORE / SENTON / SENTSINCE 只需要「哪一天」。解析失败返回 `None`，
/// 搜索判定随后按「不匹配」处理 —— 不把坏头的邮件当成「今天」。
pub fn parse_header_date(value: &str) -> Option<i64> {
    let cleaned = value.split('(').next().unwrap_or(value).trim();
    let mut fields = cleaned.split_whitespace();
    let first = fields.next()?;
    // 有的客户端把日期写成 "Mon, 3 Oct 2026 ..."（逗号紧跟星期）。
    let day_field = if first
        .trim_end_matches(',')
        .chars()
        .all(|c| c.is_ascii_alphabetic())
    {
        fields.next()?
    } else {
        first
    };
    let day: u32 = day_field.parse().ok()?;
    let month = month_number(fields.next()?)?;
    let year: i64 = fields.next()?.parse().ok()?;
    let (hour, minute, second) = match fields.next() {
        Some(time_field) => {
            let mut clock = time_field.split(':');
            let hour: i64 = clock.next().and_then(|part| part.parse().ok())?;
            let minute: i64 = clock.next().and_then(|part| part.parse().ok()).unwrap_or(0);
            let second: i64 = clock.next().and_then(|part| part.parse().ok()).unwrap_or(0);
            if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..=60).contains(&second)
            {
                return None;
            }
            (hour, minute, second)
        }
        None => (0, 0, 0),
    };
    // Date 头的时区必须参与换算；否则「23 Oct 14:30 +0800」会被当成 UTC，
    // SENTON 在跨时区邮件上会落到相邻一天。
    let offset = fields
        .find_map(|token| {
            if token.starts_with(['+', '-']) {
                parse_zone(token)
            } else {
                None
            }
        })
        .unwrap_or(0);
    validate_date(year, month, day, value).ok()?;
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_conversion_roundtrips_across_epoch_and_leap_days() {
        for days in [-30_000, -1, 0, 1, 19_000, 110_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(days_from_civil(2026, 10, 30), 20_756);
        // 已知锚点：2024-01-01 的 Unix 天数是 19723（与外部工具核对过）。
        assert_eq!(days_from_civil(2024, 1, 1), 19_723);
    }

    #[test]
    fn date_only_parsing_is_lenient_about_padding_but_strict_about_calendar() {
        assert_eq!(parse_date_only("03-Oct-2026").unwrap(), 20_729);
        assert_eq!(parse_date_only("3-oct-2026").unwrap(), 20_729);
        assert_eq!(parse_date_only(" 3-Oct-2026 ").unwrap(), 20_729);
        assert!(parse_date_only("31-Feb-2026").is_err());
        assert!(parse_date_only("29-Feb-2025").is_err());
        assert!(parse_date_only("29-Feb-2024").is_ok());
        assert!(parse_date_only("3-Foo-2026").is_err());
        assert!(parse_date_only("3-Oct").is_err());
    }

    #[test]
    fn date_time_honours_the_zone_offset() {
        // 2026-10-23 14:30:00 +0800 == 06:30:00 UTC
        let ts = parse_date_time("23-Oct-2026 14:30:00 +0800").unwrap();
        assert_eq!(
            ts,
            days_from_civil(2026, 10, 23) * 86_400 + 6 * 3_600 + 30 * 60
        );
        assert_eq!(
            parse_date_time("\"23-Oct-2026 14:30:00 +0800\"").unwrap(),
            ts,
            "APPEND 的日期是 quoted string，解析器必须容忍引号"
        );
        assert_eq!(parse_date_time("23-Oct-2026 06:30:00 -0000").unwrap(), ts);
        assert!(parse_date_time("23-Oct-2026 25:00:00 +0000").is_err());
        assert!(parse_date_time("23-Oct-2026 14:30:00 +9900").is_err());
    }

    #[test]
    fn formatting_is_the_inverse_of_parsing() {
        let ts = parse_date_time("23-Oct-2026 14:30:00 +0000").unwrap();
        assert_eq!(format_date_time(ts), "23-Oct-2026 14:30:00 +0000");
        assert_eq!(format_date(ts), "23-Oct-2026");
        assert_eq!(parse_date_time(&format_date_time(ts)).unwrap(), ts);
    }

    #[test]
    fn header_dates_with_weekday_and_comments_are_parsed() {
        let ts = parse_header_date("Fri, 23 Oct 2026 14:30:00 +0800 (CST)").unwrap();
        assert_eq!(format_date_time(ts), "23-Oct-2026 06:30:00 +0000");
        assert!(parse_header_date("not a date").is_none());
        assert!(parse_header_date("32 Oct 2026 00:00:00 +0000").is_none());
        assert!(
            parse_header_date("23 Oct 2026 99:30:00 +0000").is_none(),
            "越界时间不得被当成合法日期"
        );
        assert!(parse_header_date("23 Oct 2026 12:61:00 +0000").is_none());
    }
}

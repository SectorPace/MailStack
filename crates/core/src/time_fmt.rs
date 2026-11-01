//! 时间工具。审计记录与配置都用 ISO 8601，格式必须与 Python 侧可互操作。

/// 当前 UTC 时间，ISO 8601 带偏移（对应 `datetime.now(timezone.utc).isoformat()`）。
pub fn now_iso8601_utc() -> String {
    format_iso8601(time::OffsetDateTime::now_utc())
}

/// 当前本地时间，ISO 8601 **带本地偏移**（±HH:MM，与 [`format_iso8601`] 一致；
/// 无法取得本地时区时回落 UTC 偏移）。
///
/// 注意：Python 的 `datetime.now().isoformat()` 是**无偏移**的，这里不是它的
/// 对应物 —— 输出形态更接近 `datetime.now().astimezone().isoformat()`。
pub fn now_iso8601_local() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format_iso8601(now)
}

/// 格式化为 `YYYY-MM-DDTHH:MM:SS(.ffffff)?+HH:MM`。
///
/// 刻意不引入 `time` 的 serde feature：格式串在这里集中定义，便于与 Python
/// 的 `isoformat()` 输出逐字对齐。
pub fn format_iso8601(dt: time::OffsetDateTime) -> String {
    let offset = dt.offset();
    let total_minutes = offset.whole_minutes();
    let (sign, abs_minutes) = if total_minutes < 0 {
        ('-', -total_minutes)
    } else {
        ('+', total_minutes)
    };
    let (oh, om) = (abs_minutes / 60, abs_minutes % 60);

    let micros = dt.microsecond();
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    let frac = if micros == 0 {
        String::new()
    } else {
        format!(".{micros:06}")
    };
    format!("{base}{frac}{sign}{oh:02}:{om:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_utc_with_explicit_offset() {
        let dt = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let s = format_iso8601(dt);
        assert_eq!(s, "2023-11-14T22:13:20+00:00");
    }

    #[test]
    fn renders_negative_offset() {
        let dt = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap()
            .to_offset(time::UtcOffset::from_hms(-5, 0, 0).unwrap());
        let s = format_iso8601(dt);
        assert!(s.ends_with("-05:00"), "实际: {s}");
    }

    #[test]
    fn renders_fractional_seconds_when_present() {
        let dt = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap()
            .replace_microsecond(123_456)
            .unwrap();
        assert!(format_iso8601(dt).contains(".123456"));
    }

    #[test]
    fn now_utc_is_parseable_iso8601_shape() {
        let s = now_iso8601_utc();
        // Python 的 `isoformat()` 在微秒非零时会带上 `.ffffff`，
        // 故长度是 25（无小数）或 32（有小数）。
        assert!(
            s.len() == 25 || s.len() == 32,
            "意外的 ISO 8601 长度 {}: {s}",
            s.len()
        );
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
        assert!(s.ends_with("+00:00"));
    }
}

pub fn now_iso8601_utc() -> String {
    format_iso8601(time::OffsetDateTime::now_utc())
}

pub fn now_iso8601_local() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format_iso8601(now)
}

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

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

pub fn system_proc_root() -> PathBuf {
    PathBuf::from("/proc")
}

pub fn read_loadavg(proc_root: &Path) -> Option<LoadAverage> {
    let text = std::fs::read_to_string(proc_root.join("loadavg")).ok()?;
    let mut fields = text.split_whitespace();
    Some(LoadAverage {
        one: fields.next()?.parse().ok()?,
        five: fields.next()?.parse().ok()?,
        fifteen: fields.next()?.parse().ok()?,
    })
}

pub fn read_uptime_secs(proc_root: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(proc_root.join("uptime")).ok()?;
    let first = text.split_whitespace().next()?;
    let seconds: f64 = first.parse().ok()?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    Some(seconds as u64)
}

pub fn read_meminfo(proc_root: &Path) -> Option<MemoryInfo> {
    let text = std::fs::read_to_string(proc_root.join("meminfo")).ok()?;
    let mut total_kib = None;
    let mut available_kib = None;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let value: u64 = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        match key {
            "MemTotal" => total_kib = Some(value),
            "MemAvailable" => available_kib = Some(value),
            _ => {}
        }
    }
    Some(MemoryInfo {
        total_bytes: total_kib?.saturating_mul(1024),
        available_bytes: available_kib?.saturating_mul(1024),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn proc_fixture(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-proc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        for (name, body) in files {
            fs::write(root.join(name), body).unwrap();
        }
        root
    }

    #[test]
    fn loadavg_reads_the_first_three_fields() {
        let root = proc_fixture("loadavg", &[("loadavg", "0.52 0.58 0.59 2/1234 56789\n")]);
        let load = read_loadavg(&root).unwrap();
        assert_eq!(load.one, 0.52);
        assert_eq!(load.five, 0.58);
        assert_eq!(load.fifteen, 0.59);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn uptime_truncates_to_whole_seconds() {
        let root = proc_fixture("uptime", &[("uptime", "12345.67 8901.23\n")]);
        assert_eq!(read_uptime_secs(&root), Some(12345));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn meminfo_converts_kib_to_bytes() {
        let root = proc_fixture(
            "meminfo",
            &[(
                "meminfo",
                "MemTotal:       16384000 kB\n\
                 MemFree:         1000000 kB\n\
                 MemAvailable:   12000000 kB\n\
                 Buffers:          100000 kB\n",
            )],
        );
        let mem = read_meminfo(&root).unwrap();
        assert_eq!(mem.total_bytes, 16_384_000 * 1024);
        assert_eq!(mem.available_bytes, 12_000_000 * 1024);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn missing_mem_available_is_reported_rather_than_guessed() {
        let root = proc_fixture(
            "noavailable",
            &[(
                "meminfo",
                "MemTotal:       16384000 kB\nMemFree: 800000 kB\n",
            )],
        );
        assert_eq!(read_meminfo(&root), None);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn missing_or_garbage_proc_files_yield_none_not_a_panic() {
        let root = proc_fixture(
            "garbage",
            &[
                ("loadavg", "not numbers at all"),
                ("uptime", "-1.0 0.0"),
                ("meminfo", ""),
            ],
        );
        assert_eq!(read_loadavg(&root), None);
        assert_eq!(read_uptime_secs(&root), None);
        assert_eq!(read_meminfo(&root), None);
        assert_eq!(read_loadavg(Path::new("/nonexistent/proc")), None);
        fs::remove_dir_all(&root).ok();
    }
}

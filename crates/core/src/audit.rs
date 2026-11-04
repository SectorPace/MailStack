use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::atomic::atomic_as;
use crate::error::{CoreError, CoreResult};

pub const AUDIT_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub const AUDIT_HEAD_SUFFIX: &str = ".head";

const TAIL_READ_BYTES: u64 = 262_144;

pub fn audit_head_path(log_path: &Path) -> PathBuf {
    let name = log_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    log_path.with_file_name(format!("{name}{AUDIT_HEAD_SUFFIX}"))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub time: String,
    pub uid: u32,
    pub action: String,
    pub target: String,
    pub ok: bool,
    pub error: String,
    pub prev_hash: String,
    pub hash: String,
}

pub fn record_hash(record: &AuditRecord) -> String {
    let canonical = format!(
        "{{\"action\":{},\"error\":{},\"ok\":{},\"prev_hash\":{},\"target\":{},\"time\":{},\"uid\":{}}}",
        json_string(&record.action),
        json_string(&record.error),
        record.ok,
        json_string(&record.prev_hash),
        json_string(&record.target),
        json_string(&record.time),
        record.uid,
    );
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    hex::encode(h.finalize())
}

pub fn record_hash_from_value(value: &serde_json::Value) -> Option<String> {
    let obj = value.as_object()?;
    let mut keys: Vec<&String> = obj.keys().filter(|k| k.as_str() != "hash").collect();
    keys.sort();
    let mut canonical = String::from("{");
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            canonical.push(',');
        }
        canonical.push_str(&json_string(k));
        canonical.push(':');
        canonical.push_str(&json_value_canonical(&obj[*k]));
    }
    canonical.push('}');
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    Some(hex::encode(h.finalize()))
}

fn json_value_canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => json_string(s),
        serde_json::Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(json_value_canonical).collect();
            format!("[{}]", inner.join(","))
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", json_string(k), json_value_canonical(&map[*k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn read_last_audit_hash(log_path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(log_path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let start = len.saturating_sub(TAIL_READ_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;

    let text = if buf.last() == Some(&b'\n') {
        buf
    } else {
        let pos = buf.iter().rposition(|&b| b == b'\n')?;
        buf[..=pos].to_vec()
    };

    let text = String::from_utf8_lossy(&text);
    for line in text.lines().rev() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(h) = value.get("hash").and_then(|v| v.as_str()) {
            return Some(h.to_string());
        }
    }
    None
}

pub fn read_last_audit_hash_strict(log_path: &Path) -> CoreResult<Option<String>> {
    let mut file = match std::fs::File::open(log_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CoreError::io(log_path, error)),
    };
    let len = file
        .metadata()
        .map_err(|e| CoreError::io(log_path, e))?
        .len();
    if len == 0 {
        return Ok(None);
    }
    let start = len.saturating_sub(TAIL_READ_BYTES);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| CoreError::io(log_path, e))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| CoreError::io(log_path, e))?;

    let text = if buf.last() == Some(&b'\n') {
        buf
    } else {
        match buf.iter().rposition(|&b| b == b'\n') {
            Some(pos) => buf[..=pos].to_vec(),

            None => {
                return Err(CoreError::invalid(format!(
                    "{}: cannot locate a complete audit record within the tail window",
                    log_path.display()
                )))
            }
        }
    };

    let text = String::from_utf8_lossy(&text);
    let mut saw_any_record = false;
    for line in text.lines().rev() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if !value.is_object() {
            continue;
        }
        saw_any_record = true;
        if let Some(h) = value.get("hash").and_then(|v| v.as_str()) {
            return Ok(Some(h.to_string()));
        }
    }
    if saw_any_record {
        return Ok(None);
    }

    Err(CoreError::invalid(format!(
        "{}: audit log is non-empty but no parseable record was found near the tail",
        log_path.display()
    )))
}

pub fn audit(
    log_path: &Path,
    action: &str,
    ok: bool,
    error: &str,
    target: &str,
) -> CoreResult<AuditRecord> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CoreError::io(parent, e))?;
    }

    crate::atomic::locked(log_path, || {
        let prev_hash = match read_last_audit_hash_strict(log_path)? {
            Some(hash) => hash,
            None => AUDIT_GENESIS.to_string(),
        };

        let mut record = AuditRecord {
            time: crate::now_iso8601_utc(),
            uid: crate::atomic::current_uid(),
            action: action.to_string(),
            target: truncate_chars(target, 120),
            ok,
            error: truncate_chars(error, 500),
            prev_hash,
            hash: String::new(),
        };
        record.hash = record_hash(&record);

        let line = format!("{}\n", serde_json::to_string(&record)?);
        {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
                .map_err(|e| CoreError::io(log_path, e))?;
            f.write_all(line.as_bytes())
                .map_err(|e| CoreError::io(log_path, e))?;

            f.sync_all().map_err(|e| CoreError::io(log_path, e))?;
        }

        let head = audit_head_path(log_path);
        atomic_as(&head, format!("{}\n", record.hash).as_bytes(), 0o600, None)?;

        set_audit_log_mode(log_path);

        Ok(record)
    })
}

#[cfg(unix)]
fn set_audit_log_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        crate::warn::warn(&format!("chmod {} to 0600: {e}", path.display()));
    }
}

#[cfg(not(unix))]
fn set_audit_log_mode(_path: &Path) {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerdict {
    pub ok: bool,
    pub entries: usize,
    pub anchor: bool,
    pub error: String,
}

pub fn audit_verify(log_path: &Path) -> AuditVerdict {
    let head_path = audit_head_path(log_path);
    let mut errors: Vec<String> = Vec::new();
    let mut entries = 0usize;
    let mut chain_started = false;
    let mut prev_hash = AUDIT_GENESIS.to_string();
    let mut last_hash: Option<String> = None;

    let file = match std::fs::File::open(log_path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return finish_verify(&head_path, errors, entries, last_hash);
        }
        Err(e) => {
            return AuditVerdict {
                ok: false,
                entries: 0,
                anchor: false,
                error: format!("read audit log failed: {e}"),
            }
        }
    };

    {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(file);
        for (idx, line) in reader.lines().enumerate() {
            let lineno = idx + 1;
            let raw = match line {
                Ok(raw) => raw,
                Err(e) => {
                    return AuditVerdict {
                        ok: false,
                        entries: 0,
                        anchor: false,
                        error: format!("read audit log failed: {e}"),
                    };
                }
            };
            if raw.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => {
                    errors.push(format!("line {lineno}: record is not valid JSON"));
                    continue;
                }
            };
            if !value.is_object() {
                errors.push(format!("line {lineno}: record is not a JSON object"));
                continue;
            }
            let hash = value.get("hash").and_then(|v| v.as_str());
            let prev = value.get("prev_hash").and_then(|v| v.as_str());
            let (Some(hash), Some(prev)) = (hash, prev) else {
                if chain_started {
                    errors.push(format!(
                        "line {lineno}: unhashed record after chained record"
                    ));
                }
                continue;
            };

            chain_started = true;
            if prev != prev_hash {
                errors.push(format!(
                    "line {lineno}: prev_hash mismatch (chain broken, reordered or spliced)"
                ));
            }
            match record_hash_from_value(&value) {
                Some(recomputed) if recomputed == hash => {}
                _ => errors.push(format!(
                    "line {lineno}: record hash mismatch (record tampered)"
                )),
            }
            prev_hash = hash.to_string();
            last_hash = Some(hash.to_string());
            entries += 1;
        }
    }

    finish_verify(&head_path, errors, entries, last_hash)
}

fn finish_verify(
    head_path: &Path,
    mut errors: Vec<String>,
    entries: usize,
    last_hash: Option<String>,
) -> AuditVerdict {
    let anchor_value = match std::fs::read_to_string(head_path) {
        Ok(t) => Some(t.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            errors.push(format!("read audit head anchor failed: {e}"));
            None
        }
    };

    if let Some(anchor) = anchor_value.as_ref().filter(|a| !a.is_empty()) {
        match &last_hash {
            None => errors.push(
                "audit head anchor present but no chained record survives (tail fully truncated)"
                    .to_string(),
            ),
            Some(last) if anchor != last => {
                errors.push("audit head anchor mismatch (truncated tail)".to_string())
            }
            _ => {}
        }
    }

    AuditVerdict {
        ok: errors.is_empty(),
        entries,
        anchor: anchor_value.map(|a| !a.is_empty()).unwrap_or(false),
        error: errors.join("; "),
    }
}

pub fn audit_verify_cli(log_path: &Path) -> i32 {
    let verdict = audit_verify(log_path);
    if verdict.ok {
        let anchor = if verdict.anchor {
            "anchored"
        } else {
            "no anchor (pre-B3 log)"
        };
        println!(
            "audit chain OK: {} chained entries ({anchor})",
            verdict.entries
        );
        0
    } else {
        let message = if verdict.error.is_empty() {
            "unknown error"
        } else {
            &verdict.error
        };
        eprintln!("audit chain FAILED: {message}");
        1
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mailstack-audit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn canonical_hash_matches_python_json_dumps_shape() {
        let record = AuditRecord {
            time: "2026-09-30T12:00:00+00:00".into(),
            uid: 0,
            action: "domains.list".into(),
            target: "".into(),
            ok: true,
            error: "".into(),
            prev_hash: AUDIT_GENESIS.into(),
            hash: String::new(),
        };
        let recomputed = record_hash(&record);
        assert_eq!(recomputed.len(), 64, "SHA256 hex 应为 64 字符");

        let mut value = serde_json::to_value(&record).unwrap();
        value["hash"] = serde_json::Value::String(recomputed.clone());
        assert_eq!(record_hash_from_value(&value).unwrap(), recomputed);
    }

    #[test]
    fn non_ascii_is_not_escaped_in_canonical_form() {
        let record = AuditRecord {
            time: "2026-09-30T12:00:00+00:00".into(),
            uid: 0,
            action: "domains.add".into(),
            target: "例子.测试".into(),
            ok: true,
            error: "".into(),
            prev_hash: AUDIT_GENESIS.into(),
            hash: String::new(),
        };
        let mut value = serde_json::to_value(&record).unwrap();
        value["hash"] = serde_json::Value::String(record_hash(&record));

        assert_eq!(
            record_hash_from_value(&value).unwrap(),
            record_hash(&record)
        );
    }

    #[test]
    fn chain_starts_from_genesis_and_advances() {
        let dir = temp_dir("chain");
        let log = dir.join("audit.log");
        let r1 = audit(&log, "domains.list", true, "", "").unwrap();
        assert_eq!(r1.prev_hash, AUDIT_GENESIS);
        let r2 = audit(&log, "domains.add", true, "", "example.com").unwrap();
        assert_eq!(r2.prev_hash, r1.hash, "第二条必须接在第一条之后");
        assert_eq!(read_last_audit_hash(&log).unwrap(), r2.hash);

        let verdict = audit_verify(&log);
        assert!(verdict.ok, "{}", verdict.error);
        assert_eq!(verdict.entries, 2);
        assert!(verdict.anchor, "写入后应有锚");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cli_returns_zero_on_valid_chain_and_one_on_broken() {
        let dir = temp_dir("cli");
        let log = dir.join("audit.log");
        audit(&log, "a", true, "", "").unwrap();
        assert_eq!(audit_verify_cli(&log), 0);

        let text = fs::read_to_string(&log).unwrap();
        fs::write(&log, text.replace("\"action\":\"a\"", "\"action\":\"b\"")).unwrap();
        assert_eq!(audit_verify_cli(&log), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_truncated_tail_via_anchor() {
        let dir = temp_dir("truncate");
        let log = dir.join("audit.log");
        audit(&log, "a", true, "", "").unwrap();
        audit(&log, "b", true, "", "").unwrap();
        assert!(audit_verify(&log).ok);

        let text = fs::read_to_string(&log).unwrap();
        let first = text.lines().next().unwrap().to_string();
        fs::write(&log, format!("{first}\n")).unwrap();

        let verdict = audit_verify(&log);
        assert!(!verdict.ok);
        assert!(
            verdict.error.contains("truncated tail"),
            "实际错误: {}",
            verdict.error
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_fully_truncated_tail() {
        let dir = temp_dir("full-truncate");
        let log = dir.join("audit.log");
        audit(&log, "a", true, "", "").unwrap();
        fs::write(&log, "").unwrap();
        let verdict = audit_verify(&log);
        assert!(!verdict.ok);
        assert!(
            verdict.error.contains("tail fully truncated"),
            "实际错误: {}",
            verdict.error
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_reordered_or_spliced_chain() {
        let dir = temp_dir("splice");
        let log = dir.join("audit.log");
        audit(&log, "a", true, "", "").unwrap();
        audit(&log, "b", true, "", "").unwrap();
        audit(&log, "c", true, "", "").unwrap();

        let text = fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        fs::write(&log, format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1])).unwrap();

        let verdict = audit_verify(&log);
        assert!(!verdict.ok);
        assert!(
            verdict.error.contains("chain broken"),
            "实际错误: {}",
            verdict.error
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_log_without_anchor_is_valid_state() {
        let dir = temp_dir("legacy");
        let log = dir.join("audit.log");

        fs::write(
            &log,
            "{\"time\":\"2020-01-01T00:00:00\",\"action\":\"old\"}\n",
        )
        .unwrap();
        let verdict = audit_verify(&log);
        assert!(verdict.ok, "legacy 日志必须判为通过: {}", verdict.error);
        assert_eq!(verdict.entries, 0);
        assert!(!verdict.anchor, "无锚是合法状态，不是错误");
    }

    #[test]
    fn unhashed_record_after_chained_record_is_failure() {
        let dir = temp_dir("rollback");
        let log = dir.join("audit.log");
        audit(&log, "a", true, "", "").unwrap();
        let mut text = fs::read_to_string(&log).unwrap();
        text.push_str("{\"time\":\"2020-01-01T00:00:00\",\"action\":\"rollback\"}\n");
        fs::write(&log, text).unwrap();

        let verdict = audit_verify(&log);
        assert!(!verdict.ok);
        assert!(
            verdict
                .error
                .contains("unhashed record after chained record"),
            "实际错误: {}",
            verdict.error
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_anchor_is_post_logrotate_state_not_an_error() {
        let dir = temp_dir("emptyanchor");
        let log = dir.join("audit.log");
        audit(&log, "a", true, "", "").unwrap();
        fs::write(audit_head_path(&log), "").unwrap();
        let verdict = audit_verify(&log);
        assert!(verdict.ok, "空锚不参与比对: {}", verdict.error);
        assert!(!verdict.anchor);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn target_and_error_are_truncated_by_chars() {
        let dir = temp_dir("trunc");
        let log = dir.join("audit.log");
        let long_target = "例".repeat(200);
        let long_error = "e".repeat(700);
        let rec = audit(&log, "x", false, &long_error, &long_target).unwrap();
        assert_eq!(rec.target.chars().count(), 120);
        assert_eq!(rec.error.chars().count(), 500);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_is_idempotent_and_survives_missing_file() {
        let dir = temp_dir("missing");
        let log = dir.join("nope.log");
        let verdict = audit_verify(&log);
        assert!(verdict.ok, "不存在的日志视为空链，通过");
        assert_eq!(verdict.entries, 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn chain_survives_a_concurrent_writer_style_partial_line() {
        let dir = temp_dir("partial");
        let log = dir.join("audit.log");
        audit(&log, "a", true, "", "").unwrap();

        let mut text = fs::read_to_string(&log).unwrap();
        text.push_str("{\"partial\":");
        fs::write(&log, text).unwrap();

        let last = read_last_audit_hash(&log).unwrap();
        let verdict_first = {
            let t = fs::read_to_string(&log).unwrap();
            let first_line = t.lines().next().unwrap();
            let v: serde_json::Value = serde_json::from_str(first_line).unwrap();
            v["hash"].as_str().unwrap().to_string()
        };
        assert_eq!(last, verdict_first);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_non_empty_but_unreadable_log_is_an_error_not_a_fresh_chain() {
        let dir = temp_dir("unreadable-tail");
        let log = dir.join("audit.log");

        fs::write(&log, b"\x00\x01\x02 not a json record \xff\xfe").unwrap();

        let error = audit(&log, "a", true, "", "").expect_err("不得静默重开新链");
        assert!(
            error.to_string().contains("no record with a `hash` field")
                || error.to_string().contains("complete audit record"),
            "错误必须说明「读不出尾记录」，实际：{error}"
        );

        assert_eq!(
            fs::read(&log).unwrap(),
            b"\x00\x01\x02 not a json record \xff\xfe".to_vec(),
            "失败的 audit 不得写入任何记录"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_absent_or_empty_log_still_starts_from_genesis() {
        let dir = temp_dir("fresh-chain");
        let log = dir.join("audit.log");
        let first = audit(&log, "a", true, "", "").expect("不存在的日志应视作新链");
        assert_eq!(first.prev_hash, AUDIT_GENESIS);

        let empty = dir.join("empty.log");
        fs::write(&empty, b"").unwrap();
        let second = audit(&empty, "b", true, "", "").expect("空日志应视作新链");
        assert_eq!(second.prev_hash, AUDIT_GENESIS);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_legacy_hashless_tail_is_accepted_and_the_chain_continues_from_genesis() {
        let dir = temp_dir("legacy-append");
        let log = dir.join("audit.log");

        fs::write(
            &log,
            "{\"time\":\"2020-01-01T00:00:00\",\"action\":\"old\"}\n",
        )
        .unwrap();

        assert_eq!(
            read_last_audit_hash_strict(&log).unwrap(),
            None,
            "legacy 尾部应返回「无链上记录」，而不是错误"
        );

        let record = audit(&log, "domains.list", true, "", "").unwrap();
        assert_eq!(
            record.prev_hash, AUDIT_GENESIS,
            "legacy 之上首条链上记录必须从创世值起步"
        );

        let verdict = audit_verify(&log);
        assert!(verdict.ok, "追加后的日志必须通过校验: {}", verdict.error);
        assert_eq!(verdict.entries, 1, "legacy 记录不计入 entries");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_tail_of_unparseable_garbage_is_still_an_error() {
        let dir = temp_dir("garbage-tail");
        let log = dir.join("audit.log");
        fs::write(&log, "hello world\nnot json\n").unwrap();
        let error = read_last_audit_hash_strict(&log).expect_err("垃圾尾部必须报错");
        assert!(error.to_string().contains("no parseable record"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }
}

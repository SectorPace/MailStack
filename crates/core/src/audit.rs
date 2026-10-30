//! 审计哈希链（规格书 §5.6；INV-4）。
//!
//! 每条记录带 `prev_hash`（前一条的 hash，链首为创世值 `'0' * 64`）与 `hash`
//! （本条**规范化 JSON** 的 SHA256，排除 `hash` 字段自身）。文件旁的 `.head`
//! 锚文件记录最后一条的 hash，用于检测**截尾**。
//!
//! **新实现必须能继续写同一条链**（读取现有 `.head` 作为起点），且必须能读
//! 现有历史日志。历史记录格式不得改变。
//!
//! 注意 "no anchor (pre-B3 log)" 是**合法状态**，不得当作错误。

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::atomic::atomic_as;
use crate::error::{CoreError, CoreResult};

/// 创世 hash：64 个 `0`。
pub const AUDIT_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 锚文件后缀。
pub const AUDIT_HEAD_SUFFIX: &str = ".head";

/// 读尾部时最多读取的字节数（单条记录远小于 2 KB，256 KB 覆盖数千条）。
const TAIL_READ_BYTES: u64 = 262_144;

/// 锚文件路径：`<log>.head`。
pub fn audit_head_path(log_path: &Path) -> PathBuf {
    let name = log_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    log_path.with_file_name(format!("{name}{AUDIT_HEAD_SUFFIX}"))
}

/// 单条审计记录的线格式。
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

/// 记录 hash：对其余字段的**规范化 JSON** 取 SHA256。
///
/// 规范化 = 键排序 + 无多余空白 + 不转义非 ASCII（对应 Python 的
/// `json.dumps(..., sort_keys=True, ensure_ascii=False, separators=(',', ':'))`）。
/// 必须与 Python 侧产出逐字节一致，否则历史链校验会失败。
pub fn record_hash(record: &AuditRecord) -> String {
    // 手工构造规范化 JSON，保证与 Python 的 json.dumps 输出一致：
    // 键按字典序：action, error, ok, prev_hash, target, time, uid
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

/// 对任意 JSON 对象（来自历史文件）重算 hash —— 用 `serde_json` 的排序语义。
///
/// 校验历史记录时必须走这条路径，因为历史记录可能含其它字段。
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

/// 转义为 JSON 字符串字面量（含引号），与 Python `json.dumps` 的转义规则一致。
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

/// 读取最后一条链上记录的 hash；无记录返回 `None`。
///
/// 只读文件尾部；并发写入者写了一半的尾行会被丢弃而不是被解析。
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

    // 尾行不完整（无结尾换行）时截掉它——可能正有并发写入者。
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

/// [`read_last_audit_hash`] 的**如实报错**版本（6.10）。
///
/// 语义严格区分三件事，这正是原实现混为一谈的地方：
///
/// * 文件**不存在** → `Ok(None)`：这是一条新链，用创世值合法。
/// * 文件存在但**为空** → `Ok(None)`：同上。
/// * 文件存在、非空，却**读不出可用的尾 hash** → `Err`：
///   truncate、权限错误、尾部只剩半行、尾行 JSON 损坏 —— 都不能当成「新链」，
///   否则审计链会在没有任何告警的情况下被分叉。
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

    // 尾部不完整（无结尾换行）时截掉它 —— 可能正有并发写入者。
    let text = if buf.last() == Some(&b'\n') {
        buf
    } else {
        match buf.iter().rposition(|&b| b == b'\n') {
            Some(pos) => buf[..=pos].to_vec(),
            // 整个 TAIL_READ_BYTES 窗口里一个换行都没有：这不是「空链」，
            // 而是文件格式已经不可解释。
            None => {
                return Err(CoreError::invalid(format!(
                    "{}: cannot locate a complete audit record within the tail window",
                    log_path.display()
                )))
            }
        }
    };

    let text = String::from_utf8_lossy(&text);
    for line in text.lines().rev() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(h) = value.get("hash").and_then(|v| v.as_str()) {
            return Ok(Some(h.to_string()));
        }
    }
    // 非空文件里一条可用记录都没有 —— 绝不当成新链。
    Err(CoreError::invalid(format!(
        "{}: audit log is non-empty but no record with a `hash` field was found near the tail",
        log_path.display()
    )))
}

/// 追加一条审计记录（对应 `audit()`）。
///
/// 整个「读尾 → 追加 → 重设锚」序列在 `locked()` 临界区内，避免并发的一次性 CLI
/// 与常驻进程交错而分叉哈希链。
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
        // 6.10：**区分「没有记录」与「读不出来」**。
        //
        // 原实现是 `read_last_audit_hash(..).unwrap_or_else(|| AUDIT_GENESIS)`：
        // 只要读尾失败（文件被 truncate、权限错误、尾部只剩半行），就会**静默
        // 从创世值重新开一条链**。结果是审计链被悄悄分叉成两条互不相连的链，
        // 而表面上一切正常 —— 一次故障被伪装成了「新链的第一次写入」。
        //
        // 现在：文件不存在或长度为 0 才用创世值；其余任何读失败都如实报错。
        let prev_hash = match read_last_audit_hash_strict(log_path)? {
            Some(hash) => hash,
            None => AUDIT_GENESIS.to_string(),
        };

        // target 截断到 120 字符、error 截断到 500 字符（与原文一致）。
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
            // 6.11：先 `sync_all` 再写 `.head` 锚。
            //
            // 原实现 `write_all` 之后直接去写锚文件，两边没有任何顺序保证：
            // 掉电时可能落成「锚已更新、日志行没落盘」，下一次 `audit_verify`
            // 就会把一份**完好的**日志判成**截尾篡改**（假告警）。
            // 反过来（日志落了、锚没落）则是一次可容忍的滞后。
            // 先把日志行刷到稳定介质，再更新锚，代价是一行 fsync，换掉一整类假篡改告警。
            f.sync_all().map_err(|e| CoreError::io(log_path, e))?;
        }

        let head = audit_head_path(log_path);
        atomic_as(&head, format!("{}\n", record.hash).as_bytes(), 0o600, None)?;

        // 日志本体权限收紧到 0600（尽力而为）。
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

/// 链校验结果（对应 `audit_verify` 的返回结构）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerdict {
    pub ok: bool,
    pub entries: usize,
    pub anchor: bool,
    pub error: String,
}

/// 校验 `prev_hash` 链与 `.head` 锚（对应 `audit_verify`）。
///
/// 规则（`core.py:320-349` 逐条保留）：
///
/// * B3 之前写的无 hash 记录按 legacy 跳过；一旦见过链上记录，之后任何无 hash
///   记录都是失败（格式回滚会断链）
/// * 首条链上记录的 `prev_hash` 必须等于创世值
/// * 每条记录的 `prev_hash` 必须等于前一条的 hash，且自身 hash 必须重算一致
/// * `.head` 存在且非空时必须等于最后一条链上记录的 hash（截尾检测）
/// * 空锚是 logrotate 后的状态，不参与比对；锚缺失则跳过检查（B3 前日志从未写过）
pub fn audit_verify(log_path: &Path) -> AuditVerdict {
    let head_path = audit_head_path(log_path);
    let mut errors: Vec<String> = Vec::new();
    let mut entries = 0usize;
    let mut chain_started = false;
    let mut prev_hash = AUDIT_GENESIS.to_string();
    let mut last_hash: Option<String> = None;

    let text = match std::fs::read_to_string(log_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return AuditVerdict {
                ok: false,
                entries: 0,
                anchor: false,
                error: format!("read audit log failed: {e}"),
            }
        }
    };

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(raw) {
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

    let anchor_value = match std::fs::read_to_string(&head_path) {
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

/// `audit_verify_cli` 的等价实现：返回退出码。
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

/// 按字符数截断（Python 的 `str[:n]` 语义，不是字节）。
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
        // 与 Python 侧 `json.dumps(payload, sort_keys=True, ensure_ascii=False,
        // separators=(',',':'))` 的输出逐字节对齐是 INV-4 的前提。
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

        // 通过 Value 路径重算必须得到同一结果。
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
        // ensure_ascii=False：中文按原字符参与哈希。
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

        // 篡改内容 → 必须报失败且退出码 1。
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

        // 删掉最后一条：纯链校验看不出来，锚必须抓住它。
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
        // 交换第 2、3 条 → prev_hash 断裂。
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
        // B3 之前的记录：无 hash/prev_hash 字段。
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
        // 追加一个没有结尾换行的半条记录（模拟并发写入者写到一半）。
        let mut text = fs::read_to_string(&log).unwrap();
        text.push_str("{\"partial\":");
        fs::write(&log, text).unwrap();
        // read_last_audit_hash 必须丢弃半行并返回第一条的 hash。
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

    /// 6.10：非空但读不出尾 hash 时，**不得**把它当成新链。
    ///
    /// 原实现 `read_last_audit_hash(..).unwrap_or_else(|| AUDIT_GENESIS)` 会在
    /// 读尾失败时静默从创世值重开一条链 —— 审计链被悄悄分叉成两条互不相连的链，
    /// 表面上却一切正常。
    #[test]
    fn a_non_empty_but_unreadable_log_is_an_error_not_a_fresh_chain() {
        let dir = temp_dir("unreadable-tail");
        let log = dir.join("audit.log");

        // 文件非空，但通篇没有一条可解析记录（模拟 truncate / 尾部损坏）。
        fs::write(&log, b"\x00\x01\x02 not a json record \xff\xfe").unwrap();

        let error = audit(&log, "a", true, "", "").expect_err("不得静默重开新链");
        assert!(
            error.to_string().contains("no record with a `hash` field")
                || error.to_string().contains("complete audit record"),
            "错误必须说明「读不出尾记录」，实际：{error}"
        );

        // 文件内容未被改动（没有追加一条基于创世值的记录）。
        assert_eq!(
            fs::read(&log).unwrap(),
            b"\x00\x01\x02 not a json record \xff\xfe".to_vec(),
            "失败的 audit 不得写入任何记录"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// 空文件与不存在的文件仍然是合法的「新链」。
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
}

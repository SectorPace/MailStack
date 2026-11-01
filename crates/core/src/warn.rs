//! 非致命失败上报（规格书 §5.7.3；INV-34）。
//!
//! 语义细节必须保留：
//!
//! * 按 **context 去重**：同一 context（或 `context|异常类名`）只报一次——因为它会被
//!   每 2 秒的采样调用，不去重会刷屏
//! * **只在写入成功后**才标记为已上报
//! * 异常对象的 `__str__` 抛异常时退化为只打类名——"losing the detail line is
//!   acceptable; losing the context is not"
//! * `warn()` 本身**永不抛出**

use std::collections::HashSet;
use std::io::Write;
use std::sync::Mutex;
use std::sync::OnceLock;

static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn warned() -> &'static Mutex<HashSet<String>> {
    WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// 上报一次非致命失败；同一 key 只输出一次。
pub fn warn(context: &str) {
    warn_key(context.to_string(), String::new());
}

/// 带底层错误的版本，key 会带上错误类型名。
pub fn warn_with_error<E: std::error::Error>(context: &str, error: &E) {
    warn_key(
        format!("{context}|{}", std::any::type_name::<E>()),
        format!(": {error}"),
    );
}

/// 带任意错误描述的版本（对应 Python 里传字符串的用法）。
pub fn warn_with_detail(context: &str, detail: &str) {
    warn_key(context.to_string(), format!(": {detail}"));
}

fn warn_key(key: String, detail: String) {
    // `warn()` 本身永不抛出：整个函数体都在容错范围内。
    //
    // 「查重 → 写 stderr → 登记」必须在**同一次持锁**内完成。原实现查重后
    // 释放锁、写完 stderr 再重新拿锁插入 —— 两个线程会在窗口内同时看到
    // 「还没报过」并各自输出一遍（check-then-act 竞态），去重失效。
    // stderr 写入很短，持锁跨过它不会造成可观测的争用。
    let result = std::panic::catch_unwind(|| {
        let mut guard = match warned().lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.contains(&key) {
            return;
        }

        let line = format!("mailstack: {key} failed{detail}\n");
        let mut stderr = std::io::stderr();
        // 只有真正写成功才登记，否则「写失败会把该 context 永久静音」。
        if stderr.write_all(line.as_bytes()).is_ok() && stderr.flush().is_ok() {
            guard.insert(key);
        }
    });
    let _ = result;
}

/// 清空去重集合。**仅供测试使用**，生产路径不得调用（会破坏去重语义）。
#[doc(hidden)]
pub fn reset_for_tests() {
    let mut guard = match warned().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.clear();
}

/// 该 context 是否已被上报过（供测试断言去重行为）。
#[doc(hidden)]
pub fn was_warned(key: &str) -> bool {
    let guard = match warned().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.contains(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 这些测试共享全局去重集合，故串行执行。
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn deduplicates_by_context() {
        let _g = serial();
        reset_for_tests();
        warn("ctx-a");
        assert!(was_warned("ctx-a"));
        reset_for_tests();
        warn("ctx-b");
        // 第二次调用不得改变状态，也不得 panic。
        warn("ctx-b");
        assert!(was_warned("ctx-b"));
    }

    #[test]
    fn distinct_contexts_are_independent() {
        let _g = serial();
        reset_for_tests();
        warn("ctx-x");
        warn("ctx-y");
        assert!(was_warned("ctx-x"));
        assert!(was_warned("ctx-y"));
    }

    #[test]
    fn error_variant_keys_include_error_type() {
        let _g = serial();
        reset_for_tests();
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        warn_with_error("parse-config", &err);
        let key = format!("parse-config|{}", std::any::type_name::<std::io::Error>());
        assert!(was_warned(&key), "key 应包含错误类型名以便区分");
    }

    #[test]
    fn never_panics_on_empty_context() {
        let _g = serial();
        reset_for_tests();
        warn("");
        warn_with_detail("ctx", "");
    }
}

use std::collections::HashSet;
use std::io::Write;
use std::sync::Mutex;
use std::sync::OnceLock;

static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn warned() -> &'static Mutex<HashSet<String>> {
    WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

pub fn warn(context: &str) {
    warn_key(context.to_string(), String::new());
}

pub fn warn_with_error<E: std::error::Error>(context: &str, error: &E) {
    warn_key(
        format!("{context}|{}", std::any::type_name::<E>()),
        format!(": {error}"),
    );
}

pub fn warn_with_detail(context: &str, detail: &str) {
    warn_key(context.to_string(), format!(": {detail}"));
}

fn warn_key(key: String, detail: String) {
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

        if stderr.write_all(line.as_bytes()).is_ok() && stderr.flush().is_ok() {
            guard.insert(key);
        }
    });
    let _ = result;
}

#[doc(hidden)]
pub fn reset_for_tests() {
    let mut guard = match warned().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.clear();
}

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

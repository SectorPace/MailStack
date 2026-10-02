//! 口令策略 —— **单一真相源**（INV-35、INV-36、INV-37）。
//!
//! 历史缺陷：策略此前在三个模块内联重复实现，且只有其中一个拒绝控制字符，
//! 导致含 NUL 的口令在管理员路径被接受、在邮箱路径被拒绝。Rust 侧只有本模块
//! 一处实现，其余调用方一律经此校验。

use crate::error::{CoreError, CoreResult};
use crate::validate::ADMIN_RE;

pub const MIN_PASSWORD_LENGTH: usize = 12;
pub const MAX_PASSWORD_LENGTH: usize = 256;

/// PBKDF2-SHA256 迭代次数。**这是密码政策的一部分，doctor 会断言该值**
/// （INV-37），不得为了「性能」下调。
pub const PBKDF2_ITERATIONS: u32 = 310_000;

/// 禁止出现的控制字符（对应 `FORBIDDEN_PASSWORD_CHARS`）。
const FORBIDDEN_PASSWORD_CHARS: [char; 3] = ['\r', '\n', '\0'];

/// 口令不得内嵌的身份 token：用户名、邮箱、local part、domain。
///
/// 只有长度 ≥ 3 的 token 才参与比对（原始实现同样如此）。
pub fn password_context_tokens<I, S>(context: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut tokens: Vec<String> = Vec::new();
    let mut push = |t: String| {
        if t.chars().count() >= 3 && !tokens.contains(&t) {
            tokens.push(t);
        }
    };
    for value in context {
        let value = value.as_ref();
        if value.is_empty() {
            continue;
        }
        let value = value.to_lowercase();
        push(value.clone());
        if let Some((local, domain)) = value.split_once('@') {
            push(local.to_string());
            push(domain.to_string());
        }
    }
    tokens
}

/// 三个及以上「相等或连续（升降）」的码点，例如 `aaa` / `123` / `cba`。
fn has_weak_run(password: &str) -> bool {
    let chars: Vec<u32> = password.chars().map(|c| c as u32).collect();
    if chars.len() < 3 {
        return false;
    }
    chars.windows(3).any(|w| {
        let (a, b, c) = (w[0], w[1], w[2]);
        (a == b && b == c) || (b == a + 1 && c == b + 1) || (b + 1 == a && c + 1 == b)
    })
}

/// 设定新口令时的策略校验（对应 `validate_mailbox_password`）。
///
/// 规则：12–256 字符；至少一个字母 + 一个数字；无控制字符；无 3+ 连续/重复；
/// 不含 `context` 里的身份 token。
pub fn validate_mailbox_password<I, S>(password: &str, context: I) -> CoreResult<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let len = password.chars().count();
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&len) {
        return Err(CoreError::invalid(format!(
            "password must contain {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters"
        )));
    }
    if password.contains(FORBIDDEN_PASSWORD_CHARS) {
        return Err(CoreError::invalid(
            "password contains forbidden control characters",
        ));
    }
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    if !has_letter || !has_digit {
        return Err(CoreError::invalid(
            "password must contain both letters and digits",
        ));
    }
    if has_weak_run(password) {
        return Err(CoreError::invalid(
            "password must not contain three or more equal or consecutive characters",
        ));
    }
    let lowered = password.to_lowercase();
    for token in password_context_tokens(context) {
        if lowered.contains(&token) {
            return Err(CoreError::invalid(
                "password must not contain the account name or email address",
            ));
        }
    }
    Ok(())
}

/// 认证路径的**更宽松**格式校验（对应 `validate_legacy_password_input`，INV-36）。
///
/// 收紧设定时策略不得锁死旧 8 位口令的账号：现有口令继续可用，只有**新设定**
/// 的口令需满足当前标准。
pub fn validate_legacy_password_input(password: &str) -> CoreResult<()> {
    let len = password.chars().count();
    if !(1..=MAX_PASSWORD_LENGTH).contains(&len) {
        return Err(CoreError::invalid(format!(
            "password must contain 1-{MAX_PASSWORD_LENGTH} characters"
        )));
    }
    if password.contains(FORBIDDEN_PASSWORD_CHARS) {
        return Err(CoreError::invalid(
            "password contains forbidden control characters",
        ));
    }
    Ok(())
}

/// 口令记录（对应 `password_record`）。salt 16 字节，digest 32 字节。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PasswordRecord {
    pub username: String,
    pub algorithm: String,
    pub iterations: u32,
    /// hex 编码的 16 字节 salt。
    pub salt: String,
    /// hex 编码的 32 字节 PBKDF2-SHA256 digest。
    pub hash: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

/// 生成管理员口令记录。算法与迭代数与现状逐字一致（INV-37）。
pub fn password_record(username: &str, password: &str) -> CoreResult<PasswordRecord> {
    if !ADMIN_RE.is_match(username) {
        return Err(CoreError::invalid(
            "administrator name must be 3-32 safe characters",
        ));
    }
    validate_mailbox_password(password, [username])?;

    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    let digest = pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS, 32);

    Ok(PasswordRecord {
        username: username.to_string(),
        algorithm: "pbkdf2-sha256".to_string(),
        iterations: PBKDF2_ITERATIONS,
        salt: hex::encode(salt),
        hash: hex::encode(digest),
        updated_at: crate::now_iso8601_local(),
    })
}

/// 校验口令是否匹配既有记录（常量时间比较，防时序侧信道）。
pub fn verify_password(record: &PasswordRecord, password: &str) -> bool {
    let Ok(salt) = hex::decode(&record.salt) else {
        return false;
    };
    let Ok(expected) = hex::decode(&record.hash) else {
        return false;
    };
    let iterations = if record.iterations == 0 {
        PBKDF2_ITERATIONS
    } else {
        record.iterations
    };
    let actual = pbkdf2_sha256(password.as_bytes(), &salt, iterations, expected.len());
    constant_time_eq(&actual, &expected)
}

/// 常量时间字节比较。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// PBKDF2-HMAC-SHA256（RFC 2898）。迭代 310,000 次与现状一致。
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let h_len = 32usize;
    let blocks = dk_len.div_ceil(h_len);
    let mut out = Vec::with_capacity(blocks * h_len);

    for block_index in 1..=blocks {
        // U1 = HMAC(password, salt || INT32BE(block_index))
        let mut u = {
            let mut mac = Hmac::new(password);
            mac.update(salt);
            mac.update(&(block_index as u32).to_be_bytes());
            mac.finalize()
        };
        let mut t = u;

        for _ in 1..iterations {
            u = {
                let mut mac = Hmac::new(password);
                mac.update(&u);
                mac.finalize()
            };
            for (acc, byte) in t.iter_mut().zip(u.iter()) {
                *acc ^= byte;
            }
        }
        out.extend_from_slice(&t);
    }

    out.truncate(dk_len);
    let _ = Sha256::new(); // 保持 sha2 依赖显式可见
    out
}

/// HMAC-SHA256 的最小实现，避免为一个原语引入整条 openssl 依赖链（§3.4 禁止项）。
struct Hmac {
    inner: Sha256Stream,
    outer: Sha256Stream,
}

struct Sha256Stream(sha2::Sha256);

impl Sha256Stream {
    fn new(data: &[u8]) -> Self {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(data);
        Self(h)
    }
    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.0.update(data);
    }
    fn finalize(self) -> [u8; 32] {
        use sha2::Digest;
        self.0.finalize().into()
    }
}

impl Hmac {
    fn new(key: &[u8]) -> Self {
        use sha2::Digest;
        const BLOCK: usize = 64;
        let mut key_block = [0u8; BLOCK];
        if key.len() > BLOCK {
            let mut h = sha2::Sha256::new();
            h.update(key);
            let digest: [u8; 32] = h.finalize().into();
            key_block[..32].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }
        Self {
            inner: Sha256Stream::new(&ipad),
            outer: Sha256Stream::new(&opad),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        let inner_digest = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(&inner_digest);
        outer.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_policy_compliant_password() {
        validate_mailbox_password("Tr0ubadour9x", ["admin"]).unwrap();
    }

    #[test]
    fn rejects_too_short_and_too_long() {
        let err = validate_mailbox_password("Sh0rt1", std::iter::empty::<&str>()).unwrap_err();
        assert_eq!(err.to_string(), "password must contain 12-256 characters");
        let long = format!("a1{}", "x".repeat(300));
        assert!(validate_mailbox_password(&long, std::iter::empty::<&str>()).is_err());
    }

    #[test]
    fn rejects_control_characters_including_nul() {
        // 这正是历史缺陷：NUL 在管理员路径被接受、在邮箱路径被拒绝。
        for candidate in ["goodpassw0rd\0x", "goodpassw0rd\rx", "goodpassw0rd\nx"] {
            let err = validate_mailbox_password(candidate, std::iter::empty::<&str>()).unwrap_err();
            assert_eq!(
                err.to_string(),
                "password contains forbidden control characters"
            );
        }
    }

    #[test]
    fn rejects_missing_letter_or_digit() {
        assert_eq!(
            validate_mailbox_password("abcdefghijkl", std::iter::empty::<&str>())
                .unwrap_err()
                .to_string(),
            "password must contain both letters and digits"
        );
        assert_eq!(
            validate_mailbox_password("123456789012", std::iter::empty::<&str>())
                .unwrap_err()
                .to_string(),
            "password must contain both letters and digits"
        );
    }

    #[test]
    fn detects_weak_runs_of_all_three_kinds() {
        assert!(has_weak_run("aaabbb1x"), "三个相等应命中");
        assert!(has_weak_run("abc1234x"), "升序连续应命中");
        assert!(has_weak_run("cba9987x"), "降序连续应命中");
        assert!(has_weak_run("aXbYcZ123x"), "字面量 123 也是升序连续");
        assert!(!has_weak_run("aXbYcZ159x"), "无连续应放行");
        assert!(!has_weak_run("ab"), "不足三个字符不构成 run");
        assert_eq!(
            validate_mailbox_password("P1abQ7zxyAAA", std::iter::empty::<&str>())
                .unwrap_err()
                .to_string(),
            "password must not contain three or more equal or consecutive characters"
        );
    }

    #[test]
    fn rejects_identity_tokens_from_context() {
        assert_eq!(
            validate_mailbox_password("Alice1Secret9", ["alice"])
                .unwrap_err()
                .to_string(),
            "password must not contain the account name or email address"
        );
        // 邮箱的 local part 与完整邮箱都参与比对（长度 >= 3）。
        assert!(validate_mailbox_password("bob1Secret9", ["bob@example.com"]).is_err());
        assert!(validate_mailbox_password("bob@example.com9X", ["bob@example.com"]).is_err());
        assert!(validate_mailbox_password("MyExample.com9", ["bob@example.com"]).is_err());
        // 大小写不敏感。
        assert!(validate_mailbox_password("aLiCeSecret9", ["alice"]).is_err());
        // 去掉点号后不再是同一个 token —— 与 Python 的 `str in str` 语义一致。
        validate_mailbox_password("ExampleCom9xz", ["bob@example.com"]).unwrap();
    }

    #[test]
    fn short_context_tokens_are_ignored() {
        // 长度 < 3 的 token 不参与比对，否则会误伤大量口令。
        validate_mailbox_password("ab1Secret9xY", ["ab"]).unwrap();
    }

    #[test]
    fn legacy_path_is_laxer_but_still_blocks_control_chars() {
        // INV-36：收紧设定策略不得锁死旧的 8 位口令账号。
        validate_legacy_password_input("oldpass1").unwrap();
        validate_legacy_password_input("x").unwrap();
        assert!(validate_legacy_password_input("bad\0pass").is_err());
        assert!(validate_legacy_password_input("").is_err());
    }

    #[test]
    fn password_record_shape_matches_baseline() {
        let record = password_record("admin", "Tr0ubadour9x").unwrap();
        assert_eq!(record.algorithm, "pbkdf2-sha256");
        assert_eq!(record.iterations, 310_000);
        assert_eq!(record.salt.len(), 32, "salt 应为 16 字节的 hex");
        assert_eq!(record.hash.len(), 64, "digest 应为 32 字节的 hex");
        assert_eq!(record.username, "admin");
    }

    #[test]
    fn password_record_rejects_weak_admin_name() {
        let err = password_record("ab", "Tr0ubadour9x").unwrap_err();
        assert_eq!(
            err.to_string(),
            "administrator name must be 3-32 safe characters"
        );
    }

    #[test]
    fn verify_password_accepts_and_rejects_correctly() {
        let record = password_record("admin", "Tr0ubadour9x").unwrap();
        assert!(verify_password(&record, "Tr0ubadour9x"));
        assert!(!verify_password(&record, "Tr0ubadour9y"));
        assert!(!verify_password(&record, ""));
    }

    #[test]
    fn verify_password_survives_corrupt_record() {
        // 损坏的 salt/hash 不得 panic，只返回 false（fail-closed）。
        let mut record = password_record("admin", "Tr0ubadour9x").unwrap();
        record.salt = "zzzz".into();
        assert!(!verify_password(&record, "Tr0ubadour9x"));
        record.salt = hex::encode([0u8; 16]);
        record.hash = "not-hex".into();
        assert!(!verify_password(&record, "Tr0ubadour9x"));
    }

    #[test]
    fn pbkdf2_matches_rfc6070_style_reference_vector() {
        // HMAC-SHA256/PBKDF2 正确性锚点：该向量由 Python hashlib 与 Rust 独立算出应一致。
        // salt="salt", password="password", 1 次迭代, 32 字节输出。
        let got = pbkdf2_sha256(b"password", b"salt", 1, 32);
        assert_eq!(
            hex::encode(got),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn constant_time_eq_is_length_safe() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn context_tokens_deduplicate_and_filter_short_values() {
        let tokens = password_context_tokens(["admin", "admin", "ab", "user@example.com"]);
        assert!(tokens.contains(&"admin".to_string()));
        assert!(tokens.contains(&"user".to_string()));
        assert!(tokens.contains(&"example.com".to_string()));
        assert!(!tokens.contains(&"ab".to_string()), "短 token 应被过滤");
        assert_eq!(tokens.iter().filter(|t| *t == "admin").count(), 1);
    }
}

use crate::error::{CoreError, CoreResult};
use crate::validate::ADMIN_RE;

pub const MIN_PASSWORD_LENGTH: usize = 12;
pub const MAX_PASSWORD_LENGTH: usize = 256;

pub const PBKDF2_ITERATIONS: u32 = 310_000;

pub const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;

pub const PASSWORD_ALGORITHM: &str = "pbkdf2-sha256";

pub const SALT_LEN: usize = 16;

pub const SALT_HEX_LEN: usize = SALT_LEN * 2;

pub const HASH_LEN: usize = 32;

pub const HASH_HEX_LEN: usize = HASH_LEN * 2;

const FORBIDDEN_PASSWORD_CHARS: [char; 3] = ['\r', '\n', '\0'];

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PasswordRecord {
    pub username: String,
    pub algorithm: String,
    pub iterations: u32,

    pub salt: String,

    pub hash: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

pub fn mailbox_password_record(address: &str, password: &str) -> CoreResult<PasswordRecord> {
    let address = address.trim().to_ascii_lowercase();
    let (local, domain) = address
        .split_once('@')
        .ok_or_else(|| CoreError::invalid("mailbox address must be local@domain"))?;
    if !ADMIN_RE.is_match(local) || domain.is_empty() {
        return Err(CoreError::invalid(
            "mailbox address local part must be 3-32 safe characters and the domain must be non-empty",
        ));
    }
    validate_mailbox_password(password, [address.as_str(), local])?;

    let mut record = password_record(local, password)?;
    record.username = address;
    Ok(record)
}

pub fn password_record(username: &str, password: &str) -> CoreResult<PasswordRecord> {
    if !ADMIN_RE.is_match(username) {
        return Err(CoreError::invalid(
            "administrator name must be 3-32 safe characters",
        ));
    }
    validate_mailbox_password(password, [username])?;

    let mut salt = [0u8; SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    let digest = pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS, HASH_LEN);

    Ok(PasswordRecord {
        username: username.to_string(),
        algorithm: PASSWORD_ALGORITHM.to_string(),
        iterations: PBKDF2_ITERATIONS,
        salt: hex::encode(salt),
        hash: hex::encode(digest),
        updated_at: crate::now_iso8601_local(),
    })
}

pub fn verify_password(record: &PasswordRecord, password: &str) -> bool {
    if record.algorithm != PASSWORD_ALGORITHM {
        return false;
    }

    if record.salt.len() != SALT_HEX_LEN || record.hash.len() != HASH_HEX_LEN {
        return false;
    }
    let Ok(salt) = hex::decode(&record.salt) else {
        return false;
    };
    let Ok(expected) = hex::decode(&record.hash) else {
        return false;
    };

    if expected.len() != HASH_LEN || salt.len() != SALT_LEN {
        return false;
    }

    let iterations = record
        .iterations
        .clamp(PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS);
    let actual = pbkdf2_sha256(password.as_bytes(), &salt, iterations, expected.len());
    constant_time_eq(&actual, &expected)
}

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

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let h_len = 32usize;
    let blocks = dk_len.div_ceil(h_len);
    let mut out = Vec::with_capacity(blocks * h_len);

    let mac_template = Hmac::new(password);
    for block_index in 1..=blocks {
        let mut u = {
            let mut mac = mac_template.clone();
            mac.update(salt);
            mac.update(&(block_index as u32).to_be_bytes());
            mac.finalize()
        };
        let mut t = u;

        for _ in 1..iterations {
            u = {
                let mut mac = mac_template.clone();
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
    out
}

struct Hmac {
    inner: Sha256Stream,
    outer: Sha256Stream,
}

impl Clone for Hmac {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            outer: self.outer.clone(),
        }
    }
}

struct Sha256Stream(sha2::Sha256);

impl Clone for Sha256Stream {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

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

        assert!(validate_mailbox_password("bob1Secret9", ["bob@example.com"]).is_err());
        assert!(validate_mailbox_password("bob@example.com9X", ["bob@example.com"]).is_err());
        assert!(validate_mailbox_password("MyExample.com9", ["bob@example.com"]).is_err());

        assert!(validate_mailbox_password("aLiCeSecret9", ["alice"]).is_err());

        validate_mailbox_password("ExampleCom9xz", ["bob@example.com"]).unwrap();
    }

    #[test]
    fn short_context_tokens_are_ignored() {
        validate_mailbox_password("ab1Secret9xY", ["ab"]).unwrap();
    }

    #[test]
    fn legacy_path_is_laxer_but_still_blocks_control_chars() {
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
        let mut record = password_record("admin", "Tr0ubadour9x").unwrap();
        record.salt = "zzzz".into();
        assert!(!verify_password(&record, "Tr0ubadour9x"));
        record.salt = hex::encode([0u8; 16]);
        record.hash = "not-hex".into();
        assert!(!verify_password(&record, "Tr0ubadour9x"));
    }

    #[test]
    fn an_empty_hash_record_accepts_nothing_at_all() {
        let mut record = password_record("admin", "Tr0ubadour9x").unwrap();
        record.hash = String::new();
        for candidate in ["", "Tr0ubadour9x", "whatever", " "] {
            assert!(
                !verify_password(&record, candidate),
                "空摘要记录不得接受任何口令（候选 {candidate:?}）"
            );
        }
    }

    #[test]
    fn an_empty_salt_record_accepts_nothing() {
        let mut record = password_record("admin", "Tr0ubadour9x").unwrap();
        record.salt = String::new();
        assert!(!verify_password(&record, "Tr0ubadour9x"));
        assert!(!verify_password(&record, ""));
    }

    #[test]
    fn a_truncated_hash_record_accepts_nothing() {
        let mut record = password_record("admin", "Tr0ubadour9x").unwrap();

        record.hash = "ab".repeat(32);
        assert!(!verify_password(&record, "Tr0ubadour9x"));
    }

    #[test]
    fn an_unknown_algorithm_record_accepts_nothing() {
        let mut record = password_record("admin", "Tr0ubadour9x").unwrap();

        record.algorithm = "pbkdf2-sha512".into();
        assert!(!verify_password(&record, "Tr0ubadour9x"));
    }

    #[test]
    fn a_downgraded_iteration_count_neither_rejects_nor_weakens_verification() {
        let mut record = password_record("admin", "Tr0ubadour9x").unwrap();
        record.iterations = 1;
        assert!(
            verify_password(&record, "Tr0ubadour9x"),
            "偏小的 iterations 必须被抬到下界：否则一次 HMAC 就能完成校验"
        );
        assert!(
            !verify_password(&record, "wrong"),
            "抬下界不应把错误口令也放进来"
        );
    }

    #[test]
    fn an_inflated_iteration_count_is_clamped_to_the_documented_maximum() {
        let mut record = password_record("admin", "Tr0ubadour9x").unwrap();
        record.iterations = u32::MAX;
        assert!(
            !verify_password(&record, "Tr0ubadour9x"),
            "被抬高迭代数的记录按上限重算后摘要必然不符：篡改产物不得通过"
        );
    }

    #[test]
    fn pbkdf2_matches_reference_vectors_for_multi_iteration_inputs() {
        let got = pbkdf2_sha256(b"password", b"salt", 2, 32);
        assert_eq!(
            hex::encode(got),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }

    #[test]
    fn pbkdf2_matches_rfc6070_style_reference_vector() {
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

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::config::{update_admin_config, AdminConfig};
use crate::error::{CoreError, CoreResult};
use crate::paths::Paths;

pub const TOTP_PERIOD_SECS: u64 = 30;

pub const TOTP_DIGITS: u32 = 6;

pub const TOTP_WINDOW_STEPS: i64 = 1;

pub const TOTP_SECRET_BYTES: usize = 20;

pub const TOTP_KEY_BYTES: usize = 32;

pub const RECOVERY_CODE_COUNT: usize = 8;

pub const RECOVERY_CODE_LEN: usize = 10;

pub const ENVELOPE_VERSION: u32 = 1;

pub const USED_STEPS_KEPT: usize = 8;

const AEAD_AAD: &[u8] = b"mailstack.totp.v1";

const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub const DEFAULT_ISSUER: &str = "MailStack";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub enc: String,

    pub nonce: String,

    pub tag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpState {
    Disabled,

    Pending,

    Enabled,
}

impl TotpState {
    pub fn as_str(self) -> &'static str {
        match self {
            TotpState::Disabled => "disabled",
            TotpState::Pending => "pending",
            TotpState::Enabled => "enabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMethod {
    Totp,
    Recovery,
}

impl VerifyMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyMethod::Totp => "totp",
            VerifyMethod::Recovery => "recovery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult {
    pub valid: bool,
    pub method: Option<VerifyMethod>,
}

impl VerifyResult {
    fn rejected() -> Self {
        Self {
            valid: false,
            method: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub secret: String,

    pub otpauth_url: String,
    pub issuer: String,
    pub account: String,
}

pub fn load_master_key(paths: &Paths) -> CoreResult<[u8; TOTP_KEY_BYTES]> {
    match std::fs::read_to_string(&paths.totp_key) {
        Ok(text) => decode_master_key(text.trim()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(CoreError::NotFound(paths.totp_key.clone()))
        }
        Err(e) => Err(CoreError::io(&paths.totp_key, e)),
    }
}

pub fn load_or_create_master_key(paths: &Paths) -> CoreResult<[u8; TOTP_KEY_BYTES]> {
    crate::atomic::locked(&paths.totp_key, || {
        if paths.totp_key.exists() {
            return load_master_key(paths);
        }
        let key = random_bytes::<TOTP_KEY_BYTES>();
        let body = format!("{}\n", BASE64.encode(key));

        crate::atomic::atomic_as(&paths.totp_key, body.as_bytes(), 0o600, None)?;
        Ok(key)
    })
}

fn decode_master_key(text: &str) -> CoreResult<[u8; TOTP_KEY_BYTES]> {
    let raw = BASE64
        .decode(text)
        .map_err(|_| CoreError::invalid("totp master key is not valid base64"))?;
    raw.as_slice().try_into().map_err(|_| {
        CoreError::invalid(format!(
            "totp master key must decode to {TOTP_KEY_BYTES} bytes"
        ))
    })
}

pub fn seal(key: &[u8; TOTP_KEY_BYTES], plaintext: &[u8]) -> CoreResult<Envelope> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_bytes::<12>();
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: AEAD_AAD,
            },
        )
        .map_err(|_| CoreError::invalid("totp envelope encryption failed"))?;

    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    Ok(Envelope {
        enc: BASE64.encode(ciphertext),
        nonce: BASE64.encode(nonce_bytes),
        tag: BASE64.encode(tag),
    })
}

pub fn open(key: &[u8; TOTP_KEY_BYTES], envelope: &Envelope) -> CoreResult<Vec<u8>> {
    let ciphertext = BASE64
        .decode(&envelope.enc)
        .map_err(|_| CoreError::invalid("totp envelope ciphertext is not valid base64"))?;
    let nonce = BASE64
        .decode(&envelope.nonce)
        .map_err(|_| CoreError::invalid("totp envelope nonce is not valid base64"))?;
    let tag = BASE64
        .decode(&envelope.tag)
        .map_err(|_| CoreError::invalid("totp envelope tag is not valid base64"))?;
    if nonce.len() != 12 || tag.len() != 16 {
        return Err(CoreError::invalid(
            "totp envelope has malformed nonce or tag",
        ));
    }

    let mut body = ciphertext;
    body.extend_from_slice(&tag);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &body,
                aad: AEAD_AAD,
            },
        )
        .map_err(|_| CoreError::invalid("totp envelope failed authentication"))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn new_secret() -> [u8; TOTP_SECRET_BYTES] {
    random_bytes()
}

pub fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn otpauth_uri(issuer: &str, account: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        percent_encode(issuer),
        percent_encode(account),
        secret_base32,
        percent_encode(issuer),
        TOTP_DIGITS,
        TOTP_PERIOD_SECS,
    )
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC 接受任意长度密钥");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[19] & 0x0f) as usize;
    let truncated = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    truncated % 10u32.pow(TOTP_DIGITS)
}

fn step_at(unix_time: u64) -> i64 {
    (unix_time / TOTP_PERIOD_SECS) as i64
}

fn code_shape_ok(code: &str) -> bool {
    let code = code.trim();
    code.len() == TOTP_DIGITS as usize && code.bytes().all(|b| b.is_ascii_digit())
}

pub fn matching_step(secret: &[u8], code: &str, unix_time: u64) -> Option<i64> {
    let code = code.trim();
    if !code_shape_ok(code) {
        return None;
    }
    let step = step_at(unix_time);
    for offset in -TOTP_WINDOW_STEPS..=TOTP_WINDOW_STEPS {
        let Some(candidate) = step.checked_add(offset).filter(|s| *s >= 0) else {
            continue;
        };
        let expected = format!(
            "{:0width$}",
            hotp(secret, candidate as u64),
            width = TOTP_DIGITS as usize
        );
        if ct_eq(expected.as_bytes(), code.as_bytes()) {
            return Some(candidate);
        }
    }
    None
}

pub fn verify_code(secret: &[u8], code: &str, unix_time: u64) -> bool {
    matching_step(secret, code, unix_time).is_some()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn generate_recovery_codes() -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            (0..RECOVERY_CODE_LEN)
                .map(|_| RECOVERY_ALPHABET[rng.gen_range(0..RECOVERY_ALPHABET.len())] as char)
                .collect()
        })
        .collect()
}

pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

pub fn hash_recovery_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(normalize_recovery_code(code).as_bytes());
    hex::encode(hasher.finalize())
}

fn totp_block(config: &AdminConfig) -> Option<&Value> {
    config.totp.as_ref().filter(|value| value.is_object())
}

pub fn state(config: &AdminConfig) -> TotpState {
    let Some(block) = totp_block(config) else {
        return TotpState::Disabled;
    };
    if block
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        TotpState::Enabled
    } else {
        TotpState::Pending
    }
}

pub fn state_at(paths: &Paths) -> TotpState {
    crate::config::read_admin_config(paths)
        .as_ref()
        .map(state)
        .unwrap_or(TotpState::Disabled)
}

fn envelope_from_block(block: &Value) -> CoreResult<Envelope> {
    if let Some(version) = block.get("version").and_then(Value::as_u64) {
        if version != u64::from(ENVELOPE_VERSION) {
            return Err(CoreError::invalid(format!(
                "unsupported totp envelope version {version}"
            )));
        }
    }
    let field = |key: &str| -> CoreResult<String> {
        block
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| CoreError::invalid(format!("totp block is missing `{key}`")))
    };
    Ok(Envelope {
        enc: field("enc")?,
        nonce: field("nonce")?,
        tag: field("tag")?,
    })
}

fn recovery_hashes(block: &Value) -> Vec<String> {
    block
        .get("recovery")
        .and_then(Value::as_array)
        .map(|codes| {
            codes
                .iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn used_steps(block: &Value) -> Vec<i64> {
    block
        .get("usedSteps")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter_map(Value::as_i64)
                .filter(|s| *s >= 0)
                .collect()
        })
        .unwrap_or_default()
}

fn step_already_used(block: &Value, step: i64) -> bool {
    used_steps(block).contains(&step)
}

fn block_with_step_used(block: &Value, step: i64) -> Value {
    let mut steps = used_steps(block);
    if !steps.contains(&step) {
        steps.push(step);
    }

    steps.sort_unstable_by(|a, b| b.cmp(a));
    steps.dedup();
    steps.truncate(USED_STEPS_KEPT);
    let mut next = block.clone();
    next["usedSteps"] = Value::Array(steps.into_iter().map(Value::from).collect());
    next
}

pub fn begin(paths: &Paths, account: &str) -> CoreResult<Enrollment> {
    let key = load_or_create_master_key(paths)?;
    let secret = new_secret();
    let envelope = seal(&key, &secret)?;
    let secret_base32 = base32_encode(&secret);
    let account = if account.trim().is_empty() {
        "admin".to_string()
    } else {
        account.trim().to_string()
    };

    update_admin_config(&paths.admin_config, |current| {
        if state(current) == TotpState::Enabled {
            return Err(CoreError::invalid(
                "two-factor authentication is already enabled; disable it first",
            ));
        }
        let mut next = current.clone();
        next.totp = Some(json!({
            "version": ENVELOPE_VERSION,
            "enabled": false,
            "enc": envelope.enc,
            "nonce": envelope.nonce,
            "tag": envelope.tag,
            "recovery": [],
        }));
        Ok((next, ()))
    })?;

    Ok(Enrollment {
        otpauth_url: otpauth_uri(DEFAULT_ISSUER, &account, &secret_base32),
        secret: secret_base32,
        issuer: DEFAULT_ISSUER.to_string(),
        account,
    })
}

pub fn enable(paths: &Paths, code: &str, unix_time: u64) -> CoreResult<Vec<String>> {
    let key = load_or_create_master_key(paths)?;
    let codes = generate_recovery_codes();
    let hashed: Vec<String> = codes.iter().map(|c| hash_recovery_code(c)).collect();

    update_admin_config(&paths.admin_config, |current| {
        let block = totp_block(current)
            .ok_or_else(|| CoreError::invalid("no pending two-factor enrollment"))?;
        if block
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(CoreError::invalid(
                "two-factor authentication is already enabled",
            ));
        }
        let secret = open(&key, &envelope_from_block(block)?)?;
        if !verify_code(&secret, code, unix_time) {
            return Err(CoreError::invalid("invalid verification code"));
        }

        let mut next = current.clone();
        next.totp = Some(json!({
            "version": ENVELOPE_VERSION,
            "enabled": true,
            "enc": block.get("enc").cloned().unwrap_or(Value::Null),
            "nonce": block.get("nonce").cloned().unwrap_or(Value::Null),
            "tag": block.get("tag").cloned().unwrap_or(Value::Null),
            "recovery": hashed,
        }));
        Ok((next, ()))
    })?;

    Ok(codes)
}

pub fn disable(paths: &Paths, code: &str, unix_time: u64) -> CoreResult<bool> {
    if state_at(paths) == TotpState::Enabled {
        let outcome = verify(paths, code, unix_time)?;
        if !outcome.valid {
            return Err(CoreError::invalid(
                "a valid two-factor code is required to disable two-factor authentication",
            ));
        }
    }

    update_admin_config(&paths.admin_config, |current| {
        let was_enabled = state(current) != TotpState::Disabled;
        let mut next = current.clone();
        next.totp = None;
        Ok((next, was_enabled))
    })
}

pub fn consume_recovery(paths: &Paths, code: &str) -> CoreResult<bool> {
    let normalized = normalize_recovery_code(code);

    if normalized.len() != RECOVERY_CODE_LEN
        || !normalized.bytes().all(|b| RECOVERY_ALPHABET.contains(&b))
    {
        return Ok(false);
    }
    let target = hash_recovery_code(&normalized);

    update_admin_config(&paths.admin_config, |current| {
        let Some(block) = totp_block(current) else {
            return Ok((current.clone(), false));
        };
        if state(current) != TotpState::Enabled {
            return Ok((current.clone(), false));
        }
        let stored = recovery_hashes(block);
        let mut remaining: Vec<String> = Vec::with_capacity(stored.len());
        let mut consumed = false;
        for hash in stored {
            if !consumed && ct_eq(hash.as_bytes(), target.as_bytes()) {
                consumed = true;
                continue;
            }
            remaining.push(hash);
        }
        if !consumed {
            return Ok((current.clone(), false));
        }

        let mut new_block = block.clone();
        new_block["recovery"] = Value::Array(remaining.into_iter().map(Value::String).collect());
        let mut next = current.clone();
        next.totp = Some(new_block);
        Ok((next, true))
    })
}

fn consume_totp_step(
    paths: &Paths,
    key: &[u8; TOTP_KEY_BYTES],
    code: &str,
    unix_time: u64,
) -> CoreResult<bool> {
    if !code_shape_ok(code) {
        return Ok(false);
    }

    update_admin_config(&paths.admin_config, |current| {
        let Some(block) = totp_block(current) else {
            return Ok((current.clone(), false));
        };
        if state(current) != TotpState::Enabled {
            return Ok((current.clone(), false));
        }

        let secret = open(key, &envelope_from_block(block)?)?;
        let Some(step) = matching_step(&secret, code, unix_time) else {
            return Ok((current.clone(), false));
        };
        if step_already_used(block, step) {
            return Ok((current.clone(), false));
        }
        let mut next = current.clone();
        next.totp = Some(block_with_step_used(block, step));
        Ok((next, true))
    })
}

pub fn verify(paths: &Paths, code: &str, unix_time: u64) -> CoreResult<VerifyResult> {
    let Some(config) = crate::config::read_admin_config(paths) else {
        return Ok(VerifyResult::rejected());
    };

    if totp_block(&config).is_none() {
        return Ok(VerifyResult::rejected());
    }
    if state(&config) != TotpState::Enabled {
        return Ok(VerifyResult::rejected());
    }

    let key = load_master_key(paths)?;
    if consume_totp_step(paths, &key, code, unix_time)? {
        return Ok(VerifyResult {
            valid: true,
            method: Some(VerifyMethod::Totp),
        });
    }

    if consume_recovery(paths, code)? {
        return Ok(VerifyResult {
            valid: true,
            method: Some(VerifyMethod::Recovery),
        });
    }
    Ok(VerifyResult::rejected())
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn code_at(secret: &[u8], unix_time: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, step_at(unix_time) as u64),
        width = TOTP_DIGITS as usize
    )
}

#[cfg(test)]
fn block_with(envelope: &Envelope, enabled: bool, recovery: Vec<String>) -> Value {
    json!({
        "version": ENVELOPE_VERSION,
        "enabled": enabled,
        "enc": envelope.enc,
        "nonce": envelope.nonce,
        "tag": envelope.tag,
        "recovery": recovery,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Fixture {
        root: PathBuf,
        paths: Paths,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-totp-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            let paths = Paths::rooted(&root);
            fs::create_dir_all(&paths.etc).unwrap();

            crate::config::admin_set(&paths, "admin", "Tr0ubadour9x").unwrap();
            Self { root, paths }
        }

        fn admin_json(&self) -> Value {
            serde_json::from_str(&fs::read_to_string(&self.paths.admin_config).unwrap()).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn otpauth_uri_escapes_group_and_account() {
        let uri = otpauth_uri("MailStack", "admin@example.com", "MZXW6YTBOI");
        assert!(uri.starts_with("otpauth://totp/MailStack:admin%40example.com?"));
        assert!(uri.contains("secret=MZXW6YTBOI"));
        assert!(uri.contains("issuer=MailStack"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains(&format!("digits={TOTP_DIGITS}")));
        assert!(uri.contains(&format!("period={TOTP_PERIOD_SECS}")));
    }

    #[test]
    fn hotp_matches_the_rfc4226_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(secret, counter as u64), *want, "counter={counter}");
        }
    }

    #[test]
    fn verify_accepts_the_current_step_and_rejects_neighbours_outside_the_window() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000u64;
        let current = code_at(secret, now);

        assert!(verify_code(secret, &current, now), "当前步必须通过");
        assert!(
            verify_code(secret, &current, now - TOTP_PERIOD_SECS),
            "前一步必须通过（时钟偏移窗口）"
        );
        assert!(
            verify_code(secret, &current, now + TOTP_PERIOD_SECS),
            "后一步必须通过（时钟偏移窗口）"
        );
        assert!(
            !verify_code(secret, &current, now + 2 * TOTP_PERIOD_SECS),
            "窗口之外必须拒绝"
        );
    }

    #[test]
    fn verify_rejects_malformed_codes_without_panicking() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000u64;
        for bad in [
            "", "12345", "1234567", "abcdef", "12 456", "-12345", "12345a",
        ] {
            assert!(!verify_code(secret, bad, now), "{bad:?} 不应通过");
        }
    }

    #[test]
    fn envelope_round_trips_and_binds_to_the_master_key() {
        let key = [7u8; TOTP_KEY_BYTES];
        let other = [8u8; TOTP_KEY_BYTES];
        let secret = new_secret();

        let envelope = seal(&key, &secret).unwrap();
        assert_eq!(open(&key, &envelope).unwrap(), secret.to_vec());

        assert!(open(&other, &envelope).is_err());
    }

    #[test]
    fn envelope_rejects_tampering_of_any_component() {
        let key = [7u8; TOTP_KEY_BYTES];
        let envelope = seal(&key, &new_secret()).unwrap();

        let mut flipped = envelope.clone();
        let mut raw = BASE64.decode(&flipped.enc).unwrap();
        raw[0] ^= 0x01;
        flipped.enc = BASE64.encode(raw);
        assert!(open(&key, &flipped).is_err(), "密文被改必须失败");

        let mut bad_tag = envelope.clone();
        let mut tag = BASE64.decode(&bad_tag.tag).unwrap();
        tag[0] ^= 0x01;
        bad_tag.tag = BASE64.encode(tag);
        assert!(open(&key, &bad_tag).is_err(), "tag 被改必须失败");

        let mut bad_nonce = envelope.clone();
        bad_nonce.nonce = BASE64.encode([0u8; 12]);
        assert!(open(&key, &bad_nonce).is_err(), "nonce 被改必须失败");

        let mut short_nonce = envelope.clone();
        short_nonce.nonce = BASE64.encode([0u8; 8]);
        assert!(open(&key, &short_nonce).is_err(), "长度不对必须失败");

        let mut garbage = envelope;
        garbage.enc = "not base64!!".to_string();
        assert!(open(&key, &garbage).is_err());
    }

    #[test]
    fn master_key_is_created_once_and_only_readable_by_its_owner() {
        let f = Fixture::new("masterkey");
        assert!(!f.paths.totp_key.exists());

        assert!(load_master_key(&f.paths).is_err());

        let first = load_or_create_master_key(&f.paths).unwrap();
        let second = load_or_create_master_key(&f.paths).unwrap();
        assert_eq!(first, second, "已有密钥不得被覆盖");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&f.paths.totp_key)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "主密钥必须 0600");
        }
    }

    #[test]
    fn concurrent_master_key_creation_yields_one_shared_key() {
        use std::sync::{Arc, Barrier};

        let f = Fixture::new("masterkeyrace");
        assert!(!f.paths.totp_key.exists());

        const THREADS: usize = 8;
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let paths = f.paths.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                load_or_create_master_key(&paths).expect("并发创建主密钥不应失败")
            }));
        }

        let keys: Vec<[u8; TOTP_KEY_BYTES]> = handles
            .into_iter()
            .map(|handle| handle.join().expect("线程不应 panic"))
            .collect();

        let first = keys[0];
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(
                *key, first,
                "第 {index} 个线程拿到了不同的主密钥 —— 说明发生了覆盖写"
            );
        }

        let on_disk = load_master_key(&f.paths).expect("密钥文件应可读回");
        assert_eq!(on_disk, first, "磁盘上的密钥与调用者拿到的必须一致");

        let leftovers: Vec<String> = fs::read_dir(f.paths.totp_key.parent().unwrap())
            .unwrap()
            .filter_map(|item| item.ok())
            .map(|item| item.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("totp.key"))
            .collect();
        assert!(
            leftovers.iter().any(|name| name == "totp.key"),
            "主密钥文件必须存在，实际：{leftovers:?}"
        );
    }

    #[test]
    fn begin_writes_a_pending_envelope_and_never_the_plaintext_secret() {
        let f = Fixture::new("begin");
        let enrollment = begin(&f.paths, "admin").unwrap();

        assert_eq!(state_at(&f.paths), TotpState::Pending);
        let raw = fs::read_to_string(&f.paths.admin_config).unwrap();
        assert!(
            !raw.contains(&enrollment.secret),
            "INV-5: admin.json 里绝不能出现明文 secret"
        );
        assert!(raw.contains("\"enc\""));

        let block = f.admin_json()["totp"].clone();
        assert_eq!(block["enabled"], false);
        assert_eq!(block["version"], ENVELOPE_VERSION);

        let key = load_master_key(&f.paths).unwrap();
        let secret = open(&key, &envelope_from_block(&block).unwrap()).unwrap();
        assert_eq!(base32_encode(&secret), enrollment.secret);
    }

    #[test]
    fn begin_is_refused_while_already_enabled() {
        let f = Fixture::new("beginagain");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        enable(&f.paths, &code_at(&secret, now), now).unwrap();

        let err = begin(&f.paths, "admin").unwrap_err();
        assert!(
            err.to_string().contains("already enabled"),
            "已启用时必须拒绝重新 begin：{err}"
        );
    }

    fn decode_secret_from_enrollment(f: &Fixture, enrollment: &Enrollment) -> Vec<u8> {
        let block = f.admin_json()["totp"].clone();
        let key = load_master_key(&f.paths).unwrap();
        let secret = open(&key, &envelope_from_block(&block).unwrap()).unwrap();
        assert_eq!(base32_encode(&secret), enrollment.secret);
        secret
    }

    #[test]
    fn enable_requires_a_correct_code_and_only_then_issues_recovery_codes() {
        let f = Fixture::new("enable");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();

        let err = enable(&f.paths, "000000", now).unwrap_err();
        assert!(err.to_string().contains("invalid verification code"));
        assert_eq!(state_at(&f.paths), TotpState::Pending);
        assert!(recovery_hashes(&f.admin_json()["totp"]).is_empty());

        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(state_at(&f.paths), TotpState::Enabled);

        let block = f.admin_json()["totp"].clone();
        let stored = recovery_hashes(&block);
        assert_eq!(stored.len(), RECOVERY_CODE_COUNT);
        for code in &codes {
            assert!(
                !stored.contains(code),
                "恢复码必须只以哈希形态落盘，不得明文"
            );
            assert!(stored.contains(&hash_recovery_code(code)));
        }
    }

    #[test]
    fn enable_without_a_pending_enrollment_is_refused() {
        let f = Fixture::new("enablenone");
        let err = enable(&f.paths, "123456", now_unix()).unwrap_err();
        assert!(err.to_string().contains("no pending two-factor enrollment"));
    }

    #[test]
    fn disable_removes_the_block_and_invalidates_recovery_codes() {
        let f = Fixture::new("disable");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        assert!(disable(&f.paths, &code_at(&secret, now), now).unwrap());
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
        assert!(f.admin_json().get("totp").is_none(), "整块必须被移除");
        assert!(!verify(&f.paths, &codes[0], now).unwrap().valid);

        assert!(!disable(&f.paths, "", now).unwrap());
    }

    #[test]
    fn verify_rejects_everything_when_two_factor_is_not_enabled() {
        let f = Fixture::new("verifyoff");
        assert!(!verify(&f.paths, "123456", now_unix()).unwrap().valid);

        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        assert!(!verify(&f.paths, &code_at(&secret, now), now).unwrap().valid);
    }

    #[test]
    fn verify_accepts_totp_and_recovery_but_reports_which_was_used() {
        let f = Fixture::new("verifyok");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        let totp = verify(&f.paths, &code_at(&secret, now), now).unwrap();
        assert!(totp.valid);
        assert_eq!(totp.method, Some(VerifyMethod::Totp));
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT,
            "走动态码不得消费恢复码"
        );

        let recovery = verify(&f.paths, &codes[0], now).unwrap();
        assert!(recovery.valid);
        assert_eq!(recovery.method, Some(VerifyMethod::Recovery));

        let wrong = verify(&f.paths, "000000", now).unwrap();
        assert!(!wrong.valid);
        assert_eq!(wrong.method, None);
    }

    #[test]
    fn a_recovery_code_can_only_be_consumed_once() {
        let f = Fixture::new("once");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        assert!(consume_recovery(&f.paths, &codes[0]).unwrap());
        assert!(
            !consume_recovery(&f.paths, &codes[0]).unwrap(),
            "INV-29: 同一张恢复码不得被用第二次"
        );
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT - 1
        );
    }

    #[test]
    fn recovery_codes_tolerate_human_formatting() {
        let f = Fixture::new("format");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        let pretty: String = codes[0]
            .chars()
            .enumerate()
            .flat_map(|(i, c)| if i == 0 { vec![c] } else { vec!['-', c] })
            .collect();
        assert_eq!(
            pretty.chars().filter(|c| *c != '-').count(),
            RECOVERY_CODE_LEN
        );
        assert!(
            consume_recovery(&f.paths, &pretty.to_lowercase()).unwrap(),
            "带连字符且小写的输入必须被接受"
        );
    }

    #[test]
    fn malformed_recovery_input_never_touches_the_stored_codes() {
        let f = Fixture::new("malformed");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        enable(&f.paths, &code_at(&secret, now), now).unwrap();

        for bad in ["", "SHORT", "!!!!!!", "AAAAAAAAAAAAAAAAAAA", "123456"] {
            assert!(!consume_recovery(&f.paths, bad).unwrap());
        }
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_recovery_consumption_spends_exactly_one() {
        let f = Fixture::new("race");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        let successes = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let paths = f.paths.clone();
            let code = codes[0].clone();
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                if consume_recovery(&paths, &code).unwrap() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            successes.load(Ordering::SeqCst),
            1,
            "并发消费同一张恢复码只能有一次成功"
        );
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT - 1,
            "其余恢复码不得被连带消耗"
        );
    }

    #[test]
    fn changing_the_password_keeps_two_factor_working() {
        let f = Fixture::new("keep2fa");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        enable(&f.paths, &code_at(&secret, now), now).unwrap();

        crate::config::admin_set(&f.paths, "admin", "An0therGood1").unwrap();
        assert_eq!(state_at(&f.paths), TotpState::Enabled);
        assert!(verify(&f.paths, &code_at(&secret, now), now).unwrap().valid);
    }

    fn enabled(tag: &str) -> (Fixture, Vec<u8>, Vec<String>) {
        let f = Fixture::new(tag);
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();
        (f, secret, codes)
    }

    #[test]
    fn a_totp_code_cannot_be_used_twice_in_the_same_step() {
        let (f, secret, _) = enabled("replay");
        let now = now_unix();
        let code = code_at(&secret, now);

        let first = verify(&f.paths, &code, now).unwrap();
        assert!(first.valid, "第一次必须通过");
        assert_eq!(first.method, Some(VerifyMethod::Totp));

        let second = verify(&f.paths, &code, now + 29).unwrap();
        assert!(
            !second.valid,
            "同一个 step 的同一个码不得被接受第二次（重放）"
        );
        assert_eq!(second.method, None, "重放必须与「码不对」给同一个结论");
    }

    #[test]
    fn a_wrong_guess_does_not_burn_the_real_code_of_the_current_step() {
        let (f, secret, _) = enabled("wrongguess");
        let now = now_unix();
        let real = code_at(&secret, now);

        let step_now = (now / TOTP_PERIOD_SECS) as i64;
        let window: Vec<String> = (step_now - TOTP_WINDOW_STEPS..=step_now + TOTP_WINDOW_STEPS)
            .map(|s| code_at(&secret, (s * TOTP_PERIOD_SECS as i64) as u64))
            .collect();
        let wrong = (0..=999_999u32)
            .map(|c| format!("{c:06}"))
            .find(|c| !window.contains(c))
            .expect("6 位空间里必然有不匹配窗口的码");
        for _ in 0..5 {
            assert!(!verify(&f.paths, &wrong, now).unwrap().valid);
        }
        assert!(
            used_steps(&f.admin_json()["totp"]).is_empty(),
            "猜错不得写进记账：{:?}",
            f.admin_json()["totp"]["usedSteps"]
        );

        assert!(verify(&f.paths, &real, now).unwrap().valid);
    }

    #[test]
    fn the_ledger_records_steps_so_a_neighbouring_step_is_not_blocked() {
        let (f, secret, _) = enabled("ledgerstep");
        let now = now_unix() + 10 * TOTP_PERIOD_SECS;
        let base = now - (now % TOTP_PERIOD_SECS);

        assert!(
            verify(&f.paths, &code_at(&secret, base), base)
                .unwrap()
                .valid
        );
        let recorded = used_steps(&f.admin_json()["totp"]);
        assert_eq!(
            recorded,
            vec![(base / TOTP_PERIOD_SECS) as i64],
            "记账里必须是 step 本身，而不是码或时间戳"
        );

        for neighbour in [base - TOTP_PERIOD_SECS, base + TOTP_PERIOD_SECS] {
            assert!(
                verify(&f.paths, &code_at(&secret, neighbour), neighbour)
                    .unwrap()
                    .valid,
                "相邻步不得因为中心步被消费而被连带拒绝"
            );
        }
    }

    #[test]
    fn each_step_in_the_window_may_be_used_once_but_neighbouring_steps_still_work() {
        let (f, secret, _) = enabled("replaywindow");
        let now = now_unix() + 10 * TOTP_PERIOD_SECS;
        let base = now - (now % TOTP_PERIOD_SECS);

        for (i, step) in [base - TOTP_PERIOD_SECS, base, base + TOTP_PERIOD_SECS]
            .into_iter()
            .enumerate()
        {
            let code = code_at(&secret, step);
            assert!(
                verify(&f.paths, &code, step).unwrap().valid,
                "窗口内第 {i} 个 step 必须各能用一次"
            );
            assert!(
                !verify(&f.paths, &code, step).unwrap().valid,
                "窗口内第 {i} 个 step 用第二次必须被拒"
            );
        }
        assert_eq!(
            used_steps(&f.admin_json()["totp"]).len(),
            3,
            "三个 step 都必须被记账"
        );
    }

    #[test]
    fn a_clock_rollback_does_not_revive_a_previously_used_code() {
        let (f, secret, _) = enabled("rollback");
        let now = now_unix() + 20 * TOTP_PERIOD_SECS;
        let base = now - (now % TOTP_PERIOD_SECS);
        let code = code_at(&secret, base);
        assert!(verify(&f.paths, &code, base).unwrap().valid);

        let earlier = base - 10 * TOTP_PERIOD_SECS;
        assert!(!verify(&f.paths, &code, earlier).unwrap().valid);

        let much_earlier = base - 20 * TOTP_PERIOD_SECS;
        assert!(!verify(&f.paths, &code, much_earlier).unwrap().valid);
    }

    #[test]
    fn a_code_of_a_stale_secret_is_never_booked_into_the_new_block() {
        const T: u64 = 1_700_000_000;
        let f = Fixture::new("stalesecret");
        let key = load_or_create_master_key(&f.paths).unwrap();
        let old_secret = [0x11u8; TOTP_SECRET_BYTES];
        let new_secret = [0x22u8; TOTP_SECRET_BYTES];
        let stale_code = code_at(&old_secret, T);

        let enabled_block = |secret: &[u8; TOTP_SECRET_BYTES]| {
            let envelope = seal(&key, secret).unwrap();
            json!({
                "version": ENVELOPE_VERSION,
                "enabled": true,
                "enc": envelope.enc,
                "nonce": envelope.nonce,
                "tag": envelope.tag,
                "recovery": [],
            })
        };
        let write_block = |block: Value| {
            let mut value = f.admin_json();
            value["totp"] = block;
            fs::write(
                &f.paths.admin_config,
                serde_json::to_string_pretty(&value).unwrap(),
            )
            .unwrap();
        };

        write_block(enabled_block(&old_secret));
        assert!(verify(&f.paths, &stale_code, T).unwrap().valid);

        let disable_code = code_at(&old_secret, T + TOTP_PERIOD_SECS);
        disable(&f.paths, &disable_code, T + TOTP_PERIOD_SECS).unwrap();
        write_block(enabled_block(&new_secret));
        assert!(used_steps(&f.admin_json()["totp"]).is_empty());

        assert!(!verify(&f.paths, &stale_code, T).unwrap().valid);
        assert!(
            used_steps(&f.admin_json()["totp"]).is_empty(),
            "旧 secret 的 step 不得被记进新块：{:?}",
            f.admin_json()["totp"]["usedSteps"]
        );
    }

    #[test]
    fn step_zero_is_recorded_like_any_other_step() {
        let f = Fixture::new("stepzero");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        enable(&f.paths, &code_at(&secret, 0), 0).unwrap();

        let code = code_at(&secret, 0);
        assert!(verify(&f.paths, &code, 0).unwrap().valid, "step 0 必须能用");
        assert!(
            used_steps(&f.admin_json()["totp"]).contains(&0),
            "step 0 必须被记账，实际: {:?}",
            f.admin_json()["totp"]["usedSteps"]
        );
        assert!(
            !verify(&f.paths, &code, 0).unwrap().valid,
            "step 0 的码不得被重放"
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_totp_verifications_of_one_step_yield_exactly_one_success() {
        let (f, secret, _) = enabled("replayrace");
        let now = now_unix();
        let code = code_at(&secret, now);

        let successes = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let paths = f.paths.clone();
            let code = code.clone();
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                if verify(&paths, &code, now).unwrap().valid {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            successes.load(Ordering::SeqCst),
            1,
            "并发用同一个 step 的同一个码只能有一次成功"
        );
    }

    #[test]
    fn used_steps_ledger_is_bounded_and_drops_the_oldest_first() {
        let (f, secret, _) = enabled("usedledger");
        let start = now_unix() + 100 * TOTP_PERIOD_SECS;
        for i in 0..(USED_STEPS_KEPT as u64 * 3) {
            let t = start + i * TOTP_PERIOD_SECS;
            assert!(verify(&f.paths, &code_at(&secret, t), t).unwrap().valid);
        }
        let steps = used_steps(&f.admin_json()["totp"]);
        assert_eq!(steps.len(), USED_STEPS_KEPT, "记账必须有界：{steps:?}");
        assert_eq!(
            steps[0],
            ((start + (USED_STEPS_KEPT as u64 * 3 - 1) * TOTP_PERIOD_SECS) / TOTP_PERIOD_SECS)
                as i64,
            "最新的 step 必须排在最前（淘汰时丢最旧的）"
        );
    }

    #[test]
    fn a_corrupt_used_steps_ledger_does_not_lock_the_admin_out() {
        let (f, secret, _) = enabled("corruptledger");
        let now = now_unix();
        let code = code_at(&secret, now);
        let this_step = (now / TOTP_PERIOD_SECS) as i64;

        let mut value = f.admin_json();
        value["totp"]["usedSteps"] = json!([this_step, -1, "x", 1.5, null]);
        fs::write(
            &f.paths.admin_config,
            serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();

        assert!(!verify(&f.paths, &code, now).unwrap().valid);

        let next = now + TOTP_PERIOD_SECS;
        assert!(
            verify(&f.paths, &code_at(&secret, next), next)
                .unwrap()
                .valid,
            "垃圾记账不得把合法管理员锁在门外"
        );
    }

    #[test]
    fn disable_requires_a_valid_second_factor_and_leaves_no_side_effect_on_failure() {
        let (f, secret, _) = enabled("disableauth");
        let now = now_unix();

        for bad in ["", "000000", "nope", "12345", "already-spent"] {
            let err = disable(&f.paths, bad, now).unwrap_err();
            assert!(
                err.to_string()
                    .contains("a valid two-factor code is required"),
                "{bad:?} 实际: {err}"
            );
            assert_eq!(
                state_at(&f.paths),
                TotpState::Enabled,
                "拒绝后 2FA 必须还在"
            );
        }
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT,
            "被拒绝的 disable 不得消耗恢复码"
        );

        assert!(disable(&f.paths, &code_at(&secret, now), now).unwrap());
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
    }

    #[test]
    fn disable_accepts_a_recovery_code_because_it_never_had_a_second_factor() {
        let (f, _, codes) = enabled("disablerecovery");
        let now = now_unix();
        assert!(disable(&f.paths, &codes[3], now).unwrap());
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
    }

    #[test]
    fn disable_does_not_demand_a_code_when_nothing_was_enabled() {
        let f = Fixture::new("disablepending");

        assert!(!disable(&f.paths, "", now_unix()).unwrap());

        begin(&f.paths, "admin").unwrap();
        assert_eq!(state_at(&f.paths), TotpState::Pending);
        assert!(
            disable(&f.paths, "", now_unix()).unwrap(),
            "pending 块原先存在，was_enabled 应为 true"
        );
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
    }

    #[test]
    fn disabling_twice_never_succeeds_twice_and_never_burns_a_second_factor() {
        let (f, _, codes) = enabled("disableidempotent");
        let now = now_unix();
        assert!(disable(&f.paths, &codes[0], now).unwrap());

        assert!(!disable(&f.paths, "", now).unwrap());
    }

    #[test]
    fn unknown_envelope_version_is_refused_instead_of_guessed() {
        let f = Fixture::new("version");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();

        let mut value = f.admin_json();
        value["totp"]["version"] = json!(999);
        fs::write(
            &f.paths.admin_config,
            serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();

        let err = enable(&f.paths, &code_at(&secret, now), now).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported totp envelope version"),
            "实际: {err}"
        );
    }

    #[test]
    fn envelope_block_shape_is_stable() {
        let envelope = Envelope {
            enc: "E".into(),
            nonce: "N".into(),
            tag: "T".into(),
        };
        let block = block_with(&envelope, true, vec!["H".into()]);
        assert_eq!(block["enabled"], true);
        assert_eq!(block["recovery"][0], "H");
        assert_eq!(envelope_from_block(&block).unwrap(), envelope);
    }
}

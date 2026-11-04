use std::fs;
use std::path::{Path, PathBuf};

use mail_auth::dkim::generate::DkimKeyPair;
use mailstack_core::paths::Paths;
use mailstack_core::validate::{DKIM_SELECTOR_RE, DOMAIN_RE};
use mailstack_core::warn::{warn, warn_with_error};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::PrivatePkcs1KeyDer;
use serde::Serialize;

use crate::error::{AuthError, AuthResult};

pub const DEFAULT_DKIM_SELECTOR: &str = "mailstack";

pub const DKIM_KEY_BITS: usize = 2048;

pub const DKIM_KEY_GROUP: &str = "opendkim";

pub const DKIM_KEY_MODE: u32 = 0o640;

pub const MAX_DOMAIN_LENGTH: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DkimRotation {
    pub status: &'static str,
    pub domain: String,
    pub selector: String,

    pub record: String,

    #[serde(skip)]
    pub public_key_spki_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimKeyMaterial {
    pub domain: String,
    pub selector: String,

    pub private_key_pem: String,

    pub public_key_spki_b64: String,

    pub txt_value: String,

    pub txt_record: String,
}

pub fn validate_domain(domain: &str) -> AuthResult<String> {
    let domain = domain.trim().to_ascii_lowercase();
    if !DOMAIN_RE.is_match(&domain) || domain.len() > MAX_DOMAIN_LENGTH {
        return Err(AuthError::invalid("invalid domain format"));
    }
    Ok(domain)
}

pub fn validate_selector(selector: Option<&str>) -> AuthResult<String> {
    let selector = selector.unwrap_or("").trim().to_ascii_lowercase();
    let selector = if selector.is_empty() {
        DEFAULT_DKIM_SELECTOR.to_string()
    } else {
        selector
    };
    if !DKIM_SELECTOR_RE.is_match(&selector) {
        return Err(AuthError::invalid("invalid DKIM selector"));
    }
    Ok(selector)
}

pub fn dkim_key_dir(paths: &Paths, domain: &str) -> PathBuf {
    paths.opendkim.join("keys").join(domain)
}

pub fn private_key_path(paths: &Paths, domain: &str, selector: &str) -> PathBuf {
    dkim_key_dir(paths, domain).join(format!("{selector}.private"))
}

pub fn txt_record_path(paths: &Paths, domain: &str, selector: &str) -> PathBuf {
    dkim_key_dir(paths, domain).join(format!("{selector}.txt"))
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::with_capacity(4);
    let mut value = len;
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    bytes.reverse();
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(&bytes);
    out
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 5);
    out.push(tag);
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

const RSA_ALGORITHM_IDENTIFIER: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

pub fn spki_from_pkcs1(pkcs1: &[u8]) -> Vec<u8> {
    let mut bit_string = Vec::with_capacity(pkcs1.len() + 1);
    bit_string.push(0x00);
    bit_string.extend_from_slice(pkcs1);
    let bit_string = der_wrap(0x03, &bit_string);

    let mut content = Vec::with_capacity(RSA_ALGORITHM_IDENTIFIER.len() + bit_string.len());
    content.extend_from_slice(&RSA_ALGORITHM_IDENTIFIER);
    content.extend_from_slice(&bit_string);
    der_wrap(0x30, &content)
}

pub fn pkcs1_pem(der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 64);
    out.push_str("-----BEGIN RSA PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END RSA PRIVATE KEY-----\n");
    out
}

const TXT_CHUNK_LIMIT: usize = 255;

pub fn zone_txt_fragment(owner: &str, value: &str, comment: &str) -> String {
    let mut chunks: Vec<&str> = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let mut take = rest.len().min(TXT_CHUNK_LIMIT);
        while take < rest.len() && !rest.is_char_boundary(take) {
            take -= 1;
        }
        let (head, tail) = rest.split_at(take);
        chunks.push(head);
        rest = tail;
    }
    if chunks.is_empty() {
        chunks.push("");
    }

    let mut out = String::with_capacity(value.len() + chunks.len() * 16 + owner.len() + 64);
    out.push_str(owner);
    out.push_str("\tIN\tTXT\t( ");
    for (index, chunk) in chunks.iter().enumerate() {
        if index > 0 {
            out.push_str("\n\t");
        }
        out.push('"');
        out.push_str(chunk);
        out.push('"');
    }
    out.push_str(" )  ; ");
    out.push_str(comment);
    out
}

pub fn dkim_txt_value(public_key_spki_b64: &str) -> String {
    format!("v=DKIM1; h=sha256; k=rsa; p={public_key_spki_b64}")
}

pub fn generate_key_material(
    domain: &str,
    selector: &str,
    bits: usize,
) -> AuthResult<DkimKeyMaterial> {
    let pair = DkimKeyPair::generate_rsa(bits).map_err(|_| AuthError::KeyGeneration)?;
    let private_key_pem = pkcs1_pem(pair.private_key());
    let spki = spki_from_pkcs1(pair.public_key());
    let public_key_spki_b64 = base64_encode(&spki);
    let txt_value = dkim_txt_value(&public_key_spki_b64);
    let txt_record = zone_txt_fragment(
        &format!("{selector}._domainkey"),
        &txt_value,
        &format!("----- DKIM key {selector} for {domain}"),
    );
    Ok(DkimKeyMaterial {
        domain: domain.to_string(),
        selector: selector.to_string(),
        private_key_pem,
        public_key_spki_b64,
        txt_value,
        txt_record,
    })
}

pub fn apply_key_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(DKIM_KEY_MODE)) {
            warn_with_error(&format!("chmod {} to 0640", path.display()), &error);
        }

        match mailstack_core::atomic::gid_by_name(DKIM_KEY_GROUP) {
            Some(gid) => {
                if let Err(error) = std::os::unix::fs::chown(path, Some(0), Some(gid)) {
                    warn_with_error(
                        &format!("chown {} to root:{}", path.display(), DKIM_KEY_GROUP),
                        &error,
                    );
                }
            }

            None => warn(&format!(
                "chown {} to root:{}",
                path.display(),
                DKIM_KEY_GROUP
            )),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

pub fn load_private_key_der(path: &Path) -> AuthResult<Vec<u8>> {
    let pem = fs::read(path).map_err(|error| AuthError::io(path, error))?;
    let der = PrivatePkcs1KeyDer::from_pem_slice(&pem)
        .map_err(|error| AuthError::Signing(format!("{}: {error}", path.display())))?;
    Ok(der.secret_pkcs1_der().to_vec())
}

pub fn rotate(paths: &Paths, domain: &str, selector: Option<&str>) -> AuthResult<DkimRotation> {
    let domain = validate_domain(domain)?;
    let selector = validate_selector(selector)?;

    let dir = dkim_key_dir(paths, &domain);
    fs::create_dir_all(&dir).map_err(|error| AuthError::io(&dir, error))?;

    let private_path = private_key_path(paths, &domain, &selector);
    let txt_path = txt_record_path(paths, &domain, &selector);

    mailstack_core::atomic::locked_with(&private_path, || {
        rotate_locked(&dir, &domain, &selector, &private_path, &txt_path)
    })
}

fn rotate_locked(
    dir: &Path,
    domain: &str,
    selector: &str,
    private_path: &Path,
    txt_path: &Path,
) -> AuthResult<DkimRotation> {
    let old_txt = mailstack_core::atomic::file_snapshot(txt_path)?;

    let material = generate_key_material(domain, selector, DKIM_KEY_BITS)?;

    let staging = RotationStaging::create(dir)?;
    let staged_private = staging.path().join("dkim.private");
    let staged_txt = staging.path().join("dkim.txt");

    mailstack_core::atomic::atomic_as(
        &staged_private,
        material.private_key_pem.as_bytes(),
        0o600,
        None,
    )?;

    load_private_key_der(&staged_private)?;

    apply_key_permissions(&staged_private);
    mailstack_core::atomic::atomic_as(&staged_txt, material.txt_record.as_bytes(), 0o644, None)?;

    let rollback_txt = || -> String {
        match mailstack_core::atomic::file_restore(txt_path, &old_txt, None) {
            Ok(()) => "已回滚 .txt".to_string(),
            Err(error) => format!("回滚 .txt 也失败（{error}）"),
        }
    };

    if let Err(error) = fs::rename(&staged_txt, txt_path) {
        return Err(AuthError::Signing(format!(
            "DKIM 轮换失败：无法发布 DNS 记录（{error}）；私钥未改动"
        )));
    }

    #[cfg(test)]
    let injected_failure = FAIL_BEFORE_PRIVATE_RENAME.with(|flag| flag.replace(false));
    #[cfg(not(test))]
    let injected_failure = false;

    let publish_error = if injected_failure {
        Some("注入的失败点（.txt 已发布、私钥 rename 之前）".to_string())
    } else {
        fs::rename(&staged_private, private_path)
            .err()
            .map(|error| error.to_string())
    };
    if let Some(detail) = publish_error {
        let rollback = rollback_txt();
        return Err(AuthError::Signing(format!(
            "DKIM 轮换失败：无法发布私钥（{detail}）；旧私钥保持不变，{rollback}"
        )));
    }

    fsync_dir(dir);

    Ok(DkimRotation {
        status: "ok",
        domain: domain.to_string(),
        selector: selector.to_string(),
        record: material.txt_record,
        public_key_spki_b64: material.public_key_spki_b64,
    })
}

#[cfg(test)]
thread_local! {
    static FAIL_BEFORE_PRIVATE_RENAME: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

struct RotationStaging {
    path: PathBuf,
}

impl RotationStaging {
    fn create(parent: &Path) -> AuthResult<Self> {
        let path = parent.join(format!(".rotate-{}", unique_tag()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|error| AuthError::io(&path, error))?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir(&path).map_err(|error| AuthError::io(&path, error))?;
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RotationStaging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn unique_tag() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}.{}.{}", std::process::id(), seq, nanos)
}

fn fsync_dir(dir: &Path) {
    match fs::File::open(dir) {
        Ok(handle) => {
            if let Err(error) = handle.sync_all() {
                warn_with_error(&format!("fsync {}", dir.display()), &error);
            }
        }
        Err(error) => warn_with_error(&format!("open dir {}", dir.display()), &error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn fixture() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        (dir, paths)
    }

    fn shared_material() -> &'static DkimKeyMaterial {
        static MATERIAL: OnceLock<DkimKeyMaterial> = OnceLock::new();
        MATERIAL.get_or_init(|| {
            generate_key_material("example.com", "mailstack", DKIM_KEY_BITS).expect("生成密钥")
        })
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "输入 {input:?}");
        }
    }

    #[test]
    fn der_length_uses_short_and_long_forms() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(127), vec![0x7f]);
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(290), vec![0x82, 0x01, 0x22]);
        assert_eq!(der_length(65535), vec![0x82, 0xff, 0xff]);
        assert_eq!(der_length(65536), vec![0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn public_key_is_spki_not_pkcs1() {
        let material = shared_material();
        assert!(
            material
                .public_key_spki_b64
                .starts_with("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"),
            "p= 必须是 SPKI（RFC 6376 生态约定），实际前缀：{}",
            &material.public_key_spki_b64[..24.min(material.public_key_spki_b64.len())]
        );

        assert!(
            !material.public_key_spki_b64.starts_with("MIIBCgKCAQEA"),
            "不得把 PKCS#1 直接当作 p= 发布"
        );
    }

    #[test]
    fn spki_wrapping_is_exactly_the_pkcs1_plus_a_fixed_header() {
        let pair = DkimKeyPair::generate_rsa(DKIM_KEY_BITS).expect("生成密钥");
        let pkcs1 = pair.public_key();
        let spki = spki_from_pkcs1(pkcs1);
        assert_eq!(
            spki.len(),
            pkcs1.len() + 24,
            "2048 位 SPKI 只应比 PKCS#1 多 24 字节固定头"
        );
        assert_eq!(&spki[24..], pkcs1, "SPKI 尾部必须逐字是 PKCS#1");

        assert_eq!(
            &spki[4..19],
            &RSA_ALGORITHM_IDENTIFIER[..],
            "AlgorithmIdentifier 必须是 rsaEncryption"
        );
        assert_eq!(&spki[..4], &[0x30, 0x82, 0x01, 0x22], "外层长度必须自洽");

        assert_eq!(&spki[19..24], &[0x03, 0x82, 0x01, 0x0f, 0x00]);
    }

    #[test]
    fn zone_fragment_round_trips_after_stripping_quotes_and_whitespace() {
        let value = dkim_txt_value(&shared_material().public_key_spki_b64);
        let fragment = zone_txt_fragment("mailstack._domainkey", &value, "----- c");
        let flattened: String = fragment
            .chars()
            .filter(|c| *c != '"' && !c.is_whitespace())
            .collect();
        assert!(
            flattened.contains(&value.replace(' ', "")),
            "去引号去空白后必须包含完整 TXT 值"
        );
        assert!(
            flattened.contains(&format!("p={}", shared_material().public_key_spki_b64)),
            "p= 的 base64 不得被截断"
        );
    }

    #[test]
    fn zone_fragment_splits_long_values_below_the_dns_limit() {
        let value = "A".repeat(600);
        let fragment = zone_txt_fragment("x._domainkey", &value, "c");
        for line in fragment.lines() {
            let quoted: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
            for payload in quoted {
                assert!(
                    payload.len() <= TXT_CHUNK_LIMIT,
                    "每个引号串不得超过 255 字节（实际 {}）：{payload:?}",
                    payload.len()
                );
            }
        }
    }

    #[test]
    fn domain_and_selector_validation_uses_the_python_contract() {
        assert_eq!(validate_domain("Example.COM").unwrap(), "example.com");
        assert_eq!(
            validate_domain("bad domain").unwrap_err().to_string(),
            "invalid domain format"
        );
        assert_eq!(
            validate_domain("example").unwrap_err().to_string(),
            "invalid domain format"
        );

        assert_eq!(validate_selector(None).unwrap(), DEFAULT_DKIM_SELECTOR);
        assert_eq!(
            validate_selector(Some("  ")).unwrap(),
            DEFAULT_DKIM_SELECTOR
        );
        assert_eq!(validate_selector(Some("Mail-1")).unwrap(), "mail-1");
        assert_eq!(
            validate_selector(Some("bad selector"))
                .unwrap_err()
                .to_string(),
            "invalid DKIM selector"
        );
    }

    #[test]
    fn domain_total_length_is_capped_at_253_before_path_use() {
        let a63 = "a".repeat(63);
        let too_long = format!("{a63}.{a63}.{a63}.{a63}.com");
        assert_eq!(too_long.len(), 259);
        assert!(
            DOMAIN_RE.is_match(&too_long),
            "正则放行超长域名 —— 这正是本守卫要补的洞"
        );
        assert_eq!(
            validate_domain(&too_long).unwrap_err().to_string(),
            "invalid domain format"
        );

        let at_limit = format!("{a63}.{a63}.{a63}.{}", "a".repeat(61));
        assert_eq!(at_limit.len(), 253);
        assert_eq!(validate_domain(&at_limit).unwrap(), at_limit);
    }

    #[test]
    fn key_paths_live_under_the_opendkim_keys_directory() {
        let paths = Paths::production();
        assert_eq!(
            private_key_path(&paths, "example.com", "mailstack"),
            PathBuf::from("/etc/opendkim/keys/example.com/mailstack.private")
        );
        assert_eq!(
            txt_record_path(&paths, "example.com", "mailstack"),
            PathBuf::from("/etc/opendkim/keys/example.com/mailstack.txt")
        );
    }

    #[test]
    fn rotate_writes_both_files_and_returns_the_zone_record() {
        let (_dir, paths) = fixture();
        let rotation = rotate(&paths, "Example.COM", Some("Mail")).expect("轮换密钥");

        assert_eq!(rotation.status, "ok");
        assert_eq!(rotation.domain, "example.com");
        assert_eq!(rotation.selector, "mail");

        let private = private_key_path(&paths, "example.com", "mail");
        let txt = txt_record_path(&paths, "example.com", "mail");
        assert!(private.is_file(), "私钥必须落盘：{}", private.display());
        assert!(txt.is_file(), "DNS 记录必须落盘：{}", txt.display());

        let on_disk = std::fs::read_to_string(&txt).unwrap();
        assert_eq!(
            on_disk, rotation.record,
            "返回的 record 必须与 .txt 内容一致"
        );

        let der = load_private_key_der(&private).expect("读回私钥");
        assert!(!der.is_empty(), "解出的 DER 不得为空");
    }

    #[cfg(unix)]
    #[test]
    fn rotated_private_key_is_never_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, paths) = fixture();
        rotate(&paths, "example.com", None).expect("轮换密钥");
        let private = private_key_path(&paths, "example.com", DEFAULT_DKIM_SELECTOR);
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o007, 0, "私钥不得对其他人可读（实际 {mode:o}）");
        assert_eq!(mode, DKIM_KEY_MODE, "加固后应为 0640（实际 {mode:o}）");
    }

    fn spki_from_zone_record(record: &str) -> String {
        let flattened: String = record
            .chars()
            .filter(|c| *c != '"' && !c.is_whitespace())
            .collect();
        let tail = flattened
            .split("p=")
            .nth(1)
            .expect("DKIM zone 片段里必须有 p=");
        tail.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
            .collect()
    }

    fn private_key_matches_record(private: &Path, record: &str) -> Result<(), String> {
        let der = load_private_key_der(private).map_err(|e| e.to_string())?;
        let message = b"From: alice@example.com\r\nSubject: pair check\r\n\r\nbody\r\n";
        let signed = crate::dkim::sign_with_default_headers(
            &der,
            "example.com",
            DEFAULT_DKIM_SELECTOR,
            message,
        )
        .map_err(|e| e.to_string())?;

        let cache = crate::cache::TxtCache::new();
        let public = spki_from_zone_record(record);
        cache
            .add_domain_key(
                &format!("{DEFAULT_DKIM_SELECTOR}._domainkey.example.com"),
                dkim_txt_value(&public).as_bytes(),
            )
            .map_err(|e| e.to_string())?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let verdicts = runtime
            .block_on(async {
                let resolver = crate::cache::system_resolver().map_err(|e| e.to_string())?;
                crate::dkim::verify_with(&resolver, &cache, &signed)
                    .await
                    .map_err(|e| e.to_string())
            })
            .map_err(|e| e.to_string())?;
        match verdicts.as_slice() {
            [verdict] if verdict.status.is_pass() => Ok(()),
            other => Err(format!("私钥与 .txt 不是一对：{other:?}")),
        }
    }

    #[test]
    fn a_failed_rotation_keeps_the_old_private_key_and_the_old_record() {
        let (_dir, paths) = fixture();

        let first = rotate(&paths, "example.com", None).expect("首次轮换");
        let private = private_key_path(&paths, "example.com", DEFAULT_DKIM_SELECTOR);
        let txt = txt_record_path(&paths, "example.com", DEFAULT_DKIM_SELECTOR);
        let old_private = std::fs::read(&private).expect("旧私钥");
        let old_record = std::fs::read_to_string(&txt).expect("旧 DNS 记录");
        assert_eq!(old_record, first.record);
        private_key_matches_record(&private, &old_record).expect("旧 pair 必须自洽");

        FAIL_BEFORE_PRIVATE_RENAME.with(|flag| flag.set(true));
        let error = rotate(&paths, "example.com", None).expect_err("注入点必须让轮换失败");
        assert!(
            error.to_string().contains("注入的失败点"),
            "错误必须如实说明失败阶段：{error}"
        );

        assert_eq!(
            std::fs::read(&private).expect("旧私钥必须仍在"),
            old_private,
            "轮换失败不得改动旧私钥"
        );
        assert_eq!(
            std::fs::read_to_string(&txt).expect("旧记录必须仍在"),
            old_record,
            ".txt 必须回滚成旧记录，否则运维会发布一把没有私钥的公钥"
        );

        private_key_matches_record(&private, &old_record).expect("失败后旧 pair 必须仍可用");

        let leftovers: Vec<String> = fs::read_dir(dkim_key_dir(&paths, "example.com"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with(".rotate-"))
            .collect();
        assert!(leftovers.is_empty(), "不得残留 staging 目录: {leftovers:?}");
    }

    #[test]
    fn concurrent_rotations_serialise_into_a_consistent_key_pair() {
        let (_dir, paths) = fixture();

        rotate(&paths, "example.com", None).expect("首次轮换");

        let mut handles = Vec::new();
        for _ in 0..3 {
            let paths = paths.clone();
            handles.push(std::thread::spawn(move || {
                rotate(&paths, "example.com", None).expect("并发轮换应串行化后成功")
            }));
        }
        let rotations: Vec<DkimRotation> = handles
            .into_iter()
            .map(|handle| handle.join().expect("轮换线程不得 panic"))
            .collect();

        let private = private_key_path(&paths, "example.com", DEFAULT_DKIM_SELECTOR);
        let txt = txt_record_path(&paths, "example.com", DEFAULT_DKIM_SELECTOR);
        let on_disk = std::fs::read_to_string(&txt).expect("读回 DNS 记录");
        assert!(
            rotations.iter().any(|rotation| rotation.record == on_disk),
            "磁盘上的记录必须来自某一次真实轮换（说明有人拿到了与磁盘不符的 record）"
        );

        private_key_matches_record(&private, &on_disk)
            .unwrap_or_else(|error| panic!("并发轮换产生了不一致的 key pair：{error}"));
    }
}

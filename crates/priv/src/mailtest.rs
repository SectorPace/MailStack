use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use mailstack_smtp::client::SmtpSession;
use mailstack_smtp::target::pinned_from_addresses;
use mailstack_smtp::{AddressPolicy, PinnedDialer, TlsMode};

pub const SUBMISSION_TIMEOUT_SECS: u64 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSubmission {
    pub mail_from: String,

    pub recipient: String,

    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionReport {
    pub code: u16,

    pub banner: String,
}

pub trait MailSubmitter: Send + Sync {
    fn submit<'a>(
        &'a self,
        submission: LocalSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<SubmissionReport, String>> + Send + 'a>>;
}

pub struct SystemMailSubmitter {
    dialer: Option<PinnedDialer>,
    reason: Option<String>,
}

impl SystemMailSubmitter {
    pub fn new() -> Self {
        match PinnedDialer::with_webpki_roots(Duration::from_secs(SUBMISSION_TIMEOUT_SECS)) {
            Ok(dialer) => Self {
                dialer: Some(dialer),
                reason: None,
            },
            Err(error) => {
                mailstack_core::warn::warn_with_detail(
                    "build local submission TLS configuration",
                    &error.to_string(),
                );
                Self {
                    dialer: None,
                    reason: Some(error.to_string()),
                }
            }
        }
    }
}

impl Default for SystemMailSubmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl MailSubmitter for SystemMailSubmitter {
    fn submit<'a>(
        &'a self,
        submission: LocalSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<SubmissionReport, String>> + Send + 'a>> {
        let Some(dialer) = self.dialer.clone() else {
            let reason = self
                .reason
                .clone()
                .unwrap_or_else(|| "no TLS backend available".to_string());
            return Box::pin(async move { Err(reason) });
        };

        Box::pin(async move {
            let (host, port) = local_submission_endpoint()?;
            let ip: IpAddr = host
                .parse()
                .map_err(|_| format!("local submission endpoint is not an IP: {host}"))?;
            let target =
                pinned_from_addresses(&host, port, vec![ip], AddressPolicy::allow_private())
                    .map_err(|error| error.to_string())?;

            let timeout = Duration::from_secs(SUBMISSION_TIMEOUT_SECS);
            let (mut session, _banner) =
                SmtpSession::connect(&dialer, &target, TlsMode::StartTls, timeout)
                    .await
                    .map_err(|error| error.to_string())?;
            session
                .ehlo("mailstack")
                .await
                .map_err(|error| error.to_string())?;
            let response = session
                .send_message(
                    &submission.mail_from,
                    std::slice::from_ref(&submission.recipient),
                    &submission.data,
                )
                .await
                .map_err(|error| error.to_string())?;
            let report = SubmissionReport {
                code: response.code,
                banner: response.banner(),
            };
            let _ = session.quit().await;
            Ok(report)
        })
    }
}

fn local_submission_endpoint() -> Result<(String, u16), String> {
    let raw = mailstack_smtp::LOCAL_SUBMISSION_ENDPOINT;
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid local submission endpoint: {raw}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid local submission endpoint: {raw}"))?;
    Ok((host.to_string(), port))
}

pub fn loopback_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("ms-loopback-{hex}")
}

pub fn find_loopback_token(vmail: &Path, home_root: &Path, recipient: &str, token: &str) -> bool {
    let (user, domain) = split_address(recipient);

    let mut candidates: Vec<PathBuf> = vec![home_root.join("home").join(&user).join("Maildir")];
    if let Some(domain) = domain {
        candidates.push(vmail.join(&domain).join(&user));
        candidates.push(vmail.join(&domain).join(&user).join("Maildir"));
    }

    candidates.iter().any(|root| {
        directory_contains_token(&root.join("new"), token)
            || directory_contains_token(&root.join("cur"), token)
    })
}

fn split_address(address: &str) -> (String, Option<String>) {
    match address.split_once('@') {
        Some((user, domain)) => (user.to_string(), Some(domain.to_string())),
        None => (address.to_string(), None),
    }
}

fn directory_contains_token(dir: &Path, token: &str) -> bool {
    let Ok(read) = std::fs::read_dir(dir) else {
        return false;
    };
    read.flatten()
        .any(|entry| file_contains_token(&entry.path(), token))
}

const TOKEN_SCAN_CHUNK: usize = 64 * 1024;

fn file_contains_token(path: &Path, token: &str) -> bool {
    use std::io::Read;

    let needle = token.as_bytes();
    if needle.is_empty() {
        return std::fs::File::open(path).is_ok();
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut window: Vec<u8> = Vec::new();
    let mut chunk = [0u8; TOKEN_SCAN_CHUNK];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return false,
            Ok(n) => {
                window.extend_from_slice(&chunk[..n]);
                if window
                    .windows(needle.len())
                    .any(|candidate| candidate == needle)
                {
                    return true;
                }

                let keep = needle.len().saturating_sub(1).min(window.len());
                let drain = window.len() - keep;
                window.drain(..drain);
            }
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape_is_24_hex_digits_and_unique() {
        let a = loopback_token();
        let b = loopback_token();
        assert!(a.starts_with("ms-loopback-"), "{a}");
        let hex = a.trim_start_matches("ms-loopback-");
        assert_eq!(hex.len(), 24, "{a}");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b, "两次自检的 token 不得相同（否则会互相冒充）");
    }

    #[test]
    fn the_system_user_maildir_layout_is_searched() {
        let dir = tempfile::tempdir().unwrap();
        let new = dir
            .path()
            .join("home")
            .join("alice")
            .join("Maildir")
            .join("new");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(
            new.join("1700000000.abc"),
            "Subject: hi\n\nms-loopback-deadbeef\n",
        )
        .unwrap();

        assert!(find_loopback_token(
            &dir.path().join("var/vmail"),
            dir.path(),
            "alice@example.com",
            "deadbeef"
        ));

        assert!(!find_loopback_token(
            &dir.path().join("var/vmail"),
            dir.path(),
            "alice@example.com",
            "cafebabe"
        ));
    }

    #[test]
    fn the_virtual_mailbox_layout_is_searched_too() {
        let dir = tempfile::tempdir().unwrap();
        let cur = dir
            .path()
            .join("var/vmail")
            .join("example.com")
            .join("bob")
            .join("Maildir")
            .join("cur");
        std::fs::create_dir_all(&cur).unwrap();
        std::fs::write(cur.join("1700000001.xyz"), "token: t0k3n\n").unwrap();

        assert!(find_loopback_token(
            &dir.path().join("var/vmail"),
            dir.path(),
            "bob@example.com",
            "t0k3n"
        ));
    }

    #[test]
    fn a_missing_maildir_is_not_found_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!find_loopback_token(
            &dir.path().join("var/vmail"),
            dir.path(),
            "ghost@example.com",
            "abc"
        ));

        assert!(!find_loopback_token(
            &dir.path().join("var/vmail"),
            dir.path(),
            "localhost",
            "abc"
        ));
    }

    #[test]
    fn an_unreadable_or_binary_file_is_treated_as_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let new = dir
            .path()
            .join("var/vmail")
            .join("example.com")
            .join("carol")
            .join("new");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(new.join("binary"), [0xff, 0xfe, 0x00, 0x01]).unwrap();
        assert!(!find_loopback_token(
            &dir.path().join("var/vmail"),
            dir.path(),
            "carol@example.com",
            "zzz"
        ));
    }

    #[test]
    fn a_token_straddling_a_chunk_boundary_is_still_found() {
        let dir = tempfile::tempdir().unwrap();
        let new = dir
            .path()
            .join("home")
            .join("alice")
            .join("Maildir")
            .join("new");
        std::fs::create_dir_all(&new).unwrap();

        let boundary = TOKEN_SCAN_CHUNK;
        let mut body = vec![b'a'; boundary - 5];
        body.extend_from_slice(b"ms-loopback-cafebabecafebabecafebabe");
        std::fs::write(new.join("straddle"), &body).unwrap();

        let big = vec![b'b'; 3 * boundary + 17];
        std::fs::write(new.join("big"), &big).unwrap();

        let token = "cafebabecafebabecafebabe";
        assert!(
            find_loopback_token(
                &dir.path().join("var/vmail"),
                dir.path(),
                "alice@example.com",
                token
            ),
            "骑在块边界上的 token 必须被找到"
        );
        assert!(
            !find_loopback_token(
                &dir.path().join("var/vmail"),
                dir.path(),
                "alice@example.com",
                "ffffffffffffffffffffffff"
            ),
            "大文件里没有 token 不得误命中"
        );
    }

    #[test]
    fn the_submission_endpoint_is_the_hardcoded_loopback_constant() {
        let (host, port) = local_submission_endpoint().unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 25);
        assert_eq!(
            format!("{host}:{port}"),
            mailstack_smtp::LOCAL_SUBMISSION_ENDPOINT
        );
    }
}

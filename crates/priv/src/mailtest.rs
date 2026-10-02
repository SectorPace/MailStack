//! 邮件环路自检（`mail.test_loopback` / `setup.mail.test`）。
//!
//! 基线的做法是「把一封信交给本机 `sendmail`，再去 Maildir 里把它找回来」。
//! 本栈没有 Postfix/`sendmail`，**自然等价物是向本机提交端点 `127.0.0.1:25`
//! 做一次真正的 SMTP 提交** —— 那正是 `mailstackd` 自己的入站面，因此这条环路
//! 覆盖的是「提交 → 入站策略 → 入队」，而不是绕开它。
//!
//! ## 四条纪律
//!
//! 1. **目标是硬编码常量**（[`mailstack_smtp::LOCAL_SUBMISSION_ENDPOINT`]），
//!    不来自请求体。否则这个动作就变成一个「任意主机的 SMTP 提交器」——
//!    既是 SSRF，也是发信能力外泄。
//! 2. **反中继由入站策略兜底**（INV-17）：外域收件人会被我们自己的 MTA 以
//!    「未认证不得中继」拒收。因此这里**不需要**再写一遍域名判断 ——
//!    写两遍迟早会出现「这里放行、那边拒收」的分歧。
//! 3. **Maildir 里找不到 ≠ 失败**。提交被 `250` 接受就说明环路通了；Maildir 只是
//!    额外证据，而且权威布局尚未定死（见 `crates/store/src/lib.rs` 的说明）。
//!    所以结果里给的是 `maildirDelivered: bool`，不是一个会被人误读成
//!    「投递失败」的错误。
//! 4. **正文必须是 CRLF**。`terminate_data` 只做 dot-stuffing 与补终止符，
//!    不做 `LF → CRLF` 转换；用裸 LF 组装正文会被入站的走私防护直接拒收
//!    （那正是它该做的）。

use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use mailstack_smtp::client::SmtpSession;
use mailstack_smtp::target::pinned_from_addresses;
use mailstack_smtp::{AddressPolicy, PinnedDialer, TlsMode};

/// 本机提交的超时（基线用 `sendmail` 时是 20s）。
pub const SUBMISSION_TIMEOUT_SECS: u64 = 20;

/// 一封待提交的本机邮件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSubmission {
    /// 信封发件人（不含尖括号）。
    pub mail_from: String,
    /// 单个收件人（不含尖括号）。
    pub recipient: String,
    /// 报文全文（**必须**是 CRLF 行尾，见模块说明第 4 条）。
    pub data: String,
}

/// 提交被接受后的回执。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionReport {
    /// 入站 MTA 的最终应答码（`2xx` 表示已接受并落盘）。
    pub code: u16,
    /// 应答首行（排查用；可能含对端自报的主机名）。
    pub banner: String,
}

/// 本机提交器。
///
/// 做成可注入的，是为了让两个自检动作能在**不启动 MTA、不发真实邮件**的前提下被
/// 完整验证（成功、被拒、连接失败、正文内容断言）。真实 SMTP 服务端不参与单元测试，
/// 否则这些断言会依赖运行环境，最终被人忽略。
pub trait MailSubmitter: Send + Sync {
    /// 提交一封信。连接/协议层失败与「被拒收」都折算成 `Err(说明)`。
    fn submit<'a>(
        &'a self,
        submission: LocalSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<SubmissionReport, String>> + Send + 'a>>;
}

/// 生产提交器：向本机提交端点做一次明文 SMTP 提交。
pub struct SystemMailSubmitter {
    /// TLS 栈构造失败时留 `None`，由调用如实报错 —— 本机端点通常还没证书，
    /// 但 TLS 配置本身缺失仍必须说出来，而不是静默跳过。
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

            // 明文提交：向导阶段的证书可能还没签发（基线的 direct 探测出于同一理由
            // 也不做 STARTTLS），而且明文提交只在环回上进行。
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

/// 拆解本机提交端点常量。
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

/// 一次性环路 token：`ms-loopback-<24 位十六进制>`。
///
/// 24 位十六进制 = 96 位随机量。它要保证的是「这一封就是刚才那一封」，
/// 因此不能用时间戳之类可预测的东西 —— 同一秒内的两次自检会互相冒充。
pub fn loopback_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("ms-loopback-{hex}")
}

/// 在候选 Maildir 位置里找带该 token 的邮件。
///
/// 候选来自基线的两个字面位置（系统用户的 `~/Maildir`，以及
/// `<vmail>/<domain>/<user>`），另加本仓库 `backup.rs` 的 `var/vmail` 许可清单
/// 所隐含的 `<vmail>/<domain>/<user>/Maildir`。
///
/// 权威布局尚未定死（`crates/store/src/lib.rs`），因此这里**并列探测多个候选**、
/// 任一命中即算命中；找不到只是 `false`，不是错误。
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

/// 目录里是否有文件包含该 token。
///
/// 读不到的文件（Maildir 扫描期间内容在churn、spool 文件权限受限）一律按
/// 「没匹配」处理：那是**预期**情况，不是错误。
fn directory_contains_token(dir: &Path, token: &str) -> bool {
    let Ok(read) = std::fs::read_dir(dir) else {
        return false;
    };
    read.flatten().any(|entry| {
        std::fs::read_to_string(entry.path())
            .map(|text| text.contains(token))
            .unwrap_or(false)
    })
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
        // 另一个 token 不得误命中。
        assert!(!find_loopback_token(
            &dir.path().join("var/vmail"),
            dir.path(),
            "alice@example.com",
            "cafebabe"
        ));
    }

    #[test]
    fn the_virtual_mailbox_layout_is_searched_too() {
        // 本仓库 backup.rs 的 var/vmail 许可清单隐含 `<domain>/<user>/Maildir`。
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
        // 没有 `@` 的地址也不得 panic。
        assert!(!find_loopback_token(
            &dir.path().join("var/vmail"),
            dir.path(),
            "localhost",
            "abc"
        ));
    }

    #[test]
    fn an_unreadable_or_binary_file_is_treated_as_no_match() {
        // Maildir 扫描期间内容在 churn，读到不可解析的内容是预期情况。
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
    fn the_submission_endpoint_is_the_hardcoded_loopback_constant() {
        // 结构性保证：提交目标只能来自常量，不能来自请求体。
        let (host, port) = local_submission_endpoint().unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 25);
        assert_eq!(
            format!("{host}:{port}"),
            mailstack_smtp::LOCAL_SUBMISSION_ENDPOINT
        );
    }
}

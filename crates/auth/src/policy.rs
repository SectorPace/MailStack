//! 签名策略：从 `setup.json` 推导「本机该用哪个域、哪个 selector 签名」。
//!
//! 基线把这件事散在两处：`network.py:94 setup_identity` 写 `setup.json`，
//! 而签名本身由 OpenDKIM 按 `/etc/opendkim/signing.table` 的 `*@<domain>` 规则做。
//! 重写后没有 OpenDKIM 了，于是「用哪把钥匙签哪封邮件」必须由调用方显式决定 ——
//! 本模块就是那个决定，且**只有这一个来源**。
//!
//! ## 为什么不静默降级
//!
//! [`signing_policy`] 把「不签」这件事做成显式的 [`SigningPolicyOutcome::Skip`]
//! 并带原因，而不是返回 `None` 了事：一封本应签名却没签的邮件会在收件方被
//! DMARC 判失败，运维必须能从日志里看出**为什么**没签（INV-34 的响亮降级精神）。

use std::path::PathBuf;

use mailstack_core::config::{read_setup_config, validate_setup_identity};
use mailstack_core::paths::Paths;

use crate::keys::{private_key_path, validate_domain};

/// 本机的 DKIM 签名策略。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSigningPolicy {
    /// 签发域（`setup.json` 的 `domain`，也用作 `d=`）。
    pub domain: String,
    /// 邮件主机名（`setup.json` 的 `mailHost`），仅作审计展示。
    pub mail_host: String,
    /// 选择器（`setup.json` 的 `dkimSelector`，也用作 `s=`）。
    pub selector: String,
    /// 私钥路径。
    pub private_key: PathBuf,
}

impl DkimSigningPolicy {
    /// 该发件域是否由本策略负责。
    ///
    /// 同域或子域都算：DMARC 的 relaxed 对齐比较的是组织域，
    /// `user@sub.example.com` 由 `d=example.com` 签名仍然对齐。
    pub fn covers(&self, from_domain: &str) -> bool {
        let from_domain = from_domain.trim().to_ascii_lowercase();
        from_domain == self.domain || from_domain.ends_with(&format!(".{}", self.domain))
    }
}

/// 策略推导结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningPolicyOutcome {
    Sign(DkimSigningPolicy),
    /// 不应签名，原因必须被上报（不得静默）。
    Skip {
        reason: String,
    },
}

/// 从 `setup.json` + 私钥文件推导签名策略。
///
/// 只校验私钥**存在**，不解析它：策略是「要不要签」的路由判断，而密钥可用性
/// 由 [`crate::keys::load_private_key_der`] 在真正签名前强制校验 —— 那里失败是
/// 硬错误，不会退化成发一封未签名邮件。
pub fn signing_policy(paths: &Paths) -> SigningPolicyOutcome {
    let Some(config) = read_setup_config(paths) else {
        return SigningPolicyOutcome::Skip {
            reason: "setup.json is absent or unreadable".to_string(),
        };
    };

    // 域名规范化后再比对，避免因大小写差异误判。
    let Ok(domain) = validate_domain(&config.domain) else {
        return SigningPolicyOutcome::Skip {
            reason: format!("setup.json holds an invalid domain: {}", config.domain),
        };
    };

    if let Err(error) = validate_setup_identity(&domain, &config.mail_host, &config.dkim_selector) {
        return SigningPolicyOutcome::Skip {
            reason: format!("setup.json failed identity validation: {error}"),
        };
    }

    let private_key = private_key_path(paths, &domain, &config.dkim_selector);
    if !private_key.is_file() {
        return SigningPolicyOutcome::Skip {
            reason: format!("DKIM private key is missing: {}", private_key.display()),
        };
    }

    SigningPolicyOutcome::Sign(DkimSigningPolicy {
        domain,
        mail_host: config.mail_host,
        selector: config.dkim_selector,
        private_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_core::config::{write_setup_config, SetupConfig};

    fn fixture() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        (dir, paths)
    }

    fn config() -> SetupConfig {
        SetupConfig {
            domain: "Example.COM".to_string(),
            mail_host: "mail.example.com".to_string(),
            server_ip: "203.0.113.10".to_string(),
            dkim_selector: "mailstack".to_string(),
            expected_spf: None,
            updated_at: "2026-10-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn absent_setup_config_skips_with_a_reason() {
        let (_dir, paths) = fixture();
        let outcome = signing_policy(&paths);
        assert!(matches!(outcome, SigningPolicyOutcome::Skip { .. }));
        if let SigningPolicyOutcome::Skip { reason } = outcome {
            assert!(
                reason.contains("setup.json"),
                "原因要指明缺的是什么：{reason}"
            );
        }
    }

    #[test]
    fn a_configured_domain_without_a_key_skips_loudly() {
        let (_dir, paths) = fixture();
        write_setup_config(&paths, &config()).unwrap();
        let outcome = signing_policy(&paths);
        match outcome {
            SigningPolicyOutcome::Skip { reason } => {
                assert!(
                    reason.contains("private key"),
                    "原因要指明缺的是密钥：{reason}"
                )
            }
            other => panic!("缺少私钥时不得给出签名策略：{other:?}"),
        }
    }

    #[test]
    fn a_complete_configuration_yields_a_policy() {
        let (_dir, paths) = fixture();
        write_setup_config(&paths, &config()).unwrap();
        let key = private_key_path(&paths, "example.com", "mailstack");
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        std::fs::write(&key, b"-----BEGIN RSA PRIVATE KEY-----\n").unwrap();

        let outcome = signing_policy(&paths);
        let SigningPolicyOutcome::Sign(policy) = outcome else {
            panic!("配置完整时必须给出签名策略");
        };
        assert_eq!(policy.domain, "example.com", "策略里的域必须已规范化");
        assert_eq!(policy.selector, "mailstack");
        assert_eq!(policy.private_key, key);
    }

    #[test]
    fn invalid_identity_in_setup_is_rejected_instead_of_signed() {
        let (_dir, paths) = fixture();
        let mut bad = config();
        // mailHost 不是 domain 的子域 —— setup 阶段就会拒绝，策略阶段也必须拒绝。
        bad.mail_host = "mail.other.test".to_string();
        write_setup_config(&paths, &bad).unwrap();
        assert!(matches!(
            signing_policy(&paths),
            SigningPolicyOutcome::Skip { .. }
        ));
    }

    #[test]
    fn coverage_includes_the_domain_and_its_subdomains() {
        let policy = DkimSigningPolicy {
            domain: "example.com".to_string(),
            mail_host: "mail.example.com".to_string(),
            selector: "mailstack".to_string(),
            private_key: PathBuf::from("/etc/opendkim/keys/example.com/mailstack.private"),
        };
        assert!(policy.covers("example.com"));
        assert!(policy.covers("Example.COM"));
        assert!(policy.covers("sub.example.com"));
        assert!(!policy.covers("notexample.com"), "后缀相同但不是子域");
        assert!(!policy.covers("example.com.evil.test"));
        assert!(!policy.covers("other.test"));
    }
}

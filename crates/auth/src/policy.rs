use std::path::PathBuf;

use mailstack_core::config::{read_setup_config, validate_setup_identity};
use mailstack_core::paths::Paths;

use crate::keys::{private_key_path, validate_domain};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSigningPolicy {
    pub domain: String,

    pub mail_host: String,

    pub selector: String,

    pub private_key: PathBuf,
}

impl DkimSigningPolicy {
    pub fn covers(&self, from_domain: &str) -> bool {
        let from_domain = from_domain.trim().to_ascii_lowercase();
        from_domain == self.domain || from_domain.ends_with(&format!(".{}", self.domain))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningPolicyOutcome {
    Sign(DkimSigningPolicy),

    Skip { reason: String },
}

pub fn signing_policy(paths: &Paths) -> SigningPolicyOutcome {
    let Some(config) = read_setup_config(paths) else {
        return SigningPolicyOutcome::Skip {
            reason: "setup.json is absent or unreadable".to_string(),
        };
    };

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

            wizard_completed: false,
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

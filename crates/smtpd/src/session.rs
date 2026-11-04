use mailstack_smtp::{RelayDecision, RelayPolicy};
use mailstack_store::LocalRecipients;

use crate::command::{Command, MailParams};
use crate::data::BareNewlinePolicy;
use crate::reply::{texts, Reply};
use crate::sasl::{is_valid_base64, AuthOutcome};

pub trait RecipientChecker: Send + Sync {
    fn exists(&self, address: &str) -> Result<bool, String>;
}

impl std::fmt::Debug for dyn RecipientChecker + '_ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecipientChecker")
    }
}

#[derive(Debug, Clone)]
pub struct DirectoryRecipients {
    directory: LocalRecipients,
}

impl DirectoryRecipients {
    pub fn new(directory: LocalRecipients) -> Self {
        Self { directory }
    }
}

impl RecipientChecker for DirectoryRecipients {
    fn exists(&self, address: &str) -> Result<bool, String> {
        match self.directory.lookup(address) {
            mailstack_store::Lookup::Known => Ok(true),
            mailstack_store::Lookup::Missing => Ok(false),
            mailstack_store::Lookup::Unavailable(reason) => Err(reason),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AnyRecipient;

impl RecipientChecker for AnyRecipient {
    fn exists(&self, _address: &str) -> Result<bool, String> {
        Ok(true)
    }
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub hostname: String,

    pub max_message_size: usize,

    pub max_recipients: usize,

    pub bare_newline_policy: BareNewlinePolicy,

    pub postmaster: Option<String>,

    pub offer_starttls: bool,

    pub offer_auth: bool,

    pub tls_active: bool,

    pub require_auth_for_submission: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".to_string(),

            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,

            bare_newline_policy: BareNewlinePolicy::Reject,
            postmaster: None,
            offer_starttls: false,
            offer_auth: false,
            tls_active: false,
            require_auth_for_submission: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Reply(Reply),

    EnterData(Reply),

    StartTls(Reply),

    Close(Reply),

    AuthChallenge(Reply),

    AuthVerify { mechanism: String, response: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Mx,

    Submission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedMessage {
    pub mail_from: String,
    pub recipients: Vec<String>,

    pub data: Vec<u8>,

    pub helo: String,

    pub role: SessionRole,

    pub authenticated: bool,

    pub secured: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connected,

    Greeted,

    Mail,
}

pub struct Session<'a> {
    config: SessionConfig,
    relay: RelayPolicy,

    directory: &'a dyn RecipientChecker,
    phase: Phase,
    helo: Option<String>,
    esmtp: bool,
    mail_from: Option<String>,
    recipients: Vec<String>,
    authenticated: bool,

    auth_user: Option<String>,

    pending_auth: Option<String>,
    tls_active: bool,

    role: SessionRole,
}

impl<'a> Session<'a> {
    pub fn new(config: SessionConfig, relay: RelayPolicy) -> Self {
        Self::with_recipients(config, relay, &AnyRecipient)
    }

    pub fn with_recipients(
        config: SessionConfig,
        relay: RelayPolicy,
        recipients: &'a dyn RecipientChecker,
    ) -> Self {
        let tls_active = config.tls_active;

        let role = if config.offer_auth || config.require_auth_for_submission {
            SessionRole::Submission
        } else {
            SessionRole::Mx
        };
        Self {
            config,
            relay,
            directory: recipients,
            phase: Phase::Connected,
            helo: None,
            esmtp: false,
            mail_from: None,
            recipients: Vec::new(),
            authenticated: false,
            auth_user: None,
            pending_auth: None,
            tls_active,
            role,
        }
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn auth_user(&self) -> Option<&str> {
        self.auth_user.as_deref()
    }

    pub fn awaiting_auth_response(&self) -> bool {
        self.pending_auth.is_some()
    }

    pub fn is_tls_active(&self) -> bool {
        self.tls_active
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn helo(&self) -> Option<&str> {
        self.helo.as_deref()
    }

    pub fn greeting(&self) -> Reply {
        Reply::new(220, format!("{} {}", self.config.hostname, texts::GREETING))
    }

    pub fn mail_from(&self) -> Option<&str> {
        self.mail_from.as_deref()
    }

    pub fn recipients(&self) -> &[String] {
        &self.recipients
    }

    pub fn handle(&mut self, command: Command) -> Action {
        match command {
            Command::Ehlo(name) => self.hello(name, true),
            Command::Helo(name) => self.hello(name, false),
            Command::Mail { from, params } => self.mail(from, params),
            Command::Rcpt { to } => self.rcpt(to),
            Command::Data => self.data(),
            Command::Rset => {
                self.reset_transaction();
                Action::Reply(Reply::new(250, texts::RSET_OK))
            }
            Command::Noop => Action::Reply(Reply::new(250, texts::NOOP_OK)),
            Command::Quit => {
                self.reset_transaction();
                Action::Close(Reply::with_enhanced(221, "2.0.0", texts::BYE))
            }

            Command::Vrfy(_) => {
                Action::Reply(Reply::with_enhanced(502, "5.5.1", texts::VRFY_DISABLED))
            }
            Command::Help(_) => Action::Reply(Reply::new(214, texts::HELP)),
            Command::StartTls => self.start_tls(),
            Command::Auth { mechanism, initial } => self.auth(mechanism, initial),

            Command::Unknown(_) => {
                Action::Reply(Reply::with_enhanced(500, "5.5.1", texts::UNKNOWN_COMMAND))
            }
        }
    }

    fn hello(&mut self, name: String, esmtp: bool) -> Action {
        self.reset_transaction();
        self.helo = Some(name);
        self.esmtp = esmtp;
        self.phase = Phase::Greeted;

        if esmtp {
            Action::Reply(self.ehlo_reply())
        } else {
            Action::Reply(Reply::new(
                250,
                format!("{} {}", self.config.hostname, texts::EHLO_OK),
            ))
        }
    }

    fn ehlo_reply(&self) -> Reply {
        let mut lines = vec![format!("{} {}", self.config.hostname, texts::EHLO_OK)];
        lines.push(format!("SIZE {}", self.config.max_message_size));

        lines.push("ENHANCEDSTATUSCODES".to_string());
        if self.config.offer_starttls && !self.tls_active {
            lines.push("STARTTLS".to_string());
        }
        if self.config.offer_auth && self.tls_active {
            lines.push("AUTH PLAIN".to_string());
        }
        lines.push("HELP".to_string());
        Reply::multiline(250, lines)
    }

    fn mail(&mut self, from: String, params: MailParams) -> Action {
        if self.phase == Phase::Connected {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }
        if self.mail_from.is_some() {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::NESTED_MAIL));
        }

        if let Some(size) = params.size {
            if size > self.config.max_message_size as u64 {
                return Action::Reply(Reply::with_enhanced(552, "5.3.4", texts::MESSAGE_TOO_LARGE));
            }
        }

        if self.config.require_auth_for_submission && !self.authenticated {
            return Action::Reply(Reply::with_enhanced(
                530,
                "5.7.0",
                texts::SUBMISSION_AUTH_REQUIRED,
            ));
        }

        if self.role == SessionRole::Submission {
            if let Some(user) = self.auth_user.as_deref() {
                if !sender_owned_by(user, &from) {
                    return Action::Reply(Reply::with_enhanced(
                        550,
                        "5.7.1",
                        texts::SENDER_NOT_OWNED,
                    ));
                }
            }
        }
        self.mail_from = Some(from);
        self.recipients.clear();
        self.phase = Phase::Mail;
        Action::Reply(Reply::with_enhanced(250, "2.1.0", texts::MAIL_OK))
    }

    fn rcpt(&mut self, to: String) -> Action {
        if self.phase != Phase::Mail {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }

        if self.recipients.iter().any(|existing| existing == &to) {
            return Action::Reply(Reply::with_enhanced(250, "2.1.5", texts::RCPT_OK));
        }

        let reserved_postmaster = match to.rsplit_once('@') {
            Some((local, domain)) => {
                local.eq_ignore_ascii_case("postmaster") && self.relay.is_managed(domain)
            }
            None => to.eq_ignore_ascii_case("postmaster"),
        };
        if reserved_postmaster {
            return match &self.config.postmaster {
                Some(address) => {
                    let address = address.clone();
                    self.accept_recipient(address)
                }
                None => Action::Reply(Reply::with_enhanced(
                    550,
                    "5.1.1",
                    "postmaster address is not configured on this host",
                )),
            };
        }

        if self.recipients.len() >= self.config.max_recipients {
            return Action::Reply(Reply::with_enhanced(
                452,
                "4.5.3",
                texts::TOO_MANY_RECIPIENTS,
            ));
        }

        let domain = to.rsplit_once('@').map_or("", |(_, domain)| domain);
        match self.relay.evaluate(domain, self.authenticated) {
            RelayDecision::DeliverLocal => {}
            RelayDecision::RelayAuthenticated => {
                return self.accept_recipient(to);
            }
            RelayDecision::Reject { code, message } => {
                return Action::Reply(Reply::with_enhanced(code, "5.7.1", message));
            }
        }

        match self.directory.exists(&to) {
            Ok(true) => {}

            Ok(false) => {
                return Action::Reply(Reply::with_enhanced(550, "5.1.1", texts::RECIPIENT_UNKNOWN))
            }
            Err(reason) => {
                tracing::warn!(
                    helo = %self.helo.clone().unwrap_or_default(),
                    reason = %reason,
                    "收件人名录不可用，本次 RCPT 只判域（不据此拒绝）"
                );
            }
        }

        self.accept_recipient(to)
    }

    fn accept_recipient(&mut self, to: String) -> Action {
        if self.recipients.iter().any(|existing| existing == &to) {
            return Action::Reply(Reply::with_enhanced(250, "2.1.5", texts::RCPT_OK));
        }

        self.recipients.push(to);
        Action::Reply(Reply::with_enhanced(250, "2.1.5", texts::RCPT_OK))
    }

    fn data(&mut self) -> Action {
        if self.phase != Phase::Mail || self.recipients.is_empty() {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::NO_RECIPIENTS));
        }
        Action::EnterData(Reply::with_enhanced(354, "2.0.0", texts::DATA_START))
    }

    pub fn discard_data(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
        self.phase = Phase::Greeted;
    }

    pub fn finish_data(&mut self, data: Vec<u8>) -> (Reply, Option<AcceptedMessage>) {
        let (mail_from, recipients, helo) = match (
            self.mail_from.take(),
            std::mem::take(&mut self.recipients),
            self.helo.clone(),
        ) {
            (Some(mail_from), recipients, helo) => (mail_from, recipients, helo),
            (None, _, _) => {
                self.phase = Phase::Greeted;
                return (Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE), None);
            }
        };
        self.phase = Phase::Greeted;

        if data.len() > self.config.max_message_size {
            return (
                Reply::with_enhanced(552, "5.3.4", texts::MESSAGE_TOO_LARGE),
                None,
            );
        }

        (
            Reply::with_enhanced(250, "2.0.0", texts::DATA_OK),
            Some(AcceptedMessage {
                mail_from,
                recipients,
                data,
                helo: helo.unwrap_or_default(),
                role: self.role,
                authenticated: self.authenticated,
                secured: self.tls_active,
            }),
        )
    }

    fn start_tls(&mut self) -> Action {
        if self.tls_active {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::ALREADY_TLS));
        }
        if !self.config.offer_starttls {
            return Action::Reply(Reply::with_enhanced(
                502,
                "5.5.1",
                texts::STARTTLS_UNAVAILABLE,
            ));
        }
        if self.mail_from.is_some() {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }

        self.reset_transaction();
        self.helo = None;
        self.phase = Phase::Connected;
        self.esmtp = false;
        Action::StartTls(Reply::new(220, "Ready to start TLS"))
    }

    pub fn activate_tls(&mut self) {
        self.tls_active = true;
    }

    fn auth(&mut self, mechanism: String, initial: Option<String>) -> Action {
        if !self.config.offer_auth {
            return Action::Reply(Reply::with_enhanced(502, "5.5.1", texts::AUTH_UNAVAILABLE));
        }
        if !self.tls_active {
            return Action::Reply(Reply::with_enhanced(
                538,
                "5.7.11",
                texts::AUTH_REQUIRED_FIRST,
            ));
        }

        if !self.esmtp || self.phase == Phase::Connected || self.mail_from.is_some() {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }

        if self.authenticated {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::AUTH_ALREADY));
        }
        if self.pending_auth.is_some() {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }
        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            return Action::Reply(Reply::with_enhanced(
                504,
                "5.5.4",
                texts::AUTH_MECHANISM_UNKNOWN,
            ));
        }

        let mechanism = mechanism.to_ascii_uppercase();
        match initial {
            Some(response) => Self::request_verification(mechanism, response),
            None => {
                self.pending_auth = Some(mechanism);
                Action::AuthChallenge(Reply::new(334, ""))
            }
        }
    }

    pub fn continue_auth(&mut self, line: &[u8]) -> Action {
        let Some(mechanism) = self.pending_auth.clone() else {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        };

        if line == b"*" {
            self.pending_auth = None;
            return Action::Reply(Reply::with_enhanced(501, "5.5.2", texts::AUTH_CANCELLED));
        }
        let Ok(response) = std::str::from_utf8(line) else {
            self.pending_auth = None;
            return Action::Reply(Reply::with_enhanced(501, "5.5.2", texts::AUTH_BAD_BASE64));
        };

        self.pending_auth = None;
        Self::request_verification(mechanism, response.to_string())
    }

    fn request_verification(mechanism: String, response: String) -> Action {
        if !is_valid_base64(&response) {
            return Action::Reply(Reply::with_enhanced(501, "5.5.2", texts::AUTH_BAD_BASE64));
        }
        Action::AuthVerify {
            mechanism,
            response,
        }
    }

    pub fn complete_auth(&mut self, outcome: AuthOutcome) -> Reply {
        self.pending_auth = None;
        match outcome {
            AuthOutcome::Success { user } => {
                self.authenticated = true;
                self.auth_user = Some(user);
                Reply::with_enhanced(235, "2.7.0", texts::AUTH_OK)
            }
            AuthOutcome::InvalidCredentials => {
                Reply::with_enhanced(535, "5.7.8", texts::AUTH_FAILED)
            }
            AuthOutcome::TemporaryFailure(_) => {
                Reply::with_enhanced(454, "4.7.0", texts::AUTH_TEMPORARY_FAILURE)
            }
        }
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
        if self.phase == Phase::Mail {
            self.phase = Phase::Greeted;
        }
    }
}

fn sender_owned_by(authenticated_user: &str, mail_from: &str) -> bool {
    if mail_from.is_empty() {
        return true;
    }
    let user = authenticated_user.trim().to_ascii_lowercase();
    if user.is_empty() {
        return false;
    }
    let from = mail_from.trim().to_ascii_lowercase();
    if from == user {
        return true;
    }
    if !user.contains('@') {
        let local = from.rsplit_once('@').map_or(from.as_str(), |(l, _)| l);
        return local == user;
    }
    false
}

impl std::fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("phase", &self.phase)
            .field("helo", &self.helo)
            .field("has_mail_from", &self.mail_from.is_some())
            .field("recipients", &self.recipients.len())
            .field("authenticated", &self.authenticated)
            .field("tls_active", &self.tls_active)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(domains: &[&str]) -> Session<'static> {
        session_with(
            domains,
            SessionConfig {
                hostname: "mail.example.org".to_string(),
                postmaster: Some("postmaster@example.org".to_string()),
                ..SessionConfig::default()
            },
        )
    }

    fn session_with(domains: &[&str], config: SessionConfig) -> Session<'static> {
        Session::new(config, RelayPolicy::new(domains.iter().copied()))
    }

    fn ready(session: &mut Session<'_>, from: &str, to: &str) {
        let _ = session.handle(Command::Ehlo("client.test".into()));
        let _ = session.handle(Command::Mail {
            from: from.into(),
            params: MailParams::default(),
        });
        let action = session.handle(Command::Rcpt { to: to.into() });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.is_positive_completion()),
            "RCPT 应被接受，实际 {action:?}"
        );
    }

    #[test]
    fn greeting_is_220_and_ehlo_advertises_the_capabilities_we_really_have() {
        let session = session(&["example.org"]);
        assert_eq!(session.greeting().code, 220);

        let mut session = session;
        let Action::Reply(reply) = session.handle(Command::Ehlo("c.test".into())) else {
            panic!("EHLO 应回应答");
        };
        assert_eq!(reply.code, 250);
        let rendered = reply.render();
        assert!(
            rendered.contains("SIZE "),
            "必须通告 SIZE，否则客户端不会先报大小"
        );

        assert!(!rendered.contains("8BITMIME"));

        assert!(!rendered.contains("STARTTLS"));
        assert!(!rendered.contains("AUTH"));
    }

    #[test]
    fn capabilities_only_appear_when_actually_available() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                offer_starttls: true,
                offer_auth: true,
                tls_active: true,
                ..SessionConfig::default()
            },
        );
        let Action::Reply(reply) = session.handle(Command::Ehlo("c.test".into())) else {
            panic!("EHLO 应回应答");
        };
        let rendered = reply.render();
        assert!(rendered.contains("AUTH PLAIN"), "TLS 已建立时才通告 AUTH");
        assert!(
            !rendered.contains("STARTTLS"),
            "已在 TLS 上就不再通告 STARTTLS"
        );
    }

    #[test]
    fn commands_before_helo_are_out_of_sequence() {
        let mut session = session(&["example.org"]);
        for command in [
            Command::Mail {
                from: "a@b.test".into(),
                params: MailParams::default(),
            },
            Command::Rcpt {
                to: "x@example.org".into(),
            },
            Command::Data,
        ] {
            match session.handle(command.clone()) {
                Action::Reply(reply) => assert_eq!(reply.code, 503, "{command:?} 应判序列错误"),
                other => panic!("{command:?} 应只回应答，实际 {other:?}"),
            }
        }
    }

    #[test]
    fn rcpt_without_mail_and_data_without_rcpt_are_rejected() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));

        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "x@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);

        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Data) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503, "没有收件人就 DATA 必须拒绝");
    }

    #[test]
    fn a_second_mail_without_rset_is_rejected() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "c@d.test".into(),
            params: MailParams::default(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn unauthenticated_foreign_recipient_is_rejected_with_the_policy_text() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "attacker@evil.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "victim@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 554);
        assert!(reply.first_line().contains("Relaying denied"));
        assert!(session.recipients().is_empty(), "被拒的收件人不得进入事务");
    }

    #[test]
    fn an_empty_domain_table_rejects_rather_than_relaying() {
        let mut session = session(&[]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "attacker@evil.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "victim@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 554);
        assert!(reply.first_line().contains("no managed domains"));
    }

    #[test]
    fn local_recipients_are_accepted_and_deduplicated() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "a@b.test", "alice@example.org");
        let _ = session.handle(Command::Rcpt {
            to: "alice@example.org".into(),
        });
        assert_eq!(session.recipients().len(), 1, "重复收件人只记一次");
    }

    #[test]
    fn too_many_recipients_are_refused() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                max_recipients: 2,
                ..SessionConfig::default()
            },
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        for index in 0..2 {
            let action = session.handle(Command::Rcpt {
                to: format!("u{index}@example.org"),
            });
            assert!(matches!(action, Action::Reply(ref r) if r.is_positive_completion()));
        }
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "u3@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 452);
    }

    #[test]
    fn a_declared_oversized_message_is_refused_before_data_starts() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                max_message_size: 1024,
                ..SessionConfig::default()
            },
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams {
                size: Some(4096),
                ..MailParams::default()
            },
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 552);
    }

    #[test]
    fn an_undeclared_oversized_message_is_still_refused_after_data() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                max_message_size: 16,
                ..SessionConfig::default()
            },
        );
        ready(&mut session, "a@b.test", "alice@example.org");
        let (reply, accepted) = session.finish_data(vec![b'x'; 64]);
        assert_eq!(reply.code, 552);
        assert!(accepted.is_none());
    }

    #[test]
    fn a_complete_transaction_yields_the_accepted_message_and_resets() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "a@b.test", "alice@example.org");
        let Action::EnterData(reply) = session.handle(Command::Data) else {
            panic!("DATA 应进入正文收集");
        };
        assert_eq!(reply.code, 354);

        let (reply, accepted) = session.finish_data(b"Subject: t\r\n\r\nbody\r\n".to_vec());
        assert_eq!(reply.code, 250);
        let accepted = accepted.expect("应产出被接受的邮件");
        assert_eq!(accepted.mail_from, "a@b.test");
        assert_eq!(accepted.recipients, vec!["alice@example.org".to_string()]);
        assert_eq!(accepted.helo, "client.test");

        assert!(session.mail_from().is_none());
        assert!(session.recipients().is_empty());
        let Action::Reply(reply) = session.handle(Command::Data) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn null_sender_is_preserved_end_to_end() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "", "alice@example.org");
        let (_, accepted) = session.finish_data(b"bounce\r\n".to_vec());
        let accepted = accepted.unwrap();
        assert_eq!(accepted.mail_from, "", "null sender 必须原样保留");
    }

    #[test]
    fn rset_clears_the_transaction_without_dropping_the_greeting() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "a@b.test", "alice@example.org");
        let _ = session.handle(Command::Rset);
        assert!(session.mail_from().is_none());
        assert!(session.recipients().is_empty());

        let action = session.handle(Command::Mail {
            from: "c@d.test".into(),
            params: MailParams::default(),
        });
        assert!(matches!(action, Action::Reply(ref r) if r.code == 250));
    }

    #[test]
    fn vrfy_is_always_refused() {
        let mut session = session(&["example.org"]);
        for target in ["alice@example.org", "nobody@example.org", "postmaster"] {
            let Action::Reply(reply) = session.handle(Command::Vrfy(target.into())) else {
                panic!("应回应答");
            };
            assert_eq!(reply.code, 502, "{target} 的 VRFY 必须同样被拒");
        }
    }

    #[test]
    fn postmaster_is_resolved_to_the_configured_address() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        let action = session.handle(Command::Rcpt {
            to: "postmaster".into(),
        });
        assert!(matches!(action, Action::Reply(ref r) if r.code == 250));
        assert_eq!(
            session.recipients(),
            &["postmaster@example.org".to_string()]
        );
    }

    #[test]
    fn postmaster_is_refused_when_not_configured_instead_of_guessed() {
        let mut session = session_with(&["example.org"], SessionConfig::default());
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "postmaster".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550);
        assert!(reply.first_line().contains("not configured"));
    }

    #[test]
    fn quit_closes_the_connection_after_221() {
        let mut session = session(&["example.org"]);
        let Action::Close(reply) = session.handle(Command::Quit) else {
            panic!("QUIT 应关闭连接");
        };
        assert_eq!(reply.code, 221);
    }

    #[test]
    fn starttls_is_refused_when_not_offered_and_in_sequence_when_it_is() {
        let mut session = session(&["example.org"]);
        let Action::Reply(reply) = session.handle(Command::StartTls) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 502, "没提供 TLS 就不能假装可以");

        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                offer_starttls: true,
                ..SessionConfig::default()
            },
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::StartTls(reply) = session.handle(Command::StartTls) else {
            panic!("应回 StartTls");
        };
        assert_eq!(reply.code, 220);
        assert_eq!(session.helo(), None, "升级后必须重新 EHLO");
        assert!(
            !session.is_tls_active(),
            "握手尚未完成，此时不得声称已在 TLS 上"
        );

        session.activate_tls();
        assert!(session.is_tls_active());
    }

    #[test]
    fn starttls_during_a_transaction_is_refused() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                offer_starttls: true,
                ..SessionConfig::default()
            },
        );
        ready(&mut session, "a@b.test", "alice@example.org");
        let Action::Reply(reply) = session.handle(Command::StartTls) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn auth_over_a_plaintext_session_is_refused() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                offer_auth: true,
                ..SessionConfig::default()
            },
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::Reply(reply) = session.handle(Command::Auth {
            mechanism: "PLAIN".into(),
            initial: None,
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 538);
        assert!(!session.is_authenticated());
    }

    #[test]
    fn hello_resets_a_transaction_in_progress() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "a@b.test", "alice@example.org");
        let _ = session.handle(Command::Helo("other.test".into()));
        assert!(session.mail_from().is_none(), "HELO 是事务边界");
        assert!(session.recipients().is_empty());
    }

    fn submission_session() -> Session<'static> {
        session_with(
            &["example.org"],
            SessionConfig {
                offer_auth: true,
                tls_active: true,
                ..SessionConfig::default()
            },
        )
    }

    fn auth_plain(initial: Option<&str>) -> Command {
        Command::Auth {
            mechanism: "PLAIN".into(),
            initial: initial.map(str::to_string),
        }
    }

    #[test]
    fn a_successful_auth_sets_the_identity_and_a_second_attempt_is_refused() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));

        let action = session.handle(auth_plain(Some("AGJvYg==")));
        let Action::AuthVerify {
            mechanism,
            response,
        } = action
        else {
            panic!("应请求校验，实际 {action:?}");
        };
        assert_eq!(mechanism, "PLAIN");
        assert_eq!(response, "AGJvYg==");
        assert!(
            !session.is_authenticated(),
            "后端结果回来之前不得置为已认证"
        );

        let reply = session.complete_auth(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });
        assert_eq!(reply.code, 235);
        assert!(session.is_authenticated());
        assert_eq!(session.auth_user(), Some("alice@example.org"));

        let Action::Reply(reply) = session.handle(auth_plain(Some("AGJvYg=="))) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn authentication_is_what_unlocks_relaying_to_a_foreign_domain() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        let Action::Reply(before) = session.handle(Command::Rcpt {
            to: "bob@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(before.code, 554, "未认证时不得中继");
        let _ = session.handle(Command::Rset);

        let action = session.handle(auth_plain(Some("AGJvYg==")));
        assert!(matches!(action, Action::AuthVerify { .. }), "{action:?}");
        let _ = session.complete_auth(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });

        let _ = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        let Action::Reply(after) = session.handle(Command::Rcpt {
            to: "bob@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert!(after.is_positive_completion(), "认证后应放行：{after:?}");
    }

    #[test]
    fn an_unsupported_mechanism_is_refused_with_504_not_a_vague_502() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::Reply(reply) = session.handle(Command::Auth {
            mechanism: "LOGIN".into(),
            initial: None,
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 504);
        assert!(!session.awaiting_auth_response());
    }

    #[test]
    fn sasl_is_an_esmtp_extension_so_helo_sessions_cannot_authenticate() {
        let mut session = submission_session();
        let _ = session.handle(Command::Helo("c.test".into()));
        let Action::Reply(reply) = session.handle(auth_plain(Some("AGJvYg=="))) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn a_bare_auth_gets_an_empty_challenge_and_the_continuation_must_be_base64() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));

        let Action::AuthChallenge(reply) = session.handle(auth_plain(None)) else {
            panic!("无初始应答应发挑战");
        };
        assert_eq!(reply.code, 334, "PLAIN 的挑战是空串");
        assert!(session.awaiting_auth_response());

        let action = session.continue_auth(b"AAAA\tresp=injected");
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 501),
            "应回 501，实际 {action:?}"
        );
        assert!(!session.awaiting_auth_response(), "交换应已结束");
        assert!(!session.is_authenticated());
    }

    #[test]
    fn a_star_cancels_the_sasl_exchange() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(None));
        let action = session.continue_auth(b"*");
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 501),
            "实际 {action:?}"
        );
        assert!(!session.awaiting_auth_response());
    }

    #[test]
    fn a_continuation_without_an_exchange_in_progress_is_out_of_sequence() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let action = session.continue_auth(b"AGJvYg==");
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 503),
            "实际 {action:?}"
        );
    }

    #[test]
    fn credential_failure_and_backend_failure_are_different_replies() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        assert_eq!(
            session.complete_auth(AuthOutcome::InvalidCredentials).code,
            535
        );
        assert!(!session.is_authenticated());
        assert_eq!(session.auth_user(), None);

        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        let reply = session.complete_auth(AuthOutcome::TemporaryFailure("down".to_string()));
        assert_eq!(reply.code, 454);
        assert!(!session.is_authenticated(), "临时失败不得置位");
    }

    #[test]
    fn an_invalid_initial_response_is_refused_before_any_backend_call() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let action = session.handle(auth_plain(Some("not base64")));
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 501),
            "实际 {action:?}"
        );
        assert!(!session.awaiting_auth_response());
    }

    fn submission_session_requiring_auth() -> Session<'static> {
        session_with(
            &["example.org"],
            SessionConfig {
                offer_auth: true,
                tls_active: true,
                require_auth_for_submission: true,
                ..SessionConfig::default()
            },
        )
    }

    #[test]
    fn a_submission_session_that_requires_auth_refuses_an_unauthenticated_mail_with_530() {
        let mut session = submission_session_requiring_auth();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 530, "未认证的提交必须被 530 拒绝");
        assert_eq!(reply.enhanced, Some("5.7.0"));
        assert!(reply.first_line().contains("Authentication required"));
        assert!(session.mail_from().is_none(), "被拒的事务不得置位发件人");
    }

    #[test]
    fn an_authenticated_submission_passes_the_auth_gate() {
        let mut session = submission_session_requiring_auth();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        let _ = session.complete_auth(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });

        let _ = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        let action = session.handle(Command::Rcpt {
            to: "alice@example.org".into(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.is_positive_completion()),
            "认证后的提交应放行：{action:?}"
        );
    }

    #[test]
    fn without_the_flag_the_previous_unauthenticated_behaviour_is_preserved() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let action = session.handle(Command::Mail {
            from: "someone@example.org".into(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "默认配置下未认证 MAIL 必须照旧接受：{action:?}"
        );
    }

    fn authenticated_submission(user: &str) -> Session<'static> {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        let reply = session.complete_auth(AuthOutcome::Success {
            user: user.to_string(),
        });
        assert_eq!(reply.code, 235);
        session
    }

    #[test]
    fn an_authenticated_submission_may_not_use_another_senders_address() {
        let mut session = authenticated_submission("alice@example.org");
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "ceo@example.org".into(),
            params: MailParams::default(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550, "冒用他人发件人必须被拒绝：{reply:?}");
        assert_eq!(reply.enhanced, Some("5.7.1"));
        assert!(session.mail_from().is_none(), "被拒的事务不得置位发件人");

        let action = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "认证身份自己的地址必须放行：{action:?}"
        );
    }

    #[test]
    fn a_bare_account_name_may_send_from_its_own_address() {
        let mut session = authenticated_submission("alice");
        let action = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "alice 用 alice@example.org 发信是同一主体：{action:?}"
        );

        let mut session = authenticated_submission("alice");
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "bob@example.org".into(),
            params: MailParams::default(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550, "裸账号名也不得冒用别人的地址");
    }

    #[test]
    fn the_null_sender_is_allowed_from_an_authenticated_submission() {
        let mut session = authenticated_submission("alice@example.org");
        let action = session.handle(Command::Mail {
            from: String::new(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "null sender 不得被发件人归属校验拦下：{action:?}"
        );
    }

    #[test]
    fn an_mx_session_is_not_subject_to_sender_ownership() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let action = session.handle(Command::Mail {
            from: "ceo@example.org".into(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "25 端口不得出现提交口语义：{action:?}"
        );
    }

    struct FakeDirectory {
        known: Vec<String>,

        unavailable: Option<String>,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl FakeDirectory {
        fn knowing(known: &[&str]) -> Self {
            Self {
                known: known.iter().map(|s| s.to_string()).collect(),
                unavailable: None,
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn broken() -> Self {
            Self {
                known: Vec::new(),
                unavailable: Some("registry is corrupt".to_string()),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn queried(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl RecipientChecker for FakeDirectory {
        fn exists(&self, address: &str) -> Result<bool, String> {
            self.seen.lock().unwrap().push(address.to_string());
            if let Some(reason) = &self.unavailable {
                return Err(reason.clone());
            }
            Ok(self.known.iter().any(|k| k == address))
        }
    }

    fn session_with_directory<'a>(domains: &[&str], directory: &'a FakeDirectory) -> Session<'a> {
        Session::with_recipients(
            SessionConfig {
                hostname: "mail.example.org".to_string(),
                postmaster: Some("postmaster@example.org".to_string()),
                ..SessionConfig::default()
            },
            RelayPolicy::new(domains.iter().copied()),
            directory,
        )
    }

    fn opened(session: &mut Session<'_>, from: &str) {
        let _ = session.handle(Command::Ehlo("client.test".into()));
        let _ = session.handle(Command::Mail {
            from: from.into(),
            params: MailParams::default(),
        });
    }

    #[test]
    fn an_unknown_local_recipient_is_refused_with_550_and_never_enters_the_transaction() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "attacker@evil.test");

        let action = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550, "不存在的本域收件人必须 550");
        assert_eq!(reply.enhanced, Some("5.1.1"), "必须是 user unknown");
        assert!(session.recipients().is_empty(), "被拒的收件人不得进入事务");

        let action = session.handle(Command::Data);
        assert!(
            matches!(action, Action::Reply(ref r) if r.code == 503),
            "没有收件人时 DATA 必须拒绝：{action:?}"
        );
    }

    #[test]
    fn a_known_local_recipient_is_still_accepted() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let action = session.handle(Command::Rcpt {
            to: "alice@example.org".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(reply.is_positive_completion(), "{reply:?}");
        assert_eq!(session.recipients(), &["alice@example.org".to_string()]);
    }

    #[test]
    fn repeated_recipients_are_deduplicated_before_any_directory_lookup() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        for _ in 0..100 {
            let action = session.handle(Command::Rcpt {
                to: "alice@example.org".into(),
            });
            assert!(
                matches!(action, Action::Reply(ref reply) if reply.is_positive_completion()),
                "重复收件人应答必须与首次一致：{action:?}"
            );
        }
        assert_eq!(session.recipients(), &["alice@example.org".to_string()]);
        assert_eq!(
            directory.queried().len(),
            1,
            "同一地址 100 次 RCPT 只应查一次名录，实际 {:?}",
            directory.queried()
        );
    }

    #[test]
    fn a_remote_domain_is_judged_by_relay_policy_and_never_queries_the_directory() {
        let directory = FakeDirectory::knowing(&[]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "bob@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 554, "外域未认证必须按反中继拒");
        assert!(
            directory.queried().is_empty(),
            "远程域不得查本地名录（实际查了 {:?}）",
            directory.queried()
        );
    }

    #[test]
    fn an_authenticated_relay_to_a_remote_domain_never_queries_the_directory() {
        let directory = FakeDirectory::broken();
        let mut session = Session::with_recipients(
            SessionConfig {
                offer_auth: true,
                tls_active: true,
                ..SessionConfig::default()
            },
            RelayPolicy::new(["example.org"]),
            &directory,
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        let _ = session.complete_auth(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });
        let _ = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });

        let action = session.handle(Command::Rcpt {
            to: "bob@gmail.com".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "认证后提交到外域必须放行：{reply:?}"
        );
        assert!(directory.queried().is_empty(), "提交路径不得查本地名录");
    }

    #[test]
    fn an_unavailable_directory_never_turns_into_a_rejection() {
        let directory = FakeDirectory::broken();
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let action = session.handle(Command::Rcpt {
            to: "alice@example.org".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "查不了时必须保持现状（只判域），不得误拒：{reply:?}"
        );
        assert_eq!(
            directory.queried(),
            vec!["alice@example.org".to_string()],
            "确实问过名录（否则这条测试什么也没证明）"
        );
    }

    #[test]
    fn unknown_and_unavailable_are_distinguished_and_only_the_first_one_refuses() {
        let missing = FakeDirectory::knowing(&[]);
        let mut session = session_with_directory(&["example.org"], &missing);
        opened(&mut session, "a@remote.test");
        let Action::Reply(refused) = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(refused.code, 550);

        let broken = FakeDirectory::broken();
        let mut session = session_with_directory(&["example.org"], &broken);
        opened(&mut session, "a@remote.test");
        let Action::Reply(allowed) = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert!(
            allowed.is_positive_completion(),
            "同一个地址：查得到 ⇒ 550，查不了 ⇒ 放行。实际 {allowed:?}"
        );
    }

    #[test]
    fn without_a_directory_the_previous_domain_only_behaviour_is_preserved() {
        let mut session = session(&["example.org"]);
        opened(&mut session, "a@remote.test");
        let action = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "未挂名录时不得拒本域收件人：{reply:?}"
        );
    }

    #[test]
    fn the_production_directory_reads_the_real_registries() {
        let dir = tempfile::tempdir().unwrap();
        let paths = mailstack_core::paths::Paths::rooted(dir.path());
        std::fs::create_dir_all(&paths.postfix).unwrap();
        std::fs::create_dir_all(paths.managed_mailboxes.parent().unwrap()).unwrap();
        std::fs::write(
            &paths.managed_mailboxes,
            r#"[{"email":"alice@example.org","unixUser":"alice"}]"#,
        )
        .unwrap();
        std::fs::write(&paths.aliases, "sales@example.org alice\n").unwrap();

        let recipients = DirectoryRecipients::new(mailstack_store::LocalRecipients::new(&paths));
        let mut session = Session::with_recipients(
            SessionConfig::default(),
            RelayPolicy::new(["example.org"]),
            &recipients,
        );
        opened(&mut session, "a@remote.test");

        for known in ["alice@example.org", "sales@example.org"] {
            let action = session.handle(Command::Rcpt {
                to: known.to_string(),
            });
            assert!(
                matches!(action, Action::Reply(ref r) if r.is_positive_completion()),
                "{known} 应当在名录里：{action:?}"
            );
        }
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550, "名录外的本域地址必须 550");
    }

    #[test]
    fn the_rfc_mandated_postmaster_address_is_not_judged_by_the_directory() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let action = session.handle(Command::Rcpt {
            to: "postmaster".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "RFC 5321 §4.1.1.3 要求必须接受 postmaster：{reply:?}"
        );
        assert_eq!(
            session.recipients(),
            &["postmaster@example.org".to_string()]
        );
        assert!(
            directory.queried().is_empty(),
            "postmaster 不该查名录（实际查了 {:?}）",
            directory.queried()
        );
    }

    #[test]
    fn postmaster_at_a_managed_domain_is_reserved_too() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "PostMaster@Example.ORG".into(),
        }) else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "postmaster@纳管网域必须接受：{reply:?}"
        );
        assert_eq!(
            session.recipients(),
            &["postmaster@example.org".to_string()],
            "必须映射到配置的 postmaster 地址"
        );
        assert!(
            directory.queried().is_empty(),
            "保留地址不得查名录（实际查了 {:?}）",
            directory.queried()
        );
    }

    #[test]
    fn postmaster_at_a_foreign_domain_is_not_reserved() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "postmaster@evil.test".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 554, "外域 postmaster 必须按反中继拒");
        assert!(session.recipients().is_empty());
    }
}

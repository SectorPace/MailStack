//! MailStack 领域核心 —— 从 v0.8.0-beta.10 的 `backend/mailstackctl/core.py` 等价移植。
//!
//! 本 crate 承载全部**安全关键**的纯逻辑：
//!
//! * [`actions`] —— 特权动作三集（RO / RW / DESTRUCTIVE）与通道推导
//! * [`password`] —— 口令策略单一真相源（INV-35 / INV-36 / INV-37）
//! * [`audit`] —— 审计哈希链与截尾检测（INV-4）
//! * [`atomic`] —— `atomic()` / `locked()` 写入原语（INV-31 ~ INV-33）
//! * [`warn`] —— 非致命失败上报的去重语义（INV-34）
//! * [`config`] —— `/etc/mailstack/*.json` 的 schema 与写入白名单（INV-43）
//! * [`totp`] —— 2FA：AES-256-GCM 信封、RFC 6238 校验、恢复码持锁消费
//!   （INV-5 / INV-29 / INV-32）
//! * [`certs`] —— TLS 证书读取与到期天数（`certs.list`）
//! * [`sysinfo`] —— `/proc` 只读采样（遥测的只读半边）
//! * [`security`] —— 敏感文件权限体检（`security.scan`）
//! * [`bans`] —— 管理台手工封禁的持久化（`security.ban` / `security.unban`）
//! * [`backup`] —— 备份归档的创建与恢复（`backup.create` / `restore` / `delete`）
//!
//! 设计约束：全部路径都通过 [`paths::Paths`] 注入，生产默认值与原实现逐字一致，
//! 测试使用临时目录。**不得**在库内硬编码路径后绕过该注入点。

pub mod actions;
pub mod atomic;
pub mod audit;
pub mod backup;
pub mod bans;
pub mod certs;
pub mod config;
pub mod error;
pub mod exec;
pub mod mode;
pub mod password;
pub mod paths;
pub mod security;
pub mod sysinfo;
pub mod time_fmt;
pub mod totp;
pub mod validate;
pub mod version;
pub mod warn;

pub use error::{CoreError, CoreResult};
pub use exec::{
    is_service_active, postmap_and_reload, service_ctl, CommandOutput, CommandRunner,
    PostmapOutcome, ServiceBackend, ServiceCtlOutcome, ServiceEnv, ServiceVerb,
    SystemCommandRunner, SystemServiceEnv,
};
pub use paths::Paths;
pub use time_fmt::{format_iso8601, now_iso8601_local, now_iso8601_utc};
pub use version::VERSION;

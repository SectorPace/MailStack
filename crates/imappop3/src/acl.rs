//! RFC 4314 ACL 权限位与标识符校验。
//!
//! 权限字母：`l` 查找、`r` 读、`s` 保留 \Seen、`w` 写其它标志、`i` 插入、
//! `p` 投递、`k` 建子邮箱、`x` 删子邮箱、`t` 删邮件、`e` 清空（EXPUNGE）、
//! `a` 管理权限；聚合位 `c` = `k`+`x`、`d` = `t`+`e`。
//!
//! 本 crate 的会话只持有一个用户的 `MailStore`，跨用户共享邮箱需要部署层注入
//! 「用户名 → Maildir」解析器（见 crate 文档「未实现」）。因此 ACL 数据与命令
//! 在协议面完整可用，但访问控制目前只覆盖**所有者**（始终拥有全部权限）。

use crate::error::{MailError, Result};

/// 全部权限，按规范顺序排列（用于 MYRIGHTS / LISTRIGHTS / 所有者）。
pub const ALL_RIGHTS: &str = "lrswipkxtead";
/// 可出现在 SETACL 里的权限字母（含聚合位）。
const VALID_RIGHTS: &[u8] = b"lrswipkxtead";

/// 规范化权限串：逐字符校验、去重、按 [`ALL_RIGHTS`] 的顺序输出。
///
/// 空串合法（等价于移除该标识符的全部权限）。未知字母返回错误。
pub fn normalize_rights(rights: &str) -> Result<String> {
    for byte in rights.bytes() {
        if !VALID_RIGHTS.contains(&byte) {
            return Err(MailError::invalid(format!(
                "invalid ACL right: {}",
                char::from(byte)
            )));
        }
    }
    Ok(ALL_RIGHTS
        .chars()
        .filter(|letter| rights.contains(*letter))
        .collect())
}

/// 标识符：用户名（可见 ASCII，不含空白）或特殊值 `anyone` / `authenticated`。
pub fn valid_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= 255
        && identifier.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_are_validated_and_canonicalised() {
        assert_eq!(normalize_rights("rls").unwrap(), "lrs");
        assert_eq!(normalize_rights("lrsl").unwrap(), "lrs");
        assert_eq!(normalize_rights("").unwrap(), "");
        assert_eq!(normalize_rights(ALL_RIGHTS).unwrap(), ALL_RIGHTS);
        assert!(normalize_rights("z").is_err());
        assert!(normalize_rights("lr q").is_err());
    }

    #[test]
    fn identifiers_reject_whitespace_and_empty() {
        assert!(valid_identifier("bob@example.com"));
        assert!(valid_identifier("anyone"));
        assert!(!valid_identifier(""));
        assert!(!valid_identifier("has space"));
    }
}

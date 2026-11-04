use crate::error::{MailError, Result};

pub const ALL_RIGHTS: &str = "lrswipkxtead";

const VALID_RIGHTS: &[u8] = b"lrswipkxtead";

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

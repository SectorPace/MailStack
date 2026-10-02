//! 版本常量。
//!
//! 单一真相源是 workspace 根 `Cargo.toml` 的 `[workspace.package] version`，
//! 与仓库根的 `VERSION` 文件必须一致（由 `cargo test` 中的一致性断言守护）。

/// 形如 `0.8.1-beta1`。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_repository_version_file() {
        let shipped = include_str!("../../../VERSION").trim();
        assert_eq!(
            VERSION, shipped,
            "Cargo.toml 的 version 与仓库根 VERSION 文件不一致"
        );
    }
}

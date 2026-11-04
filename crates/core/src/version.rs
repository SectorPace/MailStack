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

# 工具链策略
#
# 本项目**不**在仓库根放置 `rust-toolchain.toml`，原因：
# 本机（Windows 开发机）rustup 的 default host 是 `x86_64-pc-windows-msvc`，
# 而可用的链接器只随 `stable-x86_64-pc-windows-gnu` 提供。一个裸的
# `channel = "1.98.1"` 会让 rustup 解析到 msvc 工具链并因缺少 `link.exe`
# 而整体构建失败（连带 clippy/fmt 代理）。
#
# 工具链版本改为在两处显式固定，二者都运行在 Linux 上：
#
#   1. `.github/workflows/ci.yml` —— `dtolnay/rust-toolchain@1.98.1`
#   2. `deploy/build.sh`         —— 调用前断言 `rustc --version` 前缀
#
# 版本下限同时由 workspace `Cargo.toml` 的 `rust-version` 字段表达。
#
# 生产构建目标为 `x86_64-unknown-linux-gnu`；开发机若需类型检查 Linux 代码：
#     cargo check --target x86_64-unknown-linux-gnu
# 贡献指南

感谢关注 MailStack。提交前请先阅读本指南。

## 报告问题

欢迎通过 Issue 报告可复现问题，提交前请说明：

- 操作系统及版本、MailStack 版本（`ms version`）
- 安装方式（git 安装 / Release 压缩包 / Docker）
- 相关服务状态（`ms status`、`ms doctor` 输出）
- 已脱敏的错误日志与完整复现步骤

**请勿公开提交**：SMTP 密码、管理员哈希、AI API Key、DKIM 私钥、TLS 私钥、ACME DNS 凭据、备份口令、邮箱正文或未脱敏的生产日志。

## 提交代码

1. Fork 后基于 `main` 拉出功能分支
2. 保证本地门禁通过：

   ```bash
   npm run test:all   # tsc + Node 契约/集成测试 + Vitest + Python 助手测试 + 备份 E2E
   ```

3. 涉及部署 / 验证脚本（`*.sh`、`deploy/`）的改动会经过 CI 的 shell-gate（shellcheck + 未定义函数扫描）与四发行版装机矩阵，请保持脚本零告警
4. 安全相关改动请对照 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) 的资产分级、信任边界与非目标；特权助手（`backend/mailstackctl/`）的行为变更必须附带行为级测试
5. 新增网络相关依赖需安全评审、钉定版本范围并写入发布说明（见 [docs/DEPENDENCY_POLICY.md](docs/DEPENDENCY_POLICY.md)）
6. 提交信息请说明动机与影响面；涉及版本号变更时保持 `VERSION`、`package.json` 与文档一致（CI 会做发布一致性校验）

## 安全问题

安全漏洞**不要**在公开 Issue 披露。请使用 GitHub Private Vulnerability Reporting，或通过仓库维护者提供的私密渠道报告。响应时间承诺（SLA）与 VEX 政策的唯一权威来源是 [docs/VULNERABILITY_RESPONSE.md](docs/VULNERABILITY_RESPONSE.md)。

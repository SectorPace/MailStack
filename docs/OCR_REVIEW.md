# OCR 全量复审报告（v1.0.0 发行代码）

> 工具：`open-code-review`（OCR）CLI + DeepSeek（`deepseek-chat`）；对象：`crates/`、`bin/`、`webui/src/`、`deploy/`。

## 1. 扫描统计

- 复核文件：280 个（扫描摘要 files_reviewed=287）
- 原始意见：1411 条；严重度：critical=8 high=199 medium=689 low=515
- 类别：{'maintainability': 379, 'bug': 645, 'performance': 98, '?': 2, 'security': 173, 'test': 61, 'documentation': 14, 'other': 20, 'style': 19}
- 定位校验：verified=1364，无法定位/文件缺失/无代码片段=47 条
- 自动归类为非运行时缺陷（documentation/style/test 建议）：94 条

## 2. 复核发现与修复

对 critical/high 逐条人工复核（重复渲染/同一个问题在不同文件重复出现时按一条计），确认并修复如下缺陷：

1. `crates/priv/src/lib.rs` — mailstackctl --privileged-stdin 未注册 Readers，users.*/setup.*/certs.* 全部 NOT_IMPLEMENTED（生产阻断）
2. `crates/auth/src/dmarc.rs` — DMARC pct 采样使用确定哈希 + 攻击者可控 Message-ID，可绕过 pct 策略削弱；改为随机化 SipHash
3. `crates/webmail/src/http/handlers.rs` — raw_message 下载缺少 X-Content-Type-Options: nosniff；补齐
4. `bin/mailstack-web/src/assets.rs` — 静态资源路径未拒绝百分号编码（%2e%2e%2f 纵深防御缺口）；拒绝含 % 路径
5. `bin/mailstack-webmail/src/lib.rs` — public run() 未调用 WebmailConfig::validate()；绑定前 fail-closed 校验
6. `webui/src/webmail/components/Compose.tsx` — initial.html 回填 innerHTML 前未 sanitize（回复/转发原文 XSS）
7. `webui/src/lib/webmail.ts` — VITE_WEBMAIL_URL 未校验 scheme/host；IPv6 host 未加括号；webmail 端口硬编码 8444
8. `deploy/install.sh` — 发布包/归档缺少 SHA256SUMS 时仅告警继续安装；改为默认 fail-closed（--allow-unsigned 显式放行）
9. `deploy/install.sh` — staging 包装器缺 --config-dir（特权动作写到宿主 /etc）；install/upgrade/repair/identity/防火墙等面板式能力重写
10. `deploy/mailstack-manage.sh` — 旧版管理脚本缺 status/doctor/backup/update/service/security 等面板能力；整体重写，状态文件改白名单解析（不再 source）
11. `deploy/verify-setup-wizard-e2e.sh` — rm -rf 守卫可被尾斜杠/相对路径绕过；realpath + 前缀 + 仓库根校验
12. `deploy/clean-host-postfix-test-residue.sh` — 清理脚本可能误删真实 SendGrid relay 配置；默认拒绝执行，需显式 --yes/MAILSTACK_CLEAN_TEST_RESIDUE=1
13. `deploy/uninstall.sh` — 卸载脚本错误处理/数据保留语义重写；--purge 显式删除

其余 critical/high 意见经复核为 OCR 误报或已由现有实现覆盖（典型：`crates/webmail/src/account.rs` 的 `nth(4)` 读取 passwd home 实际正确；`webui/src/api/client.ts` 已同时映射 `relay.test` 与 `setup.relay.test`；`deploy/verify-auth-clean-tree.sh` 已启用 `pipefail`，重试逻辑有效；`deploy/build.sh` 空可执行列表已有显式 `die` 兜底）。

## 3. 接受风险（记录，不阻塞发布）

- **[medium]** `crates/core/src/audit.rs` — 审计日志已 append+sync 后 head 锚点写入失败会返回 Err；hash 链仍是完整可校验的，残留为已知窗口（后续可补偿），本轮接受
- **[medium]** `bin/mailstackd/src/queue.rs` — shutdown abort 不运行 ClaimGuard::Drop，依赖 CLAIM_TTL 释放 claim；重复投递风险已被收件人去重约束，本轮接受并记录
- **[low]** `bin/mailstackd/src/lib.rs` — 非 Unix 目标下 lmtp 模块 cfg 缺失无法编译；项目目标平台为 Linux（README/CI 明确），接受
- **[low]** `crates/core/src/atomic.rs` — atomic 与 locked 使用不同 lock sidecar 是刻意设计（避免嵌套死锁，已有 lock_sidecar_names_never_collide 测试），接受

## 4. 质量分

评分口径（只对人工核实且未修复的真实缺陷扣分；OCR 建议/误报不计）：

```text
质量分 = max(0, 100 - 15*C_open - 8*H_open - 3*M_open - 1*L_open)
C_open=0  H_open=0  M_open=2  L_open=2
质量分 = 92
结果：PASS（门槛 >= 90）
```

## 5. 结论

- 本轮全量 OCR 复审 + 人工复核修复 13 项确认缺陷，无未修复 critical/high。
- 质量分 **92/100**（≥90，达到提交门槛）。
- 残余风险：见第 3 节；均为已记录的架构性/平台性取舍，不影响 v1.0.0 发布。
- 扫描结果原始 JSON：`work/ocr-final2.json`（本地工作副本，不随仓库发布）。

# MailStack v0.8.1-beta1 测试报告（Rust 重写）

> ## ⚠️ v1.0.0 最终门禁实测（2026-11-03，本节取代下方历史数字）
>
> 本文件正文是 **v0.8.1-beta1 检查点**的测试报告（历史存档）。v1.0.0 发布前的
> 权威门禁实测如下（Ubuntu 26.04 / WSL2 + Rust 1.98.1）：
>
> | 指标 | 实测值 |
> |---|---|
> | `cargo test --workspace --all-targets` | **1647 passed / 0 failed**（AI 功能移除后减少 55 项） |
> | 前端 `npm test`（vitest，`webui/`） | **187 passed / 0 failed** |
> | `cargo fmt --all -- --check` | 通过 |
> | `cargo clippy --workspace --all-targets -- -D warnings` | 通过 |
> | `deploy/verify-invariant-gate.sh` | `INVARIANT_GATE_OK`（293 条不变量） |
> | `deploy/verify-deliverables.sh` | `DELIVERABLES_OK` |
> | 特权动作白名单 / HTTP 契约路由 | 52 条（RO 20 + RW 32）/ 62 条（AI 功能已移除） |
>
> v1.0.0 新增 `crates/webmail` + `bin/mailstack-webmail`（Webmail 独立进程）、
> `deploy/install.sh`（curl 一键 / 源码构建两种形态）、完整中英文 README 与
> LICENSE/CHANGELOG/SECURITY。发布前完成 7 份独立审查（R1–R7，144 条发现），
> critical/high 优先修复；本文件 §4/§5 的历史缺陷与未验证事项仍适用（但测试数、
> 动作数已被 v1.0.0 覆盖）。

- 版本：`0.8.1-beta1`
- 规格书：`docs/REWRITE_TO_RUST.md` **v3**（本仓库外的源码包内）
- 平台：WSL Ubuntu 24.04 / `x86_64-unknown-linux-gnu`（生产目标平台）
- 工具链：rustc 1.98.1（`deploy/build.sh` 与 CI 双重固定）
- 结论：**1371 个测试全部通过**（含 `mailstackd` / `mailstackctl` / `mailstack-web` 二进制与 4 组真实集成套件）；rustfmt 与 clippy(`-D warnings`) 全绿；277/277 不变量测试存在
- 58 条白名单动作**已全部实现**，72 条契约路由**已全部接线**
  - 另 34 个集成测试需真实环境（TLS 握手 / TCP / unix socket / 容器内 Postfix）

复现命令：

```bash
deploy/wsl-quality-gate.sh        # rustfmt --check + clippy -D warnings + cargo test
deploy/verify-invariant-gate.sh   # 确认 CI 列出的不变量测试名都真实存在
```

## 1. 规模

| crate | 测试数 | 职责 |
|---|---:|---|
| `mailstack-core` | 208 | 动作三集、口令策略（**含记录形状校验：空摘要/截断摘要 fail-closed**）、审计哈希链、`atomic`/`locked`（**权限在首字节落盘前生效**）、`warn`、**`exec`（命令原语 + postmap 序列 + `service_ctl` 降级链，含 spawn 失败不再报成功）**、配置 schema、部署模式、**`totp`（2FA：AES-256-GCM 信封、RFC 6238、**重放记账**、恢复码持锁消费）**、**`certs`（证书到期解析）**、**`sysinfo`（`/proc` 只读采样）**、**`security`（敏感文件权限体检）**、**`backup`（归档打包/恢复：成员白名单、链接与设备拒绝、校验和先验）**、**`bans`（手工封禁文件）** |
| `mailstack-priv` | 230 | 动作门控、RPC 帧、RO/RW socket 服务端、**全部 58 个动作的处理器**（只读面、2FA 全生命周期、域名/别名/设置/管理员/DKIM 轮换、只读聚合面、服务与队列动作、手工封禁、备份、初始化向导 `setup.*`、**ACME 证书 `setup.cert.issue`/`certs.renew`**、邮件环路自检、邮箱用户 `users.*`、**为管理前端新增的 8 个只读列表动作**）、fallback 规则、**特权调用客户端**（通道推导 + 失败分类） |
| `mailstack-smtp` | 141 + 7 | IP 固定拨号器、中继校验、分阶段测试、出站探测、反中继策略、落地与回滚、真实落盘载体、**MX 解析与直投目标选择**、**`dns_query`（A/MX/TXT 查询，TXT 分片拼接）**、**`AddressPolicy`（SSRF 地址筛选：IPv6 走 `2000::/3` 白名单）**、**出站响应限长 / CRLF 注入拒绝 / 裸 LF 点填充 / 解析超时**（7 个为真实 TLS 集成测试） |
| `mailstack-queue` | 80 | 队列持久化与原子性、指数退避与去共振、DSN 退信、并发限流、快速失败与出站判据、**出站必签 DKIM**、**直投（逐域 MX，绝不回退中继）** |
| `mailstack-store` | 42 + 10 | Postfix 表文件（域名/别名）、**本地收件人名录**（`recipients.rs`：三态判定，「查不了」≠「不存在」）、**LMTP 客户端**（含尾部 CRLF 与裸 LF 点填充） （10 个为真实 unix socket 端到端） |
| `mailstack-auth` | 47 | DKIM 密钥（原生 RSA-2048、SPKI 记录、0640 加固）、签名与**自签自验**、SPF、**DMARC（类型化策略 — 不再靠 `Debug` 字符串判定）**、ARC **校验与封印**（自封自验、续封、篡改反例）、**离线 TXT 缓存（带 TTL 上界与容量上界；注入条目不参与淘汰）** |
| `mailstack-smtpd` | 163 + 11 | 入站 SMTP：命令解析、**DATA 字节流（SMTP 走私防护；超限后不缓冲但仍认得结束标记）**、会话状态机与反中继（INV-17）、**RCPT 收件人名录查验（消目录枚举与 backscatter）**、**`Authentication-Results` 值引用（防 `;` 注入）**、会话驱动；**TCP 监听 + TLS 1.2 起（STARTTLS / 隐式 465）**、**连接限速**、**IP 自动封禁（含认证失败记账 + 每连接连续失败上限）**、**提交端口 SASL（RFC 4954 + Dovecot auth socket）**、**入站认证（SPF/DKIM/DMARC）与入队**（11 个为真实 TCP/TLS/auth-socket 端到端） |
| `mailstack-web` | 94 | 契约路由表、会话/CSRF（**Cookie 带 `__Host-` 前缀**）、登录限流（**窗口会重置、键长与表容量有上界**）、错误模型、特权通道、Axum 装配、**2FA 路由**、**动作×路由一致性（全表接线守卫，破坏性集合与 `DESTRUCTIVE_ACTIONS` 双向对照）**、**时序遥测采集器（`telemetry`：7 档环形缓冲 + `/proc` 差分采样 + `df`/`postqueue`）**、**RPC 桥（动作允许集由契约表推导，见 §3.10）**、**改密/2FA 变更后按用户全量吊销会话** |
| `mailstack-web-bin` | 9 | **管理控制台服务入口**（`bin/mailstack-web`）：API + 前端产物托管、SPA 回退、`/api` 兜底保持 JSON、路径穿越拒绝、内容类型、遥测后台采样宿主、**`ConnectInfo` 接线（per-IP 限流取真实对端）**（详见 §3.10；端到端复验见 §4.24） |
| `mailstackd` | 28 | **进程入口**：`Paths`→运行期配置的 fail-closed 装配、三端口共用准入状态、监听集中绑定、**特权 RPC 双通道绑定与门控**、停机信号扇出、出站队列调度（详见 §3.1.5） |
| `mailstackctl` | 7 | **CLI**：参数→特权调用的翻译（`--confirm` 必须是真布尔）、退出码映射（详见 §3.1.6） |
| `mailstack-smtp`（真实 Postfix） | 6 | 需显式开启；在一次性容器中对 Postfix 3.8.6 运行 |
| **合计** | **1371** | 含 34 个真实环境集成测试（TLS / TCP / unix socket / Postfix） |

## 2. 门禁结果

| 门禁 | 命令 | 结果 |
|---|---|---|
| 格式 | `cargo fmt --all -- --check` | ✅ PASS |
| Lint | `cargo clippy --all-targets -- -D warnings` | ✅ PASS（warnings 即失败） |
| 单元/集成测试 | `cargo test` | ✅ 1371 passed / 0 failed |
| 真实 Postfix 集成 | `deploy/test-relay-postfix-in-container.sh` | ✅ 6/6 passed（Postfix 3.8.6） |
| 不变量存在性 | `verify-invariant-gate.sh` | ✅ 277/277 存在（扫描范围含 `bin/`） |
| 交付物 | `deploy/verify-deliverables.sh` | ✅ `DELIVERABLES_OK` |
| 二进制冒烟 | `mailstackd` + `mailstackctl` + `mailstack-web` + 真实客户端 | ✅ 收信→入队→RPC 门控→CLI→SIGTERM 优雅停机（见 §3.1.5、§3.1.6）；`mailstack-web` 的托管与底线行为见 §3.10 |

## 3. 不变量覆盖：43 条中已覆盖 37 条

### 3.1 本阶段（Phase 2）新增覆盖

| 不变量 | 关键测试 | 验证方式 |
|---|---|---|
| **INV-14** 中继连接必须用固定 IP 拨号、SNI/校验用原域名 | `dials_the_pinned_ip_while_verifying_the_original_hostname` | **真实 TLS 握手**：自签 CA 起本地 TLS 服务端（SAN=`relay.example.test`），断言拨号目标为环回 IP、服务端看到的 SNI 为原域名 |
| INV-14 反例守卫 | `certificate_verification_is_actually_enforced`、`wrong_sni_fails_verification` | 信任库不含签发者 / SNI 与 SAN 不匹配时握手**必须失败** |
| INV-14 结构性保证 | `pinned_target_never_carries_a_hostname_into_the_dial_path` | 拨号地址只能由 IP 构成 |
| INV-13 中继强制 TLS、端口白名单 | `rejects_plaintext_relay_with_the_documented_message`、`rejects_ports_outside_the_whitelist` | 明文中继以契约文案拒绝 |
| INV-15 私网策略 + 凭证注入 | `private_network_requires_deployment_opt_in`、`rejects_credential_injection_via_crlf_and_nul` | 部署未开启即拒绝；CRLF/NUL 凭证拒绝 |
| INV-17 反中继 fail-closed | `empty_domain_table_fails_closed`、`unauthenticated_foreign_recipient_is_rejected` | **域名表为空必须拒绝**（不复现历史缺陷） |
| INV-18 relay-only 无旁路 | `with_relay_configuration_every_message_goes_through_the_relay` | 有 relay 配置即走 relay |
| INV-19 出站探测 ≠ 本机提交探测 | `direct_verdict_follows_the_probe_not_the_local_submission_endpoint` | 出站 25 被封时**不得**推荐 direct |
| INV-20 465 必须带 wrappermode | `port_465_with_starttls_still_requires_wrappermode`、`port_465_relay_enables_wrappermode_on_the_route` | 端口 465 **或** tlsMode=SSL/TLS 取并集判定 |
| INV-21 不得退回直投 | `direct_route_is_never_used_as_a_fallback_when_relay_exists` | 路由在配置层决定，无运行时回退分支 |
| INV-16** 写入后必须回读校验；失败回滚到原凭证 | `refuses_to_write_anything_when_the_test_did_not_pass`、`readback_mismatch_is_reported_and_rolled_back`、`write_failure_triggers_rollback_to_previous_values`、`persistent_storage_failure_reports_rollback_as_incomplete` | 顺序为「先测后写 → 快照 → 写 → 回读 → 不一致则回滚」；回滚未完成时**诚实报 `rolledBack: false`** |
| **队列原子性（风险表「队列原子性」）** | `queue_writes_are_atomic_and_leave_no_partial_files`、`queue_files_are_owner_only` | 落盘后目录里无 `.tmp`；锁 sidecar 不被当作条目；文件 `0600` |
| **§5.8 指数退避** | `nominal_delay_grows_exponentially_and_is_capped`、`nominal_delay_is_monotonic` | 名义延迟 5m→10m→20m… 封顶 4h，且**单调不减** |
| **重试风暴抑制（风险表）** | `different_entries_do_not_retry_in_lockstep` | 退避抖动按条目 id 派生，同时刻入队的消息**不会集体重试**；抖动可复现 |
| **§5.8 超阈值生成 DSN** | `transient_failures_retry_then_bounce_after_the_retry_limit`、`permanent_failure_bounces_immediately_without_retry` | 4xx 重试至上限后退信；5xx 立即退信不重试 |
| **退信语义：防双退信回环** | `bounce_is_never_generated_for_a_null_sender`、`dsn_entries_are_never_bounced_again` | null sender 与退信自身失败时**丢弃**，不得再退信 |
| **退信头注入防护** | `dsn_sanitises_server_text_against_header_injection`、`dsn_sanitises_recipient_and_mta_against_injection` | 对端返回的 `\r\nBcc:` 不得成为新头行；头区行数固定 |
| **INV-21 队列侧落点** | `bounces_use_the_same_outbound_route_as_user_mail`、`a_bounce_addressed_to_a_local_sender_is_delivered_locally` | 退信与用户邮件经**同一** `OutboundRoute`；本域发件人的退信走 LMTP |
| **INV-18 队列侧落点** | `direct_route_fails_loudly_and_never_falls_back_to_the_relay` | 直投不可用时**明确失败**，不偷偷改用中继 |
| **未知结果不得退信** | `unknown_transport_errors_are_retryable_never_bounces` | 连接断开/超时是「结果未知」，只能重试 |
| **§5.9.8 并发上限可调且可见** | `concurrency_is_bounded_by_relay_concurrency`、`default_concurrency_matches_the_settings_schema`、`metrics_snapshot_exposes_backlog_concurrency_and_health` | 并发峰值 ≤ `relayConcurrency`；默认值与 §2.6 settings schema 一致；积压量与并发上限可观测 |
| **并发上限为 0 不得死锁** | `zero_concurrency_is_clamped_instead_of_deadlocking` | 夹到 1 而非让信号量永久无许可 |
| **§5.10.3 R-25-3 快速失败** | `consecutive_outbound_failures_produce_the_blocked_verdict`、`blocked_queue_fast_fails_instead_of_hammering`、`blocked_verdict_survives_restart`、`a_successful_probe_clears_the_blocked_verdict` | 连续失败达阈值 → 明确结论「出站 25 被封，请配置中继」；此后每轮**只放行一次**探测（半开），其余条目原样留在队列；结论跨重启保留，恢复后能自愈 |
| **本地投递失败不污染出站判据** | `a_local_transport_failure_does_not_trip_the_outbound_verdict` | LMTP 故障 ≠ 出站 25 被封 |
| **INV-11 落箱只能经 LMTP** | `connection_failure_is_reported_as_an_error_not_a_silent_success` | 连不上 Dovecot 必须报错；`crates/store` **不提供任何写 Maildir 的 API** |
| **LMTP 协议差异（易错点）** | `reads_one_reply_per_recipient_after_data`、`a_recipient_rejected_at_rcpt_stage_still_appears_in_the_result`、`every_recipient_rejected_at_rcpt_skips_the_data_phase` | **真实 unix socket 端到端**：`DATA` 之后逐收件人应答；`LHLO` 而非 `EHLO`；被拒收件人仍须出现在结果里 |
| **DATA 帧正确性** | `message_body_is_dot_stuffed_and_terminated` | 行首句点必须转义，否则正文被截断 |
| **部分成功不得重放（防重复邮件）** | `transport_reports_partial_success_so_nothing_is_delivered_twice`、`recipients_accepted_by_a_partial_delivery_are_not_retried_or_bounced`、`a_fully_accepted_but_failed_batch_does_not_retry_anything` | 已落箱的收件人进入 `DeliveryFailure::accepted`，既不重试也不退信 |
| **§2.5 表文件格式与 postmap** | `domain_add_writes_the_postfix_hash_format_and_runs_postmap`、`every_write_triggers_postmap`、`table_files_are_world_readable_like_the_installer_creates_them` | `<domain> OK` 格式；写完必须编译 hash 表并重载；`0644` 与安装脚本一致 |
| **表文件注入防护（基线点名）** | `alias_add_rejects_newline_injection_into_the_table`、`alias_add_rejects_space_separated_injection`、`delete_alias_validates_the_id_before_writing`、`domain_add_rejects_newline_injection` | 空格=多列、换行=多行；**删除路径同样要校验 id** |
| **删域名不留孤儿路由** | `delete_domain_also_removes_its_aliases` | 同时清掉该域下的别名行 |
| **错误文案是对外契约** | `domain_add_rejects_invalid_input_with_the_documented_message`、`alias_source_domain_is_validated_separately`、`alias_add_requires_at_least_one_destination`、`alias_add_caps_the_destination_count` | 逐字对齐 Python 基线（含 `invalid alias domain` 这一独立判定） |
| **§5.7.4 服务控制降级链** | `service_ctl_prefers_systemctl_when_systemd_is_present`、`service_ctl_does_not_use_systemctl_without_the_systemd_runtime_dir`、`service_ctl_falls_back_to_rc_service_and_maps_reload_to_restart`、`service_ctl_falls_back_to_the_init_script`、`service_ctl_uses_the_postfix_special_case`、`service_ctl_maps_dovecot_restart_to_reload`、`service_ctl_routes_fail2ban_verbs_through_the_client`、`service_ctl_is_a_no_op_when_nothing_applies` | **逐级覆盖**：systemd 判据是「命令存在**且** `/run/systemd/system` 存在」；OpenRC 把 `reload` 退化为 `restart`；Dovecot 把 `restart` 退化为 `reload` |
| **§5.7.4 服务存活探测** | `is_service_active_keeps_probing_after_a_failed_backend`、`is_service_active_accepts_a_running_string_from_service_status`、`is_service_active_recognises_the_fail2ban_socket` | 探测是「逐个尝试、命中即真」，与执行路径的首命中语义**不同** |
| **`postmap` 序列** | `postmap_sequence_matches_the_python_order`、`every_step_still_runs_when_all_fail` | `postmap` → `postfix check` → 重载；任一步失败不得中断后续（基线一律 `check=False`） |

### 3.1.1 认证与签名（§3.3、§5.8；替代 OpenDKIM）

这一节的条目按**规格书章节**而非 INV 编号索引 —— 认证/签名在规格书里是以 §3.3
（组件职责）与 §5.8（DKIM 密钥与签名）表述的，这里不臆造 INV 号。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **`p=` 必须是 SPKI**（§5.2.1 的「本地绿、生产静默失败」） | `public_key_is_spki_not_pkcs1`、`spki_wrapping_is_exactly_the_pkcs1_plus_a_fixed_header` | 断言 2048 位公钥的 base64 以 `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A` 开头（**不是** PKCS#1 的 `MIIBCgKCAQEA`）；并逐字节校验 SPKI = 24 字节固定头 + PKCS#1（含 `rsaEncryption` OID、BIT STRING 长度、外层 SEQUENCE 长度全部自洽） |
| **zone 片段的公钥不得被截断**（`network.py:115` 的真实事故） | `zone_fragment_round_trips_after_stripping_quotes_and_whitespace`、`zone_fragment_splits_long_values_below_the_dns_limit` | 去引号去空白后拼接**必须逐字等于**原 TXT 值；每个引号串 ≤ 255 字节（RFC 1035） |
| **私钥权限加固** | `rotated_private_key_is_never_world_readable` | 轮换后私钥为 `0640`，且 `mode & 0o007 == 0`（绝不 world-readable）；开发机无 `opendkim` 组时经 `warn()` **响亮降级**而非静默 |
| **原生生成，不调用外部二进制**（§3.3 移除 OpenDKIM） | `rotate_writes_both_files_and_returns_the_zone_record` | 一次 `rotate` 产出 `.private`（PKCS#1 PEM）与 `.txt`，返回的 `record` 与磁盘内容逐字一致；私钥能被自己读回并解出 DER |
| **本阶段验收：同一密钥自签自验** | `a_message_signed_with_a_key_pair_verifies_with_the_same_pair` | **真实 RSA-2048 密钥**签名后，用**同一密钥对**的 SPKI 公钥记录（注入 TXT 缓存，全程离线）跑完整 DKIM 验签，断言 `Pass`；同时断言签名头前置、原报文逐字保留 |
| 验签确实在做事（反例守卫） | `a_tampered_body_fails_verification` | 改动正文一个字节后必须验不过；另断言「无 DKIM 头的报文 ↔ 零条结论」 |
| **SPF 判据** | `a_matching_ip_passes_and_a_stranger_ip_does_not` | `ip4:203.0.113.10 -all` 下：命中 IP 判 `Pass`，域外 IP 判 `Fail`；另用纯映射测试覆盖 RFC 7208 全部七个取值 |
| **DMARC 失败关闭** | `an_unaligned_source_fails_a_reject_policy`、`an_aligned_spf_passes_dmarc_without_any_dkim_signature` | SPF 与 DKIM **都**不对齐时判 `Fail("Policy not aligned")`（断言具体错误，证明失败来自对齐判断而非 DNS 故障）；仅 SPF 对齐即可 `Pass` |
| **ARC：无链 ≠ 通过** | `a_message_without_arc_headers_reports_none_rather_than_pass`、`a_truncated_arc_header_is_rejected_instead_of_being_ignored` | 没有 ARC 头时结论是 `None` 而**不是** `Pass`（否则剥掉 ARC 头就能伪装成已验证）；残缺的 `ARC-Seal` 必须判失败而非跳过 |
| **ARC 封印：自封必须能自验** | `a_sealed_message_verifies_as_an_arc_pass_and_keeps_the_original_bytes` | 真实 RSA-2048 密钥封印后，用同一把公钥（注入 TXT 缓存）跑 `verify_arc` 断言 `Pass` 且 `sets=1`；同时断言头部顺序 `AS → AMS → AAR → AR`、原报文**逐字**保留在最后、`i=1 & cv=none` |
| ARC 封印：续封要递增而不是替换 | `sealing_twice_extends_the_chain_instead_of_replacing_it` | 对已封的报文再封一次：必须出现 `i=2`、`cv=pass`（上一跳的结论），校验后 `sets=2` —— 链被延长而不是被覆盖 |
| ARC 封印确实在做事（反例守卫） | `a_tampered_body_fails_arc_verification_after_sealing` | 改一个正文字节后 `verify_arc` 不得判 `Pass` |
| ARC 封印失败关闭 | `an_unusable_key_or_message_is_refused_rather_than_half_sealed` | 私钥不是 DER、报文不可解析 → 返回 `SigningError` 而不是产出没有签名能力的半成品 |
| ARC 封印的签名集合不得漂移 | `the_arc_header_set_is_the_dkim_set_plus_the_dkim_signature_header` | `h=` 必须**恰好**是 DKIM 默认集 + `DKIM-Signature`，且**不含任何 `ARC-*`**（本集合的三个头在签名之后才前置，写进 `h=` 会让验签多出自己这一份，签名必然对不上） |
| **对外契约：报错文案** | `domain_and_selector_validation_uses_the_python_contract` | `invalid domain format`、`invalid DKIM selector` 逐字对齐 `certs.py`；缺省/空 selector 落到 `mailstack` |
| **发件域的提取**（决定「该不该签」） | `from_domain_handles_display_names_brackets_and_folding` | `<a@b>`、`"Name" <a@b>`、显示名里带 `@`、头折叠四种写法都要取对；没有 `From` 或没有 `@` 时返回 `None` 而不是猜一个域 |

### 3.1.2 出站 DKIM 签名（§5.8）

签名被做成**远端传输的装饰器**，并由 `QueueRunner::new` 无条件套上 ——
「一条未签名的出站路径」在代码里不可表达（与 `crates/store` 不提供写 Maildir 的 API
是同一个思路）。本地投递（LMTP）刻意不套：DKIM 的意义在于向**外部**接收方证明身份。

失败语义（已裁定）：**失败关闭**。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **结构性保证：签名不可绕过** | `the_signed_bytes_are_what_the_inner_transport_receives` | 内层传输收到的报文**就是**签名后的字节，不是原文 |
| 不该签的不动它 | `not_applicable_passes_the_entry_through_unchanged`、`an_uninitialised_host_reports_not_applicable_rather_than_failing` | 没有签名策略时原样透传；**新装未初始化是正常状态**，不是故障（否则首投必失败） |
| **失败关闭 + 不污染出站健康** | `a_signing_failure_is_fail_closed_and_marked_as_a_local_fault` | 签名失败时内层传输**零次调用**（未签名邮件绝不发出）；失败类别为 `Transient` 且 `local_fault == true` |
| **队列侧落点** | `a_signing_failure_defers_without_tripping_the_outbound_verdict` | 端到端：条目进入退避重试、`lastError` 留下原因；`consecutive_failures == 0` 且**不判「出站 25 被封」**（否则运维会去查一个与密钥无关的方向） |
| **只在语义上属于本机时才签** | `a_real_key_signs_covered_senders_and_leaves_foreign_senders_unsigned` | **真实 RSA-2048 密钥**（`keys::rotate` 生成）：本域与子域被签（`d=`/`s=` 正确、原文逐字保留）；外域发件人返回 `NotApplicable` —— 不用自己的密钥替别人的域背书 |
| 私钥损坏不得静默降级为「不签」 | `a_broken_key_fails_instead_of_silently_sending_unsigned` | 策略在（文件存在）但内容不可解析 → `Failed`，且原因里带私钥路径便于定位 |

### 3.1.3 入站 SMTP 服务端（§5.10；INV-17）

新增 crate `crates/smtpd`。**为什么不放进 `mailstack-smtp`**：后者是纯出站的，
而 `mailstack-queue` 已经依赖它；入站要反向依赖队列（收信入队），同 crate 会成环。
两者的威胁模型也相反 —— 出站防「把凭证发给错的对方」，入站防「让对端决定我们的行为」。

本节是**与 I/O 无关但安全关键**的那一层：走私、注入、长度耗尽这类缺陷一旦上线
就是远程可利用的，而它们可以被离线穷举验证 —— 用「跑一遍真实会话」去测成本极高
且覆盖不全。会话驱动（`connection`）用 `tokio::io::duplex` 跑真实字节流。
网络与密码学那一层见 §3.1.4。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **SMTP 走私：正文里的裸 LF** | `a_bare_line_feed_is_rejected_under_the_reject_policy`、`normalization_rejects_a_bare_lf_that_would_create_the_terminator` | `Reject` 策略下裸 LF 一律 550 并断开；`Normalize` 策略下**归一化后若产生结束标记则拒绝** —— 那正是走私形态（上游按裸 LF 切、本机不切，两边对事务边界理解不一致） |
| **结束标记的任意分块** | `the_terminator_is_recognised_across_any_chunk_boundary`、`a_split_crlf_dot_crlf_is_not_mistaken_for_body_content` | 逐字节喂入与整块喂入结果**必须相同**；把 `CRLF.CRLF` 切成 5 段仍须识别 |
| **去点（dot-unstuffing）** | `dot_stuffing_round_trips_for_arbitrary_bodies` | 按 RFC 5321 §4.5.2 转义后的正文必须逐字还原（含 `.\r\n` 这种全点行） |
| **命令注入** | `crlf_inside_a_command_cannot_smuggle_a_second_command`、`control_characters_are_rejected` | 一行里混入 CRLF 的「命令」不得被解析；控制字符一律 501 |
| **应答注入** | `control_characters_in_text_cannot_forge_a_second_reply` | 被回显的地址里带 CRLF 时，应答仍**只有一条**（CR/LF 被替换为空格） |
| **资源耗尽** | `an_endless_line_cannot_exhaust_memory`、`oversized_messages_are_reported_once_then_drained` | 「永不发 CRLF 的巨大行」触发上限而不是吃光内存；超限后**只回一次 552** |
| **超限后会话不错位** | `an_oversized_message_is_refused_and_the_session_stays_in_sync` | 552 之后仍要把正文读完到结束标记，然后**正确处理后续命令** —— 少了这步，剩下的正文会被当成命令解析（本轮实现时真踩到并通过这条测试抓出） |
| **流水线不丢命令** | `commands_pipelined_after_the_data_terminator_are_not_lost`、`the_sink_runs_before_the_250_is_sent` | 正文结束标记与后续命令在同一 TCP 段里时，后续命令必须被处理；**先落盘再回 250**（先答 250 再落盘等于对发送方说谎） |
| **INV-17 反中继（服务端落点）** | `unauthenticated_foreign_recipient_is_rejected_with_the_policy_text`、`an_empty_domain_table_rejects_rather_than_relaying` | 未认证 + 非本域 → 554；**域名表为空时拒绝而非放行**（历史缺陷不得复现）。复用出站侧同一份 `RelayPolicy`，避免两处语义漂移 |
| 事务序列 | `commands_before_helo_are_out_of_sequence`、`rcpt_without_mail_and_data_without_rcpt_are_rejected` | 缺前置即 503，不替客户端补全 |
| **VRFY 恒拒** | `vrfy_is_always_refused` | 一律 502 且**不区分地址是否存在** —— 否则它就是一个目录枚举接口 |
| 凭证明文不外发 | `auth_over_a_plaintext_session_is_refused` | 未加密会话上 `AUTH` 一律 538，绝不接收明文口令 |
| SIZE 声明与实际上限 | `a_declared_oversized_message_is_refused_before_data_starts`、`an_undeclared_oversized_message_is_still_refused_after_data` | 声明超限 → 收正文前就 552；不声明 → 收完后仍然拦住 |

### 3.1.4 安全通信、限速封禁与入站认证（§5.10）

在 3.1.3 的协议核心之上叠加四层，全部有单元测试；**端到端部分跑真实 socket 与
真实 TLS 握手**（`crates/smtpd/tests/inbound.rs`，自签 CA 由 `rcgen` 生成）。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **TLS 1.2 起** | `only_tls_12_and_13_are_offered` | 协商版本列表**恰好**是 `TLS12`+`TLS13`（引用相等，不是名字匹配）。rustls 本身不实现 1.0/1.1，但把策略写成显式列表才**可测** |
| TLS 下界真的可用 | `a_client_that_only_speaks_tls12_can_still_connect` | **真实握手**：只支持 1.2 的客户端必须被接受 —— 否则「1.2 及以上」只是口号 |
| 没有材料就不启动 | `missing_material_is_refused_instead_of_starting_without_tls`、`an_empty_certificate_file_is_refused`、`contradictory_tls_configuration_is_refused_at_construction` | 缺证书 / 空证书 / 通告 STARTTLS 却无 acceptor / 隐式 TLS 无材料 → **构造期即拒绝**，绝不静默降级为明文 |
| 证书路径穿越 | `cert_paths_reject_traversal_domains` | `../../etc/shadow` 之类的「域名」无法构造出路径；合法域名先规范化 |
| **STARTTLS 升级丢弃明文缓冲** | `starttls_returns_the_upgrade_outcome_and_discards_pipelined_plaintext` | 把 `STARTTLS` 与后续命令流水线在同一段里发出：升级后那条命令**必须被丢弃**，而不是在加密会话里执行 |
| 升级后不重发 220 | `an_upgraded_session_never_repeats_the_220_greeting`、`starttls_upgrades_in_place_and_the_session_restarts_at_ehlo` | RFC 3207：升级后由客户端首发 EHLO；端到端版本用**真实 TLS 流**走完整事务 |
| 隐式 TLS（465） | `implicit_tls_handshakes_before_the_greeting` | 建连即握手，问候语只出现在加密通道里 |
| **连接限速（令牌桶）** | `a_burst_is_allowed_then_the_bucket_runs_dry`、`tokens_refill_over_time`、`limits_are_per_ip`、`connections_beyond_the_burst_are_refused_with_421` | 突发内放行、之后 421；令牌按时间补充；配额**按 IP 独立**；端到端在真实连接上验证 |
| 时钟回拨不得放水 | `a_backwards_clock_does_not_grant_tokens` | 时间倒流既不补令牌也不回挪基准时间 |
| 限速表自身不得被撑爆 | `the_table_is_bounded_by_max_entries` | 用大量源地址冲击时表被淘汰约束，**绝不**因表满而放行 |
| **IP 自动封禁** | `reaching_the_threshold_issues_a_temporary_ban`、`repeated_offences_escalate_to_a_permanent_ban_that_never_expires`、`a_temporary_ban_expires_and_clears_the_window` | 窗口内失败达阈值 → 临时封禁并自动到期；临时封禁到期只清窗口、**保留 strike**，于是屡犯会升级为永久 |
| 封禁不得自我叠加 | `failures_while_already_banned_do_not_self_escalate` | 已在封禁中的连接不计失败 —— 否则一次攻击会把临时封禁自己顶成永久 |
| 封禁表内存有界 | `the_table_is_bounded_and_never_drops_a_permanent_ban` | 淘汰空闲条目，**绝不淘汰永久封禁**（那等于悄悄解封） |
| 两类触发源都生效 | `repeated_rate_limit_triggers_ban_the_address`、`tls_handshake_failures_accumulate_into_a_ban` | 端到端：连续触发限速 → 421「blocked」；隐式 TLS 握手连续失败 → 同样升级为封禁 |
| **`Authentication-Results` 头注入** | `crlf_in_injected_values_cannot_forge_a_new_header`、`a_control_character_in_the_hostname_cannot_break_framing` | 发件人 / 域名 / 主机名里的 CRLF 被压成同一行的普通字符，折行后**只能**是空白续行 |
| **DMARC 策略检查** | `a_dmarc_fail_under_a_reject_policy_is_refused_and_not_enqueued`、`a_dmarc_fail_under_a_none_policy_is_still_delivered_with_the_verdict` | `fail` + `p=reject` → 550 且**不入队**；`p=none` → 照常投递但如实标注 |
| 非 UTF-8 不得有损转换 | `a_non_utf8_body_is_refused_rather_than_silently_corrupted` | 队列把报文建模为 `String`；与其静默篡改字节（并让下游 DKIM 校验失败），不如 554 明确拒绝 |
| **入队全链路** | `a_dmarc_aligned_message_is_enqueued_with_an_authentication_results_header`、`a_verified_message_enters_the_queue_end_to_end` | 真实 TCP 会话 → SPF/DKIM/DMARC 编排 → 加头 → 落盘；读回队列文件断言头**前置**在报文最前面且正文逐字保留 |

### 3.1.5 进程入口（`bin/mailstackd`）

在此之前，各 crate 只是**可装配的库** —— 仓库里没有任何 `main.rs`，没有进程能真正收信与
投递。本节覆盖把库装成服务的那一层：配置装配、三端口准入、停机扇出、出站调度。

**这个 crate 只做装配**，因此它最值得测的不是「功能」，而是**「什么情况下拒绝启动」**：
每一条 fail-closed 判定都对应一种「服务看起来在跑、行为却是错的」的状态。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **身份靠猜** | `a_missing_setup_file_refuses_to_start_instead_of_guessing_an_identity` | `setup.json` 缺失/损坏 ⇒ 拒绝启动（它决定问候名、`Reporting-MTA`、证书路径、postmaster） |
| **空域名表静默变砖** | `an_empty_domain_table_refuses_to_start_instead_of_silently_rejecting_everything` | 库层会 fail-closed 拒收全部收件人（INV-17），但那是静默变砖 —— 启动即失败才看得见 |
| **中继损坏被当成「未配置」** | `a_corrupt_relay_config_is_fatal_and_never_falls_back_to_direct`、`an_absent_relay_config_is_a_legitimate_unconfigured_state` | 严格区分「文件不存在」（合法未配置 → 直投）与「文件损坏」（fatal）。混为一谈就会静默退回直投，违反 INV-18/INV-21 |
| **明文中继** | `a_plaintext_relay_is_refused`、`opportunistic_encryption_is_not_accepted_because_credentials_would_leak` | `smtp_tls_security_level` 为 `none`/`may` 也算明文（`may` 是机会性加密，会退回明文），一律拒绝 —— 这条链路上要发 SASL 口令 |
| **私网中继的部署许可** | `a_private_relay_is_only_allowed_when_the_deployment_opt_in_is_present` | 中继**本身**需不需要私网许可（由地址段判定）与**部署**是否许可（`ACCESS_MODE`）是两件事，二者合起来才构成 INV-15 的判定。地址段判定直接复用出站侧的 `AddressPolicy::public_only()`，不另写一份 |
| **465 必须是隐式 TLS** | `port_465_implies_wrappermode_even_without_the_explicit_key` | INV-20：即使没写 `smtp_tls_wrappermode`，端口 465 也必须走隐式 TLS |
| **端口 → TLS 模式** | `ports_map_to_the_right_tls_mode_and_starttls_advertisement`、`a_minimal_installation_assembles_all_three_default_listeners` | 25/587 ⇒ STARTTLS 且通告；465 ⇒ 隐式 TLS 且**不**通告 STARTTLS（已加密还通告会让客户端白跑一次升级） |
| **证书缺失不得降级为明文** | `binding_is_refused_when_the_tls_material_is_missing` | 绑定前先装载证书；缺失即拒绝启动 |
| **多端口共用准入状态** | `servers_sharing_a_limiter_use_one_budget_across_listeners` | 25/465/587 必须共用**同一份**限速配额与封禁表。各端口各记一份账的话，轮换端口即可拿到成倍配额，且 `strike` 永远攒不满、永久封禁无从触发。用 `Arc::ptr_eq` 断言结构，再用「一个监听耗尽额度后另一个立刻超速」断言行为 |
| **停机是电平而不是事件** | `a_late_waiter_completes_immediately`、`every_waiter_is_woken`、`a_waiter_completes_once_the_signal_is_triggered` | 三个监听 + 队列循环共用一个信号；信号**已触发后**才加入的等待者必须立刻返回，而不是永远等下去 |
| **端到端：绑定→服务→停机** | `a_bound_server_serves_a_session_and_stops_on_the_shutdown_signal`、`the_scheduler_stops_promptly_on_the_shutdown_signal` | 真实 socket（`127.0.0.1:0`）：问候 220 → EHLO → QUIT 221；触发信号后监听与调度都在限定时间内退出 |
| **特权 RPC 双通道** | `both_faces_are_bound_under_run_dir_with_the_documented_modes`、`a_read_only_action_is_served_over_the_real_ro_socket` | 两个 socket 建在 `run_dir` 下且权限位与契约一致（RO `0660`、RW `0600`）；通过**真实 unix socket** 发 `settings.get` 得到真实配置。socket 路径由 `run_dir` 推导 —— 写死绝对路径会让 `--config-dir` 旁路部署踩到生产 |
| RPC 门控不被绕过 | `ro_surface_rejects_mutating_action`（`crates/priv`，已列入 CI required） | 线上形态的 INV-24：走只读 socket 的变更动作被 `ActionGate` 拒绝。**门控只有一份实现**，守护进程这一层不重复判定 |
| RPC 绑定失败即启动失败 | 冒烟中的「启动阶段绑定」路径 | 绑定放在启动阶段而非后台任务：建不起来就直接失败，不留「进程正常、管理台永远 503」的状态 |

**二进制冒烟**（真实进程、真实端口、真实客户端，非特权端口 2525）：

```
220 wcxdr2011 MailStack ESMTP ready        ← 问候
EHLO 通告 STARTTLS ✓
DATA 应答 250 2.0.0 Message accepted for delivery
ro mode=660 / rw mode=600 ✓
settings.get over RO → ok ✓ (hostname=…)
settings.set over RO → 被拒 ✓ (ACTION_REQUIRES_PRIVILEGE)   ← INV-24
SIGTERM → 监听 / 队列 / ro / rw 全部停止，进程干净退出 ✓
队列条目以 Authentication-Results: mail.example.org;… 前置 ✓
```

### 3.1.6 CLI（`bin/mailstackctl`）

```text
mailstackctl <action> [JSON] [--confirm] [--config-dir DIR] [--ro-socket PATH] [--sudo-wrapper PATH]
```

命令行本身没什么好测的，但**两处一旦写错就发生在特权边界上**，因此被单独抽进 `lib.rs`：

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **`--confirm` 必须是真布尔** | `confirm_is_injected_as_a_real_boolean`、`confirm_on_a_non_object_payload_is_refused`、`without_the_flag_no_confirm_key_is_added` | `ActionGate` 明确拒绝「真值」（字符串 `"true"`、数字 `1`）。若这里拼成字符串，破坏性动作**永远无法执行**；若被宽松解析，确认门形同虚设 —— 两个方向都不可接受。数组/字符串载荷无法携带 `confirm`，**拒绝**而不是静默忽略 |
| **退出码必须可区分** | `helper_unavailable_and_operation_failure_get_different_exit_codes`、`an_unreachable_socket_is_classified_as_a_transport_failure` | INV-8：脚本与监控靠状态码判断该重试还是该报警。`0` 成功 / `1` 动作失败 / `2` 用法错误 / `3` 助手不可达 / `4` 中途超时 |
| **JSON 非法不得静默变空** | `malformed_json_is_a_usage_error_not_a_silent_empty_payload` | 静默变成 `{}` 会让 `domains.add` 以「参数缺失」失败，掩盖真正的原因 |
| **通道不由调用方指定** | （结构性：CLI 没有「强制通道」开关） | 动作走 socket 还是 `sudo` 由 `PrivilegedCaller::channel_for` 唯一判定；提供开关就等于提供一个绕过门控的入口 |

**特权调用客户端的归属**：`PrivilegedCaller` 从 `crates/web` 下沉到 `crates/priv`。它用的是特权协议、
实现的是特权通道的失败策略（INV-25/INV-26）——与协议同源。留在 `crates/web` 里，第二个调用方
（`mailstackctl`）只能复制一份，而「复制一份特权判定」正是这个项目一直在避免的事。
`crates/web` 现在只剩「把 `CallError` 映射成 HTTP 状态码」（`every_failure_kind_maps_to_a_distinguishable_status`）。

**二进制冒烟**（同一次会话中，真实 CLI 对真实守护进程）：

```
mailstackctl domains.list            → {"domains":[{"name":"example.org","target":"ok"}]}   ← 走只读 socket
mailstackctl totally.unknown         → 退出码 1（未登记动作默认走只读面并被门控拒绝）   ← INV-24
mailstackctl settings.set --sudo-wrapper <fake> → 输出 {"via":"fake-wrapper"}              ← 变更动作确实经 sudo
```

> **门禁范围已扩展到 `bin/`**：CI 与 `verify-invariant-gate.sh` 原先只 `grep crates/`，
> 于是 `bin/` 下的安全断言「加了等于没加」。现在两者都扫 `crates/ bin/`，并把
> `unknown_actions_default_to_the_read_only_channel`、`an_unreachable_socket_is_classified_as_a_transport_failure`、
> `helper_unavailable_and_operation_failure_get_different_exit_codes` 列入 required。

### 3.1.7 提交端口 SASL（§3.5；RFC 4954）

在此之前 587/465 **开了却不能用**：会话通告了 AUTH 也无法认证，`AUTH` 一律回 454。
本节补上答辩链条的最后一环 —— 认证后端是 **Dovecot auth socket**，不另建一份口令源
（自己读 `/etc/shadow` 等于凭空多出第二份真相源，改密时必然漂移）。

分层与 TLS 层同构：**协议/状态机（`session`）不做 I/O**，认证调用由驱动
（`connection`）完成，后端（`sasl`）只负责 Dovecot auth-client 协议（v1.2）。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **明文连接上不得认证** | `auth_over_a_plaintext_session_is_refused`、`sasl_is_an_esmtp_extension_so_helo_sessions_cannot_authenticate` | 未加密会话 `AUTH` 一律 538（口令不上明文）；AUTH 是 ESMTP 扩展，HELO 之后回 503 |
| **认证是「能不能中继」的开关** | `authentication_is_what_unlocks_relaying_to_a_foreign_domain`、`an_authenticated_submission_may_relay_to_a_foreign_domain` | 同一个外域收件人：认证前 554、认证后 250。前者是状态机单元，后者是**真实 TCP + TLS + auth socket** 的端到端 |
| 认证失败不得放行 | `a_rejected_credential_does_not_grant_relay` | 535 之后会话仍为未认证，外域收件人继续被 554 拒绝 |
| 成功后不得再次认证 | `a_successful_auth_sets_the_identity_and_a_second_attempt_is_refused` | RFC 4954 §4：第二次 `AUTH` 回 503，且身份不被覆盖 |
| **凭据应答不得注入 auth socket 协议行** | `a_sasl_response_that_is_not_base64_never_reaches_the_auth_backend`、`base64_validation_rejects_anything_that_could_inject_a_protocol_field`、`a_bare_auth_gets_an_empty_challenge_and_the_continuation_must_be_base64` | Dovecot 的协议行是**制表符分隔**的。一行 `AAAA\tresp=…` 若被转发就会凭空多出一个字段。防线是严格 base64 字符集校验，并且断言**后端一次都没被调用** |
| **535（凭据错）与 454（后端不可用）必须可区分** | `credential_failure_and_backend_failure_are_different_replies`、`an_unreachable_auth_backend_yields_454_and_never_535`、`a_dovecot_temporary_failure_surfaces_as_454_and_keeps_the_peer_unauthenticated` | 后端抖动被当成口令错，会让客户端去改密码；端到端版本让假 Dovecot 回 `FAIL temp`，断言对端看到 454 且仍未认证 |
| **真协议字节** | `a_submission_over_implicit_tls_authenticates_against_a_dovecot_auth_socket` | 假 Dovecot 逐字断言客户端发了 `VERSION 1 2`、`AUTH\t1\tPLAIN\tservice=smtp\tsecured=tls\t…\tresp=<b64>` |
| 两段式交换 | `a_bare_auth_gets_a_challenge_and_the_next_line_is_taken_as_the_response` | `AUTH PLAIN` → `334 ` → base64 单独一行；该行**不经命令解析器**（否则会被当成未知动词） |
| 取消与失序 | `a_star_cancels_the_sasl_exchange`、`a_continuation_without_an_exchange_in_progress_is_out_of_sequence` | RFC 4954 §4 的 `*` 取消回 501；没有交换在进行时收到续行回 503（双方状态已分叉） |
| 构造期一致性 | `contradictory_tls_configuration_is_refused_at_construction`（新增 AUTH 分支） | 通告了 AUTH 却没有后端 ⇒ **拒绝启动**：每次认证都必然 454，那是在骗客户端 |

**响应码语义（对外契约）**：`235` 成功 / `334` 挑战 / `501` 应答非法 / `503` 失序或重复认证 /
`504` 机制不支持 / `535` 凭据错 / `454` 后端暂时不可用。535 的文案**不区分**「用户不存在」
与「口令错」，避免认证端点变成目录枚举工具。

**运行时取舍**：Dovecot socket 连不上**不会**拦住服务启动（否则 Dovecot 重启会连带停掉
收信），只让 AUTH 回 454；这与「构造期配置错误必须 fail-fast」是有意区分的两类失败。

### 3.1.8 直投：MX 解析与按优先级投递（§5.10.10；INV-15、INV-18、INV-21）

在此之前 `OutboundRoute::Direct` 是一个**明确的临时失败**（`DirectDeliveryUnavailable`）——
没有中继配置时邮件投不出去，但至少不会假装成功，也**不会**偷偷改用中继。本节补上
「本机自己当 MTA」这条路：逐收件域解析 MX → 按优先级依次拨号 25 端口。

分层与其余部分一致：**解析与决策分开**。[`classify_mx`] 是纯函数（排序、null MX、
隐式回退），[`MxResolver`] 只负责「把域名换成记录」。于是真正容易写错的规则可以在
无网络环境下穷举验证。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **优先级只决定尝试顺序** | `records_are_ordered_by_preference_not_left_in_answer_order`、`equal_preferences_are_ordered_deterministically` | 必须按 `preference` 升序，而不是 DNS 应答里碰巧的顺序；同优先级用主机名做**稳定**次序（随机只影响负载分摊，却让行为不可复现） |
| 同一主机多条记录 | `a_duplicate_host_keeps_the_better_preference` | 取更优的那条，否则顺序里会出现「同一台机器既排第一又排最后」 |
| **null MX 是明确拒绝** | `a_null_mx_is_an_explicit_refusal_not_an_implicit_fallback`、`a_null_mx_alongside_other_records_still_refuses`、`a_null_mx_is_permanent_and_reported_as_such`、`a_null_mx_is_a_permanent_failure_not_a_retry` | RFC 7505 的 `MX 0 .` 表示「本域不收信」。若按「空主机名 → 无记录 → 退化为域本身」处理，就会反过来往一个明确拒收的域投递。判**永久**失败并立即退信 |
| **无 MX 不是投不出去** | `no_records_falls_back_to_the_domain_itself` | RFC 5321 §5.1：退化为「把域本身当 MX」（查 A/AAAA）。当成永久失败会拒掉一大批只配 A 记录的域 |
| **INV-15 的直投侧** | `an_unroutable_mx_is_rejected_by_the_address_policy`、`direct_delivery_is_refused_when_the_mx_points_into_private_space` | 收件域可以用 MX 记录把本机变成内网扫描器。公网策略必须拒绝环回/私网 MX，并**不回落**到中继 |
| 一台不可用不影响其余 | `one_unusable_mx_does_not_hide_the_next_one`、`a_resolver_failure_is_surfaced_as_a_dns_error` | 依次尝试下一台；全部不可用才失败（DNS 故障 → 可重试，地址全被拒 → 永久） |
| **直投绝不发凭证** | `direct_delivery_follows_the_mx_and_never_sends_credentials` | 真实 TCP 上的假 MX：直投路径**即便被误配了凭证也不发送**，也不去碰 STARTTLS（链路无凭证，见 §5 的登记） |
| 逐域分组 | `recipients_are_grouped_by_domain_in_a_deterministic_order`、`a_recipient_without_a_domain_is_never_silently_accepted` | 一封邮件可能同时投给多个外域，各域有各自的 MX；分组顺序确定，无 `@` 的收件人绝不被判成「投递成功」 |
| **不回头改用中继** | `direct_route_fails_loudly_and_never_falls_back_to_the_relay` | 直投不可用时结果是**明确的失败**，不是「悄悄改用中继」那种会破坏 SPF 对齐的兜底（§5.10.10） |

### 3.2 Phase 1 已覆盖（此前报告，保持不变）

INV-1、2、3、4、6、7、8、10、12、22、23、24、25、26、27、28、30、31、33、34、35、36、37、43。

### 3.3 尚未适用（5 条）

| 不变量 | 阻塞原因 |
|---|---|
| INV-9 | 遥测采样（`metrics.realtime` / 采样器）尚未移植 |
| INV-11 | 已覆盖（LMTP 是落箱唯一路径，见 §3.1）；此处仅剩「真实 Dovecot 未验证」这一环境事实，见 §5 |
| INV-38 – INV-42 | 前端与主题属 Phase 3（htmx 管理台尚未开始） |

### 3.4 Phase 4 新增覆盖（2FA 与写面）

这一节按**章节**索引：规格书把 2FA 表述在 §5.5、把写面表述在 §5.4/§2.5，这里不臆造 INV 号。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| **INV-5** secret **绝不明文落盘** | `begin_writes_a_pending_envelope_and_never_the_plaintext_secret`、`master_key_is_created_once_and_only_readable_by_its_owner` | `admin.json` 里只有 `enc`/`nonce`/`tag`；主密钥单独落在 `0600` 的 `totp.key`。**读路径（登录校验）不得顺手造密钥** —— 否则「密钥被运维删掉」会被静默掩盖 |
| **INV-5** 信封的完整性与绑定性 | `envelope_round_trips_and_binds_to_the_master_key`、`envelope_rejects_tampering_of_any_component`、`unknown_envelope_version_is_refused_instead_of_guessed` | 换密钥 / 改密文 / 改 tag / 改 nonce / 长度不对 / 未知版本**全部必须失败**，绝不返回部分明文 |
| 动态码正确性（RFC 4226/6238） | `hotp_matches_the_rfc4226_vectors`、`verify_accepts_the_current_step_and_rejects_neighbours_outside_the_window` | 逐条比对 RFC 4226 Appendix D 的十条向量；±1 步窗口内通过、窗口外拒绝；畸形输入不 panic |
| **INV-29** 一张恢复码只能用一次 | `a_recovery_code_can_only_be_consumed_once`、`recovery_codes_tolerate_human_formatting`、`malformed_recovery_input_never_touches_the_stored_codes` | 消费后即从集合移除；连字符/空格/小写等抄录格式差异不得让**正确的码**失效；形状不对的输入不进临界区、也不改动任何码 |
| **INV-32** 整个读-改-写必须在**同一把锁**内 | `concurrent_recovery_consumption_spends_exactly_one` | 8 个线程并发消费同一张码：**恰好一个**成功，其余恢复码一张不少。若退化成「各自 read 后 write」，会有多个线程看到「码还在」而同时成功 |
| 失败关闭：确认码不对就不置位 | `enable_requires_a_correct_code_and_only_then_issues_recovery_codes`、`enable_without_a_pending_enrollment_is_refused`、`begin_is_refused_while_already_enabled` | 打错确认码时**不置位、也不签发恢复码** —— 否则一次误输就把账号锁在「用户拿不到恢复码」的 2FA 状态里；已启用时重新 `begin` 会静默换掉在用 secret，必须拒绝 |
| 未启用 / pending 一律不放行 | `verify_rejects_everything_when_two_factor_is_not_enabled` | `disabled` 与 `pending` 两态都不得接受任何因子 |
| 「码不对」是结论而不是错误 | `totp_verify_reports_a_wrong_code_as_a_conclusion_not_an_error` | 登录侧依赖它：若返回 `Err`，Web 会把「验证码错」误报成 `503` 基础设施故障，与 INV-23 的不可区分性冲突 |
| **INV-30**（动作面）改密不得关掉 2FA | `admin_set_preserves_two_factor_through_the_registry`、`changing_the_password_keeps_two_factor_working` | 走 `admin.set` 改密后 2FA 仍启用、恢复码张数不变、旧 secret 仍能通过校验 |
| **INV-43**（动作面）写入白名单 | `settings_set_applies_only_the_whitelisted_keys`、`settings_set_refuses_a_patch_that_is_not_an_object` | 白名单外的键（含 `version`）不写入、不回显为已应用；非对象载荷直接报错 |
| 表写入与 **INV-11/§2.5** 的对外形态 | `domain_and_alias_writes_round_trip_through_the_registry` | 经动作面写域名/别名后能从 `domains.list` 读回；**删域名连带删掉其别名**，不留孤儿路由 |
| 基线缺陷守卫：目标不得逐字符展开 | `a_single_string_destination_is_never_expanded_into_characters`、`alias_add_rejects_a_non_string_destination` | 基线把裸字符串目标逐字符迭代，`"xy"` 静默变成两个目标 `x`、`y`。Rust 侧只接受字符串或字符串数组，数组里混入非字符串直接报错 |
| 失败关闭：拒绝不产生副作用 | `write_actions_report_missing_fields_instead_of_guessing`、`dkim_rotate_validates_before_generating_anything` | 字段缺失/域名非法时明确报错，且**不留下任何文件**（尤其不得先建出密钥目录） |
| 2FA 的 HTTP 面已接线 | `two_factor_state_is_served_in_process_and_the_write_routes_are_wired` | 读状态由 Web 进程直接应答（不带助手）；三条写路由必须被 CSRF 层拦下（`404` 表示路由没挂上） |
| **动作路由全表已接线**（防「已实现却点不到」与「误挂到免认证面」） | `every_implemented_action_route_is_wired_and_behind_auth` | 真相源是**助手侧的注册表**（`Registry::with_core_actions` + `with_readers`），不是本文件的路由清单 —— 用被测量给自己打分等于同义反复。凡已实现的动作，其契约路由必须已挂进 `build_router`，且无会话时回 `401`（`404` = 未接线；`401` 缺失 = 被挂到了免认证面）。请求在认证层即被拦下，**不会**触达真实助手，故 `system.doctor` 的封禁探针不会产生副作用 |

### 3.5 Phase 4 只读聚合面（`snapshot` / `logs.list` / `metrics.realtime` / `certs.list` / `network.check_port` / `system.doctor`）

这一组动作的共同纪律是**「读不到就说读不到」**：静默省略会把「没数据」渲染成
「没问题」，而这两者对运维的含义正好相反。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| 读不到的片段必须**显式出现** | `snapshot_reports_what_it_cannot_read_instead_of_omitting_it`、`metrics_realtime_marks_missing_proc_entries_rather_than_reporting_zero`、`logs_list_says_unavailable_instead_of_returning_an_empty_list` | `snapshot` 用 `unavailable: [...]` 列出尚未移植的子项（当前是 `users`）；`metrics.realtime` 缺哪一项就把它列进 `unavailable` 且该字段为 `null`（**不编一个 0 出来**）；`logs.list` 读不到 journal 时回 `available: false` + 原因，而不是空数组 |
| 不拿错的东西顶替 | `missing_mem_available_is_reported_rather_than_guessed` | 老内核缺 `MemAvailable` 时用 `MemFree` 顶替会低估可用内存，让「内存告急」看起来比实际严重 —— 宁可报「读不到」 |
| 一个子项失败不拖垮整条 | `metrics_realtime_marks_missing_proc_entries_rather_than_reporting_zero`、`logs_list_parses_journal_json_including_binary_messages` | 缺 `meminfo` 时 `uptime`、队列、服务仍照常返回；journal 里一行不是 JSON 只跳过该行 |
| 出站结论与调度器**同源** | `snapshot_surfaces_the_persisted_outbound_verdict` | `QueueRunner::outbound_health` 与只读聚合面现在共用同一个自由函数 `outbound_health_from`（结论文案只有一份）；断言「无中继 → 请配中继」「有中继 → 中继本身在失败」两种文案 |
| 队列积压与隔离可见 | `snapshot_counts_backlog_and_quarantined_entries` | 积压量来自磁盘条目数；被隔离的坏条目单列一个数（它们不该凭空消失） |
| 证书表的核心是**到期天数** | `a_certificate_reports_its_expiry_in_days`、`certs_list_flags_the_soon_expiring_ones`、`an_unparseable_certificate_reports_why_instead_of_pretending_it_is_fine`、`name_attributes_use_openssl_style_short_names` | 用 rcgen 现场签一张 **45 天后**到期的自签证书，断言解析出的 `daysUntilExpiry == 45`、`notAfter` 是 `2026-02-15`、subject/issuer 渲染成 `CN=...`；7 天的那张必须进 `expiringSoon`；解析失败必须写明原因 |
| 私钥权限问题要能被看见 | `a_group_or_world_readable_private_key_is_flagged` | `0644` 的私钥被标为 `keyGroupOrWorldReadable` —— 这是**必须能被管理台看见**的配置问题 |
| **只读接口不得变成任意主机探针** | `network_check_port_never_accepts_targets_from_the_request` | 请求体里给 `targets` / `target` 一律无效：探测目标只来自部署配置（`MAILSTACK_PORT_PROBE_TARGETS`），地址策略只允许公网地址 |
| 边界夹取 | `network_check_port_rejects_out_of_range_ports`、`logs_lines_are_clamped_at_both_ends` | 端口必须在 `1..=65535`（非整数也拒绝）；日志行数默认 200、夹在 `1..=1000` —— 否则这条只读接口就是一个「把 journalctl 全量倒出来」的开关 |
| 诊断**无副作用** | `system_doctor_probes_the_ban_list_and_leaves_no_trace` | 封禁往返探针跑在**新建的内存表**上，对 `192.0.2.1`（TEST-NET-1，不可路由）ban→查询命中→unban→查询不命中；连跑两次结果逐字相同，证明它没有累积状态 |
| 诊断项覆盖与失败表达 | `system_doctor_reports_each_broken_precondition`、`system_doctor_passes_when_the_host_is_fully_configured` | 八项检查顺序固定：identity / admin_credentials / domain_table / relay_config / dkim_key / tls_certificate / audit_chain / ban_round_trip。空域名表必须点名 INV-17；**没有中继配置是合法状态**而不是故障 |

### 3.6 Phase 4 进程内时序遥测（`GET /api/metrics/telemetry`）

契约里这条路由的 `action` 是 `None`（**不经助手**），动作白名单又已冻结为 50 条，
因此采样器落在 Web 进程内（`crates/web/src/telemetry.rs`，等价移植基线的
`SystemMetricsCollector`）。它不在「动作×路由」守卫的覆盖范围里（那条守卫只扫
`action` 非空的路由），所以另有一条接线与认证的测试单独钉住它。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| 7 档时间窗与采样间隔 | `telemetry_uses_the_baseline_intervals_and_falls_back_to_one_hour` | 7 档的 `intervalMs` 逐档比对（2s/5s/30s/60s/5m/15m/1h）；非法 `range`（含路径穿越形态）一律回落 `1h` —— 档位值**不会被透传** |
| CPU 是**差分**采样 | `cpu_is_differential_so_the_first_sample_has_nothing_to_compare_against` | 构造时基线 = 当前快照 ⇒ 第一次差分为 0；改夹具使 idle +200、总增量 +400 ⇒ 恰好 50.0%（口径见 §4.20） |
| 环形的容量与节流 | `the_one_minute_ring_takes_every_cycle_and_the_others_are_time_gated` | t=1s 时只有 1m 档进点；t=1h 时各档按自己的间隔全部进点（容量上限见 `RANGES`） |
| 空的环不能假装有历史 | `an_unsampled_collector_reports_zero_points_but_still_fills_current` | `samplingCount == 0` 且 `points == []`，但 `current` 仍由一次即时采样填充 |
| 守护进程槽位**恒在** | `daemons_come_from_proc_comm_and_an_absent_one_stays_stopped` | 六个槽位固定顺序输出；`comm` 命中才置 `ACTIVE`，否则保持 `STOPPED`（界面据此区分「没在跑」与「没读到」）；`node` 这个通用名刻意不归属 |
| 同一守护进程的多个进程相加 | `several_processes_of_one_daemon_are_summed` | 两个 `postfix` 进程（`qmgr` + `pickup`）内存相加；`pid` 取先看到的那个（顺序不定，故只断言非 0） |
| 队列读数来自 `postqueue -j` | `queue_totals_come_from_postqueue_and_deferred_needs_a_delay_reason` | 非 JSON 行不算条目；只有收件人带 `delay_reason` 的条目才算延迟 |
| 磁盘读数与刷新节流 | `disk_usage_is_parsed_from_df_and_refreshed_at_most_once_a_minute`、`an_unparseable_df_leaves_disk_at_zero_rather_than_guessing` | 一分钟内只跑一次 `df`；解析不出就不给数（不拿残缺行凑） |
| 内存回退语义与 `core::sysinfo` **不同** | `missing_mem_available_falls_back_to_mem_free_instead_of_reporting_nothing` | 遥测的形状里没有「读不到」的位置，缺 `MemAvailable` 时退到 `MemFree`（基线即如此）；`core::sysinfo::read_meminfo` 仍保持 fail-loud —— 两种纪律不揉进同一个函数 |
| 响应形状对齐前端类型 | `the_response_carries_every_field_the_frontend_type_declares` | 逐字段对照基线 `src/types.ts` 的 `TelemetryResponse` / `TelemetryPoint` / `TelemetrySummary` |
| 接线与认证 | `telemetry_is_served_in_process_and_returns_the_raw_object` | 无会话回 401；带会话回 200 且是**遥测对象本身**（不套 `{ok,data}`） |

> 这些测试全部注入假 `CommandRunner` 与固定时钟，**不会**在开发机上真的跑 `df` / `postqueue`。

### 3.7 Phase 4 邮箱用户（`users.*`）

`users.*` 长期挂在「**需先裁决**」下（HANDOVER 登记的前提是「vmail 布局未定、Dovecot
口令方案未定」）。**基线其实已经给出答案**，本轮照抄即可：

* **不用 `/var/vmail` 布局**：账号就是**系统账号**。`useradd -m` 建 `/home/<u>`，
  Maildir 即 `~/Maildir`（`cur`/`new`/`tmp`）；Dovecot 侧配
  `mail_location = maildir:~/Maildir`。
* **不写 Dovecot passwd-file**：口令走系统 / PAM —— `chpasswd`（stdin 收
  `user:password`）设口令，`passwd -l` / `passwd -u` 锁定与解锁，`passwd -S` 的
  **第 2 个字段**（`L` / `LK`）判定是否锁定。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| 校验**先于**任何副作用 | `unmanaged_domain_is_rejected_before_any_side_effect`、`duplicate_mailbox_is_rejected` | 未受管域名 / 重复邮箱在调 `useradd` 之前就被拒；断言假 runner 一次都没被调用、两份注册表都没被创建 |
| 口令的上下文校验 | `password_is_checked_against_the_username_and_email_context` | `users.add` 的上下文是 `(username, email)`；口令里出现用户名或完整地址即拒。`users.password` 的上下文是**单个** `u`（与基线一致，刻意不统一） |
| 建账号的降级链与 stdin | `useradd_falls_back_and_chpasswd_receives_the_secret_on_stdin` | `useradd -m -N -g <grp>` 失败后退回 `useradd -m`；口令经 `chpasswd` 的 **stdin** 下发（`CommandRunner::run_with_input`，默认实现会**响亮报错**，防「默默没喂输入」） |
| Maildir 与权限 | `maildir_directories_and_modes_are_created` | `~/Maildir/{cur,new,tmp}` 被建出；家目录 `0750`、Maildir 目录 `0770`、文件 `0660`，属主改为该用户 |
| 注册表 | `registries_are_written_atomically_with_0640_and_sorted` | `managed-users.json`（**排序**数组）与 `managed-mailboxes.json` 原子写、`0640`；后者 chown 到 `mailstack-webmail` —— 它必须能被 webmail 进程读到（**不含机密**，只有地址与账号名） |
| 破坏性动作的护栏 | `delete_rejects_protected_and_system_accounts_but_removes_managed_ones` | 拒绝 `PROTECTED_USERS`（root/daemon/postfix/dovecot/…）、拒绝未托管、拒绝 `uid < 1000`；删除走 `userdel -r` → `userdel` → `deluser` |
| 会话必须被踢掉 | `status_toggles_lock_and_bumps_the_session_epoch`、`password_change_uses_chpasswd_bumps_the_epoch_and_reports_updated` | 改密与锁定/解锁都会 bump `webmail-session-epoch.json` 里该用户的 epoch。**只挡住未来登录是不够的**：已经在线的 webmail 会话也必须失效 |
| 拒绝面 | `status_rejects_protected_or_unmanaged_users` | 与 `users.delete` 同一条护栏，文案与基线一致 |
| 幽灵条目 | `list_skips_accounts_that_no_longer_exist_on_the_system` | 注册表里有、系统里已不存在的账号在列表里被**跳过**（不是报错，也不静默返回一个假条目） |

> 测试全部注入假 `CommandRunner`（含 stdin 捕获）、假 `/etc/passwd` 与 `/etc/group`、
> 临时 `Paths`：**绝不**真的执行 `useradd` / `chpasswd` / `userdel` / `passwd`，
> 也绝不读写真实的 `/etc`、`/var`。

**顺带定死了两处此前悬置的前提**（见 §5 相应条目）：`mail_test_loopback` 与
`setup.mail.test` 里「Maildir 权威布局未定」的前提现已解除 —— 权威布局就是
`<系统用户家目录>/Maildir`。

### 3.8 Phase 4 ACME 证书（`setup.cert.issue` / `certs.renew`）

「ACME 依赖选择」这个悬置问题同样是**基线已回答**：它不引入任何 ACME crate，而是调用
外部脚本 **`acme.sh`**（硬编码 `/root/.acme.sh/acme.sh`，`--home /root/.acme.sh`）。
因此本子系统**零新依赖**。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| 失败是**数据**不是错误（`certs.renew`） | `cert_renew_reports_a_missing_acme_sh_as_data_not_an_error`、`cert_renew_reports_a_failed_renewal_as_data` | `acme.sh` 缺失 / `--renew` 非 0 → 返回 `{status: failed, domain, error}`；只有域名非法才抛错（`invalid domain format`）。这个不对称是基线的真实行为，照抄 |
| 命令行逐字正确 | `cert_renew_runs_the_exact_command_and_returns_the_certificate_list`、`acme_issue_succeeds_with_the_exact_command_and_reloads_the_services` | `--renew -d <d> --force --home /root/.acme.sh`；issue 侧含 `--accountemail` / `--server letsencrypt` / `--keylength ec-256` / `--home`，随后 `--install-cert … --ecc --key-file … --fullchain-file … --reloadcmd …` |
| **自定义证书校验不落盘** | `custom_issue_validates_via_stdin_and_writes_with_the_right_modes` | **偏离基线**：基线把 cert/key 写成 0600 临时文件再让 openssl 读；这里把 PEM 从 **stdin** 喂给 `openssl`（`x509 -noout` / `-checkend 0` / `-checkhost` / `-pubkey`，`pkey -pubout`），**私钥根本不落盘**，也无需新增 `tempfile` 依赖。测试断言 runner 收到了 stdin、且 argv 里没有任何临时路径 |
| 自定义证书的四条判据 | `custom_issue_requires_the_pem_markers`、`custom_issue_reports_a_san_mismatch`、`custom_issue_reports_a_key_that_does_not_match` | PEM 标记缺失 / SAN 不匹配 / 公私钥不配对，文案与基线逐字一致 |
| **校验先于副作用** | `acme_issue_validates_before_creating_any_directory` | **偏离基线**：基线先 `mkdir -p /etc/tls/<domain>` 再校验 email/method，于是「邮箱非法」会留下一个空目录。这里全部校验通过才建目录（成功路径行为不变） |
| ACME 分支的参数校验 | `acme_issue_rejects_an_invalid_webroot`、`acme_issue_reports_a_missing_acme_sh_as_an_error`、`acme_issue_reports_issue_and_install_failures` | `webroot` 必须存在且为绝对路径；`acme.sh` 缺失即报错；`--issue` / `--install-cert` 非 0 各有自己的文案 |
| **子进程超时** | `acme_issue_treats_a_timed_out_child_as_a_failure`、`system_runner_kills_a_process_that_exceeds_its_timeout` | **对基线的补齐**：`CommandRunner` 原本没有超时，而 `acme.sh` 是可能挂在网络上的外部程序。新增 `run_with_timeout`（默认实现**明确报错**，防「默默没有超时」），`SystemCommandRunner` 实现为 `spawn` → 轮询 `try_wait` → 超时 `kill` 并回收。180/300/120 秒与基线一致 |
| 落盘权限 | 同上 | `privkey.pem` 0600、`fullchain.pem` 0644 |
| 配置与重载 | `issue_skips_postconf_when_it_is_not_installed` | 有 `postconf` 时写三条 `-e`（cert / key / `smtpd_tls_security_level = may`），随后 `service_ctl` 重载 postfix 与 dovecot（走既有降级链） |

> `acme.sh` 与 reload 脚本路径是**硬编码常量**，绝不来自请求体 —— 否则这个动作就是一个
> 任意脚本执行器。reload 脚本的写入走可注入的探测层，测试不会碰真实的 `/usr/local/sbin`。

### 3.9 Phase 4 AI 出站子系统（`ai.*`）

这是最后一个动作族，也是**攻击面最大**的一个：它把用户可控的 URL 拿到服务器上发起出站
请求。基线的防护集中在 `ai.py`，逐条对齐如下。

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| URL 语法面 | `validate_endpoint_rejects_malformed_urls`、`url_without_scheme_is_rejected_as_http_or_https`、`resolution_failure_is_reported_with_the_host` | 长度上限 2048 / 空 / 非 http(s) / 无 hostname / 带用户名口令 / 带 fragment / `http` 且未允许私网 —— 各有与基线逐字一致的文案 |
| **每一个解析结果都要筛** | `every_resolved_address_is_screened_for_ssrf`、`a_host_mixing_public_and_private_addresses_is_rejected` | 不是只筛第一个地址：只要有**任一**解析结果落在私网/环回/链路本地/云元数据/CGNAT/内嵌 IPv4，整条请求就被拒 —— 否则「A 记录里混一个私网地址」就能靠顺序绕过 |
| **固定 IP 后再拨号**（DNS-rebinding） | `an_allowed_private_endpoint_pins_the_address` | 解析 → 筛选 → **固定第一个 IP**；连接只连这个 IP，但 SNI 与 Host 头仍用原域名。复用 `smtp::target::resolve_pinned` 与 `smtp::dial::PinnedDialer`，**不另写一份解析/拨号** |
| 私网开关在**部署侧** | `private_access_requires_the_deployment_switch` | 请求写 `allowPrivateNetwork: true` 但部署没开 `MAILSTACK_ALLOW_PRIVATE_AI=1` → 明确报错；有效值等于部署开关本身，**请求无法自己提权** |
| **TLS 校验不可关** | `insecure_tls_is_rejected_everywhere` | `ai.config.set` / `ai.chat` / `ai.test` / `ai.models.list` 任何一处传 `insecureTls` 都报同一句文案 |
| 响应与重定向纪律 | `response_body_over_two_megabytes_is_rejected`、`chunked_responses_are_decoded`、`content_length_limits_the_body` | 2 MB 上限；`chunked` 与 `Content-Length` 两种都要解析对；重定向最多 3 次且**必须同源**（跨源直接拒），`303` 之后降级为 `GET` 且不带 body |
| 配置写入 | `config_set_rejects_an_unknown_provider`、`config_set_reuses_the_previous_key_when_none_is_supplied` | provider 必须精确命中预设；写 `ai-provider.json` 0600 并镜像 `etc/ai.json`；**不传 key 时沿用旧 key** 而不是清空 |
| 打码 | 同上 | 公开配置里的 key 只回前 4 位 + `****`（或 `****`），**明文绝不出现**；测试断言错误文案与 argv 里都不含 key |
| 两种协议 | `chat_openai_shape_and_reply_parsing`、`chat_anthropic_extracts_system_and_parses_text_blocks`、`chat_reports_both_protocol_error_texts` | OpenAI 兼容协议与 Anthropic 协议各拼各的请求体与头（后者把 `system` 角色抽到顶层、带 `anthropic-version`）；两边错误文案不同，照抄 |
| 取值顺序与降级 | `chat_requires_a_non_empty_message_list`、`chat_requires_an_api_key`、`chat_uses_the_fallback_when_the_primary_fails`、`an_explicit_provider_disables_the_fallback` | provider/key/baseUrl/model 一律「请求 → 已存配置 → 预设」；fallback **只在请求没显式指定 provider 时**生效 —— 否则会静默改掉调用方选定的供应商 |
| prompt 拼接 | `diagnose_and_parse_build_the_exact_prompt` | `diagnose` / `parse` 的提示词逐字比对；它们把 `logs`/`text` 拼成新 dict **只带 `messages`**，不会把请求里的 provider 带进去 |
| 出站总闸 | `crates/priv/src/dispatch.rs` 的既有测试 | `ai.test` / `ai.chat` / `ai.diagnose` / `ai.parse` / `ai.models.list` 受 `ai.conf` 总闸门控（公网默认关）；`ai.config.get` 纯读本地、不在闸内 |

> 测试全部注入假 transport 与假解析器：**CI 完全离线可跑**，不会向任何真实供应商发请求。
> `ai.config.set` 只写 JSON、不出网。

### 3.10 Phase 3 管理前端接入（8 个只读动作 + RPC 桥 + 静态托管）

前端（`mailstack-admin-frontend`，Vite + React 19 单页应用）是**用户提供的外部产物**，
它的接口假设与基线 Node 后端并不一致。这一节记录为对接它而新增的后端面与相应测试。

**新增动作与路由**

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| 8 个新动作确实已注册 | `the_frontend_list_actions_are_registered` | `users.list` / `aliases.list` / `queue.list` / `services.list` / `dkim.keys` / `dns.records` / `metrics.system` / `activity.list` 逐个查 `Registry::is_implemented` |
| **每个都必须是纯读** | `every_added_list_action_is_pure_read` | 逐条断言落在 RO、**不在** RW、不是破坏性动作 —— 一旦误归 RW，Web 进程就得经 sudo 下发，等于给列表开了一条特权通道 |
| 数量变更是有意为之 | `read_only_set_has_exactly_twenty_two_actions` | RO 由 14 增至 22 |
| 契约路由数 | `route_count_is_stable` | 62 → 72（新增 10 条，**无改动/无删除**） |
| 动作×路由全表接线 | `every_implemented_action_route_is_wired_and_behind_auth` | 真相源是助手侧 `Registry`，不是 web 自己的路由清单 |

**列动作的诚实边界**（读不到的不编）：

| 动作 | 关键测试 | 约定 |
|---|---|---|
| `users.list` | `users_list_maps_status_to_active_and_reports_the_absent_quota_as_zero`、`users_list_treats_a_locked_account_as_inactive` | `quotaUsed`/`quotaTotal` **恒 0**、`createdAt` 恒空 —— 配额与创建时间在本项目里**根本没有落盘**（基线 `mail.py:120` 同样硬编码 0）。这是「没有这个数据」，不是漏读 |
| `aliases.list` | `aliases_list_exposes_the_first_target_and_keeps_every_destination`、`aliases_list_on_a_missing_table_is_empty_not_error` | `active` 恒 `true`（别名表没有禁用概念）；表文件缺失回**空数组**而非报错 |
| `queue.list` | `queue_list_maps_only_the_two_real_states_and_derives_the_domain` | 本仓库队列只有 `active`/`deferred` 两态 → `sending`/`pending`；前端枚举里的 `delivered`/`failed`/`hold` **永不出现**，不为凑枚举造状态 |
| `services.list` | `services_list_maps_active_status_to_running_and_reuses_the_service_items` | 复用 `service_items()` 的判定，**不做第二次独立探测**（两个真相源迟早分叉，界面会出现「服务页说在跑、总览说已停」） |
| `dkim.keys` | `dkim_keys_lists_only_domains_with_a_private_key`、`dkim_keys_reports_unpublished_when_the_resolver_fails` | 只为**私钥确实存在**的域名产出条目；`keySize` 用编译期常量而不解析私钥；解析失败与未发布都表现为 `published:false`（列表不能因解析器抖动整体失败） |
| `dns.records` | `dns_records_covers_a_mx_spf_dmarc_and_dkim`、`dns_records_reports_absent_records_as_not_ok_instead_of_failing` | `value` 是**期望值**、`ok` 是**实际观测**；`ttl` 是向导建议值（`DnsQuery` 只返回记录文本，拿不到权威 TTL）；没有身份配置时**不编造** A/MX |
| `metrics.system` | `metrics_system_reports_cpu_memory_and_disk_percentages`、`metrics_system_reports_zero_when_proc_and_df_are_unavailable`、`read_cpu_counters_strips_the_core_index_before_splitting`、`cpu_busy_percent_is_the_non_idle_share_of_the_delta`、`parse_df_percent_skips_the_header_and_garbage` | CPU 两次差分采样（`idle = idle+iowait`，`total` 取前八项）；`df -kP /`（`-P` 防长设备名折行）；读不到回 0 |
| `activity.list` | `read_activity_skips_unparseable_lines_and_orders_newest_first`、`activity_list_on_a_missing_log_is_empty_not_error` | 审计日志尾部，**跳过无法解析的行**（日志可能被截断）；文件不存在回空数组 |

**RPC 桥与响应形状**

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| 桥只放行已有路由的动作 | `the_rpc_bridge_only_exposes_actions_that_already_have_a_route` | 断言 `admin.totp.verify` 与 `admin.totp.consume_recovery` 在助手白名单内**但**不在桥的允许集里 —— 它们是登录流程内部动作，不得从 HTTP 面可达 |
| 两种响应形状**必须相反** | `success_body_is_the_bare_object_without_an_ok_wrapper`、`rpc_bridge_shapes_are_the_opposite_of_the_rest_routes` | REST 成功回**裸对象**（前端对非列表动作直接读 `body.<field>`）；桥回 `{ok,data}`（前端 `bridge()` 按此拆包，`error` 是**字符串**） |
| 健康检查的成功标志 | `health_is_reachable_without_authentication` | `/api/health` 带 `ok: true` —— 前端 `probe()` 判 `body.ok === true`，判假会**静默**降级到内置 mock（界面看着完全正常，全是演示数据） |

**静态托管与 `mailstack-web` 服务入口**

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| `/api` 兜底**永远**是 JSON | `an_unknown_api_path_is_json_404_and_never_the_spa`、`api_paths_are_never_served_as_spa` | 回 `index.html` 会让前端把「接口不存在」报成「解析失败 / 服务端坏了」 |
| 路径穿越必须被拒 | `traversal_and_odd_segments_are_rejected` | `..` / 空段 / `.` / 反斜杠 / NUL 全部拒绝；另有真实路径前缀校验兜住符号链接 |
| 「没部署前端」是 503 | `a_missing_bundle_reports_503_instead_of_a_blank_page` | 不是空白 200，也不是 404 —— 反向代理与监控应当把它当服务不可用 |
| 深链接回落到入口 | `a_deep_link_falls_back_to_the_spa_entry` | 刷新任意深链接都回到 SPA 入口 |
| 内容类型不被猜 | `content_types_cover_the_bundle_and_default_to_octet_stream` | 未知扩展名回 `application/octet-stream`，**猜错等于把静态文件变成可执行内容** |
| 静态响应也带安全头 | `static_responses_still_carry_the_security_headers` | 这个进程返回的大多数响应都是静态文件，漏掉它们等于没加 |

**参数名兼容**（前端与基线的字段名不一致，认不出会**静默做错事**）：

| 关注点 | 关键测试 | 验证方式 |
|---|---|---|
| 队列动作认 `op` | `queue_action_accepts_the_frontend_field_names`、`queue_action_maps_deliver_to_retry_and_refuses_hold` | 少了 `op`，`op:"delete"` 会落到默认的 `retry` —— **删除队列邮件变成把邮件重新投递**，两边都不报错。`hold` 在本仓库没有对应状态，**显式报错**而不映射成「最接近」的动词 |
| 服务动作认 `key`/`op` | `services_action_accepts_the_frontend_field_names` | — |
| 用户动作认 `address`/`name`/`active` | `the_frontend_field_names_address_and_name_are_understood`、`add_accepts_the_frontend_address_field` | 认不出时回的是「不是受管用户」，**看起来像权限问题而不是参数问题**。`address` 取本地部分为用户名，依据是建号规则本身（`username = email.split('@')[0]`），不是猜测 |


## 4. 本阶段发现并修复的真实缺陷

### 4.1 透明代理 fake-IP 导致出站探测**假报端口开放**（已修复）

`198.18.0.0/15`（RFC 2544 基准测试段）被我的地址策略当作**可路由**地址接受。
本机 Clash 用 fake-IP 模式工作，恰好把**任意域名**（包括不存在的域名）解析成
`198.18.x.x`，且 TUN 设备会接受对该地址的 TCP 连接。

后果链：
1. 不存在的域名「解析成功」→ 得到一个 198.18.x.x
2. 对它的 TCP 连接「连接成功」（实为 TUN 接下的）
3. 出站端口探测**假报「端口开放」**

这直接违反 INV-19 的意图：用户会看到「出站 25 可用」，实际直投全部失败。

已把该段连同 `192.0.0.0/24`、`100.64.0.0/10`（CGNAT）、`240.0.0.0/4`（保留段）
一起归入不可路由（RFC 6890 本来就不含它们），并加测试固定该行为。

> 由 `probe::tests::probe_reports_all_targets_when_none_are_reachable` 抓出。

### 4.2 `pinned_from_addresses` 未校验 hostname（已修复）

空域名会让 TLS SNI 变成空串、证书校验失去依据。已补校验。
由 `target::tests::rejects_empty_hostname` 抓出。

### 4.3 契约文案首字母大小写（已修复）

`PrivateRelayDisabled` 的错误文案原为小写 `private SMTP relay access is disabled...`，
而规格书 §5.9.2 的原文是**大写开头**，属对外契约。已修正。

由 `validate::private_network_requires_deployment_opt_in` 抓出。

### 4.4 失败时丢失已完成阶段（设计期修正）

初版把失败路径写成 `return Err(SmtpError)`，会丢掉已完成的 stages ——
但分阶段测试的全部价值就是「失败时能看出卡在哪一步」。
改为返回 `RelayTestFailure { error, last_ok_stage, stages }`，成功/失败同形输出。

### 4.5 测试自身修正

`resolve_pinned_reports_dns_failure` 原断言「不存在的域名必报 Dns 错误」，
但在 fake-IP 环境下解析会成功。改为断言**不变量**（永不产出可用目标），
不再依赖运行环境的 DNS 行为。

回滚测试原用**持续性**注入故障，会导致回滚自身也失败，于是 `rolled_back` 为 `false`
而断言期望 `true`。核对后确认**代码是对的**：回滚没完成就该报 `false`（报 `true`
会让运维误以为配置已安全还原）。已把测试改为注入**瞬时**故障以验证「回滚成功」路径，
并新增 `persistent_storage_failure_reports_rollback_as_incomplete` 覆盖「回滚失败」
这一诚实上报路径。

### 4.6 说谎替身污染快照，测试「通过」却什么都没验证（已修正）

为验证「回读不一致必须回滚」，我写了一个在读路径上永远返回错值的替身。
结果是：**快照阶段读到的就是错值**，于是回滚忠实地把错值写了回去 ——
测试断言 `rolled_back: true` 反而通过了，但「还原到真值」这一核心性质完全没被验证。

已把替身改为**只在写入之后**才开始说谎，并补上「回滚后 relayhost 必须等于快照里的真值」
的断言。同样的问题也存在于原生载体的磁盘版测试里，一并修正。

> 这类缺陷比普通的断言写错更危险：它让测试看起来在保护一个不变量，实际没有。

### 4.7 回滚用「写空串」会静默弱化 Postfix 安全策略（已修复，实测确认）

用真实 Postfix 3.8.6 验证格式假设时，发现了一个**安全相关**的真实缺陷。

**根因**：`postconf -h <key>` 返回的是**有效值（含默认）**，而 `postconf -n <key>`
返回的是**仅显式设置的值**。我原先用 `-h` 读键，于是：

* 从未设置过的 `smtp_tls_wrappermode` 会被读成 `Some("no")`（其实是默认值）
* 快照因此把「未设置」记成「已设置」
* 回滚时对「原本不存在」的键**写空串**，而不是移除

**为什么这是安全问题**（容器内实测输出）：

```
移除后 effective=Some("noplaintext, noanonymous")   ← 默认保护恢复
设为空后 effective=None                              ← 默认保护被抹掉
```

即：回滚 `smtp_sasl_security_options` 时写空串，会让 Postfix 失去
`noplaintext` —— **回滚变成了一次静默的明文认证放行**。

**修复**：
1. `read_key` 改用 `postconf -n`（显式配置语义），并解析 `key = value` 格式
2. `RelayConfigStore` 新增 `remove_key()`；回滚对「原本不存在」的键走
   `postconf -X` 移除，**不再写空串**
3. 新增 `rollback_removes_keys_that_were_originally_absent` 作为安全回归测试，
   断言回滚路径**不出现任何 `key=` 形式的写入**

### 4.8 集成测试静默改动了宿主机配置（已修正）

第一版 Postfix 集成测试的守卫是「环境里有 Postfix 就跑」。本机 WSL 恰好装着
Postfix 3.8.6（早期 MailStack 安装留下的），于是 `cargo test` **在用户不知情的情况下
改写了真实的 `/etc/postfix/main.cf`**。

同时这些测试并行执行时会共用同一个 `main.cf` 互相覆盖，症状是 `read_key`
读回 `Some("")` 而非刚写入的值。

**修正**：
1. 改为**必须显式开启**（`MAILSTACK_POSTFIX_INTEGRATION=1`），否则跳过 ——
   会修改系统状态的测试不应默认执行
2. 加静态 `Mutex` 强制串行，不依赖调用方传 `--test-threads=1`
3. 提供 `deploy/clean-host-postfix-test-residue.sh` 清理残留，已执行：
   宿主机 `smtp_sasl_security_options` 已恢复为默认的 `noplaintext, noanonymous`，
   备份留在 `/etc/postfix/main.cf.before-mailstack-cleanup`

### 4.9 队列：一条「绿得没有意义」的分类测试（已修正）

为验证「4xx 重试 / 5xx 退信」的三分类，我写了一个按脚本应答的最小 SMTP 服务端，
脚本里多写了一行 `250 ok`（误以为客户端会先发 EHLO）。实际
`send_message_detailed` 只发 MAIL FROM / RCPT TO / DATA，于是**所有应答串位**：
断言里的「450 来自 RCPT 阶段」实际是 DATA 阶段返回的。

测试**仍然是绿的**（分类逻辑本身没错），但它验证的阶段与注释所述不符 —— 与 §4.6
属同一类问题：测试看起来在保护一个性质，实际保护的是另一个。已把脚本改为与真实
命令序列一一对应，并在辅助函数上写明「本条不发送 EHLO」。

### 4.10 队列：INV-21 的测试一开始**什么都没验证到**（已修正）

第一版 `bounces_use_the_same_outbound_route_as_user_mail` 用的信封发件人是
`sender@example.org`（本域）。于是 DSN 生成后寄回本域，按 `partition` 走的是
**LMTP 本地投递**，根本不会经过中继 —— 断言 `dsn_calls.len() == 1` 直接失败。

失败本身不是缺陷：**代码是对的**（本域发件人的退信就该本地投递）。但它揭示了
测试设计问题：想验证「退信与用户邮件走同一条**出站**路径」，就必须让退信真的是
出站投递。已把发件人改为外域地址，并**另加**一条互补测试
`a_bounce_addressed_to_a_local_sender_is_delivered_locally` 固定本域那一路的行为。

### 4.11 队列：部分成功会被当成整体失败而**重复投递**（已修复）

写 store 的 LMTP 客户端时暴露出队列侧的一个真实缺陷。LMTP 在 `DATA` 之后
**逐收件人**应答，所以「一个用户已落箱、另一个超配额」是完全正常的形态。但队列
的 `Transport::deliver` 只有「成功 / 失败」两态，且失败时 runner 会把**整批**
收件人都留在队列里重试 —— 那个已经投递成功的用户会**再收到一封一模一样的邮件**。

**修复**：`DeliveryFailure` 增加 `accepted: Vec<String>`，传输层如实带回本次已经
投出去的收件人；runner 在结算失败前先把它们摘掉，它们既不重试、也**不被退信**
（它们其实送到了）。

由 `recipients_accepted_by_a_partial_delivery_are_not_retried_or_bounced` 与
`a_fully_accepted_but_failed_batch_does_not_retry_anything` 固定。

### 4.12 store：LMTP 端到端测试的脚本错位（已修正）

`message_body_is_dot_stuffed_and_terminated` 的服务端脚本里写了一条 `250-caps`。
连字符不是装饰 —— 它是**多行应答的续行标记**，客户端会继续读下一行，于是整条
应答序列向后错位一位，最终死等超时。

这反过来证明了客户端的多行续行处理是对的（它确实读了第二行），错的是我的脚本。
已改为单行应答并就地写明「带连字符即续行」这一陷阱。

### 4.13 出站 DATA 终止符少了结尾的 CRLF，且每封外发邮件尾部多一个空行（已修复）

`crates/smtp/src/client.rs` 的 DATA 阶段写的是 `format!("{}\r\n.", dot_stuff(data))` ——
线上字节是 `…正文\r\n.`，**终止符缺了结尾的 CRLF**（RFC 5321 §4.5.2 要求 `CRLF.CRLF`）。
而对端的读法正是「一直读到一行的 CRLF 为止」，于是它永远等不到这一行结束：
双方都觉得自己没错，投递却**永久超时**。

同一行还有第二个问题：正文**已经**以 CRLF 结尾时（队列里的报文绝大多数如此），
它会在每封邮件尾部凭空多出一个空行 —— 那是对正文的改写，会让上游发件人的 DKIM
签名失效。

两者一直没被发现，是因为此前**没有任何测试让真实的服务端去读 DATA 正文**：
`client.rs` 的脚本化测试服务端只按顺序写应答、不解析正文，所以「少一个 CRLF」
与「多一个空行」都照样绿。本轮写直投的端到端测试（真实 TCP + 会读正文的假 MX）时
才暴露出来 —— 这正是「用真链路验证」与「用替身验证」的差别。

现在终止符统一由 `terminate_data()` 产出，并锁定三条断言：
`body` → `body\r\n.\r\n`、`body\r\n` → `body\r\n.\r\n`（**不多补空行**）、
`.\r\n` → `..\r\n.\r\n`。另附 `store` 侧的对照：LMTP 客户端从一开始就是
`format!("{}\r\n.\r\n", …)`，两条路径的形态原本就不一致。

> 由 `direct_delivery_follows_the_mx_and_never_sends_credentials` 抓出
> （回归守卫：`data_is_terminated_with_crlf_dot_crlf_and_the_body_is_never_rewritten`）。

### 4.14 三个 DMARC 安全测试一直**依赖真实 DNS**（已修复）

`crates/auth` 与 `crates/smtpd` 的一组 DMARC 测试本意是「完全离线」：把 SPF 与
`_dmarc.<域>` 记录注入 `TxtCache` 即可。这个前提在 mail-auth 0.13 起**不再成立** ——
它按 RFC 9989 §4.10 做 **DNS 树走查**，从 RFC5322.From 域**逐级向上查到顶级域**，
每级都查一次 `_dmarc.<name>`。

于是 `example.com` 的判定实际发两次查询：`_dmarc.example.com`（缓存命中）与
`_dmarc.com`（**缓存未命中 → 真实 DNS**）。本机 Clash fake-IP 环境下这一次查询
时快时慢，快时测试绿、慢时整条判定退化成 `dmarc=temperror`，三个测试一起变红。

**为什么这不是「环境问题」而是缺陷**：安全断言的结果不该随外部 DNS 的可用性漂移。
一个「有时会红」的验签测试，最终会被人加 `#[ignore]` 跳过 —— 那时它保护的性质就
彻底没有了。

**修复**：`TxtCache::pin_dmarc_walk(from_domain)` 把**每一级祖先**都钉成
`Txt::Error(Error::Dns(DnsError::InvalidRecordType))` —— 树走查的匹配臂恰好把
`DnsError::InvalidRecordType` 当作「本级无记录」并继续走查，于是判定留在缓存内结束、
一个包都不发。

这里有一个很容易踩错、也已写进断言的细节：**不能**用「一条别的类型的真记录」
（例如 SPF 记录）去顶替。`unwrap_txt` 对类型不符返回的是 `Error::Io("Invalid record
type")`，那**不是** `DnsError`，树走查不认它，整条判定会从 `temperror` 变成
`permerror` —— 换了个错的结论，测试依然红。

> 修复后 `cargo test -p mailstack-auth --lib` 的耗时从 15–38s 降到 5.6s，因为
> 那 2–3 次 DNS 往返消失了。这也反过来证明此前确实在发外网查询。
> 由 `pinning_the_dmarc_walk_blocks_every_ancestor_level` 与
> `pinning_never_overwrites_an_explicit_record` 固定。

### 4.15 SPF 的 HELO 身份漏网 —— 入队集成测试随机红的真正根因（已修复）

承接 §4.14：`_dmarc` 那一侧钉住之后，**还有一条查询路径没被钉住**，它才是
`a_verified_message_enters_the_queue_end_to_end` 随机 5 秒超时的根因。

定位过程（先排除猜测，再看证据）：给 `dmarc::evaluate` 的三个阶段各加一处计时，
得到 `spf=1.13s`、`dkim=2.6µs`、`dmarc=20.7µs` —— 卡的是 **SPF**，且确系真实网络。

机制：`SpfParameters::verify` 是 RFC 7208 §2.4 的「**EHLO + MAIL FROM 双身份**」语义，
mail-auth 的 `Sender::Full` 分支**先查 HELO 域**，只有当 HELO 判定为 `Fail` 才不去看
MAIL FROM。于是只把 MAIL FROM 域的 SPF 记录注入缓存是不够的：HELO 域（测试里是
`client.test` / `mail.example.com` 这类不存在的名字）那一次查询仍会落到真实 DNS。

**修复**：把「钉住某个名字」抽成通用能力 `TxtCache::pin_absent(name)`
（§4.14 的 `pin_dmarc_walk` 改为复用它），并在所有涉 SPF 的夹具里额外钉住 HELO 域。
它同样用 `Txt::Error(DnsError::InvalidRecordType)`，SPF 与 DMARC 都把它折算成
「此处无记录」，因此判定在缓存内结束。

> 修复后入站集成测试从 5.08s（超时）降到 0.35s，整套 `inbound.rs` 0.36s 跑完。
> 由 `pinning_a_name_absent_terminates_spf_and_dmarc_lookups_in_cache` 固定，
> 并已登记进 `ci.yml` 的 `required`。
>
> **教训**：同一个「让安全测试离线可跑」的目标有**多条查询路径**，补一条不等于补完。
> 定位时不要停在「像是环境问题」，要给每个阶段打点，让数据指出是哪一步在联网。

### 4.16 控制台写面：`services.action` 与 `queue.action`（Phase 4）

这两条路由在契约表里早就有位置，此前落到 `NOT_IMPLEMENTED`。补齐时的三条要点：

**响应就是列表本身，不是一个确认对象。** 控制台把这两条路由的响应**直接当成新的
状态**（`setServices(data)` / `setQueues(data)`）。因此返回 `{ok:true}` 会让界面在
按下按钮后变成一片空白 —— 形状在这里是契约的一部分，不是风格问题。同理，
`snapshot` 现在同时带 `queue`（积压摘要，给仪表盘）与 `queues`（明细，给队列页）。

**`services.action` 的两条判定。**
1. 动词必须已知：`ServiceVerb::parse` 对未知动词返回 `None`，处理器据此报错。
   基线的 `service_ctl` 收到未知动词会一路落到最后的 `true`（成功但什么都没做），
   那正是「点了重启、其实没重启」的来源。
2. **不许停掉控制台自己**：请求正是经 `mailstack-web` 的 sudo 包装器下发的，
   停掉它之后没有任何途径再把它拉起来，只能上控制台。重启是允许的
   （systemd 会拉回，不构成自锁）。命令返回非零时**如实报错**，不回一份
   「看起来重启成功」的列表。

**`queue.action` 的三处刻意差异。**
1. id 同时是文件名，因此先过 `is_safe_id`，把路径穿越挡在拼路径**之前**
   （基线直接把它交给 `postqueue -i` / `postsuper -d`）。
2. `retry` **重置重试预算**。只把 `next_attempt_unix` 提前而不清 `attempts`，
   对一条已耗尽预算的条目来说下一次投递会立刻退信 —— 那等于「点了重试，邮件反而
   被删掉」。运维显式重试是一次人工决定，应当重新给它一轮预算。
3. `flush` 只提前「尚未到期」的条目，已到期的条目不动（不做无谓写盘）。

> 安全落点：`services_action_refuses_to_stop_the_console_from_itself`、
> `queue_action_rejects_traversing_ids_and_unknown_verbs`，均已登记进 `ci.yml`。
> 契约形状由 `snapshot_exposes_the_queue_items_the_console_renders` 与
> `services_action_runs_the_verb_and_returns_the_service_list` 固定。

## 5. 尚未验证的事项（诚实披露）

- **【已修复，见 §4.15】`crates/smtpd/tests/inbound.rs::a_verified_message_enters_the_queue_end_to_end`
  曾随机 5 秒读超时**。当时记录的症状与已排除项：真实 TCP 拿到 `220` 与 `250`(EHLO)
  后在下一条应答上超时（事后精确定位为 **DATA 结束那条应答**，因为 `sink.accept` 只在
  那里被调用，先前记成 `MAIL FROM` 是不准确的）；单独跑也复现；同文件的
  `a_full_transaction_over_real_tcp_reaches_the_sink`（`RecordingSink`）通过。
  **根因**是入站 SPF 的 HELO 身份查询漏到真实 DNS（§4.15），已用
  `TxtCache::pin_absent` 钉住，现为确定性通过。

- `mailstackd` / `mailstackctl` 二进制已加入 workspace 并有测试（28 / 7 条，见 §3.1.5、§3.1.6）；
  `deploy/build.sh` 已能产出二进制。
- **Postfix 载体已对真实 Postfix 验证**（6 个集成测试，Postfix 3.8.6，一次性容器）：
  覆盖 `-n`/`-X` 语义、`postmap` 生成 hash 表、`postfix check`/`reload`、
  以及「移除 vs 设为空」对默认安全项的差异。
  该组测试**必须显式开启**（会修改系统配置），CI 中作为独立 job 用容器运行。
- 契约表 72 条路由**已全部注册进 Axum router**（`crates/web/src/lib.rs` 的
  `build_api_router`；`build_router` 再补上 `/api` 兜底与安全响应头）。
  **没有任何契约路由再落到 `/api` 兜底返回 `API_NOT_FOUND`**。（动作 58 条：`snapshot`、
  `system.doctor`、`ai.chat`、`ai.diagnose`、`ai.parse` 各有两条契约路由指向同一动作；
  另有 9 条进程内路由与 1 条 RPC 桥，`action` 为 `None`。）
- **进程内遥测已接线**：`GET /api/metrics/telemetry` 由 Web 进程自己采样
  （`crates/web/src/telemetry.rs`，见 §3.6）。**后台采样任务现在有宿主了** ——
  `bin/mailstack-web` 在启动时调用 `TelemetryCollector::start_sampling(2s)`（见 §3.10）。
- 58 条白名单动作**已全部实现（58/58）**：
  - RO（**22/22**）：`snapshot` / `system.doctor` / `setup.status` / `logs.list` /
    `metrics.realtime` / `domains.list` / `certs.list` / `settings.get` /
    `admin.get` / `ai.config.get` / `ai.models.list` / `network.check_port` /
    `security.scan` / `backup.list`，以及**为管理前端新增的 8 条**
    `users.list` / `aliases.list` / `queue.list` / `services.list` / `dkim.keys` /
    `dns.records` / `metrics.system` / `activity.list`（见 §3.10；由
    `every_added_list_action_is_pure_read` 逐个确认无副作用）
  - RW（**36/36**）：`admin.set` / `settings.set` / `domains.add` / `domains.delete` /
    `users.add` / `users.status` / `users.password` / `users.delete` /
    `aliases.add` / `aliases.delete` / `dkim.rotate` / `admin.totp.*`（5 条）/
    `services.action` / `queue.action` / `security.ban` / `security.unban` /
    `backup.create` / `backup.restore` / `backup.delete` /
    `setup.identity.apply` / `setup.dns.verify` / `setup.relay.test` / `setup.relay.apply` /
    `setup.cert.issue` / `setup.mail.test` / `mail.test_loopback` / `certs.renew` /
    `ai.config.set` / `ai.test` / `ai.chat` / `ai.diagnose` / `ai.parse`
  - 注意「已实现动作数」**不等于**「已注册路由数」：`admin.totp.consume_recovery` /
    `admin.totp.verify` 按设计**没有 HTTP 路由**（登录路径在进程内直呼助手）。
  **白名单与实现现已一一对应**：助手侧不会再有任何动作返回 `NOT_IMPLEMENTED`。
  路由侧的守卫是 `every_implemented_action_route_is_wired_and_behind_auth` ——
  它以防「已实现却点不到」与「动作路由被挂到免认证面」两类回归，且仍会在将来
  新增白名单动作时自动要求「实现即接线」。

### 4.17 手工封禁：文件持久化 + 守护进程热重载（Phase 4）

自动封禁（失败计数触发的临时 / 永久封禁）活在 `mailstackd` 的内存表里，重启即清空 ——
这可以接受，因为它由对端行为自动重建。**运维手工封禁不是这一类**：它是人的一次决定，
若只存在内存里，一次 `systemctl restart` 就会把它悄悄撤掉，而运维看不到任何迹象。
那正是「看起来还封着、其实已经放行」。

因此手工封禁落在 `/var/lib/mailstack/manual-bans.json`（`0600 root:root`），
并且**该文件是唯一真相源**：

```
管理台 ── security.ban/unban ──▶ 文件（原子写）
                                   │
                     mailstackd 每 5s 对齐 ──▶ 内存 BanList（只动手工封禁）
```

两个角色都不再额外维护一份权威副本。代价是生效有一个周期（≤5s）的延迟，换来的是
「重启不丢」与「只有一处需要保持一致」；`security.ban` 的响应里用
`takesEffectAfterReload: true` 把这件事明确告诉调用方，免得运维看到「封禁成功」
就去质问为什么对方还能连。

**四条刻意的判定**（每一条都对应一种「看起来正常、实际危险」的失败）：

1. **读失败一律保持现状。** `Err` 绝不当成空集合 —— 空集合的含义是「没有任何手工
   封禁」，于是会把在册的手工封禁全部解除。一次文件损坏就等于静默放行。
2. **损坏的文件拒绝写入。** `security.ban` 不会拿一个新文件覆盖运维可能还想抢救的
   旧内容。测试断言拒绝之后文件内容逐字未变。
3. **热重载绝不动自动封禁。** 只有 `manual == true` 的条目可能被本次对齐删除；
   否则一次重载就把正在攻击的地址全部放行，而且不留痕迹。
4. **只列手工封禁，并标注范围。** `security.scan` 给出 `bannedIps` 的同时给出
   `bannedIpScope: "manual"`。只报手工封禁而不加标注，会让运维以为「一共就封了这几条」，
   那比不报还糟。文件读不到时 `bannedIps` 是 `null` 而不是 `[]`。

另有两条与安全直接相关：手工封禁是**永久**的、且不受失败计数影响
（`failure_counting_cannot_escalate_or_weaken_a_manual_ban`）；它也不会被内存上限淘汰
（淘汰它同样是悄悄解封）。封禁文件的权限被纳入 `security.scan` 的体检清单 ——
能写它的人就能放行已被封禁的主机。

> 安全落点（均已登记进 `ci.yml`）：`reloading_the_file_never_lifts_automatic_bans`、
> `a_corrupt_file_leaves_the_current_bans_untouched`、
> `a_corrupt_file_is_never_treated_as_empty_and_is_never_overwritten`、
> `security_scan_flags_a_world_readable_ban_file`、
> `security_ban_rejects_anything_that_is_not_an_address`。

**兼容性说明**：控制台会一并回传 fail2ban 时代的 `jail` 字段，该字段**接受但忽略** ——
Rust 这套栈没有 jail 概念，封禁作用在全局，响应用 `scope: "global"` 说明这一点。

### 4.18 备份与恢复：把归档当成不可信输入（Phase 4）

`backup.create` / `backup.restore` / `backup.delete` 落地在 `crates/core/src/backup.rs`。
恢复的实质是「把外部文件往系统目录里写」，所以归档是不可信输入，攻击面有三个：

1. **路径穿越** —— 成员名里的 `..`、绝对路径、空分量。
2. **链接攻击** —— 归档先放一个指向 `/etc/shadow` 的符号链接，后续成员顺着它写。
3. **元数据攻击** —— 设备节点、FIFO、setuid 位。

**为什么在进程内读写 tar 而不是 shell 出 `tar -czf`**：上面第 3 条要求逐个读出成员的
**元数据**。解析 `tar -tvzf` 的人类可读输出做这件事，等于把一条安全边界建在文本格式上
—— 文件名里一个换行就能让解析结果与实际内容不一致。用 `tar` crate 直接读头部，
判断的是归档里真实的字节。

**恢复分两个阶段且不可合并**：先在临时目录里完整解出并逐成员校验（此时还没碰任何
系统路径），全部通过后才开始往目标复制，且每个目标用 `O_NOFOLLOW` 打开、逐级父目录
拒绝符号链接。少了第一阶段，一次「写到一半才发现第 3 个成员是符号链接」的恢复会留下
半个现场；少了 `O_NOFOLLOW`，校验与落地之间的时间差就足够把目标换掉。

**fail-closed 的几处**：

* 公网模式下**没有口令就拒绝创建**（明文归档是医生检查的 FAIL 项），而不是「这次先明文」；
* 加密失败时**连明文一起删**；
* 打包失败时删掉半成品 —— 一个读得到但打不开的 `.tar.gz` 比没有备份更危险；
* 恢复前**必须先过 SHA256 校验**（校验和不符时断言目标目录里一个文件都没落地）；
* 未标加密而 gzip 头不对 = **损坏**，不是「需要口令」—— 把它当成加密会让运维拿着
  口令去解一个只是丢了头部的文件；
* `home/<user>/...` 成员在用户模型（`users.*`）落地前**一律拒绝**：无法证明某个家目录
  归 MailStack 管，就不往里写。

**回滚点**：恢复前会打一个 `-pre-restore` 快照，且快照必须**能被解析回一个合法归档**
才登记。快照失败不中断恢复（配置已经换好了），但会在响应里如实给出
`preRestoreSnapshotWarning` ——「这次恢复没有回头路」必须让运维看见。

**恢复之后**：`postfix` / `dovecot` reload、`opendkim` restart（`service_ctl` 在没装的
主机上降级为 Noop）。`mailstackd` 自身需要重启：它在启动期装配配置，没有热重载。

> 安全落点（均已登记进 `ci.yml`）：`archive_members_outside_the_allowlist_are_rejected`、
> `resolve_refuses_names_that_escape_the_backup_directory`、
> `a_symbolic_link_inside_the_archive_is_refused`、
> `a_character_device_inside_the_archive_is_refused`、
> `a_member_with_a_setuid_bit_is_refused`、
> `home_members_are_rejected_until_a_user_model_exists`、
> `a_tampered_archive_fails_the_checksum_before_anything_lands`、
> `backup_restore_requires_explicit_confirmation_and_a_known_filename`、
> `backup_create_excludes_secrets_unless_explicitly_asked`。

**契约变更**：`backup.list` 现在返回**元数据数组本身**（基线形状），每条带
`filename` / `size` / `createdAt` / `sha256` / `encrypted` / `metadataMissing`，
另加一个 `empty`（0 字节归档必须看得见）。此前那个 `{ok, available, entries}` 形状
缺少 `encrypted`，恢复页无法判断要不要口令框。

**新增依赖**：`tar` 0.4（`default-features = false`）与 `flate2`（仅 `rust_backend`），
两者都是纯 Rust，不引入 C 依赖（§3.4）。

### 4.19 初始化向导（`setup.*`，Phase 4）

四个动作（`setup.identity.apply` / `setup.dns.verify` / `setup.relay.test` /
`setup.relay.apply`）是管理台初始化向导的后端。它们触及的是**最难手工回退的阶段**：
身份、DNS 发布、中继凭证。因此这一节记录的不是实现，而是**每一处「看起来成功」其实
没成功**的可能。

**1. `setup.identity.apply`：校验先于一切副作用。**
基线在这里跑 `postconf -e`、`opendkim-genkey`、写 OpenDKIM 的
`key.table`/`signing.table`/`trusted.hosts` 并重载两个服务；本栈已按规格书 §3.3 移除
Postfix/OpenDKIM，密钥改由 `mailstack_auth::keys::rotate` **原生生成**，签名在出站
路径完成。保留的是那条纪律：域名 / 主机 / IP / selector 全部验完才动磁盘，被拒的
请求**不留下** `setup.json`，也不留下半个密钥目录（`opendkim-genkey` 会先 `mkdir`
再生成，这里刻意不是那个顺序）。

`SetupConfig` 的形状就是 `snapshot` 读到的那一份（与前端共用的冻结契约）。基线额外
写了 `postmaster` 字段，本栈的 schema 里没有它 —— 已登记为偏离：它既不影响签名，
也不被守护进程读取。

返回的 `dkimPublicKey` 必须是**可发布的那个 `p=`**（SPKI base64），且有测试锁定它
与落盘 `.txt` 里 `p=` 逐字相同 —— 否则向导会把一份对不上号的公钥展示给运维。

**2. `setup.dns.verify`：「DNS 里没有」与「查询故障」不得互相冒充。**
六个判据（A / MX / 单条 SPF / 期望 SPF / DKIM / DMARC）与基线 `network.py:163`
一一对应；`observed` 把每条查询的应答**原样摊开**，因为只回一个 `verified: false`
会让运维完全无从下手。两处 fail-closed：

* 解析故障（超时 / SERVFAIL）**上抛为错误**，不折算成「记录没发布」——后者会让人
  去改一条本来正确的记录；
* 恰好一条 `v=spf1`：两条 SPF 会被收信方按 RFC 7208 直接判 permerror，向导必须挡。

DKIM 判据等价于基线正则 `p=[A-Za-z0-9+/]{100,}={0,2}`：去掉尾部 `=` 填充后不少于
100 字节。**这是一条回归守卫** —— `network.py:115` 记录过一次公钥被截断、
本地自检照样绿、对端验签失败的事故；截断的公钥在向导里必须显示为「未正确发布」。

TXT 的分片在 `crates/smtp/src/dns_query.rs` 里**拼接**后再返回：`dig +short TXT`
会把同一条记录的分片印成同一行里的多个带引号串，只取第一段会截断长 SPF/DKIM
记录（与上面同一起事故同源）。

**3. `setup.relay.test` / `setup.relay.apply`：两种「失败」必须分开。**
`setup.relay.test` 把结果分成两类：

* **请求写错了**（主机名非法、端口不在白名单、TLS 缺失、凭证只给一半）→ **错误**。
* **对端不通**（解析不了、连不上、握手失败、认证被拒）→
  `{connected: false, stage: "failed", stages: [...]}`，**保留已完成的阶段**。

基线的第二种情况抛异常，界面只能看到一句「SMTP relay test failed」——那正好把
§5.9.4 要求的分阶段可观测性丢掉了。**这是与基线的登记偏离**：向导页需要「卡在哪一步」
才能给出可操作的建议。

`setup.relay.apply` 的载体是 `/etc/mailstack/relay.json`（`mailstackd` 的
`config::load_relay` 读的就是它），因此是「校验 → 测试 → 原子写该文件」，
**没有** `postconf` / `postmap`。「测试不过一行配置都不写」「写完回读校验」「失败回滚」
三条顺序由 `mailstack_smtp::apply_relay` 保证，动作层不重写一遍（避免第二个真相源）。
测试失败时返回 `{applied: false, test: {...}}` 而不是 500 —— 那是结论，不是服务器故障。

**4. 网络后端必须可注入。**
`Readers` 新增两个可注入字段：`dns`（`DnsQuery`）与 `relay`（`RelayProbe`）。
生产分别是系统解析器与真实拨号探针；`Readers::with_parts`（测试构造）**刻意不默认成
生产实现** —— 测试若忘了注入，会看到一个明确的失败，而不是在 CI 里悄悄去打真实
DNS/SMTP。这条与 `probe_targets`、`backup_env` 是同一条理由。

`direct: true` 走本机提交端点探测：目标**硬编码**为 `LOCAL_SUBMISSION_ENDPOINT`
（不是请求体里的主机），因此不适用 SSRF 防护，`.expect`-free 的注释写明了这一点。
它只证明「本地 MTA 活着」，**不证明出站 25 可用**（INV-19）。

**5. 与部署策略共用同一判据。**
`relay_private_network_enabled()` = `!mode::is_public_mode(paths)`，与
`bin/mailstackd/src/config.rs` 的装配**同一处判定**。两者若各写一份，迟早出现
「向导测得过、守护进程连不上」。

**6. 新增依赖**：无。DNS 查询复用 `mailstack-smtp` 已依赖的 `hickory-resolver`
（新模块 `dns_query.rs`，不新增 crate）。`setup.cert.issue`（ACME）与
`setup.mail.test` / `mail.test_loopback` **尚未实现**，前者需要新增 ACME 依赖，
后两者涉及本机提交路径，均待裁决（见 §5）。

> 安全落点（已登记进 `ci.yml`）：
> `setup_identity_apply_rejects_bad_input_without_any_side_effect`、
> `setup_identity_apply_writes_setup_json_and_returns_the_publishable_key`、
> `setup_relay_apply_leaves_the_config_untouched_when_the_test_fails`、
> `setup_relay_apply_never_overwrites_the_previous_config_when_the_test_fails`、
> `setup_relay_test_rejects_malformed_requests_before_any_probe`、
> `setup_relay_test_refuses_a_private_relay_when_the_deployment_disallows_it`、
> `setup_dns_verify_reports_missing_records_as_unverified_not_as_an_error`、
> `setup_dns_verify_surfaces_a_resolver_failure_instead_of_calling_it_unpublished`、
> `setup_dns_verify_rejects_a_second_spf_record`、
> `a_truncated_dkim_key_is_not_accepted_as_published`。

### 4.20 邮件环路自检（`setup.mail.test` / `mail.test_loopback`，Phase 4）

两个动作成对：`setup.mail.test` 回答「本机能收下我提交的信吗」，`mail.test_loopback` 回答
「这封信能不能被找回来」。基线的实现是「交给本机 `sendmail`，再去 Maildir 里搜 token」。

**载体差异（登记）**：本栈没有 Postfix/`sendmail`，自然等价物是**向硬编码的
`LOCAL_SUBMISSION_ENDPOINT`（`127.0.0.1:25`）做一次真正的 SMTP 提交** —— 那正是
`mailstackd` 自己的入站面。于是这条环路覆盖的是「提交 → 入站策略 → 入队」，
而不是绕开它。目标必须是常量：若允许请求体给主机，这个动作就变成一个**任意主机的
SMTP 提交器**（SSRF 加发信能力外泄）。

**反中继守卫（P0 回归）**：基线 CHANGELOG 记录过一次真实缺口 —— 旧写法是
`if managed and ...`，全新安装上还没有任何邮箱时 `managed` 为空，守卫被**整个跳过**，
这个动作于是可以对任意互联网地址投信。修好后的判据是「至少有一个受管域，且收件域是
`localhost` 或受管域之一」，与「有没有邮箱」无关。本实现照该判据，并且有两条测试钉住
（空域名表直接拒绝；外域收件人在**提交之前**就被拒）。

**为什么不需要在这里再做一次反中继判断**：入站策略（INV-17）已经让未认证会话无法投给
外域 —— 提交给 `127.0.0.1:25` 的外域收件人会被我们自己的 MTA 以 554 拒收。写两遍
迟早出现「这里放行、那边拒收」的分歧，所以只依赖一处。

**明文提交、不做 STARTTLS**：向导阶段的证书可能还没签发（基线的 direct 探测出于同一
理由也不升级），而明文只发生在环回上。

**正文必须是 CRLF**：`terminate_data` 只做 dot-stuffing 与补终止符，**不做**
`LF → CRLF` 转换；用裸 LF 组装正文会被入站的走私防护直接拒收（那正是它该做的）。

**`maildirDelivered` 是证据，不是成败**：提交被 `250` 接受就说明环路通了。Maildir 只是
额外证据。**权威布局现已定死**（§3.7：系统账号 + `~/Maildir`），但扫描仍并列探测三处候选
（系统用户的 `~/Maildir`、`<vmail>/<domain>/<user>`、`<vmail>/<domain>/<user>/Maildir`）——
后两处是**历史候选**，留给仍按旧布局部署的主机。找不到时返回 `false` 而不是错误
—— 把它渲染成「投递失败」会让人去查一个根本不存在的故障。扫描是**只读**的，
读不到的文件按「没匹配」处理（Maildir 内容本来就在 churn）。

**基线的两条检查已恢复执行。** `setup.mail.test` 要求「sender 对应一个受管邮箱」且
「账号未锁定」；`username`/`password` 只服务于这两条检查 —— 口令**不参与认证**，且只做
**格式**校验（`validate_legacy_password_input`）而不是新口令策略：它是既有口令的**回放**，
按新策略卡会让旧策略下建的邮箱永远跑不了连通性测试。

`users.*` 落地后（见 §3.7），这两条检查与 `username`/`password` 的校验都已按基线恢复，
响应里不再有 `mailboxChecksSkipped`：**四条校验全部先于发信**。
`setup_mail_test_submits_with_crlf_and_enforces_the_mailbox_checks` 与三条拒绝用例
（不匹配的受管邮箱 / 已锁定 / 非法用户名）把这一点钉住，每条都断言提交器**一次都没被调用**。

**已知未验证项**：真实 `mailstackd` 上的完整环路（提交 → 入站认证 → 入队 → LMTP →
Dovecot 写 Maildir → 扫描命中）**未在 CI 中跑过** —— 需要一套完整部署，见 §5。
本轮的测试用注入的提交器与临时 Maildir 覆盖了编排、守卫与结果形状。

> 安全落点（已登记进 `ci.yml`）：
> `the_submission_endpoint_is_the_hardcoded_loopback_constant`、
> `mail_test_loopback_requires_a_managed_domain`、
> `mail_test_loopback_refuses_a_foreign_recipient`、
> `mail_test_loopback_never_reports_success_when_the_submission_fails`、
> `setup_mail_test_never_reports_queued_when_the_mta_rejects_it`、
> `setup_mail_test_rejects_malformed_addresses_before_submitting`、
> `setup_mail_test_submits_with_crlf_and_says_what_it_could_not_check`、
> `a_missing_maildir_is_not_found_rather_than_an_error`、
> `mail_test_loopback_reports_a_missing_maildir_as_absent_evidence_not_failure`。

**新增依赖**：`rand`（工作区已在用的同一版本，`mailstack-core` 的口令盐也用它）——
不是新的外部 crate，只是启用了一条依赖边。

### 5.0 2FA（Phase 4）的实现取舍与未验证项（新增小节，编号避开下文既有的 5.1/5.2）

规格书把 2FA 表述在 §5.5，但**没有落地为磁盘格式**；本仓库先从零定了一套，
以下三点需要明确登记：

- **`totp.key` 的磁盘格式是本仓库的选择**：base64 编码的 32 字节随机量 + 换行，
  `0600 root:root`。开发机上既没有既存 `totp.key` 也没有既存 `totp` 块
  （已实测：`/etc/mailstack/admin.json` 只有 `username/algorithm/iterations/salt/hash`），
  因此不存在需要兼容的历史格式。若裁决要求与某个具体格式对齐，改动集中在
  `load_master_key` / `load_or_create_master_key` 两个函数。
- **没有实现动态码的重放保护**（RFC 6238 §5.2 的可选项：记住上一个用过的步长）。
  规格书的 43 条不变量里没有对应条目，且它会引入「成功校验也要写盘」的新状态，
  故**没有顺手加上**。风险是：一个被肩窥或截获的动态码在 30–90 秒窗口内可被重放一次。
  登录侧的失败限流与账号锁定（INV-23 那一组）是当前的缓解手段。
- **未对真实验证器 App 做过互操作验证**：动态码的正确性由 RFC 4226 的十条标准向量
  逐条比对（`hotp_matches_the_rfc4226_vectors`），`otpauth://` URI 的字段（SHA1 /
  6 位 / 30 秒 / 无填充 base32）也逐项断言，但**没有**用 Google Authenticator 之类
  的真实客户端扫码验证过。
- **恢复码的张数与长度是本仓库的选择**（8 张 × 10 字符、32 符号去混淆字母表）：
  约 50 位熵，且登录侧另有失败限流。规格书未给出数值。

- **入站 SMTP 服务端：协议核心 + 安全通信层 + 提交认证已完成**（`crates/smtpd`，见
  §3.1.3、§3.1.4、§3.1.7）。已就绪：命令解析、DATA 字节流、会话状态机、反中继、
  会话驱动、TCP 监听与连接上限、**TLS 1.2 起**（STARTTLS / 隐式 465）、**连接限速**、
  **IP 自动封禁**、**提交端口 SASL（RFC 4954 + Dovecot auth socket）**、
  **SPF/DKIM/DMARC 认证与入队**（含真实 TCP/TLS/auth-socket 端到端测试）。
  **下面这些仍未完成**（含「已实现但未接线」两类）：
  - **Dovecot auth socket 未对真实 Dovecot 跑过**：客户端按协议 v1.2 实现，测试用的是
    一个假 Dovecot（逐字断言双方字节），但**没有**在真实 Dovecot 上验证过
    `auth-client` 的路径/权限/字段差异；路径默认 `/run/dovecot/auth-client`，可用
    `MAILSTACK_DOVECOT_AUTH_SOCKET` 覆盖
  - **非 UTF-8 报文**：当前策略是**明确拒绝（554）**，不做有损转换。队列把报文建模为
    `String`；若将来要支持 8BITMIME 的任意字节，必须先改队列的数据模型 —— 在模型改好
    之前「接受并转换」会静默篡改字节，并让下游的 DKIM 校验失败
  - **入站认证未对真实 DNS 跑过**：SPF/DKIM/DMARC 的单元与端到端测试全部使用**注入的
    TXT 缓存**。fake-IP 环境会让「不存在的域名也解析成功」（§4.1），依赖真实 DNS 的
    断言会随环境漂移
  - **ARC 封印已实现，但管线里还没有消费者**：`crates/auth` 的 `arc::seal_with`
    能独立完成「校验现有链 → 产出 ARC 三件套 + `Authentication-Results` → 原报文
    逐字保留」，并有自封自验 / 续封 / 篡改反例三组测试（见 §3.1.1）。但本机目前
    **没有转发到外域的路径**（入站投本地 LMTP，或认证用户提交外发 —— 两种情形下
    本机都不是「中转 MTA」，按 RFC 8617 §5 不该盖章）。等别名/转发落地时在那一跳
    调用即可；提前接线只会盖出语义错误的集合
  - **PIPELINING 未通告**：驱动实际能处理流水线（有测试），但在真实客户端上验证
    之前不写进 EHLO 能力列表 —— 通告了做不到比不通告更糟
  - **进程入口已有，但未在真实主机上以生产端口跑过**：`bin/mailstackd` 能装配并运行
    （配置装载、证书路径、优雅停机、出站调度都接了，见 §3.1.5 与冒烟结果），受测路径是
    非特权端口 2525。**25/465/587 需要 root 或 `CAP_NET_BIND_SERVICE`，且会与现有
    Postfix 冲突**，因此真正的端口接管（Phase 5）尚未验证
- **`crates/auth` 的服务端收信校验已接线，但仍有未验证项**（诚实披露）：
  - 收信侧（`spf::check` / `dmarc::evaluate` / `arc::verify`）已由
    `crates/smtpd` 的 `QueueSink` 装配进真实会话并有端到端测试，但仍是**注入缓存**，
    未对真实 DNS 跑过
  - **DKIM 签名已接进队列出站路径**（`crates/queue/src/signing.rs`，见 §3.1.2），但：
    - 签名的**对端接受度未验证**：只有本机「自签自验」（同一密钥对 + 注入 TXT 缓存），
      **没有**向真实收件方（Gmail 等）发信确认过签名被接受
    - 签名发生在**每一次投递尝试**时，而不是入队时：好处是密钥轮换立刻生效、
      不必重写队列里的历史条目；代价是每次重试都会重签一次（RSA-2048 签名约 1ms，
      相对一次网络投递可忽略）
    - 整条链路已在 `bin/mailstackd` 里装配（出站调度每 10s 调一次 `run_once`，远端传输由
      `QueueRunner::new` 无条件套上签名），但**未对真实收件方投递过** —— 见上一条
  - **ARC 封印未实现**：入站侧现已能产出 `Authentication-Results`（`crates/smtpd` 的
    `sink`/`auth_results`），因此封印不再是「无消费者」的接口；但它还要求把校验结论与
    本机身份写成 `ARC-Seal`/`ARC-Message-Signature` 并**自身再验一遍**，本轮未做，
    故只实现**校验**这一半（详见 `crates/auth` 模块文档）
  - **`dkim.rotate` 尚未接到管理 API / 特权动作**：`certs.py:173` 的原动作名是 `dkim.rotate`，
    Rust 侧已按同名同语义实现（见 `keys::rotate`），接线在 `crates/web` 的路由补齐阶段
  - **`s=` / `d=` 与既有 DNS 记录的互操作**：未对已发布的真实 DKIM 记录验证过
- **队列的两条投递路径**（`crates/queue` 的机制层已完成并有测试）：
  - **本地投递（Dovecot LMTP）已实现并有真实 unix socket 端到端测试**
    （`crates/store` 的 `LmtpTransport`）。但**尚未对真实 Dovecot 验证过** ——
    端点默认为 `/run/dovecot/lmtp`，可用 `MAILSTACK_LMTP_SOCKET` /
    `MAILSTACK_LMTP_ADDR` 覆盖；部署脚本还需按 §3.5 创建该 socket
  - **直投（MX）已实现，但未对真实 MX 跑过**：MX 解析（RFC 5321 §5.1、RFC 7505
    null MX）、按优先级依次尝试、逐域分组都已落地并有测试（见 §3.1.8），端到端测试
    用的是**本机假 MX**。**没有**对公网真实 MX 投递过，因此下列真实世界的差异未被
    验证：真实 MX 的证书形态、灰名单/限速、`4xx` 与延迟重试的相互作用。
    另：**直投不做机会式 TLS**，当前按 SMTP 默认行为走明文 25 端口（直投链路上没有
    凭证，与中继路径的 INV-13 不同）；机会式加密必须「加密但不校验证书」，那是一条
    独立的安全策略决定，已单独登记而非顺手塞进本次改动
- **store 的 Maildir 只读访问尚未实现**（但前提**已定**）：权威布局在实现 `users.*` 时
  已经确定 —— 账号是系统账号，Maildir 就是 `<系统用户家目录>/Maildir`（即
  `/home/<u>/Maildir`），Dovecot 配 `mail_location = maildir:~/Maildir`。
  自检里并列探测的 `<vmail>/<domain>/<user>` 是**历史候选**，不是权威布局。
  仍未实现的原因只是**没有消费者**（webmail 未开始），不再是「前提未决」
- **store 的 Dovecot auth socket 尚未实现**（webmail 认证桥，§3.5 第二行），
  属 `mailstack-webmail` 范围。**与提交端口 SASL 是两回事**：后者已实现并有测试
  （见 §3.1.7），两者只是恰好都问 Dovecot 的同一个 auth 服务
- **`service_ctl` 的降级链已实现**（§5.7.4），含 systemd 运行目录判据、OpenRC 的
  `reload→restart`、Dovecot 的 `restart→reload`、fail2ban 客户端分支；
  **但尚未在真实 OpenRC / sysv init 主机上跑过**（CI 未覆盖 alpine/rocky 的服务控制）
- **表读取的列约定在 store 与 priv 各有一份**：`store::TableStore::domains()` 只取
  第一列，`priv` 的 `domains.list` 还要 `target` 列，两者都建立在同一个
  `core::atomic::rows` 之上。合并需要让 priv 为一个一行的映射而依赖 store，
  收益不足，暂不合并（**不是**遗留缺陷，只是约定有两处消费者）
- 队列落盘目录取 `/var/lib/mailstack/queue`（规格书 §2.5 未定义队列目录，选用状态目录的子目录）。
  条目落在其下的 **`entries/`**（`QueueStore::entries_dir`），队列根只有
  `outbound-health.json` 与它的锁 —— 手工查队列时别只看根目录
- 分阶段中继测试**未对真实中继端点**跑过端到端（仅验证了结构与前置校验路径）
- `cargo-deny` / `cargo-audit` 在 CI 中暂为 `continue-on-error`
- 未产出 SBOM（`cargo-sbom` 未安装，已退化为依赖清单）
- 权威前端（htmx/Leptos）**未按原计划做**：实际接入的是用户提供的前端产物
  （Vite + React 19 单页应用）。这是与规格书 §6 Phase 3 的原计划偏离，详见 §5.3
  与 `DEPLOYMENT.md` §5 的 Phase 3 行
- ~~**遥测的后台采样任务还没有宿主进程**~~ → **已解决**：`bin/mailstack-web` 在启动时
  调用 `TelemetryCollector::start_sampling`（2 秒一次），见 §3.10。若该进程以 API-only
  模式短时运行再退出，`points` 不积累属于进程生命周期的正常结果，不是采集器故障
- **`postqueue -j` 读不到时队列数是 0，与「队列为空」不可区分**：基线的形状里没有
  「读不到」的位置（`queueTotal` / `queueDeferred` 都是必填数字）。这里刻意与基线一致
  保留 `0`，并登记为已知限制 —— 装了 Postfix 的主机上 `postqueue` 恒在，风险主要在
  「Postfix 已被下线」（Phase 5）之后。
- **`/proc/<pid>/statm` 的 RSS 按 4 KiB 页换算**（基线同样硬编码 4096）：构建目标
  `x86_64-unknown-linux-gnu` 即 4 KiB 页，故正确；换到 16/64 KiB 页的架构会低估内存。

### 4.20 遥测 CPU 采样：漏剥核心序号导致整列错位（已修复）

`/proc/stat` 的每核行形如 `cpu0 <user> <nice> <system> <idle> ...`。首版实现用
`strip_prefix("cpu")` 之后直接按空白切分，于是**核心序号那个 `0` 占住了 `user` 的位置**，
`idle` 实际取到了 `system` —— 所有列整体错位一格。

症状是「能跑、数字看着也像那么回事」：两核夹具上算出的占用是 87.5%，而按夹具的增量
应当是 50.0%。**这正是最难发现的一类缺陷** —— 没有报错、没有 panic，只有一条断言把它拦下。

教训：解析内核文本格式时先确认**列的定义**再切片。修法是
`trim_start_matches(|c: char| c.is_ascii_digit())` 把核心序号剥掉，并在原地留一行注释
说明为什么。现在 `cpu_is_differential_so_the_first_sample_has_nothing_to_compare_against`
用「idle +200 / 总增量 +400 ⇒ 恰好 50.0%」把这个口径钉死。

### 4.21 地址策略漏拆 IPv6 里内嵌的 IPv4 —— `::ffff:127.0.0.1` 直达本机（已修复）

准备 AI 出站子系统时逐条对照基线 `ai.py`，发现基线的 `is_ip_restricted` 里有一段
**Rust 侧没有**的逻辑：它先把 IPv4-mapped（`::ffff:a.b.c.d`）、6to4（`2002::/16`）、
Teredo（`2001:0::/32`）里**内嵌的 IPv4** 拆出来再筛选，并在原地留了注释说明为什么必须拆。

Rust 的 `AddressPolicy::accepts` 对 IPv6 只查了 `::1` / `fc00::/7` / `2001:db8::/32`。
后果是 `::ffff:127.0.0.1` **既不等于 `::1`，`is_private()` 也是 false**，于是它穿过全部
v4 规则、被判定成「公网地址」接受；随后 `resolve_pinned` 把它固定为拨号目标，
实际连的就是**本机**。

**影响面不止 AI**：直投的 MX 筛选、中继主机筛选、出站端口探测走的是同一个策略 ——
一个受控域名只要把 AAAA/MX 指到 `::ffff:127.0.0.1` 或 `::ffff:169.254.169.254`
（云元数据地址），就能让服务器去连自己的 25 端口或云元数据服务。

**修复**：新增 `smtp::target::embedded_ipv4_candidates`，`accepts` 先拆内嵌候选，
**任一候选不被接受即整体拒绝**（fail-closed）。Teredo 按 RFC 4380 取**两个**地址
（隧道服务端 + 末 32 位取反后的客户端），必须都通过。递归只落在 v4 分支上，
不存在无限递归。

这里**不是照抄基线**：基线的 Teredo 分支实际上会崩 —— 它把 Python 返回的二元组直接赋给
`ip` 再调 `ip.is_private`，会抛 `AttributeError`。我们按编码正确取出两个地址，属于修正。

安全落点（已登记进 `ci.yml`）：`an_ipv4_mapped_address_is_screened_as_the_address_it_embeds`、
`six_to_four_and_teredo_addresses_are_screened_through_their_embedded_ipv4`。

**追加**：实现 AI 子系统时又发现 `0.0.0.0/8`（RFC 1122 的 "this network"）也没被归入
不可路由。Python 侧 `0.0.0.1` 会被 `is_private` 判为私网；Rust 侧此前只把**恰好**
`0.0.0.0` 当 unspecified，于是 `0.0.0.1` 被接受 —— 与上面 Teredo 拆出来的客户端地址
（0.0.0.1）组合起来就是一个可绕过的面。已把整个 `0.0.0.0/8` 归入不可路由。

### 4.22 队列「删除」被静默降级成「重新投递」——一次删除变成一次发信（已修复）

接入管理前端时逐条比对它的调用参数，发现**前端按 `{id, op}` 提交队列动作**，
而 `readers.rs::queue_action` 只认 `verb` / `action`：

```rust
let verb = optional_str(data, "verb")
    .or_else(|| optional_str(data, "action"))
    .unwrap_or("retry");          // ← 两个候选都没命中时就落到这里
```

于是 `op: "delete"` 被**完全忽略**，落到默认值 `retry`。后果是：

1. 运维在界面上点「删除这条队列邮件」；
2. 后端执行的是 `retry` —— **清零重试预算并把 `next_attempt_unix` 提前到当下**；
3. 下一次调度立刻把这封邮件**投递出去**；
4. 两个方向都不报错：前端收到一个成功的列表，后端完成了一次「合法」的重试。

也就是说，**一个删除操作被替换成了另一个有外部副作用的操作**（发信），而且没有任何
一处日志或响应能把这件事显出来。这比「参数不认导致报错」严重得多 —— 报错至少能被发现。

**修复**：把 `op` 加入候选名，并显式映射前端的动词（`deliver` → `retry`）。
`hold` 在本仓库的队列模型里没有对应状态（条目只有「到期」与「未到期」两态），
因此**显式报错**，而不是挑一个「最接近」的动词执行 —— 让界面看到失败，
胜过让它以为挂起了、实际发生了别的事。

同类问题一并处理：`services.action` 不认 `key`/`op`；`users.delete`/`status`/`password`
不认 `address`。后者的表现是回「不是受管用户」，**看起来像权限问题而不是参数问题**，
排查成本很高。

安全落点（已登记进 `ci.yml`）：`queue_action_accepts_the_frontend_field_names`、
`queue_action_maps_deliver_to_retry_and_refuses_hold`、
`services_action_accepts_the_frontend_field_names`、
`the_frontend_field_names_address_and_name_are_understood`。

### 4.23 成功响应被套了 `{ok,data}` 外壳 —— 非列表动作一个字段都读不到（已修复）

`ok_json` 此前把载荷包成 `{ ok: true, data: ... }`，而基线 `server.production.ts` 的业务
路由是 `res.json(result)` —— **裸对象**。`lib.rs` 顶部声称本模块是对它的「等价移植」，
但这一处并不等价。

后果不是报错，而是**静默读空**：前端对非列表动作直接读 `body.<field>`
（`snapshot` / `settings.get` / `admin.get` / `certs.list` 的详情字段…），外壳让这些
读取全部得到 `undefined`，界面渲染成空白或 `NaN`。列表类动作之所以没暴露这个问题，
是因为前端自己的 `pickList` 兜底了 `o.data ?? o`，把偏差掩盖了一部分。

**修复**：`ok_json` 直接返回裸对象。错误外壳 `{ok:false,error:{code,message}}` 保持不变
（前端确实按嵌套读）。**RPC 桥刻意相反**：`rpc_ok_json` 必须带外壳，因为前端 `bridge()`
按 `body.ok` / `body.data` 拆包；两种形状并存是前端传输层设计的结果，不是不一致。

安全落点：`success_body_is_the_bare_object_without_an_ok_wrapper`、
`rpc_bridge_shapes_are_the_opposite_of_the_rest_routes`。

### 4.24 控制台首页被当成二进制下载 —— 内容类型按 URL 而非文件名判定（已修复）

**这条是端到端冒烟测出来的，不是单元测试测出来的** —— 值得单独记下来，因为它是本轮
唯一一个「测试全绿但真实运行时界面打不开」的问题。

`mailstack-web` 的静态托管原本这样推内容类型：

```rust
Some(file) => file_response(&file, path).await,   // ← path 是**请求的 URL**
...
let content_type = content_type_for(url_path);
```

首页的 URL 是 `/` —— **没有扩展名**，于是 `content_type_for` 落到兜底分支
`application/octet-stream`，浏览器不会渲染 HTML 而是**弹出下载**。用户打开控制台看到的是
一个下载框，而不是登录页。

为什么单元测试没抓到：

* 深链接（如 `/domains`）走的是 **SPA 回退分支**，那里硬编码了 `text/html`，所以是好的；
* 而 `/` **恰好命中真实的 `index.html` 文件**，因此走的是 `file_response` 分支；
* 现有测试 `a_real_asset_is_served_with_its_content_type` 用的是 `/assets/app-abc.js`，
  URL 与文件名都带 `.js`，两条路径推出同一个类型 —— 掩盖了差异。

只有「URL 无扩展名 + 命中真实文件」这个组合会暴露它，而**首页正是这个组合**，
且它是用户打开控制台时请求的第一个路径。

**修复**：内容类型改为按**解析后的真实文件名**（`file.to_string_lossy()`）判定。
回归测试：`the_bundle_entry_is_served_as_html_not_octet_stream`（要求 `/` 回 `text/html`）。

实测复验（真实进程 + 真实前端产物）：

| 请求 | 结果 |
|---|---|
| `GET /` | `200 text/html; charset=utf-8` ✅ |
| `GET /domains`（深链接） | `200 text/html; charset=utf-8` ✅ |
| `GET /api/nope` | `404 application/json` + `API_NOT_FOUND` ✅（**不是** HTML） |
| `GET /../../../../etc/passwd`（`--path-as-is`） | 回 SPA 的 HTML，**不是** `/etc/passwd` ✅ |
| `GET /api/users` / `/api/queue` / `/api/ai/models` | 均 `401`（已接线且受认证保护）✅ |
| `POST /api/rpc` | `401`（未带会话）✅ |
| `GET /assets/index-*.js` | `200 text/javascript` + 530857 字节 ✅ |

### 4.25 外部审查驱动的一批修复（2026-10-04）

**这一节不是「复盘单个缺陷」，而是一次系统性加固的记录。** 完整台账见
[`docs/REVIEW_FIXES.md`](REVIEW_FIXES.md)；这里只记**共性与教训**，因为它是本项目
测试方法论的一次修正。

**背景**：5 份独立的第三方审查报告在**同一批缺陷上独立收敛**（例如「登录限流窗口
永不重置」被 5 份全部发现）。逐条回源码核实后修复，共 3 批、约 20 条。

**共性特征（审查报告的原话，值得贴在墙上）**：

> 最刺眼的几条有一个共同特征：**文档/注释声称的不变量，与代码的实际行为相反，
> 且被一条恰好构造在盲区里的测试固定成了绿灯。**

具体到本仓库，这个「盲区模式」有四种稳定的形态：

| 盲区模式 | 实例 | 测试为何失明 |
|---|---|---|
| **只在唯一时间点构造** | 限流窗口永不重置 | 三个限流测试全在同一个 `t0` 上构造，**从没有一条检查第二个窗口** |
| **恰好以「复位」收尾** | RCPT 枚举、超限后状态机 | 超限测试在**首次** `TooLarge` 就 `break`；DATA 超限测试以 `RSET` 收尾 |
| **只测 happy path 的输入形态** | 裸 LF 点填充 | 三个 `dot_stuff` 测试**全部**只喂 CRLF，裸 LF 从未进入 |
| **测「已实现的分支」而非「声称的性质」** | 空摘要 fail-open | `verify_password_survives_corrupt_record` 只试「非 hex」一种损坏形态，而 `hex::decode("")` 是**成功**的 |

**因此本轮的修复纪律是：每条修复都配一个「反例测试」，判据是
「把修复改回坏代码，它会变红吗？」** 不满足就不是守卫。

实证：`data.rs` 的 `the_line_buffer_stops_growing_after_the_limit_is_hit`
经过**真实的反向验证** —— 我把修复临时改回坏代码（`if !self.overflowed || true`），
测试确实变红（`assertion left == right failed: 超限后继续喂入撑大了行缓冲`），
再改回。这是本轮唯一做了完整反向验证的一条，其余按同样标准设计但未逐条实测。

**两条我自己的错误（都被测试当场抓住）**：

1. 修限流时把 `entry().or_insert_with(..)` 换成 `get_mut`，导致**首次出现的键
   永远不会被建立计数器** —— 计数静默停止。6 个既有测试变红。
2. `iterations` 下界的测试**断言方向写反**（以为降级后正确口令应失败）。
   新测试变红，才发现理解反了。

> 这两条说明「反例测试」不只是防回归，它同时**校验我自己对缺陷的理解是否正确**。

**被否掉的报告结论**：3 条（`keys.rs` 的 `split_at` 不可达、`bind→chmod` 竞态
实际风险低、审计链「零写入」实为迁移就绪度问题）。**逐条回源码核实是必要步骤**
—— 否则会把有意选择当成 bug 改回去。详见 `REVIEW_FIXES.md` §4。

**过程留痕**：其中一个子代理在返回前**中断**，留下三处半成品（重复函数定义、
六处缺 `&`、两个测试用旧 cookie 名），由我手工收拾。
**教训**：子代理的核心逻辑可用，但**收尾不可信** —— 必须读实际改动而非它的汇报。



## 5.1 与规格书的偏差（登记，待裁决）

| 偏差 | 规格书要求 | 现状 | 说明 |
|---|---|---|---|
| DSN 生成方式 | §3.4 依赖清单推荐 `mail-builder` | 自研 MIME（`crates/queue/src/dsn.rs`） | 仅工程取舍：DSN 的 `message/delivery-status` 与 `message/rfc822` 两部分在高层构建器里需绕开封装。**不得**用「依赖链/离线可复现」为理由 —— `mail-builder` 是纯 Rust，不违反 §3.4 硬约束。若裁决改用该 crate，只需替换 `dsn.rs` 内部实现，对外接口 `build_dsn` 不变 |
| DKIM 私钥目录 | §2.5/§5.8 取 `/etc/opendkim/keys/<domain>/` | 统一取 `/etc/opendkim/keys/<domain>/` | **基线自身不一致**：`network.py:105`（setup 流程）写 `/etc/opendkim/keys/<domain>/`，而 `certs.py:182`（`dkim.rotate`）写 `/etc/mailstack/dkim/<domain>/`。`telemetry.key_permission_scan` 的默认扫描目录是前者。Rust 版**统一采用前者**，`certs.py` 那条路径记为偏离。若裁决要保留 `/etc/mailstack/dkim`，只需改 `keys::dkim_key_dir` 一处 |
| `dkim.rotate` 生成失败的文案 | `certs.py:188` 抛 `OpenDKIM key generation failed` | `DKIM key generation failed` | 生成改为原生后，「opendkim-genkey 未安装」这一前置条件（`certs.py:180`）消失，文案再声称是 OpenDKIM 的产出会让运维去排查一个已被移除的组件。该字符串**不在**已冻结的 62 条路由契约里，故按可读性调整 |
| `dkim.rotate` 返回的 `record` | 基线返回 `.txt` 文件全文（多行带引号的 zone 片段） | 同基线 | 保持「`record` == `.txt` 内容」这一关系不变。注意 UI 的 DKIM 记录取自 `setup.json` 的 `dkimPublicKey`（`DnsGuideTable.tsx:184` 会剥掉 `v=DKIM1; k=rsa; p=` 前缀），**不是**这个 `record`，因此两者各自独立演进 |
| 新增 `crates/smtpd` | 规格书 §6 的迁移路线只列到 `crates/webmail` 与 `bin/{mailstackd,mailstackctl}`，未点名入站 SMTP 服务端所在 crate | 新建 `crates/smtpd`（`mailstack-smtpd`） | 该路线**没有**为入站服务端留位置，而它又必须存在。放进 `mailstack-smtp` 会形成依赖环（`queue` → `smtp`，而 `smtpd` → `queue`）；放进 `bin/mailstackd` 会让它无法被单元测试。若裁决应改名或分拆，改动集中在 crate 名与 `Cargo.toml` |

## 5.2 依赖决策：`mail-auth` 必须按受限特性引入（实测）

规格书 §3.4 推荐用 `mail-auth` 替代 OpenDKIM。但直接引入会**违反同一条 §3.4 的硬约束**
（禁止 C 依赖链）。实测结论：

| 版本 | `zip` 依赖 | 结果 |
|---|---|---|
| 0.6.1（`cargo add mail-auth@0.6` 的默认结果） | **非可选**，且默认特性含 `zstd`/`xz`/`bzip2` | ❌ 拉入 `zstd-sys`、`xz2`、`bzip2-sys` —— **三个都编译 C** |
| 0.9.2 / 0.11.3 / 0.13.3 | **可选**，仅 `report` 特性启用，且 `default-features = false` | ✅ 可用 |

另外 0.9+ 的默认 crypto 是 `aws-lc-rs`（需要 cmake/nasm）—— 本仓库全链路刻意用
`ring` 正是为了避开它。因此最终钉法是：

```toml
mail-auth = { version = "0.13", default-features = false, features = ["ring", "arc", "generate"] }
```

`ring` 特性自带 `dns-hickory`（SPF/DKIM/DMARC 需要真实 DNS 查询），`arc` 打开 ARC。
`generate` 用于**原生生成 RSA 密钥**（`DkimKeyPair::generate_rsa`）：它只拉入纯 Rust 的
`rsa` + `rand`（实测新增 15 个包，**无 C 依赖链**）；没有它就只能退回调用
`opendkim-genkey`，那正是 §3.3 要移除的外部二进制。
**已实测**：该组合下 `cargo tree` 无任何 C 依赖链，`flate2` 走纯 Rust 的
`rust_backend`，`cargo check -p mailstack-auth` 通过。代价是依赖树 204 项。

### 5.2.1 生成的 DNS 记录必须是 SPKI，不是 PKCS#1

`mail_auth::dkim::generate::DkimKeyPair::encoded_public_key()` 输出的是 **PKCS#1** 的
base64，而 RFC 6376 的 `p=` 与生态里的既有记录都是 **SubjectPublicKeyInfo**（以
`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A` 开头，mail-auth 自己的测试向量也是如此）。
mail-auth 的验签侧有 `try_strip_rsa_prefix(...).unwrap_or(bytes)` 会**两种都容忍**，
所以本地自检会通过，但别的收件方（Gmail/OpenDKIM）解析 PKCS#1 形态的 `p=` 会验签失败
—— 属于「本地测试绿、生产静默失败」的典型。**发布 DNS 记录前必须自行做 SPKI 封装。**

### 5.3 Phase 3 前端接入的已知限制（诚实披露）

| 限制 | 说明 |
|---|---|
| **前端是外部产物，不在本仓库** | 静态资源由 `--dist <DIR>` 引入，本仓库不构建也不校验它。后端只保证「路径安全、内容类型正确、`/api` 底线是 JSON」。前端自身的构建产物哈希、体积、依赖安全不在本项目门禁覆盖范围 |
| **前端对部分字段的假设与后端不符，已按后端真实字段对齐** | 例如证书页原先读 `daysLeft`/`keySize`/`autoRenew`，而后端只提供 `daysUntilExpiry`，且**不追踪** `keySize`/`autoRenew`。这类字段前端改为显示占位，**没有伪造数值** —— 后端确实没这个数据 |
| **`setup.mail.test` 在向导里可能无法通过** | 该动作按基线恢复了四步校验（含「发件人必须对应一个受管邮箱」+ 口令格式回放），而向导的这一步只收集收件人地址。这是**前端功能缺失**，不是后端问题；后端不会为了让它过而放宽校验 |
| **`network.check_port` 忽略请求里的 `host`** | 这是**有意的 SSRF 防护**：探测目标只能来自部署配置（`probe_targets`），不接受请求体指定主机。前端传的 `host` 会被忽略，实际探测的是配置中的目标 |
| **遥测只有 2 秒采样的前台宿主** | 后台采样任务现在由 `mailstack-web` 启动。**若以 API-only 模式短时运行再退出**（例如只跑一次自检），`points` 不会积累 —— 那是进程生命周期的正常结果，不是采集器故障 |
| **管理面默认只绑回环** | `--bind 127.0.0.1:8443`。TLS 终止与对外暴露交给反向代理或 SSH 隧道，**本进程不做 TLS**（规格书 §3.4 把 TLS 栈留给真正需要加解密的组件）。若有人把 `--bind` 改成 `0.0.0.0` 而无反代，管理面就是明文暴露 —— 部署时必须注意 |

## 5.4 真实环路验证（`deploy/verify-loopback-e2e.sh`）

在 WSL 里**实跑** `mailstackd`（非注入替身），走完入站 SMTP 会话并检查队列落盘。
一条命令完成「建夹具 → 起进程 → 验证 → SIGTERM 停机 → 报告」，可重复执行。

**实测结果（全部通过）**

| 环节 | 证据 |
|---|---|
| fail-closed 装配 | `配置装配完成 domain=example.com mail_host=mail.example.com ports=[25, 587] relay="<direct>"`；缺 `setup.json` / 证书 / 域名表时**拒绝启动**（已实测，见下） |
| 监听 | `监听已就绪 port=25 mode=StartTls` 与 `port=587` |
| **RPC 双通道权限** | `srw-rw---- root mailstack-admin helper-ro.sock` / `srw------- root root helper.sock` —— 与 DEPLOYMENT §3.1 的契约**逐字一致** |
| 真实 SMTP 会话 | `220` 问候 → EHLO 得 `250-SIZE/8BITMIME/ENHANCEDSTATUSCODES/STARTTLS` → `250 2.1.0 Sender OK` → `250 2.1.5 Recipient OK` → `354` → **`250 2.0.0 Message accepted for delivery`** |
| **队列落盘** | `queue/entries/1A1027297040000.json`，`kind=outbound`、`recipients=['postmaster@example.com']`、`attempts=0` |
| RO socket 取数 | `mailstackctl snapshot` 经 RO socket 返回 JSON（`certs:[]` 与 `domains:[]` 在本夹具下是**正确**的：无已签发证书、域名表只对 `snapshot` 的 `domains` 字段可见） |
| 优雅停机 | SIGTERM 后扇出停止：listener → 队列调度 → 手工封禁热重载 → RPC 双面 → `守护进程已退出` |

**三个环境陷阱（都不是产品缺陷，但都让「测试失败」看起来像「代码坏了」）**

1. **WSL 的 `/tmp` 在每次 `wsl` 命令启动时被清理。**
   实测：建标记文件后，下一条**独立**的 wsl 命令读同一路径已是 `No such file or directory`。
   于是「生成夹具」与「使用夹具」分成两条命令的做法**必然失败** —— 表现为「启动失败」，
   而根因与启动毫无关系。本脚本因此把根目录放在 `/root/mailstack-loopback`，
   并把生成与消费合并进同一条命令。*（连续三轮看起来互不相关的失败，根因是同一个。*
2. **客户端超时要大于服务端 `data_timeout`（默认 600 秒，`connection.rs:49`）。**
   客户端只等 15 秒时，症状是「发完正文就超时、服务端日志一行都没有」——
   与「服务端卡住」**完全同形**，区别只在这个常量。第一轮排查在这里绕了很久，
   靠打印实际发出的字节才排除掉脚本自身的转义问题。
3. **证书文件名是 `fullchain.pem` / `privkey.pem`**（`CertPaths::for_domain`），
   不是 `cert.pem` / `key.pem`。写错时错误消息指向「证书」，读起来像配置问题。
   同理 **`relay.json` 不该写**：它是 `BTreeMap<String,String>`（值必须全是字符串），
   而 `relayhost` 键**不存在即合法**（= 直投，`bin/mailstackd/src/config.rs:230`）。

**覆盖边界（诚实说明）**：本脚本验证的是**入站收信 → 队列落盘**这一段。
**尚未**覆盖：LMTP 投到 Dovecot Maildir、出站直投真实公网 MX、提交端口 SASL、
DKIM 出站签名。这些需要本机装 Dovecot / 真实域名与公网环境，见 §5 的对应条目。

### 5.5 初始化向导链路的验证（`deploy/verify-setup-wizard-e2e.sh`）

向导第 5 步横跨三个动作，而**每一步的前置条件失败方式都是「返回错误」而不是
「功能不存在」** —— 界面能渲染、按钮能点，只有真发请求才知道通不通。
脚本按真实顺序验证，并**先复现失败再验证成功**：

| 步骤 | 动作 | 前置条件 |
|---|---|---|
| 1 | `domains.add` | 域名必须在受管域名表里。**`setup.identity.apply` 只写 `setup.json`，不写这张表** —— 漏了这一步，后面 `users.add` 与 `mailstackd` 都会拒绝 |
| 2 | `users.add` | **受管邮箱表只有这一个动作会写**，而 `setup.mail.test` 强校验 `(username, sender)` 命中它 |
| 3 | `setup.mail.test` | 口令不得含 `admin` / 完整邮箱（`validate_mailbox_password` 的 context 就是这两项），且长度与连续字符也要合规 |

脚本同时验证两个**反例**，因为它们证明校验真的在生效而不是我们单方面拦了一道：
未建号时发信回 `managed mailbox`；不合格口令回 `password must not contain`；
重复建号回 `already exists`（向导据此当成功继续）。

**实测结果（RO 段全通，RW 段被前置条件挡住）**

* ✅ `mailstackd` fail-closed 装配、监听 25/587、`domains.add`（RO 直连 socket）返回裸数组、SIGTERM 停机
* ⚠️ **RW 步骤被跳过并已如实说明**：本机 `/usr/local/libexec/mailstack-privileged` 是**重写前留下的包装器**，它 `exec` 的是 `/opt/mailstack/backend/mailstackctl.py`（文件仍在，但它不认识本项目的任何动作名，于是对任何 RW 动作都 `exit 1`，客户端看到 `PRIVILEGED_OPERATION_FAILED`）。

**这不是本仓库的缺陷，恰恰证明特权边界在工作**：所有 RW 动作恒经该包装器（DEPLOYMENT §3.1），
Web 进程无法绕过它直连 `helper.sock`。也因此得到一条**部署硬要求**：

> 真实部署必须先把 `/usr/local/libexec/mailstack-privileged` 指向本仓库的 `mailstackctl`。
> 在此之前，**所有写操作（建用户、加域名、发信、备份、证书…）都会失败**，
> 而界面报出来的是笼统的「权限不足」，与真实原因（包装器指向旧助手）毫无关联。

换成新包装器后重跑该脚本即可覆盖完整链路。

## 6. 构建环境约束（影响后续推进）

- Windows 开发机的 mingw 工具链上任何 tokio 异步测试都会 `STATUS_ACCESS_VIOLATION`
  崩溃（已用最小复现证明是工具链缺陷）→ 异步测试一律在 WSL 执行
- WSL 磁盘曾于 Phase 2 中途达到 100% 导致构建失败。已回收：
  `apt-get clean` + `journalctl --vacuum-size=50M` + 清除 Docker 遗留
  （两个 `mailstack:*` 镜像标签、`ms-warm-stage1`、两个已退出容器），
  回收后可用空间 **340 MB → 2.6 GB**。
  保留了 `ubuntu:24.04` / `rockylinux:9-ci` / `alpine:3.20` 三个基础镜像
  （合计约 390 MB），后续 install-matrix 测试仍会用到。
  复现脚本：`deploy/wsl-reclaim-space.sh`。
- **磁盘不足的症状是「链接失败」，不是「磁盘满」**（已固化为构建配置）。
  WSL 根分区只有 9.8 G，而本工作区有 10 个测试目标；完整 debuginfo 会把
  `target/debug` 撑到 4.5 G 以上，链接阶段报的是
  `collect2: fatal error: ld terminated with signal 7 [Bus error], core dumped` ——
  极易被误读成代码问题。`deploy/wsl-cargo.sh` 现在默认把 dev profile 的调试信息
  降到 `line-tables-only`（**保留回溯的文件与行号**，只丢掉变量/类型信息），
  需要完整调试信息时设 `MAILSTACK_FULL_DEBUG=1`。
  release profile 不受影响（`deploy/build.sh` 走 `--release`，且已 `strip`）。
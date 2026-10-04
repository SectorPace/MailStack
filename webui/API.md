# MailStack 前端 → 后端 交接文档（API 契约 v1）

> 交接对象：`crates/admin-web`（axum）的实现者。
> **契约的可执行定义**：`src/api/client.ts` 的 `mockDispatch()`（mock 数据分发器）——每个动作的请求/响应字段以它为准；本文档是其人类可读版 + 传输层语义。

---

## 1. 前端形态（部署即用，无需后端配合）

- `dist/` 纯静态产物，`base: './'`（相对路径），**hash 路由**（`#/dashboard`）→ axum 挂载到任意路径都无需 SPA fallback：

```rust
Router::new()
    .nest_service("/api", api_router)
    .fallback_service(ServeDir::new("dist").fallback(ServeFile::new("dist/index.html")))
```

- 开发期：`npm run dev`（Vite 5173，`/api` 代理到 `ADMIN_API` 环境变量，默认 `http://127.0.0.1:8080`）。

## 2. 双传输层（启动时自动探测）

前端启动时 `GET /api/setup/status`：

| 结果 | 传输层 | 说明 |
|---|---|---|
| 200 / 401 等 | **REST**（对齐原版 MailStack beta.10 admin-web） | 全部走下表 REST 端点，写操作带 `x-csrf-token` |
| 404 / 405 / 网络错误 | **RPC 桥** | `POST /api/rpc`，帧协议透传 helper socket |

REST 未映射的动作自动回退 RPC 桥 —— 因此后端**最小实现只需 §4 的 P0 项**即可点亮全部页面。

## 3. 认证 / CSRF / 错误语义

- `POST /api/auth/login` `{ username, password, code? }` → `200 { csrf: string, ... }`；
  失败 `401 { error: { code, message } }`；**`code === "TOTP_REQUIRED"`** 时前端切两步验证阶段并重发 `code` 字段。
- 前端把 `csrf` 存内存，之后所有非 GET 请求带 `x-csrf-token` 头。
- 任何端点 `401` → 前端全局弹回登录页（`HttpOnly` Cookie 会话）。
- 错误体约定：`{ error: { code, message } }` 或 `{ error: string }`，前端展示 `message`。

## 4. REST 端点契约（方法 / 路径 / 请求 / 响应）

> 响应字段结构 = mock 分发器中的同名 case。标注 ★ 的为前端扩展（原版 beta.10 没有的端点，可直接实现或统一走 §5 RPC 桥）。

### 认证与会话
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/auth/login` | POST | `{username, password, code?}` | `{csrf, ...}` |
| `/api/auth/session` | GET | — | 会话信息 |
| `/api/auth/logout` | POST | — | `{}` |
| `/api/auth/sessions` | GET | — | `[{id, current, ip, userAgent, lastActive}]` |
| `/api/auth/sessions/revoke` | POST | `{id}` 或 `{all:true}` | `{revoked}` / `{revokedAll}` |

### 管理员
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/admin` | GET | — | `{username, totp, createdAt}` |
| `/api/admin` | POST | `{username, password?}` | `{updated, revokeSessions:true}` → 前端注销所有会话 |
| `/api/admin/2fa` | GET | — | `{enabled, recoveryCodes?}` |
| `/api/admin/2fa/begin` | POST | `{code:""}` | `{secret, otpauthUri}` |
| `/api/admin/2fa/enable` | POST | `{code}` | `{recoveryCodes:[8×"xxxxxxxx-xxxxxxxx"]}` |
| `/api/admin/2fa/disable` | POST | `{code}` | `{disabled}` |

### 仪表盘（★ snapshot 扩展字段）
| 端点 | 方法 | 响应 |
|---|---|---|
| `/api/snapshot` | GET | `{health, uptime, domains{total,active,disabled}, users{...}, queue{total,pending,sending,failed,deferred,hold,bounced,delivered}, smtp{running,connections,sentToday,successRate,ports,uptime}, dovecot{...}, latency{points:[{t,v}]}, domainRows[], userRows[], serviceDist{total,running,alert,offline}, resources{cpu,memory,disk}, healthPanel{overall, items:[{key,label,status,value?}]}}` |
| `/api/metrics/realtime` | GET | `{points:[{t,v}], ts}` |
| `/api/metrics/telemetry` | GET | 遥测 |
| `/api/metrics/system` ★ | GET | `{cpu, memory, disk}` |
| `/api/system/doctor` | GET | `[{check, ok, detail}]` |
| `/api/activity` ★ | GET | `[{kind: user\|domain\|queue\|service\|cert, title, sub, time}]` |

### 资源 CRUD
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/domains` | GET | — | 域名数组（或 `{domains:[...]}`） |
| `/api/domains` | POST | `{domain}` | `{domain}` |
| `/api/domains/{domain}` | DELETE | — | `{}` |
| `/api/users` | GET | — | 用户数组 |
| `/api/users` | POST | `{address, name?, quota?}` | `{address}` |
| `/api/users/{address}` | DELETE | — | `{}` |
| `/api/users/status` | POST | `{address, active}` | `{address, active}` |
| `/api/users/password` | POST | `{address, password?}` | `{}` |
| `/api/aliases` | GET | — | 别名数组 |
| `/api/aliases` | POST | `{source, target}` | `{source, target}` |
| `/api/aliases/{source}` | DELETE | — | `{}` |

### 邮件服务
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/certificates` | GET | — | `[{domain, issuer, keySize, notAfter, daysLeft, autoRenew}]` |
| `/api/certificates/renew` | POST | `{domain}` | `{renewed}` |
| `/api/queue/action` | POST | `{id, op: deliver\|release\|hold\|delete}` | `{}` |
| `/api/services/action` | POST | `{key, op: start\|stop\|restart}` | `{running}` |
| `/api/setup/relay/test` | POST | `{relayProvider, relayHost, relayPort, relayAuthUser, ...}` | `{success, latencyMs, message}` |
| `/api/setup/relay/apply` | POST | 同上 | `{applied}` |
| `/api/network/check-port` | POST | `{port, host}` | `{open, latencyMs}` |
| `/api/status` | GET | — | 中继运行状态 |

### 初始设置向导
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/setup/status` | GET | — | `{completed: bool, step}` |
| `/api/setup/identity` | POST | `{domain, mailHost, serverIp}` | `{applied}` |
| `/api/setup/dns/verify` | POST | `{domain, mailHost}` | `{verified}` |
| `/api/setup/cert/issue` | POST | `{domain, mailHost}` | `{issued, san[], issuer, algo}` |
| `/api/setup/mail/test` | POST | `{to}` | `{success, queued, message}` |
| `/api/mail/test-loopback` | POST | — | `{success, message}` |

### 安全 / 备份 / DNS
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/security/scan` | GET | — | `{score, lastScan, findings[], bans[], failedLogins24h}` |
| `/api/security/ban` | POST | `{ip, reason?}` | `{}` |
| `/api/security/unban` | POST | `{ip}` | `{}` |
| `/api/backups` | GET | — | `[{name, size, time, kind}]` |
| `/api/backups/restore` | POST | `{name}` | `{}` |

### AI（原版 DNS 助手端点）
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/ai/config` | GET / POST | GET—；POST `{provider, endpoint, apiKey?, model?}` | 配置对象 |
| `/api/ai/models` | GET | — | `[{id, label, context}]` |
| `/api/ai/test` | POST | 配置 | `{ok, latencyMs, models}` |
| `/api/ai/dns-chat` | POST | `{message}` | `{reply}` |
| `/api/ai/diagnose-dns` | POST | `{}` | `{summary, items:[{ok,text}]}` |

## 5. RPC 桥（万能回退，前端已自动使用）

REST 表中没有的动作（`queue.list`、`services.list`、`dkim.keys`、`dkim.rotate`、`dns.records`、`ai.config.get` 在 REST 表有 GET；`backup.create/delete`、`metrics.realtime` 等其余全部）会落到：

```
POST /api/rpc
请求体: {"action": string, "data": object}     ← 与 crates/common/src/rpc.rs 帧协议字段一致
响应:   {"ok": true, "data": ...} | {"ok": false, "error": string}
```

实现 = axum handler 校验 action ∈ `crates/common/src/actions.rs` 白名单 → 写帧到 `helper-ro.sock`（RO）/ `helper.sock`（RW）→ 读回帧原样返回。约 30 行。

## 6. 后端实现清单（按优先级）

**P0（点亮登录 + 全部页面骨架）**
1. 静态托管 `dist/` + `nest_service("/api")`
2. `POST /api/auth/login`（PBKDF2 + HttpOnly Cookie + csrf 字段 + 401/TOTP_REQUIRED 语义）
3. `GET /api/setup/status`
4. `POST /api/rpc` 桥（helper socket 已实现，粘合即可）

**P1（真实数据）**
5. `GET /api/snapshot`（helper `snapshot` 动作组装）· `/api/settings` GET/POST
6. CRUD：domains / users(+status,password) / aliases / certificates(+renew) / logs
7. `queue/action` · `services/action` · `security/*` · `backups` · `system/doctor` · `metrics/*`

**P2（增强）**
8. `admin` + `admin/2fa/*`（TOTP）+ `auth/sessions*`
9. `setup/identity|dns/verify|relay/*|cert/issue|mail/test`
10. `ai/*`（可选，需外部 LLM 端点）

## 7. 验收方法

1. 后端起在 `127.0.0.1:8080` → 直接打开前端（无参数）→ 探测 REST 成功 → 走 REST。
2. 未实现 REST 时：实现 §5 的 `/api/rpc` 桥即可（前端自动回退）。
3. 演示/评审：`?mock=1`（内置 mock，无需后端）；`?mock=1&login=1` 登录页；`?mock=1&setup=1` 向导回放。
4. 任何字段拿不准 → 看 `src/api/client.ts` mock 分发器对应 case（契约的可执行定义）。

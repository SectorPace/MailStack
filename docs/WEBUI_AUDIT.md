# 管理前端（webui）审计报告（2026-10-04）

> 审计对象：`webui/` —— MailStack Admin Console 单页应用
> 规模：31 个源文件，约 7.6k 行 TS/TSX + 882 行 CSS
> 方法：全量源码通读 + `npm run build` 实跑 + 浏览器运行时实测 + 后端契约交叉核对
>
> **本报告不是 diff 审查，是对 `/api/health` 不可达时的降级路径、
> Tailwind v4 语义变更、以及前后端契约一致性做的全量审计。**
>
> 审计纪律：不信推测，回源码逐条核实；能实测的一律实测（下文标注「实测」者为浏览器真实观测结果）。

---

## 0. 结论摘要

| 级别 | 数量 | 说明 |
|---|---|---|
| 🔴 高危 | 4 | 用户可见、且会导致**误判**的缺陷 |
| 🟠 中危 | 9 | 功能失效 / 会话安全 / 契约不匹配 |
| 🟡 低危 | 20+ | 死代码、可访问性、React 实践、注释错误 |

**一句话结论：**

> 后端不可达时前端会**静默降级为 mock 模式并跳过全部认证**（实测确认），
> 而唯一能提示用户"这是假数据"的徽标**恰好因为一个多余的 `!` 而永久不可见**（实测确认）。
> 两者叠加，使一个邮件服务器管理台在故障时呈现出一份**看起来完全正常、实则全部虚构**的健康报告。

**审计纪律声明**：本次共提出 30+ 条结论，其中 §5 列出 3 条经核实**推翻**的疑似问题
（`Relay.tsx` 的 `SSL-TLS` 枚举、`__Host-` cookie 的 `Secure` 属性、mock 的 prototype 污染），
未计入缺陷。

---

## 1. 高危问题

### 1.1 🔴 后端不可达时静默降级为 mock 模式，**完全跳过认证**

| 项 | 内容 |
|---|---|
| 位置 | `webui/src/api/client.ts:41-53`（探测）、`client.ts:71-82`（降级）、`webui/src/App.tsx:112-118`（跳过认证） |
| 级别 | 🔴 高危 |

**机理**

`probe()` 请求 `api/health`，失败即 `mode = "mock"`；`App.tsx` 在 mock 模式下**无条件**放行：

```ts
// client.ts:76-77
setMode((await probe()) ? "live" : "mock");

// App.tsx:115-117
if (m === "mock") setAuthed(!forceLogin);
```

`Login.tsx:24-30` 的 mock 分支接受**任意非空口令**（`123456` 触发假两步验证）。

**实测证据**

后端返回 500 时，浏览器直接进入完整控制台，无任何登录页：

```
hasLoginForm: false        ← input[autocomplete="current-password"] 不存在
hasSidebar:   true         ← 13 项导航全部可用
bodyText: "MailStack 搜索功能… 仪表盘 AI 智能中心 … 总域名 8
           邮箱用户 1,248 邮件队列 23 待处理邮件 …"
console: GET /api/health → 500
```

**三重放大因素**

1. **探测超时仅 1500ms**（`client.ts:44`）。服务器稍有负载、或首字节超过 1.5s，即被误判为「后端不存在」。
2. **`?mock=1` 可强制进入**（`client.ts:72-73`），生产构建未关闭该分支。
3. **提示徽标本身是坏的** —— 见 §1.2，"模拟数据"徽标 `display:none`。

**危害界定**

不构成真实数据泄露（mock 不触碰后端，攻击者拿到的都是硬编码假数据）。
真正的危害是**误导性状态**：后端重启、代理异常、端口打不开时，
管理员打开控制台看到的是一份完整、自洽、数字漂亮的健康报告
（8 个域名 / 1,248 个邮箱 / 成功率 99.8%），**且没有任何界面元素提示这是演示数据**。
对邮件服务器管理台，"故障时看起来一切正常"是最危险的一类缺陷。

**修复方向**：fail-closed。探测失败应渲染明确的"后端不可达"错误页 + 重试入口，
而不是降级。生产构建用 `import.meta.env.DEV` 剥离整个 `mockDispatch` 分支
（可同时消除 §2.8 与 `?mock=1`）。

---

### 1.2 🔴 `hidden!` 使 4 个工具栏控件永久不可见，含**唯一的刷新按钮**

| 项 | 内容 |
|---|---|
| 位置 | `webui/src/components/Toolbar.tsx:119, 127, 139, 211` |
| 级别 | 🔴 高危 |

**机理**

Tailwind v4 把 important 修饰符从前缀改为后缀，`hidden!` 产出：

```css
.hidden\!{display:none!important}       /* 有 !important */
.sm\:inline-flex{display:inline-flex}   /* 没有 !important */
```

`!important` 优先级最高，`sm:` / `xl:` 响应式变体**永远无法覆盖**。

**实测证据**（构建产物 + `getBoundingClientRect`）

| 行号 | 元素 | 实测结果 | 本意 |
|---|---|---|---|
| `Toolbar.tsx:119` | 模拟数据 / 已连接后端 徽标 | `display:none`, 0×0 | `xl:` 才显示 |
| `Toolbar.tsx:127` | 服务运行正常 徽标 | `display:none`, 0×0 | `sm:` 才显示 |
| **`Toolbar.tsx:139`** | **刷新按钮** | **`display:none`, 0×0** | `sm:` 才显示 |
| `Toolbar.tsx:211` | 语言切换按钮 | `display:none`, 0×0 | `sm:` 才显示 |

**危害**

`Toolbar.tsx:139` 的刷新按钮是 `RefreshContext`（`App.tsx:48`）的**唯一入口** ——
`ScrollRail`（`App.tsx:272-310`）只有搜索/设置/回到底部，没有刷新。
即：**用户无法手动重新拉取任何数据**，只能靠切换路由触发 `useEffect` 重取。
对一个需要盯着队列和日志排查故障的管理台，这是直接影响可用性的缺陷。

> ⚠️ `Settings.tsx:321` 的 `className="hidden!"` 是**有意**隐藏 `<input type="file">`，
> 修复时不要一并改动。

---

### 1.3 🔴 安全页与仪表盘**硬编码伪造安全状态**

| 项 | 内容 |
|---|---|
| 位置 | `webui/src/pages/Security.tsx:100-115`、`webui/src/pages/Dashboard.tsx:213-223, 302, 526` |
| 级别 | 🔴 高危 |

代码库在 `Dashboard.tsx:8`、`TlsCerts.tsx:13-15`、`Security.tsx:6-7` 三处都明确写下
「后端没有的数据一律显示占位符 `—`，绝不编造」。**这两处自己违反了这个原则。**

**`Security.tsx:100-115` —— 整个安全状态卡是写死的常量：**

```tsx
<span style={{ color: "rgb(var(--ok-rgb))" }}>
  <IconCheck size={13} /> {t("verified")}        // SPF / DMARC —— 恒为已验证
</span>
<span style={{ color: "rgb(var(--err-rgb))" }}>
  <IconX size={13} /> {t("unverified")}          // DKIM·test.org —— 恒为未验证
</span>
<StatusBadge kind="ok" label="active" />          // fail2ban —— 恒为 active
```

与 `security.scan` 的真实返回**完全无关**。域名 `test.org` 是 mock 演示数据里的域名，
却被硬编码进了「生产」界面。

**`Dashboard.tsx`：**

| 行号 | 问题 |
|---|---|
| `:213-223` | 第一张状态卡恒为「系统健康 / 运行正常 / 所有服务运行正常」，不读任何真实状态 |
| `:302` | 服务分布卡徽标恒为 `<StatusBadge kind="ok" label="运行正常" />` |
| `:526` | `GaugeRing value={vm.healthPanel?.overall ?? 98}` —— **后端无数据时默认显示 98 分** |

**危害**

`98` 与「SPF/DMARC 已验证 / fail2ban active」是管理员据以采取行动的依据。
伪造的"一切正常"会让管理员在 DNS、DKIM、fail2ban 实际失效时不去修 ——
对一个以"邮件送达率与反滥用"为核心价值的系统，这是最坏的一类缺陷。

**修复方向**：删除常量，改为读取 `security.scan` 的 `findings` / `bannedIps` 推导；
后端无数据时显示 `—`，与 `Dashboard.tsx:79` 的 `nz()` 辅助函数保持一致。

---

### 1.4 🔴 `security.scan` HTTP 方法不匹配，安全页扫描永远失败

| 项 | 内容 |
|---|---|
| 前端 | `webui/src/api/client.ts:189` — `method: "GET"` |
| 后端 | `crates/web/src/contract.rs:150-155` — `r("POST", "/api/security/scan", ...)` |
| 后端 | `crates/web/src/lib.rs:343` — `.route("/api/security/scan", post(...))` |

前端映射为 `GET /api/security/scan`，后端**只注册了 POST**。
axum 对方法不匹配返回**空 body 的 405**，`restCall` 只能报出 `"HTTP 405"`：

```ts
// client.ts:220-225
const j = (await res.json().catch(() => ({}))) as Record<string, unknown>;
if (!res.ok) { ... ?? `HTTP ${res.status}` }   // → "HTTP 405"
```

于是 `Security.tsx:61` 的 `r.ok && setScan(r.data)` 永不成立，
`Security.tsx:72` 的 `if (!scan) return <skeleton />` 永不解除
—— **页面永久停留在骨架屏，且没有任何错误提示**。

---

## 2. 中危问题

| # | 问题 | 位置 | 说明 |
|---|---|---|---|
| **M1** | **「退出登录」不通知后端** | `Toolbar.tsx:256-258` | `toastLogout()` 仅 `dispatchEvent("mailstack:logout")` 做本地跳转。`REST["auth.logout"]`（`client.ts:200`）已定义但**全仓库无任何调用点**（grep 确认）。服务端会话 cookie `Max-Age=28800`（8h）依然有效，**「退出」不等于会话失效**。 |
| **M2** | **无会话恢复，CSRF token 不可重建** | `client.ts:19,57`、`App.tsx:112` | `csrf` 是模块级变量，**唯一**来源是登录响应体（`Login.tsx:37` → `captureCsrf`）。后端 `GET /api/auth/session` 会返回 csrf（`crates/web/src/lib.rs:213-220`），前端已定义映射 `client.ts:199` 却**无人调用**；`index.html` 无 `<meta name="csrf-token">`、无 cookie、无 storage 副本。**刷新页面 = 强制重新登录**（`App.tsx:116` 只在 mock 模式置 `authed=true`）。 |
| **M3** | **401/403 处理不一致** | `client.ts:112` vs `client.ts:216` | `bridge()` 把 403 当作未授权并 `dispatchEvent("mailstack:unauthorized")` 登出；`restCall()` **只认 401**。REST 传输模式下 CSRF 失效只会弹一句 `"missing or invalid CSRF token"` toast，用户被卡死在页面内且不知原因。 |
| **M4** | **2FA 启用后忽略 `reauthenticate`** | `AccountSecurity.tsx:83-91` | 后端 `crates/web/src/routes.rs:184-200` 在启用 2FA 后吊销所有会话并下发 `Max-Age=0` cookie，响应带 `reauthenticate:true`。前端只读 `recoveryCodes`，UI 停在"两步验证已启用"，下一次写操作才 401 弹回登录页。 |
| **M5** | **会话列表字段不匹配** | `AccountSecurity.tsx:17,135,272,294,304` | 后端 `sessions.list` 只返回 `{id, username, createdAt, lastSeen}`（`session.rs:245-261`），**没有 `current` / `ip` / `userAgent` / `lastActive`**。后果三连：① "当前"徽标永不显示；② "吊销"按钮会出现在**自己当前会话**上；③ `revokeOthers` 用 `filter(x => x.current)` 清理列表 —— 因 `current` 恒 undefined，**一行都不会被移除**，UI 谎报成功。 |
| **M6** | **`admin.set` 字段名拼错** | `AccountSecurity.tsx:45,51` | 前端读 `revokeSessions`（boolean），后端返回 `revokedSessions`（数字）+ `reauthenticate`（`routes.rs:250-256`）。条件恒为 false，「所有会话已注销，请重新登录」的 toast **永不触发**。 |
| **M7** | **DataTable 渲染全部页码按钮** | `DataTable.tsx:159` | `Array.from({ length: pages }, (_, i) => i)`。按 Dashboard 自述的 1,248 个邮箱、每页 10 条计算 = **125 个按钮**一次性铺在页脚。应改为窗口式 `« ‹ 1 … 5 › »`。 |
| **M8** | **mock 生产包内置硬编码 TOTP 密钥** | `client.ts:295` | 实测 `dist/assets/index-*.js`（531 KB）中含 `mock2fa.secret = "JBSWY3DPEHPK3PXP"` 及全套 mock 数据与 mock 登录分支（`123456` → 假两步验证）。 |
| **M9** | **「保持登录」复选框完全无效** | `Login.tsx:63,236` | `keep` 只有 `useState` + `checked`/`onChange`，**从不参与任何请求构造**。用户勾选/取消毫无作用，是会误导用户的死控件。 |

---

## 3. 低危问题

### 3.1 死代码与功能缺失

| 位置 | 问题 |
|---|---|
| `ui.tsx:79` | `Segmented` 组件（含 `layoutId` 胶囊动画）**从未被任何页面引用** |
| `client.ts:84` | `isReady()` 从未被调用（`modeReady` 形同虚设） |
| `client.ts:179,185,186,192,193` | REST 映射 `status.relay` / `metrics.realtime` / `metrics.telemetry` / `backups.list` / `backup.restore` 均无页面调用。**后端已有完整 backup CRUD**（`contract.rs:349-354`，含 create/restore/delete），前端**没有备份页面** |
| `tsconfig.json:16-17` | `noUnusedLocals` / `noUnusedParameters` 关闭，已藏住未使用的 `IconSearch` 导入（`MailQueue.tsx:10`）。建议开启 |
| `MailQueue.tsx:90,170` | `timeRange` state 从不参与查询构造，纯装饰性下拉框 |
| `MailQueue.tsx:108` | `toast(op === "delete" ? "OK" : "OK")` —— 三元两侧字面量相同 |
| `Dashboard.tsx:415` | 延迟图与资源图共用同一个 `resRange` state，改一个连带另一个 |

### 3.2 可访问性

| 位置 | 问题 |
|---|---|
| `DataTable.tsx:109` | 排序 `<th onClick>` **仅鼠标可达**：设了 `aria-sort` 但元素不可聚焦、无 `onKeyDown`。应改为内嵌 `<button>` 或补 `tabIndex=0` + Enter/Space |
| `App.tsx:286-293` | `ScrollRail` 设 `aria-hidden={!visible}` + `pointerEvents:none`，但内部 `<button>` **仍可 Tab 聚焦** → 焦点会进入一个视觉上不可见的工具栏 |
| `ui.tsx:91-129` | `Segmented` 用 `role="tablist"` / `role="tab"` 但无 `tabpanel`、无方向键导航、无 `aria-controls` |
| `InputDialog.tsx` | 手写 dialog：无焦点陷阱、不响应 Esc、无 `RDialog.Title`；而同项目 `ConfirmDialog`（`ui.tsx:212`）用 Radix 自带陷阱。行为不一致 |
| `DataTable.tsx:159-174` | 分页按钮 `aria-label={\`page ${i+1}\`}` 为英文硬编码，未走 i18n |

### 3.3 React 实现实践

| 位置 | 问题 |
|---|---|
| `ui.tsx:90` | `useState(() => \`seg-${Math.random().toString(36).slice(2)}\`)[0]` 当稳定 layoutId 用 → 应改 `useId()` |
| `ui.tsx:273` | `globalPush = push` 在**渲染期**赋值（渲染副作用），StrictMode 下会重复执行 → 应移入 `useEffect` |
| `useViewport.ts:10` | 裸 `resize` 监听无节流/防抖，每像素变化都触发整棵树重渲染 |
| `DataTable.tsx:47-66` | `filtered` 的 `useMemo` 依赖 `columns` 与 `filterKeys`，而两者在各页面 render 时均为新建数组字面量 → **memo 永久失效**，等同未缓存 |
| `DataTable.tsx:42` | `sort`/`query`/`page` 状态在 `rows` 变化（如删除末页最后一条）后不重置越界页码，靠 `:69` 的 `safePage` 兜底，可接受但应显式 `useEffect` 修正 |
| `CommandPalette.tsx:57` | `items.length === 0` 时 `Math.min(-1, i+1)` 得 `idx = -1` → `items[-1]` 为 undefined，Enter 静默失效 |
| `AiSuite.tsx:46-56` | `providerOptions` 是**无 memo 的 IIFE**，每次 render 重建数组 → `GlassSelect`（`ui.tsx:134`）永远拿到新 `options` 引用 |

### 3.4 其他

| 位置 | 问题 |
|---|---|
| `client.ts:45,63,106`、`Login.tsx:31` | 相对路径 `api/...` 与 `REST` 表中绝对路径 `/api/...` **混用**。当前 hash 路由在 `/` 下无害，但配合后端 SPA fallback（`crates/web/src/assets.rs:42-43`）或子路径挂载即失效 |
| `client.ts:99-123` | `bridge()` 未显式声明 `credentials`（同源默认携带，行为正确），但与 `restCall` 的 `credentials:"same-origin"` 风格不一致，易被后续改动踩坑 |
| `client.ts:207` | `restCall` 对 GET 请求也发 `Content-Type: application/json`（同源无害，但语义错误，且一旦跨域会触发预检） |
| `i18n.ts:266` | `s.replace(\`{${k}}\`, ...)` 只替换**首个**占位符。当前仅 `total_items` 用到，暂无影响 |
| `Toolbar.tsx:161-179` | 通知列表 3 条为硬编码常量，红点恒亮；`:158` "全部已读"按钮**无 `onClick`** |
| `Toolbar.tsx:224,234` | 管理员名 `admin` 与邮箱 `admin@example.com` 硬编码，不读 `admin.get`（`AccountSecurity.tsx:30` 已经在读了，两处不一致） |
| `Dashboard.tsx:630-641` | `QueueBar` 的 `width` 恒为 `"0%"`，右侧百分比恒为 `"100%"` —— 永远不反映真实比例，等于两个占位符 |
| `client.ts:1-8`、`API.md:3,133,137` | 注释指向不存在的 `crates/admin-web` / `crates/common/src/{rpc,actions}.rs`。实际路径为 `crates/web`（crate `mailstack-web`）与 `crates/core/src/actions.rs` |
| `MailQueue.tsx:3` | `MailQueue` 与 `Logs` 双向 import 关系经由 `Logs.tsx → MailQueue` 单向，无环；但 `Dashboard.tsx:17` 从页面模块 import `normalizeLog`，把页面当工具库用，建议抽到 `lib/` |

---

## 4. 后端契约核对（交叉验证结论）

由独立子代理对 `crates/web` / `crates/core` / `bin/mailstack-web` 做全量核对，
**以下前端假设经核实与后端一致**（这部分做得很好，予以确认）：

| 项 | 结论 |
|---|---|
| `setup.*` 六个动作的请求字段与响应形状 | ✅ 完全对齐（`Setup.tsx` vs `crates/priv/src/readers.rs:1713-1991`） |
| `setup.cert.issue` 的 `cert` 字段 | ✅ 前端只展示后端真实返回的字段，未编造 SAN / keySize / autoRenew |
| `users.add` 返回裸数组 | ✅ 前端已按裸数组处理（`Setup.tsx:541`） |
| `settings.get` 字段收窄 | ✅ 前端只提交 `hostname` / `adminEmail`（`Settings.tsx:19`），未提交后端会丢弃的键 |
| `logs.list` 的 `entries` 提取 | ✅ `pickList("entries","logs")` 正确 |
| REST 裸对象 vs RPC `{ok,data}` 信封区分 | ✅ 正确 |
| `{ok,data}` / `{ok,error:string}` 桥接协议 | ✅ 与 `crates/web/src/error.rs:127-158` 一致 |
| 路径遍历防护 / 安全响应头（CSP、X-Frame-Options、nosniff、no-referrer、COOP） | ✅ 后端 `crates/web/src/lib.rs:105-131` 全量设置，适用所有响应 |

**发现的契约缺口（前端侧）**：§1.4（`security.scan` 方法）、§2 M5（`sessions.list` 字段）、
M6（`admin.set` 字段名）。建议在 `client.ts` 的 `REST` 表旁加注释标注每条映射的契约出处，
便于下次后端改契约时能被立刻发现。

---

## 5. 经核实**推翻**的疑似问题（不计缺陷）

审计过程中提出但回源码核实后确认**不成立**的 3 条，记录在此避免后续重复排查：

| 疑似问题 | 核实结论 |
|---|---|
| `Relay.tsx:45` 注释称 `tlsMode` 只接受 `SSL-TLS`，而 `:50` 发送 `SSL/TLS`，会导致 465 中继被拒 | **注释错、代码对**。`crates/smtp/src/validate.rs:16,82` 确认后端枚举值就是 `"SSL/TLS"`（斜杠）。仅需订正注释 |
| 后端会话 cookie 用 `__Host-` 前缀但在 HTTP 部署下不带 `Secure`，浏览器会丢弃 | 属后端部署配置问题（`session.rs:63-80`），非前端缺陷，已超出本次审计范围 |
| `client.ts:582-585` `settings.set` 的 `k in db.settings` 存在 prototype 污染 | 仅 mock 模式、且 `data` 由前端自身构造，攻击者无法控制输入。实际不可达，不构成漏洞 |

---

## 6. 修复优先级建议

### 立即修（用户可见 + 导致误判）

1. **§1.1** — 探测失败改为 fail-closed 错误页；生产构建用 `import.meta.env.DEV` 剥离 mock 分支
   （一行门控可同时消除 §2.8 与 `?mock=1`）。
2. **§1.2** — 删除 `Toolbar.tsx:119,127,139,211` 的 4 个多余 `!`（保留 `Settings.tsx:321`），
   刷新按钮立即恢复。
3. **§1.3 + §1.4** — 删除安全页与仪表盘的硬编码状态、缺数据显示 `—`；`security.scan` 改 POST。

### 短期修（功能失效 / 会话安全）

4. **§2 M1** — `toastLogout()` 内补 `await rpc("auth.logout", {})`。
5. **§2 M2 + M3** — 启动时调 `GET /api/auth/session` 恢复登录态与 csrf；两条传输路径统一把
   401 与 403 都视为未授权。
6. **§2 M4 + M5 + M6** — 按后端真实字段名对齐 2FA / 会话 / 管理员账户三处契约。
7. **§2 M7** — 页码改窗口式。

### 清理

8. 开启 `noUnusedLocals`；删除 `Segmented` / `isReady` / 5 个无调用 REST 映射与 `IconSearch` 导入；
   订正 `Relay.tsx:45` 与 `client.ts:1-8` 的注释。

---

## 7. 复核方法（供后续验证）

本报告的每条结论均可用以下方式复现：

```powershell
cd webui
npm run build          # 通过（tsc --noEmit 无错）
```

- **§1.1 / §1.2**：构建后 `vite preview`，浏览器访问时会直接进入控制台（无登录页）；
  `getComputedStyle` 检查上述 4 个元素的 `display` 均为 `none`、`getBoundingClientRect` 为 0×0。
- **§1.2**：在 `dist/assets/*.css` 中检索 `display:none!important` 与 `.sm\:inline-flex`，
  确认后者无 `!important`。
- **§1.4**：`crates/web/src/lib.rs:343` 为 `post(...)`，`contract.rs:151` 为 `"POST"`，
  与 `client.ts:189` 的 `"GET"` 对照。
- **§2 M8**：在 `dist/assets/index-*.js` 中检索 `JBSWY3DPEHPK3PXP`，命中。
- **§2 M1**：`grep -rn "auth.logout" webui/src` 仅命中 `client.ts:200` 的映射定义本身。

---

*本报告由 AI 审计生成，所有结论均已回源码核实；标注「实测」者为浏览器真实观测。
如发现误报，请以源码为准并更新本文档。*
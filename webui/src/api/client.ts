// MailStack API 层 —— 与 Rust 后端（crates/web，crate 名 mailstack-web）衔接。
//
// 契约真相源（前端不得凭空假设）：
//   * 方法/路径/动作名：crates/web/src/contract.rs 的契约表
//   * axum 路由注册：  crates/web/src/lib.rs（`/api/*`）
// 传输层两种形态，由启动探测决定：
//   * rest —— 契约表里的 REST 端点（写操作带 x-csrf-token；登录响应体携带 csrf）
//   * rpc  —— POST /api/rpc 桥，帧协议透传 helper socket（crates/core/src/actions.rs 白名单）
//
// **fail-closed**：后端不可达（探活失败）时 mode = "unreachable"，由 App 渲染明确的
// 错误页 + 重试入口，绝不静默降级成假数据。mock 只存在于开发构建
// （`import.meta.env.DEV`），生产包中被整块剔除 —— 见 WEBUI_AUDIT §1.1 / §2.8。

export type RpcResult<T> = { ok: true; data: T } | { ok: false; error: string };

/** live = 后端可用；mock = 仅开发构建的演示模式；unreachable = 探活失败（fail-closed）。 */
export type Mode = "live" | "mock" | "unreachable";

let mode: Mode = "unreachable";
// 传输层：rest = 后端 REST 端点（CSRF 保护）；rpc = POST /api/rpc 桥（helper socket）
let transport: "rest" | "rpc" = "rpc";
let csrf = "";
const modeListeners = new Set<(m: Mode) => void>();

export function getMode(): Mode {
  return mode;
}
export function onModeChange(fn: (m: Mode) => void): () => void {
  modeListeners.add(fn);
  return () => modeListeners.delete(fn);
}
function setMode(m: Mode) {
  if (mode !== m) {
    mode = m;
    modeListeners.forEach((fn) => fn(m));
  }
}

const urlParams =
  typeof location !== "undefined"
    ? new URLSearchParams(location.search)
    : new URLSearchParams();

/**
 * 探活 `/api/health`。超时 6s（原 1.5s 在慢启动/高负载时会把可用后端误判为不可达，
 * 再叠加静默 mock 就变成「故障时看起来一切正常」）。
 */
async function probe(): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch("/api/health", { signal: ctrl.signal, credentials: "same-origin", cache: "no-store" });
    clearTimeout(timer);
    if (!res.ok) return false;
    const body = (await res.json()) as { ok?: boolean };
    return body?.ok === true;
  } catch {
    return false;
  }
}

/** 登录 / 会话恢复成功后捕获 CSRF token（写操作回传 x-csrf-token 头）。 */
export function captureCsrf(token?: string) {
  if (typeof token === "string") csrf = token;
}

/** 会话失效后必须清掉内存中的 CSRF，否则后续写操作仍会带一个已被吊销的 token。 */
export function resetCsrf() {
  csrf = "";
}

async function detectTransport() {
  try {
    const res = await fetch("/api/setup/status", { credentials: "same-origin", cache: "no-store" });
    // 404/405 = 端点不存在 → 无 REST 后端，走 RPC 桥；200/401 等视为 REST 可用
    transport = res.status === 404 || res.status === 405 ? "rpc" : "rest";
  } catch {
    transport = "rpc";
  }
}

/**
 * 启动时调用一次：决定 live / unreachable（开发构建额外允许 ?mock=1）。
 * 探活失败 → unreachable，由 App 显示错误页，**不再降级到 mock**。
 */
export async function initApi(): Promise<Mode> {
  if (import.meta.env.DEV && urlParams.get("mock") === "1") {
    setMode("mock");
    return mode;
  }
  if (!(await probe())) {
    setMode("unreachable");
    return mode;
  }
  await detectTransport();
  setMode("live");
  return mode;
}

/**
 * 破坏性动作（前端动作名）。后端 ActionGate（crates/priv/src/dispatch.rs）对这些
 * 动作强制要求载荷携带严格布尔 `confirm: true`，否则一律拒绝（CONFIRMATION_REQUIRED）
 * 且不产生任何副作用。这里在传输层统一注入：调用方（Domains/Users/AccountSecurity
 * 的 ConfirmDialog 流程）已各自先弹确认框，注入只是把「用户已在弹窗里确认」落到
 * 线上载荷 —— 没有弹窗的动作绝不进这个集合（绝不自动确认）。
 */
const DESTRUCTIVE_ACTIONS = new Set(["domains.delete", "users.delete", "admin.2fa.disable"]);

/**
 * 前端内部动作名 → 后端动作名（仅 RPC 桥路径需要）。
 *
 * 契约真相源（crates/web/src/contract.rs）：`POST /api/admin/2fa/disable` 静态绑定
 * 的动作是 `admin.totp.disable`，桥的放行集由契约表推导（is_exposed_action）——
 * 前端键 `admin.2fa.disable` 未登记，原样上桥会被整条拒掉。REST 路径按路径匹配
 * 契约，不受影响；mock 分发按前端键走，也不受影响。
 */
const BRIDGE_ACTION_ALIAS: Record<string, string> = {
  "admin.2fa.disable": "admin.totp.disable",
  "admin.2fa.begin": "admin.totp.begin",
  "admin.2fa.enable": "admin.totp.enable",
};

/** 核心 RPC 调用 —— action 名与 crates/core/src/actions.rs 白名单一致。 */
export async function rpc<T = unknown>(action: string, data?: object): Promise<RpcResult<T>> {
  // 生产构建里 import.meta.env.DEV 是 false，这一整支 + mockDispatch 全部被剔除
  if (import.meta.env.DEV && mode === "mock") {
    if (!mockDispatch) return { ok: false, error: "mock dispatcher is unavailable" };
    return (await mockDispatch(action, (data ?? {}) as Record<string, unknown>)) as RpcResult<T>;
  }
  const d = (data ?? {}) as Record<string, unknown>;
  // 破坏性动作：无论走 REST 还是桥，载荷统一携带 confirm: true（见 DESTRUCTIVE_ACTIONS）。
  if (DESTRUCTIVE_ACTIONS.has(action)) d.confirm = true;
  if (transport === "rest") return restCall<T>(action, d);
  return bridge<T>(action, d);
}

/** RPC 桥：POST /api/rpc → helper socket（原样透传 {action,data} / {ok,data|error}） */
async function bridge<T>(action: string, data: object): Promise<RpcResult<T>> {
  try {
    // 桥按**动作名**放行（契约表推导的 is_exposed_action）：别名表先把前端键
    // 归一成后端登记名，未登记的键会被后端直接 400 unknown action。
    const wireAction = BRIDGE_ACTION_ALIAS[action] ?? action;
    // 后端对所有非 GET 请求强制校验 x-csrf-token（缺了回 403），因此 RPC 桥
    // 必须与 restCall 一样回传该头；否则所有经桥的动作（setup.* / ai.* /
    // security.* / dkim.* / users.password 等）都会被拒。
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (csrf) headers["x-csrf-token"] = csrf;
    const res = await fetch("/api/rpc", {
      method: "POST",
      headers,
      // 与 restCall 保持一致：显式声明同源携带 Cookie（会话是 HttpOnly Cookie）
      credentials: "same-origin",
      cache: "no-store",
      body: JSON.stringify({ action: wireAction, data }),
    });
    if (res.status === 401 || res.status === 403) {
      resetCsrf();
      window.dispatchEvent(new CustomEvent("mailstack:unauthorized"));
      return { ok: false, error: "unauthorized" };
    }
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const body = (await res.json()) as { ok: boolean; data?: T; error?: string };
    if (body.ok) return { ok: true, data: body.data as T };
    return { ok: false, error: body.error ?? "unknown error" };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** REST 端点映射 —— 方法/路径逐条对齐 crates/web/src/contract.rs（axum 注册见 lib.rs）。 */
type RestSpec = {
  method: "GET" | "POST" | "DELETE";
  path: (d: Record<string, unknown>) => string;
  body?: (d: Record<string, unknown>) => unknown;
  pick?: (j: unknown) => unknown;
};
const pickList =
  (...keys: string[]) =>
  (j: unknown) => {
    if (Array.isArray(j)) return j;
    const o = j as Record<string, unknown>;
    for (const k of keys) if (Array.isArray(o?.[k])) return o[k];
    return o?.data ?? o;
  };

const REST: Record<string, RestSpec> = {
  snapshot: { method: "GET", path: () => "/api/snapshot" },
  "settings.get": { method: "GET", path: () => "/api/settings" },
  "settings.set": { method: "POST", path: () => "/api/settings", body: (d) => d },
  "domains.list": { method: "GET", path: () => "/api/domains", pick: pickList("domains") },
  "domains.add": { method: "POST", path: () => "/api/domains", body: (d) => ({ domain: d.domain }) },
  // 破坏性删除：后端 ActionGate 要求载荷 confirm: true（严格布尔）。DELETE 的
  // JSON body 由 restCall 正常携带（非 GET 一律带 Content-Type + CSRF 头，
  // axum 侧 json_payload 接受带主体的 DELETE），域名/地址本身在路径参数里
  // （后端 run_action 会把 :id 并入载荷，不覆盖显式 body 字段）。
  "domains.delete": {
    method: "DELETE",
    path: (d) => "/api/domains/" + encodeURIComponent(String(d.domain)),
    body: (d) => ({ confirm: d.confirm === true }),
  },
  "users.list": { method: "GET", path: () => "/api/users", pick: pickList("users") },
  "users.add": { method: "POST", path: () => "/api/users", body: (d) => d },
  // 同 domains.delete：confirm 由 rpc() 注入 d，body 显式落字段。
  "users.delete": {
    method: "DELETE",
    path: (d) => "/api/users/" + encodeURIComponent(String(d.address)),
    body: (d) => ({ confirm: d.confirm === true }),
  },
  "users.status": { method: "POST", path: () => "/api/users/status", body: (d) => ({ address: d.address, active: d.active }) },
  "aliases.list": { method: "GET", path: () => "/api/aliases", pick: pickList("aliases") },
  "aliases.add": { method: "POST", path: () => "/api/aliases", body: (d) => d },
  // 显式 `{}`：声明了 JSON Content-Type 的 DELETE 若不带主体，后端 json_payload
  // 会对空 body 的 JSON 解析报 400（aliases.delete 是最后一个踩这个坑的映射）。
  "aliases.delete": {
    method: "DELETE",
    path: (d) => "/api/aliases/" + encodeURIComponent(String(d.source)),
    body: () => ({}),
  },
  "certs.list": { method: "GET", path: () => "/api/certificates", pick: pickList("certificates", "certs") },
  "certs.renew": { method: "POST", path: () => "/api/certificates/renew", body: (d) => ({ domain: d.domain }) },
  // 契约：POST /api/dkim/rotate → dkim.rotate；GET /api/dkim/keys → dkim.keys（裸数组）；
  // GET /api/dns/records → dns.records（裸数组）。
  "dkim.rotate": { method: "POST", path: () => "/api/dkim/rotate", body: (d) => d },
  "dkim.keys": { method: "GET", path: () => "/api/dkim/keys" },
  "dns.records": { method: "GET", path: () => "/api/dns/records" },
  // 后端 GET /api/logs 返回 { ok, available, lines, unit, entries:[...] }，
  // 日志条目在 entries 下（不是 logs），pickList 需按该键取数组。
  "logs.list": { method: "GET", path: () => "/api/logs", pick: pickList("entries", "logs") },
  "queue.action": { method: "POST", path: () => "/api/queue/action", body: (d) => ({ id: d.id, op: d.op }) },
  // 契约（contract.rs）：GET /api/queue → queue.list，返回**裸数组**；条目 status
  // 只有 sending / pending 两种（active/deferred 在 readers.rs queue_list 里映射）。
  "queue.list": { method: "GET", path: () => "/api/queue" },
  "services.list": { method: "GET", path: () => "/api/services" },
  "services.action": { method: "POST", path: () => "/api/services/action", body: (d) => ({ key: d.key, op: d.op }) },
  "setup.status": { method: "GET", path: () => "/api/setup/status" },
  // 向导收尾（contract.rs 72→73 新增）：置位 setup.json 的 wizardCompleted，幂等；
  // 响应与 setup.status 同形（含 completed）。显式发空对象 body：POST 不带 body
  // 时 axum 的 Json 提取器会因「Content-Type: json 但空载荷」拒绝。
  "setup.wizard.complete": { method: "POST", path: () => "/api/setup/wizard/complete", body: () => ({}) },
  "admin.set": { method: "POST", path: () => "/api/admin", body: (d) => ({ username: d.username, password: d.password || undefined }) },
  "admin.2fa.status": { method: "GET", path: () => "/api/admin/2fa" },
  "admin.2fa.begin": { method: "POST", path: () => "/api/admin/2fa/begin", body: (d) => ({ code: d.code ?? "" }) },
  "admin.2fa.enable": { method: "POST", path: () => "/api/admin/2fa/enable", body: (d) => ({ code: d.code }) },
  // 关 2FA 是破坏性动作（actions.rs DESTRUCTIVE_ACTIONS：secret 与恢复码一并作废）：
  // body 必须 { code, confirm: true }，否则后端回 CONFIRMATION_REQUIRED。
  "admin.2fa.disable": {
    method: "POST",
    path: () => "/api/admin/2fa/disable",
    body: (d) => ({ code: d.code, confirm: d.confirm === true }),
  },
  "sessions.list": { method: "GET", path: () => "/api/auth/sessions", pick: pickList("sessions") },
  // 契约：revoke 只认单个指纹 `{id}`（routes.rs revoke_session）；吊销「其他」走 DELETE。
  "sessions.revoke": { method: "POST", path: () => "/api/auth/sessions/revoke", body: (d) => ({ id: d.id }) },
  // 后端「注销其他会话」是 DELETE /api/auth/sessions（revoke 端点只认单个 id）。
  "sessions.revokeOthers": { method: "DELETE", path: () => "/api/auth/sessions" },
  "ai.config": { method: "POST", path: () => "/api/ai/config", body: (d) => d },
  // 页面实际调用的动作名（ai.config.set）：后端 POST /api/ai/config 响应是
  // ai_public_config（provider/model/baseUrl/hasKey/maskedKey/configured，无明文 key）。
  "ai.config.set": { method: "POST", path: () => "/api/ai/config", body: (d) => d },
  "ai.config.get": { method: "GET", path: () => "/api/ai/config" },
  "ai.models.list": { method: "GET", path: () => "/api/ai/models", pick: pickList("models") },
  "ai.test": { method: "POST", path: () => "/api/ai/test", body: (d) => d },
  "relay.test": { method: "POST", path: () => "/api/setup/relay/test", body: (d) => d },
  // Setup 向导用的是长名动作；同一后端路由，避免它绕道 /api/rpc 桥双跳。
  "setup.relay.test": { method: "POST", path: () => "/api/setup/relay/test", body: (d) => d },
  "relay.apply": { method: "POST", path: () => "/api/setup/relay/apply", body: (d) => d },
  // 页面实际调用的动作名（setup.relay.apply，同一路由）。载荷 {direct: true} 是
  // 撤销语义：清除中继回直投，响应 {applied, mode:"direct", relayhost:"", wrappermode:false}。
  "setup.relay.apply": { method: "POST", path: () => "/api/setup/relay/apply", body: (d) => d },
  "network.check_port": { method: "POST", path: () => "/api/network/check-port", body: (d) => ({ port: d.port, host: d.host }) },
  "setup.identity.apply": { method: "POST", path: () => "/api/setup/identity", body: (d) => d },
  "setup.dns.verify": { method: "POST", path: () => "/api/setup/dns/verify", body: (d) => d },
  "setup.cert.issue": { method: "POST", path: () => "/api/setup/cert/issue", body: (d) => d },
  "setup.mail.test": { method: "POST", path: () => "/api/setup/mail/test", body: (d) => d },
  "mail.test_loopback": { method: "POST", path: () => "/api/mail/test-loopback", body: (d) => d },
  "metrics.system": { method: "GET", path: () => "/api/metrics/system" },
  "system.doctor": { method: "GET", path: () => "/api/system/doctor", pick: pickList("checks", "items") },
  // 后端只注册了 POST（contract.rs:150-155 / lib.rs:394）；写成 GET 会拿到空 body 的 405。
  // 显式发 `{}`：声明了 JSON Content-Type 却不带主体的 POST 会被后端 json_payload 判 400。
  "security.scan": { method: "POST", path: () => "/api/security/scan", body: () => ({}) },
  "security.ban": { method: "POST", path: () => "/api/security/ban", body: (d) => d },
  "security.unban": { method: "POST", path: () => "/api/security/unban", body: (d) => ({ ip: d.ip }) },
  "users.password": { method: "POST", path: () => "/api/users/password", body: (d) => d },
  "admin.get": { method: "GET", path: () => "/api/admin" },
  "ai.chat": { method: "POST", path: () => "/api/ai/dns-chat", body: (d) => d },
  "ai.diagnose": { method: "POST", path: () => "/api/ai/diagnose-dns", body: (d) => d },
  "activity.list": { method: "GET", path: () => "/api/activity", pick: pickList("activity", "items") },
  // 会话生命周期：GET 恢复 csrf/登录态，POST 让服务端吊销会话（否则「退出」只清前端）。
  "auth.session": { method: "GET", path: () => "/api/auth/session" },
  "auth.logout": { method: "POST", path: () => "/api/auth/logout" },
};

async function restCall<T>(action: string, data: Record<string, unknown>): Promise<RpcResult<T>> {
  const spec = REST[action];
  if (!spec) return bridge<T>(action, data); // 无映射的动作回退 RPC 桥
  try {
    // GET 不带 Content-Type（语义错误，跨域时还会触发预检）；写操作才带 CSRF 头。
    const headers: Record<string, string> = spec.method === "GET" ? {} : { "Content-Type": "application/json" };
    if (spec.method !== "GET" && csrf) headers["x-csrf-token"] = csrf;
    const res = await fetch(spec.path(data), {
      method: spec.method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      body: spec.body ? JSON.stringify(spec.body(data)) : undefined,
    });
    // 401（会话失效）与 403（CSRF 失效 / 权限不足）都必须触发全局登出，
    // 否则用户会被一句 "missing or invalid CSRF token" toast 卡死在页面内。
    if (res.status === 401 || res.status === 403) {
      resetCsrf();
      window.dispatchEvent(new CustomEvent("mailstack:unauthorized"));
      return { ok: false, error: "unauthorized" };
    }
    const j = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      const e = j.error as { message?: string } | string | undefined;
      const msg = typeof e === "object" && e?.message ? e.message : typeof e === "string" ? e : (j.message as string) ?? `HTTP ${res.status}`;
      return { ok: false, error: msg };
    }
    const payload = (spec.pick ? spec.pick(j) : j) as T;
    return { ok: true, data: payload };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/* ---------------- Mock 数据集（仅开发构建存在） ---------------- */

type MockDispatch = (action: string, data: Record<string, unknown>) => Promise<RpcResult<unknown>>;
let mockDispatch: MockDispatch | null = null;

// 生产构建中 import.meta.env.DEV === false，本块是死代码：连同硬编码 TOTP 密钥、
// mock 登录分支与全部演示数据一起被剔除（WEBUI_AUDIT §1.1 / §2.8），`?mock=1` 同时失效。
if (import.meta.env.DEV) {

type DomainRow = {
  domain: string;
  active: boolean;
  mailboxes: number;
  delivered: number;
  success: number;
  createdAt: string;
};
type UserRow = {
  address: string;
  name: string;
  active: boolean;
  quotaUsed: number;
  quotaTotal: number;
  createdAt: string;
};
type AliasRow = { source: string; target: string; active: boolean; createdAt: string };
type QueueRow = {
  id: string;
  sender: string;
  recipient: string;
  domain: string;
  status: "delivered" | "sending" | "failed" | "pending" | "hold";
  retry: number;
  time: string;
  service: string;
};
type LogRow = {
  id: string;
  time: string;
  level: "info" | "warn" | "error";
  service: string;
  message: string;
  from?: string;
  to?: string;
  domain?: string;
  retry?: number;
};
type CertRow = {
  domain: string;
  issuer: string;
  keySize: number;
  notAfter: string;
  daysLeft: number;
  autoRenew: boolean;
};
type ServiceRow = { key: string; running: boolean; detail: string };
type BanRow = { ip: string; reason: string; until: string; fails: number };

function daysAgo(n: number, hh = 9, mm = 30): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  d.setHours(hh, mm, 0, 0);
  return fmtTime(d);
}
function fmtTime(d: Date): string {
  const p = (x: number) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const mock2fa = { enabled: false, secret: "JBSWY3DPEHPK3PXP", codes: [] as string[] };
const mockSessions = [
  { id: "s-current", current: true, ip: "203.0.113.7", userAgent: "Chrome · Windows", lastActive: "10:24" },
  { id: "s-2", current: false, ip: "198.51.100.23", userAgent: "Safari · macOS", lastActive: "09:12" },
  { id: "s-3", current: false, ip: "192.0.2.101", userAgent: "Edge · Windows", lastActive: "昨天 21:40" },
];

const db = {
  domains: [
    { domain: "example.com", active: true, mailboxes: 320, delivered: 1280, success: 99.2, createdAt: daysAgo(212) },
    { domain: "mailstack.io", active: true, mailboxes: 216, delivered: 864, success: 98.7, createdAt: daysAgo(180) },
    { domain: "test.org", active: true, mailboxes: 96, delivered: 452, success: 97.1, createdAt: daysAgo(96) },
    { domain: "relay.example.net", active: true, mailboxes: 0, delivered: 0, success: 0, createdAt: daysAgo(90) },
    { domain: "corp.example.com", active: true, mailboxes: 578, delivered: 996, success: 99.4, createdAt: daysAgo(75) },
    { domain: "news.example.com", active: true, mailboxes: 0, delivered: 120, success: 96.8, createdAt: daysAgo(60) },
    { domain: "legacy.example.org", active: false, mailboxes: 38, delivered: 0, success: 0, createdAt: daysAgo(400) },
    { domain: "sandbox.dev", active: false, mailboxes: 0, delivered: 0, success: 0, createdAt: daysAgo(30) },
  ] as DomainRow[],
  users: [
    { address: "user@example.com", name: "示例用户", active: true, quotaUsed: 12.4, quotaTotal: 25, createdAt: daysAgo(200) },
    { address: "admin@mailstack.io", name: "Admin", active: true, quotaUsed: 8.1, quotaTotal: 50, createdAt: daysAgo(220) },
    { address: "test@test.org", name: "测试账户", active: true, quotaUsed: 3.9, quotaTotal: 10, createdAt: daysAgo(150) },
    { address: "sales@example.com", name: "销售组", active: true, quotaUsed: 18.2, quotaTotal: 25, createdAt: daysAgo(120) },
    { address: "noreply@news.example.com", name: "通知发送", active: true, quotaUsed: 1.2, quotaTotal: 5, createdAt: daysAgo(90) },
    { address: "hr@corp.example.com", name: "人事部", active: true, quotaUsed: 6.7, quotaTotal: 25, createdAt: daysAgo(80) },
    { address: "legacy@legacy.example.org", name: "旧系统", active: false, quotaUsed: 0, quotaTotal: 5, createdAt: daysAgo(390) },
    { address: "dev@sandbox.dev", name: "沙箱", active: false, quotaUsed: 0, quotaTotal: 2, createdAt: daysAgo(28) },
  ] as UserRow[],
  aliases: [
    { source: "postmaster@example.com", target: "admin@mailstack.io", active: true, createdAt: daysAgo(210) },
    { source: "abuse@example.com", target: "admin@mailstack.io", active: true, createdAt: daysAgo(210) },
    { source: "support@example.com", target: "sales@example.com", active: true, createdAt: daysAgo(160) },
    { source: "hr@corp.example.com", target: "hr-team@corp.example.com", active: true, createdAt: daysAgo(75) },
    { source: "info@test.org", target: "test@test.org", active: false, createdAt: daysAgo(95) },
  ] as AliasRow[],
  queue: [
    { id: "q-8f31", sender: "user1@example.com", recipient: "test@domain.com", domain: "example.com", status: "delivered", retry: 0, time: "2026-09-29 14:32:10", service: "smtp" },
    { id: "q-8f32", sender: "admin@mailstack.io", recipient: "user1@company.com", domain: "mailstack.io", status: "sending", retry: 1, time: "2026-09-29 14:28:44", service: "smtp" },
    { id: "q-8f33", sender: "notice@system.com", recipient: "user2@domain.com", domain: "domain.com", status: "failed", retry: 3, time: "2026-09-29 14:26:48", service: "smtp" },
    { id: "q-8f34", sender: "support@help.com", recipient: "client1@client.com", domain: "client.com", status: "delivered", retry: 0, time: "2026-09-29 14:21:02", service: "smtp" },
    { id: "q-8f35", sender: "noreply@mailer.com", recipient: "user3@domain.com", domain: "example.com", status: "pending", retry: 0, time: "2026-09-29 14:18:37", service: "dovecot" },
    { id: "q-8f36", sender: "admin@mailstack.io", recipient: "test@test.com", domain: "test.org", status: "delivered", retry: 0, time: "2026-09-29 14:12:19", service: "smtp" },
    { id: "q-8f37", sender: "news@news.example.com", recipient: "sub@list.org", domain: "example.com", status: "hold", retry: 2, time: "2026-09-29 13:58:51", service: "smtp" },
    { id: "q-8f38", sender: "hr@corp.example.com", recipient: "all@corp.example.com", domain: "corp.example.com", status: "sending", retry: 0, time: "2026-09-29 13:52:05", service: "smtp" },
    { id: "q-8f39", sender: "bounce@system.com", recipient: "old@domain.com", domain: "domain.com", status: "failed", retry: 4, time: "2026-09-29 13:44:22", service: "smtp" },
    { id: "q-8f40", sender: "user@example.com", recipient: "friend@gmail.com", domain: "example.com", status: "delivered", retry: 0, time: "2026-09-29 13:40:03", service: "smtp" },
    { id: "q-8f41", sender: "bot@status.io", recipient: "ops@corp.example.com", domain: "corp.example.com", status: "pending", retry: 1, time: "2026-09-29 13:35:12", service: "dovecot" },
    { id: "q-8f42", sender: "sales@example.com", recipient: "lead@corp.com", domain: "example.com", status: "delivered", retry: 0, time: "2026-09-29 13:21:55", service: "smtp" },
  ] as QueueRow[],
  logs: [
    { id: "l-901", time: "2026-09-29 14:32:10", level: "info", service: "smtp", message: "250 2.0.0 Ok: queued as 4B8F2C1A9E", from: "user1@example.com", to: "test@domain.com", domain: "example.com", retry: 0 },
    { id: "l-902", time: "2026-09-29 14:28:44", level: "info", service: "smtp", message: "Sending via relay route[primary] conversation id 8F32", from: "admin@mailstack.io", to: "user1@company.com", domain: "mailstack.io", retry: 1 },
    { id: "l-903", time: "2026-09-29 14:26:48", level: "error", service: "smtp", message: "550 5.7.1 Relaying denied. Please use authenticated SMTP.", from: "noreply@system.com", to: "user@domain.com", domain: "domain.com", retry: 3 },
    { id: "l-904", time: "2026-09-29 14:22:31", level: "warn", service: "dovecot", message: "imap-login: Disconnected (auth failed, 2 attempts): user=<test>, rip=203.0.113.7", domain: "test.org" },
    { id: "l-905", time: "2026-09-29 14:21:02", level: "info", service: "smtp", message: "250 2.0.0 Ok: delivered to mailbox client1@client.com", from: "support@help.com", to: "client1@client.com", domain: "client.com", retry: 0 },
    { id: "l-906", time: "2026-09-29 14:18:37", level: "warn", service: "dovecot", message: "lmtp: connect to /run/dovecot/lmtp deferred: retry in 300s", domain: "example.com", retry: 0 },
    { id: "l-907", time: "2026-09-29 14:12:19", level: "info", service: "smtp", message: "TLS established with tls.test.com: TLS1.3 ECDHE-RSA-AES256-GCM", from: "admin@mailstack.io", to: "test@test.com", domain: "test.org", retry: 0 },
    { id: "l-908", time: "2026-09-29 13:58:51", level: "warn", service: "smtp", message: "Message held by policy filter (spam score 7.2 > 6.5)", from: "news@news.example.com", to: "sub@list.org", domain: "example.com", retry: 2 },
    { id: "l-909", time: "2026-09-29 13:44:22", level: "error", service: "smtp", message: "connect to mx.domain.com[198.51.100.9]: Connection timed out", from: "bounce@system.com", to: "old@domain.com", domain: "domain.com", retry: 4 },
    { id: "l-910", time: "2026-09-29 13:40:03", level: "info", service: "smtp", message: "250 2.0.0 Ok: queued as 77C1D0B4AA", from: "user@example.com", to: "friend@gmail.com", domain: "example.com", retry: 0 },
    { id: "l-911", time: "2026-09-29 13:35:12", level: "info", service: "dovecot", message: "quota warning: user ops@corp.example.com usage 87% (8.7/10 GB)", domain: "corp.example.com" },
    { id: "l-912", time: "2026-09-29 13:30:44", level: "error", service: "dkim", message: "DNSSEC validation failed for selector s1._domainkey.example.com", domain: "example.com" },
  ] as LogRow[],
  certs: [
    { domain: "mail.example.com", issuer: "Let's Encrypt R12", keySize: 2048, notAfter: daysAgo(-58), daysLeft: 58, autoRenew: true },
    { domain: "smtp.mailstack.io", issuer: "Let's Encrypt R12", keySize: 2048, notAfter: daysAgo(-23), daysLeft: 23, autoRenew: true },
    { domain: "imap.mailstack.io", issuer: "Let's Encrypt R12", keySize: 2048, notAfter: daysAgo(-23), daysLeft: 23, autoRenew: true },
    { domain: "webmail.test.org", issuer: "ZeroSSL ECC Domain", keySize: 384, notAfter: daysAgo(-6), daysLeft: 6, autoRenew: false },
  ] as CertRow[],
  services: [
    { key: "smtp", running: true, detail: "postfix/master" },
    { key: "imap", running: true, detail: "dovecot" },
    { key: "lmtp", running: true, detail: "dovecot-lmtp" },
    { key: "dkim", running: true, detail: "rspamd dkim signer" },
    { key: "fail2ban", running: true, detail: "fail2ban-server" },
    { key: "webmail", running: false, detail: "roundcube-fpm" },
    { key: "admin", running: true, detail: "mailstack-admin-web" },
  ] as ServiceRow[],
  bans: [
    { ip: "203.0.113.7", reason: "SMTP auth brute-force", until: "2026-09-30 14:22:00", fails: 42 },
    { ip: "198.51.100.23", reason: "IMAP auth brute-force", until: "2026-09-29 18:10:00", fails: 18 },
    { ip: "192.0.2.101", reason: "SPF/DNSBL listed relay attempt", until: "2026-09-29 16:40:00", fails: 7 },
  ] as BanRow[],
  settings: {
    serverName: "mail.example.com",
    hostname: "mx1.example.com",
    adminEmail: "admin@example.com",
    relayProvider: "direct",
    relayAuthUser: "",
    relayTls: "required",
    relayWeight: 100,
  },
  ai: {
    provider: "openai-compatible",
    model: "gpt-4o-mini",
    endpoint: "https://api.openai.com/v1",
    enabled: true,
  },
  notifications: [
    { id: "n1", level: "warn", time: "2026-09-29 14:22", text: "TLS 证书 webmail.test.org 将于 6 天后到期" },
    { id: "n2", level: "info", time: "2026-09-29 13:35", text: "邮箱 ops@corp.example.com 配额使用率已达 87%" },
    { id: "n3", level: "err", time: "2026-09-29 13:12", text: "检测到 3 次来自 203.0.113.7 的登录失败" },
  ],
};

function num(v: unknown, d: number): number {
  return typeof v === "number" && Number.isFinite(v) ? v : d;
}
function str(v: unknown, d: string): string {
  return typeof v === "string" && v.length > 0 ? v : d;
}

/** Mock 分发器 —— 与真实 action 语义一一对应（ mutations 同步内存库）。 */
async function dispatch(action: string, data: Record<string, unknown>): Promise<RpcResult<unknown>> {
  await new Promise((r) => setTimeout(r, 120 + Math.random() * 180)); // 真实网络感
  const d = data;
  switch (action) {
    case "snapshot":
      return ok({
        health: "healthy",
        version: "1.0.0",
        uptime: "24d 6h",
        domains: { total: db.domains.length, active: db.domains.filter((x) => x.active).length, disabled: db.domains.filter((x) => !x.active).length },
        users: { total: 1248, active: 1210, disabled: 38 },
        queue: { total: 23, pending: 23, sending: 12, failed: 1, deferred: 2, hold: 3, bounced: 8, delivered: 12 },
        smtp: { running: true, connections: 24, sentToday: 12483, successRate: 99.8, ports: [25, 465, 587], uptime: "24d 6h" },
        dovecot: { running: true, connections: 18, loggedIn: 12, successRate: 99.6, ports: [143, 993], uptime: "24d 6h" },
        latency: { range: "24h", points: latencySeries() },
        domainRows: db.domains.filter((x) => x.delivered > 0).slice(0, 3).map((x) => ({ domain: x.domain, delivered: x.delivered, success: x.success })),
        userRows: db.users.slice(0, 3).map((x, i) => ({ address: x.address, mailboxCount: Math.round(x.quotaTotal * 10), success: i === 2 ? 98.3 : 100 })),
        // 参考图 1 / 图 2 的仪表盘扩展契约
        serviceDist: { total: 8, running: 6, alert: 1, offline: 1 },
        resources: { cpu: 32, memory: 48, disk: 61 },
        healthPanel: {
          overall: 98,
          items: [
            { key: "smtp", label: "SMTP", status: "ok" },
            { key: "dovecot", label: "Dovecot", status: "ok" },
            { key: "queue", label: "queue", status: "ok" },
            { key: "database", label: "database", status: "ok" },
            { key: "disk", label: "disk", status: "ok", value: 78 },
          ],
        },
      }) as RpcResult<unknown>;
    case "activity.list":
      return ok([
        { kind: "user", title: "act_user_created", sub: "user@example.com", time: "10:24" },
        { kind: "domain", title: "act_domain_added", sub: "mailstack.io", time: "09:48" },
        { kind: "queue", title: "act_queue_processed", sub: "23 messages", time: "08:32" },
        { kind: "service", title: "act_service_restarted", sub: "Dovecot", time: "06:17" },
        { kind: "cert", title: "act_cert_renewed", sub: "Let's Encrypt", time: "01:03" },
      ]) as RpcResult<unknown>;
    case "metrics.system":
      return ok({ cpu: 32, memory: 48, disk: 61 }) as RpcResult<unknown>;
    case "metrics.realtime":
      return ok({ points: latencySeries(), ts: fmtTime(new Date()) }) as RpcResult<unknown>;
    case "system.doctor":
      return ok([
        { check: "postfix", ok: true, detail: "master.pid 存在，队列目录权限正常" },
        { check: "dovecot", ok: true, detail: "imap/lmtp 服务监听正常" },
        { check: "dns:mx", ok: true, detail: "mx1.example.com → 198.51.100.10" },
        { check: "dns:spf", ok: true, detail: '"v=spf1 mx -all" 已发布' },
        { check: "dns:dkim", ok: false, detail: "test.org 选择器 s1 未发布 TXT 记录" },
        { check: "cert", ok: false, detail: "webmail.test.org 6 天后到期" },
      ]) as RpcResult<unknown>;
    case "domains.list":
      return ok(db.domains) as RpcResult<unknown>;
    case "domains.add": {
      const domain = str(d.domain, "").toLowerCase();
      if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return err("invalid domain");
      // 真实后端 add_domain 是**幂等**的（同域名只是重写同一行，不报错）。
      // mock 原先对重复域名报错，会让向导第 1 步在已存在的域名上直接失败。
      if (!db.domains.some((x) => x.domain === domain))
        db.domains.unshift({ domain, active: true, mailboxes: 0, delivered: 0, success: 0, createdAt: fmtTime(new Date()) });
      // 真实响应是 { ok, domains: [名称…] }。
      return ok({ ok: true, domains: db.domains.map((x) => x.domain) }) as RpcResult<unknown>;
    }
    case "domains.delete": {
      const domain = str(d.domain, "");
      db.domains = db.domains.filter((x) => x.domain !== domain);
      return ok({ domain }) as RpcResult<unknown>;
    }
    case "users.list":
      return ok(db.users) as RpcResult<unknown>;
    case "users.add": {
      // 真实后端返回**裸数组**（Users::list() 的快照），不是 {address} 外壳；
      // 这里保持同形，免得 mock 掩盖了对响应形状的错误假设。
      const address = str(d.address || d.email, "").toLowerCase();
      const name = str(d.name ?? d.displayName, address.split("@")[0]);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) return err("invalid mailbox identity");
      // 与真实 users.add 一致：域名必须已在受管域名表里（向导第 1 步写入）。
      const mailDomain = address.split("@")[1] ?? "";
      if (!db.domains.some((x) => x.domain === mailDomain)) return err("mailbox domain is not managed");
      if (db.users.some((x) => x.address === address)) return err("mailbox already exists");
      // 后端要求口令且做强度校验（12–256、字母+数字、不含账号名或邮箱）；
      // mock 至少守住「不得为空」与「不得包含账号身份」这两条最常踩的。
      const password = str(d.password, "");
      if (!password) return err("password is required");
      const lowered = password.toLowerCase();
      if (lowered.includes(address) || (address.split("@")[0] && lowered.includes(address.split("@")[0])))
        return err("password must not contain the account name or email address");
      db.users.unshift({ address, name, active: true, quotaUsed: 0, quotaTotal: num(d.quota, 10), createdAt: fmtTime(new Date()) });
      return ok(db.users) as RpcResult<unknown>;
    }
    case "users.delete": {
      const address = str(d.address, "");
      db.users = db.users.filter((x) => x.address !== address);
      return ok({ address }) as RpcResult<unknown>;
    }
    case "users.status": {
      const u = db.users.find((x) => x.address === str(d.address, ""));
      if (!u) return err("用户不存在");
      u.active = d.active === true;
      return ok({ address: u.address, active: u.active }) as RpcResult<unknown>;
    }
    case "aliases.list":
      return ok(db.aliases) as RpcResult<unknown>;
    case "aliases.add": {
      const source = str(d.source, "").toLowerCase();
      const target = str(d.target, "").toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(source) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) return err("无效地址");
      db.aliases.unshift({ source, target, active: true, createdAt: fmtTime(new Date()) });
      return ok({ source, target }) as RpcResult<unknown>;
    }
    case "aliases.delete": {
      const source = str(d.source, "");
      db.aliases = db.aliases.filter((x) => x.source !== source);
      return ok({ source }) as RpcResult<unknown>;
    }
    case "certs.list":
      return ok(db.certs) as RpcResult<unknown>;
    case "certs.renew": {
      const c = db.certs.find((x) => x.domain === str(d.domain, ""));
      if (c) {
        c.daysLeft = 90;
        c.notAfter = daysAgo(-90);
      }
      return ok({ domain: d.domain, renewed: true }) as RpcResult<unknown>;
    }
    case "queue.list":
      return ok(db.queue) as RpcResult<unknown>;
    case "queue.action": {
      const id = str(d.id, "");
      const q = db.queue.find((x) => x.id === id);
      const act = str(d.op, typeof d.action === "string" ? d.action : "");
      if (q && act) {
        if (act === "delete") db.queue = db.queue.filter((x) => x.id !== id);
        else if (act === "deliver" || act === "release") q.status = "sending";
        else if (act === "hold") q.status = "hold";
      }
      return ok({ id, op: act }) as RpcResult<unknown>;
    }
    case "logs.list":
      return ok(db.logs) as RpcResult<unknown>;
    case "services.list":
      return ok(db.services) as RpcResult<unknown>;
    case "services.action": {
      const key = str(d.key, typeof d.service === "string" ? d.service : "");
      const op = str(d.op, typeof d.action === "string" ? d.action : "");
      const s = db.services.find((x) => x.key === key);
      if (s && (op === "start" || op === "restart")) s.running = true;
      if (s && op === "stop") s.running = false;
      return ok({ key, op, running: s?.running }) as RpcResult<unknown>;
    }
    case "security.scan":
      return ok({
        score: 82,
        lastScan: daysAgo(0, 6, 12),
        findings: [
          { id: "f1", severity: "warn", title: "DKIM 选择器缺失", detail: "test.org 的选择器 s1 未发布 TXT 记录", advice: "在 DNS 服务商处补发布 DKIM 记录" },
          { id: "f2", severity: "err", title: "证书即将到期", detail: "webmail.test.org 将于 6 天后到期且未开启自动续期", advice: "执行续期或开启 autoRenew" },
          { id: "f3", severity: "info", title: "SPF/DMARC 已发布", detail: "example.com / mailstack.io 的 SPF、DMARC 策略均已生效", advice: "" },
          { id: "f4", severity: "warn", title: "认证爆破尝试", detail: "近 24 小时 3 个 IP 触发封禁阈值", advice: "保持 fail2ban 规则启用" },
        ],
        bans: db.bans,
        failedLogins24h: 67,
      }) as RpcResult<unknown>;
    case "security.unban": {
      const ip = str(d.ip, "");
      db.bans = db.bans.filter((x) => x.ip !== ip);
      return ok({ ip, unbanned: true }) as RpcResult<unknown>;
    }
    case "security.ban":
      db.bans.unshift({ ip: str(d.ip, "0.0.0.0"), reason: str(d.reason, "manual"), until: daysAgo(-1), fails: 0 });
      return ok({ ip: d.ip }) as RpcResult<unknown>;
    case "settings.get":
      return ok(db.settings) as RpcResult<unknown>;
    case "settings.set":
      for (const [k, v] of Object.entries(d)) {
        if (k in db.settings) (db.settings as Record<string, unknown>)[k] = v;
      }
      return ok(db.settings) as RpcResult<unknown>;
    case "backup.list":
      return ok([
        { name: "backup-2026-09-29-0300.tar.zst", size: "412 MB", time: "2026-09-29 03:00:00", kind: "auto" },
        { name: "backup-2026-09-28-0300.tar.zst", size: "409 MB", time: "2026-09-28 03:00:00", kind: "auto" },
        { name: "backup-manual-preupgrade.tar.zst", size: "388 MB", time: "2026-09-25 21:14:37", kind: "manual" },
      ]) as RpcResult<unknown>;
    case "admin.get":
      return ok({ username: "admin", totp: false, createdAt: daysAgo(220) }) as RpcResult<unknown>;
    case "admin.set":
      // 与后端一致：admin.set 成功后会全量吊销会话并带 revokedSessions + reauthenticate
      return ok({ updated: true, revokedSessions: 1, reauthenticate: true }) as RpcResult<unknown>;
    case "admin.2fa.status":
      return ok({ enabled: mock2fa.enabled, recoveryCodes: mock2fa.enabled ? mock2fa.codes : undefined }) as RpcResult<unknown>;
    case "admin.2fa.begin":
      return ok({
        secret: mock2fa.secret,
        otpauthUri: "otpauth://totp/MailStack:admin?secret=" + mock2fa.secret + "&issuer=MailStack",
      }) as RpcResult<unknown>;
    case "admin.2fa.enable": {
      const code = str(d.code, "");
      if (!/^\d{6}$/.test(code) && !/^[a-z0-9]{8}-[a-z0-9]{8}$/i.test(code)) return err("验证码不正确");
      mock2fa.enabled = true;
      mock2fa.codes = Array.from({ length: 8 }, () =>
        Math.random().toString(36).slice(2, 10) + "-" + Math.random().toString(36).slice(2, 10),
      );
      return ok({ recoveryCodes: mock2fa.codes }) as RpcResult<unknown>;
    }
    case "admin.2fa.disable": {
      const code = str(d.code, "");
      if (!/^\d{6}$/.test(code) && !/^[a-z0-9]{8}-[a-z0-9]{8}$/i.test(code)) return err("验证码不正确");
      mock2fa.enabled = false;
      mock2fa.codes = [];
      return ok({ disabled: true }) as RpcResult<unknown>;
    }
    case "sessions.list":
      return ok(mockSessions) as RpcResult<unknown>;
    case "sessions.revoke": {
      if (d.all === true) {
        mockSessions.splice(1);
        return ok({ revokedAll: true }) as RpcResult<unknown>;
      }
      const i = mockSessions.findIndex((x) => x.id === str(d.id, ""));
      if (i >= 0) mockSessions.splice(i, 1);
      return ok({ revoked: true }) as RpcResult<unknown>;
    }
    case "sessions.revokeOthers":
      mockSessions.splice(1);
      return ok({ revokedAll: true }) as RpcResult<unknown>;
    case "ai.config.get":
      return ok(db.ai) as RpcResult<unknown>;
    case "ai.config.set":
      for (const [k, v] of Object.entries(d)) {
        if (k in db.ai) (db.ai as Record<string, unknown>)[k] = v;
      }
      return ok(db.ai) as RpcResult<unknown>;
    case "ai.models.list":
      return ok([
        { id: "gpt-4o-mini", label: "GPT-4o mini", context: "128k" },
        { id: "deepseek-v3", label: "DeepSeek V3", context: "64k" },
        { id: "qwen-max", label: "Qwen Max", context: "32k" },
        { id: "local-llama8b", label: "Local Llama-3-8B", context: "8k" },
      ]) as RpcResult<unknown>;
    case "ai.chat": {
      const q = str(d.message, str(d.prompt, "")).toLowerCase();
      let reply: string;
      if (q.includes("队列") || q.includes("queue")) reply = "当前队列共 23 封待处理，12 封发送中，1 封失败。失败项是 noreply@system.com → user2@domain.com（550 5.7.1 中继被拒），建议确认该域名的认证凭据后重试投递。";
      else if (q.includes("证书") || q.includes("cert")) reply = "webmail.test.org 的证书将在 6 天内到期，且未开启自动续期。建议执行 certs.renew，或开启 autoRenew 由 ACME 定时任务处理。";
      else if (q.includes("诊断") || q.includes("diagnos")) reply = "整体健康度 82/100：Postfix 与 Dovecot 运行正常，MX/SPF 正常；两处需要关注 —— test.org 的 DKIM 选择器未发布，webmail.test.org 证书临近到期。";
      else reply = "我已读取服务器快照：8 个域名（6 启用）、1,248 个邮箱用户、SMTP/Dovecot 均运行中。可以直接询问队列、证书、安全或让我执行一键诊断。";
      return ok({ reply }) as RpcResult<unknown>;
    }
    case "ai.diagnose":
      return ok({
        summary: "整体健康度 82/100",
        items: [
          { ok: true, text: "SMTP 服务运行中，成功率 99.8%" },
          { ok: true, text: "Dovecot 运行中，12 个活跃会话" },
          { ok: false, text: "test.org DKIM 选择器 s1 未发布 DNS 记录" },
          { ok: false, text: "webmail.test.org 证书 6 天后到期" },
        ],
      }) as RpcResult<unknown>;
    case "relay.test":
      return ok({ success: true, latencyMs: 842, hops: ["mx1.example.com", "relay.primary.net"], message: "测试邮件已通过上级中继投递" }) as RpcResult<unknown>;
    // 真后端的动作名是 setup.relay.apply（relay.apply 不存在）；mock 保留原键名
    // 的同时兼容新名，避免演示模式下点「应用」失败。
    case "relay.apply":
    case "setup.relay.apply":
      return ok({ applied: true }) as RpcResult<unknown>;
    case "dkim.rotate":
      return ok({ selector: `s${Math.floor(Math.random() * 5) + 2}`, keySize: 2048, rotatedAt: fmtTime(new Date()) }) as RpcResult<unknown>;
    case "dkim.keys":
      return ok([
        { domain: "example.com", selector: "s1", keySize: 2048, lastRotated: daysAgo(120), published: true },
        { domain: "mailstack.io", selector: "s1", keySize: 2048, lastRotated: daysAgo(96), published: true },
        { domain: "test.org", selector: "s1", keySize: 2048, lastRotated: daysAgo(60), published: false },
      ]) as RpcResult<unknown>;
    case "dns.records":
      return ok([
        { type: "A", name: "mx1.example.com", value: "198.51.100.10", ttl: 3600, required: true, ok: true },
        { type: "MX", name: "example.com", value: "10 mx1.example.com.", ttl: 3600, required: true, ok: true },
        { type: "TXT", name: "example.com", value: "v=spf1 mx -all", ttl: 3600, required: true, ok: true },
        { type: "TXT", name: "_dmarc.example.com", value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com", ttl: 3600, required: true, ok: true },
        { type: "TXT", name: "s1._domainkey.example.com", value: "v=DKIM1; k=rsa; p=MIGfMA0GCS…", ttl: 3600, required: true, ok: true },
        { type: "TXT", name: "s1._domainkey.test.org", value: "v=DKIM1; k=rsa; p=MIGfMA0GCS…", ttl: 3600, required: true, ok: false },
      ]) as RpcResult<unknown>;
    case "mail.test_loopback":
      return ok({ success: true, message: "本地回环测试通过：投递 → 队列 → LMTP → 邮箱" }) as RpcResult<unknown>;
    case "network.check_port":
      return ok({ port: num(d.port, 25), open: true, latencyMs: 38 }) as RpcResult<unknown>;
    case "ai.test":
      return ok({ ok: true, latencyMs: 842, models: 4 }) as RpcResult<unknown>;
    case "setup.status": {
      // ?setup=1 回放向导（演示首次部署）；mock 默认视为已完成
      const forceWizard = urlParams.get("setup") === "1";
      return ok({ step: forceWizard ? 0 : 6, completed: !forceWizard }) as RpcResult<unknown>;
    }
    // 与真后端同形：幂等收尾，回 setup.status 形状（含 completed: true）。
    case "setup.wizard.complete":
      return ok({
        identityConfigured: true,
        identity: null,
        passwordConfigured: true,
        twoFactorEnabled: false,
        completed: true,
      }) as RpcResult<unknown>;
    case "setup.identity.apply":
      // 真实形状：{ applied, identity: SetupConfig, dkimPublicKey }。
      // dkimPublicKey 是服务器生成的真公钥（SPKI base64），向导第 2 步要靠它
      // 拼 DKIM TXT；少了它 mock 就测不到「公钥必须与服务器一致」这条路径。
      return ok({
        applied: true,
        identity: {
          domain: str(d.domain, ""),
          mailHost: str(d.mailHost, ""),
          serverIp: str(d.serverIp, ""),
          dkimSelector: "mail",
          updatedAt: fmtTime(new Date()),
        },
        dkimPublicKey: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQMockDemoKeyMaterialForWizardOnly0000000000000000000000000",
      }) as RpcResult<unknown>;
    case "setup.dns.verify":
      // 真实形状：{ verified, checks:{a,mx,spfSingle,spfExpected,dkim,dmarc},
      // observed:{…}, spfRecordCount }。逐条判据原样给出，前端才能指出到底哪条没过。
      return ok({
        verified: true,
        checks: { a: true, mx: true, spfSingle: true, spfExpected: true, dkim: true, dmarc: true },
        observed: { a: [str(d.serverIp, "203.0.113.10")], mx: [`10 ${str(d.mailHost, "mail.example.com")}.`], spf: [str(d.expectedSpf, "")], dkim: [], dmarc: [] },
        spfRecordCount: 1,
      }) as RpcResult<unknown>;
    case "setup.cert.issue":
      // 真实形状：{ status, method, reloaded, cert: certificate_to_json(…) }。
      // cert 里**没有** SAN 列表、密钥位数或自动续期，mock 也不编这些字段。
      return ok({
        status: "ok",
        method: str(d.method, "standalone"),
        reloaded: true,
        cert: {
          domain: str(d.domain, "mail.example.com"),
          certPath: `/etc/mailstack/tls/${str(d.domain, "mail.example.com")}/fullchain.pem`,
          keyPath: `/etc/mailstack/tls/${str(d.domain, "mail.example.com")}/privkey.pem`,
          certPresent: true,
          keyPresent: true,
          keyMode: "600",
          keyGroupOrWorldReadable: false,
          notBefore: fmtTime(new Date()),
          notAfter: daysAgo(-58),
          daysUntilExpiry: 58,
          issuer: "Let's Encrypt",
          subject: str(d.domain, "mail.example.com"),
          error: null,
        },
      }) as RpcResult<unknown>;
    case "setup.mail.test":
      // 真实形状：{ queued, roundTripVerified, scope, sender, recipient, code }。
      return ok({ queued: true, roundTripVerified: false, scope: "local submission", sender: str(d.sender, ""), recipient: str(d.recipient, ""), code: 250 }) as RpcResult<unknown>;
    default:
      return err(`mock 未实现该动作: ${action}`) as RpcResult<unknown>;
  }
}

function ok(data: unknown): RpcResult<unknown> {
  return { ok: true, data };
}
function err(message: string): RpcResult<unknown> {
  return { ok: false, error: message };
}

function latencySeries(): { t: string; v: number }[] {
  const out: { t: string; v: number }[] = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600_000);
    const base = 18 + 10 * Math.sin(i / 3.1) + 6 * Math.sin(i / 1.7);
    const jitter = Math.random() * 4;
    out.push({ t: `${String(d.getHours()).padStart(2, "0")}:00`, v: Math.max(4, Math.round((base + jitter) * 10) / 10) });
  }
  return out;
}

  // 把块内的分发器交给模块级句柄：生产构建里这一行与被引用的整块都不存在。
  mockDispatch = dispatch;
}

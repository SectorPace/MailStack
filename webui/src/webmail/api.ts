// Webmail API 客户端 —— 契约 §2/§5.10：
//   * `fetch` + `credentials: "same-origin"`（会话是 HttpOnly Cookie，前端不碰 token）；
//   * 非 GET 一律带 `x-csrf-token`（登录响应 / GET /session 返回的 csrfToken）；
//   * 401 → 清 CSRF + 广播会话失效（App 回登录门并提示会话过期）；
//   * 403 CSRF_REJECTED → 同样按会话失效处理（admin 既有纪律：CSRF 失效必须回登录门，
//     而不是让用户被一句错误卡死在页面里）；
//   * 网络错误 → `ApiError{network:true}`，UI 如实显示「无法连接 mailstack-webmail」；
//   * 429 → TOO_MANY_ATTEMPTS（登录限流）。
//
// 演示数据只存在于开发构建（`import.meta.env.DEV` + `?mock=1`）：动态 import 的
// 分支在生产构建里被 Vite 静态替换 + Rollup 剔除，生产包不含任何假数据。

import type {
  BatchRequest,
  ComposeRequest,
  DraftResult,
  FlagsPatch,
  MailFolder,
  MessageDetail,
  MessageListResult,
  MessageQuery,
  QuotaInfo,
  SendResult,
  SessionInfo,
} from "./types";
import type { Lang } from "./i18n";
import { mt } from "./i18n";

const API_ROOT = "/mail/api";

/** `?mock=1`（仅开发构建）→ 使用前端演示数据。 */
const DEMO_REQUESTED =
  typeof location !== "undefined" && new URLSearchParams(location.search).get("mock") === "1";

export function isDemoMode(): boolean {
  return import.meta.env.DEV && DEMO_REQUESTED;
}

let csrfToken = "";

/** 保存 / 清理 CSRF token（登录成功、GET /session、注销、会话失效时调用）。 */
export function setCsrfToken(token: string | null | undefined): void {
  csrfToken = typeof token === "string" ? token : "";
}

export function getCsrfToken(): string {
  return csrfToken;
}

export type SessionLostReason = "expired" | "csrf";

const sessionListeners = new Set<(reason: SessionLostReason) => void>();

/** 订阅会话失效（401 / CSRF_REJECTED）；返回取消订阅函数。 */
export function onSessionLost(fn: (reason: SessionLostReason) => void): () => void {
  sessionListeners.add(fn);
  return () => sessionListeners.delete(fn);
}

function broadcastSessionLost(reason: SessionLostReason): void {
  csrfToken = "";
  for (const fn of sessionListeners) fn(reason);
}

/** API 错误：`status=0` 且 `network=true` 表示请求根本没到达服务器。 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly network: boolean;

  constructor(status: number, code: string, message: string, network = false) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.network = network;
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

/** 把任意异常翻译成当前语言的用户可读文案（不吞原始信息：服务端 message 优先）。 */
export function describeError(e: unknown, lang: Lang): string {
  if (isApiError(e)) {
    if (e.network) return mt(lang, "error_network");
    if (e.status === 401) return mt(lang, "session_expired");
    if (e.status === 429 || e.code === "TOO_MANY_ATTEMPTS") return mt(lang, "too_many_requests");
    if (e.code === "CSRF_REJECTED") return mt(lang, "csrf_rejected");
    if (e.message) return e.message;
    return mt(lang, "server_error", { status: e.status });
  }
  if (e instanceof Error && e.message) return e.message;
  return mt(lang, "unexpected_error");
}

type HttpMethod = "GET" | "POST" | "PATCH" | "DELETE";

type RequestOptions = { signal?: AbortSignal };

/**
 * 核心请求函数（唯一 fetch 出口）。
 * 204 → undefined；其余要求 JSON（契约所有响应都是 JSON）。
 */
async function request<T>(method: HttpMethod, path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
  // 开发构建的演示数据分支：生产构建中整块被剔除（见文件头注释）。
  if (import.meta.env.DEV && DEMO_REQUESTED) {
    const { mockRequest } = await import("./mock");
    try {
      return await mockRequest<T>(method, path, body);
    } catch (e) {
      // 演示模式复用与真实传输相同的会话失效语义（注销后再请求 → 回登录门）。
      const status = (e as { status?: unknown } | null)?.status;
      if (status === 401) {
        broadcastSessionLost("expired");
        throw new ApiError(401, "UNAUTHORIZED", "session expired");
      }
      throw e;
    }
  }

  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["x-csrf-token"] = csrfToken;

  let res: Response;
  try {
    res = await fetch(`${API_ROOT}${path}`, {
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: opts?.signal,
    });
  } catch (e) {
    if (e instanceof Error && e.name === "AbortError") throw e;
    throw new ApiError(0, "NETWORK", "mailstack-webmail is unreachable", true);
  }

  if (res.status === 401) {
    broadcastSessionLost("expired");
    throw new ApiError(401, "UNAUTHORIZED", "session expired");
  }

  if (res.status === 204) return undefined as T;

  let payload: unknown = null;
  try {
    payload = await res.json();
  } catch {
    payload = null;
  }

  if (!res.ok) {
    const errObj = (payload as { error?: { code?: string; message?: string } } | null)?.error;
    const code = errObj?.code ?? `HTTP_${res.status}`;
    const message = errObj?.message ?? "";
    if (res.status === 403 && code === "CSRF_REJECTED") broadcastSessionLost("csrf");
    throw new ApiError(res.status, code, message);
  }
  return payload as T;
}

function folderPath(folder: string): string {
  return encodeURIComponent(folder);
}

function queryString(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "" || value === false) continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

/* ---------------- 会话 ---------------- */

export async function getSession(opts?: RequestOptions): Promise<SessionInfo> {
  const info = await request<SessionInfo>("GET", "/session", undefined, opts);
  setCsrfToken(info.csrfToken);
  return info;
}

/** 登录：登录名是完整邮箱地址（契约 §1.1）。失败语义统一 INVALID_CREDENTIALS。 */
export async function login(email: string, password: string): Promise<SessionInfo> {
  const info = await request<SessionInfo>("POST", "/session", { login: email, password });
  setCsrfToken(info.csrfToken);
  return info;
}

/** 注销：服务端吊销会话并清 Cookie；成功后才清本地 CSRF。 */
export async function logout(): Promise<void> {
  await request<void>("DELETE", "/session");
  setCsrfToken("");
}

/* ---------------- 文件夹 ---------------- */

export async function listFolders(opts?: RequestOptions): Promise<MailFolder[]> {
  const payload = await request<{ folders?: MailFolder[] }>("GET", "/folders", undefined, opts);
  return Array.isArray(payload?.folders) ? payload.folders : [];
}

export async function createFolder(name: string): Promise<{ name: string }> {
  return request<{ name: string }>("POST", "/folders", { name });
}

export async function renameFolder(folder: string, name: string): Promise<{ name: string }> {
  return request<{ name: string }>("PATCH", `/folders/${folderPath(folder)}`, { name });
}

export async function deleteFolder(folder: string): Promise<void> {
  await request<void>("DELETE", `/folders/${folderPath(folder)}`);
}

export async function getQuota(opts?: RequestOptions): Promise<QuotaInfo> {
  return request<QuotaInfo>("GET", "/quota", undefined, opts);
}

/* ---------------- 邮件 ---------------- */

export async function listMessages(query: MessageQuery, opts?: RequestOptions): Promise<MessageListResult> {
  const qs = queryString({
    folder: query.folder,
    limit: query.limit,
    offset: query.offset,
    q: query.q,
    unread: query.unread,
    flagged: query.flagged,
    sort: query.sort,
  });
  const payload = await request<Partial<MessageListResult>>("GET", `/messages${qs}`, undefined, opts);
  return {
    folder: payload?.folder ?? query.folder,
    total: typeof payload?.total === "number" ? payload.total : 0,
    offset: typeof payload?.offset === "number" ? payload.offset : query.offset,
    limit: typeof payload?.limit === "number" ? payload.limit : query.limit,
    messages: Array.isArray(payload?.messages) ? payload.messages : [],
  };
}

/** 单封详情；`images=true` 时服务端保留远程图片 src（契约 §2.2）。 */
export async function getMessage(
  folder: string,
  uid: number,
  opts?: { images?: boolean; signal?: AbortSignal },
): Promise<MessageDetail> {
  const qs = queryString({ images: opts?.images ? 1 : undefined });
  const payload = await request<{ message?: MessageDetail }>(
    "GET",
    `/messages/${folderPath(folder)}/${uid}${qs}`,
    undefined,
    { signal: opts?.signal },
  );
  if (!payload?.message) {
    throw new ApiError(500, "MALFORMED_RESPONSE", "message payload missing");
  }
  return payload.message;
}

/** 改 flags（只改给出字段）：打开邮件标已读、点星标、标记已读/未读都用它。 */
export async function patchFlags(folder: string, uid: number, patch: FlagsPatch): Promise<string[]> {
  const payload = await request<{ flags?: string[] }>("PATCH", `/messages/${folderPath(folder)}/${uid}`, { flags: patch });
  return Array.isArray(payload?.flags) ? payload.flags : [];
}

export async function moveMessage(
  folder: string,
  uid: number,
  to: string,
  copy = false,
): Promise<{ uid: number; folder: string }> {
  return request<{ uid: number; folder: string }>("POST", `/messages/${folderPath(folder)}/${uid}/move`, { to, copy });
}

export async function deleteMessage(folder: string, uid: number): Promise<void> {
  await request<void>("DELETE", `/messages/${folderPath(folder)}/${uid}`);
}

export async function batchMessages(req: BatchRequest): Promise<{ affected: number }> {
  const payload = await request<{ affected?: number }>("POST", "/messages/batch", req);
  return { affected: typeof payload?.affected === "number" ? payload.affected : 0 };
}

export async function searchMessages(
  q: string,
  opts?: { folder?: string; limit?: number; signal?: AbortSignal },
): Promise<MessageListResult> {
  const qs = queryString({ q, folder: opts?.folder, limit: opts?.limit });
  const payload = await request<Partial<MessageListResult>>("GET", `/search${qs}`, undefined, { signal: opts?.signal });
  return {
    folder: payload?.folder ?? opts?.folder ?? "INBOX",
    total: typeof payload?.total === "number" ? payload.total : 0,
    offset: typeof payload?.offset === "number" ? payload.offset : 0,
    limit: typeof payload?.limit === "number" ? payload.limit : (opts?.limit ?? 50),
    messages: Array.isArray(payload?.messages) ? payload.messages : [],
  };
}

/* ---------------- 写信 / 草稿 ---------------- */

export async function saveDraft(req: ComposeRequest, draftUid?: number | null): Promise<DraftResult> {
  const payload = await request<Partial<DraftResult>>("POST", "/messages", {
    ...req,
    mailbox: "Drafts",
    draftUid: draftUid ?? null,
  });
  return { uid: typeof payload?.uid === "number" ? payload.uid : 0, folder: payload?.folder ?? "Drafts" };
}

export async function sendMessage(req: ComposeRequest): Promise<SendResult> {
  const payload = await request<Partial<SendResult>>("POST", "/send", req);
  return {
    queued: payload?.queued === true,
    queueId: payload?.queueId ?? "",
    sentUid: typeof payload?.sentUid === "number" ? payload.sentUid : null,
    warning: payload?.warning ?? null,
  };
}

/* ---------------- 下载 URL（浏览器直接导航，不经过 fetch 客户端） ---------------- */

export function rawMessageUrl(folder: string, uid: number): string {
  return `${API_ROOT}/messages/${folderPath(folder)}/${uid}/raw`;
}

export function attachmentUrl(folder: string, uid: number, partId: string, download = true): string {
  return `${API_ROOT}/messages/${folderPath(folder)}/${uid}/parts/${encodeURIComponent(partId)}${download ? "?download=1" : ""}`;
}

// API 客户端测试：CSRF 头 / 401 会话失效广播 / 网络错误 / 错误体解析 / 查询串。
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  deleteMessage,
  describeError,
  getCsrfToken,
  getMessage,
  isApiError,
  listMessages,
  login,
  patchFlags,
  onSessionLost,
  setCsrfToken,
} from "./api";

type FetchCall = [input: string, init?: RequestInit];

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

function stubFetch(handler: (call: FetchCall) => Response): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => handler([String(input), init]));
  vi.stubGlobal("fetch", fn);
  return fn;
}

beforeEach(() => {
  setCsrfToken("");
});

describe("CSRF 与请求头", () => {
  it("POST login sends same-origin credentials and stores csrfToken", async () => {
    const fetchMock = stubFetch(() =>
      jsonResponse({
        user: { email: "alice@example.com", account: "alice", displayName: "Alice" },
        csrfToken: "tok-123",
        expiresInSeconds: 28800,
      }),
    );
    const session = await login("alice@example.com", "secret");
    expect(session.user.email).toBe("alice@example.com");
    expect(getCsrfToken()).toBe("tok-123");

    const [, init] = fetchMock.mock.calls[0] as FetchCall;
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("same-origin");
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(JSON.parse(String(init?.body))).toEqual({ login: "alice@example.com", password: "secret" });
  });

  it("writes carry x-csrf-token after login; GET requests do not", async () => {
    const fetchMock = stubFetch((call) => {
      const [url] = call;
      if (url.endsWith("/session")) {
        return jsonResponse({
          user: { email: "alice@example.com", account: "alice", displayName: "Alice" },
          csrfToken: "tok-abc",
          expiresInSeconds: 28800,
        });
      }
      return jsonResponse({ flags: ["seen"] });
    });
    await login("alice@example.com", "pw");
    await patchFlags("INBOX", 7, { seen: true });
    const patchInit = fetchMock.mock.calls[1][1] as RequestInit;
    expect((patchInit.headers as Record<string, string>)["x-csrf-token"]).toBe("tok-abc");
    expect(String(fetchMock.mock.calls[1][0])).toContain("/mail/api/messages/INBOX/7");
  });

  it("omits x-csrf-token on GET list requests and encodes the query", async () => {
    const fetchMock = stubFetch(() =>
      jsonResponse({ folder: "INBOX", total: 1, offset: 0, limit: 25, messages: [] }),
    );
    const result = await listMessages({ folder: "Projects/2026", limit: 25, offset: 50, flagged: true });
    expect(result.total).toBe(1);
    const [url, init] = fetchMock.mock.calls[0] as FetchCall;
    expect(url).toContain("/mail/api/messages?");
    expect(url).toContain("folder=Projects%2F2026");
    expect(url).toContain("limit=25");
    expect(url).toContain("offset=50");
    expect(url).toContain("flagged=true");
    expect((init?.headers as Record<string, string>)["x-csrf-token"]).toBeUndefined();
    expect(init?.method).toBe("GET");
  });
});

describe("会话失效 / 错误语义", () => {
  it("401 clears csrf and broadcasts session-lost", async () => {
    setCsrfToken("stale");
    stubFetch(() => jsonResponse({ error: { code: "UNAUTHORIZED" } }, 401));
    const reasons: string[] = [];
    const off = onSessionLost((reason) => reasons.push(reason));
    await expect(patchFlags("INBOX", 1, { seen: true })).rejects.toMatchObject({ status: 401 });
    expect(getCsrfToken()).toBe("");
    expect(reasons).toEqual(["expired"]);
    off();
  });

  it("403 CSRF_REJECTED broadcasts csrf session-lost", async () => {
    stubFetch(() => jsonResponse({ error: { code: "CSRF_REJECTED" } }, 403));
    const reasons: string[] = [];
    const off = onSessionLost((reason) => reasons.push(reason));
    await expect(patchFlags("INBOX", 1, { flagged: true })).rejects.toBeInstanceOf(ApiError);
    expect(reasons).toEqual(["csrf"]);
    off();
  });

  it("network failure becomes ApiError{network:true} and localized message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("failed to fetch");
      }),
    );
    let caught: unknown = null;
    try {
      await listMessages({ folder: "INBOX", limit: 50, offset: 0 });
    } catch (e) {
      caught = e;
    }
    expect(isApiError(caught)).toBe(true);
    const err = caught as ApiError;
    expect(err.network).toBe(true);
    expect(err.status).toBe(0);
    expect(describeError(err, "zh")).toBe("无法连接 mailstack-webmail");
    expect(describeError(err, "en")).toBe("Cannot connect to mailstack-webmail");
  });

  it("parses error bodies and maps 429", async () => {
    stubFetch(() => jsonResponse({ error: { code: "TOO_MANY_ATTEMPTS", message: "slow down" } }, 429));
    let caught: unknown = null;
    try {
      await login("a@b.com", "x");
    } catch (e) {
      caught = e;
    }
    const err = caught as ApiError;
    expect(err.status).toBe(429);
    expect(err.code).toBe("TOO_MANY_ATTEMPTS");
    expect(describeError(err, "zh")).toBe("请求过于频繁，请稍后再试");
  });

  it("204 responses resolve to undefined", async () => {
    stubFetch(() => ({ ok: true, status: 204, json: async () => ({}) }) as unknown as Response);
    await expect(deleteMessage("Trash", 9)).resolves.toBeUndefined();
  });
});

describe("详情 / 图片开关", () => {
  it("unwraps message payload and forwards images=1", async () => {
    const fetchMock = stubFetch(() =>
      jsonResponse({
        message: {
          uid: 5,
          folder: "INBOX",
          flags: [],
          size: 1,
          headers: {},
          body: { text: null, html: "<p>x</p>", truncated: false },
          attachments: [],
          remoteImagesBlocked: 2,
        },
      }),
    );
    const detail = await getMessage("INBOX", 5, { images: true });
    expect(detail.remoteImagesBlocked).toBe(2);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/mail/api/messages/INBOX/5?images=1");
  });

  it("throws ApiError on malformed detail payload", async () => {
    stubFetch(() => jsonResponse({}));
    await expect(getMessage("INBOX", 5)).rejects.toMatchObject({ code: "MALFORMED_RESPONSE" });
  });
});

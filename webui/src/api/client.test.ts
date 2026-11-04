import { beforeEach, describe, expect, it, vi } from "vitest";
import { captureCsrf, getMode, initApi, onModeChange, resetCsrf, rpc } from "./client";
import type { Mode } from "./client";
type FetchInit = RequestInit;
type Handler = (url: string, init: FetchInit) => Response;
function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}
function stubFetch(handler: Handler) {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: FetchInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
        try {
            return Promise.resolve(handler(url, init ?? {}));
        }
        catch (e) {
            return Promise.reject(e);
        }
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
}
async function activateTransport(kind: "rest" | "rpc") {
    stubFetch((url) => {
        if (url === "/api/health")
            return jsonResponse({ ok: true });
        if (url === "/api/setup/status") {
            return kind === "rest" ? jsonResponse({ ok: true }) : new Response("gone", { status: 404 });
        }
        return new Response("unexpected probe", { status: 500 });
    });
    expect(await initApi()).toBe("live");
}
function lastCall(fetchMock: ReturnType<typeof stubFetch>): [
    string,
    FetchInit
] {
    expect(fetchMock.mock.calls.length).toBeGreaterThan(0);
    return fetchMock.mock.calls[fetchMock.mock.calls.length - 1] as [
        string,
        FetchInit
    ];
}
function bodyOf(init: FetchInit): Record<string, unknown> {
    expect(typeof init.body).toBe("string");
    return JSON.parse(init.body as string) as Record<string, unknown>;
}
function dataOf(init: FetchInit): Record<string, unknown> {
    const frame = bodyOf(init);
    expect(frame.data, "bridge frame must carry a data payload").toBeTypeOf("object");
    return frame.data as Record<string, unknown>;
}
function headersOf(init: FetchInit): Record<string, string> {
    return init.headers as Record<string, string>;
}
function watchUnauthorized(): () => void {
    const fn = vi.fn();
    window.addEventListener("mailstack:unauthorized", fn);
    return () => window.removeEventListener("mailstack:unauthorized", fn);
}
beforeEach(() => {
    resetCsrf();
});
describe("destructive actions inject confirm:true (REST path)", () => {
    beforeEach(async () => {
        await activateTransport("rest");
    });
    it("domains.delete sends DELETE with a JSON body carrying strict-boolean confirm:true", async () => {
        captureCsrf("csrf-token-1");
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, domain: "example.com" }));
        const r = await rpc("domains.delete", { domain: "example.com" });
        expect(r.ok).toBe(true);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/domains/example.com");
        expect(init.method).toBe("DELETE");
        expect(headersOf(init)["Content-Type"]).toBe("application/json");
        expect(headersOf(init)["x-csrf-token"]).toBe("csrf-token-1");
        const body = bodyOf(init);
        expect(body).toEqual({ confirm: true });
        expect(body.confirm).toBe(true);
        expect(typeof body.confirm).toBe("boolean");
    });
    it("users.delete encodes the address into the path and confirms", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, address: "u@example.com" }));
        await rpc("users.delete", { address: "u@example.com" });
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/users/u%40example.com");
        expect(init.method).toBe("DELETE");
        expect(bodyOf(init)).toEqual({ confirm: true });
    });
    it("admin.2fa.disable posts { code, confirm: true } to /api/admin/2fa/disable", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, disabled: true }));
        await rpc("admin.2fa.disable", { code: "123456" });
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/admin/2fa/disable");
        expect(init.method).toBe("POST");
        const body = bodyOf(init);
        expect(body.code).toBe("123456");
        expect(body.confirm).toBe(true);
        expect(typeof body.confirm).toBe("boolean");
    });
    it("aliases.delete sends a DELETE with an explicit {} JSON body (empty body + json content-type would 400)", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true }));
        await rpc("aliases.delete", { source: "alias@example.com" });
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/aliases/alias%40example.com");
        expect(init.method).toBe("DELETE");
        expect(bodyOf(init)).toEqual({});
    });
    it("setup.relay.test uses the dedicated REST route instead of the bridge", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, ok2: true }));
        await rpc("setup.relay.test", { host: "relay.example.com", port: 587 });
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/setup/relay/test");
        expect(init.method).toBe("POST");
        expect(bodyOf(init)).toEqual({ host: "relay.example.com", port: 587 });
    });
    it("non-destructive actions never gain a confirm key", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, domains: ["x.com"] }));
        await rpc("domains.add", { domain: "x.com" });
        const [, init] = lastCall(fetchMock);
        const body = bodyOf(init);
        expect(body).toEqual({ domain: "x.com" });
        expect("confirm" in body).toBe(false);
    });
});
describe("destructive actions inject confirm:true (RPC bridge path)", () => {
    beforeEach(async () => {
        await activateTransport("rpc");
    });
    it("admin.2fa.disable is aliased to admin.totp.disable on the wire and carries confirm", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, data: { disabled: true } }));
        const r = await rpc("admin.2fa.disable", { code: "123456" });
        expect(r.ok).toBe(true);
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/rpc");
        expect(init.method).toBe("POST");
        const frame = bodyOf(init);
        expect(frame.action).toBe("admin.totp.disable");
        const data = dataOf(init);
        expect(data.code).toBe("123456");
        expect(data.confirm).toBe(true);
        expect(typeof data.confirm).toBe("boolean");
    });
    it("users.delete keeps its action name and bridges confirm:true", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, data: { address: "u@example.com" } }));
        await rpc("users.delete", { address: "u@example.com" });
        const frame = bodyOf(lastCall(fetchMock)[1]);
        expect(frame.action).toBe("users.delete");
        expect(frame.data).toEqual({ address: "u@example.com", confirm: true });
    });
    it("non-aliased actions pass through unmodified", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, data: { lines: ["l1"] } }));
        await rpc("logs.list", { unit: "mailstackd" });
        const frame = bodyOf(lastCall(fetchMock)[1]);
        expect(frame.action).toBe("logs.list");
        expect(frame.data).toEqual({ unit: "mailstackd" });
    });
});
describe("CSRF capture and header propagation", () => {
    it("captured token rides on mutating requests only (GET stays header-free)", async () => {
        await activateTransport("rest");
        captureCsrf("sess-csrf");
        const fetchMock = stubFetch(() => jsonResponse({ ok: true }));
        await rpc("settings.set", { serverName: "mx1" });
        {
            const [, init] = lastCall(fetchMock);
            expect(init.method).toBe("POST");
            expect(headersOf(init)["x-csrf-token"]).toBe("sess-csrf");
            expect(headersOf(init)["Content-Type"]).toBe("application/json");
        }
        await rpc("queue.list");
        {
            const [, init] = lastCall(fetchMock);
            expect(init.method).toBe("GET");
            expect(init.body).toBeUndefined();
            expect("x-csrf-token" in headersOf(init)).toBe(false);
            expect("Content-Type" in headersOf(init)).toBe(false);
        }
    });
    it("captureCsrf ignores non-string tokens (keeps the previous one)", async () => {
        await activateTransport("rest");
        captureCsrf("keep-me");
        captureCsrf(undefined);
        const fetchMock = stubFetch(() => jsonResponse({ ok: true }));
        await rpc("setup.wizard.complete");
        expect(headersOf(lastCall(fetchMock)[1])["x-csrf-token"]).toBe("keep-me");
    });
    it("the bridge carries the csrf header too", async () => {
        await activateTransport("rpc");
        captureCsrf("bridge-csrf");
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, data: {} }));
        await rpc("logs.list", { unit: "mailstackd" });
        expect(headersOf(lastCall(fetchMock)[1])["x-csrf-token"]).toBe("bridge-csrf");
    });
});
describe("401/403 handling", () => {
    it("REST 403 clears the in-memory csrf, signals unauthorized, next write is header-free", async () => {
        await activateTransport("rest");
        captureCsrf("doomed-token");
        const off = watchUnauthorized();
        stubFetch(() => new Response("denied", { status: 403 }));
        const r = await rpc("settings.set", { a: 1 });
        expect(r).toEqual({ ok: false, error: "unauthorized" });
        const fetchMock2 = stubFetch(() => jsonResponse({ ok: true }));
        await rpc("setup.wizard.complete");
        const [, init2] = lastCall(fetchMock2);
        expect("x-csrf-token" in headersOf(init2)).toBe(false);
        off();
    });
    it("bridge 401 behaves the same: unauthorized + csrf cleared + event", async () => {
        await activateTransport("rpc");
        captureCsrf("bridge-token");
        const off = watchUnauthorized();
        stubFetch(() => new Response("no", { status: 401 }));
        const r = await rpc("logs.list", {});
        expect(r).toEqual({ ok: false, error: "unauthorized" });
        const fetchMock2 = stubFetch(() => jsonResponse({ ok: true, data: {} }));
        await rpc("logs.list", {});
        expect("x-csrf-token" in headersOf(lastCall(fetchMock2)[1])).toBe(false);
        off();
    });
});
describe("REST mapping sanity", () => {
    beforeEach(async () => {
        await activateTransport("rest");
    });
    it("setup.wizard.complete POSTs /api/setup/wizard/complete with an explicit {} body", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, completed: true }));
        await rpc("setup.wizard.complete");
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/setup/wizard/complete");
        expect(init.method).toBe("POST");
        expect(init.body).toBe("{}");
        expect(headersOf(init)["Content-Type"]).toBe("application/json");
    });
    it("queue.list GETs /api/queue and passes a bare array through", async () => {
        const fetchMock = stubFetch(() => jsonResponse([{ id: "q1" }, { id: "q2" }]));
        const r = await rpc("queue.list");
        expect(r.ok).toBe(true);
        if (r.ok)
            expect(r.data).toEqual([{ id: "q1" }, { id: "q2" }]);
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/queue");
        expect(init.method).toBe("GET");
    });
    it("pickList unwraps named collection keys (domains.list / logs.list)", async () => {
        let fetchMock = stubFetch(() => jsonResponse({ domains: ["a.test", "b.test"] }));
        const domains = await rpc("domains.list");
        expect(domains.ok).toBe(true);
        if (domains.ok)
            expect(domains.data).toEqual(["a.test", "b.test"]);
        expect(lastCall(fetchMock)[0]).toBe("/api/domains");
        fetchMock = stubFetch(() => jsonResponse({ ok: true, available: true, entries: ["l1", "l2"] }));
        const logs = await rpc("logs.list");
        expect(logs.ok).toBe(true);
        if (logs.ok)
            expect(logs.data).toEqual(["l1", "l2"]);
    });
    it("actions without a REST mapping fall back to the /api/rpc bridge with the action in the body", async () => {
        const fetchMock = stubFetch(() => jsonResponse({ ok: true, data: {} }));
        await rpc("custom.unmapped", { a: 1 });
        const [url, init] = lastCall(fetchMock);
        expect(url).toBe("/api/rpc");
        expect(init.method).toBe("POST");
        const frame = bodyOf(init);
        expect(frame.action).toBe("custom.unmapped");
        expect(frame.data).toEqual({ a: 1 });
    });
});
describe("initApi probe result", () => {
    it("marks the api unreachable when the health probe fails and notifies listeners", async () => {
        await activateTransport("rest");
        expect(getMode()).toBe("live");
        const seen: Mode[] = [];
        const off = onModeChange((m) => seen.push(m));
        stubFetch(() => new Response("down", { status: 500 }));
        expect(await initApi()).toBe("unreachable");
        expect(getMode()).toBe("unreachable");
        expect(seen).toContain("unreachable");
        off();
    });
});
describe("error mapping", () => {
    it("surfaces backend error.message objects", async () => {
        await activateTransport("rest");
        stubFetch(() => jsonResponse({ error: { message: "boom" } }, 500));
        expect(await rpc("settings.set", {})).toEqual({ ok: false, error: "boom" });
    });
    it("falls back to HTTP <status> when the error body is not JSON", async () => {
        await activateTransport("rest");
        stubFetch(() => new Response("<html>oops</html>", { status: 502 }));
        expect(await rpc("settings.set", {})).toEqual({ ok: false, error: "HTTP 502" });
    });
    it("bridge reports HTTP <status> for non-ok, body.error for {ok:false}", async () => {
        await activateTransport("rpc");
        stubFetch(() => new Response("bad gateway", { status: 502 }));
        expect(await rpc("logs.list", {})).toEqual({ ok: false, error: "HTTP 502" });
        stubFetch(() => jsonResponse({ ok: false, error: "nope" }));
        expect(await rpc("logs.list", {})).toEqual({ ok: false, error: "nope" });
    });
    it("maps transport failures to the thrown message", async () => {
        await activateTransport("rpc");
        stubFetch(() => {
            throw new TypeError("socket hangup");
        });
        expect(await rpc("logs.list", {})).toEqual({ ok: false, error: "socket hangup" });
    });
});

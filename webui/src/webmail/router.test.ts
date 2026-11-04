import { describe, expect, it } from "vitest";
import { isMailboxRoute, mailHash, parseMailHash, routeKey } from "./router";
describe("parseMailHash", () => {
    it("parses every contract route", () => {
        expect(parseMailHash("#/mail/login")).toEqual({ name: "login" });
        expect(parseMailHash("#/mail/inbox")).toEqual({ name: "inbox" });
        expect(parseMailHash("#/mail/compose")).toEqual({ name: "compose" });
        expect(parseMailHash("#/mail/settings")).toEqual({ name: "settings" });
        expect(parseMailHash("#/mail/folder/Sent")).toEqual({ name: "folder", folder: "Sent" });
        expect(parseMailHash("#/mail/message/INBOX/42")).toEqual({ name: "message", folder: "INBOX", uid: 42 });
        expect(parseMailHash("#/mail/search?q=hello%20world")).toEqual({ name: "search", q: "hello world" });
    });
    it("handles encoded folder names containing slashes", () => {
        expect(parseMailHash("#/mail/folder/Projects%2F2026")).toEqual({ name: "folder", folder: "Projects/2026" });
        expect(parseMailHash("#/mail/message/Projects%2F2026/7")).toEqual({
            name: "message",
            folder: "Projects/2026",
            uid: 7,
        });
    });
    it("falls back to inbox for unknown/invalid routes", () => {
        expect(parseMailHash("")).toEqual({ name: "inbox" });
        expect(parseMailHash("#/")).toEqual({ name: "inbox" });
        expect(parseMailHash("#/mail")).toEqual({ name: "inbox" });
        expect(parseMailHash("#/mail/unknown/thing")).toEqual({ name: "inbox" });
        expect(parseMailHash("#/mail/folder/")).toEqual({ name: "inbox" });
        expect(parseMailHash("#/mail/message/INBOX/not-a-number")).toEqual({ name: "inbox" });
        expect(parseMailHash("#/mail/message/INBOX/-3")).toEqual({ name: "inbox" });
        expect(parseMailHash("#/dashboard")).toEqual({ name: "inbox" });
    });
});
describe("mailHash / routeKey / isMailboxRoute", () => {
    it("round-trips routes through hash construction", () => {
        const routes = [
            { name: "login" as const },
            { name: "inbox" as const },
            { name: "compose" as const },
            { name: "settings" as const },
            { name: "folder" as const, folder: "项目 2026" },
            { name: "message" as const, folder: "INBOX", uid: 42 },
            { name: "search" as const, q: "账单 & invoice" },
        ];
        for (const route of routes) {
            expect(parseMailHash(mailHash(route))).toEqual(route);
        }
    });
    it("produces stable effect keys", () => {
        expect(routeKey({ name: "inbox" })).toBe("inbox");
        expect(routeKey({ name: "folder", folder: "Sent" })).toBe("folder:Sent:");
        expect(routeKey({ name: "message", folder: "INBOX", uid: 3 })).toBe("message:INBOX:3");
        expect(routeKey({ name: "search", q: "x" })).toBe("search:x");
    });
    it("classifies mailbox routes", () => {
        expect(isMailboxRoute({ name: "inbox" })).toBe(true);
        expect(isMailboxRoute({ name: "folder", folder: "Sent" })).toBe(true);
        expect(isMailboxRoute({ name: "message", folder: "INBOX", uid: 1 })).toBe(true);
        expect(isMailboxRoute({ name: "search", q: "x" })).toBe(true);
        expect(isMailboxRoute({ name: "login" })).toBe(false);
        expect(isMailboxRoute({ name: "compose" })).toBe(false);
        expect(isMailboxRoute({ name: "settings" })).toBe(false);
    });
});

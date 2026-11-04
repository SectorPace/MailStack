import { describe, expect, it } from "vitest";
import { buildReplyDraft, quotePlainText, replyRecipients, replySubject } from "./reply";
import { addr, makeDetail } from "../test-utils";
describe("replySubject", () => {
    it("adds Re:/Fwd: only when missing (case-insensitive)", () => {
        expect(replySubject("Hello", "reply")).toBe("Re: Hello");
        expect(replySubject("Re: Hello", "reply")).toBe("Re: Hello");
        expect(replySubject("RE:Hello", "reply")).toBe("RE:Hello");
        expect(replySubject("Hello", "forward")).toBe("Fwd: Hello");
        expect(replySubject("Fw: Hello", "forward")).toBe("Fw: Hello");
        expect(replySubject("", "reply")).toBe("Re: ");
    });
});
describe("replyRecipients", () => {
    const detail = makeDetail({
        headers: {
            from: addr("Alice", "alice@example.com"),
            to: [addr("Me", "me@example.com"), addr("Bob", "bob@example.com")],
            cc: [addr("Carol", "carol@example.com"), addr("Me", "me@example.com")],
            replyTo: [],
        },
    });
    it("reply targets the sender", () => {
        expect(replyRecipients(detail, "reply", "me@example.com")).toEqual({ to: ["alice@example.com"], cc: [] });
    });
    it("reply-all = from + to - self; cc = cc - self and without duplicates", () => {
        expect(replyRecipients(detail, "replyAll", "me@example.com")).toEqual({
            to: ["alice@example.com", "bob@example.com"],
            cc: ["carol@example.com"],
        });
    });
    it("reply prefers Reply-To when present", () => {
        const withReplyTo = makeDetail({ headers: { replyTo: [addr("List", "list@example.com")] } });
        expect(replyRecipients(withReplyTo, "reply", "me@example.com").to).toEqual(["list@example.com"]);
    });
    it("forward starts with empty recipients", () => {
        expect(replyRecipients(detail, "forward", "me@example.com")).toEqual({ to: [], cc: [] });
    });
});
describe("quotePlainText", () => {
    it("prefixes every line with > and keeps blank lines", () => {
        expect(quotePlainText("line1\n\nline2")).toBe("> line1\n>\n> line2");
    });
});
describe("buildReplyDraft", () => {
    it("builds subject, references and quoted text for a reply", () => {
        const detail = makeDetail({
            headers: { subject: "Hello", messageId: "<m2@example.com>", references: ["<m1@example.com>"] },
            body: { text: "Original body", html: null, truncated: false },
        });
        const draft = buildReplyDraft(detail, "replyAll", { self: "me@example.com", lang: "zh" });
        expect(draft.subject).toBe("Re: Hello");
        expect(draft.inReplyTo).toBe("<m2@example.com>");
        expect(draft.references).toEqual(["<m1@example.com>", "<m2@example.com>"]);
        expect(draft.text).toContain("写道：");
        expect(draft.text).toContain("> Original body");
        expect(draft.html).toContain("<blockquote>");
    });
    it("escapes attacker-controlled body text instead of injecting HTML", () => {
        const detail = makeDetail({
            body: { text: '<img src=x onerror=alert(1)> & "quotes"', html: null, truncated: false },
        });
        const draft = buildReplyDraft(detail, "reply", { self: "me@example.com", lang: "en" });
        expect(draft.html).not.toContain("<img");
        expect(draft.html).toContain("&lt;img");
        expect(draft.html).toContain("&amp;");
    });
    it("falls back to HTML→plain when body.text is missing", () => {
        const detail = makeDetail({
            body: { text: null, html: "<p>Hello <b>HTML</b></p>", truncated: false },
        });
        const draft = buildReplyDraft(detail, "forward", { self: "me@example.com", lang: "en" });
        expect(draft.text).toContain("Hello HTML");
        expect(draft.subject).toBe("Fwd: Hello");
        expect(draft.inReplyTo).toBeUndefined();
        expect(draft.references).toEqual([]);
    });
});

import { describe, expect, it } from "vitest";
import { cssUrl, formatDayTime, formatTime, parseTimeMs } from "./format";
describe("parseTimeMs", () => {
    it("parses ISO8601 with Z as an absolute instant", () => {
        expect(parseTimeMs("2026-01-02T03:04:05Z")).toBe(Date.UTC(2026, 0, 2, 3, 4, 5));
    });
    it("parses mock 'YYYY-MM-DD HH:mm:ss' (space-separated) as local wall clock", () => {
        expect(parseTimeMs("2026-01-02 03:04:05")).toBe(Date.UTC(2026, 0, 2, 3, 4, 5));
    });
    it("returns null for null / undefined / empty / unparseable input", () => {
        expect(parseTimeMs(null)).toBeNull();
        expect(parseTimeMs(undefined)).toBeNull();
        expect(parseTimeMs("")).toBeNull();
        expect(parseTimeMs("not a date")).toBeNull();
    });
});
describe("formatTime (HH:mm, local clock)", () => {
    it("renders UTC-clock output under the pinned UTC timezone", () => {
        expect(formatTime("2026-01-02T03:04:05Z")).toBe("03:04");
        expect(formatTime("2026-01-02T21:30:00Z")).toBe("21:30");
    });
    it("renders the mock timestamp format", () => {
        expect(formatTime("2026-01-02 23:05:00")).toBe("23:05");
    });
    it("echoes unparseable input instead of fabricating a value; null/undefined → ''", () => {
        expect(formatTime("nope")).toBe("nope");
        expect(formatTime(null)).toBe("");
        expect(formatTime(undefined)).toBe("");
    });
});
describe("formatDayTime (MM-DD HH:mm, local clock)", () => {
    it("renders date and time from an ISO instant", () => {
        expect(formatDayTime("2026-01-02T03:04:05Z")).toBe("01-02 03:04");
    });
    it("renders the mock timestamp format", () => {
        expect(formatDayTime("2026-12-31 08:00:00")).toBe("12-31 08:00");
    });
    it("echoes unparseable input", () => {
        expect(formatDayTime("garbage")).toBe("garbage");
    });
});
describe("cssUrl", () => {
    it("wraps plain values in double quotes", () => {
        expect(cssUrl("bg.png")).toBe('"bg.png"');
    });
    it("escapes double quotes so the value cannot terminate the url() string", () => {
        expect(cssUrl('a"b')).toBe('"a\\"b"');
    });
    it("escapes backslashes so they cannot neutralize the quote escaping", () => {
        expect(cssUrl("a\\b")).toBe('"a\\\\b"');
    });
    it("escapes backslash-then-quote in the right order (injection-shaped input)", () => {
        const out = cssUrl('\\"');
        expect(out.startsWith('"')).toBe(true);
        expect(out.endsWith('"')).toBe(true);
        const inner = out.slice(1, -1);
        expect(inner.match(/(^|[^\\])"/g)).toBeNull();
        expect(inner.endsWith('\\"')).toBe(true);
    });
    it("keeps a full CSS-injection payload inside the quoted value", () => {
        const evil = '"); background:url("http://evil.test/x.png"); url("';
        const out = cssUrl(evil);
        const inner = out.slice(1, -1);
        expect(inner.match(/(^|[^\\])"/g)).toBeNull();
        expect(inner.includes(evil.replaceAll('"', '\\"'))).toBe(true);
    });
});

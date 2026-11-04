import { describe, expect, it } from "vitest";
import { formatAddressList, formatFileSize, formatFullDate, formatListDate, initials, parseMailDate, senderName, truncate, } from "./format";
const NOW = new Date("2026-11-03T12:00:00Z");
describe("formatListDate（今天→HH:mm；今年→M月D日/MMM D；更早→YYYY-MM-DD）", () => {
    it("formats today as HH:mm in both languages", () => {
        expect(formatListDate("2026-11-03T07:00:00Z", "zh", NOW)).toBe("07:00");
        expect(formatListDate("2026-11-03T23:59:00Z", "en", NOW)).toBe("23:59");
    });
    it("formats this year without time", () => {
        expect(formatListDate("2026-03-05T07:00:00Z", "zh", NOW)).toBe("3月5日");
        expect(formatListDate("2026-03-05T07:00:00Z", "en", NOW)).toBe("Mar 5");
    });
    it("formats older years as YYYY-MM-DD", () => {
        expect(formatListDate("2024-12-31T23:00:00Z", "zh", NOW)).toBe("2024-12-31");
        expect(formatListDate("2024-12-31T23:00:00Z", "en", NOW)).toBe("2024-12-31");
    });
    it("returns empty string for missing/invalid dates (never invents a value)", () => {
        expect(formatListDate("", "zh", NOW)).toBe("");
        expect(formatListDate(null, "zh", NOW)).toBe("");
        expect(formatListDate("not-a-date", "zh", NOW)).toBe("");
        expect(parseMailDate("not-a-date")).toBeNull();
        expect(parseMailDate("2026-11-03T07:00:00Z")).toBeInstanceOf(Date);
    });
});
describe("formatFullDate", () => {
    it("formats reader dates per language", () => {
        expect(formatFullDate("2026-11-03T07:05:00Z", "zh")).toBe("2026年11月3日 07:05");
        expect(formatFullDate("2026-11-03T07:05:00Z", "en")).toBe("Nov 3, 2026 07:05");
        expect(formatFullDate(null, "zh")).toBe("");
    });
});
describe("formatFileSize", () => {
    it("uses binary units with one decimal above 100 checks", () => {
        expect(formatFileSize(0)).toBe("0 B");
        expect(formatFileSize(1024)).toBe("1.0 KiB");
        expect(formatFileSize(1536)).toBe("1.5 KiB");
        expect(formatFileSize(25 * 1024 * 1024)).toBe("25.0 MiB");
        expect(formatFileSize(-1)).toBe("");
    });
});
describe("address display helpers", () => {
    it("senderName prefers display name then address", () => {
        expect(senderName({ name: "Alice", address: "alice@example.com" })).toBe("Alice");
        expect(senderName({ name: "", address: "alice@example.com" })).toBe("alice@example.com");
        expect(senderName(null)).toBe("");
    });
    it("formatAddressList renders name <addr> pairs", () => {
        expect(formatAddressList([
            { name: "Alice", address: "alice@example.com" },
            { name: "", address: "bob@example.com" },
        ])).toBe("Alice <alice@example.com>, bob@example.com");
        expect(formatAddressList(null)).toBe("");
    });
    it("initials handles CJK, latin words and empty values", () => {
        expect(initials("Alice Chen")).toBe("AC");
        expect(initials("张三")).toBe("张");
        expect(initials("")).toBe("?");
    });
    it("truncate keeps short text and adds an ellipsis", () => {
        expect(truncate("abc", 10)).toBe("abc");
        expect(truncate("abcdef", 3)).toBe("abc…");
    });
});

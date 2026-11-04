import { describe, expect, it } from "vitest";
import { DICT, t } from "./i18n";
import type { DictKey } from "./i18n";
const entries = Object.entries(DICT) as [
    DictKey,
    readonly [
        string,
        string
    ]
][];
const placeholders = (s: string) => new Set([...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]));
describe("i18n dictionary structural integrity", () => {
    it("has entries to check", () => {
        expect(entries.length).toBeGreaterThan(100);
    });
    it("every key maps to a [zh, en] tuple of two non-empty strings", () => {
        for (const [key, value] of entries) {
            expect(Array.isArray(value), `key ${key}: value must be a [zh, en] tuple`).toBe(true);
            expect(value, `key ${key}: tuple length`).toHaveLength(2);
            expect(typeof value[0], `key ${key}: zh must be a string`).toBe("string");
            expect(typeof value[1], `key ${key}: en must be a string`).toBe("string");
            expect(value[0].length, `key ${key}: zh must be non-empty`).toBeGreaterThan(0);
            expect(value[1].length, `key ${key}: en must be non-empty`).toBeGreaterThan(0);
        }
    });
    it("zh and en expose identical {placeholder} sets per key", () => {
        for (const [key, [zh, en]] of entries) {
            expect(placeholders(en), `key ${key}: placeholder mismatch between zh and en`).toEqual(placeholders(zh));
        }
    });
    it("t() selects the language slice and substitutes parameters", () => {
        expect(t("zh", "total_items", { n: 5 })).toBe("共 5 条");
        expect(t("en", "total_items", { n: 5 })).toBe("Total 5 items");
        expect(t("zh", "service_confirm", { name: "smtp", op: "restart" })).toBe("即将对「smtp」执行「restart」");
        expect(t("en", "service_confirm", { name: "smtp", op: "restart" })).toBe("Apply restart to smtp?");
        expect(t("en", "findings_count", { n: 3 })).toBe("3 findings");
    });
    it("t() without params returns the raw template", () => {
        expect(t("zh", "total_items")).toBe("共 {n} 条");
        expect(t("en", "page_number")).toBe("Page {n}");
    });
});

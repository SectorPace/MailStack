import { describe, expect, it } from "vitest";
import { MAIL_DICT, htmlLang, mt, type MailKey } from "./i18n";
const keys = Object.keys(MAIL_DICT) as MailKey[];
describe("MAIL_DICT 完整性", () => {
    it("has a meaningful number of keys", () => {
        expect(keys.length).toBeGreaterThan(120);
    });
    it("every key has two non-empty strings (zh, en)", () => {
        for (const key of keys) {
            const pair = MAIL_DICT[key];
            expect(Array.isArray(pair)).toBe(true);
            expect(pair).toHaveLength(2);
            expect(typeof pair[0]).toBe("string");
            expect(typeof pair[1]).toBe("string");
            expect(pair[0].trim().length).toBeGreaterThan(0);
            expect(pair[1].trim().length).toBeGreaterThan(0);
        }
    });
    it("zh and en are not accidentally identical placeholders for prose keys", () => {
        const same = keys.filter((key) => MAIL_DICT[key][0] === MAIL_DICT[key][1]);
        expect(same.length).toBeLessThan(keys.length * 0.1);
    });
});
describe("mt", () => {
    it("returns the language-specific string", () => {
        expect(mt("zh", "folder_inbox")).toBe("收件箱");
        expect(mt("en", "folder_inbox")).toBe("Inbox");
    });
    it("replaces every occurrence of a placeholder (replaceAll semantics)", () => {
        expect(mt("zh", "quota_used", { used: "1.2 MiB", messages: 3 })).toBe("已使用 1.2 MiB · 3 封");
        expect(mt("en", "delete_confirm_body", { n: 2 })).toContain("2 message(s)");
    });
    it("htmlLang maps to BCP47 tags", () => {
        expect(htmlLang("zh")).toBe("zh-CN");
        expect(htmlLang("en")).toBe("en");
    });
});

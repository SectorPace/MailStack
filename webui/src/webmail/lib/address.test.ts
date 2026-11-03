// 收件人地址解析 / 校验 / 去重（写信芯片输入）纯函数测试。
import { describe, expect, it } from "vitest";
import {
  dedupeAddresses,
  isValidAddress,
  mergeAddresses,
  normalizeAddress,
  parseAddresses,
  splitAddressInput,
} from "./address";

describe("isValidAddress", () => {
  it("accepts normal RFC5321-lite addresses", () => {
    expect(isValidAddress("alice@example.com")).toBe(true);
    expect(isValidAddress("alice.smith+tag@mail.example.org")).toBe(true);
    expect(isValidAddress("  bob@example.com  ")).toBe(true);
  });

  it("rejects missing parts, illegal characters and header-injection attempts", () => {
    expect(isValidAddress("")).toBe(false);
    expect(isValidAddress("alice")).toBe(false);
    expect(isValidAddress("a@b")).toBe(false); // 无点域名
    expect(isValidAddress("@example.com")).toBe(false);
    expect(isValidAddress("alice@")).toBe(false);
    expect(isValidAddress("alice@@example.com")).toBe(false);
    expect(isValidAddress("alice@example.com\r\nBcc: evil@example.com")).toBe(false);
    expect(isValidAddress("alice smith@example.com")).toBe(false);
    expect(isValidAddress('"alice"@example.com')).toBe(false);
    expect(isValidAddress("a".repeat(320) + "@example.com")).toBe(false);
  });
});

describe("splitAddressInput", () => {
  it("splits on EN/CN commas, semicolons, newlines and tabs", () => {
    expect(splitAddressInput("a@x.com, b@x.com;c@x.com，d@x.com；e@x.com\nf@x.com\tg@x.com")).toEqual([
      "a@x.com",
      "b@x.com",
      "c@x.com",
      "d@x.com",
      "e@x.com",
      "f@x.com",
      "g@x.com",
    ]);
  });

  it("unwraps Name <addr> forms and tolerates empty input", () => {
    expect(splitAddressInput("Alice <alice@example.com>")).toEqual(["alice@example.com"]);
    expect(splitAddressInput("   ")).toEqual([]);
    expect(splitAddressInput("")).toEqual([]);
  });
});

describe("parseAddresses", () => {
  it("returns valid/invalid/duplicate buckets against existing list", () => {
    const result = parseAddresses("bob@example.com, bad, BOB@example.com, carol@example.com", ["bob@example.com"]);
    expect(result.valid).toEqual(["carol@example.com"]);
    expect(result.invalid).toEqual(["bad"]);
    // 与已有列表重复（大小写不敏感）
    expect(result.duplicates).toEqual(["bob@example.com", "BOB@example.com"]);
  });

  it("dedupes inside the same batch", () => {
    const result = parseAddresses("a@x.com, A@X.com");
    expect(result.valid).toEqual(["a@x.com"]);
    expect(result.duplicates).toEqual(["A@X.com"]);
  });
});

describe("dedupe / merge / normalize", () => {
  it("normalizes case and whitespace for comparison", () => {
    expect(normalizeAddress("  Alice@Example.COM ")).toBe("alice@example.com");
  });

  it("dedupes case-insensitively while keeping the first spelling", () => {
    expect(dedupeAddresses(["Bob@X.com", "bob@x.com", "carol@x.com"])).toEqual(["Bob@X.com", "carol@x.com"]);
  });

  it("merges multiple lists (reply-all 汇总)", () => {
    expect(mergeAddresses(["a@x.com"], ["A@x.com", "b@x.com"], ["c@x.com"])).toEqual(["a@x.com", "b@x.com", "c@x.com"]);
  });
});

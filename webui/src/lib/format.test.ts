// src/lib/format.test.ts —— 格式化助手契约。
// 时区由 vitest.config.ts 的 test.env { TZ: "UTC" } + vitest.setup.ts 钉住：
// 下面的「本地时钟」断言全部是 UTC 钟面（进程启动时即 UTC，Node 24 / Windows 实测有效）。
import { describe, expect, it } from "vitest";
import { cssUrl, formatDayTime, formatTime, parseTimeMs } from "./format";

describe("parseTimeMs", () => {
  it("parses ISO8601 with Z as an absolute instant", () => {
    expect(parseTimeMs("2026-01-02T03:04:05Z")).toBe(Date.UTC(2026, 0, 2, 3, 4, 5));
  });

  it("parses mock 'YYYY-MM-DD HH:mm:ss' (space-separated) as local wall clock", () => {
    // TZ=UTC 下本地墙钟 == UTC，两种写法得到同一毫秒值
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
    // 先转义 \ 再转义 " 的顺序是契约：反序会让新增的反斜杠逃过转义，引号裸奔
    const out = cssUrl('\\"');
    // 内部出现过的每个双引号都必须带反斜杠前缀，首尾各恰有一个定界引号
    expect(out.startsWith('"')).toBe(true);
    expect(out.endsWith('"')).toBe(true);
    const inner = out.slice(1, -1);
    expect(inner.match(/(^|[^\\])"/g)).toBeNull();
    // 收尾必须是 \" —— 引号被转义，声明不会在此提前终止
    expect(inner.endsWith('\\"')).toBe(true);
  });

  it("keeps a full CSS-injection payload inside the quoted value", () => {
    const evil = '"); background:url("http://evil.test/x.png"); url("';
    const out = cssUrl(evil);
    const inner = out.slice(1, -1);
    expect(inner.match(/(^|[^\\])"/g)).toBeNull(); // 所有内嵌引号都被转义
    expect(inner.includes(evil.replaceAll('"', '\\"'))).toBe(true);
  });
});

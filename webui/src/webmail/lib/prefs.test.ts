// Webmail 偏好存储测试：前缀 / 默认值 / 逐字段校验 / 主题解析。
import { describe, expect, it } from "vitest";
import {
  PREFS_KEY,
  defaultPrefs,
  detectLang,
  loadPrefs,
  resolveTheme,
  savePrefs,
  type MailPrefs,
} from "./prefs";

function memoryStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  return {
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => {
      map.set(key, value);
    },
    dump: () => Object.fromEntries(map),
  };
}

describe("存储键与默认值", () => {
  it("uses the mailstack.mail. prefix (contract §5.6)", () => {
    expect(PREFS_KEY.startsWith("mailstack.mail.")).toBe(true);
  });

  it("defaults follow navigator.language and system theme", () => {
    const prefs = defaultPrefs();
    expect(prefs.lang).toBe(detectLang());
    expect(["zh", "en"]).toContain(prefs.lang);
    expect(prefs.theme).toBe("system");
    expect(prefs.pageSize).toBe(50);
    expect(prefs.density).toBe("comfortable");
    expect(prefs.loadRemoteImages).toBe(false);
  });

  it("loads defaults when storage is empty or unavailable", () => {
    expect(loadPrefs(memoryStorage())).toEqual(defaultPrefs());
    expect(loadPrefs(null)).toEqual(defaultPrefs());
  });
});

describe("loadPrefs 校验", () => {
  it("round-trips saved prefs", () => {
    const storage = memoryStorage();
    const prefs: MailPrefs = {
      ...defaultPrefs(),
      displayName: "Alice",
      signature: "sig",
      pageSize: 25,
      density: "compact",
      loadRemoteImages: true,
      theme: "dark",
      lang: "zh",
    };
    savePrefs(prefs, storage);
    expect(loadPrefs(storage)).toEqual(prefs);
  });

  it("falls back on corrupted JSON", () => {
    const storage = memoryStorage({ [PREFS_KEY]: "{not json" });
    expect(loadPrefs(storage)).toEqual(defaultPrefs());
  });

  it("rejects wrong enums/types and clamps pageSize", () => {
    const storage = memoryStorage({
      [PREFS_KEY]: JSON.stringify({
        theme: "banana",
        lang: "fr",
        density: "tiny",
        pageSize: 9999,
        displayName: 42,
        signature: null,
        loadRemoteImages: "yes",
      }),
    });
    const prefs = loadPrefs(storage);
    expect(prefs.theme).toBe("system");
    expect(prefs.lang).toBe(detectLang());
    expect(prefs.density).toBe("comfortable");
    expect(prefs.pageSize).toBe(200);
    expect(prefs.displayName).toBe("");
    expect(prefs.signature).toBe("");
    expect(prefs.loadRemoteImages).toBe(false);
  });

  it("does not throw when setItem fails (private mode)", () => {
    const throwing = {
      getItem: () => null,
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
    };
    expect(() => savePrefs(defaultPrefs(), throwing)).not.toThrow();
  });
});

describe("resolveTheme", () => {
  it("resolves explicit and system themes", () => {
    expect(resolveTheme("light")).toBe("light");
    expect(resolveTheme("dark")).toBe("dark");
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
  });
});

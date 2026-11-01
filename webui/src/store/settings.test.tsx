// src/store/settings.test.tsx —— 持久化偏好 store 契约。
// localStorage 可被外部改写：load() 必须逐字段校验 + 钳制；setCustomBg 必须把
// QuotaExceededError 抛给调用方（Settings 页的 toast 依赖它）。key/形状以源码为准：
//   prefs = "mailstack.prefs.v1"（JSON Prefs），自定义背景 = "mailstack.customBg"（原串）。
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { SettingsProvider, useSettings } from "./settings";

const PREFS_KEY = "mailstack.prefs.v1";
const BG_KEY = "mailstack.customBg";

const wrapper = ({ children }: { children: ReactNode }) => (
  <SettingsProvider>{children}</SettingsProvider>
);
const mount = () => renderHook(() => useSettings(), { wrapper });

beforeEach(() => {
  window.localStorage.clear();
});

describe("SettingsProvider · localStorage validation", () => {
  it("applies defaults when nothing is stored", () => {
    const { result } = mount();
    expect(result.current.prefs).toEqual({
      theme: "light",
      lang: "zh",
      accent: "blue",
      glassLevel: 50,
      reduceTransparency: false,
      increaseContrast: false,
      reduceMotion: false,
      sidebarCollapsed: false,
    });
    expect(result.current.customBg).toBeNull();
  });

  it("falls back to defaults on corrupted JSON", () => {
    window.localStorage.setItem(PREFS_KEY, "{not json at all");
    const { result } = mount();
    expect(result.current.prefs.theme).toBe("light");
    expect(result.current.prefs.glassLevel).toBe(50);
  });

  it("rejects wrong enum values and string-typed fields per key", () => {
    window.localStorage.setItem(
      PREFS_KEY,
      JSON.stringify({
        theme: "banana",
        lang: "fr",
        accent: "pink",
        glassLevel: "80", // 字符串数字必须被拒（原实现 as Partial<Prefs> 会放行）
        reduceTransparency: "yes",
      }),
    );
    const { result } = mount();
    expect(result.current.prefs.theme).toBe("light");
    expect(result.current.prefs.lang).toBe("zh");
    expect(result.current.prefs.accent).toBe("blue");
    expect(result.current.prefs.glassLevel).toBe(50);
    expect(result.current.prefs.reduceTransparency).toBe(false);
  });

  it("clamps glassLevel into 0..100 with rounding", () => {
    const cases: [unknown, number][] = [
      [{ glassLevel: 250 }, 100],
      [{ glassLevel: -8.6 }, 0],
      [{ glassLevel: 42.4 }, 42],
      [{ glassLevel: Number.POSITIVE_INFINITY }, 50], // 非有限数 → 默认
    ];
    for (const [stored, expected] of cases) {
      window.localStorage.setItem(PREFS_KEY, JSON.stringify(stored));
      const harness = mount();
      expect(harness.result.current.prefs.glassLevel).toBe(expected);
      harness.unmount();
    }
  });

  it("keeps valid values (theme/lang/accent/flags) and resolves theme", () => {
    window.localStorage.setItem(
      PREFS_KEY,
      JSON.stringify({
        theme: "dark",
        lang: "en",
        accent: "purple",
        glassLevel: 80,
        reduceTransparency: true,
        increaseContrast: true,
        reduceMotion: true,
      }),
    );
    const { result } = mount();
    expect(result.current.prefs.theme).toBe("dark");
    expect(result.current.prefs.lang).toBe("en");
    expect(result.current.prefs.accent).toBe("purple");
    expect(result.current.prefs.glassLevel).toBe(80);
    expect(result.current.prefs.reduceTransparency).toBe(true);
    expect(result.current.resolvedTheme).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("migrates the legacy sidebar-collapse key into prefs and removes it", () => {
    window.localStorage.setItem("mailstack.sidebar-collapsed", "1");
    const { result } = mount();
    expect(result.current.prefs.sidebarCollapsed).toBe(true);
    expect(window.localStorage.getItem("mailstack.sidebar-collapsed")).toBeNull();
    // 迁移结果持久化，下次加载不再依赖旧键
    act(() => {
      result.current.setSidebarCollapsed(false);
    });
    expect(result.current.prefs.sidebarCollapsed).toBe(false);
  });

  it("abandons the legacy merge when the prefs payload itself is corrupted", () => {
    window.localStorage.setItem(PREFS_KEY, "{corrupted");
    window.localStorage.setItem("mailstack.sidebar-collapsed", "1");
    const { result } = mount();
    // prefs 损坏 → 整体回落默认值，不产出半迁移状态
    expect(result.current.prefs).toEqual({
      theme: "light",
      lang: "zh",
      accent: "blue",
      glassLevel: 50,
      reduceTransparency: false,
      increaseContrast: false,
      reduceMotion: false,
      sidebarCollapsed: false,
    });
  });
});

describe("SettingsProvider · custom background", () => {
  it("setCustomBg persists the value and reset removes it", () => {
    const { result } = mount();
    act(() => {
      result.current.setCustomBg("data:image/gif;base64,BBB");
    });
    expect(result.current.customBg).toBe("data:image/gif;base64,BBB");
    expect(window.localStorage.getItem(BG_KEY)).toBe("data:image/gif;base64,BBB");

    act(() => {
      result.current.setCustomBg(null);
    });
    expect(result.current.customBg).toBeNull();
    expect(window.localStorage.getItem(BG_KEY)).toBeNull();
  });

  it("rethrows the quota error to the caller while the session state still updates", () => {
    const { result } = mount();
    const spy = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("quota exceeded", "QuotaExceededError");
    });

    let thrown: unknown;
    act(() => {
      try {
        result.current.setCustomBg("data:image/png;base64,AAA");
      } catch (e) {
        thrown = e;
      }
    });

    spy.mockRestore();

    expect(thrown).toBeInstanceOf(DOMException);
    expect((thrown as DOMException).name).toBe("QuotaExceededError");
    // 状态先落地：持久化失败时至少当前会话生效（源码注释的契约）
    expect(result.current.customBg).toBe("data:image/png;base64,AAA");
    // 但存储里没有写进去
    expect(window.localStorage.getItem(BG_KEY)).toBeNull();
  });
});

describe("SettingsProvider · persistence", () => {
  it("writes preference changes back to the storage key", () => {
    const { result } = mount();
    act(() => {
      result.current.setGlassLevel(80);
    });
    expect(result.current.prefs.glassLevel).toBe(80);
    const raw = JSON.parse(window.localStorage.getItem(PREFS_KEY) ?? "{}") as Record<
      string,
      unknown
    >;
    expect(raw.glassLevel).toBe(80);
  });
});

describe("useSettings guard", () => {
  it("throws when used outside SettingsProvider", () => {
    expect(() => renderHook(() => useSettings())).toThrow(/SettingsProvider/);
  });
});

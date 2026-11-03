// Webmail 偏好 Provider —— 把 lib/prefs.ts 的纯数据层接到 React：
//   * 保存即持久化（localStorage `mailstack.mail.prefs.v1`）；
//   * 主题解析（light/dark/system 跟随系统）、`<html data-theme>` 与 lang 实时应用；
//   * `t()` 随语言切换即时生效（组件重渲染，无需刷新）。

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  defaultPrefs,
  loadPrefs,
  resolveTheme,
  savePrefs,
  type Density,
  type MailPrefs,
  type ThemeMode,
} from "../lib/prefs";
import { htmlLang, mt, type Lang, type MailKey } from "../i18n";

type MailPrefsContextValue = {
  prefs: MailPrefs;
  resolvedTheme: "light" | "dark";
  setPrefs: (patch: Partial<MailPrefs>) => void;
  setTheme: (theme: ThemeMode) => void;
  setLang: (lang: Lang) => void;
  setDensity: (density: Density) => void;
  /** 当前语言文案；参数 `{name}` 占位替换。 */
  t: (key: MailKey, params?: Record<string, string | number>) => string;
};

const MailPrefsContext = createContext<MailPrefsContextValue | null>(null);

function systemPrefersDark(): boolean {
  try {
    return typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
  } catch {
    return false;
  }
}

export function MailPrefsProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefsState] = useState<MailPrefs>(() => {
    try {
      return loadPrefs();
    } catch {
      return defaultPrefs();
    }
  });
  const [systemDark, setSystemDark] = useState<boolean>(systemPrefersDark);

  useEffect(() => {
    let mq: MediaQueryList | null = null;
    try {
      mq = matchMedia("(prefers-color-scheme: dark)");
    } catch {
      return;
    }
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mq.addEventListener("change", onChange);
    return () => mq?.removeEventListener("change", onChange);
  }, []);

  const resolvedTheme: "light" | "dark" = resolveTheme(prefs.theme, prefs.theme === "system" ? systemDark : undefined);

  // 持久化（失败静默：本会话仍生效；隐私模式不阻塞界面）。
  useEffect(() => {
    savePrefs(prefs);
  }, [prefs]);

  // 主题 / 语言落到 <html>（data-theme 是 index.css token 的开关；lang 影响读屏与断词）。
  useEffect(() => {
    if (typeof document === "undefined") return;
    const root = document.documentElement;
    root.dataset.theme = resolvedTheme;
    root.lang = htmlLang(prefs.lang);
  }, [resolvedTheme, prefs.lang]);

  const setPrefs = useCallback((patch: Partial<MailPrefs>) => {
    setPrefsState((prev) => ({ ...prev, ...patch }));
  }, []);
  const setTheme = useCallback((theme: ThemeMode) => setPrefs({ theme }), [setPrefs]);
  const setLang = useCallback((lang: Lang) => setPrefs({ lang }), [setPrefs]);
  const setDensity = useCallback((density: Density) => setPrefs({ density }), [setPrefs]);

  const value = useMemo<MailPrefsContextValue>(
    () => ({
      prefs,
      resolvedTheme,
      setPrefs,
      setTheme,
      setLang,
      setDensity,
      t: (key, params) => mt(prefs.lang, key, params),
    }),
    [prefs, resolvedTheme, setPrefs, setTheme, setLang, setDensity],
  );

  return <MailPrefsContext.Provider value={value}>{children}</MailPrefsContext.Provider>;
}

export function useMailPrefs(): MailPrefsContextValue {
  const value = useContext(MailPrefsContext);
  if (!value) throw new Error("useMailPrefs must be used within MailPrefsProvider");
  return value;
}

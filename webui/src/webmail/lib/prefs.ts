// Webmail 本机偏好（契约 §5.6：全部只存 localStorage，不建后端接口）。
//
// 存储键统一前缀 `mailstack.mail.`：与管理台的 `mailstack.prefs.v1` 完全隔离 ——
// 管理台与 Webmail 是两个进程/两个入口，用户在两处的语言、主题选择可以不同。
//
// 安全/健壮性：localStorage 可被同源脚本或用户手工改写，load 时逐字段校验类型与
// 取值范围，非法值回落默认（与 admin `store/settings.tsx` 的既有纪律一致）。

import type { Lang } from "../i18n";

export const PREFS_KEY = "mailstack.mail.prefs.v1";

export type ThemeMode = "light" | "dark" | "system";
export type Density = "comfortable" | "compact";

export type MailPrefs = {
  /** 本地展示名（账户菜单与签名署名）；留空时回落后端 displayName。 */
  displayName: string;
  /** 纯文本签名，写信时自动追加。 */
  signature: string;
  /** 列表分页大小（后端 limit）。 */
  pageSize: number;
  /** 阅读密度：舒适 / 紧凑。 */
  density: Density;
  /** 总是加载远程图片（跳过阅读窗格的图片阻断横幅）。 */
  loadRemoteImages: boolean;
  theme: ThemeMode;
  lang: Lang;
};

export const PAGE_SIZE_OPTIONS = [25, 50, 100] as const;

/** 当前浏览器语言 → 默认界面语言（契约 §5.9：默认按 navigator.language）。 */
export function detectLang(): Lang {
  try {
    const nav = typeof navigator !== "undefined" ? navigator.language : "";
    return /^zh/i.test(nav ?? "") ? "zh" : "en";
  } catch {
    return "en";
  }
}

export function defaultPrefs(): MailPrefs {
  return {
    displayName: "",
    signature: "",
    pageSize: 50,
    density: "comfortable",
    loadRemoteImages: false,
    theme: "system",
    lang: detectLang(),
  };
}

type StorageLike = Pick<Storage, "getItem" | "setItem">;

function storageOrNull(): StorageLike | null {
  try {
    return typeof localStorage !== "undefined" ? localStorage : null;
  } catch {
    return null;
  }
}

function asString(v: unknown, fallback: string): string {
  return typeof v === "string" ? v : fallback;
}

function asBool(v: unknown, fallback: boolean): boolean {
  return typeof v === "boolean" ? v : fallback;
}

/** 加载偏好：逐字段校验 + 钳制，损坏/缺失/存储不可用一律回落默认。 */
export function loadPrefs(storage: StorageLike | null = storageOrNull()): MailPrefs {
  const base = defaultPrefs();
  if (!storage) return base;
  let raw: string | null = null;
  try {
    raw = storage.getItem(PREFS_KEY);
  } catch {
    return base;
  }
  if (!raw) return base;
  try {
    const j = JSON.parse(raw) as Record<string, unknown>;
    if (!j || typeof j !== "object" || Array.isArray(j)) return base;
    const theme = j.theme === "light" || j.theme === "dark" || j.theme === "system" ? j.theme : base.theme;
    const lang = j.lang === "zh" || j.lang === "en" ? j.lang : base.lang;
    const density = j.density === "compact" || j.density === "comfortable" ? j.density : base.density;
    const pageSize =
      typeof j.pageSize === "number" && Number.isFinite(j.pageSize)
        ? Math.min(200, Math.max(10, Math.round(j.pageSize)))
        : base.pageSize;
    return {
      displayName: asString(j.displayName, base.displayName).slice(0, 120),
      signature: asString(j.signature, base.signature).slice(0, 4000),
      pageSize,
      density,
      loadRemoteImages: asBool(j.loadRemoteImages, base.loadRemoteImages),
      theme,
      lang,
    };
  } catch {
    return base;
  }
}

/** 持久化偏好（失败静默：隐私模式/配额满时本会话内仍生效）。 */
export function savePrefs(prefs: MailPrefs, storage: StorageLike | null = storageOrNull()): void {
  if (!storage) return;
  try {
    storage.setItem(PREFS_KEY, JSON.stringify(prefs));
  } catch {
    /* 存储不可用：仅本会话生效 */
  }
}

/** 主题解析：system 跟随 `prefers-color-scheme`；无 matchMedia 时按浅色。 */
export function resolveTheme(theme: ThemeMode, prefersDark?: boolean): "light" | "dark" {
  if (theme === "dark") return "dark";
  if (theme === "light") return "light";
  const dark =
    typeof prefersDark === "boolean"
      ? prefersDark
      : typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
  return dark ? "dark" : "light";
}

/**
 * 把主题 / 语言 / 平台初值写到 `<html>`（首帧 preboot 与运行时 Provider 共用）。
 * 平台度量（data-platform）初值是 `theme-init.js` 的职责；这里只补主题与语言。
 */
export function applyPrefsToDocument(prefs: MailPrefs, root?: HTMLElement): void {
  if (typeof document === "undefined") return;
  const el = root ?? document.documentElement;
  el.dataset.theme = resolveTheme(prefs.theme);
  el.lang = prefs.lang === "zh" ? "zh-CN" : "en";
}

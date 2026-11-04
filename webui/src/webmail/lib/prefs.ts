import type { Lang } from "../i18n";
export const PREFS_KEY = "mailstack.mail.prefs.v1";
export type ThemeMode = "light" | "dark" | "system";
export type Density = "comfortable" | "compact";
export type MailPrefs = {
    displayName: string;
    signature: string;
    pageSize: number;
    density: Density;
    loadRemoteImages: boolean;
    theme: ThemeMode;
    lang: Lang;
};
export const PAGE_SIZE_OPTIONS = [25, 50, 100] as const;
export function detectLang(): Lang {
    try {
        const nav = typeof navigator !== "undefined" ? navigator.language : "";
        return /^zh/i.test(nav ?? "") ? "zh" : "en";
    }
    catch {
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
    }
    catch {
        return null;
    }
}
function asString(v: unknown, fallback: string): string {
    return typeof v === "string" ? v : fallback;
}
function asBool(v: unknown, fallback: boolean): boolean {
    return typeof v === "boolean" ? v : fallback;
}
export function loadPrefs(storage: StorageLike | null = storageOrNull()): MailPrefs {
    const base = defaultPrefs();
    if (!storage)
        return base;
    let raw: string | null = null;
    try {
        raw = storage.getItem(PREFS_KEY);
    }
    catch {
        return base;
    }
    if (!raw)
        return base;
    try {
        const j = JSON.parse(raw) as Record<string, unknown>;
        if (!j || typeof j !== "object" || Array.isArray(j))
            return base;
        const theme = j.theme === "light" || j.theme === "dark" || j.theme === "system" ? j.theme : base.theme;
        const lang = j.lang === "zh" || j.lang === "en" ? j.lang : base.lang;
        const density = j.density === "compact" || j.density === "comfortable" ? j.density : base.density;
        const pageSize = typeof j.pageSize === "number" && Number.isFinite(j.pageSize)
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
    }
    catch {
        return base;
    }
}
export function savePrefs(prefs: MailPrefs, storage: StorageLike | null = storageOrNull()): void {
    if (!storage)
        return;
    try {
        storage.setItem(PREFS_KEY, JSON.stringify(prefs));
    }
    catch {
    }
}
export function resolveTheme(theme: ThemeMode, prefersDark?: boolean): "light" | "dark" {
    if (theme === "dark")
        return "dark";
    if (theme === "light")
        return "light";
    const dark = typeof prefersDark === "boolean"
        ? prefersDark
        : typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
    return dark ? "dark" : "light";
}
export function applyPrefsToDocument(prefs: MailPrefs, root?: HTMLElement): void {
    if (typeof document === "undefined")
        return;
    const el = root ?? document.documentElement;
    el.dataset.theme = resolveTheme(prefs.theme);
    el.lang = prefs.lang === "zh" ? "zh-CN" : "en";
}

export type MailShortcut = "compose" | "reply" | "replyAll" | "forward" | "next" | "prev" | "toggleUnread" | "toggleStar" | "archive" | "delete" | "search" | "escape";
export type ShortcutEventLike = {
    key: string;
    ctrlKey?: boolean;
    metaKey?: boolean;
    altKey?: boolean;
};
const LETTER_SHORTCUTS: Record<string, MailShortcut> = {
    c: "compose",
    r: "reply",
    a: "replyAll",
    f: "forward",
    j: "next",
    k: "prev",
    u: "toggleUnread",
    s: "toggleStar",
    e: "archive",
};
export function isEditableTarget(target: EventTarget | null): boolean {
    if (!target || typeof target !== "object")
        return false;
    const el = target as {
        tagName?: string;
        isContentEditable?: boolean;
        getAttribute?: (name: string) => string | null;
        closest?: (selector: string) => unknown;
    };
    const tag = (el.tagName ?? "").toUpperCase();
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT")
        return true;
    if (el.isContentEditable === true)
        return true;
    if (typeof el.getAttribute === "function") {
        const attr = el.getAttribute("contenteditable");
        if (attr === "true" || attr === "")
            return true;
    }
    if (typeof el.closest === "function" && el.closest("[contenteditable]"))
        return true;
    return false;
}
export function resolveShortcut(ev: ShortcutEventLike): MailShortcut | null {
    if (ev.ctrlKey || ev.metaKey || ev.altKey)
        return null;
    const key = ev.key ?? "";
    if (key === "Escape")
        return "escape";
    if (key === "Delete")
        return "delete";
    if (key === "#")
        return "delete";
    if (key === "/")
        return "search";
    const lower = key.toLowerCase();
    return LETTER_SHORTCUTS[lower] ?? null;
}

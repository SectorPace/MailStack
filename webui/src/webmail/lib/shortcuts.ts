// 键盘快捷键解析（纯函数）—— 契约 §5.7：
//   c 写信 / r 回复 / a 全部回复 / f 转发 / j 下一封 / k 上一封 / u 未读切换 /
//   s 星标 / e 归档 / # 或 Delete 删除 / / 搜索 / Esc 关闭。
//
// 两条纪律：
//  1. 带 Ctrl/Meta/Alt 的组合键不吞（浏览器/系统快捷键优先）；
//  2. 输入框、文本域、下拉、contenteditable 聚焦时一律不触发（`isEditableTarget`）。

export type MailShortcut =
  | "compose"
  | "reply"
  | "replyAll"
  | "forward"
  | "next"
  | "prev"
  | "toggleUnread"
  | "toggleStar"
  | "archive"
  | "delete"
  | "search"
  | "escape";

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

/** 输入类元素判定（keydown 的 target 可能是子节点，需向上找 contenteditable）。 */
export function isEditableTarget(target: EventTarget | null): boolean {
  if (!target || typeof target !== "object") return false;
  const el = target as {
    tagName?: string;
    isContentEditable?: boolean;
    getAttribute?: (name: string) => string | null;
    closest?: (selector: string) => unknown;
  };
  const tag = (el.tagName ?? "").toUpperCase();
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (el.isContentEditable === true) return true;
  if (typeof el.getAttribute === "function") {
    const attr = el.getAttribute("contenteditable");
    if (attr === "true" || attr === "") return true;
  }
  if (typeof el.closest === "function" && el.closest("[contenteditable]")) return true;
  return false;
}

/**
 * 事件 → 快捷键动作；不匹配/应忽略时返回 null。
 * 注意 `#` 在多数键盘布局上是 Shift+3，因此这里**不**因 shiftKey 而拒绝。
 */
export function resolveShortcut(ev: ShortcutEventLike): MailShortcut | null {
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return null;
  const key = ev.key ?? "";
  if (key === "Escape") return "escape";
  if (key === "Delete") return "delete";
  if (key === "#") return "delete";
  if (key === "/") return "search";
  const lower = key.toLowerCase();
  return LETTER_SHORTCUTS[lower] ?? null;
}

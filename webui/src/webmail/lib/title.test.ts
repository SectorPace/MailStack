// document.title 未读计数 / 键盘快捷键解析的纯函数测试。
import { describe, expect, it } from "vitest";
import { buildDocumentTitle } from "./title";
import { isEditableTarget, resolveShortcut } from "./shortcuts";

describe("buildDocumentTitle", () => {
  it("prefixes unread count when positive", () => {
    expect(buildDocumentTitle(3, "Inbox")).toBe("(3) Inbox · MailStack Webmail");
    expect(buildDocumentTitle(1, "收件箱")).toBe("(1) 收件箱 · MailStack Webmail");
  });

  it("omits the counter at zero and tolerates junk counts", () => {
    expect(buildDocumentTitle(0, "Inbox")).toBe("Inbox · MailStack Webmail");
    expect(buildDocumentTitle(Number.NaN, "Inbox")).toBe("Inbox · MailStack Webmail");
    expect(buildDocumentTitle(-2, "Inbox")).toBe("Inbox · MailStack Webmail");
    expect(buildDocumentTitle(2, "")).toBe("(2) MailStack Webmail");
  });
});

describe("resolveShortcut", () => {
  it("maps the contract shortcut set", () => {
    expect(resolveShortcut({ key: "c" })).toBe("compose");
    expect(resolveShortcut({ key: "r" })).toBe("reply");
    expect(resolveShortcut({ key: "a" })).toBe("replyAll");
    expect(resolveShortcut({ key: "f" })).toBe("forward");
    expect(resolveShortcut({ key: "j" })).toBe("next");
    expect(resolveShortcut({ key: "k" })).toBe("prev");
    expect(resolveShortcut({ key: "u" })).toBe("toggleUnread");
    expect(resolveShortcut({ key: "s" })).toBe("toggleStar");
    expect(resolveShortcut({ key: "e" })).toBe("archive");
    expect(resolveShortcut({ key: "#" })).toBe("delete");
    expect(resolveShortcut({ key: "Delete" })).toBe("delete");
    expect(resolveShortcut({ key: "/" })).toBe("search");
    expect(resolveShortcut({ key: "Escape" })).toBe("escape");
  });

  it("is case-insensitive for letters and ignores modified combos", () => {
    expect(resolveShortcut({ key: "C" })).toBe("compose");
    expect(resolveShortcut({ key: "c", ctrlKey: true })).toBeNull();
    expect(resolveShortcut({ key: "c", metaKey: true })).toBeNull();
    expect(resolveShortcut({ key: "c", altKey: true })).toBeNull();
    // Shift 不拦截：# 在多数键盘上是 Shift+3
    expect(resolveShortcut({ key: "#" })).toBe("delete");
  });

  it("returns null for unmapped keys", () => {
    expect(resolveShortcut({ key: "x" })).toBeNull();
    expect(resolveShortcut({ key: "Enter" })).toBeNull();
  });
});

describe("isEditableTarget", () => {
  it("detects inputs, textareas, selects and contenteditable", () => {
    const input = document.createElement("input");
    const textarea = document.createElement("textarea");
    const select = document.createElement("select");
    const div = document.createElement("div");
    div.setAttribute("contenteditable", "true");
    const span = document.createElement("span");
    div.appendChild(span);
    expect(isEditableTarget(input)).toBe(true);
    expect(isEditableTarget(textarea)).toBe(true);
    expect(isEditableTarget(select)).toBe(true);
    expect(isEditableTarget(div)).toBe(true);
    // 子节点在 contenteditable 容器内也算可编辑（事件 target 通常是深层节点）
    expect(isEditableTarget(span)).toBe(true);
    expect(isEditableTarget(null)).toBe(false);
    expect(isEditableTarget(document.body)).toBe(false);
  });
});

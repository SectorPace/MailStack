// 写信的草稿组装 / 校验（纯函数）—— App 与 Compose 组件共用，覆盖：
//   * 新邮件 / 回复 / 全部回复 / 转发 / 编辑草稿 的初始内容；
//   * 签名自动追加（纯文本，localStorage 偏好）；
//   * 收件人校验（To/Cc/Bcc 合计至少一个合法地址）；
//   * 附件总量 ≤ 25 MiB 预校验；
//   * ComposeRequest 组装的唯一入口（避免组件里散装字段拼错）。

import type { ComposeAttachment, ComposeRequest, MessageDetail } from "../types";
import type { Lang } from "../i18n";
import type { MailPrefs } from "./prefs";
import { buildReplyDraft, type ReplyKind } from "./reply";
import { dedupeAddresses, isValidAddress } from "./address";
import { escapeHtml, htmlToPlain, sanitizeEditorHtml, textToHtml } from "./html";

/** 单封邮件附件总量上限（契约 §2.2：25 MiB，base64 解码后计算）。 */
export const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

export type ComposeKind = "new" | ReplyKind | "draft";

export type ComposeInitial = {
  kind: ComposeKind;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text: string;
  html: string;
  inReplyTo?: string;
  references: string[];
  /** 编辑已存草稿时带上旧 uid（保存成功后服务端会 expunge 旧草稿）。 */
  draftUid: number | null;
};

/** 头像/签名署名的展示名：本地偏好优先，其次后端 displayName。 */
export function effectiveDisplayName(prefs: Pick<MailPrefs, "displayName">, backendName?: string | null): string {
  const local = (prefs.displayName ?? "").trim();
  if (local) return local;
  return (backendName ?? "").trim();
}

/** 签名 HTML：`-- ` 分隔线 + 名字 + 正文（全部转义）。没有签名时返回空串。 */
export function signatureHtml(prefs: Pick<MailPrefs, "signature" | "displayName">, backendName?: string | null): string {
  const name = effectiveDisplayName(prefs, backendName);
  const sig = (prefs.signature ?? "").replace(/\r\n|\r/g, "\n").trimEnd();
  if (!name && !sig) return "";
  const lines = ["--", name, sig].filter((x) => x !== "").map((x) => escapeHtml(x).replace(/\n/g, "<br>"));
  return `<p>${lines.join("<br>")}</p>`;
}

/** 签名纯文本版本（与 HTML 对齐，供 text 兜底）。 */
export function signatureText(prefs: Pick<MailPrefs, "signature" | "displayName">, backendName?: string | null): string {
  const name = effectiveDisplayName(prefs, backendName);
  const sig = (prefs.signature ?? "").trimEnd();
  const lines = ["--", name, sig].filter((x) => x !== "");
  return lines.length ? `\n\n${lines.join("\n")}` : "";
}

/** 新邮件：空收件人 + 主题，正文只有签名（光标停在正文最前）。 */
export function buildNewCompose(
  prefs: Pick<MailPrefs, "signature" | "displayName">,
  backendName?: string | null,
): ComposeInitial {
  const sigHtml = signatureHtml(prefs, backendName);
  const sigText = signatureText(prefs, backendName);
  return {
    kind: "new",
    to: [],
    cc: [],
    bcc: [],
    subject: "",
    text: `\n${sigText}`,
    html: `<p><br></p>${sigHtml}`,
    references: [],
    draftUid: null,
  };
}

/** 回复 / 全部回复 / 转发：预填收件人、主题前缀、引用原文，签名放在引用之前。 */
export function buildReplyCompose(
  kind: ReplyKind,
  detail: MessageDetail,
  prefs: Pick<MailPrefs, "signature" | "displayName">,
  opts: { self: string; lang: Lang; backendName?: string | null },
): ComposeInitial {
  const draft = buildReplyDraft(detail, kind, { self: opts.self, lang: opts.lang });
  const sigHtml = signatureHtml(prefs, opts.backendName);
  const sigText = signatureText(prefs, opts.backendName);
  return {
    kind,
    to: draft.to,
    cc: draft.cc,
    bcc: draft.bcc,
    subject: draft.subject,
    text: `\n${sigText}\n${draft.text}`,
    // 光标位置在最前：空段落 → 签名 → 引用原文。
    html: `<p><br></p>${sigHtml}${draft.html}`,
    inReplyTo: draft.inReplyTo,
    references: draft.references,
    draftUid: null,
  };
}

/**
 * 编辑已有草稿：把服务端返回的已消毒正文放回编辑器（sanitizeEditorHtml 只做纵深
 * 防御，服务端消毒器才是权威）。收件人取 headers.to/cc/bcc。
 */
export function buildDraftCompose(detail: MessageDetail): ComposeInitial {
  const h = detail.headers;
  const list = (arr: { address: string }[] | null | undefined): string[] =>
    Array.isArray(arr) ? arr.map((a) => (a?.address ?? "").trim()).filter(Boolean) : [];
  const html = sanitizeEditorHtml(detail.body?.html ?? textToHtml(detail.body?.text ?? ""));
  const text = detail.body?.text ?? htmlToPlain(html);
  return {
    kind: "draft",
    to: list(h.to),
    cc: list(h.cc),
    bcc: list(h.bcc),
    subject: h.subject ?? "",
    text,
    html,
    references: Array.isArray(h.references) ? h.references.filter(Boolean) : [],
    draftUid: detail.uid,
  };
}

export type ComposeValidation = {
  ok: boolean;
  /** 一个收件人都没有（To/Cc/Bcc 全空）。 */
  missingRecipients: boolean;
  /** 非空但不合法的地址（理论上芯片输入已经挡住，这里兜底）。 */
  invalid: string[];
};

/** 收件人校验（To/Cc/Bcc 合计）。 */
export function validateCompose(input: { to: string[]; cc: string[]; bcc: string[] }): ComposeValidation {
  const all = [...input.to, ...input.cc, ...input.bcc].map((a) => (a ?? "").trim()).filter(Boolean);
  const invalid = all.filter((a) => !isValidAddress(a));
  return {
    ok: all.length > 0 && invalid.length === 0,
    missingRecipients: all.length === 0,
    invalid: dedupeAddresses(invalid),
  };
}

/** 附件总量（字节）。 */
export function totalAttachmentSize(list: readonly { size: number }[]): number {
  return list.reduce((sum, item) => sum + (Number.isFinite(item.size) ? Math.max(0, item.size) : 0), 0);
}

/** 新增附件后是否仍在 25 MiB 以内。 */
export function canAddAttachment(currentTotal: number, nextSize: number): boolean {
  return currentTotal + Math.max(0, nextSize) <= MAX_ATTACHMENT_BYTES;
}

export type ComposeInput = {
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text: string;
  html: string;
  inReplyTo?: string;
  references: string[];
  attachments: readonly ComposeAttachment[];
};

/**
 * 组装 ComposeRequest：地址去重、主题/正文不裁剪（服务端做头注入防护），
 * 空的可选字段不发送（服务端按缺省处理）。
 */
export function buildComposeRequest(input: ComposeInput): ComposeRequest {
  const req: ComposeRequest = {
    to: dedupeAddresses(input.to),
    cc: dedupeAddresses(input.cc),
    bcc: dedupeAddresses(input.bcc),
    subject: input.subject ?? "",
    text: input.text ?? "",
    html: input.html ?? "",
  };
  const inReplyTo = (input.inReplyTo ?? "").trim();
  if (inReplyTo) req.inReplyTo = inReplyTo;
  const references = Array.isArray(input.references) ? input.references.filter(Boolean) : [];
  if (references.length) req.references = references;
  const attachments = Array.isArray(input.attachments) ? input.attachments : [];
  if (attachments.length) {
    req.attachments = attachments.map((a) => ({
      filename: a.filename,
      contentType: a.contentType || "application/octet-stream",
      dataBase64: a.dataBase64,
    }));
  }
  return req;
}

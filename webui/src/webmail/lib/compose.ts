import type { ComposeAttachment, ComposeRequest, MessageDetail } from "../types";
import type { Lang } from "../i18n";
import type { MailPrefs } from "./prefs";
import { buildReplyDraft, type ReplyKind } from "./reply";
import { dedupeAddresses, isValidAddress } from "./address";
import { escapeHtml, htmlToPlain, sanitizeEditorHtml, textToHtml } from "./html";
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
    draftUid: number | null;
};
export function effectiveDisplayName(prefs: Pick<MailPrefs, "displayName">, backendName?: string | null): string {
    const local = (prefs.displayName ?? "").trim();
    if (local)
        return local;
    return (backendName ?? "").trim();
}
export function signatureHtml(prefs: Pick<MailPrefs, "signature" | "displayName">, backendName?: string | null): string {
    const name = effectiveDisplayName(prefs, backendName);
    const sig = (prefs.signature ?? "").replace(/\r\n|\r/g, "\n").trimEnd();
    if (!name && !sig)
        return "";
    const lines = ["--", name, sig].filter((x) => x !== "").map((x) => escapeHtml(x).replace(/\n/g, "<br>"));
    return `<p>${lines.join("<br>")}</p>`;
}
export function signatureText(prefs: Pick<MailPrefs, "signature" | "displayName">, backendName?: string | null): string {
    const name = effectiveDisplayName(prefs, backendName);
    const sig = (prefs.signature ?? "").trimEnd();
    const lines = ["--", name, sig].filter((x) => x !== "");
    return lines.length ? `\n\n${lines.join("\n")}` : "";
}
export function buildNewCompose(prefs: Pick<MailPrefs, "signature" | "displayName">, backendName?: string | null): ComposeInitial {
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
export function buildReplyCompose(kind: ReplyKind, detail: MessageDetail, prefs: Pick<MailPrefs, "signature" | "displayName">, opts: {
    self: string;
    lang: Lang;
    backendName?: string | null;
}): ComposeInitial {
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
        html: `<p><br></p>${sigHtml}${draft.html}`,
        inReplyTo: draft.inReplyTo,
        references: draft.references,
        draftUid: null,
    };
}
export function buildDraftCompose(detail: MessageDetail): ComposeInitial {
    const h = detail.headers;
    const list = (arr: {
        address: string;
    }[] | null | undefined): string[] => Array.isArray(arr) ? arr.map((a) => (a?.address ?? "").trim()).filter(Boolean) : [];
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
    missingRecipients: boolean;
    invalid: string[];
};
export function validateCompose(input: {
    to: string[];
    cc: string[];
    bcc: string[];
}): ComposeValidation {
    const all = [...input.to, ...input.cc, ...input.bcc].map((a) => (a ?? "").trim()).filter(Boolean);
    const invalid = all.filter((a) => !isValidAddress(a));
    return {
        ok: all.length > 0 && invalid.length === 0,
        missingRecipients: all.length === 0,
        invalid: dedupeAddresses(invalid),
    };
}
export function totalAttachmentSize(list: readonly {
    size: number;
}[]): number {
    return list.reduce((sum, item) => sum + (Number.isFinite(item.size) ? Math.max(0, item.size) : 0), 0);
}
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
    if (inReplyTo)
        req.inReplyTo = inReplyTo;
    const references = Array.isArray(input.references) ? input.references.filter(Boolean) : [];
    if (references.length)
        req.references = references;
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

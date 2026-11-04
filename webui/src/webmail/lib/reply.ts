import type { MailAddress, MessageDetail } from "../types";
import type { Lang } from "../i18n";
import { formatAddressList, formatFullDate } from "./format";
import { escapeHtml, htmlToPlain, textToParagraphHtml } from "./html";
import { dedupeAddresses, normalizeAddress } from "./address";
export type ReplyKind = "reply" | "replyAll" | "forward";
export type ReplyDraft = {
    to: string[];
    cc: string[];
    bcc: string[];
    subject: string;
    text: string;
    html: string;
    inReplyTo?: string;
    references: string[];
};
export function replySubject(subject: string, kind: ReplyKind): string {
    const s = (subject ?? "").trim();
    if (kind === "forward") {
        return /^(fwd?|转发)\s*:/i.test(s) ? s : `Fwd: ${s}`;
    }
    return /^re\s*:/i.test(s) ? s : `Re: ${s}`;
}
function addressList(list: MailAddress[] | null | undefined): string[] {
    if (!Array.isArray(list))
        return [];
    return list.map((a) => (a?.address ?? "").trim()).filter(Boolean);
}
function notSelf(addresses: readonly string[], self: string): string[] {
    const me = normalizeAddress(self);
    if (!me)
        return [...addresses];
    return addresses.filter((a) => normalizeAddress(a) !== me);
}
function dedupeStrings(list: readonly string[]): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const item of list) {
        const key = item.trim().toLowerCase();
        if (!key || seen.has(key))
            continue;
        seen.add(key);
        out.push(item.trim());
    }
    return out;
}
export function replyRecipients(detail: MessageDetail, kind: ReplyKind, self: string): {
    to: string[];
    cc: string[];
} {
    if (kind === "forward")
        return { to: [], cc: [] };
    const h = detail.headers;
    const replyTargets = addressList(h.replyTo);
    const primary = replyTargets[0] ?? (h.from?.address ?? "").trim();
    if (kind === "reply") {
        return { to: dedupeAddresses([primary].filter(Boolean)), cc: [] };
    }
    const to = dedupeAddresses([primary, ...addressList(h.to)].filter(Boolean));
    const toFiltered = notSelf(to, self);
    const cc = notSelf(addressList(h.cc), self).filter((addr) => !toFiltered.some((t) => normalizeAddress(t) === normalizeAddress(addr)));
    return { to: toFiltered, cc: dedupeAddresses(cc) };
}
export function quotedBodyText(detail: MessageDetail): string {
    const text = detail.body?.text;
    if (typeof text === "string" && text.trim())
        return text.replace(/\s+$/, "");
    const html = detail.body?.html;
    if (typeof html === "string" && html.trim())
        return htmlToPlain(html);
    return "";
}
function attribution(detail: MessageDetail, lang: Lang): string {
    const h = detail.headers;
    const who = h.from?.name?.trim() ? `${h.from.name} <${h.from.address}>` : (h.from?.address ?? "");
    const when = formatFullDate(h.date, lang) || h.date || "";
    if (lang === "zh")
        return `在 ${when}，${who} 写道：`;
    return `On ${when}, ${who} wrote:`;
}
function forwardHeaderText(detail: MessageDetail, lang: Lang): string {
    const h = detail.headers;
    const lines = [
        lang === "zh" ? "---------- 转发的邮件 ----------" : "---------- Forwarded message ----------",
        `${lang === "zh" ? "发件人" : "From"}: ${formatAddressList([h.from])}`,
        `${lang === "zh" ? "日期" : "Date"}: ${formatFullDate(h.date, lang) || h.date || ""}`,
        `${lang === "zh" ? "主题" : "Subject"}: ${h.subject ?? ""}`,
        `${lang === "zh" ? "收件人" : "To"}: ${formatAddressList(h.to)}`,
    ];
    if (Array.isArray(h.cc) && h.cc.length) {
        lines.push(`${lang === "zh" ? "抄送" : "Cc"}: ${formatAddressList(h.cc)}`);
    }
    return lines.join("\n");
}
function quoteHtml(text: string): string {
    const inner = textToParagraphHtml(text);
    return `<blockquote>${inner}</blockquote>`;
}
export function quotePlainText(text: string): string {
    return text
        .replace(/\r\n|\r/g, "\n")
        .split("\n")
        .map((line) => (line ? `> ${line}` : ">"))
        .join("\n");
}
export function buildReplyDraft(detail: MessageDetail, kind: ReplyKind, opts: {
    self: string;
    lang: Lang;
}): ReplyDraft {
    const { to, cc } = replyRecipients(detail, kind, opts.self);
    const subject = replySubject(detail.headers?.subject ?? "", kind);
    const bodyText = quotedBodyText(detail);
    if (kind === "forward") {
        const fwdHead = forwardHeaderText(detail, opts.lang);
        const text = `${fwdHead}\n\n${bodyText}`;
        const html = [`<p>${escapeHtml(fwdHead).replace(/\n/g, "<br>")}</p>`, quoteHtml(bodyText)].join("");
        return { to, cc, bcc: [], subject, text, html, references: [] };
    }
    const attr = attribution(detail, opts.lang);
    const quotedPlain = quotePlainText(bodyText);
    const text = `${attr}\n${quotedPlain}`;
    const html = [`<p>${escapeHtml(attr)}</p>`, quoteHtml(bodyText)].join("");
    const messageId = (detail.headers?.messageId ?? "").trim();
    const refs = Array.isArray(detail.headers?.references) ? detail.headers.references.filter(Boolean) : [];
    return {
        to,
        cc,
        bcc: [],
        subject,
        text,
        html,
        inReplyTo: messageId || undefined,
        references: dedupeStrings([...refs, messageId].filter(Boolean)),
    };
}

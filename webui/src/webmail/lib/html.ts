export const READER_CSP_BLOCKED = "default-src 'none'; img-src data:; style-src 'unsafe-inline'";
export const READER_CSP_IMAGES = "default-src 'none'; img-src data: http: https:; style-src 'unsafe-inline'";
const HTML_ESCAPE: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
};
export function escapeHtml(text: string): string {
    return (text ?? "").replace(/[&<>"']/g, (ch) => HTML_ESCAPE[ch] ?? ch);
}
const NAMED_ENTITIES: Record<string, string> = {
    amp: "&",
    lt: "<",
    gt: ">",
    quot: '"',
    apos: "'",
    nbsp: " ",
    hellip: "…",
    mdash: "—",
    ndash: "–",
    lsquo: "‘",
    rsquo: "’",
    ldquo: "“",
    rdquo: "”",
    middot: "·",
    copy: "©",
    reg: "®",
    trade: "™",
};
export function decodeEntities(text: string): string {
    return (text ?? "").replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (whole, body: string) => {
        if (body.startsWith("#")) {
            const hex = body[1] === "x" || body[1] === "X";
            const code = Number.parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10);
            if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff)
                return whole;
            try {
                return String.fromCodePoint(code);
            }
            catch {
                return whole;
            }
        }
        return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
    });
}
export function textToHtml(text: string): string {
    return escapeHtml(text ?? "").replace(/\r\n|\r|\n/g, "<br>");
}
export function textToParagraphHtml(text: string): string {
    const blocks = (text ?? "").replace(/\r\n|\r/g, "\n").split(/\n{2,}/);
    return blocks
        .map((block) => `<p>${escapeHtml(block).replace(/\n/g, "<br>")}</p>`)
        .join("");
}
export function htmlToPlain(html: string): string {
    if (!html)
        return "";
    let s = html
        .replace(/<style[\s\S]*?<\/style>/gi, "")
        .replace(/<script[\s\S]*?<\/script>/gi, "")
        .replace(/<head[\s\S]*?<\/head>/gi, "")
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(/<\/(p|div|li|tr|h[1-6]|blockquote|table|caption|dd|dt)>/gi, "\n")
        .replace(/<li[^>]*>/gi, "• ")
        .replace(/<hr[^>]*>/gi, "\n---\n")
        .replace(/<[^>]+>/g, "");
    s = decodeEntities(s);
    return s
        .replace(/[ \t]+\n/g, "\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
}
const QUOTE_HEADER_EN = /^On\b.*\bwrote:\s*$/i;
const QUOTE_HEADER_ZH = /^在\s.*写道[:：]\s*$/;
const FORWARD_MARKER = /^-{2,}\s*(Original Message|Forwarded message|原始邮件|转发的邮件|转发邮件)/i;
export type QuotedText = {
    head: string;
    quote: string | null;
};
export function splitQuotedText(text: string): QuotedText {
    const lines = (text ?? "").replace(/\r\n|\r/g, "\n").split("\n");
    for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        const trimmed = line.trimStart();
        const isQuote = trimmed.startsWith(">") ||
            QUOTE_HEADER_EN.test(trimmed) ||
            QUOTE_HEADER_ZH.test(trimmed) ||
            FORWARD_MARKER.test(trimmed);
        if (!isQuote)
            continue;
        const quoteLines = lines.slice(i);
        const headLines = lines.slice(0, i);
        while (headLines.length && headLines[headLines.length - 1].trim() === "")
            headLines.pop();
        if (!quoteLines.some((l) => l.trim() !== ""))
            continue;
        return { head: headLines.join("\n"), quote: quoteLines.join("\n").replace(/\s+$/, "") };
    }
    return { head: (text ?? "").trimEnd(), quote: null };
}
export type ReaderDocumentOptions = {
    allowRemoteImages: boolean;
    dark: boolean;
};
export function buildReaderDocument(bodyHtml: string, opts: ReaderDocumentOptions): string {
    const csp = opts.allowRemoteImages ? READER_CSP_IMAGES : READER_CSP_BLOCKED;
    const fg = opts.dark ? "#e8edf5" : "#1b1f27";
    const bg = opts.dark ? "#16181e" : "#ffffff";
    const muted = opts.dark ? "#9aa7b8" : "#5b6472";
    const line = opts.dark ? "#2b3039" : "#d9dde3";
    const link = opts.dark ? "#4aa3ff" : "#007aff";
    return [
        "<!doctype html>",
        '<html><head><meta charset="utf-8">',
        `<meta http-equiv="Content-Security-Policy" content="${csp}">`,
        '<meta name="referrer" content="no-referrer">',
        "<style>",
        `html,body{margin:0;padding:0;background:${bg};color:${fg};}`,
        "body{padding:14px 16px 18px;font:13px/1.55 -apple-system,BlinkMacSystemFont,'Inter Variable','Segoe UI','PingFang SC','Microsoft YaHei UI',sans-serif;word-wrap:break-word;overflow-wrap:anywhere;}",
        "img{max-width:100%!important;height:auto!important;}",
        "a{color:" + link + ";}",
        "table{max-width:100%;border-collapse:collapse;}",
        "td,th{max-width:100%;}",
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:transparent;}",
        `blockquote{margin:8px 0 8px 2px;padding-left:10px;border-left:2px solid ${line};color:${muted};}`,
        `hr{border:0;border-top:1px solid ${line};margin:12px 0;}`,
        "h1,h2,h3,h4,h5,h6{line-height:1.3;}",
        "font,center{max-width:100%;}",
        "</style></head><body>",
        bodyHtml || "<p></p>",
        "</body></html>",
    ].join("");
}
export function sanitizeEditorHtml(html: string): string {
    if (!html)
        return "";
    if (typeof DOMParser === "undefined")
        return textToHtml(htmlToPlain(html));
    const doc = new DOMParser().parseFromString(html, "text/html");
    const DROP = "script,style,iframe,object,embed,form,input,button,select,textarea,link,meta,base,svg,math,template,noscript";
    doc.querySelectorAll(DROP).forEach((el) => el.remove());
    doc.querySelectorAll("*").forEach((el) => {
        for (const attr of Array.from(el.attributes)) {
            const name = attr.name.toLowerCase();
            const value = attr.value.trim();
            if (name.startsWith("on") || name === "srcdoc") {
                el.removeAttribute(attr.name);
                continue;
            }
            if ((name === "href" || name === "src" || name === "background") && /^\s*(javascript|vbscript|data:text\/html)/i.test(value)) {
                el.removeAttribute(attr.name);
            }
        }
    });
    return doc.body.innerHTML;
}
export function isSafeLinkUrl(raw: string): boolean {
    const url = (raw ?? "").trim();
    if (!url)
        return false;
    if (/^(https?:|mailto:)/i.test(url))
        return true;
    return /^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(url);
}
export function normalizeLinkUrl(raw: string): string {
    const url = (raw ?? "").trim();
    if (/^(https?:|mailto:)/i.test(url))
        return url;
    return `https://${url}`;
}

// 邮件正文的纯函数层：转义 / 纯文本回退 / 引用拆分 / 阅读 iframe 文档 / 编辑器安全材料。
//
// 安全边界（契约 §2.2）：**服务端消毒器是唯一权威**，它输出 `body.html`；前端
// 只负责把它放进 `sandbox=""` 的 iframe（内部 meta CSP）渲染，绝不把同一段 HTML
// 写进主文档 innerHTML。这里的 htmlToPlain / sanitizeEditorHtml 是「把已消毒内容拿来
// 二次加工」的便利函数与纵深防御，不宣称能替代服务端消毒。

/** 阅读 iframe 内 meta CSP（契约 §5.3 指定字符串；阻断态不加载任何图片请求）。 */
export const READER_CSP_BLOCKED = "default-src 'none'; img-src data:; style-src 'unsafe-inline'";

/**
 * 允许加载图片时的 CSP：在阻断态基础上放行 http/https。
 * 说明：`sandbox=""` 的 srcdoc iframe 是不透明源（opaque origin），CSP 的 `'self'`
 * 匹配不到任何 URL —— cid 图片被服务端改写为同源 `/mail/api/...` 路径，只有
 * 显式放行 http: / https: 才能显示（阻断态下整封邮件的图片都不加载，与横幅
 * 「显示图片」的语义一致）。
 */
export const READER_CSP_IMAGES =
  "default-src 'none'; img-src data: http: https:; style-src 'unsafe-inline'";

const HTML_ESCAPE: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** 文本转义（用于拼接我们自己的 HTML，不用于服务端 HTML）。 */
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

/** HTML 实体解码（命名实体子集 + 十进制/十六进制数字实体）。 */
export function decodeEntities(text: string): string {
  return (text ?? "").replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (whole, body: string) => {
    if (body.startsWith("#")) {
      const hex = body[1] === "x" || body[1] === "X";
      const code = Number.parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10);
      if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff) return whole;
      try {
        return String.fromCodePoint(code);
      } catch {
        return whole;
      }
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
  });
}

/** 纯文本 → 我们自己的 HTML（全转义，换行变 `<br>`）。 */
export function textToHtml(text: string): string {
  return escapeHtml(text ?? "").replace(/\r\n|\r|\n/g, "<br>");
}

/** 纯文本 → 段落化 HTML（空行分段，单换行 `<br>`）。用于引用原文。 */
export function textToParagraphHtml(text: string): string {
  const blocks = (text ?? "").replace(/\r\n|\r/g, "\n").split(/\n{2,}/);
  return blocks
    .map((block) => `<p>${escapeHtml(block).replace(/\n/g, "<br>")}</p>`)
    .join("");
}

/** 消毒后的 HTML → 可读纯文本（引用构造、打印、草稿回退用）。 */
export function htmlToPlain(html: string): string {
  if (!html) return "";
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

export type QuotedText = { head: string; quote: string | null };

/**
 * 把纯文本正文拆成「新内容 + 引用原文」两段（阅读窗格的引用折叠）。
 * 识别三类引用起点：`>` 引用行、`On … wrote:` / `在 … 写道：`、以及
 * `-----Original Message-----` 分隔线。找不到引用时 quote = null。
 */
export function splitQuotedText(text: string): QuotedText {
  const lines = (text ?? "").replace(/\r\n|\r/g, "\n").split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const trimmed = line.trimStart();
    const isQuote =
      trimmed.startsWith(">") ||
      QUOTE_HEADER_EN.test(trimmed) ||
      QUOTE_HEADER_ZH.test(trimmed) ||
      FORWARD_MARKER.test(trimmed);
    if (!isQuote) continue;
    // 只有一行 `>`（例如签名里的符号）不足以认定为引用块：要求后面还有内容
    // 或引用行总数 ≥ 1 且行数 ≥ 2。
    const quoteLines = lines.slice(i);
    const headLines = lines.slice(0, i);
    while (headLines.length && headLines[headLines.length - 1].trim() === "") headLines.pop();
    if (!quoteLines.some((l) => l.trim() !== "")) continue;
    return { head: headLines.join("\n"), quote: quoteLines.join("\n").replace(/\s+$/, "") };
  }
  return { head: (text ?? "").trimEnd(), quote: null };
}

export type ReaderDocumentOptions = {
  allowRemoteImages: boolean;
  dark: boolean;
};

/**
 * 构造 `iframe srcdoc` 文档：`sandbox=""` + 内部 meta CSP（父级 CSP 不作用于 srcdoc）。
 * `bodyHtml` 必须是服务端消毒后的 HTML（契约 §2.2）；这里只加样式与 CSP，不做解析。
 */
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

/**
 * 草稿 HTML 的纵深防御清洗（服务端消毒器仍是权威）。DOMParser 在解析时**不执行**
 * 脚本；这里移除脚本类节点、`on*` 事件属性、`srcdoc` 与危险 URL 协议，再交给
 * contenteditable 编辑。仅用于「把服务端已消毒内容放回编辑器」，不作为安全边界。
 */
export function sanitizeEditorHtml(html: string): string {
  if (!html) return "";
  if (typeof DOMParser === "undefined") return textToHtml(htmlToPlain(html));
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

/**
 * 链接 URL 白名单（写信「插入链接」用）。只允许 http / https / mailto：
 * — 用户输入 `javascript:` 时不能把它发给收件人（收件端可能执行）。
 */
export function isSafeLinkUrl(raw: string): boolean {
  const url = (raw ?? "").trim();
  if (!url) return false;
  if (/^(https?:|mailto:)/i.test(url)) return true;
  // 无协议但像域名（example.com/path）→ 补 https: 后合法
  return /^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(url);
}

/** 把用户输入规范成可插入的链接（无协议时补 https:）。 */
export function normalizeLinkUrl(raw: string): string {
  const url = (raw ?? "").trim();
  if (/^(https?:|mailto:)/i.test(url)) return url;
  return `https://${url}`;
}

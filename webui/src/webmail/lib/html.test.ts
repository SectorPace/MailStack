// 正文处理纯函数测试：转义 / 实体解码 / 纯文本回退 / 引用拆分 / 阅读 iframe CSP /
// 编辑器清洗 / 链接白名单。
import { describe, expect, it } from "vitest";
import {
  READER_CSP_BLOCKED,
  READER_CSP_IMAGES,
  buildReaderDocument,
  decodeEntities,
  escapeHtml,
  htmlToPlain,
  isSafeLinkUrl,
  normalizeLinkUrl,
  sanitizeEditorHtml,
  splitQuotedText,
  textToHtml,
  textToParagraphHtml,
} from "./html";

describe("escape / entities", () => {
  it("escapes HTML metacharacters", () => {
    expect(escapeHtml(`<a href="x">&'`)).toBe("&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
  });

  it("decodes named and numeric entities", () => {
    expect(decodeEntities("a &amp; b &lt;c&gt; &nbsp; &#65; &#x42;")).toBe("a & b <c>   A B");
    expect(decodeEntities("&unknown;")).toBe("&unknown;");
  });

  it("textToHtml escapes then converts newlines", () => {
    expect(textToHtml("a<b\nc")).toBe("a&lt;b<br>c");
  });

  it("textToParagraphHtml splits on blank lines", () => {
    expect(textToParagraphHtml("p1\nline2\n\np2")).toBe("<p>p1<br>line2</p><p>p2</p>");
  });
});

describe("htmlToPlain", () => {
  it("converts block tags, entities and strips scripts", () => {
    const html = "<style>p{}</style><script>alert(1)</script><p>Hello &amp; <b>world</b></p><p>Next</p>";
    expect(htmlToPlain(html)).toBe("Hello & world\nNext");
  });

  it("returns empty for empty input", () => {
    expect(htmlToPlain("")).toBe("");
  });
});

describe("splitQuotedText（阅读窗格引用折叠）", () => {
  it("splits at a > quote block", () => {
    const result = splitQuotedText("My reply\n\n> old line 1\n> old line 2");
    expect(result.head).toBe("My reply");
    expect(result.quote).toBe("> old line 1\n> old line 2");
  });

  it("recognises On ... wrote: attribution", () => {
    const result = splitQuotedText("Thanks\n\nOn Mon, Alice wrote:\nHello");
    expect(result.head).toBe("Thanks");
    expect(result.quote).toContain("On Mon, Alice wrote:");
  });

  it("returns quote:null when there is no quoted block", () => {
    const result = splitQuotedText("just a normal message\nwith two lines");
    expect(result.quote).toBeNull();
    expect(result.head).toContain("just a normal message");
  });
});

describe("buildReaderDocument（sandbox iframe 内的 CSP）", () => {
  it("blocks remote images by default with the contract CSP", () => {
    const doc = buildReaderDocument("<p>Hello</p>", { allowRemoteImages: false, dark: false });
    expect(doc).toContain(READER_CSP_BLOCKED);
    expect(doc).toContain("default-src 'none'");
    expect(doc).toContain("img-src data:");
    expect(doc).not.toContain("http: https:");
    expect(doc).toContain("<p>Hello</p>");
    expect(doc).toContain("no-referrer");
  });

  it("allows http/https images only when requested", () => {
    const doc = buildReaderDocument("<p>Hello</p>", { allowRemoteImages: true, dark: true });
    expect(doc).toContain(READER_CSP_IMAGES);
    expect(doc).toContain("http: https:");
    expect(doc).toContain("#16181e");
  });

  it("renders an empty paragraph for empty bodies (valid HTML)", () => {
    expect(buildReaderDocument("", { allowRemoteImages: false, dark: false })).toContain("<p></p>");
  });
});

describe("sanitizeEditorHtml（草稿回填的纵深防御）", () => {
  it("removes scripts, handlers and javascript: urls", () => {
    const out = sanitizeEditorHtml(
      '<p onclick="evil()">Hi<script>alert(1)</script><img src="javascript:alert(1)"><a href="https://ok">ok</a></p>',
    );
    expect(out).not.toContain("<script");
    expect(out).not.toContain("onclick");
    expect(out).not.toContain("javascript:");
    expect(out).toContain("https://ok");
    expect(out).toContain("Hi");
  });
});

describe("链接白名单", () => {
  it("allows http/https/mailto and bare domains", () => {
    expect(isSafeLinkUrl("https://example.com")).toBe(true);
    expect(isSafeLinkUrl("http://example.com")).toBe(true);
    expect(isSafeLinkUrl("mailto:alice@example.com")).toBe(true);
    expect(isSafeLinkUrl("example.com/path")).toBe(true);
    expect(normalizeLinkUrl("example.com")).toBe("https://example.com");
    expect(normalizeLinkUrl("mailto:a@b.com")).toBe("mailto:a@b.com");
  });

  it("rejects javascript:/vbscript:/data: urls", () => {
    expect(isSafeLinkUrl("javascript:alert(1)")).toBe(false);
    expect(isSafeLinkUrl("vbscript:msgbox")).toBe(false);
    expect(isSafeLinkUrl("data:text/html,<script>")).toBe(false);
    expect(isSafeLinkUrl("")).toBe(false);
  });
});

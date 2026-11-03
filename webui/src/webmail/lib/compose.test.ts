// 写信草稿组装 / 校验 / ComposeRequest 构造测试。
import { describe, expect, it } from "vitest";
import {
  MAX_ATTACHMENT_BYTES,
  buildComposeRequest,
  buildDraftCompose,
  buildNewCompose,
  buildReplyCompose,
  canAddAttachment,
  effectiveDisplayName,
  signatureHtml,
  totalAttachmentSize,
  validateCompose,
} from "./compose";
import type { MailPrefs } from "./prefs";
import { makeDetail } from "../test-utils";

const PREFS: MailPrefs = {
  displayName: "Alice",
  signature: "Alice Chen\nMailStack",
  pageSize: 50,
  density: "comfortable",
  loadRemoteImages: false,
  theme: "system",
  lang: "zh",
};

describe("签名", () => {
  it("renders a -- separated signature block and resolves the display name", () => {
    const html = signatureHtml(PREFS, "Backend Name");
    expect(html).toContain("--<br>Alice<br>Alice Chen<br>MailStack");
    expect(effectiveDisplayName({ displayName: "" }, "Backend Name")).toBe("Backend Name");
    expect(effectiveDisplayName({ displayName: " Local " }, "Backend Name")).toBe("Local");
  });

  it("returns empty string when no signature and no name", () => {
    const empty: MailPrefs = { ...PREFS, displayName: "", signature: "" };
    expect(signatureHtml(empty, "")).toBe("");
    expect(signatureHtml(empty, null)).toBe("");
  });
});

describe("初始草稿", () => {
  it("new message has no recipients and signature at the end", () => {
    const initial = buildNewCompose(PREFS, "Backend");
    expect(initial.kind).toBe("new");
    expect(initial.to).toEqual([]);
    expect(initial.subject).toBe("");
    expect(initial.html.startsWith("<p><br></p>")).toBe(true);
    expect(initial.html).toContain("Alice Chen");
    expect(initial.draftUid).toBeNull();
  });

  it("reply puts the signature before the quoted original", () => {
    const detail = makeDetail({
      headers: { subject: "Hello", messageId: "<m2@x>", references: [] },
      body: { text: "Original", html: null, truncated: false },
    });
    const initial = buildReplyCompose("reply", detail, PREFS, {
      self: "me@example.com",
      lang: "zh",
      backendName: "Backend",
    });
    expect(initial.kind).toBe("reply");
    expect(initial.subject).toBe("Re: Hello");
    expect(initial.inReplyTo).toBe("<m2@x>");
    expect(initial.references).toEqual(["<m2@x>"]);
    const sigIndex = initial.html.indexOf("MailStack");
    const quoteIndex = initial.html.indexOf("<blockquote>");
    expect(sigIndex).toBeGreaterThan(-1);
    expect(quoteIndex).toBeGreaterThan(sigIndex);
  });

  it("draft editing keeps server HTML (sanitized defensively) and recipients", () => {
    const detail = makeDetail({
      folder: "Drafts",
      flags: ["draft"],
      headers: {
        to: [{ name: "", address: "bob@example.com" }],
        cc: [{ name: "", address: "carol@example.com" }],
        subject: "Draft subject",
        references: ["<r1@x>"],
      },
      body: { text: null, html: '<p>Body<script>alert(1)</script></p>', truncated: false },
    });
    const initial = buildDraftCompose(detail);
    expect(initial.kind).toBe("draft");
    expect(initial.to).toEqual(["bob@example.com"]);
    expect(initial.cc).toEqual(["carol@example.com"]);
    expect(initial.subject).toBe("Draft subject");
    expect(initial.draftUid).toBe(detail.uid);
    expect(initial.html).not.toContain("<script");
    expect(initial.html).toContain("Body");
  });
});

describe("validateCompose", () => {
  it("requires at least one recipient across to/cc/bcc", () => {
    expect(validateCompose({ to: [], cc: [], bcc: [] })).toEqual({ ok: false, missingRecipients: true, invalid: [] });
    expect(validateCompose({ to: ["a@x.com"], cc: [], bcc: [] }).ok).toBe(true);
    expect(validateCompose({ to: [], cc: [], bcc: ["c@x.com"] }).ok).toBe(true);
  });

  it("reports invalid addresses (fallback after chip validation)", () => {
    const result = validateCompose({ to: ["a@x.com", "bad"], cc: [], bcc: [] });
    expect(result.ok).toBe(false);
    expect(result.missingRecipients).toBe(false);
    expect(result.invalid).toEqual(["bad"]);
  });
});

describe("附件限额（25 MiB 预校验）", () => {
  it("sums sizes and checks the cap", () => {
    expect(MAX_ATTACHMENT_BYTES).toBe(25 * 1024 * 1024);
    expect(totalAttachmentSize([{ size: 100 }, { size: 200 }])).toBe(300);
    expect(totalAttachmentSize([])).toBe(0);
    expect(canAddAttachment(MAX_ATTACHMENT_BYTES - 1, 1)).toBe(true);
    expect(canAddAttachment(MAX_ATTACHMENT_BYTES, 1)).toBe(false);
  });
});

describe("buildComposeRequest", () => {
  it("dedupes recipients and omits empty optional fields", () => {
    const req = buildComposeRequest({
      to: ["Bob@X.com", "bob@x.com"],
      cc: [],
      bcc: [],
      subject: "Hi",
      text: "body",
      html: "<p>body</p>",
      references: [],
      attachments: [],
    });
    expect(req).toEqual({ to: ["Bob@X.com"], cc: [], bcc: [], subject: "Hi", text: "body", html: "<p>body</p>" });
    expect("inReplyTo" in req).toBe(false);
    expect("references" in req).toBe(false);
    expect("attachments" in req).toBe(false);
  });

  it("keeps reply metadata and attachments", () => {
    const req = buildComposeRequest({
      to: ["a@x.com"],
      cc: [],
      bcc: [],
      subject: "Re: x",
      text: "t",
      html: "<p>t</p>",
      inReplyTo: "<m@x>",
      references: ["<m@x>"],
      attachments: [{ filename: "a.pdf", contentType: "", dataBase64: "AAA" }],
    });
    expect(req.inReplyTo).toBe("<m@x>");
    expect(req.references).toEqual(["<m@x>"]);
    expect(req.attachments).toEqual([{ filename: "a.pdf", contentType: "application/octet-stream", dataBase64: "AAA" }]);
  });
});

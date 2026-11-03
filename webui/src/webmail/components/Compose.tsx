// 写信浮层（契约 §5.4）：桌面右下浮层（可全屏）/ 移动端全屏。
//   * To/Cc/Bcc 芯片输入（回车/逗号分隔、格式校验、去重、可删）；
//   * 主题；contenteditable 富文本工具栏（粗体/斜体/下划线/有序无序列表/引用/
//     链接/清除格式，不引第三方库）；
//   * 附件多选 + 总量 ≤ 25 MiB 预校验；
//   * 发送（Ctrl+Enter）/ 存草稿 / 丢弃（确认）；
//   * 键盘：Ctrl+Enter 发送；Esc 走「有改动先确认」的关闭流程。
import { useEffect, useRef, useState, type ChangeEvent, type KeyboardEvent } from "react";
import type { ComposeAttachment, SendResult } from "../types";
import { deleteMessage, describeError, saveDraft, sendMessage } from "../api";
import type { ComposeInitial } from "../lib/compose";
import {
  MAX_ATTACHMENT_BYTES,
  buildComposeRequest,
  canAddAttachment,
  totalAttachmentSize,
  validateCompose,
} from "../lib/compose";
import { formatFileSize } from "../lib/format";
import { isSafeLinkUrl, normalizeLinkUrl } from "../lib/html";
import { useMailPrefs } from "../store/prefs";
import { useToast } from "./Toast";
import { AddressChips } from "./AddressChips";
import { ConfirmDialog } from "./Confirm";
import { Spinner } from "./states";
import {
  IconBold,
  IconChevronDown,
  IconEraser,
  IconExpand,
  IconItalic,
  IconLink,
  IconListBullet,
  IconListOrdered,
  IconMinimize,
  IconPaperclip,
  IconQuoteMark,
  IconSend,
  IconTrash,
  IconUnderline,
  IconX,
} from "./icons";

export type ComposeAttachmentItem = ComposeAttachment & { key: string; size: number };

const KIND_TITLE_KEY = {
  new: "compose_new",
  reply: "compose_reply",
  replyAll: "compose_reply_all",
  forward: "compose_forward",
  draft: "compose_draft",
} as const;

function readFileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === "string" ? reader.result : "";
      const comma = result.indexOf(",");
      resolve(comma >= 0 ? result.slice(comma + 1) : "");
    };
    reader.onerror = () => reject(new Error("file read failed"));
    reader.readAsDataURL(file);
  });
}

export function Compose({
  initial,
  fullscreen,
  onToggleFullscreen,
  onClose,
  onSent,
  onDraftSaved,
}: {
  initial: ComposeInitial;
  fullscreen: boolean;
  onToggleFullscreen: () => void;
  onClose: () => void;
  onSent: (result: SendResult) => void;
  onDraftSaved: (uid: number) => void;
}) {
  const { t, prefs } = useMailPrefs();
  const toast = useToast();
  const editorRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const [to, setTo] = useState<string[]>(initial.to);
  const [cc, setCc] = useState<string[]>(initial.cc);
  const [bcc, setBcc] = useState<string[]>(initial.bcc);
  const [showCcBcc, setShowCcBcc] = useState(initial.cc.length > 0 || initial.bcc.length > 0);
  const [subject, setSubject] = useState(initial.subject);
  const [attachments, setAttachments] = useState<ComposeAttachmentItem[]>([]);
  const [draftUid, setDraftUid] = useState<number | null>(initial.draftUid);
  const [busy, setBusy] = useState<"send" | "draft" | null>(null);
  const [error, setError] = useState("");
  const [dirty, setDirty] = useState(false);
  const [confirm, setConfirm] = useState<"discard" | null>(null);

  // 初始正文（签名 / 引用）只在挂载时写入 contenteditable —— App 每次打开用 key 重挂载。
  useEffect(() => {
    const el = editorRef.current;
    if (!el) return;
    el.innerHTML = initial.html || "<p><br></p>";
    el.focus();
    // 光标放到正文最前（内容已在首行）
    try {
      const range = document.createRange();
      range.selectNodeContents(el);
      range.collapse(true);
      const selection = window.getSelection();
      selection?.removeAllRanges();
      selection?.addRange(range);
    } catch {
      /* 选区 API 不可用时忽略 */
    }
  }, [initial.html]);

  function markDirty() {
    if (!dirty) setDirty(true);
  }

  function readEditor(): { html: string; text: string } {
    const el = editorRef.current;
    if (!el) return { html: initial.html, text: initial.text };
    const elWithInnerText = el as HTMLElement & { innerText?: string };
    return {
      html: el.innerHTML,
      text: typeof elWithInnerText.innerText === "string" ? elWithInnerText.innerText : (el.textContent ?? ""),
    };
  }

  function exec(command: string, value?: string) {
    const el = editorRef.current;
    if (!el) return;
    el.focus();
    if (typeof document.execCommand !== "function") return; // jsdom / 极旧浏览器：富文本降级为无操作
    try {
      document.execCommand(command, false, value);
      markDirty();
    } catch {
      /* 浏览器拒绝该命令时保持原内容 */
    }
  }

  function insertLink() {
    const raw = window.prompt(t("link_prompt"), "https://");
    if (raw == null) return;
    if (!isSafeLinkUrl(raw)) {
      toast(t("link_invalid"), "err");
      return;
    }
    exec("createLink", normalizeLinkUrl(raw));
  }

  async function addFiles(e: ChangeEvent<HTMLInputElement>) {
    const files = Array.from(e.target.files ?? []);
    e.target.value = "";
    if (!files.length) return;
    const currentTotal = totalAttachmentSize(attachments);
    const nextTotal = currentTotal + files.reduce((sum, f) => sum + f.size, 0);
    if (nextTotal > MAX_ATTACHMENT_BYTES) {
      toast(t("attachment_total_limit", { size: formatFileSize(nextTotal) }), "err");
      return;
    }
    if (!canAddAttachment(currentTotal, nextTotal - currentTotal)) return;
    const added: ComposeAttachmentItem[] = [];
    for (const file of files) {
      try {
        const dataBase64 = await readFileAsBase64(file);
        added.push({
          key: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          filename: file.name,
          contentType: file.type || "application/octet-stream",
          size: file.size,
          dataBase64,
        });
      } catch {
        toast(t("operation_failed", { error: file.name }), "err");
      }
    }
    if (added.length) {
      setAttachments((prev) => [...prev, ...added]);
      markDirty();
    }
  }

  function removeAttachment(key: string) {
    setAttachments((prev) => prev.filter((a) => a.key !== key));
    markDirty();
  }

  function composePayload() {
    const { html, text } = readEditor();
    return buildComposeRequest({
      to,
      cc,
      bcc,
      subject,
      text,
      html,
      inReplyTo: initial.inReplyTo,
      references: initial.references,
      attachments: attachments.map(({ filename, contentType, dataBase64 }) => ({ filename, contentType, dataBase64 })),
    });
  }

  async function doSend() {
    if (busy) return;
    const validation = validateCompose({ to, cc, bcc });
    if (!validation.ok) {
      setError(
        validation.missingRecipients
          ? t("recipients_required")
          : t("recipients_invalid", { list: validation.invalid.join(", ") }),
      );
      return;
    }
    const total = totalAttachmentSize(attachments);
    if (total > MAX_ATTACHMENT_BYTES) {
      setError(t("attachment_total_limit", { size: formatFileSize(total) }));
      return;
    }
    setBusy("send");
    setError("");
    try {
      const result = await sendMessage(composePayload());
      onSent(result);
    } catch (e) {
      setError(describeError(e, prefs.lang));
    } finally {
      setBusy(null);
    }
  }

  async function doSaveDraft() {
    if (busy) return;
    setBusy("draft");
    setError("");
    try {
      const result = await saveDraft(composePayload(), draftUid);
      setDirty(false);
      if (result.uid) setDraftUid(result.uid);
      toast(t("draft_saved"), "ok");
      onDraftSaved(result.uid);
    } catch (e) {
      setError(describeError(e, prefs.lang));
    } finally {
      setBusy(null);
    }
  }

  async function doDiscard() {
    setConfirm(null);
    if (draftUid != null) {
      try {
        await deleteMessage("Drafts", draftUid);
      } catch (e) {
        toast(describeError(e, prefs.lang), "err");
        return;
      }
    }
    toast(t("discard_done"), "info");
    onClose();
  }

  function requestClose() {
    // 只有「未保存的改动」需要确认；保存过草稿后关闭 = 保留草稿，不应提示丢弃。
    if (!dirty) {
      onClose();
      return;
    }
    setConfirm("discard");
  }

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      void doSend();
      return;
    }
    if (e.key === "Escape") {
      e.stopPropagation();
      requestClose();
    }
  }

  const totalSize = totalAttachmentSize(attachments);
  const titleKey = KIND_TITLE_KEY[initial.kind] ?? "compose_new";

  return (
    <div className={`mail-compose ${fullscreen ? "mail-compose--full" : ""}`} role="dialog" aria-modal="false" aria-label={t(titleKey)} onKeyDown={onKeyDown}>
      <div className="mail-compose-head">
        <span className="mail-compose-title">{t(titleKey)}</span>
        <div className="mail-compose-head-actions">
          <button type="button" className="icon-btn" onClick={onToggleFullscreen} aria-label={fullscreen ? t("minimize") : t("expand")} title={fullscreen ? t("minimize") : t("expand")}>
            {fullscreen ? <IconMinimize size={15} /> : <IconExpand size={15} />}
          </button>
          <button type="button" className="icon-btn" onClick={requestClose} aria-label={t("close")} title={t("close")}>
            <IconX size={16} />
          </button>
        </div>
      </div>

      <div className="mail-compose-body">
        <AddressChips label={t("compose_to")} addresses={to} onChange={(next) => { setTo(next); markDirty(); }} autoFocus placeholder={t("login_email_placeholder")} variant="to" />
        {!showCcBcc ? (
          <button type="button" className="mail-cc-toggle" onClick={() => setShowCcBcc(true)}>
            {t("add_cc_bcc")}
            <IconChevronDown size={11} />
          </button>
        ) : (
          <>
            <AddressChips label={t("compose_cc")} addresses={cc} onChange={(next) => { setCc(next); markDirty(); }} variant="cc" />
            <AddressChips label={t("compose_bcc")} addresses={bcc} onChange={(next) => { setBcc(next); markDirty(); }} variant="bcc" />
          </>
        )}

        <div className="mail-field mail-subject-field">
          <label className="mail-field-label" htmlFor="mail-compose-subject">
            {t("compose_subject")}
          </label>
          <input
            id="mail-compose-subject"
            className="mail-subject-input"
            value={subject}
            placeholder={t("compose_subject")}
            onChange={(e) => {
              setSubject(e.target.value);
              markDirty();
            }}
          />
        </div>

        <div className="mail-editor-toolbar" role="toolbar" aria-label={t("compose_body")}>
          <button type="button" className="mail-tool" aria-label={t("bold")} title={t("bold")} onMouseDown={(e) => e.preventDefault()} onClick={() => exec("bold")}>
            <IconBold size={14} />
          </button>
          <button type="button" className="mail-tool" aria-label={t("italic")} title={t("italic")} onMouseDown={(e) => e.preventDefault()} onClick={() => exec("italic")}>
            <IconItalic size={14} />
          </button>
          <button type="button" className="mail-tool" aria-label={t("underline")} title={t("underline")} onMouseDown={(e) => e.preventDefault()} onClick={() => exec("underline")}>
            <IconUnderline size={14} />
          </button>
          <span className="mail-tool-sep" aria-hidden />
          <button type="button" className="mail-tool" aria-label={t("ordered_list")} title={t("ordered_list")} onMouseDown={(e) => e.preventDefault()} onClick={() => exec("insertOrderedList")}>
            <IconListOrdered size={14} />
          </button>
          <button type="button" className="mail-tool" aria-label={t("unordered_list")} title={t("unordered_list")} onMouseDown={(e) => e.preventDefault()} onClick={() => exec("insertUnorderedList")}>
            <IconListBullet size={14} />
          </button>
          <button type="button" className="mail-tool" aria-label={t("quote")} title={t("quote")} onMouseDown={(e) => e.preventDefault()} onClick={() => exec("formatBlock", "<blockquote>")}>
            <IconQuoteMark size={14} />
          </button>
          <span className="mail-tool-sep" aria-hidden />
          <button type="button" className="mail-tool" aria-label={t("link")} title={t("link")} onMouseDown={(e) => e.preventDefault()} onClick={insertLink}>
            <IconLink size={14} />
          </button>
          <button type="button" className="mail-tool" aria-label={t("clear_format")} title={t("clear_format")} onMouseDown={(e) => e.preventDefault()} onClick={() => { exec("removeFormat"); exec("unlink"); }}>
            <IconEraser size={14} />
          </button>
        </div>

        <div
          ref={editorRef}
          className="mail-editor"
          contentEditable
          suppressContentEditableWarning
          role="textbox"
          aria-multiline="true"
          aria-label={t("compose_body")}
          data-placeholder={t("editor_placeholder")}
          onInput={markDirty}
        />

        {attachments.length > 0 && (
          <div className="mail-attachments mail-attachments--compose">
            <span className="mail-attachments-title">
              {t("attachment_count", { n: attachments.length })} · {formatFileSize(totalSize)}
            </span>
            {attachments.map((attachment) => (
              <span className="mail-attachment-chip" key={attachment.key} title={attachment.filename}>
                <IconPaperclip size={13} />
                <span className="mail-attachment-name">{attachment.filename}</span>
                <span className="mail-attachment-size tnum">{formatFileSize(attachment.size)}</span>
                <button
                  type="button"
                  className="mail-chip-x"
                  aria-label={`${t("remove_attachment")}: ${attachment.filename}`}
                  onClick={() => removeAttachment(attachment.key)}
                >
                  <IconX size={10} />
                </button>
              </span>
            ))}
          </div>
        )}

        {error && (
          <div className="mail-compose-error" role="alert">
            {error}
          </div>
        )}
      </div>

      <div className="mail-compose-foot">
        <button type="button" className="btn btn-accent mail-send-btn" onClick={() => void doSend()} disabled={busy !== null}>
          {busy === "send" ? <Spinner size={13} /> : <IconSend size={14} />}
          {busy === "send" ? t("sending") : t("send")}
        </button>
        <button type="button" className="btn glass--control" onClick={() => void doSaveDraft()} disabled={busy !== null}>
          {busy === "draft" ? t("saving_draft") : t("save_draft")}
        </button>
        <button type="button" className="icon-btn" onClick={() => setConfirm("discard")} aria-label={t("discard")} title={t("discard")}>
          <IconTrash size={16} />
        </button>
        <button type="button" className="icon-btn" onClick={() => fileRef.current?.click()} aria-label={t("add_attachment")} title={t("add_attachment")}>
          <IconPaperclip size={16} />
        </button>
        <input ref={fileRef} type="file" multiple className="mail-file-input" onChange={(e) => void addFiles(e)} />
        <span className="mail-compose-hint">{t("ctrl_enter_hint")}</span>
      </div>

      <ConfirmDialog
        open={confirm === "discard"}
        danger
        title={t("discard_confirm_title")}
        body={t("discard_confirm_body")}
        confirmLabel={t("discard")}
        cancelLabel={t("cancel")}
        onClose={() => setConfirm(null)}
        onConfirm={() => void doDiscard()}
      />
    </div>
  );
}

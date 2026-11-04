import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { MailAttachment, MessageDetail } from "../types";
import { attachmentUrl, describeError, getMessage, isDemoMode, patchFlags, rawMessageUrl } from "../api";
import { formatFileSize, formatFullDate, senderName } from "../lib/format";
import { buildReaderDocument, htmlToPlain, splitQuotedText } from "../lib/html";
import type { ReplyKind } from "../lib/reply";
import { useMailPrefs } from "../store/prefs";
import { useToast } from "./Toast";
import { EmptyState, ErrorBanner, MailAvatar, SkeletonRows } from "./states";
import { IconArchive, IconArrowLeft, IconChevronDown, IconDownload, IconForward, IconMail, IconPrinter, IconReply, IconReplyAll, IconStar, IconTrash, IconWarn, } from "./icons";
export type MessageViewActions = {
    onBack: () => void;
    onReply: (kind: ReplyKind, detail: MessageDetail) => void;
    onArchive: (detail: MessageDetail) => void;
    onDelete: (detail: MessageDetail) => void;
    onMove: (detail: MessageDetail, target: string) => void;
    onFlagsChanged: (detail: MessageDetail, flags: string[]) => void;
    onLoaded: (detail: MessageDetail) => void;
};
function triggerDownload(url: string): void {
    const a = document.createElement("a");
    a.href = url;
    a.rel = "noopener";
    a.download = "";
    document.body.appendChild(a);
    a.click();
    a.remove();
}
export function MessageView({ folder, uid, moveTargets, canArchive, showBack, actions, }: {
    folder: string;
    uid: number;
    moveTargets: {
        name: string;
        label: string;
    }[];
    canArchive: boolean;
    showBack: boolean;
    actions: MessageViewActions;
}) {
    const { t, prefs, resolvedTheme } = useMailPrefs();
    const toast = useToast();
    const [message, setMessage] = useState<MessageDetail | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showImages, setShowImages] = useState(prefs.loadRemoteImages);
    const [detailsOpen, setDetailsOpen] = useState(false);
    const [reloadKey, setReloadKey] = useState(0);
    const [flags, setFlags] = useState<string[]>([]);
    const seq = useRef(0);
    const onLoadedRef = useRef(actions.onLoaded);
    useEffect(() => {
        onLoadedRef.current = actions.onLoaded;
    });
    const load = useCallback(async (images: boolean) => {
        const id = ++seq.current;
        setLoading(true);
        setError(null);
        try {
            const detail = await getMessage(folder, uid, { images });
            if (id !== seq.current)
                return;
            setMessage(detail);
            setFlags(detail.flags);
            setLoading(false);
            onLoadedRef.current(detail);
        }
        catch (e) {
            if (id !== seq.current)
                return;
            setError(describeError(e, prefs.lang));
            setLoading(false);
        }
    }, [folder, uid, prefs.lang]);
    useEffect(() => {
        setShowImages(prefs.loadRemoteImages);
    }, [prefs.loadRemoteImages, uid, folder]);
    useEffect(() => {
        void load(showImages);
    }, [load, showImages, reloadKey]);
    useEffect(() => {
        if (!message)
            return;
        if (message.flags.includes("seen"))
            return;
        let live = true;
        void patchFlags(folder, message.uid, { seen: true })
            .then((next) => {
            if (!live)
                return;
            const nextFlags = Array.isArray(next) && next.length ? next : [...message.flags, "seen"];
            setFlags(nextFlags);
            actions.onFlagsChanged(message, nextFlags);
        })
            .catch(() => {
        });
        return () => {
            live = false;
        };
    }, [message?.uid, message?.flags, folder]);
    const starred = flags.includes("flagged");
    const header = message?.headers;
    const subject = header?.subject || t("no_subject");
    const fromName = header ? senderName(header.from) || t("unknown_sender") : "";
    const toggleStar = async () => {
        if (!message)
            return;
        const next = !starred;
        const optimistic = next ? [...flags, "flagged"] : flags.filter((f) => f !== "flagged");
        const previous = flags;
        setFlags(optimistic);
        try {
            const serverFlags = await patchFlags(folder, message.uid, { flagged: next });
            const resolved = Array.isArray(serverFlags) && serverFlags.length ? serverFlags : optimistic;
            setFlags(resolved);
            actions.onFlagsChanged(message, resolved);
            toast(next ? t("starred") : t("unstarred"), "ok");
        }
        catch (e) {
            setFlags(previous);
            toast(describeError(e, prefs.lang), "err");
        }
    };
    const downloadRaw = () => {
        if (isDemoMode()) {
            toast(t("download_demo"), "warn");
            return;
        }
        if (message)
            triggerDownload(rawMessageUrl(folder, message.uid));
    };
    const downloadAttachment = (attachment: MailAttachment) => {
        if (isDemoMode()) {
            toast(t("download_demo"), "warn");
            return;
        }
        if (message)
            triggerDownload(attachmentUrl(folder, message.uid, attachment.partId, true));
    };
    const printMessage = () => {
        if (!message)
            return;
        const win = window.open("", "_blank", "width=820,height=920");
        if (!win) {
            toast(t("print_blocked"), "err");
            return;
        }
        const doc = win.document;
        doc.title = subject;
        const style = doc.createElement("style");
        style.textContent =
            "body{font:13px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC',sans-serif;margin:32px;color:#111}h1{font-size:18px;line-height:1.3}.meta{color:#555;font-size:12px;margin:10px 0 18px;white-space:pre-wrap}pre{white-space:pre-wrap;word-break:break-word;font:inherit}";
        doc.head.appendChild(style);
        const h1 = doc.createElement("h1");
        h1.textContent = subject;
        doc.body.appendChild(h1);
        const meta = doc.createElement("div");
        meta.className = "meta";
        meta.textContent = [
            `${t("from")}: ${fromName} <${header?.from?.address ?? ""}>`,
            `${t("to")}: ${(header?.to ?? []).map((a) => a.address).join(", ")}`,
            header?.cc?.length ? `${t("cc")}: ${header.cc.map((a) => a.address).join(", ")}` : "",
            `${t("date")}: ${formatFullDate(header?.date, prefs.lang)}`,
        ]
            .filter(Boolean)
            .join("\n");
        doc.body.appendChild(meta);
        const pre = doc.createElement("pre");
        const textBody = message.body.text ?? htmlToPlain(message.body.html ?? "");
        pre.textContent = textBody;
        doc.body.appendChild(pre);
        win.focus();
        win.print();
    };
    const quoted = useMemo(() => {
        if (!message?.body?.text)
            return null;
        return splitQuotedText(message.body.text);
    }, [message]);
    const readerDoc = useMemo(() => {
        if (!message?.body?.html)
            return "";
        return buildReaderDocument(message.body.html, {
            allowRemoteImages: showImages,
            dark: resolvedTheme === "dark",
        });
    }, [message, showImages, resolvedTheme]);
    if (loading && !message) {
        return (<section className="mail-reader" aria-busy="true">
        <SkeletonRows count={5}/>
      </section>);
    }
    if (error && !message) {
        return (<section className="mail-reader">
        <ErrorBanner message={error} retryLabel={t("retry")} onRetry={() => setReloadKey((n) => n + 1)}/>
      </section>);
    }
    if (!message) {
        return (<section className="mail-reader">
        <EmptyState icon={<IconMail size={26}/>} title={t("empty_reader")} hint={t("empty_reader_hint")}/>
      </section>);
    }
    const blocked = !showImages && message.remoteImagesBlocked > 0;
    return (<section className={`mail-reader ${prefs.density === "compact" ? "mail-reader--compact" : ""}`} aria-label={subject}>
      <div className="mail-reader-head">
        <div className="mail-reader-subject-row">
          {showBack && (<button type="button" className="icon-btn mail-back-btn" onClick={actions.onBack} aria-label={t("back")} title={t("back")}>
              <IconArrowLeft size={17}/>
            </button>)}
          <h2 className="mail-reader-subject">{subject}</h2>
          <button type="button" className={`mail-star mail-star--reader ${starred ? "is-on" : ""}`} aria-pressed={starred} aria-label={starred ? t("unstar") : t("star")} title={starred ? t("unstar") : t("star")} onClick={() => void toggleStar()}>
            <IconStar size={17} filled={starred}/>
          </button>
        </div>

        <div className="mail-reader-meta">
          <MailAvatar label={fromName} size={34}/>
          <div className="mail-meta-main">
            <div className="mail-meta-name">
              {fromName} <span className="mail-meta-email">&lt;{header?.from?.address ?? ""}&gt;</span>
            </div>
            <div className="mail-meta-sub">
              {t("to")}: {(header?.to ?? []).map((a) => senderName(a) || a.address).join(", ") || t("no_recipients")}
            </div>
            <button type="button" className="mail-meta-toggle" onClick={() => setDetailsOpen((v) => !v)} aria-expanded={detailsOpen}>
              {detailsOpen ? t("hide_details") : t("show_details")}
              <IconChevronDown size={11} className={detailsOpen ? "rotate-180" : ""}/>
            </button>
          </div>
          <div className="mail-meta-date tnum" title={header?.date ?? ""}>
            {formatFullDate(header?.date, prefs.lang)}
          </div>
        </div>

        {detailsOpen && (<div className="mail-details">
            <DetailRow label={t("from")} value={`${formatAddress(header?.from)}`}/>
            {header?.replyTo?.length ? <DetailRow label={t("reply_to")} value={header.replyTo.map(formatAddress).join(", ")}/> : null}
            <DetailRow label={t("to")} value={(header?.to ?? []).map(formatAddress).join(", ")}/>
            {header?.cc?.length ? <DetailRow label={t("cc")} value={header.cc.map(formatAddress).join(", ")}/> : null}
            {header?.bcc?.length ? <DetailRow label={t("bcc")} value={header.bcc.map(formatAddress).join(", ")}/> : null}
            <DetailRow label={t("date")} value={formatFullDate(header?.date, prefs.lang)}/>
            <DetailRow label={t("message_id")} value={header?.messageId ?? ""} mono/>
          </div>)}

        <div className="mail-actions" role="toolbar" aria-label={t("more")}>
          <button type="button" className="icon-btn mail-tool-btn" onClick={() => actions.onReply("reply", message)} aria-label={t("reply")} title={t("reply")}>
            <IconReply size={16}/>
          </button>
          <button type="button" className="icon-btn mail-tool-btn" onClick={() => actions.onReply("replyAll", message)} aria-label={t("reply_all")} title={t("reply_all")}>
            <IconReplyAll size={16}/>
          </button>
          <button type="button" className="icon-btn mail-tool-btn" onClick={() => actions.onReply("forward", message)} aria-label={t("forward")} title={t("forward")}>
            <IconForward size={16}/>
          </button>
          <span className="mail-actions-sep" aria-hidden/>
          <button type="button" className="icon-btn mail-tool-btn" onClick={() => actions.onArchive(message)} disabled={!canArchive} aria-label={t("archive")} title={canArchive ? t("archive") : t("archive_unavailable")}>
            <IconArchive size={16}/>
          </button>
          <button type="button" className="icon-btn mail-tool-btn" onClick={() => actions.onDelete(message)} aria-label={t("delete")} title={t("delete")}>
            <IconTrash size={16}/>
          </button>
          <select className="mail-move-select mail-move-select--reader" aria-label={t("move_to")} title={t("move_to")} value="" disabled={moveTargets.length === 0} onChange={(e) => {
            const target = e.target.value;
            if (target)
                actions.onMove(message, target);
        }}>
            <option value="">{t("move_to")}…</option>
            {moveTargets.map((target) => (<option key={target.name} value={target.name}>
                {target.label}
              </option>))}
          </select>
          <button type="button" className="icon-btn mail-tool-btn" onClick={printMessage} aria-label={t("print")} title={t("print")}>
            <IconPrinter size={16}/>
          </button>
          <button type="button" className="icon-btn mail-tool-btn" onClick={downloadRaw} aria-label={t("download_raw")} title={t("download_raw")}>
            <IconDownload size={16}/>
          </button>
        </div>
      </div>

      {blocked && (<div className="mail-banner" role="status">
          <IconWarn size={14}/>
          <div className="mail-banner-text">
            <div>{t("images_blocked", { n: message.remoteImagesBlocked })}</div>
            <div className="mail-banner-hint">{t("images_blocked_hint")}</div>
          </div>
          <button type="button" className="btn glass--control mail-banner-btn" onClick={() => setShowImages(true)}>
            {t("show_images")}
          </button>
        </div>)}

      {message.body.truncated && (<div className="mail-banner mail-banner--info" role="status">
          <IconWarn size={14}/> {t("truncated_notice")}
        </div>)}

      <div className="mail-reader-body">
        {readerDoc ? (<iframe className="mail-reader-frame" title={subject} sandbox="" referrerPolicy="no-referrer" srcDoc={readerDoc}/>) : (<div className="mail-reader-text-wrap">
            {quoted ? (<>
                <pre className="mail-reader-text">{quoted.head}</pre>
                {quoted.quote && (<details className="mail-quote">
                    <summary>{t("show_quote")}</summary>
                    <pre className="mail-reader-text mail-reader-quote">{quoted.quote}</pre>
                  </details>)}
              </>) : (<pre className="mail-reader-text">{message.body.text ?? ""}</pre>)}
          </div>)}
      </div>

      {message.attachments.length > 0 && (<div className="mail-attachments" aria-label={t("attachments", { n: message.attachments.length })}>
          <span className="mail-attachments-title">{t("attachments", { n: message.attachments.length })}</span>
          {message.attachments.map((attachment) => (<button key={attachment.partId} type="button" className="mail-attachment-chip" title={`${attachment.filename} · ${formatFileSize(attachment.size)}`} onClick={() => downloadAttachment(attachment)}>
              <IconDownload size={13}/>
              <span className="mail-attachment-name">{attachment.filename}</span>
              <span className="mail-attachment-size tnum">{formatFileSize(attachment.size)}</span>
            </button>))}
        </div>)}
    </section>);
}
function formatAddress(address: {
    name?: string;
    address?: string;
} | null | undefined): string {
    if (!address)
        return "";
    const name = (address.name ?? "").trim();
    const addr = (address.address ?? "").trim();
    if (!addr)
        return name;
    return name ? `${name} <${addr}>` : addr;
}
function DetailRow({ label, value, mono = false }: {
    label: string;
    value: string;
    mono?: boolean;
}) {
    return (<div className="mail-detail-row">
      <span className="mail-detail-label">{label}</span>
      <span className={`mail-detail-value ${mono ? "mono" : ""}`}>{value}</span>
    </div>);
}

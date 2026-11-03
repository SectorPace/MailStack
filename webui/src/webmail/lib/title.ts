// document.title 的未读计数（契约 §5.8）：未读 > 0 时形如 `(3) Inbox · MailStack Webmail`。

export function buildDocumentTitle(unread: number, folderLabel: string): string {
  const n = Number.isFinite(unread) && unread > 0 ? Math.floor(unread) : 0;
  const label = (folderLabel ?? "").trim();
  const base = label ? `${label} · MailStack Webmail` : "MailStack Webmail";
  return n > 0 ? `(${n}) ${base}` : base;
}

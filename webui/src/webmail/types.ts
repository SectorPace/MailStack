// Webmail API 数据类型 —— 逐字段对齐冻结契约 `review/WEBMAIL_CONTRACT.md` §2.1。
//
// 纪律：这里只声明后端**确实返回**的形状。后端可选字段（可空）一律显式 `| null`，
// 前端渲染时必须做空值兜底，不得用 `as` 把不确定数据硬转成确定类型。

/** 邮件地址（`{name, address}`；name 可为空串）。 */
export type MailAddress = { name: string; address: string };

/** 登录账号（来自 `/etc/mailstack/managed-mailboxes.json` 的展示信息）。 */
export type MailUser = {
  email: string;
  account: string;
  displayName: string;
};

/** POST /mail/api/session、GET /mail/api/session 的 200 响应。 */
export type SessionInfo = {
  user: MailUser;
  csrfToken: string;
  expiresInSeconds: number;
};

/**
 * Maildir 特殊用途。服务端按 `MailStore::special_use_map` + 名称兜底映射，
 * `flagged` / `all` 可能是虚拟用途（取决于后端实现）。
 */
export type SpecialUse =
  | "inbox"
  | "sent"
  | "drafts"
  | "trash"
  | "junk"
  | "archive"
  | "flagged"
  | "all";

/** GET /mail/api/folders 的单条 folder。 */
export type MailFolder = {
  name: string;
  specialUse: SpecialUse[];
  subscribed: boolean;
  total: number;
  unseen: number;
};

/** 列表行（MessageSummary）。 */
export type MessageSummary = {
  uid: number;
  flags: string[];
  size: number;
  from: MailAddress;
  to: MailAddress[];
  subject: string;
  date: string;
  snippet: string;
  hasAttachments: boolean;
  messageId: string;
  threadKey: string;
};

/** 阅读窗格正文。`html` 是**服务端消毒后**的 HTML（客户端不再信任其它来源）。 */
export type MessageBody = {
  text: string | null;
  html: string | null;
  truncated: boolean;
};

/** 附件 / 内嵌资源。partId 用于 `/parts/{partId}` 下载端点。 */
export type MailAttachment = {
  partId: string;
  filename: string;
  contentType: string;
  size: number;
  disposition: string;
  inline: boolean;
  cid: string | null;
};

/** 阅读窗格头信息。 */
export type MessageHeaders = {
  from: MailAddress;
  to: MailAddress[];
  cc: MailAddress[];
  bcc: MailAddress[];
  replyTo: MailAddress[];
  subject: string;
  date: string;
  messageId: string;
  inReplyTo: string | null;
  references: string[];
  listUnsubscribe: string | null;
};

/** GET /mail/api/messages/{folder}/{uid} 的单封详情。 */
export type MessageDetail = {
  uid: number;
  folder: string;
  flags: string[];
  size: number;
  headers: MessageHeaders;
  body: MessageBody;
  attachments: MailAttachment[];
  /** 被服务端阻断的远程图片数量（`?images=1` 时保留原 src、此值为 0）。 */
  remoteImagesBlocked: number;
};

/** GET /mail/api/messages 的响应（过滤 + 分页后的总数在 total）。 */
export type MessageListResult = {
  folder: string;
  total: number;
  offset: number;
  limit: number;
  messages: MessageSummary[];
};

/** 写操作 → 新 flags。 */
export type FlagsPatch = {
  seen?: boolean;
  flagged?: boolean;
  answered?: boolean;
};

/** POST /mail/api/messages（保存草稿）响应。 */
export type DraftResult = { uid: number; folder: string };

/** POST /mail/api/send 的 202 响应。 */
export type SendResult = {
  queued: boolean;
  queueId: string;
  /** Sent 副本的 uid；Sent append 失败时为 null（不可丢信，宁可少一份副本）。 */
  sentUid: number | null;
  warning?: string | null;
};

/** POST /mail/api/messages/batch 的动作。 */
export type BatchAction =
  | "move"
  | "copy"
  | "delete"
  | "mark_seen"
  | "mark_unseen"
  | "flag"
  | "unflag";

/** POST /mail/api/messages/batch 请求。 */
export type BatchRequest = {
  folder: string;
  uids: number[];
  action: BatchAction;
  target?: string;
};

/** GET /mail/api/quota。limits 为 null 表示无限制。 */
export type QuotaInfo = {
  messages: number;
  storageBytes: number;
  limits: { messages: number | null; storageBytes: number | null };
};

/** ComposeRequest 附件：base64（不含 data: 前缀）。 */
export type ComposeAttachment = {
  filename: string;
  contentType: string;
  dataBase64: string;
};

/** POST /mail/api/send 与 POST /mail/api/messages（草稿）的载荷。 */
export type ComposeRequest = {
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text?: string;
  html?: string;
  inReplyTo?: string;
  references?: string[];
  attachments?: ComposeAttachment[];
};

/** GET /mail/api/messages 的查询参数。 */
export type MessageQuery = {
  folder: string;
  limit: number;
  offset: number;
  q?: string;
  unread?: boolean;
  flagged?: boolean;
  sort?: "date_desc" | "date_asc";
};

/** 错误响应体：`{"error":{"code","message"}}`。 */
export type ApiErrorBody = { error?: { code?: string; message?: string } };

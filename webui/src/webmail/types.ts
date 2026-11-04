export type MailAddress = {
    name: string;
    address: string;
};
export type MailUser = {
    email: string;
    account: string;
    displayName: string;
};
export type SessionInfo = {
    user: MailUser;
    csrfToken: string;
    expiresInSeconds: number;
};
export type SpecialUse = "inbox" | "sent" | "drafts" | "trash" | "junk" | "archive" | "flagged" | "all";
export type MailFolder = {
    name: string;
    specialUse: SpecialUse[];
    subscribed: boolean;
    total: number;
    unseen: number;
};
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
export type MessageBody = {
    text: string | null;
    html: string | null;
    truncated: boolean;
};
export type MailAttachment = {
    partId: string;
    filename: string;
    contentType: string;
    size: number;
    disposition: string;
    inline: boolean;
    cid: string | null;
};
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
export type MessageDetail = {
    uid: number;
    folder: string;
    flags: string[];
    size: number;
    headers: MessageHeaders;
    body: MessageBody;
    attachments: MailAttachment[];
    remoteImagesBlocked: number;
};
export type MessageListResult = {
    folder: string;
    total: number;
    offset: number;
    limit: number;
    messages: MessageSummary[];
};
export type FlagsPatch = {
    seen?: boolean;
    flagged?: boolean;
    answered?: boolean;
};
export type DraftResult = {
    uid: number;
    folder: string;
};
export type SendResult = {
    queued: boolean;
    queueId: string;
    sentUid: number | null;
    warning?: string | null;
};
export type BatchAction = "move" | "copy" | "delete" | "mark_seen" | "mark_unseen" | "flag" | "unflag";
export type BatchRequest = {
    folder: string;
    uids: number[];
    action: BatchAction;
    target?: string;
};
export type QuotaInfo = {
    messages: number;
    storageBytes: number;
    limits: {
        messages: number | null;
        storageBytes: number | null;
    };
};
export type ComposeAttachment = {
    filename: string;
    contentType: string;
    dataBase64: string;
};
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
export type MessageQuery = {
    folder: string;
    limit: number;
    offset: number;
    q?: string;
    unread?: boolean;
    flagged?: boolean;
    sort?: "date_desc" | "date_asc";
};
export type ApiErrorBody = {
    error?: {
        code?: string;
        message?: string;
    };
};

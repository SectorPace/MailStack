// Webmail 测试夹具（仅测试 import；应用入口不引用，不会进入构建产物）。
import type { MailAddress, MailFolder, MessageDetail, MessageSummary } from "./types";

export function addr(name: string, address: string): MailAddress {
  return { name, address };
}

export function makeSummary(over: Partial<MessageSummary> = {}): MessageSummary {
  return {
    uid: 1,
    flags: ["seen"],
    size: 2048,
    from: addr("Alice Chen", "alice@example.com"),
    to: [addr("Bob", "bob@example.com")],
    subject: "Hello",
    date: new Date().toISOString(),
    snippet: "snippet",
    hasAttachments: false,
    messageId: "<m1@example.com>",
    threadKey: "<m1@example.com>",
    ...over,
  };
}

/** 详情夹具：headers/body 允许只覆盖部分字段（其余用默认值补齐）。 */
export type DetailOverrides = Omit<Partial<MessageDetail>, "headers" | "body"> & {
  headers?: Partial<MessageDetail["headers"]>;
  body?: Partial<MessageDetail["body"]>;
};

export function makeDetail(over: DetailOverrides = {}): MessageDetail {
  const base: MessageDetail = {
    uid: 1,
    folder: "INBOX",
    flags: ["seen"],
    size: 2048,
    headers: {
      from: addr("Alice Chen", "alice@example.com"),
      to: [addr("Me", "me@example.com")],
      cc: [],
      bcc: [],
      replyTo: [],
      subject: "Hello",
      date: "2026-11-03T07:00:00Z",
      messageId: "<m1@example.com>",
      inReplyTo: null,
      references: [],
      listUnsubscribe: null,
    },
    body: { text: "Hello there", html: null, truncated: false },
    attachments: [],
    remoteImagesBlocked: 0,
  };
  return {
    ...base,
    ...over,
    headers: { ...base.headers, ...(over.headers ?? {}) },
    body: { ...base.body, ...(over.body ?? {}) },
  };
}

export function makeFolder(name: string, specialUse: MailFolder["specialUse"] = [], unseen = 0, total = 0): MailFolder {
  return { name, specialUse, subscribed: true, total, unseen };
}

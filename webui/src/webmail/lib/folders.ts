// 文件夹视图模型（纯函数）—— 把后端 folders 数组映射成侧栏可渲染的分组：
//   Starred（虚拟，置顶）/ Inbox / Sent / Drafts / Archive / Junk / Trash / 自定义（字母序）。
//
// 契约 §2 的特殊用途是 `specialUse: ["inbox","sent","drafts","trash","junk","archive","flagged","all"]`：
// 真实文件夹可能带其中一个用途；没有 flagged 用途的真实文件夹时，前端合成
// 「星标」虚拟视图：对 INBOX 请求 `flagged=1`（见 `flaggedOnly`）。
//
// 这里只做纯映射（图标/徽标/排序），不发起任何请求。

import type { MailFolder, SpecialUse } from "../types";

export type FolderKind = "inbox" | "starred" | "sent" | "drafts" | "archive" | "junk" | "trash" | "custom";

export type FolderView = {
  /** 侧栏稳定 key（路由/选中态用）：`inbox`、`starred`、`sent`… 或 `custom:<name>`。 */
  key: string;
  /** 请求该视图时使用的 Maildir 文件夹名。 */
  folder: string;
  kind: FolderKind;
  /** 虚拟星标：对 INBOX 加 `flagged=1` 过滤。 */
  flaggedOnly: boolean;
  unseen: number;
  total: number;
};

const KIND_BY_SPECIAL_USE: Record<SpecialUse, FolderKind> = {
  inbox: "inbox",
  sent: "sent",
  drafts: "drafts",
  trash: "trash",
  junk: "junk",
  archive: "archive",
  flagged: "starred",
  all: "inbox",
};

/** 名称兜底映射（服务端 special_use_map 缺失时按 Maildir 惯例猜用途）。 */
const KIND_BY_NAME: Record<string, FolderKind> = {
  inbox: "inbox",
  sent: "sent",
  "sent items": "sent",
  "sent messages": "sent",
  drafts: "drafts",
  draft: "drafts",
  archive: "archive",
  archives: "archive",
  junk: "junk",
  spam: "junk",
  "junk e-mail": "junk",
  trash: "trash",
  deleted: "trash",
  "deleted items": "trash",
  trashcan: "trash",
  starred: "starred",
  flagged: "starred",
};

/** 单个文件夹的用途判定：specialUse 优先，名称兜底，最后 custom。 */
export function folderKind(folder: MailFolder): FolderKind {
  const uses = Array.isArray(folder.specialUse) ? folder.specialUse : [];
  for (const use of uses) {
    const kind = KIND_BY_SPECIAL_USE[use];
    if (kind) return kind;
  }
  const byName = KIND_BY_NAME[(folder.name ?? "").trim().toLowerCase()];
  return byName ?? "custom";
}

/** INBOX 的真实 Maildir 名（服务端大小写不敏感映射；缺失时回退 "INBOX"）。 */
export function inboxFolderName(folders: readonly MailFolder[]): string {
  const inbox = folders.find((f) => folderKind(f) === "inbox");
  return inbox?.name ?? "INBOX";
}

/** 真实归档文件夹名；没有归档用途的文件夹时返回 null（前端禁用「归档」）。 */
export function archiveFolderName(folders: readonly MailFolder[]): string | null {
  const archive = folders.find((f) => folderKind(f) === "archive");
  return archive?.name ?? null;
}

/** 目标文件夹的下拉候选（排除当前文件夹）。 */
export function moveTargets(folders: readonly MailFolder[], currentFolder: string): { name: string; kind: FolderKind }[] {
  return folders
    .filter((f) => f.name !== currentFolder)
    .map((f) => ({ name: f.name, kind: folderKind(f) }));
}

const ORDER: FolderKind[] = ["starred", "inbox", "sent", "drafts", "archive", "junk", "trash", "custom"];

/**
 * 构建侧栏视图列表（顺序固定；自定义文件夹按名称本地化排序）。
 * 星标：若后端有 flagged 用途的真实文件夹则直接使用，否则合成虚拟视图。
 */
export function buildFolderViews(folders: readonly MailFolder[]): FolderView[] {
  const real = Array.isArray(folders) ? folders.filter((f) => typeof f?.name === "string" && f.name) : [];
  const views: FolderView[] = [];
  const starredReal = real.find((f) => folderKind(f) === "starred");
  const inboxName = inboxFolderName(real);

  if (starredReal) {
    views.push({
      key: "starred",
      folder: starredReal.name,
      kind: "starred",
      flaggedOnly: false,
      unseen: starredReal.unseen ?? 0,
      total: starredReal.total ?? 0,
    });
  } else {
    // 无真实 flagged 文件夹：合成虚拟星标视图，对 INBOX 请求 flagged=1。
    views.push({
      key: "starred",
      folder: inboxName,
      kind: "starred",
      flaggedOnly: true,
      unseen: 0,
      total: 0,
    });
  }

  for (const kind of ORDER) {
    if (kind === "starred" || kind === "custom") continue;
    const folder = real.find((f) => folderKind(f) === kind);
    if (!folder) continue;
    views.push({
      key: kind,
      folder: folder.name,
      kind,
      flaggedOnly: false,
      unseen: folder.unseen ?? 0,
      total: folder.total ?? 0,
    });
  }

  const customs = real
    .filter((f) => folderKind(f) === "custom")
    .sort((a, b) => a.name.localeCompare(b.name, "zh-Hans-CN"));
  for (const folder of customs) {
    views.push({
      key: `custom:${folder.name}`,
      folder: folder.name,
      kind: "custom",
      flaggedOnly: false,
      unseen: folder.unseen ?? 0,
      total: folder.total ?? 0,
    });
  }
  return views;
}

/** 未读总数（侧栏徽标 + document.title 用；星标虚拟视图不重复计数）。 */
export function totalUnseen(folders: readonly MailFolder[]): number {
  const seen = new Set<string>();
  let total = 0;
  for (const f of folders) {
    const kind = folderKind(f);
    // 星标只是过滤视图，其 unseen 与 INBOX 重叠，排除避免重复计数。
    if (kind === "starred") continue;
    if (seen.has(f.name)) continue;
    seen.add(f.name);
    total += Math.max(0, f.unseen ?? 0);
  }
  return total;
}

/** 当前路由/视图对应的 FolderView（找不到时回退收件箱视图）。 */
export function findFolderView(views: readonly FolderView[], folderName: string): FolderView | undefined {
  return views.find((v) => v.folder === folderName && !v.flaggedOnly) ?? views.find((v) => v.folder === folderName);
}

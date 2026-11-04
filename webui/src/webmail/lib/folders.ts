import type { MailFolder, SpecialUse } from "../types";
export type FolderKind = "inbox" | "starred" | "sent" | "drafts" | "archive" | "junk" | "trash" | "custom";
export type FolderView = {
    key: string;
    folder: string;
    kind: FolderKind;
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
export function folderKind(folder: MailFolder): FolderKind {
    const uses = Array.isArray(folder.specialUse) ? folder.specialUse : [];
    for (const use of uses) {
        const kind = KIND_BY_SPECIAL_USE[use];
        if (kind)
            return kind;
    }
    const byName = KIND_BY_NAME[(folder.name ?? "").trim().toLowerCase()];
    return byName ?? "custom";
}
export function inboxFolderName(folders: readonly MailFolder[]): string {
    const inbox = folders.find((f) => folderKind(f) === "inbox");
    return inbox?.name ?? "INBOX";
}
export function archiveFolderName(folders: readonly MailFolder[]): string | null {
    const archive = folders.find((f) => folderKind(f) === "archive");
    return archive?.name ?? null;
}
export function moveTargets(folders: readonly MailFolder[], currentFolder: string): {
    name: string;
    kind: FolderKind;
}[] {
    return folders
        .filter((f) => f.name !== currentFolder)
        .map((f) => ({ name: f.name, kind: folderKind(f) }));
}
const ORDER: FolderKind[] = ["starred", "inbox", "sent", "drafts", "archive", "junk", "trash", "custom"];
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
    }
    else {
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
        if (kind === "starred" || kind === "custom")
            continue;
        const folder = real.find((f) => folderKind(f) === kind);
        if (!folder)
            continue;
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
export function totalUnseen(folders: readonly MailFolder[]): number {
    const seen = new Set<string>();
    let total = 0;
    for (const f of folders) {
        const kind = folderKind(f);
        if (kind === "starred")
            continue;
        if (seen.has(f.name))
            continue;
        seen.add(f.name);
        total += Math.max(0, f.unseen ?? 0);
    }
    return total;
}
export function findFolderView(views: readonly FolderView[], folderName: string): FolderView | undefined {
    return views.find((v) => v.folder === folderName && !v.flaggedOnly) ?? views.find((v) => v.folder === folderName);
}

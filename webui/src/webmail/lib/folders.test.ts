// 文件夹视图模型测试：特殊用途映射 / 星标虚拟视图 / 顺序 / 未读汇总 / 归档目标。
import { describe, expect, it } from "vitest";
import {
  archiveFolderName,
  buildFolderViews,
  findFolderView,
  folderKind,
  inboxFolderName,
  moveTargets,
  totalUnseen,
} from "./folders";
import { makeFolder } from "../test-utils";

const FOLDERS = [
  makeFolder("INBOX", ["inbox"], 2, 10),
  makeFolder("Sent", ["sent"], 0, 3),
  makeFolder("Drafts", ["drafts"], 0, 1),
  makeFolder("Archive", ["archive"], 0, 5),
  makeFolder("Junk", ["junk"], 1, 2),
  makeFolder("Trash", ["trash"], 0, 4),
  makeFolder("Projects", [], 0, 0),
  makeFolder("Alpha", [], 0, 0),
];

describe("folderKind", () => {
  it("prefers specialUse, falls back to name conventions", () => {
    expect(folderKind(makeFolder("anything", ["archive"]))).toBe("archive");
    expect(folderKind(makeFolder("Inbox"))).toBe("inbox");
    expect(folderKind(makeFolder("Spam"))).toBe("junk");
    expect(folderKind(makeFolder("Sent Items"))).toBe("sent");
    expect(folderKind(makeFolder("Projects"))).toBe("custom");
  });
});

describe("buildFolderViews", () => {
  it("puts Starred first and keeps the contract order, customs last (alphabetical)", () => {
    const views = buildFolderViews(FOLDERS);
    expect(views.map((v) => v.kind)).toEqual([
      "starred",
      "inbox",
      "sent",
      "drafts",
      "archive",
      "junk",
      "trash",
      "custom",
      "custom",
    ]);
    expect(views[7].folder).toBe("Alpha");
    expect(views[8].folder).toBe("Projects");
  });

  it("synthesizes the Starred view as INBOX + flagged when no real flagged folder exists", () => {
    const starred = buildFolderViews(FOLDERS)[0];
    expect(starred.flaggedOnly).toBe(true);
    expect(starred.folder).toBe("INBOX");
    expect(starred.unseen).toBe(0);
  });

  it("uses a real flagged folder when the backend provides one", () => {
    const withFlagged = [...FOLDERS, makeFolder("Starred", ["flagged"], 4, 9)];
    const starred = buildFolderViews(withFlagged)[0];
    expect(starred.flaggedOnly).toBe(false);
    expect(starred.folder).toBe("Starred");
    expect(starred.unseen).toBe(4);
  });

  it("does not duplicate a custom folder when its name matches a known alias", () => {
    const views = buildFolderViews([makeFolder("INBOX", ["inbox"]), makeFolder("inbox", [])]);
    expect(views.filter((v) => v.folder === "inbox").length).toBe(0);
  });
});

describe("totalUnseen", () => {
  it("sums unseen across folders but ignores the starred filter view", () => {
    expect(totalUnseen(FOLDERS)).toBe(3); // INBOX 2 + Junk 1
    expect(totalUnseen([...FOLDERS, makeFolder("Starred", ["flagged"], 4, 9)])).toBe(3);
    expect(totalUnseen([])).toBe(0);
  });
});

describe("folder helpers", () => {
  it("resolves INBOX and Archive names", () => {
    expect(inboxFolderName(FOLDERS)).toBe("INBOX");
    expect(inboxFolderName([])).toBe("INBOX");
    expect(archiveFolderName(FOLDERS)).toBe("Archive");
    expect(archiveFolderName([makeFolder("INBOX", ["inbox"])])).toBeNull();
  });

  it("builds move targets without the current folder", () => {
    const targets = moveTargets(FOLDERS, "INBOX");
    expect(targets.some((t) => t.name === "INBOX")).toBe(false);
    expect(targets.some((t) => t.name === "Archive")).toBe(true);
  });

  it("finds a view by folder name", () => {
    const views = buildFolderViews(FOLDERS);
    expect(findFolderView(views, "Sent")?.kind).toBe("sent");
    expect(findFolderView(views, "missing")).toBeUndefined();
  });
});

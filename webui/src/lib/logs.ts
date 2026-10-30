// 日志条目归一化 —— 从页面模块抽出的纯工具。
//
// 原先 `Dashboard.tsx` 直接 `import { normalizeLog } from "./MailQueue"`，把页面模块当
// 工具库用：Dashboard 是首屏（同步按需加载的 chunk），而 MailQueue 也是 `lazy()` 分包，
// 这条 import 会把整个 MailQueue 页面（含 Radix Tabs、DataTable 用法）拽进 Dashboard 的
// chunk，代码分割失效。工具函数独立成模块后，两页各自按需加载。

/** 后端 logs.list 的条目（journalctl JSON）：{ time, priority, level, unit, identifier, message }。 */
export type RawLog = {
  id?: string;
  time?: string;
  level?: string;
  service?: string;
  identifier?: string | null;
  unit?: string | null;
  message?: string;
  from?: string;
  to?: string;
  domain?: string;
  retry?: number;
};

export type LogRow = {
  id: string;
  time: string;
  level: "info" | "warn" | "error";
  service: string;
  message: string;
  from?: string;
  to?: string;
  domain?: string;
  retry?: number;
};

/** syslog 级别名 → UI 三态；mock 已给 info/warn/error。 */
export function normLevel(level?: string): "info" | "warn" | "error" {
  switch (level) {
    case "err":
    case "crit":
    case "emerg":
    case "alert":
    case "error":
      return "error";
    case "warning":
    case "warn":
      return "warn";
    default:
      return "info";
  }
}

/** 把后端/mock 两种日志形状统一成前端 LogRow（后端没有 service/from 等，取 identifier/unit）。 */
export function normalizeLog(e: RawLog, i: number): LogRow {
  return {
    id: e.id ?? `${e.time ?? "log"}-${i}`,
    time: e.time ?? "",
    level: normLevel(e.level),
    service: e.service ?? e.identifier ?? e.unit ?? "",
    message: e.message ?? "",
    from: e.from,
    to: e.to,
    domain: e.domain,
    retry: e.retry,
  };
}

// 共享格式化助手 —— 各页面原先各自 slice() 时间戳、拼接 url()，行为不一且有坑：
//   * 后端时间戳是 ISO8601（UTC），`slice(11,16)` 会把 UTC 当本地时间展示
//     （UTC+8 用户看到「14:22」，实际发生在本地 22:22）；
//   * CSS url() 不加引号时，值里出现 `"`/`\`/`)` 就会破坏声明甚至注入。
// MailQueue.tsx 的 parseTime 先行（mock 的 "YYYY-MM-DD HH:mm:ss" 与 ISO 双兼容），
// 这里抽成共享模块，Dashboard / Toolbar / Security 统一使用。

/** 解析 ISO8601 或 mock 的 "YYYY-MM-DD HH:mm:ss"；解析不了返回 null。 */
export function parseTimeMs(s?: string | null): number | null {
  if (!s) return null;
  const raw = s.includes("T") ? s : s.replace(" ", "T");
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? ms : null;
}

/** HH:mm（本地时区）；无法解析时原样返回输入（不编造，也不返回空串掩盖）。 */
export function formatTime(s?: string | null): string {
  const ms = parseTimeMs(s);
  if (ms == null) return s ?? "";
  const d = new Date(ms);
  const p = (x: number) => String(x).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** MM-DD HH:mm（本地时区）；无法解析时原样返回输入。 */
export function formatDayTime(s?: string | null): string {
  const ms = parseTimeMs(s);
  if (ms == null) return s ?? "";
  const d = new Date(ms);
  const p = (x: number) => String(x).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/**
 * CSS url("…") 的安全插值：先转义反斜杠再转义双引号，最后带引号返回。
 * customBg 来自 localStorage / data URL，可被外部改写 —— 裸拼进 style 会破坏 CSS。
 */
export function cssUrl(v: string): string {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

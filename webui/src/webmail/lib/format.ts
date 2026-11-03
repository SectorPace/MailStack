// Webmail 纯函数 —— 日期 / 大小 / 地址展示。
//
// 全部为无副作用的纯函数（可被 vitest 直接覆盖）；时间格式化显式接收 `now`，
// 避免测试依赖真实时钟。列表时间规则（契约 §5.1）：
//   今天 → HH:mm；今年 → M月D日（zh）/ MMM D（en）；更早 → YYYY-MM-DD。
// 时区：使用浏览器本地时区（邮件客户端惯例）；测试由 vitest.config.ts 钉住 UTC。

import type { MailAddress } from "../types";
import type { Lang } from "../i18n";

const MONTHS_EN = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** 解析 ISO8601（或契约允许的其它 Date.parse 可识别串）；非法输入返回 null。 */
export function parseMailDate(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? new Date(ms) : null;
}

const pad2 = (n: number): string => String(n).padStart(2, "0");

/** `HH:mm`（本地时区）。 */
export function formatClock(d: Date): string {
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

/**
 * 列表行时间（契约 §5.1）：今天 → HH:mm；今年 → 日期；更早 → YYYY-MM-DD。
 * `now` 显式传入（默认取当前时间），测试可固定。
 */
export function formatListDate(iso: string | null | undefined, lang: Lang, now: Date = new Date()): string {
  const d = parseMailDate(iso);
  if (!d) return "";
  const sameDay =
    d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  if (sameDay) return formatClock(d);
  if (d.getFullYear() === now.getFullYear()) {
    return lang === "zh" ? `${d.getMonth() + 1}月${d.getDate()}日` : `${MONTHS_EN[d.getMonth()]} ${d.getDate()}`;
  }
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

/** 阅读窗格完整日期：`YYYY年M月D日 HH:mm` / `MMM D, YYYY HH:mm`。 */
export function formatFullDate(iso: string | null | undefined, lang: Lang): string {
  const d = parseMailDate(iso);
  if (!d) return "";
  const time = formatClock(d);
  return lang === "zh"
    ? `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日 ${time}`
    : `${MONTHS_EN[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()} ${time}`;
}

/** 字节数 → 人类可读（1024 进制，保留一位小数；0 显示 0 B）。 */
export function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = v >= 100 ? 0 : 1;
  return `${v.toFixed(digits)} ${units[i]}`;
}

/** 发件人展示名：优先 name，其次地址；两者皆空回退「未知发件人」占位（由调用方 i18n 化）。 */
export function senderName(from: MailAddress | null | undefined): string {
  if (!from) return "";
  const name = (from.name ?? "").trim();
  if (name) return name;
  return (from.address ?? "").trim();
}

/** 地址列表 → `"A <a@x>, B <b@y>"`。 */
export function formatAddressList(list: MailAddress[] | null | undefined): string {
  if (!Array.isArray(list)) return "";
  return list
    .map((a) => {
      const name = (a?.name ?? "").trim();
      const addr = (a?.address ?? "").trim();
      if (!addr) return "";
      return name ? `${name} <${addr}>` : addr;
    })
    .filter(Boolean)
    .join(", ");
}

/** 头像首字母：中文取首字，英文取单词首字母（最多 2 个），空值用 "?"。 */
export function initials(label: string): string {
  const s = (label ?? "").trim();
  if (!s) return "?";
  if (/^[\u4e00-\u9fff]/.test(s)) return s.slice(0, 1);
  const parts = s.split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return s.slice(0, 2).toUpperCase();
}

/** 截断长文本（按字符数，不切断代理对的开销可忽略；末尾加省略号）。 */
export function truncate(text: string, max: number): string {
  const s = text ?? "";
  if (max <= 0 || s.length <= max) return s;
  return `${s.slice(0, max)}…`;
}

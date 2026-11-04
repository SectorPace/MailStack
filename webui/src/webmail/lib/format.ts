import type { MailAddress } from "../types";
import type { Lang } from "../i18n";
const MONTHS_EN = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export function parseMailDate(iso: string | null | undefined): Date | null {
    if (!iso)
        return null;
    const ms = Date.parse(iso);
    return Number.isFinite(ms) ? new Date(ms) : null;
}
const pad2 = (n: number): string => String(n).padStart(2, "0");
export function formatClock(d: Date): string {
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}
export function formatListDate(iso: string | null | undefined, lang: Lang, now: Date = new Date()): string {
    const d = parseMailDate(iso);
    if (!d)
        return "";
    const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
    if (sameDay)
        return formatClock(d);
    if (d.getFullYear() === now.getFullYear()) {
        return lang === "zh" ? `${d.getMonth() + 1}月${d.getDate()}日` : `${MONTHS_EN[d.getMonth()]} ${d.getDate()}`;
    }
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}
export function formatFullDate(iso: string | null | undefined, lang: Lang): string {
    const d = parseMailDate(iso);
    if (!d)
        return "";
    const time = formatClock(d);
    return lang === "zh"
        ? `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日 ${time}`
        : `${MONTHS_EN[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()} ${time}`;
}
export function formatFileSize(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes < 0)
        return "";
    if (bytes < 1024)
        return `${Math.round(bytes)} B`;
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
export function senderName(from: MailAddress | null | undefined): string {
    if (!from)
        return "";
    const name = (from.name ?? "").trim();
    if (name)
        return name;
    return (from.address ?? "").trim();
}
export function formatAddressList(list: MailAddress[] | null | undefined): string {
    if (!Array.isArray(list))
        return "";
    return list
        .map((a) => {
        const name = (a?.name ?? "").trim();
        const addr = (a?.address ?? "").trim();
        if (!addr)
            return "";
        return name ? `${name} <${addr}>` : addr;
    })
        .filter(Boolean)
        .join(", ");
}
export function initials(label: string): string {
    const s = (label ?? "").trim();
    if (!s)
        return "?";
    if (/^[\u4e00-\u9fff]/.test(s))
        return s.slice(0, 1);
    const parts = s.split(/[\s._-]+/).filter(Boolean);
    if (parts.length >= 2)
        return (parts[0][0] + parts[1][0]).toUpperCase();
    return s.slice(0, 2).toUpperCase();
}
export function truncate(text: string, max: number): string {
    const s = text ?? "";
    if (max <= 0 || s.length <= max)
        return s;
    return `${s.slice(0, max)}…`;
}

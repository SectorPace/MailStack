export function parseTimeMs(s?: string | null): number | null {
    if (!s)
        return null;
    const raw = s.includes("T") ? s : s.replace(" ", "T");
    const ms = Date.parse(raw);
    return Number.isFinite(ms) ? ms : null;
}
export function formatTime(s?: string | null): string {
    const ms = parseTimeMs(s);
    if (ms == null)
        return s ?? "";
    const d = new Date(ms);
    const p = (x: number) => String(x).padStart(2, "0");
    return `${p(d.getHours())}:${p(d.getMinutes())}`;
}
export function formatDayTime(s?: string | null): string {
    const ms = parseTimeMs(s);
    if (ms == null)
        return s ?? "";
    const d = new Date(ms);
    const p = (x: number) => String(x).padStart(2, "0");
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
export function cssUrl(v: string): string {
    return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

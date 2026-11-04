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

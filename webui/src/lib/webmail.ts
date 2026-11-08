const CONFIGURED_RAW = (import.meta.env.VITE_WEBMAIL_URL as string | undefined)?.trim();
const WEBMAIL_PORT_RAW = (import.meta.env.VITE_WEBMAIL_PORT as string | undefined)?.trim();

function normalizePort(raw: string | undefined): string {
    const value = Number(raw ?? "");
    if (!Number.isInteger(value) || value < 1 || value > 65535)
        return "8444";
    return String(value);
}

const WEBMAIL_PORT = normalizePort(WEBMAIL_PORT_RAW);

function configuredUrl(raw: string | undefined): string | null {
    if (!raw)
        return null;
    try {
        const url = new URL(raw);
        if (url.protocol !== "http:" && url.protocol !== "https:")
            return null;
        return url.toString();
    }
    catch {
        return null;
    }
}

export function webmailUrl(): string | null {
    const configured = configuredUrl(CONFIGURED_RAW);
    if (configured)
        return configured;
    if (typeof location === "undefined")
        return null;
    const { protocol, hostname } = location;
    if (!hostname)
        return null;
    if (protocol !== "http:" && protocol !== "https:")
        return null;
    const host = hostname.includes(":") ? `[${hostname}]` : hostname;
    return `${protocol}//${host}:${WEBMAIL_PORT}/`;
}

export function hasWebmailUrl(): boolean {
    return webmailUrl() !== null;
}

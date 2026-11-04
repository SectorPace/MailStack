const CONFIGURED = (import.meta.env.VITE_WEBMAIL_URL as string | undefined)?.trim();
export function webmailUrl(): string | null {
    if (CONFIGURED)
        return CONFIGURED;
    if (typeof location === "undefined")
        return null;
    const { protocol, hostname } = location;
    if (!hostname)
        return null;
    if (protocol !== "http:" && protocol !== "https:")
        return null;
    return `${protocol}//${hostname}:8444/`;
}
export function hasWebmailUrl(): boolean {
    return webmailUrl() !== null;
}

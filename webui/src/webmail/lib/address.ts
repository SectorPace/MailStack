const MAX_ADDRESS_LENGTH = 320;
const ILLEGAL_ADDRESS_CHARS = /[\s\u0000-\u001f\u007f"'<>()[\],;]/;
export function isValidAddress(raw: string): boolean {
    const addr = (raw ?? "").trim();
    if (!addr || addr.length > MAX_ADDRESS_LENGTH)
        return false;
    if (ILLEGAL_ADDRESS_CHARS.test(addr))
        return false;
    const at = addr.indexOf("@");
    if (at <= 0 || at !== addr.lastIndexOf("@"))
        return false;
    const local = addr.slice(0, at);
    const domain = addr.slice(at + 1);
    if (!local || !domain)
        return false;
    if (!domain.includes("."))
        return false;
    if (local.startsWith(".") || local.endsWith(".") || local.includes(".."))
        return false;
    if (domain.startsWith(".") || domain.endsWith(".") || domain.includes(".."))
        return false;
    return true;
}
export function normalizeAddress(addr: string): string {
    return (addr ?? "").trim().toLowerCase();
}
export function splitAddressInput(raw: string): string[] {
    if (!raw)
        return [];
    return raw
        .split(/[,;，；\n\r\t]+/)
        .map((part) => {
        const s = part.trim();
        const wrapped = /^.*<([^<>]+)>\s*$/.exec(s);
        return (wrapped ? wrapped[1] : s).trim();
    })
        .filter(Boolean);
}
export type ParsedAddresses = {
    valid: string[];
    invalid: string[];
    duplicates: string[];
};
export function parseAddresses(raw: string, existing: readonly string[] = []): ParsedAddresses {
    const seen = new Set<string>(existing.map(normalizeAddress));
    const valid: string[] = [];
    const invalid: string[] = [];
    const duplicates: string[] = [];
    for (const candidate of splitAddressInput(raw)) {
        const key = normalizeAddress(candidate);
        if (!isValidAddress(candidate)) {
            invalid.push(candidate);
            continue;
        }
        if (seen.has(key)) {
            duplicates.push(candidate);
            continue;
        }
        seen.add(key);
        valid.push(candidate);
    }
    return { valid, invalid, duplicates };
}
export function dedupeAddresses(list: readonly string[]): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const item of list) {
        const key = normalizeAddress(item);
        if (!key || seen.has(key))
            continue;
        seen.add(key);
        out.push(item.trim());
    }
    return out;
}
export function mergeAddresses(...lists: readonly (readonly string[])[]): string[] {
    return dedupeAddresses(lists.flat());
}

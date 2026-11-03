// 收件人地址的解析 / 校验 / 去重 —— 写信芯片输入（To/Cc/Bcc）纯函数层。
//
// 契约 §2.2 对地址的要求（服务端还会再校验一次，前端先挡住明显输错的）：
// 非空、无 CR/LF/NUL、含 `@`、长度 ≤ 320；前端额外拒绝空白/引号/尖括号等
// 会破坏头部的字符，避免用户写出「看起来合法、发出去被退回」的地址。
//
// 去重规则：忽略大小写（邮箱 local-part 理论上区分大小写，但收件人去重按
// 大小写不敏感处理是邮件客户端通行行为），保留首次出现的原始写法。

const MAX_ADDRESS_LENGTH = 320;

/** 一个地址里不允许出现的字符（空白、控制字符、引号、尖括号、分隔符）。 */
const ILLEGAL_ADDRESS_CHARS = /[\s\u0000-\u001f\u007f"'<>()[\],;]/;

/** 单地址校验（RFC 5321 简化，与服务端「含 @ 且无 CR/LF」的立场一致但更严）。 */
export function isValidAddress(raw: string): boolean {
  const addr = (raw ?? "").trim();
  if (!addr || addr.length > MAX_ADDRESS_LENGTH) return false;
  if (ILLEGAL_ADDRESS_CHARS.test(addr)) return false;
  const at = addr.indexOf("@");
  if (at <= 0 || at !== addr.lastIndexOf("@")) return false;
  const local = addr.slice(0, at);
  const domain = addr.slice(at + 1);
  if (!local || !domain) return false;
  if (!domain.includes(".")) return false; // 拒绝 alice@localhost 之类（邮件客户端通行做法）
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return false;
  if (domain.startsWith(".") || domain.endsWith(".") || domain.includes("..")) return false;
  return true;
}

/** 大小写不敏感归一（仅用于比较/去重，不用于发送）。 */
export function normalizeAddress(addr: string): string {
  return (addr ?? "").trim().toLowerCase();
}

/**
 * 把一段原始输入拆成候选地址：逗号 / 分号（中英文）/ 换行 / 制表符都是分隔符。
 * 同时去掉可选的 `Name <addr>` 包装，只留下 addr。
 */
export function splitAddressInput(raw: string): string[] {
  if (!raw) return [];
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
  /** 合法且去重后的地址（保留原始大小写）。 */
  valid: string[];
  /** 不合法、被丢弃的候选地址（用于提示用户）。 */
  invalid: string[];
  /** 已存在（重复）被跳过的候选地址。 */
  duplicates: string[];
};

/**
 * 解析并合并到已有列表：
 *  - 合法 + 未重复 → 追加到 valid；
 *  - 不合法 → invalid；
 *  - 与 existing 或本批前面重复 → duplicates。
 */
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

/** 去重（大小写不敏感）后的地址列表。 */
export function dedupeAddresses(list: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of list) {
    const key = normalizeAddress(item);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(item.trim());
  }
  return out;
}

/** 合并多个地址数组并去重（reply-all 的 from+to+cc 汇总用）。 */
export function mergeAddresses(...lists: readonly (readonly string[])[]): string[] {
  return dedupeAddresses(lists.flat());
}

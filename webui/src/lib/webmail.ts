// Webmail 入口 URL。
//
// Webmail 是**独立进程**（默认 127.0.0.1:8444），与管理台（默认 8443）分属不同
// 端口与会话体系。管理台只提供外部链接，不做 iframe 内嵌 —— 同源嵌入会把
// 「邮箱用户会话」和「管理员会话」放进同一个浏览上下文，CSP 与 CSRF 边界都会变糊。
//
// 部署差异用构建期环境变量覆盖：
//   VITE_WEBMAIL_URL=https://mail.example.com/
// 未配置时按「同主机、8444 端口」推导（与本仓库 mailstackd/systemd 默认一致），
// 适用于 SSH 隧道（-L 8443 -L 8444）或内网直连。
const CONFIGURED = (import.meta.env.VITE_WEBMAIL_URL as string | undefined)?.trim();

export function webmailUrl(): string | null {
  if (CONFIGURED) return CONFIGURED;
  if (typeof location === "undefined") return null;
  const { protocol, hostname } = location;
  if (!hostname) return null;
  // file:// 打开 dist/index.html 的调试场景没有可用后端，不给链接。
  if (protocol !== "http:" && protocol !== "https:") return null;
  return `${protocol}//${hostname}:8444/`;
}

/** 链接是否可用（不可用时管理台不渲染入口，避免死链）。 */
export function hasWebmailUrl(): boolean {
  return webmailUrl() !== null;
}

// 通用状态组件：头像 / 空态 / 加载骨架 / 错误横幅。
// 加载骨架与错误横幅必须与「空列表」可区分（管理台 WEBUI_AUDIT 的同款纪律：
// 失败页不能长得像「暂无数据」）。
import type { ReactNode } from "react";
import { initials } from "../lib/format";
import { IconRefresh, IconWarn } from "./icons";

/** 圆形首字母头像（发件人 / 账户菜单）。 */
export function MailAvatar({ label, size = 32 }: { label: string; size?: number }) {
  const text = initials(label);
  const hue = hashHue(label);
  return (
    <span
      aria-hidden
      className="mail-avatar"
      style={{
        width: size,
        height: size,
        fontSize: Math.max(10, Math.round(size * 0.38)),
        background: `linear-gradient(180deg, hsl(${hue} 72% 58%), hsl(${hue} 66% 46%))`,
      }}
    >
      {text}
    </span>
  );
}

function hashHue(seed: string): number {
  let hash = 0;
  const s = seed ?? "";
  for (let i = 0; i < s.length; i += 1) hash = (hash * 31 + s.charCodeAt(i)) % 360;
  return hash;
}

/** 空态（收件箱空 / 搜索无结果 / 未选中邮件）。 */
export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon: ReactNode;
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="mail-empty" role="status">
      <span className="mail-empty-icon" aria-hidden>
        {icon}
      </span>
      <div className="mail-empty-title">{title}</div>
      {hint && <div className="mail-empty-hint">{hint}</div>}
      {action}
    </div>
  );
}

/** 列表加载骨架（N 行灰条），与内容同宽同高节奏。 */
export function SkeletonRows({ count = 7 }: { count?: number }) {
  return (
    <div aria-busy="true" aria-label="loading">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="mail-skeleton-row">
          <span className="mail-skeleton-dot" />
          <span className="mail-skeleton-lines">
            <span className="mail-skeleton-line" style={{ width: `${38 + ((i * 13) % 24)}%` }} />
            <span className="mail-skeleton-line mail-skeleton-line--soft" style={{ width: `${58 + ((i * 17) % 28)}%` }} />
          </span>
        </div>
      ))}
    </div>
  );
}

/** 错误横幅（带重试）。message 由调用方翻译/透传（网络错误用 i18n error_network）。 */
export function ErrorBanner({ message, retryLabel, onRetry }: { message: string; retryLabel: string; onRetry?: () => void }) {
  return (
    <div className="mail-error" role="alert">
      <span className="mail-error-text" title={message}>
        <IconWarn size={13} /> {message}
      </span>
      {onRetry && (
        <button type="button" className="mail-error-retry" onClick={onRetry}>
          <IconRefresh size={12} /> {retryLabel}
        </button>
      )}
    </div>
  );
}

/** 小型旋转指示器（按钮内 loading 用）。 */
export function Spinner({ size = 14 }: { size?: number }) {
  return <span className="mail-spinner" style={{ width: size, height: size }} aria-hidden />;
}

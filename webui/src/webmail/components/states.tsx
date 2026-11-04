import type { ReactNode } from "react";
import { initials } from "../lib/format";
import { IconRefresh, IconWarn } from "./icons";
export function MailAvatar({ label, size = 32 }: {
    label: string;
    size?: number;
}) {
    const text = initials(label);
    const hue = hashHue(label);
    return (<span aria-hidden className="mail-avatar" style={{
            width: size,
            height: size,
            fontSize: Math.max(10, Math.round(size * 0.38)),
            background: `linear-gradient(180deg, hsl(${hue} 72% 58%), hsl(${hue} 66% 46%))`,
        }}>
      {text}
    </span>);
}
function hashHue(seed: string): number {
    let hash = 0;
    const s = seed ?? "";
    for (let i = 0; i < s.length; i += 1)
        hash = (hash * 31 + s.charCodeAt(i)) % 360;
    return hash;
}
export function EmptyState({ icon, title, hint, action, }: {
    icon: ReactNode;
    title: string;
    hint?: string;
    action?: ReactNode;
}) {
    return (<div className="mail-empty" role="status">
      <span className="mail-empty-icon" aria-hidden>
        {icon}
      </span>
      <div className="mail-empty-title">{title}</div>
      {hint && <div className="mail-empty-hint">{hint}</div>}
      {action}
    </div>);
}
export function SkeletonRows({ count = 7 }: {
    count?: number;
}) {
    return (<div aria-busy="true" aria-label="loading">
      {Array.from({ length: count }, (_, i) => (<div key={i} className="mail-skeleton-row">
          <span className="mail-skeleton-dot"/>
          <span className="mail-skeleton-lines">
            <span className="mail-skeleton-line" style={{ width: `${38 + ((i * 13) % 24)}%` }}/>
            <span className="mail-skeleton-line mail-skeleton-line--soft" style={{ width: `${58 + ((i * 17) % 28)}%` }}/>
          </span>
        </div>))}
    </div>);
}
export function ErrorBanner({ message, retryLabel, onRetry }: {
    message: string;
    retryLabel: string;
    onRetry?: () => void;
}) {
    return (<div className="mail-error" role="alert">
      <span className="mail-error-text" title={message}>
        <IconWarn size={13}/> {message}
      </span>
      {onRetry && (<button type="button" className="mail-error-retry" onClick={onRetry}>
          <IconRefresh size={12}/> {retryLabel}
        </button>)}
    </div>);
}
export function Spinner({ size = 14 }: {
    size?: number;
}) {
    return <span className="mail-spinner" style={{ width: size, height: size }} aria-hidden/>;
}

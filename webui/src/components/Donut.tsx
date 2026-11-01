// SVG 环形图：多段分布（服务状态分布）与单值渐变环（综合健康度）
import { useId } from "react";

export type DonutSegment = { value: number; color: string };

/** 多段环形（各段颜色自定，顺时针排布，带 2° 间隙） */
export function DonutChart({
  segments,
  size = 128,
  thickness = 13,
  centerTop,
  centerSub,
}: {
  segments: DonutSegment[];
  size?: number;
  thickness?: number;
  centerTop: string;
  centerSub: string;
}) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const r = (size - thickness) / 2;
  const C = 2 * Math.PI * r;
  const gap = 2.5; // 段间隙（单位：弧长）
  let offset = 0;
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={centerSub}>
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          {segments.map((seg, i) => {
            const len = (seg.value / total) * C;
            // 零值/极小段（len<=gap）：linecap=round 会把它们画成脱线的「幽灵圆点」，
            // 视觉上像多出一个状态 —— 直接跳过（offset 仍按 len 前进，占位不变）。
            if (len <= gap) {
              offset += len;
              return null;
            }
            const dash = Math.max(0, len - gap);
            const el = (
              <circle
                key={i}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={seg.color}
                strokeWidth={thickness}
                strokeLinecap="round"
                strokeDasharray={`${dash} ${C - dash}`}
                strokeDashoffset={-offset}
              />
            );
            offset += len;
            return el;
          })}
        </g>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="tnum text-[24px] font-semibold leading-none text-[var(--text-1)]">{centerTop}</span>
        <span className="mt-1 text-[10.5px] text-[var(--text-3)]">{centerSub}</span>
      </div>
    </div>
  );
}

/** 单值渐变环（综合健康度）；value 为 null 时显示占位符 —（后端没给数据，绝不编造分数）。 */
export function GaugeRing({
  value,
  size = 128,
  thickness = 12,
  label,
}: {
  value: number | null;
  size?: number;
  thickness?: number;
  label: string;
}) {
  const gid = useId();
  const r = (size - thickness) / 2;
  const C = 2 * Math.PI * r;
  const pct = value == null ? 0 : Math.max(0, Math.min(100, value)) / 100;
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label}>
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="rgb(var(--accent-rgb))" />
            <stop offset="100%" stopColor="rgb(var(--ok-rgb))" />
          </linearGradient>
        </defs>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--bar-track)" strokeWidth={thickness} />
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={`url(#${gid})`}
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={`${C * pct} ${C}`}
            style={{ transition: "stroke-dasharray .9s cubic-bezier(.32,.72,0,1)" }}
          />
        </g>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="tnum text-[26px] font-semibold leading-none text-[var(--text-1)]">{value == null ? "—" : `${value}%`}</span>
        <span className="mt-1 text-[10px] text-[var(--text-3)]">{label}</span>
      </div>
    </div>
  );
}

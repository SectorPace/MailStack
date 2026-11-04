import { useId, useMemo, useState } from "react";
export type ChartPoint = {
    t: string;
    v: number;
};
function smoothPath(coords: {
    x: number;
    y: number;
}[]): string {
    if (coords.length === 0)
        return "";
    if (coords.length < 3) {
        return coords.map((c, i) => `${i === 0 ? "M" : "L"}${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(" ");
    }
    let d = `M${coords[0].x.toFixed(1)},${coords[0].y.toFixed(1)}`;
    for (let i = 0; i < coords.length - 1; i++) {
        const p0 = coords[Math.max(0, i - 1)];
        const p1 = coords[i];
        const p2 = coords[i + 1];
        const p3 = coords[Math.min(coords.length - 1, i + 2)];
        const c1x = p1.x + (p2.x - p0.x) / 6;
        const c1y = p1.y + (p2.y - p0.y) / 6;
        const c2x = p2.x - (p3.x - p1.x) / 6;
        const c2y = p2.y - (p3.y - p1.y) / 6;
        d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}`;
    }
    return d;
}
export function LineChart({ points, height = 148, unit = "s", area = true, }: {
    points: ChartPoint[];
    height?: number;
    unit?: string;
    area?: boolean;
}) {
    const [hover, setHover] = useState<number | null>(null);
    const gid = useId();
    const W = 640;
    const H = height;
    const padL = 34;
    const padR = 10;
    const padT = 12;
    const padB = 22;
    const { maxY, ticks, path, areaPath, coords } = useMemo(() => {
        const vals = points.map((p) => p.v);
        const rawMax = Math.max(10, ...vals);
        const step = rawMax > 60 ? 20 : rawMax > 30 ? 10 : 5;
        const maxY = Math.ceil(rawMax / step) * step;
        const ticks: number[] = [];
        for (let v = 0; v <= maxY; v += step)
            ticks.push(v);
        const x = (i: number) => padL + (i / Math.max(1, points.length - 1)) * (W - padL - padR);
        const y = (v: number) => padT + (1 - v / maxY) * (H - padT - padB);
        const coords = points.map((p, i) => ({ x: x(i), y: y(p.v), p }));
        const path = smoothPath(coords);
        const areaPath = `${path} L${coords[coords.length - 1]?.x ?? padL},${H - padB} L${padL},${H - padB} Z`;
        return { maxY, ticks, path, areaPath, coords };
    }, [points, H]);
    const xLabelEvery = Math.ceil(points.length / 7);
    const h = hover != null && hover < coords.length ? hover : null;
    return (<div className="relative w-full" style={{ fontSize: 10.5 }}>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="delivery latency chart">
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgb(var(--accent-rgb))" stopOpacity="0.22"/>
            <stop offset="100%" stopColor="rgb(var(--accent-rgb))" stopOpacity="0.02"/>
          </linearGradient>
        </defs>

        {ticks.map((v) => {
            const y = padT + (1 - v / maxY) * (H - padT - padB);
            return (<g key={v}>
              <line x1={padL} x2={W - padR} y1={y} y2={y} stroke="var(--hairline)" strokeWidth="1"/>
              <text x={padL - 7} y={y + 3.5} textAnchor="end" fill="var(--text-3)">
                {v}
                {unit === "s" ? "s" : ""}
              </text>
            </g>);
        })}

        {coords.map((c, i) => i % xLabelEvery === 0 ? (<text key={`x-${i}`} x={c.x} y={H - 6} textAnchor="middle" fill="var(--text-3)">
              {c.p.t}
            </text>) : null)}

        {area && <path d={areaPath} fill={`url(#${gid})`} stroke="none"/>}
        <path d={path} fill="none" stroke="rgb(var(--accent-rgb))" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>

        {coords.map((c, i) => (<circle key={`d-${i}`} cx={c.x} cy={c.y} r={h === i ? 4 : 2.4} fill="rgb(var(--accent-rgb))" stroke="white" strokeWidth={h === i ? 1.6 : 0} opacity={h == null || h === i ? 1 : 0.55}/>))}

        {coords.map((c, i) => (<rect key={`h-${i}`} x={c.x - (W - padL - padR) / points.length / 2} y={0} width={(W - padL - padR) / points.length} height={H} fill="transparent" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}/>))}

        {h != null && (<line x1={coords[h].x} x2={coords[h].x} y1={padT} y2={H - padB} stroke="rgb(var(--accent-rgb) / 0.4)" strokeWidth="1"/>)}
      </svg>
      {h != null && (<div className="glass--clear pointer-events-none absolute z-10 rounded-lg px-2.5 py-1.5 text-[11.5px] text-[var(--text-1)]" style={{
                left: `${(coords[h].x / W) * 100}%`,
                top: 0,
                transform: `translateX(${coords[h].x > W * 0.7 ? "-108%" : "8%"})`,
            }}>
          <span className="tnum font-semibold">
            {coords[h].p.v}
            {unit}
          </span>
          <span className="ml-1.5 text-[var(--text-3)]">{coords[h].p.t}</span>
        </div>)}
    </div>);
}

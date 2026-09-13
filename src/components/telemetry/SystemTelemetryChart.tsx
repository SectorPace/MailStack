import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { api } from '../../api';
import { getErrorMessage } from '../../utils/errors';
import { TelemetryTimeframe, TelemetryResponse, TelemetryPoint } from '../../types';
import { TelemetryRangeDropdown } from './TelemetryRangeDropdown';
import {
  Activity,
  Cpu,
  Layers,
  Server,
  RefreshCw,
  Sparkles,
  Maximize2,
  HardDrive,
  Info,
  CheckCircle2,
  AlertCircle
} from '@/lib/icons';

type ActiveMetric = 'daemon_memory' | 'cpu_percent' | 'system_memory' | 'load_average';

interface Props {
  language: 'zh' | 'en';
  isLight?: boolean;
  onOpenInspector?: () => void;
}

export const SystemTelemetryChart: React.FC<Props> = ({
  language,
  isLight = false,
  onOpenInspector,
}) => {
  const [timeframe, setTimeframe] = useState<TelemetryTimeframe>('1h');
  const [activeMetric, setActiveMetric] = useState<ActiveMetric>('daemon_memory');
  const [data, setData] = useState<TelemetryResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const [mousePos, setMousePos] = useState<{ x: number; y: number } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const fetchTelemetry = useCallback(
    async (showSpinner = false) => {
      if (showSpinner) setIsRefreshing(true);
      try {
        const res: TelemetryResponse = await api(`/api/metrics/telemetry?range=${timeframe}`);
        setData(res);
      } catch (err) {
        console.error('Failed to fetch telemetry:', getErrorMessage(err));
      } finally {
        setLoading(false);
        if (showSpinner) setIsRefreshing(false);
      }
    },
    [timeframe]
  );

  // Poll intervals based on timeframe
  useEffect(() => {
    fetchTelemetry(true);
    const intervalMs =
      timeframe === '1m'
        ? 2000
        : timeframe === '5m'
        ? 3000
        : timeframe === '30m'
        ? 5000
        : timeframe === '1h'
        ? 10000
        : 30000;

    const interval = setInterval(() => {
      if (!document.hidden) {
        fetchTelemetry(false);
      }
    }, intervalMs);

    return () => clearInterval(interval);
  }, [timeframe, fetchTelemetry]);

  const points = useMemo(() => data?.points || [], [data]);

  // Metric metadata
  const metricConfig = useMemo(() => {
    switch (activeMetric) {
      case 'daemon_memory':
        return {
          titleZh: '守护进程内存',
          titleEn: 'Daemon Memory',
          unit: 'MB',
          color: '#00f2c3',
          lightColor: '#059669',
          gradientFrom: '#00f2c3',
          gradientTo: '#0284c7',
          getValue: (p: TelemetryPoint) => p.memoryMb,
          formatter: (v: number) => `${v.toFixed(1)} MB`,
        };
      case 'cpu_percent':
        return {
          titleZh: 'CPU 利用率',
          titleEn: 'CPU Utilization',
          unit: '%',
          color: '#38bdf8',
          lightColor: '#0284c7',
          gradientFrom: '#38bdf8',
          gradientTo: '#6366f1',
          getValue: (p: TelemetryPoint) => p.cpuPercent,
          formatter: (v: number) => `${v.toFixed(1)}%`,
        };
      case 'system_memory':
        return {
          titleZh: '系统内存占用',
          titleEn: 'System Memory',
          unit: '%',
          color: '#a855f7',
          lightColor: '#7e22ce',
          gradientFrom: '#a855f7',
          gradientTo: '#ec4899',
          getValue: (p: TelemetryPoint) => p.systemMemoryPercent,
          formatter: (v: number) => `${v.toFixed(1)}%`,
        };
      case 'load_average':
        return {
          titleZh: '系统平均负载 (1m Load)',
          titleEn: 'Load Average (1m)',
          unit: '',
          color: '#f59e0b',
          lightColor: '#d97706',
          gradientFrom: '#f59e0b',
          gradientTo: '#ef4444',
          getValue: (p: TelemetryPoint) => p.load1,
          formatter: (v: number) => `${v.toFixed(2)}`,
        };
    }
  }, [activeMetric]);

  // Calculate SVG Coordinates & Curves
  const chartMath = useMemo(() => {
    const width = 700;
    const height = 180;
    if (points.length < 2) {
      return {
        pathD: '',
        areaD: '',
        coords: [],
        minVal: 0,
        maxVal: 100,
        ticks: [0, 25, 50, 75, 100],
      };
    }

    const values = points.map(metricConfig.getValue);
    let minVal = Math.min(...values);
    let maxVal = Math.max(...values);

    if (activeMetric === 'cpu_percent' || activeMetric === 'system_memory') {
      minVal = 0;
      maxVal = Math.max(10, Math.ceil(maxVal / 10) * 10);
      if (maxVal > 100) maxVal = 100;
    } else if (activeMetric === 'daemon_memory') {
      minVal = Math.max(0, Math.floor(minVal * 0.8));
      maxVal = Math.max(20, Math.ceil(maxVal * 1.2));
    } else {
      minVal = 0;
      maxVal = Math.max(1.0, Math.ceil(maxVal * 1.3 * 10) / 10);
    }

    const range = maxVal - minVal || 1;
    const padding = 10;
    const plotHeight = height - padding * 2;

    const coords = points.map((p, idx) => {
      const x = (idx / (points.length - 1)) * width;
      const val = metricConfig.getValue(p);
      const y = height - padding - ((val - minVal) / range) * plotHeight;
      return { x, y, val, point: p };
    });

    // Smooth Bezier Curve generation
    let pathD = `M ${coords[0].x},${coords[0].y}`;
    for (let i = 0; i < coords.length - 1; i++) {
      const curr = coords[i];
      const next = coords[i + 1];
      const cpx1 = curr.x + (next.x - curr.x) / 3;
      const cpy1 = curr.y;
      const cpx2 = curr.x + ((next.x - curr.x) * 2) / 3;
      const cpy2 = next.y;
      pathD += ` C ${cpx1},${cpy1} ${cpx2},${cpy2} ${next.x},${next.y}`;
    }

    const areaD = `${pathD} L ${width},${height} L 0,${height} Z`;

    const ticks = [
      minVal,
      minVal + range * 0.25,
      minVal + range * 0.5,
      minVal + range * 0.75,
      maxVal,
    ];

    return { pathD, areaD, coords, minVal, maxVal, ticks };
  }, [points, metricConfig, activeMetric]);

  // Handle SVG Mouse Move for Tooltip
  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!svgRef.current || chartMath.coords.length === 0) return;
    const rect = svgRef.current.getBoundingClientRect();
    const clientX = e.clientX - rect.left;
    const clientY = e.clientY - rect.top;
    const relativeX = Math.max(0, Math.min(700, (clientX / rect.width) * 700));

    // Find nearest point index
    let nearestIdx = 0;
    let nearestDist = Infinity;
    chartMath.coords.forEach((coord, i) => {
      const dist = Math.abs(coord.x - relativeX);
      if (dist < nearestDist) {
        nearestDist = dist;
        nearestIdx = i;
      }
    });

    setHoverIndex(nearestIdx);
    setMousePos({ x: clientX, y: clientY });
  };

  const handleMouseLeave = () => {
    setHoverIndex(null);
    setMousePos(null);
  };

  // Format time labels for X-axis
  const formatTimeLabel = (isoStr?: string) => {
    if (!isoStr) return '';
    try {
      const d = new Date(isoStr);
      if (timeframe === '1m' || timeframe === '5m' || timeframe === '30m') {
        return d.toTimeString().substring(0, 8);
      }
      if (timeframe === '1h' || timeframe === '6h') {
        return d.toTimeString().substring(0, 5);
      }
      return `${d.getMonth() + 1}-${d.getDate()} ${d.toTimeString().substring(0, 5)}`;
    } catch {
      return '';
    }
  };

  const hoveredPoint = hoverIndex !== null && chartMath.coords[hoverIndex] ? chartMath.coords[hoverIndex] : null;

  return (
    <div className="space-y-4">
      {/* Top Header: Title, Real-time status, Dropdown & Inspector Launcher */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h3 className={`text-sm font-bold tracking-wide flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
              <Activity className="w-4 h-4 text-cyan-500 dark:text-cyan-400" />
              <span>{language === 'zh' ? '系统守护进程内存与资源负载' : 'System Daemon Telemetry & Workload'}</span>
            </h3>
            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 text-[10px] font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
              <span>{language === 'zh' ? '实时监控中' : 'Live Sampling'}</span>
            </div>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            {language === 'zh'
              ? `已监控 ${data?.current.daemons.length || 6} 项核心服务，总内存消耗约 ${data?.current.totalDaemonMemoryMb.toFixed(1) || '0.0'} MB (${data?.current.hostname || 'MailStack'})`
              : `Tracking ${data?.current.daemons.length || 6} daemons with ~${data?.current.totalDaemonMemoryMb.toFixed(1) || '0.0'} MB memory on ${data?.current.hostname || 'MailStack'}`}
          </p>
        </div>

        {/* Controls: Range Dropdown, Manual Refresh, Inspector Modal Button */}
        <div className="flex items-center gap-2">
          {/* Timeframe Dropdown (1m, 5m, 30m, 1h [Default], 6h, 24h, 3d) */}
          <TelemetryRangeDropdown
            value={timeframe}
            onChange={(val) => setTimeframe(val)}
            language={language}
            isLight={isLight}
          />

          {/* Refresh Button */}
          <button
            type="button"
            onClick={() => fetchTelemetry(true)}
            disabled={isRefreshing}
            className={`p-1.5 rounded-xl border text-slate-500 hover:text-cyan-500 transition-all cursor-pointer ${
              isLight ? 'bg-slate-100 hover:bg-slate-200 border-slate-300' : 'bg-white/[0.08] hover:bg-white/[0.15] border-white/10'
            }`}
            title={language === 'zh' ? '立即刷新时序数据' : 'Refresh Telemetry'}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          {/* Open Deep Inspector Modal */}
          {onOpenInspector && (
            <button
              type="button"
              onClick={onOpenInspector}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-xs font-medium text-cyan-600 dark:text-cyan-400 transition-all cursor-pointer shadow-sm ${
                isLight
                  ? 'bg-cyan-50 hover:bg-cyan-100/80 border-cyan-300/80'
                  : 'bg-cyan-500/10 hover:bg-cyan-500/20 border-cyan-400/30'
              }`}
            >
              <Maximize2 className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '系统监测工具' : 'Inspector'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Metric Switcher Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
        {[
          {
            id: 'daemon_memory' as const,
            titleZh: '守护进程内存',
            titleEn: 'Daemon Memory',
            val: `${data?.current.totalDaemonMemoryMb.toFixed(1) || '0.0'} MB`,
            subZh: `峰值 ${data?.summary.maxMemoryMb.toFixed(1) || '0.0'} MB`,
            subEn: `Peak ${data?.summary.maxMemoryMb.toFixed(1) || '0.0'} MB`,
            icon: Layers,
            accent: 'text-emerald-500 dark:text-emerald-400',
            border: 'border-emerald-500/30',
          },
          {
            id: 'cpu_percent' as const,
            titleZh: 'CPU 利用率',
            titleEn: 'CPU Utilization',
            val: `${data?.current.cpuPercent.toFixed(1) || '0.0'}%`,
            subZh: `均值 ${data?.summary.avgCpu.toFixed(1) || '0.0'}%`,
            subEn: `Avg ${data?.summary.avgCpu.toFixed(1) || '0.0'}%`,
            icon: Cpu,
            accent: 'text-sky-500 dark:text-sky-400',
            border: 'border-sky-500/30',
          },
          {
            id: 'system_memory' as const,
            titleZh: '系统内存占用',
            titleEn: 'System Memory',
            val: `${data?.current.systemMemoryPercent.toFixed(1) || '0.0'}%`,
            subZh: `${data?.current.systemMemoryUsedMb || 0} / ${data?.current.systemMemoryTotalMb || 0} MB`,
            subEn: `${data?.current.systemMemoryUsedMb || 0} / ${data?.current.systemMemoryTotalMb || 0} MB`,
            icon: Server,
            accent: 'text-purple-500 dark:text-purple-400',
            border: 'border-purple-500/30',
          },
          {
            id: 'load_average' as const,
            titleZh: '系统平均负载',
            titleEn: 'Load Average',
            val: `${data?.current.loadAvg[0].toFixed(2) || '0.00'}`,
            subZh: `5m: ${data?.current.loadAvg[1].toFixed(2) || '0.00'} | 15m: ${data?.current.loadAvg[2].toFixed(2) || '0.00'}`,
            subEn: `5m: ${data?.current.loadAvg[1].toFixed(2) || '0.00'} | 15m: ${data?.current.loadAvg[2].toFixed(2) || '0.00'}`,
            icon: Activity,
            accent: 'text-amber-500 dark:text-amber-400',
            border: 'border-amber-500/30',
          },
        ].map((tab) => {
          const isSelected = activeMetric === tab.id;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveMetric(tab.id)}
              className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                isSelected
                  ? isLight
                    ? 'bg-white shadow-md border-cyan-400 ring-2 ring-cyan-400/20'
                    : 'bg-white/[0.10] shadow-lg border-cyan-400/60 ring-2 ring-cyan-500/20'
                  : isLight
                  ? 'bg-slate-50/80 hover:bg-slate-100 border-slate-200'
                  : 'bg-white/[0.03] hover:bg-white/[0.07] border-white/10'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400 truncate">
                  {language === 'zh' ? tab.titleZh : tab.titleEn}
                </span>
                <Icon className={`w-3.5 h-3.5 ${tab.accent}`} />
              </div>
              <div className={`text-base font-bold font-mono tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
                {tab.val}
              </div>
              <div className="text-[10px] text-slate-400 font-mono mt-0.5 truncate">
                {language === 'zh' ? tab.subZh : tab.subEn}
              </div>
            </button>
          );
        })}
      </div>

      {/* SVG Dynamic Telemetry Curve Chart */}
      <div className="relative pt-2 pb-1">
        <div className="h-56 w-full relative">
          <svg
            ref={svgRef}
            className="w-full h-full overflow-visible select-none cursor-crosshair"
            viewBox="0 0 700 180"
            preserveAspectRatio="none"
            onMouseMove={handleMouseMove}
            onMouseLeave={handleMouseLeave}
          >
            <defs>
              <linearGradient id="metricGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={metricConfig.color} stopOpacity={isLight ? 0.4 : 0.3} />
                <stop offset="85%" stopColor={metricConfig.color} stopOpacity={0.03} />
                <stop offset="100%" stopColor={metricConfig.color} stopOpacity={0.0} />
              </linearGradient>
            </defs>

            {/* Horizontal Grid Lines */}
            {[0, 45, 90, 135, 180].map((y, idx) => (
              <line
                key={y}
                x1="0"
                y1={y}
                x2="700"
                y2={y}
                stroke={isLight ? 'rgba(203, 213, 225, 0.7)' : 'rgba(255, 255, 255, 0.08)'}
                strokeDasharray="4 4"
              />
            ))}

            {/* Dynamic Smooth Area Fill */}
            {chartMath.areaD && (
              <path d={chartMath.areaD} fill="url(#metricGrad)" className="transition-all duration-300" />
            )}

            {/* Dynamic Smooth Line */}
            {chartMath.pathD && (
              <path
                d={chartMath.pathD}
                fill="none"
                stroke={isLight ? metricConfig.lightColor : metricConfig.color}
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="transition-all duration-300"
              />
            )}

            {/* Sample data point dots */}
            {chartMath.coords.map((c, i) => {
              if (points.length > 30 && i % Math.ceil(points.length / 20) !== 0) return null;
              return (
                <circle
                  key={i}
                  cx={c.x}
                  cy={c.y}
                  r="3"
                  fill={isLight ? metricConfig.lightColor : metricConfig.color}
                  stroke={isLight ? '#ffffff' : '#080d1a'}
                  strokeWidth="1.5"
                  className="transition-transform hover:scale-150 duration-150"
                />
              );
            })}

            {/* Active Hover Crosshair Line and Circle */}
            {hoveredPoint && (
              <g>
                <line
                  x1={hoveredPoint.x}
                  y1="0"
                  x2={hoveredPoint.x}
                  y2="180"
                  stroke={isLight ? '#0284c7' : '#00f2c3'}
                  strokeWidth="1.5"
                  strokeDasharray="3 3"
                />
                <circle
                  cx={hoveredPoint.x}
                  cy={hoveredPoint.y}
                  r="6"
                  fill={isLight ? '#0284c7' : '#00f2c3'}
                  stroke="#ffffff"
                  strokeWidth="2.5"
                  className="animate-pulse"
                />
              </g>
            )}
          </svg>

          {/* Interactive Hover Tooltip Popover */}
          {hoveredPoint && mousePos && (
            <div
              className={`absolute pointer-events-none z-30 p-2.5 rounded-xl border shadow-xl backdrop-blur-xl text-xs space-y-1.5 transition-all duration-75 ${
                isLight ? 'bg-white/95 border-slate-200 text-slate-800 shadow-slate-300/60' : 'bg-slate-900/95 border-white/20 text-slate-100 shadow-black/80'
              }`}
              style={{
                left: `${Math.min(mousePos.x + 12, 480)}px`,
                top: `${Math.max(10, mousePos.y - 70)}px`,
              }}
            >
              <div className="flex items-center justify-between gap-4 border-b border-slate-200 dark:border-white/10 pb-1">
                <span className="font-mono text-[11px] text-slate-400">
                  {formatTimeLabel(hoveredPoint.point.timestamp)}
                </span>
                <span className="font-bold font-mono text-cyan-600 dark:text-cyan-400">
                  {metricConfig.formatter(hoveredPoint.val)}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] font-mono">
                <div>
                  <span className="text-slate-400">CPU: </span>
                  <span className="font-semibold">{hoveredPoint.point.cpuPercent.toFixed(1)}%</span>
                </div>
                <div>
                  <span className="text-slate-400">服务内存: </span>
                  <span className="font-semibold">{hoveredPoint.point.memoryMb.toFixed(1)} MB</span>
                </div>
                <div>
                  <span className="text-slate-400">系统内存: </span>
                  <span className="font-semibold">{hoveredPoint.point.systemMemoryPercent.toFixed(1)}%</span>
                </div>
                <div>
                  <span className="text-slate-400">Load(1m): </span>
                  <span className="font-semibold">{hoveredPoint.point.load1.toFixed(2)}</span>
                </div>
              </div>

              {/* Daemon memory breakdown */}
              {hoveredPoint.point.daemons && Object.keys(hoveredPoint.point.daemons).length > 0 && (
                <div className="pt-1 border-t border-slate-200 dark:border-white/10 flex flex-wrap gap-1.5 text-[10px] font-mono">
                  {Object.entries(hoveredPoint.point.daemons).map(([name, d]) => (
                    <span key={name} className="px-1.5 py-0.2 rounded bg-slate-100 dark:bg-white/10 text-slate-600 dark:text-slate-300">
                      {name}: {d.memoryMb.toFixed(1)}M
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Dynamic X-axis Time Labels */}
        <div className="flex justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400 mt-2 px-1">
          {points.length > 0 ? (
            <>
              <span>{formatTimeLabel(points[0]?.timestamp)}</span>
              {points.length > 3 && <span>{formatTimeLabel(points[Math.floor(points.length * 0.25)]?.timestamp)}</span>}
              {points.length > 2 && <span>{formatTimeLabel(points[Math.floor(points.length * 0.5)]?.timestamp)}</span>}
              {points.length > 3 && <span>{formatTimeLabel(points[Math.floor(points.length * 0.75)]?.timestamp)}</span>}
              <span className="text-cyan-600 dark:text-cyan-400 font-bold">{language === 'zh' ? '现在 (Now)' : 'Now'}</span>
            </>
          ) : (
            <span>{language === 'zh' ? '正在连接系统时序遥测引擎...' : 'Connecting to telemetry engine...'}</span>
          )}
        </div>
      </div>
    </div>
  );
};

import React, { useState, useRef, useEffect } from 'react';
import { TelemetryTimeframe } from '../../types';
import { ChevronDown, Clock, Check, Calendar, Activity } from '@/lib/icons';

interface RangeOption {
  id: TelemetryTimeframe;
  labelZh: string;
  labelEn: string;
  subZh: string;
  subEn: string;
  badgeZh: string;
  badgeEn: string;
}

const RANGE_OPTIONS: RangeOption[] = [
  { id: '1m', labelZh: '最近 1 分钟', labelEn: 'Last 1 Min', subZh: '2 秒极速高频采样', subEn: '2s Real-time Sampling', badgeZh: '1m', badgeEn: '1m' },
  { id: '5m', labelZh: '最近 5 分钟', labelEn: 'Last 5 Mins', subZh: '5 秒实时采样', subEn: '5s Real-time Sampling', badgeZh: '5m', badgeEn: '5m' },
  { id: '30m', labelZh: '最近 30 分钟', labelEn: 'Last 30 Mins', subZh: '30 秒时序聚合', subEn: '30s Aggregation', badgeZh: '30m', badgeEn: '30m' },
  { id: '1h', labelZh: '最近 1 小时 (默认)', labelEn: 'Last 1 Hour (Default)', subZh: '1 分钟标准监测', subEn: '1m Standard Metric', badgeZh: '1h', badgeEn: '1h' },
  { id: '6h', labelZh: '最近 6 小时', labelEn: 'Last 6 Hours', subZh: '5 分钟历史趋势', subEn: '5m Historical Trend', badgeZh: '6h', badgeEn: '6h' },
  { id: '24h', labelZh: '最近 24 小时', labelEn: 'Last 24 Hours', subZh: '15 分钟日载荷', subEn: '15m Daily Workload', badgeZh: '24h', badgeEn: '24h' },
  { id: '3d', labelZh: '最近 3 天', labelEn: 'Last 3 Days', subZh: '1 小时长周期监测', subEn: '1h Multi-day Telemetry', badgeZh: '3d', badgeEn: '3d' },
];

interface Props {
  value: TelemetryTimeframe;
  onChange: (value: TelemetryTimeframe) => void;
  language: 'zh' | 'en';
  isLight?: boolean;
}

export const TelemetryRangeDropdown: React.FC<Props> = ({
  value,
  onChange,
  language,
  isLight = false,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const currentOption = RANGE_OPTIONS.find((opt) => opt.id === value) || RANGE_OPTIONS[3];

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setIsOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  return (
    <div className="relative inline-block text-left" ref={dropdownRef}>
      {/* Dropdown Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        className={`inline-flex items-center justify-between gap-2 px-3 py-1.5 rounded-xl text-xs font-medium transition-all duration-200 cursor-pointer border shadow-sm ${
          isLight
            ? 'bg-slate-100 hover:bg-slate-200/80 text-slate-800 border-slate-300/80 hover:border-slate-400'
            : 'bg-white/[0.08] hover:bg-white/[0.14] text-slate-100 border-white/15 hover:border-cyan-400/40 backdrop-blur-md'
        } ${isOpen ? 'ring-2 ring-cyan-500/40 border-cyan-400' : ''}`}
        aria-expanded={isOpen}
        aria-haspopup="true"
      >
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-cyan-500 dark:text-cyan-400 shrink-0" />
          <span className="font-semibold tracking-tight">
            {language === 'zh' ? currentOption.labelZh : currentOption.labelEn}
          </span>
          <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
            {currentOption.badgeZh}
          </span>
        </div>
        <ChevronDown
          className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${
            isOpen ? 'rotate-180 text-cyan-500' : ''
          }`}
        />
      </button>

      {/* Collapsible Dropdown Menu Panel */}
      {isOpen && (
        <div
          className={`absolute right-0 mt-2 w-64 rounded-2xl shadow-2xl z-50 p-1.5 border backdrop-blur-xl animate-in fade-in zoom-in-95 duration-150 origin-top-right ${
            isLight
              ? 'bg-white/95 border-slate-200 text-slate-800 shadow-slate-300/50'
              : 'bg-slate-900/95 border-white/15 text-slate-100 shadow-black/80'
          }`}
          role="menu"
        >
          <div className="px-2.5 py-1.5 mb-1 border-b border-slate-200/60 dark:border-white/10 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
            <span className="flex items-center gap-1 font-semibold">
              <Activity className="w-3 h-3 text-cyan-500" />
              {language === 'zh' ? '选择时序监控跨度' : 'Select Time Range'}
            </span>
            <span className="text-[10px] font-mono text-cyan-500 font-bold">7 个预设档位</span>
          </div>

          <div className="space-y-0.5 max-h-72 overflow-y-auto custom-scrollbar">
            {RANGE_OPTIONS.map((opt) => {
              const isSelected = opt.id === value;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => {
                    onChange(opt.id);
                    setIsOpen(false);
                  }}
                  className={`w-full text-left px-2.5 py-2 rounded-xl flex items-center justify-between text-xs transition-all cursor-pointer group ${
                    isSelected
                      ? isLight
                        ? 'bg-cyan-50 text-cyan-900 font-semibold border border-cyan-300/60'
                        : 'bg-cyan-500/20 text-cyan-200 font-semibold border border-cyan-400/30'
                      : isLight
                      ? 'hover:bg-slate-100/90 text-slate-700'
                      : 'hover:bg-white/[0.08] text-slate-300'
                  }`}
                  role="menuitem"
                >
                  <div className="flex flex-col">
                    <div className="flex items-center gap-2">
                      <span className="tracking-tight">
                        {language === 'zh' ? opt.labelZh : opt.labelEn}
                      </span>
                      {opt.id === '1h' && (
                        <span className="text-[9px] px-1 py-0.2 rounded bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 font-mono font-bold">
                          {language === 'zh' ? '默认' : 'DEF'}
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] text-slate-400 dark:text-slate-400 font-mono mt-0.5">
                      {language === 'zh' ? opt.subZh : opt.subEn}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0 ml-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-200/60 dark:bg-white/10 text-slate-600 dark:text-slate-300">
                      {opt.badgeZh}
                    </span>
                    {isSelected ? (
                      <Check className="w-4 h-4 text-cyan-500 dark:text-cyan-400" />
                    ) : (
                      <div className="w-4 h-4" />
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

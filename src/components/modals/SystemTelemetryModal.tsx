import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../../api';
import { getErrorMessage } from '../../utils/errors';
import { SystemRealtimeMetrics, TelemetryResponse } from '../../types';
import { LiquidGlass } from '../common/LiquidGlass';
import {
  Activity,
  Cpu,
  Server,
  HardDrive,
  RefreshCw,
  X,
  Layers,
  Download,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Zap
} from '@/lib/icons';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  language: 'zh' | 'en';
  isLight?: boolean;
  onRestartService?: (name: string) => void;
}

export const SystemTelemetryModal: React.FC<Props> = ({
  isOpen,
  onClose,
  language,
  isLight = false,
  onRestartService,
}) => {
  const [metrics, setMetrics] = useState<SystemRealtimeMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchRealtime = useCallback(async (showSpin = false) => {
    if (showSpin) setIsRefreshing(true);
    try {
      const res: SystemRealtimeMetrics = await api('/api/metrics/realtime');
      setMetrics(res);
    } catch (err) {
      console.error('Failed to fetch realtime metrics:', getErrorMessage(err));
    } finally {
      setLoading(false);
      if (showSpin) setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    fetchRealtime(true);
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      if (!document.hidden) fetchRealtime(false);
    }, 2500);
    return () => clearInterval(timer);
  }, [isOpen, autoRefresh, fetchRealtime]);

  if (!isOpen) return null;

  const handleExportJson = () => {
    if (!metrics) return;
    const blob = new Blob([JSON.stringify(metrics, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mailstack-telemetry-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-md animate-in fade-in duration-200">
      <div className="w-full max-w-4xl max-h-[90vh] flex flex-col rounded-3xl overflow-hidden shadow-2xl border border-white/20 bg-slate-900/90 dark:bg-slate-950/95 text-slate-100 backdrop-blur-2xl">
        {/* Header */}
        <div className="p-5 border-b border-white/10 flex items-center justify-between bg-white/[0.03]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-cyan-400 to-blue-500 flex items-center justify-center text-slate-950 shadow-[0_0_15px_rgba(0,242,195,0.3)]">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-tight">
                  {language === 'zh' ? '系统深度监测与守护进程分析工具' : 'System Telemetry & Daemon Inspector'}
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                  REAL-TIME 2.5s
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {language === 'zh'
                  ? '秒级实时捕获 Linux 系统负载、多核分配、物理内存与邮件守护进程资源占用'
                  : 'Second-by-second telemetry for CPU cores, RAM, Disk, and MailStack Daemons'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleExportJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-white/10 hover:border-cyan-400/40 bg-white/[0.05] hover:bg-white/[0.1] text-xs font-medium text-slate-300 hover:text-white transition-all cursor-pointer"
              title="Export JSON"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>{language === 'zh' ? '导出数据' : 'Export'}</span>
            </button>

            <button
              type="button"
              onClick={() => fetchRealtime(true)}
              className="p-1.5 rounded-xl border border-white/10 hover:border-white/20 bg-white/[0.05] hover:bg-white/[0.1] text-slate-300 hover:text-white transition-all cursor-pointer"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-xl border border-white/10 hover:border-white/20 bg-white/[0.05] hover:bg-rose-500/20 text-slate-400 hover:text-rose-300 transition-all cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 custom-scrollbar">
          {/* Top 3 Metric Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* CPU Load Card */}
            <div className="p-4 rounded-2xl bg-white/[0.04] border border-white/10 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="flex items-center gap-1.5 font-semibold text-sky-400">
                  <Cpu className="w-4 h-4" />
                  {language === 'zh' ? 'CPU 整体负载' : 'Total CPU Load'}
                </span>
                <span className="font-mono text-cyan-400">{metrics?.cores || 1} Cores</span>
              </div>
              <div className="flex items-baseline justify-between">
                <div className="text-3xl font-black font-mono text-white">
                  {metrics?.cpuPercent.toFixed(1) || '0.0'}%
                </div>
                <div className="text-right text-[11px] font-mono text-slate-400">
                  <div>Load: {metrics?.loadAvg[0].toFixed(2) || '0.00'}</div>
                  <div className="text-[10px] text-slate-500">
                    5m: {metrics?.loadAvg[1].toFixed(2)} | 15m: {metrics?.loadAvg[2].toFixed(2)}
                  </div>
                </div>
              </div>
              {/* CPU Usage Bar */}
              <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-gradient-to-r from-sky-400 to-cyan-400 h-full transition-all duration-300"
                  style={{ width: `${Math.min(100, metrics?.cpuPercent || 0)}%` }}
                />
              </div>
            </div>

            {/* RAM Memory Card */}
            <div className="p-4 rounded-2xl bg-white/[0.04] border border-white/10 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="flex items-center gap-1.5 font-semibold text-purple-400">
                  <Server className="w-4 h-4" />
                  {language === 'zh' ? '系统物理内存' : 'Physical Memory'}
                </span>
                <span className="font-mono text-purple-400">{metrics?.systemMemoryPercent.toFixed(1) || '0.0'}%</span>
              </div>
              <div className="flex items-baseline justify-between">
                <div className="text-3xl font-black font-mono text-white">
                  {metrics?.systemMemoryUsedMb || 0}
                  <span className="text-sm font-normal text-slate-400 ml-1">MB</span>
                </div>
                <div className="text-right text-[11px] font-mono text-slate-400">
                  <div>{language === 'zh' ? '总量' : 'Total'}: {metrics?.systemMemoryTotalMb || 0} MB</div>
                  <div className="text-[10px] text-slate-500">
                    {language === 'zh' ? '空闲' : 'Free'}: {metrics?.systemMemoryFreeMb || 0} MB
                  </div>
                </div>
              </div>
              {/* Memory Bar */}
              <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-gradient-to-r from-purple-400 to-pink-500 h-full transition-all duration-300"
                  style={{ width: `${Math.min(100, metrics?.systemMemoryPercent || 0)}%` }}
                />
              </div>
            </div>

            {/* Storage Card */}
            <div className="p-4 rounded-2xl bg-white/[0.04] border border-white/10 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="flex items-center gap-1.5 font-semibold text-amber-400">
                  <HardDrive className="w-4 h-4" />
                  {language === 'zh' ? '根磁盘空间 (/)' : 'Root Disk Usage'}
                </span>
                <span className="font-mono text-amber-400">{metrics?.diskUsagePercent.toFixed(1) || '0.0'}%</span>
              </div>
              <div className="flex items-baseline justify-between">
                <div className="text-3xl font-black font-mono text-white">
                  {metrics?.diskUsedGb.toFixed(1) || '0.0'}
                  <span className="text-sm font-normal text-slate-400 ml-1">GB</span>
                </div>
                <div className="text-right text-[11px] font-mono text-slate-400">
                  <div>{language === 'zh' ? '总量' : 'Total'}: {metrics?.diskTotalGb.toFixed(1) || '0.0'} GB</div>
                  <div className="text-[10px] text-emerald-400 font-bold">
                    {language === 'zh' ? '可用' : 'Avail'}: {((metrics?.diskTotalGb || 0) - (metrics?.diskUsedGb || 0)).toFixed(1)} GB
                  </div>
                </div>
              </div>
              {/* Disk Bar */}
              <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-gradient-to-r from-amber-400 to-orange-500 h-full transition-all duration-300"
                  style={{ width: `${Math.min(100, metrics?.diskUsagePercent || 0)}%` }}
                />
              </div>
            </div>
          </div>

          {/* Core breakdown if multiple cores exist */}
          {metrics?.coreUsage && metrics.coreUsage.length > 1 && (
            <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-cyan-400" />
                  {language === 'zh' ? '多核处理器实时分配' : 'CPU Core Distribution'}
                </span>
                <span className="text-[10px] font-mono text-slate-400">{metrics.coreUsage.length} Logical Cores</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {metrics.coreUsage.map((usage, idx) => (
                  <div key={idx} className="p-2.5 rounded-xl bg-white/[0.03] border border-white/5 space-y-1.5">
                    <div className="flex justify-between text-[11px] font-mono">
                      <span className="text-slate-400">Core #{idx}</span>
                      <span className="font-bold text-cyan-400">{usage.toFixed(1)}%</span>
                    </div>
                    <div className="w-full bg-white/10 h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-cyan-400 h-full transition-all duration-300"
                        style={{ width: `${Math.min(100, usage)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* MailStack Active Daemons Table */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-emerald-400" />
                <span>{language === 'zh' ? '核心邮件守护进程资源占用明细' : 'MailStack Daemons Footprint'}</span>
              </h3>
              <span className="text-xs font-mono text-slate-400">
                {metrics?.daemons.filter((d) => d.status === 'ACTIVE').length || 0} / {metrics?.daemons.length || 0} {language === 'zh' ? '活跃' : 'Active'}
              </span>
            </div>

            <div className="rounded-2xl border border-white/10 overflow-hidden bg-white/[0.02]">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-white/10 bg-white/[0.04] text-[11px] font-mono text-slate-400">
                    <th className="py-2.5 px-4">{language === 'zh' ? '守护进程 / 服务名' : 'Daemon / Unit'}</th>
                    <th className="py-2.5 px-3">PID</th>
                    <th className="py-2.5 px-3">{language === 'zh' ? '运行状态' : 'Status'}</th>
                    <th className="py-2.5 px-3">{language === 'zh' ? 'CPU 占用' : 'CPU %'}</th>
                    <th className="py-2.5 px-3">{language === 'zh' ? '物理内存 (RSS)' : 'Memory (RSS)'}</th>
                    <th className="py-2.5 px-4 text-right">{language === 'zh' ? '快速运维' : 'Actions'}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 font-mono">
                  {metrics?.daemons.map((d) => {
                    const isActive = d.status === 'ACTIVE';
                    return (
                      <tr key={d.id} className="hover:bg-white/[0.04] transition-colors">
                        <td className="py-3 px-4 font-semibold text-slate-200">
                          <div className="flex items-center gap-2 font-sans">
                            <span className="font-mono text-cyan-300 font-bold">{d.name}</span>
                          </div>
                        </td>
                        <td className="py-3 px-3 text-slate-400">{d.pid || '-'}</td>
                        <td className="py-3 px-3">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-bold ${
                              isActive
                                ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                                : 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
                            }`}
                          >
                            <span
                              className={`w-1.5 h-1.5 rounded-full ${isActive ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`}
                            />
                            {d.status}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-sky-400 font-bold">{d.cpuPercent.toFixed(1)}%</td>
                        <td className="py-3 px-3 text-emerald-400 font-bold">{d.memoryMb.toFixed(1)} MB</td>
                        <td className="py-3 px-4 text-right">
                          {onRestartService && (
                            <button
                              type="button"
                              onClick={() => onRestartService(d.id)}
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-white/10 hover:border-cyan-400/40 bg-white/[0.05] hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 transition-all cursor-pointer text-[11px]"
                            >
                              <RotateCcw className="w-3 h-3" />
                              <span>{language === 'zh' ? '重启' : 'Restart'}</span>
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10 flex items-center justify-between bg-white/[0.02] text-xs text-slate-400 font-mono">
          <div>
            {language === 'zh' ? '最后采样时间' : 'Last sampled'}: {metrics?.timestamp ? new Date(metrics.timestamp).toLocaleTimeString() : '-'}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-xl border border-white/20 bg-white/[0.08] hover:bg-white/[0.15] text-white transition-all cursor-pointer font-sans text-xs font-semibold"
          >
            {language === 'zh' ? '关闭' : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
};

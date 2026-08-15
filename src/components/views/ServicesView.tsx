import React from 'react';
import { useApp } from '../../context/AppContext';
import { Cpu, RefreshCw, CheckCircle2, ShieldCheck, Activity, Terminal } from 'lucide-react';

export const ServicesView: React.FC = () => {
  const { services, restartService, language, themeMode } = useApp();

  const getServiceStatusBadge = (status: string) => {
    if (status === 'RUNNING') {
      return themeMode === 'light'
        ? 'bg-emerald-50 text-emerald-700 border border-emerald-300 font-semibold'
        : 'bg-emerald-950 text-emerald-300 border border-emerald-500/40';
    }
    return themeMode === 'light'
      ? 'bg-amber-50 text-amber-800 border border-amber-300 font-semibold'
      : 'bg-amber-950 text-amber-300 border border-amber-500/40';
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">
              {language === 'zh' ? '系统核心服务与守护进程' : 'System Core Services & Daemons'}
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Systemd units / Postfix, Dovecot, Rspamd, ClamAV, OpenDKIM
            </p>
          </div>
        </div>

        <span className="px-3.5 py-1 rounded-full bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 text-xs font-mono font-bold flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          6/6 SERVICES HEALTHY
        </span>
      </div>

      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {services.map((srv) => (
          <div
            key={srv.id}
            className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800/90 hover:border-cyan-500/40 backdrop-blur-md space-y-4 transition-all"
          >
            <div className="flex items-start justify-between">
              <div>
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>{srv.name}</span>
                </h4>
                <div className="text-xs text-slate-400 mt-0.5">{srv.type}</div>
              </div>

              <span
                className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                  srv.status === 'ACTIVE'
                    ? (themeMode === 'light' ? 'bg-emerald-50 text-emerald-700 border border-emerald-300 font-semibold' : 'bg-emerald-950 text-emerald-300 border border-emerald-500/40')
                    : (themeMode === 'light' ? 'bg-amber-50 text-amber-800 border border-amber-300 font-semibold' : 'bg-amber-950 text-amber-300 border border-amber-500/40')
                }`}
              >
                {srv.status}
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              {srv.description}
            </p>

            <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-1.5 text-xs font-mono">
              <div className="flex justify-between text-slate-400">
                <span>PID / 进程号:</span>
                <span className="text-white">{srv.pid}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>内存占用:</span>
                <span className="text-cyan-300">{srv.memoryMb} MB</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>监听端口:</span>
                <span className="text-slate-200">{srv.ports.join(', ')}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>运行时间:</span>
                <span className="text-slate-300">{srv.uptime}</span>
              </div>
            </div>

            <button
              onClick={() => restartService(srv.id)}
              disabled={srv.status === 'RESTARTING'}
              className="w-full py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-cyan-300 flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${srv.status === 'RESTARTING' ? 'animate-spin' : ''}`} />
              <span>{srv.status === 'RESTARTING' ? (language === 'zh' ? '正在重启...' : 'Restarting...') : (language === 'zh' ? '重启该守护进程' : 'Restart Daemon')}</span>
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

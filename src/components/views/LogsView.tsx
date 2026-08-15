import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import {
  Search,
  Download,
  Maximize2,
  Minimize2,
  Play,
  Pause,
  Trash2,
  Terminal,
  Filter,
  ChevronDown,
  RefreshCw
} from 'lucide-react';

export const LogsView: React.FC = () => {
  const {
    logs,
    clearLogs,
    isLiveLogStreaming,
    setIsLiveLogStreaming,
    logRate,
    logBufferSize,
    totalLogLines,
    language,
    themeMode,
    showToast
  } = useApp();

  const [selectedService, setSelectedService] = useState<string>('all');
  const [selectedLevel, setSelectedLevel] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);
  const [showLevelMenu, setShowLevelMenu] = useState<boolean>(false);

  const filteredLogs = logs.filter((log) => {
    if (selectedService !== 'all' && !log.service.includes(selectedService)) {
      return false;
    }
    if (selectedLevel !== 'all' && log.level !== selectedLevel) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        log.details.toLowerCase().includes(q) ||
        log.service.toLowerCase().includes(q) ||
        (log.clientIp && log.clientIp.includes(q))
      );
    }
    return true;
  });

  const handleExportLogs = () => {
    const content = filteredLogs.map(l => `[${l.timestamp}] [${l.service}] [${l.level}] [${l.processId}] ${l.details}`).join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mailstack-syslog-${Date.now()}.log`;
    a.click();
    showToast('success', language === 'zh' ? '日志已导出' : 'Logs Exported', `${filteredLogs.length} ${language === 'zh' ? '条日志已下载' : 'entries downloaded'}`);
  };

  return (
    <div className={`p-6 space-y-4 max-w-7xl mx-auto flex flex-col ${
      isFullscreen
        ? `fixed inset-0 z-50 p-6 ${themeMode === 'light' ? 'bg-slate-50' : 'bg-slate-950'}`
        : 'min-h-[calc(100vh-80px)]'
    }`}>
      {/* Top Filter Bar (Matching Image 3) */}
      <div className={`flex flex-wrap items-center justify-between gap-3 p-4 rounded-2xl border backdrop-blur-md ${
        themeMode === 'light'
          ? 'bg-white/90 border-slate-200/90 shadow-sm'
          : 'bg-slate-900/80 border-slate-800'
      }`}>
        {/* Left: Service Pill Filters */}
        <div className="flex flex-wrap items-center gap-1.5">
          {[
            { id: 'all', labelZh: '全部服务', labelEn: 'All Services' },
            { id: 'postfix', labelZh: 'Postfix', labelEn: 'Postfix' },
            { id: 'dovecot', labelZh: 'Dovecot', labelEn: 'Dovecot' },
            { id: 'rspamd', labelZh: 'Rspamd', labelEn: 'Rspamd' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setSelectedService(item.id)}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all ${
                selectedService === item.id
                  ? themeMode === 'light'
                    ? 'bg-cyan-50 text-cyan-800 border border-cyan-300 font-bold shadow-sm'
                    : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_10px_rgba(0,242,195,0.15)] font-semibold'
                  : themeMode === 'light'
                  ? 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-transparent'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 border border-transparent'
              }`}
            >
              {language === 'zh' ? item.labelZh : item.labelEn}
            </button>
          ))}
        </div>

        {/* Center: Log Level Dropdown & Live Search */}
        <div className="flex items-center gap-2.5 flex-1 max-w-md">
          {/* Level Dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowLevelMenu(!showLevelMenu)}
              className={`h-9 px-3 rounded-xl border text-xs flex items-center gap-1.5 font-mono ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-700 hover:border-slate-300 shadow-sm'
                  : 'bg-slate-950/80 border-slate-800 text-slate-300 hover:border-slate-700'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${themeMode === 'light' ? 'bg-cyan-600' : 'bg-cyan-400'}`} />
              <span>{selectedLevel === 'all' ? (language === 'zh' ? '日志级别' : 'Log Level') : selectedLevel}</span>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            </button>

            {showLevelMenu && (
              <div className={`absolute left-0 mt-1 w-32 border rounded-xl shadow-xl py-1 z-30 font-mono text-xs ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 shadow-lg'
                  : 'bg-slate-900 border-slate-800'
              }`}>
                {['all', 'INFO', 'SUCC', 'ERR', 'WARN'].map((lvl) => (
                  <button
                    key={lvl}
                    onClick={() => {
                      setSelectedLevel(lvl);
                      setShowLevelMenu(false);
                    }}
                    className={`w-full px-3 py-1.5 text-left flex items-center justify-between transition-colors ${
                      themeMode === 'light'
                        ? selectedLevel === lvl ? 'text-cyan-700 font-bold bg-cyan-50' : 'text-slate-700 hover:bg-slate-50'
                        : selectedLevel === lvl ? 'text-cyan-400 font-bold bg-slate-800' : 'text-slate-300 hover:bg-slate-800'
                    }`}
                  >
                    <span>{lvl.toUpperCase()}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={language === 'zh' ? '搜索日志内容, IP, 邮件地址...' : 'Search logs, IP, recipient...'}
              className={`w-full h-9 pl-9 pr-3 rounded-xl border text-xs transition-all font-mono focus:outline-none ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-900 placeholder-slate-400 focus:border-cyan-500 shadow-sm'
                  : 'bg-slate-950/80 border-slate-800 text-slate-200 placeholder-slate-500 focus:border-cyan-400'
              }`}
            />
          </div>
        </div>

        {/* Right Actions: Live Monitor, Download, Fullscreen, Clear */}
        <div className="flex items-center gap-2">
          {/* Live Streaming Toggle */}
          <button
            onClick={() => setIsLiveLogStreaming(!isLiveLogStreaming)}
            className={`h-9 px-3.5 rounded-xl border text-xs font-semibold flex items-center gap-2 transition-all ${
              isLiveLogStreaming
                ? themeMode === 'light'
                  ? 'bg-cyan-50 border-cyan-300 text-cyan-800 shadow-sm'
                  : 'bg-cyan-950/80 border-cyan-500/40 text-cyan-300 shadow-[0_0_10px_rgba(0,242,195,0.1)]'
                : themeMode === 'light'
                ? 'bg-white border-slate-200 text-slate-600 hover:text-slate-900 shadow-sm'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {isLiveLogStreaming ? (
              <>
                <span className={`w-2 h-2 rounded-full ${themeMode === 'light' ? 'bg-cyan-600' : 'bg-cyan-400'} animate-ping`} />
                <span>{language === 'zh' ? '正在监控' : 'Streaming'}</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-slate-400" />
                <span>{language === 'zh' ? '已暂停' : 'Paused'}</span>
              </>
            )}
          </button>

          {/* Download Logs */}
          <button
            onClick={handleExportLogs}
            title={language === 'zh' ? '下载日志' : 'Download Log'}
            className={`w-9 h-9 flex items-center justify-center rounded-xl border transition-colors ${
              themeMode === 'light'
                ? 'bg-white border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 shadow-sm'
                : 'bg-slate-950/80 border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            <Download className="w-4 h-4" />
          </button>

          {/* Fullscreen Toggle */}
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
            className={`w-9 h-9 flex items-center justify-center rounded-xl border transition-colors ${
              themeMode === 'light'
                ? 'bg-white border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 shadow-sm'
                : 'bg-slate-950/80 border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>

          {/* Clear Buffer */}
          <button
            onClick={clearLogs}
            title={language === 'zh' ? '清空控制台' : 'Clear Logs'}
            className={`w-9 h-9 flex items-center justify-center rounded-xl border transition-colors ${
              themeMode === 'light'
                ? 'bg-white border-slate-200 text-slate-500 hover:text-rose-600 hover:bg-rose-50 hover:border-rose-300 shadow-sm'
                : 'bg-slate-950/80 border-slate-800 hover:border-rose-500/40 text-slate-400 hover:text-rose-400'
            }`}
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Real-time Syslog Table Terminal (Matching Image 3) */}
      <div className={`flex-1 rounded-2xl border overflow-hidden flex flex-col ${
        themeMode === 'light'
          ? 'bg-white/95 border-slate-200/90 shadow-[0_8px_30px_rgba(0,0,0,0.06)]'
          : 'bg-[#060a14] border-slate-800/90 shadow-2xl'
      }`}>
        {/* Table Header */}
        <div className={`px-5 py-3 border-b grid grid-cols-12 gap-3 text-[11px] font-mono uppercase tracking-wider select-none ${
          themeMode === 'light'
            ? 'bg-slate-50 border-slate-200 text-slate-600 font-semibold'
            : 'bg-slate-950/90 border-slate-800/80 text-slate-400'
        }`}>
          <div className="col-span-2">{language === 'zh' ? '时间戳 (UTC+8)' : 'Timestamp (UTC+8)'}</div>
          <div className="col-span-2">{language === 'zh' ? '服务模块' : 'Service'}</div>
          <div className="col-span-1">{language === 'zh' ? '级别' : 'Level'}</div>
          <div className="col-span-1">{language === 'zh' ? '进程 ID' : 'PID'}</div>
          <div className="col-span-6">{language === 'zh' ? '日志详情' : 'Log Details'}</div>
        </div>

        {/* Table Body */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1 font-mono text-xs max-h-[560px]">
          {filteredLogs.length === 0 ? (
            <div className="py-20 text-center text-slate-400 space-y-2">
              <Terminal className="w-8 h-8 mx-auto text-slate-400 opacity-60" />
              <div>{language === 'zh' ? '无匹配的系统日志' : 'No matching log entries'}</div>
            </div>
          ) : (
            filteredLogs.map((log) => {
              const levelBadge = {
                INFO: themeMode === 'light'
                  ? 'bg-slate-100 border-slate-300 text-slate-700 font-semibold'
                  : 'bg-slate-900 border-slate-700 text-slate-300',
                SUCC: themeMode === 'light'
                  ? 'bg-emerald-50 border-emerald-300 text-emerald-700 font-bold'
                  : 'bg-cyan-950/80 border-cyan-500/50 text-cyan-300 font-bold',
                ERR: themeMode === 'light'
                  ? 'bg-rose-50 border-rose-300 text-rose-700 font-bold'
                  : 'bg-rose-950/90 border-rose-500/60 text-rose-300 font-bold',
                WARN: themeMode === 'light'
                  ? 'bg-amber-50 border-amber-300 text-amber-800 font-bold'
                  : 'bg-amber-950/80 border-amber-500/50 text-amber-300 font-bold',
              }[log.level] || (themeMode === 'light' ? 'bg-slate-100 text-slate-700' : 'bg-slate-800 text-slate-300');

              return (
                <div
                  key={log.id}
                  className={`px-3 py-2 rounded-xl transition-colors grid grid-cols-12 gap-3 items-center border ${
                    themeMode === 'light'
                      ? 'border-transparent hover:bg-slate-50 hover:border-slate-200 text-slate-800'
                      : 'border-transparent hover:bg-slate-900/60 hover:border-slate-800/80 text-slate-200'
                  } group`}
                >
                  {/* Timestamp */}
                  <div className={`col-span-2 text-[11px] truncate ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                    {log.timestamp}
                  </div>

                  {/* Service Module */}
                  <div className={`col-span-2 font-medium truncate ${themeMode === 'light' ? 'text-sky-700 font-semibold' : 'text-cyan-400/90'}`}>
                    {log.service}
                  </div>

                  {/* Level Badge */}
                  <div className="col-span-1">
                    <span className={`px-2 py-0.5 rounded text-[10px] border ${levelBadge}`}>
                      {log.level}
                    </span>
                  </div>

                  {/* Process ID */}
                  <div className={`col-span-1 text-[11px] ${themeMode === 'light' ? 'text-slate-400' : 'text-slate-500'}`}>
                    [{log.processId}]
                  </div>

                  {/* Details */}
                  <div className={`col-span-6 text-[11.5px] leading-relaxed break-all ${themeMode === 'light' ? 'text-slate-800 font-medium' : 'text-slate-200'}`}>
                    {log.details}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Bottom Status Bar (Matching Image 3) */}
        <div className={`px-5 py-2.5 border-t flex flex-wrap items-center justify-between text-[11px] font-mono select-none ${
          themeMode === 'light'
            ? 'bg-slate-50 border-slate-200 text-slate-600'
            : 'bg-slate-950 border-slate-800/80 text-slate-400'
        }`}>
          <div className="flex items-center gap-4">
            <span className={`flex items-center gap-1.5 font-semibold ${themeMode === 'light' ? 'text-cyan-700' : 'text-cyan-400'}`}>
              <span className={`w-2 h-2 rounded-full ${themeMode === 'light' ? 'bg-cyan-600' : 'bg-cyan-400 shadow-[0_0_6px_#00f2c3]'}`} />
              SYSLOG CONNECTED
            </span>
            <span className={themeMode === 'light' ? 'text-slate-300' : 'text-slate-600'}>|</span>
            <span>RATE: {logRate} MSG/SEC</span>
          </div>

          <div className="flex items-center gap-4">
            <span>BUFFER: {logBufferSize}</span>
            <span className={themeMode === 'light' ? 'text-slate-300' : 'text-slate-600'}>|</span>
            <span>LINES: {totalLogLines.toLocaleString()}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

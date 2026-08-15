import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import {
  Send,
  Mail,
  KeyRound,
  Inbox,
  AlertTriangle,
  ExternalLink,
  Cpu,
  ShieldCheck,
  CheckCircle2,
  Activity,
  RefreshCw,
  Sparkles,
  Compass,
  Bot,
  ArrowRight,
  Zap,
  Globe
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { LiquidGlass } from '../common/LiquidGlass';

export const DashboardView: React.FC = () => {
  const {
    setCurrentSection,
    language,
    services,
    anomalies,
    showToast,
    queues,
    themeMode,
    hasCompletedOnboarding,
    setIsOnboardingModalOpen
  } = useApp();
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(100);
  const [latencyTimeframe, setLatencyTimeframe] = useState<'1H' | '24H' | '7D'>('24H');
  const isLight = themeMode === 'light';

  const handleRunScan = () => {
    setIsScanning(true);
    setScanProgress(10);
    const interval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsScanning(false);
          confetti({ particleCount: 35, spread: 60, origin: { y: 0.7 } });
          showToast(
            'success',
            language === 'zh' ? '全局诊断已完成' : 'Diagnostics Passed',
            language === 'zh' ? '所有 6 项核心服务与 DNS 记录均处于健康运行状态' : 'All 6 services & DNS records are healthy'
          );
          return 100;
        }
        return prev + 20;
      });
    }, 250);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Onboarding Welcome / Deployment Quick-Status Bar */}
      <LiquidGlass
        variant="panel"
        glowColor={hasCompletedOnboarding ? 'cyan' : 'amber'}
        className="p-5 space-y-3"
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div
              className={`w-11 h-11 rounded-2xl flex items-center justify-center font-bold shrink-0 transition-transform ${
                hasCompletedOnboarding
                  ? 'bg-gradient-to-tr from-cyan-400 to-blue-500 text-slate-950 shadow-[0_0_15px_rgba(0,242,195,0.3)]'
                  : 'bg-gradient-to-tr from-amber-400 to-orange-500 text-slate-950 shadow-[0_0_15px_rgba(251,191,36,0.3)] animate-pulse'
              }`}
            >
              {hasCompletedOnboarding ? <ShieldCheck className="w-5 h-5" /> : <Compass className="w-5 h-5" />}
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">
                  {hasCompletedOnboarding
                    ? (language === 'zh' ? '邮件基础设施已处于最佳企业就绪态' : 'Email Infrastructure Operational')
                    : (language === 'zh' ? '欢迎使用 MailStack • 推荐完成首次邮件服务初始化' : 'Welcome to MailStack • Complete Setup Guide')}
                </h2>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                    hasCompletedOnboarding
                      ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                      : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                  }`}
                >
                  {hasCompletedOnboarding ? '100% READY' : 'ONBOARDING'}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {hasCompletedOnboarding
                  ? (language === 'zh'
                      ? '所有权威 DNS 解析、2048-bit DKIM 签名与出站中继通道均已通过校验。'
                      : 'Authoritative DNS, 2048-bit DKIM, and SMTP relays are synchronized.')
                  : (language === 'zh'
                      ? '引导您配置主域名、解析矩阵 (MX/SPF/DKIM/DMARC)、出站中继与 25 端口绕行，获取首封测试信。'
                      : 'Configure domain identity, DNS matrix, outbound relay, and perform live ping delivery.')}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <button
              onClick={() => setCurrentSection('setup_guide')}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-sm ${
                hasCompletedOnboarding
                  ? 'border border-white/10 bg-white/[0.04] hover:bg-white/[0.08] text-slate-200'
                  : 'bg-gradient-to-r from-amber-400 to-orange-500 hover:from-amber-300 hover:to-orange-400 text-slate-950 shadow-[0_0_15px_rgba(251,191,36,0.25)]'
              }`}
            >
              <Compass className="w-4 h-4" />
              <span>
                {hasCompletedOnboarding
                  ? (language === 'zh' ? '添加配置引导' : 'Add Config Wizard')
                  : (language === 'zh' ? '初次配置引导向导' : 'Launch Setup Wizard')}
              </span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>

            <button
              onClick={() => setCurrentSection('ai_suite')}
              className="px-3.5 py-2 rounded-xl border border-cyan-400/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{language === 'zh' ? 'AI 智能中心' : 'AI Suite'}</span>
            </button>
          </div>
        </div>
      </LiquidGlass>

      {/* Top 4 Metric Cards powered by LiquidGlass */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: SMTP Inbound/Outbound */}
        <LiquidGlass
          variant="card"
          glowColor="cyan"
          className="group cursor-pointer"
          onClick={() => setCurrentSection('smtp_relay')}
        >
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <div className={`flex items-center gap-2 text-xs font-semibold ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
              <span className="text-cyan-500 dark:text-cyan-400">&gt;</span>
              <span>{language === 'zh' ? 'SMTP 入站/出站' : 'SMTP In/Outbound'}</span>
            </div>
            <Send className="w-4 h-4 text-cyan-500 dark:text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>

          <div className="flex items-baseline justify-between">
            <div className={`text-3xl font-black tracking-tight font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              99.99<span className="text-xl font-normal text-cyan-500 dark:text-cyan-400">%</span>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-mono">{language === 'zh' ? '并发连接' : 'Connections'}</div>
              <div className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 font-mono">1,420</div>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400">{language === 'zh' ? '可用性状态' : 'Availability'}</span>
            <span className="text-cyan-600 dark:text-cyan-400 font-mono flex items-center gap-1 font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 dark:bg-cyan-400 animate-pulse" />
              {language === 'zh' ? '12 项处理中' : '12 pending'}
            </span>
          </div>

          {/* Progress bar */}
          <div className="w-full bg-slate-200 dark:bg-white/10 h-1.5 rounded-full mt-2.5 overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-500 to-sky-400 h-full w-[99.9%]" />
          </div>
        </LiquidGlass>

        {/* Card 2: IMAP / POP3 */}
        <LiquidGlass
          variant="card"
          glowColor="sky"
          className="group cursor-pointer"
          onClick={() => setCurrentSection('services')}
        >
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <div className={`flex items-center gap-2 text-xs font-semibold ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
              <span className="text-sky-500 dark:text-sky-400">📥</span>
              <span>IMAP / POP3</span>
            </div>
            <Mail className="w-4 h-4 text-sky-500 dark:text-sky-400 group-hover:scale-110 transition-transform" />
          </div>

          <div className="flex items-baseline justify-between">
            <div className={`text-3xl font-black tracking-tight font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              100.0<span className="text-xl font-normal text-sky-500 dark:text-sky-400">%</span>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-mono">{language === 'zh' ? '活跃会话' : 'Active Sessions'}</div>
              <div className="text-xs font-semibold text-sky-600 dark:text-sky-400 font-mono">842</div>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400">{language === 'zh' ? '服务可用性' : 'Service Uptime'}</span>
            <span className="text-emerald-600 dark:text-emerald-400 font-mono font-medium">Optimal</span>
          </div>

          <div className="w-full bg-slate-200 dark:bg-white/10 h-1.5 rounded-full mt-2.5 overflow-hidden">
            <div className="bg-gradient-to-r from-sky-500 to-emerald-400 h-full w-[100%]" />
          </div>
        </LiquidGlass>

        {/* Card 3: DNS & DKIM */}
        <LiquidGlass
          variant="card"
          glowColor="amber"
          className="group cursor-pointer"
          onClick={() => setCurrentSection('dkim_dns')}
        >
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <div className={`flex items-center gap-2 text-xs font-semibold ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
              <span className="text-amber-500 dark:text-amber-400">🔑</span>
              <span>{language === 'zh' ? 'DNS 解析与 DKIM' : 'DNS & DKIM'}</span>
            </div>
            <KeyRound className="w-4 h-4 text-amber-500 dark:text-amber-400 group-hover:scale-110 transition-transform" />
          </div>

          <div className="flex items-baseline justify-between">
            <div className={`text-2xl font-bold tracking-tight font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              42<span className="text-sm font-normal text-slate-500 dark:text-slate-400">ms</span>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-mono">{language === 'zh' ? '平均耗时' : 'Avg Time'}</div>
              <div className={`text-xs font-semibold font-mono ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>145ms Max</div>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400">{language === 'zh' ? '状态检测' : 'Status'}</span>
            <span className="text-cyan-600 dark:text-cyan-400 font-mono font-medium">{language === 'zh' ? '解析正常' : 'Optimal'}</span>
          </div>

          <div className="w-full bg-slate-200 dark:bg-white/10 h-1.5 rounded-full mt-2.5 overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-400 to-blue-500 h-full w-[94%]" />
          </div>
        </LiquidGlass>

        {/* Card 4: Mail Queue */}
        <LiquidGlass
          variant="card"
          glowColor="cyan"
          className="group cursor-pointer"
          onClick={() => setCurrentSection('mail_queue')}
        >
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <div className={`flex items-center gap-2 text-xs font-semibold ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
              <span className="text-rose-500 dark:text-rose-400">📨</span>
              <span>{language === 'zh' ? '投递队列' : 'Mail Queue'}</span>
            </div>
            <Inbox className="w-4 h-4 text-rose-500 dark:text-rose-400 group-hover:scale-110 transition-transform" />
          </div>

          <div className="flex items-baseline justify-between">
            <div className={`text-3xl font-black tracking-tight font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {queues.length}
              <span className="text-sm font-normal text-slate-500 dark:text-slate-400 ml-1">
                {language === 'zh' ? '封' : 'msgs'}
              </span>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-mono">{language === 'zh' ? '积压邮件' : 'Backlog'}</div>
              <div className="text-xs font-semibold text-amber-600 dark:text-amber-400 font-mono">
                {queues.filter(q => q.status === 'deferred').length} {language === 'zh' ? '延迟' : 'deferred'}
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400">{language === 'zh' ? '处理速率' : 'Process Rate'}</span>
            <span className="text-emerald-600 dark:text-emerald-400 font-mono font-medium">120 msg/sec</span>
          </div>

          <div className="w-full bg-slate-200 dark:bg-white/10 h-1.5 rounded-full mt-2.5 overflow-hidden">
            <div className="bg-gradient-to-r from-amber-400 to-rose-400 h-full w-[25%]" />
          </div>
        </LiquidGlass>
      </div>

      {/* Middle Grid: Latency Chart & Recent Anomalies */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Global Delivery Latency Chart */}
        <LiquidGlass variant="card" className="lg:col-span-2 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className={`text-sm font-bold tracking-wide flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                <Activity className="w-4 h-4 text-cyan-500 dark:text-cyan-400" />
                <span>{language === 'zh' ? '全局投递延迟表现' : 'Global Delivery Latency Performance'}</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {language === 'zh' ? '入站与出站 SMTP 会话延迟趋势监控 (毫秒)' : 'Inbound & Outbound SMTP session latency trend (ms)'}
              </p>
            </div>

            {/* Timeframe & Legend */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3 text-xs">
                <div className="flex items-center gap-1.5 text-cyan-600 dark:text-cyan-400 font-medium">
                  <span className="w-2 h-2 rounded-full bg-cyan-500 dark:bg-cyan-400" />
                  <span>{language === 'zh' ? '入站 (ms)' : 'Inbound (ms)'}</span>
                </div>
                <div className="flex items-center gap-1.5 text-sky-600 dark:text-sky-400 font-medium">
                  <span className="w-2 h-2 rounded-full bg-sky-500 dark:bg-sky-400" />
                  <span>{language === 'zh' ? '出站 (ms)' : 'Outbound (ms)'}</span>
                </div>
              </div>

              <div className="flex bg-slate-100 dark:bg-white/[0.06] p-0.5 rounded-lg border border-slate-200 dark:border-white/10 text-xs">
                {(['1H', '24H', '7D'] as const).map((tf) => (
                  <button
                    key={tf}
                    onClick={() => setLatencyTimeframe(tf)}
                    className={`px-2 py-0.5 rounded-md font-mono transition-all cursor-pointer ${
                      latencyTimeframe === tf
                        ? 'bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 font-bold border border-cyan-400/30'
                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    {tf}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Interactive SVG Trend Chart */}
          <div className="h-56 w-full pt-4 relative">
            <svg className="w-full h-full overflow-visible" viewBox="0 0 700 180" preserveAspectRatio="none">
              <defs>
                <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00f2c3" stopOpacity={isLight ? 0.35 : 0.25} />
                  <stop offset="100%" stopColor="#00f2c3" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="skyGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity={isLight ? 0.3 : 0.2} />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              {[0, 45, 90, 135, 180].map((y) => (
                <line
                  key={y}
                  x1="0"
                  y1={y}
                  x2="700"
                  y2={y}
                  stroke={isLight ? 'rgba(203, 213, 225, 0.6)' : 'rgba(255, 255, 255, 0.08)'}
                  strokeDasharray="4 4"
                />
              ))}

              {/* Area & Line for Inbound (Cyan) */}
              <polygon
                fill="url(#cyanGrad)"
                points="0,180 0,110 70,95 140,120 210,85 280,105 350,60 420,75 490,45 560,70 630,55 700,65 700,180"
              />
              <polyline
                fill="none"
                stroke={isLight ? '#0284c7' : '#00f2c3'}
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                points="0,110 70,95 140,120 210,85 280,105 350,60 420,75 490,45 560,70 630,55 700,65"
              />

              {/* Area & Line for Outbound (Sky Blue) */}
              <polygon
                fill="url(#skyGrad)"
                points="0,180 0,140 70,130 140,145 210,115 280,125 350,90 420,105 490,80 560,95 630,85 700,90 700,180"
              />
              <polyline
                fill="none"
                stroke={isLight ? '#2563eb' : '#38bdf8'}
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                points="0,140 70,130 140,145 210,115 280,125 350,90 420,105 490,80 560,95 630,85 700,90"
              />

              {/* Key Data Point Dots */}
              <circle cx="350" cy="60" r="4" fill={isLight ? '#0284c7' : '#00f2c3'} stroke={isLight ? '#ffffff' : '#080d1a'} strokeWidth="2" />
              <circle cx="490" cy="45" r="4" fill={isLight ? '#0284c7' : '#00f2c3'} stroke={isLight ? '#ffffff' : '#080d1a'} strokeWidth="2" />
              <circle cx="700" cy="65" r="4" fill={isLight ? '#0284c7' : '#00f2c3'} stroke={isLight ? '#ffffff' : '#080d1a'} strokeWidth="2" />
            </svg>

            {/* X-axis labels */}
            <div className="flex justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400 mt-2">
              <span>00:00</span>
              <span>04:00</span>
              <span>08:00</span>
              <span>12:00</span>
              <span>16:00</span>
              <span>20:00</span>
              <span>现在 (Now)</span>
            </div>
          </div>
        </LiquidGlass>

        {/* Right 1 Col: Recent Anomalies */}
        <LiquidGlass variant="card" className="flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className={`text-sm font-bold tracking-wide flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                <AlertTriangle className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                <span>{language === 'zh' ? '近期异常摘要' : 'Recent Anomalies'}</span>
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-400/30 font-bold">
                {anomalies.length} 条待复核
              </span>
            </div>

            {/* Anomalies List with Unified Dark Colors */}
            <div className="space-y-2.5">
              {anomalies.map((anom) => (
                <div
                  key={anom.id}
                  className={`p-3 rounded-xl border transition-all text-xs ${
                    isLight
                      ? 'bg-slate-50/90 border-slate-200 hover:border-sky-400/50'
                      : 'bg-white/[0.04] border-white/10 hover:border-cyan-400/50'
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                    <span className="font-semibold text-cyan-600 dark:text-cyan-400">{anom.type}</span>
                    <span className="text-slate-400">{anom.timestamp}</span>
                  </div>
                  <p className={`text-[11px] leading-relaxed ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
                    {anom.message}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Button to Open Logs Console */}
          <LiquidGlass
            variant="button"
            onClick={() => setCurrentSection('logs')}
            className="w-full py-2.5 px-4 text-xs font-semibold flex items-center justify-center gap-2"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '打开完整日志控制台' : 'Open Full Log Console'}</span>
          </LiquidGlass>
        </LiquidGlass>
      </div>

      {/* Bottom Grid: Service Diagnostics & Core Records */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Service Diagnostics (Left 2 cols) */}
        <LiquidGlass variant="card" className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className={`text-sm font-bold tracking-wide flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
              <Cpu className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span>Service Diagnostics ({language === 'zh' ? '服务诊断' : 'Daemons'})</span>
            </h3>

            {/* Run Full Scan Button */}
            <LiquidGlass
              variant="button"
              onClick={handleRunScan}
              className="px-3.5 py-1.5 text-xs font-semibold flex items-center gap-2"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-cyan-500 dark:text-cyan-400' : ''}`} />
              <span>{isScanning ? (language === 'zh' ? `扫描中 ${scanProgress}%` : `Scanning ${scanProgress}%`) : 'Run Full Scan'}</span>
            </LiquidGlass>
          </div>

          {/* Diagnostic Service Items with Unified Dark Theme */}
          <div className="space-y-3">
            {services.slice(0, 3).map((srv) => (
              <div
                key={srv.id}
                className={`p-3.5 rounded-xl border flex items-center justify-between transition-all ${
                  isLight
                    ? 'bg-slate-50/90 border-slate-200 hover:border-sky-400/40'
                    : 'bg-white/[0.04] border-white/10 hover:border-cyan-400/40'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg border flex items-center justify-center ${
                    isLight ? 'bg-white border-slate-200 text-sky-600' : 'bg-white/[0.05] border-white/10 text-cyan-400'
                  }`}>
                    <Mail className="w-4 h-4" />
                  </div>
                  <div>
                    <div className={`text-xs font-semibold flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                      <span>{srv.name}</span>
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 mt-0.5">
                      pid: {srv.pid} • up {srv.uptime}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-6 text-xs font-mono">
                  <div className="text-right hidden sm:block">
                    <div className={`${isLight ? 'text-slate-700' : 'text-slate-300'} font-medium`}>Mem: {srv.memoryMb}MB</div>
                    <div className="text-slate-500 dark:text-slate-400 text-[10px]">CPU: {srv.cpuPercent}%</div>
                  </div>

                  <span className="px-2.5 py-1 rounded-md text-[11px] font-bold border bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400">
                    ACTIVE
                  </span>
                </div>
              </div>
            ))}
          </div>
        </LiquidGlass>

        {/* Core Records (Right 1 col) */}
        <LiquidGlass variant="card" className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className={`text-sm font-bold tracking-wide flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
              <ShieldCheck className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span>Core Records ({language === 'zh' ? '核心记录' : 'DNS State'})</span>
            </h3>
            <span className="text-xs font-mono text-emerald-600 dark:text-emerald-400 font-semibold">4/4 OK</span>
          </div>

          <div className="space-y-3">
            {[
              { code: '{ }', name: 'MX Record', status: 'OK' },
              { code: '📜', name: 'SPF Policy', status: 'OK' },
              { code: '🔑', name: 'DKIM Keys', status: 'OK' },
              { code: '@', name: 'DMARC', status: 'OK' },
            ].map((rec, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-xl border flex items-center justify-between transition-all ${
                  isLight
                    ? 'bg-slate-50/90 border-slate-200 hover:border-sky-400/40'
                    : 'bg-white/[0.04] border-white/10 hover:border-cyan-400/40'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className={`w-6 h-6 rounded-lg border flex items-center justify-center text-xs font-mono ${
                    isLight ? 'bg-white border-slate-200 text-slate-700' : 'bg-white/[0.05] border-white/10 text-slate-200'
                  }`}>
                    {rec.code}
                  </span>
                  <span className={`text-xs font-medium ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>{rec.name}</span>
                </div>
                <span className="text-xs font-bold font-mono flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {rec.status}
                </span>
              </div>
            ))}
          </div>
        </LiquidGlass>
      </div>
    </div>
  );
};

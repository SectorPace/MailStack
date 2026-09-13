import React, { useState, useMemo } from 'react';
import { useApp } from '../../context/AppContext';
import { api } from '../../api';
import { getErrorMessage } from '../../utils/errors';
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
  ArrowRight,
  Zap,
  Globe,
  Server,
  Layers,
  XCircle,
  Check,
  Stethoscope,
  Radio,
  FileCheck2,
  X,
  ChevronDown,
  ChevronUp,
  Copy
} from '@/lib/icons';
import confetti from 'canvas-confetti';
import { LiquidGlass } from '../common/LiquidGlass';
import { SystemTelemetryChart } from '../telemetry/SystemTelemetryChart';
import { SystemTelemetryModal } from '../modals/SystemTelemetryModal';

export const DashboardView: React.FC = () => {
  const {
    setCurrentSection,
    language,
    services,
    domains,
    users,
    aliases,
    queues,
    anomalies,
    showToast,
    themeMode,
    hasCompletedOnboarding,
    settings,
    restartService
  } = useApp();
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(100);
  const [latencyTimeframe, setLatencyTimeframe] = useState<'1H' | '24H' | '7D'>('24H');
  const [doctorModalOpen, setDoctorModalOpen] = useState(false);
  const [doctorLoading, setDoctorLoading] = useState(false);
  const [doctorData, setDoctorData] = useState<any | null>(null);
  const [loopbackModalOpen, setLoopbackModalOpen] = useState(false);
  const [loopbackRecipient, setLoopbackRecipient] = useState('');
  const [loopbackLoading, setLoopbackLoading] = useState(false);
  const [loopbackResult, setLoopbackResult] = useState<any | null>(null);
  const [telemetryModalOpen, setTelemetryModalOpen] = useState(false);
  const [expandedRecordCode, setExpandedRecordCode] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const isLight = themeMode === 'light';

  const copyRecordParam = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast('success', language === 'zh' ? '已复制到剪贴板' : 'Copied to Clipboard', text);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const runDoctor = async () => {
    setDoctorLoading(true);
    setDoctorModalOpen(true);
    try {
      const res = await api('/api/system/doctor');
      setDoctorData(res);
      if (res.overall === 'HEALTHY') confetti({ particleCount: 30, spread: 50 });
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '体检执行失败' : 'Doctor Failed', getErrorMessage(e));
    } finally {
      setDoctorLoading(false);
    }
  };

  const runLoopbackTest = async () => {
    setLoopbackLoading(true);
    try {
      const res = await api('/api/mail/test-loopback', {
        method: 'POST',
        body: JSON.stringify({ recipient: loopbackRecipient || undefined }),
      });
      setLoopbackResult(res);
      showToast('success', language === 'zh' ? '邮件闭环投递成功' : 'Loopback Delivered', `耗时 ${res.deliveryTimeMs}ms`);
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '投递验证失败' : 'Loopback Failed', getErrorMessage(e));
    } finally {
      setLoopbackLoading(false);
    }
  };

  // Live service indicators
  const postfixSrv = useMemo(() => services.find(s => s.id === 'postfix' || s.name === 'postfix'), [services]);
  const dovecotSrv = useMemo(() => services.find(s => s.id === 'dovecot' || s.name === 'dovecot'), [services]);
  const opendkimSrv = useMemo(() => services.find(s => s.id === 'opendkim' || s.name === 'opendkim'), [services]);
  const activeServicesCount = useMemo(() => services.filter(s => s.status === 'ACTIVE').length, [services]);
  const totalMemoryMb = useMemo(() => services.reduce((acc, s) => acc + (s.memoryMb || 0), 0), [services]);

  const deferredCount = useMemo(() => queues.filter(q => q.status === 'deferred').length, [queues]);
  const primaryDomain = useMemo(() => domains[0], [domains]);
  const primaryDomainName = primaryDomain?.name || '';
  const primaryDkimValue = (primaryDomain?.dkimPublicKey?.trim() || '')
    .replace(/^v=DKIM1;\s*k=rsa;\s*p=/i, '')
    .replace(/\s+/g, '');

  const handleRunScan = async () => {
    setIsScanning(true);
    setScanProgress(15);
    try {
      const res = await api('/api/system/doctor');
      setScanProgress(75);
      const checks = res?.checks || [];
      setDoctorData(res);
      const failCount = checks.filter((c: any) => c.status === 'FAIL').length;
      const warnCount = checks.filter((c: any) => c.status === 'WARN').length;
      setScanProgress(100);
      if (failCount > 0) {
        showToast(
          'error',
          language === 'zh' ? '系统诊断发现异常' : 'Diagnostics Issues Detected',
          language === 'zh' ? `${failCount} 项系统检查失败，请排查` : `${failCount} check(s) failed.`
        );
      } else if (warnCount > 0) {
        showToast(
          'warning',
          language === 'zh' ? '系统诊断存在告警' : 'Diagnostics Warnings',
          language === 'zh' ? `${warnCount} 项检查提示警告` : `${warnCount} check(s) flagged warnings.`
        );
      } else {
        confetti({ particleCount: 35, spread: 60, origin: { y: 0.7 } });
        showToast(
          'success',
          language === 'zh' ? '全局实时诊断已完成' : 'Diagnostics Passed',
          language === 'zh'
            ? `${checks.length || activeServicesCount} 项系统核心指标与服务全部正常`
            : `All ${checks.length || activeServicesCount} core health metrics operating nominally`
        );
      }
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '诊断执行失败' : 'Diagnostics Failed', getErrorMessage(e));
    } finally {
      setIsScanning(false);
    }
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
                  {hasCompletedOnboarding ? '100% READY' : 'SETUP REQUIRED'}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {hasCompletedOnboarding
                  ? (language === 'zh'
                      ? `已纳管 ${domains.length} 个域名、${users.length} 个邮箱账户，核心守护进程运行正常。`
                      : `Managing ${domains.length} domain(s), ${users.length} mailbox(es). Core services healthy.`)
                  : (language === 'zh'
                      ? '引导您配置主域名、解析矩阵 (MX/SPF/DKIM/DMARC)、出站中继与 25 端口绕行，获取首封测试信。'
                      : 'Configure domain identity, DNS matrix, outbound relay, and perform live ping delivery.')}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              onClick={runDoctor}
              className="px-3.5 py-2 rounded-xl border border-cyan-400/40 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 hover:from-cyan-500/30 hover:to-blue-500/30 text-cyan-300 text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-[0_0_15px_rgba(0,242,195,0.15)]"
            >
              <Stethoscope className="w-4 h-4 text-cyan-400" />
              <span>{language === 'zh' ? '全栈体检 (Doctor)' : 'System Doctor'}</span>
            </button>

            <button
              onClick={() => { setLoopbackModalOpen(true); setLoopbackResult(null); }}
              className="px-3 py-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <Radio className="w-3.5 h-3.5 text-emerald-400" />
              <span>{language === 'zh' ? '闭环投递验证' : 'Loopback Test'}</span>
            </button>

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
                  ? (language === 'zh' ? '系统配置向导' : 'Setup Wizard')
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
        {/* Card 1: SMTP Inbound/Outbound (Postfix) */}
        <LiquidGlass
          variant="card"
          glowColor="cyan"
          className="group cursor-pointer"
          onClick={() => setCurrentSection('services')}
        >
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <div className={`flex items-center gap-2 text-xs font-semibold ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
              <span className="text-cyan-500 dark:text-cyan-400">&gt;</span>
              <span>{language === 'zh' ? 'SMTP 核心服务' : 'SMTP Service (Postfix)'}</span>
            </div>
            <Send className="w-4 h-4 text-cyan-500 dark:text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>

          <div className="flex items-baseline justify-between">
            <div className={`text-2xl font-black tracking-tight font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {postfixSrv?.status === 'ACTIVE' ? 'ACTIVE' : 'STOPPED'}
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-mono">{language === 'zh' ? '主进程 PID' : 'Main PID'}</div>
              <div className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 font-mono">
                {postfixSrv?.pid ? `#${postfixSrv.pid}` : '--'}
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400">{language === 'zh' ? '内存占用' : 'Memory'}</span>
            <span className="text-cyan-600 dark:text-cyan-400 font-mono flex items-center gap-1 font-medium">
              <span className={`w-1.5 h-1.5 rounded-full ${postfixSrv?.status === 'ACTIVE' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
              {postfixSrv?.memoryMb ? `${postfixSrv.memoryMb} MB` : '0 MB'}
            </span>
          </div>

          <div className="w-full bg-slate-200 dark:bg-white/10 h-1.5 rounded-full mt-2.5 overflow-hidden">
            <div
              className={`h-full ${postfixSrv?.status === 'ACTIVE' ? 'bg-gradient-to-r from-cyan-500 to-sky-400 w-full' : 'bg-rose-500 w-0'}`}
            />
          </div>
        </LiquidGlass>

        {/* Card 2: IMAP / POP3 (Dovecot) */}
        <LiquidGlass
          variant="card"
          glowColor="sky"
          className="group cursor-pointer"
          onClick={() => setCurrentSection('users')}
        >
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <div className={`flex items-center gap-2 text-xs font-semibold ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
              <Mail className="w-4 h-4 text-sky-500 dark:text-sky-400" />
              <span>{language === 'zh' ? '邮箱与 IMAP' : 'Mailboxes / IMAP'}</span>
            </div>
            <Mail className="w-4 h-4 text-sky-500 dark:text-sky-400 group-hover:scale-110 transition-transform" />
          </div>

          <div className="flex items-baseline justify-between">
            <div className={`text-3xl font-black tracking-tight font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {users.length}
              <span className="text-sm font-normal text-slate-500 dark:text-slate-400 ml-1">
                {language === 'zh' ? '个账户' : 'accts'}
              </span>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-mono">{language === 'zh' ? 'Dovecot 状态' : 'Dovecot Status'}</div>
              <div className="text-xs font-semibold text-sky-600 dark:text-sky-400 font-mono">
                {dovecotSrv?.status === 'ACTIVE' ? 'RUNNING' : 'STOPPED'}
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400">{language === 'zh' ? '虚拟别名' : 'Aliases'}</span>
            <span className="text-emerald-600 dark:text-emerald-400 font-mono font-medium">
              {aliases.length} {language === 'zh' ? '条映射' : 'mapped'}
            </span>
          </div>

          <div className="w-full bg-slate-200 dark:bg-white/10 h-1.5 rounded-full mt-2.5 overflow-hidden">
            <div
              className={`h-full ${dovecotSrv?.status === 'ACTIVE' ? 'bg-gradient-to-r from-sky-500 to-emerald-400 w-full' : 'bg-rose-500 w-0'}`}
            />
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
              <KeyRound className="w-4 h-4 text-amber-500 dark:text-amber-400" />
              <span>{language === 'zh' ? '域名与 DKIM 签名' : 'Domains & DKIM'}</span>
            </div>
            <KeyRound className="w-4 h-4 text-amber-500 dark:text-amber-400 group-hover:scale-110 transition-transform" />
          </div>

          <div className="flex items-baseline justify-between">
            <div className={`text-3xl font-black tracking-tight font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {domains.length}
              <span className="text-sm font-normal text-slate-500 dark:text-slate-400 ml-1">
                {language === 'zh' ? '个域名' : 'doms'}
              </span>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-mono">{language === 'zh' ? 'DKIM 引擎' : 'DKIM Engine'}</div>
              <div className={`text-xs font-semibold font-mono ${opendkimSrv?.status === 'ACTIVE' ? 'text-emerald-500' : 'text-slate-400'}`}>
                {opendkimSrv?.status === 'ACTIVE' ? '2048-bit RSA' : 'INACTIVE'}
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400">{language === 'zh' ? '主要选择器' : 'Selector'}</span>
            <span className="text-cyan-600 dark:text-cyan-400 font-mono font-medium">mail._domainkey</span>
          </div>

          <div className="w-full bg-slate-200 dark:bg-white/10 h-1.5 rounded-full mt-2.5 overflow-hidden">
            <div className="bg-gradient-to-r from-amber-400 to-cyan-400 h-full w-full" />
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
              <Inbox className="w-4 h-4 text-rose-500 dark:text-rose-400" />
              <span>{language === 'zh' ? 'Postfix 投递队列' : 'Mail Queue'}</span>
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
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-mono">{language === 'zh' ? '延迟积压' : 'Deferred'}</div>
              <div className="text-xs font-semibold text-amber-600 dark:text-amber-400 font-mono">
                {deferredCount} {language === 'zh' ? '封' : 'delayed'}
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400">{language === 'zh' ? '队列状态' : 'Spool State'}</span>
            <span className="text-emerald-600 dark:text-emerald-400 font-mono font-medium">
              {queues.length === 0 ? (language === 'zh' ? '清空 (Nominal)' : 'Clean') : (language === 'zh' ? '处理中' : 'Processing')}
            </span>
          </div>

          <div className="w-full bg-slate-200 dark:bg-white/10 h-1.5 rounded-full mt-2.5 overflow-hidden">
            <div
              className={`h-full ${queues.length > 0 ? 'bg-amber-400 w-3/4' : 'bg-emerald-400 w-full'}`}
            />
          </div>
        </LiquidGlass>
      </div>

      {/* Middle Grid: Dynamic Telemetry & Recent Anomalies */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Real-time System Telemetry Chart with 1m/5m/30m/1h/6h/24h/3d selector */}
        <LiquidGlass variant="card" className="lg:col-span-2">
          <SystemTelemetryChart
            language={language}
            isLight={isLight}
            onOpenInspector={() => setTelemetryModalOpen(true)}
          />
        </LiquidGlass>

        {/* Right 1 Col: Recent Anomalies & Security Events */}
        <LiquidGlass variant="card" className="flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className={`text-sm font-bold tracking-wide flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                <AlertTriangle className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                <span>{language === 'zh' ? '安全事件与审计' : 'Security & Audits'}</span>
              </h3>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${
                anomalies.length > 0
                  ? 'bg-amber-500/10 text-amber-400 border-amber-400/30'
                  : 'bg-emerald-500/10 text-emerald-400 border-emerald-400/30'
              }`}>
                {anomalies.length > 0 ? `${anomalies.length} 条待复核` : '全项安全'}
              </span>
            </div>

            {/* Anomalies List */}
            <div className="space-y-2.5">
              {anomalies.length === 0 ? (
                <div className={`p-4 rounded-xl border text-center text-xs ${
                  isLight ? 'bg-slate-50 border-slate-200 text-slate-600' : 'bg-white/[0.03] border-white/10 text-slate-400'
                }`}>
                  <ShieldCheck className="w-6 h-6 mx-auto mb-1.5 text-emerald-500" />
                  <p className="font-semibold text-emerald-600 dark:text-emerald-400">
                    {language === 'zh' ? '安全扫描未发现异常' : 'All security checks nominal'}
                  </p>
                  <p className="text-[11px] mt-1 text-slate-500">
                    {language === 'zh' ? 'Postfix 中继鉴权与 SASL 权限正常' : 'Postfix relay restrictions & SASL secure'}
                  </p>
                </div>
              ) : (
                anomalies.slice(0, 3).map((anom) => (
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
                      <span className="text-slate-400">{anom.timestamp ? anom.timestamp.substring(11, 19) : ''}</span>
                    </div>
                    <p className={`text-[11px] leading-relaxed ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
                      {anom.message}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Button to Open Logs Console */}
          <LiquidGlass
            variant="button"
            onClick={() => setCurrentSection('logs')}
            className="w-full py-2.5 px-4 text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '打开完整日志控制台' : 'Open Full Log Console'}</span>
          </LiquidGlass>
        </LiquidGlass>
      </div>

      {/* Bottom Grid: Service Diagnostics & Core Records */}
      <div className={`grid gap-6 transition-all duration-300 ${expandedRecordCode ? 'grid-cols-1' : 'grid-cols-1 lg:grid-cols-3'}`}>
        {/* Service Diagnostics (Left 2 cols when collapsed, full width when expanded) */}
        <LiquidGlass variant="card" className={`${expandedRecordCode ? 'w-full' : 'lg:col-span-2'} space-y-4`}>
          <div className="flex items-center justify-between">
            <h3 className={`text-sm font-bold tracking-wide flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
              <Cpu className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span>{language === 'zh' ? '系统核心服务状态' : 'Core System Daemons'} ({activeServicesCount}/{services.length})</span>
            </h3>

            {/* Run Full Scan Button */}
            <LiquidGlass
              variant="button"
              onClick={handleRunScan}
              className="px-3.5 py-1.5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-cyan-500 dark:text-cyan-400' : ''}`} />
              <span>{isScanning ? (language === 'zh' ? `诊断中 ${scanProgress}%` : `Scanning ${scanProgress}%`) : (language === 'zh' ? '重新诊断' : 'Run Diagnostics')}</span>
            </LiquidGlass>
          </div>

          {/* Diagnostic Service Items */}
          <div className="space-y-3">
            {services.slice(0, 4).map((srv) => (
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
                    {srv.id === 'postfix' ? <Send className="w-4 h-4" /> : srv.id === 'dovecot' ? <Mail className="w-4 h-4" /> : srv.id === 'opendkim' ? <KeyRound className="w-4 h-4" /> : <Server className="w-4 h-4" />}
                  </div>
                  <div>
                    <div className={`text-xs font-semibold flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                      <span>{srv.name}</span>
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 mt-0.5">
                      pid: {srv.pid || 'none'} • {srv.uptime ? `up ${srv.uptime.substring(0, 19)}` : 'stopped'}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono">
                  <div className="text-right hidden sm:block">
                    <div className={`${isLight ? 'text-slate-700' : 'text-slate-300'} font-medium`}>Mem: {srv.memoryMb}MB</div>
                  </div>

                  <span className={`px-2.5 py-1 rounded-md text-[11px] font-bold border ${
                    srv.status === 'ACTIVE'
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
                      : 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-400'
                  }`}>
                    {srv.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </LiquidGlass>

        {/* Core Records & Primary Domain (Right 1 col, expands smoothly when opened) */}
        <LiquidGlass variant="card" className={`space-y-4 transition-all duration-300 ${expandedRecordCode ? 'w-full ring-1 ring-cyan-500/30' : ''}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <h3 className={`text-sm font-bold tracking-wide ${isLight ? 'text-slate-900' : 'text-white'}`}>
                {language === 'zh' ? '主域名解析记录状态' : 'Domain DNS Records'}
              </h3>
              {expandedRecordCode && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse">
                  {language === 'zh' ? '详情展开中' : 'Expanded'}
                </span>
              )}
            </div>
            <span className="text-xs font-mono text-cyan-600 dark:text-cyan-400 font-semibold">
              {primaryDomainName ? `@${primaryDomainName}` : (language === 'zh' ? '尚未配置域名' : 'No domain configured')}
            </span>
          </div>

          <div className="space-y-3">
            {[
              {
                code: 'MX',
                name: language === 'zh' ? 'MX 邮件交换路由' : 'MX Record',
                status: primaryDomain ? primaryDomain.mxStatus || 'pending' : 'pending',
                type: 'MX',
                host: '@',
                value: primaryDomainName ? `mail.${primaryDomainName}` : '',
                priority: 10,
                ttl: '3600 (Auto)',
                desc: language === 'zh' ? '将所有发送到本域名的邮件流量正确路由至本台 MailStack 服务器。' : 'Directs inbound email traffic to your MailStack server.'
              },
              {
                code: 'SPF',
                name: language === 'zh' ? 'SPF 发件人身份防伪' : 'SPF Policy',
                status: primaryDomain ? primaryDomain.spfStatus || 'pending' : 'pending',
                type: 'TXT',
                host: '@',
                value: primaryDomainName ? (settings?.relay === 'ses' ? 'v=spf1 mx include:amazonses.com ~all' : settings?.relay === 'sendgrid' ? 'v=spf1 mx include:sendgrid.net ~all' : 'v=spf1 mx ~all') : '',
                priority: null,
                ttl: '3600 (Auto)',
                desc: language === 'zh' ? '声明只有本服务器 IP 与指定中继有权代表该域名发信，杜绝被冒充。' : 'Declares authorized sender IPs to prevent email spoofing.'
              },
              {
                code: 'DKIM',
                name: language === 'zh' ? 'DKIM 2048位签名' : 'DKIM Key',
                status: primaryDomain ? primaryDomain.dkimStatus || 'pending' : 'pending',
                type: 'TXT',
                host: `${primaryDomain?.dkimSelector || 'mail'}._domainkey`,
                value: primaryDkimValue ? `v=DKIM1; k=rsa; p=${primaryDkimValue}` : '',
                priority: null,
                ttl: '3600 (Auto)',
                desc: language === 'zh' ? 'OpenDKIM 2048 位密码学签名公钥，接收方验签确保邮件内容未被中间人篡改。' : '2048-bit RSA public key for cryptographic email authenticity verification.'
              },
              {
                code: 'DMARC',
                name: language === 'zh' ? 'DMARC 安全对齐' : 'DMARC Policy',
                status: primaryDomain ? primaryDomain.dmarcStatus || 'pending' : 'pending',
                type: 'TXT',
                host: '_dmarc',
                value: primaryDomainName ? `v=DMARC1; p=none; sp=none; rua=mailto:postmaster@${primaryDomainName}` : '',
                priority: null,
                ttl: '3600 (Auto)',
                desc: language === 'zh' ? '指示各邮件厂商如何处置验签失败邮件，并将投递与仿冒告警发送至管理员。' : 'Defines email authentication policy and aggregates failure telemetry reports.'
              },
            ].map((rec) => {
              const isExpanded = expandedRecordCode === rec.code;
              return (
                <div
                  key={rec.code}
                  className={`rounded-xl border transition-all duration-200 overflow-hidden ${
                    isExpanded
                      ? isLight ? 'bg-cyan-50/70 border-cyan-400/60 shadow-md' : 'bg-slate-900/90 border-cyan-500/50 shadow-lg'
                      : isLight ? 'bg-slate-50/90 border-slate-200 hover:border-sky-400/40' : 'bg-white/[0.04] border-white/10 hover:border-cyan-400/40'
                  }`}
                >
                  {/* Top Bar Header */}
                  <div className="p-3 flex items-center justify-between gap-2">
                    <div className="flex items-center gap-3">
                      <span className={`w-8 h-6 rounded-md border flex items-center justify-center text-[10px] font-mono font-bold ${
                        rec.code === 'MX' ? 'bg-blue-500/10 text-blue-400 border-blue-500/30' :
                        rec.code === 'SPF' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                        rec.code === 'DKIM' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                        'bg-purple-500/10 text-purple-400 border-purple-500/30'
                      }`}>
                        {rec.code}
                      </span>
                      <div>
                        <div className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
                          {rec.name}
                        </div>
                        <div className="text-[10px] font-mono text-slate-500">
                          {rec.host}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2.5">
                      <span className={`text-xs font-bold font-mono flex items-center gap-1 ${
                        rec.status === 'ok'
                          ? 'text-emerald-500'
                          : 'text-amber-500'
                      }`}>
                        {rec.status === 'ok' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                        <span className="hidden sm:inline">{rec.status.toUpperCase()}</span>
                      </span>

                      {/* Right Collapsible Accordion Toggle Button */}
                      <button
                        onClick={() => setExpandedRecordCode(isExpanded ? null : rec.code)}
                        className={`px-2.5 py-1 rounded-lg border text-xs font-mono font-bold flex items-center gap-1 transition-all cursor-pointer ${
                          isExpanded
                            ? 'bg-cyan-400 text-slate-950 border-cyan-400 shadow-sm'
                            : isLight
                              ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300'
                              : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
                        }`}
                        title={isExpanded ? (language === 'zh' ? '收起详情' : 'Collapse') : (language === 'zh' ? '展开参数' : 'View Parameters')}
                      >
                        <span>{isExpanded ? (language === 'zh' ? '收起' : 'Hide') : (language === 'zh' ? '参数' : 'Details')}</span>
                        {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>

                  {/* Expandable Parameter Details Box */}
                  {isExpanded && (
                    <div className={`p-4 border-t space-y-3 font-mono text-xs ${
                      isLight ? 'bg-white/80 border-cyan-200' : 'bg-slate-950/60 border-cyan-900/40'
                    }`}>
                      <p className="text-[11px] font-sans text-slate-400 leading-relaxed">
                        {rec.desc}
                      </p>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        <div className={`p-2.5 rounded-lg border ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/70 border-slate-800'}`}>
                          <div className="text-[10px] uppercase font-bold text-slate-400 mb-1">{language === 'zh' ? '记录类型' : 'Type'}</div>
                          <div className="font-bold text-cyan-400">{rec.type}</div>
                        </div>

                        <div className={`p-2.5 rounded-lg border ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/70 border-slate-800'}`}>
                          <div className="flex items-center justify-between text-[10px] uppercase font-bold text-slate-400 mb-1">
                            <span>{language === 'zh' ? '主机记录 (Host)' : 'Host Name'}</span>
                            <button
                              onClick={() => copyRecordParam(rec.host, `${rec.code}-host`)}
                              className="text-cyan-400 hover:text-cyan-300 cursor-pointer"
                              title="复制主机名"
                            >
                              {copiedKey === `${rec.code}-host` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                          <div className="font-semibold break-all text-slate-200">{rec.host}</div>
                        </div>

                        <div className={`p-2.5 rounded-lg border ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/70 border-slate-800'}`}>
                          <div className="text-[10px] uppercase font-bold text-slate-400 mb-1">{language === 'zh' ? '优先级 / TTL' : 'Priority / TTL'}</div>
                          <div className="text-slate-200">
                            {rec.priority !== null ? `Priority: ${rec.priority} • ` : ''}TTL: {rec.ttl}
                          </div>
                        </div>
                      </div>

                      <div className={`p-3 rounded-lg border ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/70 border-slate-800'}`}>
                        <div className="flex items-center justify-between text-[10px] uppercase font-bold text-slate-400 mb-1.5">
                          <span>{language === 'zh' ? '实时记录值 (Value / Content)' : 'Record Content'}</span>
                          <button
                            onClick={() => copyRecordParam(rec.value, `${rec.code}-val`)}
                            className="px-2 py-0.5 rounded bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-[11px] flex items-center gap-1 cursor-pointer transition-colors"
                          >
                            {copiedKey === `${rec.code}-val` ? <Check className="w-3 h-3 text-emerald-950" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedKey === `${rec.code}-val` ? (language === 'zh' ? '已复制' : 'Copied') : (language === 'zh' ? '复制完整值' : 'Copy Value')}</span>
                          </button>
                        </div>
                        <div className="p-2 rounded bg-slate-950 text-cyan-300 text-xs break-all select-all font-mono border border-slate-800">
                          {rec.value}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {!primaryDomain && (
            <button
              onClick={() => setCurrentSection('domains')}
              className="w-full py-2 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-400/30 text-xs font-bold transition-all cursor-pointer"
            >
              + {language === 'zh' ? '添加首个托管域名' : 'Add First Domain'}
            </button>
          )}
        </LiquidGlass>
      </div>

      {/* Doctor Health Diagnostic Modal */}
      {doctorModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 max-w-3xl w-full max-h-[90vh] overflow-y-auto space-y-5 shadow-2xl font-sans">
            <div className="flex items-center justify-between border-b pb-4 border-slate-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/20 text-cyan-400 flex items-center justify-center">
                  <Stethoscope className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-base text-white">
                    {language === 'zh' ? 'MailStack 全栈系统体检报告 (System Doctor)' : 'MailStack System Doctor'}
                  </h3>
                  <p className="text-xs text-slate-400">
                    {language === 'zh' ? '覆盖 OS、守护进程、端口、队列、DNS 矩阵与安全权限' : 'Deep inspection across daemons, ports, queue, DNS & security'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setDoctorModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {doctorLoading ? (
              <div className="py-12 flex flex-col items-center justify-center space-y-3">
                <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
                <p className="text-xs text-slate-400">{language === 'zh' ? '正在执行深度全栈体检...' : 'Running comprehensive diagnostic checks...'}</p>
              </div>
            ) : doctorData ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 rounded-xl bg-slate-950/70 border border-slate-800">
                  <div className="text-xs space-y-1">
                    <div className="text-slate-400">{language === 'zh' ? '实时诊断' : 'Live diagnostics'}: <span className="text-slate-200 font-mono">{doctorData.checks?.length || 0} checks</span></div>
                    <div className="text-slate-400">{language === 'zh' ? '结果由服务器当前状态生成' : 'Generated from current server state'}</div>
                  </div>
                  <div className={`px-3 py-1.5 rounded-xl font-mono text-xs font-bold border ${
                    doctorData.overall === 'HEALTHY'
                      ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                      : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                  }`}>
                    STATUS: {doctorData.overall}
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">{language === 'zh' ? '体检项清单' : 'Inspection Checks'}</h4>
                  <div className="divide-y divide-slate-800/60 rounded-xl border border-slate-800 bg-slate-950/50 overflow-hidden">
                    {(doctorData.checks || []).map((c: any, i: number) => (
                      <div key={i} className="p-3 flex items-start justify-between gap-4 text-xs hover:bg-slate-900/50">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-slate-200">{c.name}</span>
                            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">{c.category}</span>
                          </div>
                          <p className="text-slate-400 font-mono text-[11px]">{c.message || c.detail}</p>
                          {(c.fixSuggestion || c.suggestion) && (
                            <p className="text-amber-400/90 text-[11px]">{c.fixSuggestion || c.suggestion}</p>
                          )}
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                          c.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-300' :
                          c.status === 'WARN' ? 'bg-amber-500/20 text-amber-300' :
                          'bg-red-500/20 text-red-300'
                        }`}>
                          {c.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    onClick={runDoctor}
                    className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>{language === 'zh' ? '重新体检' : 'Re-run Doctor'}</span>
                  </button>
                  <button
                    onClick={() => setDoctorModalOpen(false)}
                    className="px-4 py-2 rounded-xl text-xs font-bold bg-cyan-400 hover:bg-cyan-300 text-slate-950"
                  >
                    {language === 'zh' ? '关闭' : 'Close'}
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* Loopback Mail Test Modal */}
      {loopbackModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 max-w-lg w-full space-y-4 shadow-2xl font-sans">
            <div className="flex items-center justify-between border-b pb-4 border-slate-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
                  <Radio className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-base text-white">
                    {language === 'zh' ? '邮件闭环投递验证 (Loopback Test)' : 'Mail Delivery Loopback Test'}
                  </h3>
                  <p className="text-xs text-slate-400">
                    {language === 'zh' ? '实时注入测试邮件并校验从 Postfix 到 Maildir 投递' : 'Inject test token & verify roundtrip to Maildir'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setLoopbackModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block mb-1.5 font-medium text-slate-300">
                  {language === 'zh' ? '测试收件邮箱地址 (留空则自动选择第一个有效邮箱)' : 'Test Recipient Address (Optional)'}
                </label>
                <input
                  type="email"
                  placeholder="admin@yourdomain.com"
                  value={loopbackRecipient}
                  onChange={(e) => setLoopbackRecipient(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl border bg-slate-950 border-slate-800 text-white font-mono text-xs focus:border-emerald-400 focus:outline-none"
                />
              </div>

              {loopbackResult && (
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>{language === 'zh' ? '闭环投递成功！' : 'Loopback Delivery Succeeded!'}</span>
                  </div>
                  <div className="font-mono text-[11px] text-slate-300 space-y-1">
                    <div>Recipient: {loopbackResult.recipient}</div>
                    <div>Delivery Latency: {loopbackResult.deliveryTimeMs}ms</div>
                    <div>UUID Token: {loopbackResult.token}</div>
                    <div>Maildir: {loopbackResult.maildir}</div>
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 pt-2 border-t border-slate-800">
              <button
                onClick={() => setLoopbackModalOpen(false)}
                className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white"
              >
                {language === 'zh' ? '取消' : 'Cancel'}
              </button>
              <button
                disabled={loopbackLoading}
                onClick={runLoopbackTest}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center gap-2 shadow-lg"
              >
                <Radio className={loopbackLoading ? "animate-spin w-3.5 h-3.5" : "w-3.5 h-3.5"} />
                <span>{loopbackLoading ? (language === 'zh' ? '正在投递与校验...' : 'Testing...') : (language === 'zh' ? '开始闭环投递测试' : 'Start Loopback Test')}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Deep System Telemetry Inspector Modal */}
      <SystemTelemetryModal
        isOpen={telemetryModalOpen}
        onClose={() => setTelemetryModalOpen(false)}
        language={language}
        isLight={isLight}
        onRestartService={restartService}
      />
    </div>
  );
};


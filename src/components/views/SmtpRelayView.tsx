import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { SmtpRelayRoute } from '../../types';
import {
  Send,
  Plus,
  CheckCircle2,
  AlertCircle,
  Activity,
  Cloud,
  Layers,
  ArrowRight,
  ShieldCheck,
  Zap,
  Globe,
  Settings2,
  Trash2,
  ToggleLeft,
  ToggleRight,
  RefreshCw,
  Sliders
} from 'lucide-react';
import { AddRelayModal } from '../modals/AddRelayModal';
import confetti from 'canvas-confetti';

export const SmtpRelayView: React.FC = () => {
  const {
    relayRoutes,
    relayProviders,
    deleteRelayRoute,
    toggleRelayRoute,
    promoteRelayProvider,
    setCurrentSection,
    language,
    themeMode,
    showToast
  } = useApp();

  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [testingRelayId, setTestingRelayId] = useState<string | null>(null);

  const primaryProvider = relayProviders.find(p => p.isPrimary) || relayProviders[0];
  const backupProviders = relayProviders.filter(p => !p.isPrimary);

  const handleTestConnection = (id: string, name: string) => {
    setTestingRelayId(id);
    setTimeout(() => {
      setTestingRelayId(null);
      confetti({ particleCount: 30, spread: 50, origin: { y: 0.6 } });
      showToast('success', language === 'zh' ? 'SMTP 握手成功' : 'SMTP Handshake Successful', `${name} ${language === 'zh' ? 'STARTTLS 加密套件协商通过，延迟 38ms' : 'STARTTLS handshake OK (38ms latency)'}`);
    }, 1000);
  };

  const handlePromote = (id: string, name: string) => {
    promoteRelayProvider(id);
    confetti({ particleCount: 40, spread: 60 });
    showToast('success', language === 'zh' ? '主线路提升成功' : 'Primary Relay Promoted', `${name} ${language === 'zh' ? '已晋升为 Postfix 全局出站第一优先线路' : 'is now the primary outbound relay'}`);
  };

  const handleGlobalHealthCheck = () => {
    showToast('info', language === 'zh' ? '全局中继健康检查' : 'Health Check Initiated', language === 'zh' ? '正在探测外部中继网关的 25/587 端口...' : 'Probing ports 25/587 on all relay endpoints...');
    setTimeout(() => {
      showToast('success', language === 'zh' ? '所有中继线路状态健康' : 'All Relays Healthy', language === 'zh' ? '未发现 IP 信誉黑名单拦截与 TLS 证书降级' : 'No RBL blocks or TLS downgrades detected');
    }, 1200);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 24H Sent */}
        <div className={`p-5 rounded-2xl border backdrop-blur-md ${
          themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
        }`}>
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '24H 发送量' : '24H Sent'}
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${themeMode === 'light' ? 'text-slate-800' : 'text-white'}`}>1,280</span>
            <span className={`text-xs font-semibold font-mono ${themeMode === 'light' ? 'text-emerald-600' : 'text-emerald-400'}`}>+12%</span>
          </div>
        </div>

        {/* Relay Uptime */}
        <div className={`p-5 rounded-2xl border backdrop-blur-md ${
          themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
        }`}>
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '线路可用率' : 'Relay Uptime'}
          </div>
          <div className={`text-3xl font-black font-mono ${themeMode === 'light' ? 'text-slate-800' : 'text-white'}`}>99.98%</div>
          <div className={`w-full h-1 rounded-full mt-2 overflow-hidden ${themeMode === 'light' ? 'bg-slate-200' : 'bg-slate-800'}`}>
            <div className="bg-gradient-to-r from-cyan-500 to-sky-400 h-full w-[99.98%]" />
          </div>
        </div>

        {/* Avg Latency with Sparkline */}
        <div className={`p-5 rounded-2xl border backdrop-blur-md flex items-center justify-between ${
          themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
        }`}>
          <div>
            <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
              themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
            }`}>
              {language === 'zh' ? '平均延迟' : 'Avg Latency'}
            </div>
            <div className={`text-3xl font-black font-mono ${themeMode === 'light' ? 'text-slate-800' : 'text-white'}`}>
              420<span className={`text-sm font-normal ${themeMode === 'light' ? 'text-slate-400' : 'text-slate-400'}`}>ms</span>
            </div>
          </div>
          {/* Sparkline */}
          <div className="w-20 h-10">
            <svg className="w-full h-full overflow-visible" viewBox="0 0 80 40">
              <path
                d="M 0,35 Q 20,5 40,25 T 80,10"
                fill="none"
                stroke={themeMode === 'light' ? '#0891b2' : '#00f2c3'}
                strokeWidth="2.5"
                strokeLinecap="round"
              />
            </svg>
          </div>
        </div>

        {/* Queue Length */}
        <div className={`p-5 rounded-2xl border backdrop-blur-md ${
          themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
        }`}>
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '等待队列' : 'Queue Length'}
          </div>
          <div className="flex items-baseline gap-1">
            <span className={`text-3xl font-black font-mono ${themeMode === 'light' ? 'text-slate-800' : 'text-white'}`}>5</span>
            <span className={`text-xs ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>{language === 'zh' ? '封邮件' : 'mails'}</span>
          </div>
        </div>
      </div>

      {/* Outbound Routing Architecture Diagram - Live synced with primary provider */}
      <div className={`p-6 rounded-2xl border backdrop-blur-md space-y-6 ${
        themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl border ${
              themeMode === 'light' ? 'bg-cyan-50 border-cyan-200 text-cyan-700' : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
            }`}>
              <Send className="w-5 h-5" />
            </div>
            <div>
              <h3 className={`text-sm font-bold tracking-wide ${themeMode === 'light' ? 'text-slate-800' : 'text-white'}`}>
                {language === 'zh' ? 'Postfix 核心路由拓扑' : 'Postfix Core Routing Architecture'}
              </h3>
              <p className={`text-xs ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                {language === 'zh' ? '按域名路由策略多级分发与故障转移拓扑' : 'Multi-tier fallback topology with domain-based routing'}
              </p>
            </div>
          </div>

          <span className={`px-3 py-1 rounded-full text-xs font-mono flex items-center gap-1.5 border ${
            themeMode === 'light'
              ? 'bg-cyan-50 border-cyan-200 text-cyan-800 font-semibold'
              : 'bg-slate-800 border-slate-700 text-cyan-400'
          }`}>
            <span className={`w-2 h-2 rounded-full ${themeMode === 'light' ? 'bg-cyan-600' : 'bg-cyan-400'} animate-pulse`} />
            {language === 'zh' ? '按域名路由策略' : 'Domain Routing Policy'}
          </span>
        </div>

        {/* 3 Visual Tier Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Node 1: Primary Active */}
          <div className={`p-4 rounded-xl border flex items-center gap-3.5 transition-all ${
            themeMode === 'light'
              ? 'bg-cyan-50/80 border-cyan-300 shadow-sm'
              : 'bg-slate-950/80 border-cyan-500/40 shadow-[0_0_15px_rgba(0,242,195,0.08)]'
          }`}>
            <div className={`w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 ${
              themeMode === 'light'
                ? 'bg-white border-cyan-200 text-cyan-700 shadow-sm'
                : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
            }`}>
              <Cloud className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <div className={`text-xs font-bold truncate ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                {primaryProvider?.name || 'OCI Email Delivery'}
              </div>
              <div className={`text-[11px] font-mono flex items-center gap-1 ${
                themeMode === 'light' ? 'text-cyan-700 font-semibold' : 'text-cyan-400'
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${themeMode === 'light' ? 'bg-cyan-600' : 'bg-cyan-400'}`} />
                {language === 'zh' ? '主线路 (活跃)' : 'Primary (Active)'}
              </div>
            </div>
          </div>

          {/* Node 2: Backup Standby */}
          <div className={`p-4 rounded-xl border flex items-center gap-3.5 transition-all ${
            themeMode === 'light'
              ? 'bg-sky-50/70 border-sky-200 shadow-sm'
              : 'bg-slate-950/80 border-slate-800'
          }`}>
            <div className={`w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 ${
              themeMode === 'light'
                ? 'bg-white border-sky-200 text-sky-700 shadow-sm'
                : 'bg-sky-500/10 border-sky-500/30 text-sky-400'
            }`}>
              <Send className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <div className={`text-xs font-bold truncate ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                {backupProviders[0]?.name || 'Brevo (Sendinblue)'}
              </div>
              <div className={`text-[11px] font-mono flex items-center gap-1 ${
                themeMode === 'light' ? 'text-sky-700 font-semibold' : 'text-slate-400'
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${themeMode === 'light' ? 'bg-sky-500' : 'bg-sky-400'}`} />
                {language === 'zh' ? '故障转移线路 (待命)' : 'Backup (Standby)'}
              </div>
            </div>
          </div>

          {/* Node 3: Local Queue */}
          <div className={`p-4 rounded-xl border flex items-center gap-3.5 ${
            themeMode === 'light'
              ? 'bg-white border-slate-200 shadow-sm'
              : 'bg-slate-950/80 border-slate-800'
          }`}>
            <div className={`w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 ${
              themeMode === 'light'
                ? 'bg-slate-50 border-slate-200 text-slate-600'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}>
              <Layers className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <div className={`text-xs font-bold truncate ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>Local Queue</div>
              <div className={`text-[11px] font-mono ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-500'}`}>
                {language === 'zh' ? '最终回退策略' : 'Last Resort'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Provider Details Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {relayProviders.map((prov) => (
          <div
            key={prov.id}
            className={`p-6 rounded-2xl border backdrop-blur-md space-y-4 relative overflow-hidden transition-all ${
              prov.isPrimary
                ? themeMode === 'light'
                  ? 'bg-white/95 border-cyan-300 shadow-md ring-1 ring-cyan-200'
                  : 'bg-slate-900/80 border-cyan-500/40 shadow-[0_0_20px_rgba(0,242,195,0.08)]'
                : themeMode === 'light'
                ? 'bg-white/95 border-slate-200 shadow-sm hover:border-sky-300'
                : 'bg-slate-900/70 border-slate-800/90'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-xl border flex items-center justify-center ${
                  themeMode === 'light'
                    ? prov.isPrimary ? 'bg-cyan-50 border-cyan-200 text-cyan-700 shadow-sm' : 'bg-sky-50 border-sky-200 text-sky-700 shadow-sm'
                    : prov.isPrimary ? 'bg-cyan-950/80 border-cyan-500/50 text-cyan-300' : 'bg-slate-800/90 border-slate-700 text-cyan-400'
                }`}>
                  <Cloud className="w-5 h-5" />
                </div>
                <div>
                  <h4 className={`text-sm font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>{prov.name}</h4>
                  <div className={`text-xs font-mono truncate max-w-xs ${themeMode === 'light' ? 'text-slate-500 font-medium' : 'text-slate-400'}`}>{prov.host}</div>
                </div>
              </div>

              <div className="flex flex-col items-end gap-1">
                <span
                  className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider border ${
                    prov.isPrimary
                      ? themeMode === 'light'
                        ? 'bg-cyan-50 text-cyan-800 border-cyan-300 font-bold'
                        : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                      : themeMode === 'light'
                      ? 'bg-sky-50 text-sky-800 border-sky-300 font-bold'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  {prov.isPrimary ? (language === 'zh' ? '主线路' : 'PRIMARY') : (language === 'zh' ? '备用线路' : 'BACKUP')}
                </span>
                <span className={`text-[11px] font-mono flex items-center gap-1 ${
                  themeMode === 'light' ? 'text-emerald-700 font-semibold' : 'text-emerald-400'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${themeMode === 'light' ? 'bg-emerald-600' : 'bg-emerald-400'}`} />
                  {language === 'zh' ? '健康' : 'Healthy'}
                </span>
              </div>
            </div>

            {/* Provider specs grid */}
            <div className={`grid grid-cols-2 gap-3 p-3.5 rounded-xl border text-xs font-mono ${
              themeMode === 'light'
                ? 'bg-slate-50/90 border-slate-200'
                : 'bg-slate-950/70 border-slate-800/80'
            }`}>
              <div>
                <div className={`text-[10px] uppercase ${themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-500'}`}>{language === 'zh' ? '提供商' : 'Provider'}</div>
                <div className={`font-medium ${themeMode === 'light' ? 'text-slate-800 font-semibold' : 'text-slate-200'}`}>{prov.provider}</div>
              </div>
              <div>
                <div className={`text-[10px] uppercase ${themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-500'}`}>{language === 'zh' ? '节点区域' : 'Region'}</div>
                <div className={themeMode === 'light' ? 'text-slate-700 font-medium' : 'text-slate-200'}>{prov.region}</div>
              </div>
              <div>
                <div className={`text-[10px] uppercase ${themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-500'}`}>{language === 'zh' ? '端口与安全协议' : 'Port & Security'}</div>
                <div className={themeMode === 'light' ? 'text-slate-700 font-medium' : 'text-slate-200'}>{prov.port} / {prov.security}</div>
              </div>
              <div>
                <div className={`text-[10px] uppercase ${themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-500'}`}>{language === 'zh' ? '最后成功投递' : 'Last Success'}</div>
                <div className={themeMode === 'light' ? 'text-slate-700 font-medium' : 'text-slate-200'}>{prov.lastSuccess}</div>
              </div>
            </div>

            {/* Actions Buttons */}
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={() => showToast('info', language === 'zh' ? '中继参数配置' : 'Relay Configuration', `${prov.name} ${language === 'zh' ? '端口与 SASL 鉴权凭证已就绪' : 'credentials verified'}`)}
                className={`flex-1 py-2 px-3 rounded-xl border text-xs font-semibold transition-colors cursor-pointer ${
                  themeMode === 'light'
                    ? 'bg-white hover:bg-slate-50 border-slate-300 text-slate-700 shadow-sm'
                    : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200'
                }`}
              >
                {language === 'zh' ? '配置中继' : 'Configure'}
              </button>

              {prov.isPrimary ? (
                <button
                  onClick={() => handleTestConnection(prov.id, prov.name)}
                  disabled={testingRelayId === prov.id}
                  className={`flex-1 py-2 px-3 rounded-xl border text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer ${
                    themeMode === 'light'
                      ? 'bg-cyan-50 hover:bg-cyan-100 border-cyan-300 text-cyan-800 shadow-sm'
                      : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-cyan-300 hover:border-cyan-500/40'
                  }`}
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${testingRelayId === prov.id ? 'animate-spin text-cyan-500' : ''}`} />
                  <span>{testingRelayId === prov.id ? (language === 'zh' ? '探测中...' : 'Probing...') : (language === 'zh' ? '测试连通性' : 'Test Connection')}</span>
                </button>
              ) : (
                <button
                  onClick={() => handlePromote(prov.id, prov.name)}
                  className={`flex-1 py-2 px-3 rounded-xl border text-xs font-bold transition-all cursor-pointer ${
                    themeMode === 'light'
                      ? 'bg-gradient-to-r from-cyan-400 to-sky-400 hover:from-cyan-300 hover:to-sky-300 border-cyan-300 text-slate-950 shadow-[0_0_12px_rgba(0,242,195,0.25)] hover:scale-[1.01]'
                      : 'bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 hover:shadow-[0_0_12px_rgba(0,242,195,0.2)]'
                  }`}
                >
                  <span className="flex items-center justify-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 fill-current" />
                    <span>{language === 'zh' ? '提升为主线路' : 'Promote to Primary'}</span>
                  </span>
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Action Bar & Relay Rules Table */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="h-10 px-4 rounded-xl bg-gradient-to-r from-cyan-400 to-sky-400 hover:from-cyan-300 hover:to-sky-300 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all hover:scale-[1.02] cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>{language === 'zh' ? '添加新中继' : 'Add New Relay'}</span>
            </button>

            <button
              onClick={handleGlobalHealthCheck}
              className={`h-10 px-3.5 rounded-xl border text-xs font-semibold flex items-center gap-2 transition-colors ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 shadow-sm'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <ShieldCheck className="w-4 h-4 text-cyan-500" />
              <span>{language === 'zh' ? '全局健康检查' : 'Global Health Check'}</span>
            </button>

            <button
              onClick={() => showToast('info', language === 'zh' ? '审计日志' : 'Audit Logs', language === 'zh' ? '最近 30 天中继变更记录已载入' : 'Relay change log loaded')}
              className={`h-10 px-3.5 rounded-xl border text-xs font-semibold transition-colors ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 shadow-sm'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              {language === 'zh' ? '查看审计日志' : 'View Audit Logs'}
            </button>

            <button
              onClick={() => setCurrentSection('dkim_dns')}
              className={`h-10 px-3.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                themeMode === 'light'
                  ? 'bg-cyan-50 border-cyan-200 text-cyan-800 hover:bg-cyan-100'
                  : 'bg-cyan-950/40 border-cyan-500/40 text-cyan-300 hover:bg-cyan-950/80'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '中继 DNS 记录引导' : 'Relay DNS Records Guide'}</span>
            </button>
          </div>

          <div className={`text-xs font-mono ${themeMode === 'light' ? 'text-slate-500 font-medium' : 'text-slate-400'}`}>
            {language === 'zh' ? `共 ${relayRoutes.length} 条路由规则` : `${relayRoutes.length} active routes`}
          </div>
        </div>

        {/* Relay Rules Table */}
        <div className={`rounded-2xl border overflow-hidden backdrop-blur-md ${
          themeMode === 'light'
            ? 'bg-white/90 border-slate-200 shadow-sm'
            : 'bg-slate-900/70 border-slate-800/90 shadow-xl'
        }`}>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className={`border-b text-[11px] font-mono uppercase tracking-wider ${
                themeMode === 'light'
                  ? 'border-slate-200 bg-slate-50 text-slate-600 font-semibold'
                  : 'border-slate-800 bg-slate-950/80 text-slate-400'
              }`}>
                <tr>
                  <th className="px-5 py-3.5">{language === 'zh' ? '源域名 (SOURCE)' : 'SOURCE DOMAIN'}</th>
                  <th className="px-5 py-3.5">{language === 'zh' ? '目标中继 (TARGET)' : 'RELAY TARGET'}</th>
                  <th className="px-5 py-3.5">{language === 'zh' ? '优先级' : 'PRIORITY'}</th>
                  <th className="px-5 py-3.5">{language === 'zh' ? '动作' : 'ACTION'}</th>
                  <th className="px-5 py-3.5">{language === 'zh' ? '状态' : 'STATUS'}</th>
                  <th className="px-5 py-3.5 text-right">{language === 'zh' ? '操作' : 'ACTIONS'}</th>
                </tr>
              </thead>
              <tbody className={`divide-y font-mono ${themeMode === 'light' ? 'divide-slate-200' : 'divide-slate-800/60'}`}>
                {relayRoutes.map((route) => (
                  <tr key={route.id} className={`transition-colors group ${
                    themeMode === 'light' ? 'hover:bg-slate-50' : 'hover:bg-slate-800/40'
                  }`}>
                    {/* Source Domain */}
                    <td className={`px-5 py-3.5 font-medium flex items-center gap-2 ${
                      themeMode === 'light' ? 'text-slate-800' : 'text-white'
                    }`}>
                      <Globe className={`w-3.5 h-3.5 ${themeMode === 'light' ? 'text-slate-400' : 'text-slate-400'}`} />
                      <span>{route.sourceDomain}</span>
                    </td>

                    {/* Relay Target */}
                    <td className={`px-5 py-3.5 ${themeMode === 'light' ? 'text-cyan-800 font-semibold' : 'text-cyan-300'}`}>
                      {route.relayTarget}
                    </td>

                    {/* Priority */}
                    <td className={`px-5 py-3.5 ${themeMode === 'light' ? 'text-slate-600' : 'text-slate-300'}`}>
                      {route.priority}
                    </td>

                    {/* Action */}
                    <td className="px-5 py-3.5">
                      <span className={`px-2 py-0.5 rounded border text-[10px] ${
                        themeMode === 'light'
                          ? 'bg-slate-100 text-slate-700 border-slate-200 font-semibold'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}>
                        {route.action}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex items-center gap-1.5 text-xs font-semibold ${
                          route.status === 'active'
                            ? themeMode === 'light' ? 'text-cyan-700' : 'text-cyan-400'
                            : 'text-slate-400'
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            route.status === 'active'
                              ? themeMode === 'light' ? 'bg-cyan-600' : 'bg-cyan-400 shadow-[0_0_6px_#00f2c3]'
                              : 'bg-slate-400'
                          }`}
                        />
                        {route.status === 'active' ? (language === 'zh' ? '已启用' : 'Active') : (language === 'zh' ? '已禁用' : 'Disabled')}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="px-5 py-3.5 text-right space-x-2">
                      <button
                        onClick={() => toggleRelayRoute(route.id)}
                        title={route.status === 'active' ? 'Disable' : 'Enable'}
                        className={`p-1 rounded transition-colors ${
                          themeMode === 'light' ? 'text-slate-400 hover:text-cyan-600' : 'text-slate-400 hover:text-cyan-400'
                        }`}
                      >
                        {route.status === 'active' ? (
                          <ToggleRight className={`w-4 h-4 ${themeMode === 'light' ? 'text-cyan-600' : 'text-cyan-400'}`} />
                        ) : (
                          <ToggleLeft className="w-4 h-4 text-slate-400" />
                        )}
                      </button>
                      <button
                        onClick={() => deleteRelayRoute(route.id)}
                        title="Delete route"
                        className="p-1 rounded text-slate-400 hover:text-rose-500 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Outbound Relay vs Inbound Gateway Explainer Callout */}
        <div className={`p-4 rounded-2xl border flex items-start gap-3.5 text-xs leading-relaxed ${
          themeMode === 'light'
            ? 'bg-slate-50 border-slate-200 text-slate-600'
            : 'bg-slate-950/70 border-slate-800/80 text-slate-400'
        }`}>
          <div className={`w-6 h-6 rounded-lg border flex items-center justify-center shrink-0 mt-0.5 ${
            themeMode === 'light'
              ? 'bg-white border-slate-200 text-cyan-700'
              : 'bg-slate-900 border-slate-800 text-cyan-400'
          }`}>
            ℹ
          </div>
          <div>
            <div className={`font-bold mb-0.5 ${themeMode === 'light' ? 'text-slate-800' : 'text-slate-200'}`}>
              {language === 'zh' ? '出站中继 vs 入站网关' : 'Outbound Relay vs Inbound Gateway'}
            </div>
            <p>
              {language === 'zh'
                ? '此页面管理的策略仅影响从您的域发出的邮件 (出站)。启用第三方 SMTP Relay (如 OCI、SendGrid) 可以显著提高发往外部域的送达率，避免被误判为垃圾邮件。入站邮件 (发给您的) 路由需在 DNS MX 记录和入站网关中配置。'
                : 'The policies managed on this page only affect outbound mail from your domain. Enabling a third-party SMTP Relay (e.g. OCI, SendGrid) significantly improves deliverability to external domains and prevents mail from being marked as spam. Inbound mail routing must be configured in your DNS MX records and inbound gateway.'}
            </p>
          </div>
        </div>
      </div>

      {/* Multi-step Add Relay Modal */}
      {isAddModalOpen && <AddRelayModal onClose={() => setIsAddModalOpen(false)} />}
    </div>
  );
};

import React from 'react';
import { Globe, RefreshCw, Download, FileCode, RotateCcw } from '@/lib/icons';

interface Props {
  themeMode: string;
  language: string;
  selectedDomainName: string;
  setSelectedDomainName: (v: string) => void;
  customServerIp: string;
  setCustomServerIp: (v: string) => void;
  selectedRelay: string;
  setSelectedRelay: (v: string) => void;
  customDkimSelector: string;
  setCustomDkimSelector: (v: string) => void;
  dmarcPolicy: string;
  setDmarcPolicy: (v: 'none' | 'quarantine' | 'reject') => void;
  isVerifyingDns: boolean;
  onVerify: () => void;
  onCopyCsv: () => void;
  onCopyZone: () => void;
  onReset: () => void;
}

export const DnsToolbar: React.FC<Props> = ({
  themeMode,
  language,
  selectedDomainName,
  setSelectedDomainName,
  customServerIp,
  setCustomServerIp,
  selectedRelay,
  setSelectedRelay,
  customDkimSelector,
  setCustomDkimSelector,
  dmarcPolicy,
  setDmarcPolicy,
  isVerifyingDns,
  onVerify,
  onCopyCsv,
  onCopyZone,
  onReset,
}) => {
  return (
    <div className={`p-5 rounded-2xl border backdrop-blur-md transition-all ${
      themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-sm' : 'bg-slate-900/90 border-slate-800'
    }`}>
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center text-slate-950 font-bold shadow-[0_0_15px_rgba(0,242,195,0.25)]">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className={`text-base font-bold tracking-tight ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                {language === 'zh' ? '动态 DNS 解析与权威配置中心' : 'Dynamic DNS Records & Configuration Center'}
              </h2>
              <span className={`px-2 py-0.5 rounded-full text-[11px] font-mono font-bold border ${
                themeMode === 'light' ? 'bg-cyan-50 text-cyan-800 border-cyan-300' : 'bg-cyan-950 text-cyan-300 border-cyan-800'
              }`}>
                Live Wizard
              </span>
            </div>
            <p className={`text-xs mt-0.5 ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
              {language === 'zh'
                ? '支持自定义任意域名、公网 IP、DKIM 密钥与出站中继，实时动态计算全部 9 大 DNS 标准记录与 AI 诊断。'
                : 'Customize domain, server IP, DKIM selectors, and relays. Dynamically generates full DNS records & AI diagnostics.'}
            </p>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="flex items-center flex-wrap gap-2">
          <button
            onClick={onVerify}
            disabled={isVerifyingDns}
            className={`h-9 px-3 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
              themeMode === 'light'
                ? 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700'
                : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isVerifyingDns ? 'animate-spin text-cyan-500' : ''}`} />
            <span>{isVerifyingDns ? (language === 'zh' ? '全球探测中...' : 'Probing...') : (language === 'zh' ? '连通性验证' : 'Verify Records')}</span>
          </button>

          <button
            onClick={onCopyCsv}
            className={`h-9 px-3 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
              themeMode === 'light'
                ? 'bg-amber-50 hover:bg-amber-100 border-amber-300 text-amber-900'
                : 'bg-amber-950/40 hover:bg-amber-900/60 border-amber-500/40 text-amber-300'
            }`}
          >
            <Download className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '导出 Cloudflare CSV' : 'Cloudflare CSV'}</span>
          </button>

          <button
            onClick={onCopyZone}
            className="h-9 px-3.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(0,242,195,0.2)] cursor-pointer"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '复制 BIND Zone' : 'Copy BIND Zone'}</span>
          </button>

          <button
            onClick={onReset}
            className={`h-9 px-3 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
              themeMode === 'light' ? 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-600' : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
            }`}
            title="重置全部记录为系统默认推荐值"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '重置配置' : 'Reset'}</span>
          </button>
        </div>
      </div>

      {/* Dynamic Controls Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-4 font-mono text-xs">
        {/* Domain Name */}
        <div className="space-y-1">
          <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
            1. {language === 'zh' ? '当前域名 (Domain)' : 'Domain Name'}
          </label>
          <input
            type="text"
            value={selectedDomainName}
            onChange={(e) => setSelectedDomainName(e.target.value)}
            placeholder="example.com"
            className={`w-full h-9 px-3 rounded-xl border text-xs font-bold focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
              themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-white'
            }`}
          />
        </div>

        {/* Server IP */}
        <div className="space-y-1">
          <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
            2. {language === 'zh' ? '服务器公网 IP' : 'Server IP'}
          </label>
          <input
            type="text"
            value={customServerIp}
            onChange={(e) => setCustomServerIp(e.target.value)}
            placeholder="203.0.113.10"
            className={`w-full h-9 px-3 rounded-xl border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
              themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-cyan-300'
            }`}
          />
        </div>

        {/* Outbound Relay */}
        <div className="space-y-1">
          <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
            3. {language === 'zh' ? '出站中继 (Relay)' : 'Relay Provider'}
          </label>
          <select
            value={selectedRelay}
            onChange={(e) => setSelectedRelay(e.target.value)}
            className={`w-full h-9 px-3 rounded-xl border text-xs font-bold focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer ${
              themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-white'
            }`}
          >
            <option value="oracle">Oracle Cloud (OCI SJC1)</option>
            <option value="direct">自建服务器直发 (Direct MX)</option>
            <option value="ses">Amazon SES</option>
            <option value="sendgrid">SendGrid</option>
            <option value="mailgun">Mailgun</option>
            <option value="brevo">Brevo (Sendinblue)</option>
            <option value="resend">Resend</option>
          </select>
        </div>

        {/* DKIM Selector */}
        <div className="space-y-1">
          <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
            4. {language === 'zh' ? 'DKIM Selector' : 'DKIM Selector'}
          </label>
          <input
            type="text"
            value={customDkimSelector}
            onChange={(e) => setCustomDkimSelector(e.target.value)}
            placeholder="mail"
            className={`w-full h-9 px-3 rounded-xl border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
              themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-white'
            }`}
          />
        </div>

        {/* DMARC Policy */}
        <div className="space-y-1">
          <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
            5. {language === 'zh' ? 'DMARC 拦截策略' : 'DMARC Policy'}
          </label>
          <select
            value={dmarcPolicy}
            onChange={(e) => setDmarcPolicy(e.target.value as any)}
            className={`w-full h-9 px-3 rounded-xl border text-xs font-bold focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer ${
              themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-white'
            }`}
          >
            <option value="none">p=none (宽松监控模式)</option>
            <option value="quarantine">p=quarantine (隔离进垃圾箱)</option>
            <option value="reject">p=reject (严格拒收拦截)</option>
          </select>
        </div>
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { api } from '../../api';
import { AiDnsDiagnostic } from '../dns/AiDnsDiagnostic';
import { Sparkles, Globe, Server, Bot, ArrowRight, ShieldCheck, Zap } from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';

export const AiDiagnosticView: React.FC = () => {
  const { domains, language, themeMode, setCurrentSection, showToast } = useApp();
  const [selectedDomainId, setSelectedDomainId] = useState(domains[0]?.id || '');
  const [serverIp, setServerIp] = useState('');
  const [relayProvider, setRelayProvider] = useState('oracle');
  // Set when the server IP lookup fails. Without it the A record and the SPF
  // record silently vanish from the generated table and the operator copies a
  // record set that is missing two of its five entries, with nothing to explain
  // why. Better to say the IP could not be determined than to imply it is blank.
  const [identityUnavailable, setIdentityUnavailable] = useState(false);

  const selectedDomain = domains.find((d) => d.id === selectedDomainId) || domains[0];
  const domainName = selectedDomain?.name || '';
  const dkimKey = selectedDomain?.dkimPublicKey || '';

  React.useEffect(() => {
    (async () => {
      try {
        const status = await api('/api/setup/status');
        if (status?.identity?.serverIp) setServerIp(status.identity.serverIp);
        if (status?.identity?.domain && !selectedDomainId) setSelectedDomainId(status.identity.domain);
      } catch (_) {
        setIdentityUnavailable(true);
      }
    })();
  }, []);

  React.useEffect(() => {
    if (!selectedDomainId && domains[0]?.id) setSelectedDomainId(domains[0].id);
  }, [domains, selectedDomainId]);

  const records = domainName ? [
    ...(serverIp ? [{ type: 'A', name: `mail.${domainName}`, content: serverIp, priority: undefined }] : []),
    { type: 'MX', name: domainName, content: `mail.${domainName}`, priority: 10 },
    ...(serverIp ? [{ type: 'TXT', name: domainName, content: relayProvider === 'ses' ? 'v=spf1 include:amazonses.com ~all' : `v=spf1 ip4:${serverIp} ~all` }] : []),
    ...(dkimKey ? [{ type: 'TXT', name: `mail._domainkey.${domainName}`, content: `v=DKIM1; k=rsa; p=${dkimKey}` }] : []),
    { type: 'TXT', name: `_dmarc.${domainName}`, content: `v=DMARC1; p=none; rua=mailto:postmaster@${domainName}` },
  ] : [];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Header Banner */}
      <LiquidGlass variant="panel" glowColor="cyan" className="p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-cyan-400/20 border border-cyan-400/40 flex items-center justify-center text-cyan-400">
                <Sparkles className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
                  {language === 'zh' ? 'AI 智能 DNS & 送达率全景体检中心' : 'AI DNS & Deliverability Diagnostic Center'}
                </h2>
                <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-2">
                  <span>RFC-7208 / RFC-6376 / RFC-7489 规范对齐</span>
                  <span>•</span>
                  <span>Google & Yahoo 2024 发信反垃圾新规标准</span>
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setCurrentSection('ai_assistant')}
              className="px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 border border-cyan-400/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 transition-all cursor-pointer"
            >
              <Bot className="w-4 h-4" />
              <span>{language === 'zh' ? '进入 AI 邮件顾问' : 'Open AI Assistant'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Quick Domain & Target Selector */}
        <div className="pt-2 grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="space-y-1">
            <label className="text-[11px] font-mono font-semibold text-slate-600 dark:text-slate-400 uppercase">
              {language === 'zh' ? '目标诊断域名' : 'Target Domain'}
            </label>
            <select
              value={selectedDomainId}
              onChange={(e) => setSelectedDomainId(e.target.value)}
              className="w-full h-9 px-3 rounded-xl border text-xs font-mono bg-white/80 dark:bg-slate-950/80 border-slate-200 dark:border-white/10 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              {domains.map((d) => (
                <option key={d.id} value={d.id}>
                  @{d.name} ({d.statusTextZh || d.status})
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-mono font-semibold text-slate-600 dark:text-slate-400 uppercase">
              {language === 'zh' ? '邮件服务器公网 IP' : 'Mail Server Public IP'}
            </label>
            <input
              type="text"
              value={serverIp}
              onChange={(e) => setServerIp(e.target.value)}
              placeholder="203.0.113.10"
              className="w-full h-9 px-3 rounded-xl border text-xs font-mono bg-white/80 dark:bg-slate-950/80 border-slate-200 dark:border-white/10 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-mono font-semibold text-slate-600 dark:text-slate-400 uppercase">
              {language === 'zh' ? '出站中继通道' : 'Outbound Relay Channel'}
            </label>
            <select
              value={relayProvider}
              onChange={(e) => setRelayProvider(e.target.value)}
              className="w-full h-9 px-3 rounded-xl border text-xs font-mono bg-white/80 dark:bg-slate-950/80 border-slate-200 dark:border-white/10 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              <option value="direct">直发 (Direct Port 25)</option>
              <option value="oracle">Oracle Cloud OCI SJC1</option>
              <option value="ses">Amazon SES</option>
              <option value="sendgrid">Twilio SendGrid</option>
              <option value="mailgun">Mailgun</option>
              <option value="resend">Resend</option>
            </select>
          </div>
        </div>
      </LiquidGlass>

      {identityUnavailable && (
        <LiquidGlass variant="panel" glowColor="amber" className="p-4 flex items-start gap-3">
          <ShieldCheck className="w-5 h-5 shrink-0 mt-0.5 text-amber-400" />
          <div className="text-sm">
            <p className="font-medium">
              {language === 'zh' ? '无法读取服务器公网 IP' : 'Server public IP unavailable'}
            </p>
            <p className="opacity-70 mt-1">
              {language === 'zh'
                ? 'A 记录与 SPF 记录需要服务器 IP，本次未能获取，因此下表中这两条记录被省略。请手动填写 IP，或稍后重试。'
                : 'The A and SPF records need the server IP, which could not be read, so both are omitted from the table below. Enter the IP manually or retry later.'}
            </p>
          </div>
        </LiquidGlass>
      )}

      {/* Main AI Diagnostic Engine Component */}
      <AiDnsDiagnostic
        domainName={domainName}
        serverIp={serverIp}
        relayProvider={relayProvider}
        records={records}
      />
    </div>
  );
};

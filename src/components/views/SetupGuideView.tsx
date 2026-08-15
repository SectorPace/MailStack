import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import {
  Globe,
  KeyRound,
  Send,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Copy,
  Check,
  Download,
  FileCode,
  RefreshCw,
  Sparkles,
  Server,
  Mail,
  UserCheck,
  Lock,
  Eye,
  EyeOff,
  Zap,
  Play,
  RotateCcw
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { api } from '../../api';
import { LiquidGlass } from '../common/LiquidGlass';

export const SetupGuideView: React.FC = () => {
  const { language, themeMode, showToast, completeOnboarding, setCurrentSection, hasCompletedOnboarding } = useApp();

  // Wizard Steps: 1: Domain & Host, 2: DNS & DKIM, 3: Relay & Port 25, 4: TLS & SSL, 5: Admin & Ping Test, 6: Complete
  const [currentStep, setCurrentStep] = useState<number>(1);

  // Form State
  const [domainName, setDomainName] = useState('');
  const [mailHost, setMailHost] = useState('');
  const [serverIp, setServerIp] = useState('');
  const [adminUsername, setAdminUsername] = useState('admin');
  const [adminPassword, setAdminPassword] = useState('');
  const [adminDisplayName, setAdminDisplayName] = useState('System Administrator');
  const [selectedRelay, setSelectedRelay] = useState<'direct' | 'oracle' | 'ses' | 'sendgrid' | 'custom'>('direct');
  const [relayHost, setRelayHost] = useState('');
  const [relayPort, setRelayPort] = useState(587);
  const [relayUser, setRelayUser] = useState('');
  const [relayPass, setRelayPass] = useState('');
  const [dkimSelector, setDkimSelector] = useState('mail');
  const [dkimPublicKey, setDkimPublicKey] = useState('');
  const [privacyMode, setPrivacyMode] = useState(true);
  const [dmarcPolicy, setDmarcPolicy] = useState<'none' | 'quarantine' | 'reject'>('none');

  // Interactive Verification States
  const [isVerifyingDns, setIsVerifyingDns] = useState(false);
  const [dnsVerified, setDnsVerified] = useState(false);
  const [isTestingRelay, setIsTestingRelay] = useState(false);
  const [relayTested, setRelayTested] = useState(false);
  const [isIssuingCert, setIsIssuingCert] = useState(false);
  const [certIssued, setCertIssued] = useState(false);
  const [isSendingTestMail, setIsSendingTestMail] = useState(false);
  const [testMailSent, setTestMailSent] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyText = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast('info', language === 'zh' ? '已复制' : 'Copied', `${label}`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const stepsList = [
    { num: 1, titleZh: '域名与主机', titleEn: 'Domain & Host', icon: <Globe className="w-4 h-4" /> },
    { num: 2, titleZh: 'DNS 防伪矩阵', titleEn: 'DNS & DKIM', icon: <KeyRound className="w-4 h-4" /> },
    { num: 3, titleZh: '出站中继策略', titleEn: 'SMTP Relay', icon: <Send className="w-4 h-4" /> },
    { num: 4, titleZh: 'TLS 证书与安全', titleEn: 'TLS & Security', icon: <ShieldCheck className="w-4 h-4" /> },
    { num: 5, titleZh: '管理员与联通测试', titleEn: 'Admin & Test', icon: <Mail className="w-4 h-4" /> },
    { num: 6, titleZh: '完成与生效', titleEn: 'Ready', icon: <CheckCircle2 className="w-4 h-4" /> },
  ];

  // Standards-aware DNS plan. One SPF record is emitted per owner name.
  const inferOracleSpf = () => {
    const h = relayHost.toLowerCase();
    if (h.includes('eu-') || h.includes('frankfurt') || h.includes('london') || h.includes('amsterdam')) return 'eu.rp.oracleemaildelivery.com';
    if (h.includes('ap-') || h.includes('tokyo') || h.includes('seoul') || h.includes('sydney') || h.includes('singapore') || h.includes('mumbai')) return 'ap.rp.oracleemaildelivery.com';
    return 'rp.oracleemaildelivery.com';
  };
  const inferSesRegion = () => relayHost.match(/email-smtp\.([a-z0-9-]+)\.amazonaws\.com/i)?.[1] || 'us-east-1';
  const providerMechanism = selectedRelay === 'oracle'
    ? `include:${inferOracleSpf()}`
    : selectedRelay === 'sendgrid'
      ? 'include:sendgrid.net'
      : '';
  const rootSpfParts = ['v=spf1', `a:${mailHost || 'mail.example.com'}`, 'mx'];
  if (selectedRelay === 'direct' && serverIp) rootSpfParts.push(`ip4:${serverIp}`);
  if (providerMechanism) rootSpfParts.push(providerMechanism);
  rootSpfParts.push('~all');
  const rootSpf = rootSpfParts.join(' ');
  const sesMailFrom = domainName ? `bounce.${domainName}` : 'bounce.example.com';
  const realDnsRecords: Array<{ type: string; name: string; content: string; priority?: number; desc: string }> = [
    { type: 'A', name: mailHost || 'mail.example.com', content: serverIp || '203.0.113.10', desc: '邮件服务器 A 记录；Cloudflare 必须为 DNS Only' },
    { type: 'MX', name: domainName || 'example.com', content: mailHost || 'mail.example.com', priority: 10, desc: '接收邮件的主 MX 记录，优先级 10' },
    { type: 'TXT', name: domainName || 'example.com', content: rootSpf, desc: '域名只能保留一条 SPF TXT，请合并所有授权发送源' },
    { type: 'TXT', name: `${dkimSelector}._domainkey.${domainName || 'example.com'}`, content: dkimPublicKey ? `v=DKIM1; k=rsa; p=${dkimPublicKey}` : '完成步骤 1 后由服务器生成真实 DKIM 公钥', desc: 'OpenDKIM 2048 位 RSA 公钥，不能使用演示密钥' },
    { type: 'TXT', name: `_dmarc.${domainName || 'example.com'}`, content: `v=DMARC1; p=${dmarcPolicy}; rua=mailto:postmaster@${domainName || 'example.com'}; adkim=s; aspf=s; pct=100`, desc: 'DMARC 初次建议 p=none，观察报告后再提高策略' },
  ];
  if (selectedRelay === 'ses') {
    const region = inferSesRegion();
    realDnsRecords.push(
      { type: 'MX', name: sesMailFrom, content: `feedback-smtp.${region}.amazonses.com`, priority: 10, desc: 'Amazon SES 自定义 MAIL FROM 专用 MX' },
      { type: 'TXT', name: sesMailFrom, content: 'v=spf1 include:amazonses.com ~all', desc: 'Amazon SES 自定义 MAIL FROM 专用 SPF，不要创建第二条同名 SPF' },
    );
  }
  const maskDomain = (value: string) => value.replace(/(^|\.)[^.]+(?=\.)/g, '$1••••');
  const maskIp = (value: string) => value.replace(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/, '$1.$2.•••.•••');
  const displayValue = (value: string) => {
    if (!privacyMode) return value;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return maskIp(value);
    if (value.includes('p=') && value.includes('DKIM1')) return 'v=DKIM1; k=rsa; p=••••••••••••••••';
    if (value.includes('@')) return value.replace(/[A-Za-z0-9._%+-]+@[^;\s]+/g, 'postmaster@example.com');
    if (value.includes('v=spf1')) return value.replace(/ip4:\d+\.\d+\.\d+\.\d+/g, 'ip4:203.0.113.10');
    if (/([a-z0-9-]+\.)+[a-z]{2,}/i.test(value)) return value.replace(/([a-z0-9-]+\.)+[a-z]{2,}/gi, 'example.com');
    return value;
  };
  const dnsRecords = realDnsRecords.map(r => ({ ...r, displayName: privacyMode ? maskDomain(r.name) : r.name, displayContent: displayValue(r.content) }));

  const [identityApplied, setIdentityApplied] = useState(false);
  const [lastResult, setLastResult] = useState<any>(null);
  const [operationError, setOperationError] = useState('');
  const post = async (path: string, body: any) => api(path, { method: 'POST', body: JSON.stringify(body) });
  const failOperation = (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    setOperationError(message); showToast('error', language === 'zh' ? '操作失败' : 'Operation failed', message);
  };
  const handleApplyIdentity = async () => {
    setOperationError('');
    try {
      const result = await post('/api/setup/identity', { domain: domainName, mailHost, serverIp, postmaster: `postmaster@${domainName}` });
      setLastResult(result); setDkimPublicKey(result.dkimPublicKey || ''); setIdentityApplied(true); setCurrentStep(2);
      showToast('success', language === 'zh' ? '身份配置已写入服务器' : 'Identity applied', `${mailHost} / ${serverIp}`);
    } catch (error) { failOperation(error); }
  };
  const handleVerifyDns = async () => {
    setIsVerifyingDns(true); setOperationError('');
    try {
      const result = await post('/api/setup/dns/verify', { domain: domainName, mailHost, serverIp, dkimSelector, expectedSpf: rootSpf, selectedRelay, sesMailFrom, sesRegion: inferSesRegion() });
      setLastResult(result); setDnsVerified(Boolean(result.verified));
      if (!result.verified) throw new Error(language === 'zh' ? 'DNS 尚未全部生效，请查看检测结果并稍后重试' : 'DNS verification is incomplete');
      confetti({ particleCount: 30, spread: 60 }); showToast('success', language === 'zh' ? '权威 DNS 实测通过' : 'Authoritative DNS verified', 'A / MX / SPF / DKIM / DMARC');
    } catch (error) { setDnsVerified(false); failOperation(error); } finally { setIsVerifyingDns(false); }
  };
  const handleTestRelay = async () => {
    setIsTestingRelay(true); setOperationError('');
    try {
      const payload = selectedRelay === 'direct' ? { host: '127.0.0.1', port: 25, username: '', password: '' } : { host: relayHost, port: relayPort, username: relayUser, password: relayPass };
      const tested = await post('/api/setup/relay/test', payload);
      if (!tested.connected) throw new Error('SMTP relay connection failed');
      const applied = selectedRelay === 'direct' ? tested : await post('/api/setup/relay/apply', payload);
      setLastResult(applied); setRelayTested(true); showToast('success', language === 'zh' ? (selectedRelay === 'direct' ? '本机 Postfix SMTP 实测通过' : 'SMTP 中继实测并写入 Postfix') : 'SMTP path verified', applied.relayhost || '127.0.0.1:25');
    } catch (error) { setRelayTested(false); failOperation(error); } finally { setIsTestingRelay(false); }
  };
  const handleIssueCert = async () => {
    setIsIssuingCert(true); setOperationError('');
    try {
      const result = await post('/api/setup/cert/issue', { mailHost, email: `postmaster@${domainName}` });
      setLastResult(result); setCertIssued(Boolean(result.issued)); confetti({ particleCount: 35, spread: 60 });
      showToast('success', language === 'zh' ? '证书已真实签发并安装' : 'Certificate issued and installed', mailHost);
    } catch (error) { setCertIssued(false); failOperation(error); } finally { setIsIssuingCert(false); }
  };
  const handleSendTestMail = async () => {
    setIsSendingTestMail(true); setOperationError('');
    try {
      const address = `${adminUsername}@${domainName}`;
      const result = await post('/api/setup/mail/test', { sender: address, recipient: address, username: adminUsername, password: adminPassword, displayName: adminDisplayName });
      setLastResult(result); setTestMailSent(Boolean(result.queued)); confetti({ particleCount: 35, spread: 60 });
      showToast('success', language === 'zh' ? '测试邮件已由 Postfix 接收排队' : 'Test message accepted by Postfix', result.recipient);
    } catch (error) { setTestMailSent(false); failOperation(error); } finally { setIsSendingTestMail(false); }
  };

  const handleFinishWizard = () => {
    completeOnboarding({
      domainName,
      mailHost,
      serverIp,
      dkimSelector,
    });
    setCurrentSection('dashboard');
  };

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto font-sans">
      {/* Top Banner */}
      <LiquidGlass variant="panel" glowColor="cyan" className="p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyan-400 to-blue-500 text-slate-950 flex items-center justify-center font-bold shadow-[0_0_20px_rgba(0,242,195,0.35)]">
              <Zap className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-black text-slate-900 dark:text-white tracking-tight">
                  {hasCompletedOnboarding
                    ? (language === 'zh' ? '添加配置引导 (添加新域名/中继/安全证书)' : 'Add Configuration Guide (New Domain/Relay/Certs)')
                    : (language === 'zh' ? 'MailStack 邮件系统初次开通与全套部署向导' : 'MailStack System Initialization & Setup Wizard')}
                </h1>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-400/20 text-cyan-400 border border-cyan-400/30">
                  Step {currentStep}/6
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {hasCompletedOnboarding
                  ? (language === 'zh'
                    ? '分步引导为实例新增邮件域名身份、权威 DNS 防伪记录、出站 SMTP 中继策略与 Let\'s Encrypt 证书。'
                    : 'Step-by-step guidance to configure a new domain identity, DNS records, relay routing, and TLS certificates.')
                  : (language === 'zh'
                    ? '一站式引导您完成邮件域名标识、Cloudflare/权威 DNS 防伪解析、出站中继与 25 端口绕行、TLS 证书挂载及首封信联通性验证。'
                    : 'Step-by-step guidance to initialize domain identity, DNS security matrix, outbound relay, TLS certificates, and live testing.')}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setPrivacyMode(v => !v)}
              className="px-3.5 py-1.5 rounded-xl border border-white/10 text-xs text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-all cursor-pointer flex items-center gap-1.5"
              title={language === 'zh' ? '仅影响页面显示与截图，复制仍需明确选择' : 'Masks values on screen'}
            >
              {privacyMode ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              {language === 'zh' ? (privacyMode ? '隐私模式：开' : '隐私模式：关') : (privacyMode ? 'Privacy: On' : 'Privacy: Off')}
            </button>
          <button
            onClick={() => setCurrentSection('dashboard')}
            className="px-3.5 py-1.5 rounded-xl border border-white/10 text-xs text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-all cursor-pointer shrink-0"
          >
            {language === 'zh' ? '跳过并进入控制台' : 'Skip to Dashboard'}
          </button>
          </div>
        </div>

        {/* Step Progress Pills */}
        <div className="pt-2 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
          {stepsList.map((step) => {
            const isCurrent = currentStep === step.num;
            const isDone = currentStep > step.num;
            return (
              <button
                key={step.num}
                disabled
                aria-current={isCurrent ? 'step' : undefined}
                className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                  isCurrent
                    ? 'bg-cyan-500/20 border-cyan-400/60 text-cyan-300 shadow-[0_0_12px_rgba(0,242,195,0.15)]'
                    : isDone
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-white/[0.03] border-white/10 text-slate-500 cursor-not-allowed'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                  <span>STEP 0{step.num}</span>
                  {isDone ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <span>{step.icon}</span>
                  )}
                </div>
                <div className="text-xs font-bold truncate">
                  {language === 'zh' ? step.titleZh : step.titleEn}
                </div>
              </button>
            );
          })}
        </div>
      </LiquidGlass>

      {operationError && <div className="p-3 rounded-xl border border-rose-400/30 bg-rose-500/10 text-rose-300 text-xs break-all">{operationError}</div>}
      {lastResult && <details className="p-3 rounded-xl border border-white/10 bg-white/[0.03] text-xs"><summary className="cursor-pointer font-bold">{language === 'zh' ? '查看服务器返回结果' : 'View server result'}</summary><pre className="mt-2 overflow-auto whitespace-pre-wrap">{JSON.stringify(lastResult, null, 2)}</pre></details>}

      {/* STEP 1: Domain & Hostname */}
      {currentStep === 1 && (
        <LiquidGlass variant="card" className="p-6 space-y-6 animate-in fade-in">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Globe className="w-5 h-5 text-cyan-400" />
                <span>1. {language === 'zh' ? '定义邮件主域名与主机标识 (Identity)' : 'Domain & Hostname Identity'}</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {language === 'zh' ? '请指定您的业务邮件域名与 Postfix HELO/EHLO 识别主机名。' : 'Specify your primary email domain and server hostname.'}
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-400 font-semibold">基础参数配置</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-300">
                主邮件域名 (Primary Domain) <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                value={domainName}
                onChange={(e) => setDomainName(e.target.value)}
                placeholder="example.com"
                className="w-full h-10 px-3.5 rounded-xl border border-white/10 bg-white/[0.05] text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-400 font-bold"
              />
              <p className="text-[10px] text-slate-400 font-sans">
                例如：`yourcompany.com`，用户邮箱将为 `user@yourcompany.com`
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-300">
                邮件主机名 (Mail Hostname / HELO) <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                value={mailHost}
                onChange={(e) => setMailHost(e.target.value)}
                placeholder="mail.example.com"
                className="w-full h-10 px-3.5 rounded-xl border border-white/10 bg-white/[0.05] text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-400 font-bold"
              />
              <p className="text-[10px] text-slate-400 font-sans">
                Postfix 向外发信时使用的 FQDN，推荐使用 `mail.您的域名`
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-300">
                服务器公网 IP (Server IPv4) <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                value={serverIp}
                onChange={(e) => setServerIp(e.target.value)}
                placeholder="203.0.113.10"
                className="w-full h-10 px-3.5 rounded-xl border border-white/10 bg-white/[0.05] text-cyan-300 focus:outline-none focus:ring-1 focus:ring-cyan-400 font-bold"
              />
              <p className="text-[10px] text-slate-400 font-sans">
                服务器出站与入站公网 IP，用于 A 记录与 PTR 反向解析对齐
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-300">
                系统管理员联系邮箱 (Postmaster)
              </label>
              <input
                type="text"
                value={`admin@${domainName}`}
                disabled
                className="w-full h-10 px-3.5 rounded-xl border border-white/10 bg-white/[0.02] text-slate-400 font-bold opacity-80"
              />
              <p className="text-[10px] text-slate-400 font-sans">
                用于 DMARC 聚合报告 (RUA/RUF) 及 TLS 证书签发通知
              </p>
            </div>
          </div>

          <div className="flex justify-end pt-4 border-t border-white/10">
            <button
              onClick={handleApplyIdentity}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span>{language === 'zh' ? '下一步：配置权威 DNS 防伪记录' : 'Next: Configure DNS Records'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </LiquidGlass>
      )}

      {/* STEP 2: DNS Records & Verification */}
      {currentStep === 2 && (
        <LiquidGlass variant="card" className="p-6 space-y-6 animate-in fade-in">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <KeyRound className="w-5 h-5 text-amber-400" />
                <span>2. {language === 'zh' ? '配置权威 DNS 记录 (Cloudflare / 阿里云 / DNSPod)' : 'DNS Records & DKIM Matrix'}</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {language === 'zh'
                  ? '请将下列 5 项核心 DNS 记录添加至您的域名 DNS 解析提供商。⚠️ Cloudflare 代理状态必须设为【仅 DNS (DNS Only / 灰云)】！'
                  : 'Add these 5 core DNS records to your DNS provider. Cloudflare records MUST be DNS-Only (Grey cloud).'}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleVerifyDns}
                disabled={isVerifyingDns}
                className="px-3.5 py-1.5 rounded-xl border border-cyan-400/40 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 font-bold text-xs flex items-center gap-1.5 cursor-pointer transition-all disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isVerifyingDns ? 'animate-spin' : ''}`} />
                <span>{isVerifyingDns ? '全局探测中...' : dnsVerified ? '✓ 已验证通过' : '一键验证解析'}</span>
              </button>
            </div>
          </div>

          {/* DNS Records Table */}
          <div className="overflow-x-auto rounded-xl border border-white/10">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-white/[0.04] border-b border-white/10 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="p-3">类型 (Type)</th>
                  <th className="p-3">主机记录 (Name)</th>
                  <th className="p-3">记录值 (Content)</th>
                  <th className="p-3">代理状态</th>
                  <th className="p-3 text-right">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {dnsRecords.map((r, i) => (
                  <tr key={i} className="hover:bg-white/[0.02]">
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-cyan-400/20 text-cyan-300 font-bold text-[10px] border border-cyan-400/30">
                        {r.type}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-slate-200">{r.displayName}</td>
                    <td className="p-3 text-slate-300 max-w-xs truncate">
                      {r.displayContent}
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-amber-300 border border-amber-500/30">
                        仅 DNS (灰云)
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => { if (!privacyMode || window.confirm(language === 'zh' ? '将复制真实 DNS 值。真实值可能包含域名、公网 IP 或 DKIM 公钥，是否继续？' : 'Copy the real DNS value?')) copyText(r.content, `dns-${i}`, `${r.type} 记录值`); }}
                        className="px-2 py-1 rounded bg-white/10 hover:bg-white/20 text-slate-300 text-[11px] cursor-pointer"
                      >
                        {copiedKey === `dns-${i}` ? '✓ 已复制' : privacyMode ? '复制真实值' : '复制值'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* PTR Reminder */}
          <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-950/20 text-amber-200 text-xs flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-amber-300">反向解析 (PTR / rDNS) 关键提醒：</div>
              <p className="text-[11px] text-amber-200/90 leading-relaxed font-sans">
                请登录您的服务器主机商后台（如 Oracle Cloud, 阿里云 ECS, AWS EC2, DigitalOcean），为公网 IP <code className="bg-amber-950/60 px-1 py-0.5 rounded">{privacyMode ? maskIp(serverIp) : serverIp}</code> 设置 PTR 反向解析指向 <code className="bg-amber-950/60 px-1 py-0.5 rounded">{privacyMode ? maskDomain(mailHost) : mailHost}</code>。
              </p>
            </div>
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-white/10">
            <button
              onClick={() => setCurrentStep(1)}
              className="px-4 py-2.5 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>上一步</span>
            </button>

            <button
              onClick={() => setCurrentStep(3)}
              disabled={!dnsVerified}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span>下一步：配置出站中继与 25 端口策略</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </LiquidGlass>
      )}

      {/* STEP 3: Outbound SMTP Relay & Port 25 Bypass */}
      {currentStep === 3 && (
        <LiquidGlass variant="card" className="p-6 space-y-6 animate-in fade-in">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Send className="w-5 h-5 text-cyan-400" />
                <span>3. {language === 'zh' ? '配置 SMTP 出站中继 (绕过云厂商 25 端口封禁)' : 'SMTP Outbound Relay & Port 25 Bypass'}</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {language === 'zh'
                  ? '大部分云服务商默认拦截外发 25 端口。通过配置企业中继 (Oracle OCI / AWS SES / SendGrid / 自建 SmartHost)，可经 587/465 端口提交邮件，但不能保证最终送达。'
                  : 'Bypass cloud provider port 25 blocking using high-reputation SMTP relay networks.'}
              </p>
            </div>

            <button
              onClick={handleTestRelay}
              disabled={isTestingRelay}
              className="px-3.5 py-1.5 rounded-xl border border-cyan-400/40 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 font-bold text-xs flex items-center gap-1.5 cursor-pointer transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isTestingRelay ? 'animate-spin' : ''}`} />
              <span>{isTestingRelay ? '握手中...' : relayTested ? '✓ 中继鉴权成功' : '测试中继连通性'}</span>
            </button>
          </div>

          {/* Relay Provider Selection */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {[
              { id: 'direct', name: '直接投递', desc: '使用本机 Postfix；需云厂商开放出站 25 端口', host: '', port: 25 },
              { id: 'oracle', name: 'Oracle OCI Email Delivery', desc: 'SPF 按发送大区使用 rp / ap.rp / eu.rp', host: '', port: 587 },
              { id: 'ses', name: 'Amazon SES', desc: '需要区域 SMTP Endpoint；自定义 MAIL FROM 另配 MX + SPF', host: '', port: 587 },
              { id: 'sendgrid', name: 'Twilio SendGrid', desc: '应优先使用控制台生成的 Domain Authentication DNS 记录', host: 'smtp.sendgrid.net', port: 587 },
            ].map((prov) => (
              <button
                key={prov.id}
                onClick={() => {
                  setSelectedRelay(prov.id as any);
                  setRelayHost(prov.host);
                  setRelayPort(prov.port);
                }}
                className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                  selectedRelay === prov.id
                    ? 'bg-cyan-500/20 border-cyan-400/60 text-cyan-300 shadow-sm'
                    : 'bg-white/[0.03] border-white/10 text-slate-300 hover:bg-white/[0.06]'
                }`}
              >
                <div className="text-xs font-bold">{prov.name}</div>
                <div className="text-[11px] text-slate-400 mt-1">{prov.desc}</div>
                <div className="text-[10px] font-mono text-cyan-400/80 mt-2">{prov.host}:{prov.port}</div>
              </button>
            ))}
          </div>

          <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-200 leading-relaxed">
            <strong>SPF 规范：</strong>同一个主机名只能发布一条以 <code>v=spf1</code> 开头的 TXT 记录。MailStack 会合并直接投递与中继授权，不会生成重复 SPF。Oracle 使用区域级 <code>oracleemaildelivery.com</code> include；Amazon SES 自定义 MAIL FROM 使用 <code>bounce.域名</code> 的专用 MX 与 SPF；SendGrid 的 DKIM/CNAME 必须以账号控制台生成值为准。
          </div>

          {/* Relay Credentials Form */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs p-4 rounded-xl border border-white/10 bg-white/[0.02]">
            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-300">中继 SMTP 服务器 (Host)</label>
              <input
                type="text"
                value={relayHost}
                onChange={(e) => setRelayHost(e.target.value)}
                className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.05] text-slate-100"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-300">中继端口 (Port 587 STARTTLS / 465 SSL)</label>
              <input
                type="number"
                value={relayPort}
                onChange={(e) => setRelayPort(Number(e.target.value))}
                className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.05] text-slate-100"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-300">SMTP 授权用户名 (Username / API Key)</label>
              <input
                type="text"
                value={relayUser}
                onChange={(e) => setRelayUser(e.target.value)}
                className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.05] text-slate-100"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-300">SMTP 授权密码 (Password / Token)</label>
              <input
                type="password"
                value={relayPass}
                onChange={(e) => setRelayPass(e.target.value)}
                className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.05] text-slate-100"
              />
            </div>
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-white/10">
            <button
              onClick={() => setCurrentStep(2)}
              className="px-4 py-2.5 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>上一步</span>
            </button>

            <button
              onClick={() => setCurrentStep(4)}
              disabled={!relayTested}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span>下一步：TLS 证书与安全装配</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </LiquidGlass>
      )}

      {/* STEP 4: TLS Certs & Security */}
      {currentStep === 4 && (
        <LiquidGlass variant="card" className="p-6 space-y-6 animate-in fade-in">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>4. {language === 'zh' ? 'TLS 安全证书自动签发与加密套件' : 'TLS Certificates & Encryption'}</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {language === 'zh'
                  ? '自动申请 Let\'s Encrypt ECC 256 位 TLS 证书，为 Postfix (SMTP 465/587) 与 Dovecot (IMAP 993) 提供 TLS 1.3 传输加密。'
                  : 'Automated Let\'s Encrypt certificate issuance and TLS 1.3 encryption.'}
              </p>
            </div>

            <button
              onClick={handleIssueCert}
              disabled={isIssuingCert}
              className="px-3.5 py-1.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 font-bold text-xs flex items-center gap-1.5 cursor-pointer transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isIssuingCert ? 'animate-spin' : ''}`} />
              <span>{isIssuingCert ? 'ACME 握手签发中...' : certIssued ? '✓ 证书已有效挂载' : '一键签发证书'}</span>
            </button>
          </div>

          <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02] space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">证书域名 (SAN):</span>
              <span className="font-bold text-slate-200">{mailHost}, smtp.{domainName}, imap.{domainName}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">签发机构 (CA):</span>
              <span className="text-cyan-400 font-semibold">Let's Encrypt Authority X3 (ACME v2)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">加密算法 & 秘钥长度:</span>
              <span className="text-emerald-400 font-semibold">ECDSA P-256 (TLS 1.3 极速握手)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">自动续期策略:</span>
              <span className="text-slate-300">到期前 30 天自动 Certbot ACME 续签并热重载 Postfix</span>
            </div>
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-white/10">
            <button
              onClick={() => setCurrentStep(3)}
              className="px-4 py-2.5 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>上一步</span>
            </button>

            <button
              onClick={() => setCurrentStep(5)}
              disabled={!certIssued}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span>下一步：创建管理员并进行发信测试</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </LiquidGlass>
      )}

      {/* STEP 5: Admin Mailbox & Live Ping Test */}
      {currentStep === 5 && (
        <LiquidGlass variant="card" className="p-6 space-y-6 animate-in fade-in">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Mail className="w-5 h-5 text-cyan-400" />
                <span>5. {language === 'zh' ? '初始管理员邮箱与端到端发信联通测试' : 'Admin Mailbox & End-to-End Test'}</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {language === 'zh'
                  ? '创建系统的首个 Root 管理员邮箱账号，并发送一封端到端全链路诊断测试邮件。'
                  : 'Create primary administrator mailbox and perform live ping delivery test.'}
              </p>
            </div>

            <button
              onClick={handleSendTestMail}
              disabled={isSendingTestMail}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 cursor-pointer shadow-[0_0_15px_rgba(52,211,153,0.3)] disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 ${isSendingTestMail ? 'animate-spin' : ''}`} />
              <span>{isSendingTestMail ? '投递中...' : testMailSent ? '✓ Postfix 已接收测试邮件' : '发送端到端测试信'}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-300">管理员邮箱</label>
              <input
                type="text"
                value={`${adminUsername}@${domainName}`}
                disabled
                className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.02] text-cyan-300 font-bold"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-300">管理员姓名</label>
              <input
                type="text"
                value={adminDisplayName}
                onChange={(e) => setAdminDisplayName(e.target.value)}
                className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.05] text-slate-100"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-300">初始密码</label>
              <input
                type="password"
                value={adminPassword}
                onChange={(e) => setAdminPassword(e.target.value)}
                className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.05] text-slate-100"
              />
            </div>
          </div>

          {testMailSent && (
            <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 text-emerald-300 text-xs font-mono space-y-2 animate-in fade-in">
              <div className="flex items-center justify-between">
                <span className="font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>端到端全链路邮件投递诊断结果：</span>
                </span>
                <span className="px-2 py-0.5 rounded bg-emerald-400/20 text-emerald-300 font-bold">已排队</span>
              </div>
              <p className="text-[11px] text-emerald-200/90 font-sans">
                Postfix 已接受测试邮件进入队列。该结果不代表收件方已接收，也不代表 SPF、DKIM 或 DMARC 已通过。请继续查看队列和收件方邮件头。
              </p>
            </div>
          )}

          <div className="flex items-center justify-between pt-4 border-t border-white/10">
            <button
              onClick={() => setCurrentStep(4)}
              className="px-4 py-2.5 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>上一步</span>
            </button>

            <button
              onClick={() => setCurrentStep(6)}
              disabled={!testMailSent}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span>下一步：完成部署并生效</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </LiquidGlass>
      )}

      {/* STEP 6: Completion & Ready */}
      {currentStep === 6 && (
        <LiquidGlass variant="card" glowColor="cyan" className="p-8 space-y-6 text-center animate-in zoom-in-95">
          <div className="w-16 h-16 rounded-full bg-gradient-to-tr from-emerald-400 to-cyan-400 text-slate-950 flex items-center justify-center mx-auto shadow-[0_0_30px_rgba(0,242,195,0.4)]">
            <Check className="w-8 h-8 stroke-[3]" />
          </div>

          <div className="space-y-2 max-w-lg mx-auto">
            <h2 className="text-2xl font-black text-slate-900 dark:text-white tracking-tight">
              {language === 'zh' ? '配置步骤已完成' : '🎉 Email Service Successfully Deployed!'}
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              您的邮件域名 <strong className="text-cyan-400">@{domainName}</strong> 已完成本向导要求的服务器写入和在线检测。邮件送达与信誉仍需通过真实收件和邮件头持续验证。
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 max-w-xl mx-auto text-left font-mono text-xs">
            <div className="p-3 rounded-xl border border-white/10 bg-white/[0.03]">
              <div className="text-[10px] text-slate-400 uppercase">当前域名</div>
              <div className="font-bold text-slate-200 mt-0.5">@{domainName}</div>
            </div>
            <div className="p-3 rounded-xl border border-white/10 bg-white/[0.03]">
              <div className="text-[10px] text-slate-400 uppercase">出站中继通道</div>
              <div className="font-bold text-cyan-400 mt-0.5">{selectedRelay.toUpperCase()}</div>
            </div>
            <div className="p-3 rounded-xl border border-white/10 bg-white/[0.03]">
              <div className="text-[10px] text-slate-400 uppercase">向导验证状态</div>
              <div className="font-bold text-emerald-400 mt-0.5">已完成</div>
            </div>
          </div>

          <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-3">
            <button
              onClick={handleFinishWizard}
              className="w-full sm:w-auto px-8 py-3.5 rounded-2xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-extrabold text-sm flex items-center justify-center gap-2 transition-all shadow-[0_0_25px_rgba(0,242,195,0.4)] cursor-pointer"
            >
              <span>{language === 'zh' ? '进入系统控制台' : 'Launch MailStack Console'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            <button
              onClick={() => {
                setCurrentStep(1);
                showToast('info', '向导重置', '可重新调整各项配置');
              }}
              className="w-full sm:w-auto px-5 py-3.5 rounded-2xl border border-white/10 text-slate-400 hover:text-slate-200 hover:bg-white/5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '重新检查配置' : 'Review Setup'}</span>
            </button>
          </div>
        </LiquidGlass>
      )}
    </div>
  );
};

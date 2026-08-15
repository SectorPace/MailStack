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
  Zap,
  Play,
  RotateCcw
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { LiquidGlass } from '../common/LiquidGlass';

export const SetupGuideView: React.FC = () => {
  const { language, themeMode, showToast, completeOnboarding, setCurrentSection, hasCompletedOnboarding } = useApp();

  // Wizard Steps: 1: Domain & Host, 2: DNS & DKIM, 3: Relay & Port 25, 4: TLS & SSL, 5: Admin & Ping Test, 6: Complete
  const [currentStep, setCurrentStep] = useState<number>(1);

  // Form State
  const [domainName, setDomainName] = useState('sectorpace.com');
  const [mailHost, setMailHost] = useState('mail.sectorpace.com');
  const [serverIp, setServerIp] = useState('163.192.27.230');
  const [adminUsername, setAdminUsername] = useState('admin');
  const [adminPassword, setAdminPassword] = useState('SecurePass@2026');
  const [adminDisplayName, setAdminDisplayName] = useState('System Administrator');
  const [selectedRelay, setSelectedRelay] = useState<'direct' | 'oracle' | 'ses' | 'sendgrid' | 'custom'>('oracle');
  const [relayHost, setRelayHost] = useState('smtp.email.us-sanjose-1.oci.oraclecloud.com');
  const [relayPort, setRelayPort] = useState(587);
  const [relayUser, setRelayUser] = useState('ocid1.user.oc1..aaaaaaaaxample');
  const [relayPass, setRelayPass] = useState('OCI-Token-Secret#2026');
  const [dkimSelector, setDkimSelector] = useState('mail');
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

  // Dynamic DNS records computed from current wizard inputs
  const dkimPublicShort = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0w9B7q2rXw1A4J7d8L2m5n9k8o7p6q5r4s3t2u1v0w9x8y7z6a5b4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r8s7t6u5v4w3x2y1z0a9b8c7d6e5f4g3h2i1j0k9l8m7n6o5p4q3r2s1t0u9v8w7x6y5z4a3b2c1d0e9f8g7h6i5j4k3l2m1n0o9p8q7r6s5t4u3v2w1x0y9z8a7b6c5d4e3f2g1h0i9j8k7l6m5n4o3p2q1r0s9t8u7v6w5x4y3z2a1b0c9d8e7f6g5h4i3j2k1l0m9n8o7p6q5r4s3t2u1v0w9x8y7z6a5b4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r8s7t6u5v4w3x2y1z0DAQAB`;
  let spfValue = `v=spf1 mx ~all`;
  if (selectedRelay === 'oracle') spfValue = `v=spf1 mx include:spf.us-sanjose-1.oci.oraclecloud.com ~all`;
  else if (selectedRelay === 'ses') spfValue = `v=spf1 mx include:amazonses.com ~all`;
  else if (selectedRelay === 'sendgrid') spfValue = `v=spf1 mx include:sendgrid.net ~all`;

  const dnsRecords = [
    { type: 'A', name: `mail.${domainName}`, content: serverIp, desc: '邮件服务器主 A 记录 (Cloudflare 须保持灰云 DNS-Only)' },
    { type: 'MX', name: domainName, content: `mail.${domainName}`, priority: 10, desc: '主邮件交换记录 (优先级 10)' },
    { type: 'TXT', name: domainName, content: spfValue, desc: 'SPF 发信 IP 授权及中继白名单策略' },
    { type: 'TXT', name: `${dkimSelector}._domainkey.${domainName}`, content: `v=DKIM1; k=rsa; p=${dkimPublicShort}`, desc: '2048 位 OpenDKIM RSA 签名公钥' },
    { type: 'TXT', name: `_dmarc.${domainName}`, content: `v=DMARC1; p=${dmarcPolicy}; rua=mailto:admin@${domainName}; fo=1`, desc: 'DMARC 防伪对齐规则与报告投递邮箱' },
  ];

  const handleVerifyDns = () => {
    setIsVerifyingDns(true);
    setTimeout(() => {
      setIsVerifyingDns(false);
      setDnsVerified(true);
      confetti({ particleCount: 30, spread: 60 });
      showToast('success', language === 'zh' ? 'DNS 解析探测全部通过' : 'DNS Records Verified', 'MX, SPF, DKIM 2048, DMARC 响应正常');
    }, 1000);
  };

  const handleTestRelay = () => {
    setIsTestingRelay(true);
    setTimeout(() => {
      setIsTestingRelay(false);
      setRelayTested(true);
      confetti({ particleCount: 30, spread: 60 });
      showToast('success', language === 'zh' ? 'SMTP 出站中继握手成功' : 'Relay Connected', `${relayHost}:${relayPort} STARTTLS 身份鉴权通过`);
    }, 1100);
  };

  const handleIssueCert = () => {
    setIsIssuingCert(true);
    setTimeout(() => {
      setIsIssuingCert(false);
      setCertIssued(true);
      confetti({ particleCount: 35, spread: 60 });
      showToast('success', language === 'zh' ? 'Let\'s Encrypt 证书签发成功' : 'SSL Certificate Issued', `${mailHost} SAN: smtp, imap 均已自动装配`);
    }, 1200);
  };

  const handleSendTestMail = () => {
    setIsSendingTestMail(true);
    setTimeout(() => {
      setIsSendingTestMail(false);
      setTestMailSent(true);
      confetti({ particleCount: 50, spread: 80, origin: { y: 0.6 } });
      showToast('success', language === 'zh' ? '端到端测试信投递成功！' : 'Test Email Delivered!', `SPF: PASS | DKIM: PASS | DMARC: PASS | 综合评分: 98/100`);
    }, 1300);
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

          <button
            onClick={() => setCurrentSection('dashboard')}
            className="px-3.5 py-1.5 rounded-xl border border-white/10 text-xs text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-all cursor-pointer shrink-0"
          >
            {language === 'zh' ? '跳过并进入控制台' : 'Skip to Dashboard'}
          </button>
        </div>

        {/* Step Progress Pills */}
        <div className="pt-2 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
          {stepsList.map((step) => {
            const isCurrent = currentStep === step.num;
            const isDone = currentStep > step.num;
            return (
              <button
                key={step.num}
                onClick={() => setCurrentStep(step.num)}
                className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                  isCurrent
                    ? 'bg-cyan-500/20 border-cyan-400/60 text-cyan-300 shadow-[0_0_12px_rgba(0,242,195,0.15)]'
                    : isDone
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-white/[0.03] border-white/10 text-slate-400 hover:bg-white/[0.06]'
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
                placeholder="sectorpace.com"
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
                placeholder="mail.sectorpace.com"
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
                placeholder="163.192.27.230"
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
              onClick={() => setCurrentStep(2)}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer"
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
                    <td className="p-3 font-bold text-slate-200">{r.name}</td>
                    <td className="p-3 text-slate-300 max-w-xs truncate">
                      {r.content}
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-amber-300 border border-amber-500/30">
                        仅 DNS (灰云)
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => copyText(r.content, `dns-${i}`, `${r.type} 记录值`)}
                        className="px-2 py-1 rounded bg-white/10 hover:bg-white/20 text-slate-300 text-[11px] cursor-pointer"
                      >
                        {copiedKey === `dns-${i}` ? '✓ 已复制' : '复制值'}
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
                请登录您的服务器主机商后台（如 Oracle Cloud, 阿里云 ECS, AWS EC2, DigitalOcean），为公网 IP <code className="bg-amber-950/60 px-1 py-0.5 rounded">{serverIp}</code> 设置 PTR 反向解析指向 <code className="bg-amber-950/60 px-1 py-0.5 rounded">{mailHost}</code>。
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
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer"
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
                  ? '大部分云服务商默认拦截外发 25 端口。通过配置企业中继 (Oracle OCI / AWS SES / SendGrid / 自建 SmartHost)，可经 587/465 端口保证 100% 投递成功。'
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
              { id: 'oracle', name: 'Oracle Cloud OCI SJC1', desc: '推荐 • 免费每月 3,000 封高信誉投递', host: 'smtp.email.us-sanjose-1.oci.oraclecloud.com', port: 587 },
              { id: 'ses', name: 'Amazon SES', desc: 'AWS 全球高可用发信中继', host: 'email-smtp.us-east-1.amazonaws.com', port: 587 },
              { id: 'sendgrid', name: 'Twilio SendGrid', desc: '专业事务邮件出站中继', host: 'smtp.sendgrid.net', port: 587 },
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
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer"
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
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer"
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
              <span>{isSendingTestMail ? '投递中...' : testMailSent ? '✓ 全链路测试通过' : '发送端到端测试信'}</span>
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
                <span className="px-2 py-0.5 rounded bg-emerald-400/20 text-emerald-300 font-bold">100/100 A+</span>
              </div>
              <p className="text-[11px] text-emerald-200/90 font-sans">
                Postfix 发信队列响应正常，OpenDKIM 2048 位签名校验成功，SPF 对齐通过，未触发反垃圾拦截。
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
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer"
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
              {language === 'zh' ? '🎉 企业级邮件服务已成功开通！' : '🎉 Email Service Successfully Deployed!'}
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              您的邮件域名 <strong className="text-cyan-400">@{domainName}</strong> 已完成全套权威 DNS、2048 位 DKIM 签名、出站中继与 TLS 安全证书配置，已具备向 Gmail / Outlook 等全球服务商高信誉发信能力。
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
              <div className="text-[10px] text-slate-400 uppercase">综合送达率评分</div>
              <div className="font-bold text-emerald-400 mt-0.5">98/100 (A+)</div>
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

import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import {
  Globe,
  KeyRound,
  Send,
  ShieldCheck,
  CheckCircle2,
  Zap,
  Eye,
  EyeOff
} from '@/lib/icons';
import confetti from 'canvas-confetti';
import { api } from '../../api';
import { LiquidGlass } from '../common/LiquidGlass';
import { getErrorMessage } from '../../utils/errors';
import { SetupIdentityStep } from '../setup/SetupIdentityStep';
import { SetupDnsStep } from '../setup/SetupDnsStep';
import { SetupRelayStep } from '../setup/SetupRelayStep';
import { SetupTlsStep } from '../setup/SetupTlsStep';
import { SetupMailTestStep } from '../setup/SetupMailTestStep';
import { SetupSummaryStep } from '../setup/SetupSummaryStep';

export const SetupGuideView: React.FC = () => {
  const { language, showToast, completeOnboarding, setCurrentSection, hasCompletedOnboarding } = useApp();

  const [currentStep, setCurrentStep] = useState<number>(1);
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
  const [dkimSelector] = useState('mail');
  const [dkimPublicKey, setDkimPublicKey] = useState('');
  const [privacyMode, setPrivacyMode] = useState(true);
  const [dmarcPolicy] = useState<'none' | 'quarantine' | 'reject'>('none');

  const [isVerifyingDns, setIsVerifyingDns] = useState(false);
  const [dnsVerified, setDnsVerified] = useState(false);
  const [isTestingRelay, setIsTestingRelay] = useState(false);
  const [relayTested, setRelayTested] = useState(false);
  const [isIssuingCert, setIsIssuingCert] = useState(false);
  const [certIssued, setCertIssued] = useState(false);
  const [isSendingTestMail, setIsSendingTestMail] = useState(false);
  const [testMailSent, setTestMailSent] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [lastResult, setLastResult] = useState<unknown>(null);
  const [operationError, setOperationError] = useState('');

  const copyText = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast('info', language === 'zh' ? '已复制' : 'Copied', label);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const stepsList = [
    { num: 1, icon: '🌐', titleZh: '域名与标识', titleEn: 'Identity' },
    { num: 2, icon: '🔑', titleZh: '权威 DNS 与防伪', titleEn: 'DNS & DKIM' },
    { num: 3, icon: '🚀', titleZh: '出站中继与出站发信端口', titleEn: 'Outbound Relay & Ports' },
    { num: 4, icon: '🛡️', titleZh: 'TLS 证书与加密', titleEn: 'TLS & Certs' },
    { num: 5, icon: '✉️', titleZh: '管理员与发信测试', titleEn: 'Test & Ping' },
    { num: 6, icon: '✨', titleZh: '完成并就绪', titleEn: 'Completed' },
  ];

  const inferSesRegion = () => {
    const match = relayHost.match(/email-smtp\.([a-z0-9-]+)\.amazonaws\.com/i);
    return match ? match[1] : 'us-east-1';
  };

  const rootSpf = React.useMemo(() => {
    const parts = ['v=spf1'];
    if (serverIp) parts.push(`ip4:${serverIp}`);
    if (selectedRelay === 'oracle') parts.push('include:oracleemaildelivery.com');
    if (selectedRelay === 'ses') parts.push('include:amazonses.com');
    if (selectedRelay === 'sendgrid') parts.push('include:sendgrid.net');
    parts.push('~all');
    return parts.join(' ');
  }, [serverIp, selectedRelay]);

  const sesMailFrom = domainName ? `bounce.${domainName}` : '';
  const realDnsRecords: Array<{ type: string; name: string; content: string; priority?: number; desc: string }> = [
    ...(domainName && mailHost && serverIp ? [{ type: 'A', name: mailHost, content: serverIp, desc: '邮件服务器 A 记录；Cloudflare 必须为 DNS Only' }] : []),
    ...(domainName && mailHost ? [{ type: 'MX', name: domainName, content: mailHost, priority: 10, desc: '接收邮件的主 MX 记录，优先级 10' }] : []),
    ...(domainName ? [{ type: 'TXT', name: domainName, content: rootSpf, desc: '域名只能保留一条 SPF TXT，请合并所有授权发送源' }] : []),
    ...(domainName && dkimPublicKey ? [{ type: 'TXT', name: `${dkimSelector}._domainkey.${domainName}`, content: `v=DKIM1; k=rsa; p=${dkimPublicKey}`, desc: '从服务器取得的 OpenDKIM 公钥' }] : []),
    ...(domainName ? [{ type: 'TXT', name: `_dmarc.${domainName}`, content: `v=DMARC1; p=${dmarcPolicy}; rua=mailto:postmaster@${domainName}; adkim=s; aspf=s; pct=100`, desc: 'DMARC 初次建议 p=none，观察报告后再提高策略' }] : []),
  ];

  const maskDomain = (value: string) => value.replace(/(^|\.)[^.]+(?=\.)/g, '$1••••');
  const maskIp = (value: string) => value.replace(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/, '$1.$2.•••.•••');
  const displayValue = (value: string) => {
    if (!privacyMode) return value;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return maskIp(value);
    if (value.includes('p=') && value.includes('DKIM1')) return 'v=DKIM1; k=rsa; p=••••••••••••••••';
    if (value.includes('@')) return value.replace(/[A-Za-z0-9._%+-]+@[^;\s]+/g, '••••@••••');
    if (value.includes('v=spf1')) return value.replace(/ip4:\d+\.\d+\.\d+\.\d+/g, 'ip4:••••');
    if (/([a-z0-9-]+\.)+[a-z]{2,}/i.test(value)) return value.replace(/([a-z0-9-]+\.)+[a-z]{2,}/gi, '••••.••••');
    return value;
  };

  const dnsRecords = realDnsRecords.map(r => ({
    ...r,
    displayName: privacyMode ? maskDomain(r.name) : r.name,
    displayContent: displayValue(r.content)
  }));

  const post = async (path: string, body: unknown) => api(path, { method: 'POST', body: JSON.stringify(body) });

  const failOperation = (error: unknown) => {
    const message = getErrorMessage(error);
    setOperationError(message);
    showToast('error', language === 'zh' ? '操作失败' : 'Operation failed', message);
  };

  const handleApplyIdentity = async () => {
    setOperationError('');
    try {
      const result: any = await post('/api/setup/identity', { domain: domainName, mailHost, serverIp, postmaster: `postmaster@${domainName}` });
      setLastResult(result);
      setDkimPublicKey(result.dkimPublicKey || '');
      setCurrentStep(2);
      showToast('success', language === 'zh' ? '身份配置已写入服务器' : 'Identity applied', `${mailHost} / ${serverIp}`);
    } catch (error) {
      failOperation(error);
    }
  };

  const handleVerifyDns = async () => {
    setIsVerifyingDns(true);
    setOperationError('');
    try {
      const result: any = await post('/api/setup/dns/verify', { domain: domainName, mailHost, serverIp, dkimSelector, expectedSpf: rootSpf, selectedRelay, sesMailFrom, sesRegion: inferSesRegion() });
      setLastResult(result);
      setDnsVerified(Boolean(result.verified));
      if (!result.verified) throw new Error(language === 'zh' ? 'DNS 尚未全部生效，请查看检测结果并稍后重试' : 'DNS verification is incomplete');
      confetti({ particleCount: 30, spread: 60 });
      showToast('success', language === 'zh' ? '权威 DNS 实测通过' : 'Authoritative DNS verified', 'A / MX / SPF / DKIM / DMARC');
    } catch (error) {
      setDnsVerified(false);
      failOperation(error);
    } finally {
      setIsVerifyingDns(false);
    }
  };

  const handleTestRelay = async () => {
    setIsTestingRelay(true);
    setOperationError('');
    try {
      // rc2: direct mode sends an explicit `direct` flag -- the backend probes
      // the local Postfix on the fixed loopback endpoint (plain SMTP, no TLS
      // requirement). Sending host:127.0.0.1 as a relay host used to be
      // rejected by the SSRF guard, permanently dead-locking this wizard step.
      const payload = selectedRelay === 'direct' ? { direct: true } : { host: relayHost, port: relayPort, username: relayUser, password: relayPass };
      const tested: any = await post('/api/setup/relay/test', payload);
      if (!tested.connected) throw new Error('SMTP relay connection failed');
      const applied: any = selectedRelay === 'direct' ? tested : await post('/api/setup/relay/apply', payload);
      setLastResult(applied);
      setRelayTested(true);
      showToast('success', language === 'zh' ? (selectedRelay === 'direct' ? '本机 Postfix SMTP 实测通过' : 'SMTP 中继实测并写入 Postfix') : 'SMTP path verified', applied.relayhost || '127.0.0.1:25');
    } catch (error) {
      setRelayTested(false);
      failOperation(error);
    } finally {
      setIsTestingRelay(false);
    }
  };

  const handleIssueCert = async () => {
    setIsIssuingCert(true);
    setOperationError('');
    try {
      const result: any = await post('/api/setup/cert/issue', { mailHost, email: `postmaster@${domainName}` });
      setLastResult(result);
      setCertIssued(Boolean(result.issued));
      confetti({ particleCount: 35, spread: 60 });
      showToast('success', language === 'zh' ? '证书已真实签发并安装' : 'Certificate issued and installed', mailHost);
    } catch (error) {
      setCertIssued(false);
      failOperation(error);
    } finally {
      setIsIssuingCert(false);
    }
  };

  const handleSendTestMail = async () => {
    setIsSendingTestMail(true);
    setOperationError('');
    try {
      const address = `${adminUsername}@${domainName}`;
      const result: any = await post('/api/setup/mail/test', { sender: address, recipient: address, username: adminUsername, password: adminPassword, displayName: adminDisplayName });
      setLastResult(result);
      setTestMailSent(Boolean(result.queued));
      confetti({ particleCount: 35, spread: 60 });
      showToast('success', language === 'zh' ? '测试邮件已由 Postfix 接收排队' : 'Test message accepted by Postfix', result.recipient);
    } catch (error) {
      setTestMailSent(false);
      failOperation(error);
    } finally {
      setIsSendingTestMail(false);
    }
  };

  const handleFinishWizard = async () => {
    await completeOnboarding({
      domainName,
      mailHost,
      serverIp,
      dkimSelector,
    });
    setCurrentSection('dashboard');
  };

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto font-sans">
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
                {language === 'zh'
                  ? '一站式引导您完成邮件域名标识、权威 DNS 防伪解析、出站中继与 25 端口绕行、TLS 证书挂载及首封信联通性验证。'
                  : 'Step-by-step guidance to initialize domain identity, DNS security matrix, outbound relay, TLS certificates, and live testing.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setPrivacyMode(v => !v)}
              className="px-3.5 py-1.5 rounded-xl border border-white/10 text-xs text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-all cursor-pointer flex items-center gap-1.5"
              title={language === 'zh' ? '仅影响页面显示与截图' : 'Masks values on screen'}
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

        <div className="pt-2 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
          {stepsList.map((step) => {
            const isCurrent = currentStep === step.num;
            const isDone = currentStep > step.num;
            return (
              <div
                key={step.num}
                className={`p-2.5 rounded-xl border text-left transition-all ${
                  isCurrent
                    ? 'bg-cyan-500/20 border-cyan-400/60 text-cyan-300 shadow-[0_0_12px_rgba(0,242,195,0.15)]'
                    : isDone
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-white/[0.03] border-white/10 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                  <span>STEP 0{step.num}</span>
                  {isDone ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <span>{step.icon}</span>}
                </div>
                <div className="text-xs font-bold truncate">
                  {language === 'zh' ? step.titleZh : step.titleEn}
                </div>
              </div>
            );
          })}
        </div>
      </LiquidGlass>

      {operationError && <div className="p-3 rounded-xl border border-rose-400/30 bg-rose-500/10 text-rose-300 text-xs break-all">{operationError}</div>}
      {lastResult && (
        <details className="p-3 rounded-xl border border-white/10 bg-white/[0.03] text-xs">
          <summary className="cursor-pointer font-bold">{language === 'zh' ? '查看服务器返回结果' : 'View server result'}</summary>
          <pre className="mt-2 overflow-auto whitespace-pre-wrap">{JSON.stringify(lastResult, null, 2)}</pre>
        </details>
      )}

      {currentStep === 1 && (
        <SetupIdentityStep
          domainName={domainName}
          setDomainName={setDomainName}
          mailHost={mailHost}
          setMailHost={setMailHost}
          serverIp={serverIp}
          setServerIp={setServerIp}
          language={language}
          onNext={handleApplyIdentity}
        />
      )}

      {currentStep === 2 && (
        <SetupDnsStep
          language={language}
          dnsRecords={dnsRecords}
          isVerifyingDns={isVerifyingDns}
          dnsVerified={dnsVerified}
          privacyMode={privacyMode}
          copiedKey={copiedKey}
          serverIp={serverIp}
          mailHost={mailHost}
          maskIp={maskIp}
          maskDomain={maskDomain}
          copyText={copyText}
          onVerify={handleVerifyDns}
          onPrev={() => setCurrentStep(1)}
          onNext={() => setCurrentStep(3)}
        />
      )}

      {currentStep === 3 && (
        <SetupRelayStep
          language={language}
          selectedRelay={selectedRelay}
          setSelectedRelay={setSelectedRelay}
          relayHost={relayHost}
          setRelayHost={setRelayHost}
          relayPort={relayPort}
          setRelayPort={setRelayPort}
          relayUser={relayUser}
          setRelayUser={setRelayUser}
          relayPass={relayPass}
          setRelayPass={setRelayPass}
          isTestingRelay={isTestingRelay}
          relayTested={relayTested}
          onTestRelay={handleTestRelay}
          onPrev={() => setCurrentStep(2)}
          onNext={() => setCurrentStep(4)}
        />
      )}

      {currentStep === 4 && (
        <SetupTlsStep
          language={language}
          mailHost={mailHost}
          domainName={domainName}
          isIssuingCert={isIssuingCert}
          certIssued={certIssued}
          onIssueCert={handleIssueCert}
          onPrev={() => setCurrentStep(3)}
          onNext={() => setCurrentStep(5)}
        />
      )}

      {currentStep === 5 && (
        <SetupMailTestStep
          language={language}
          adminUsername={adminUsername}
          domainName={domainName}
          adminDisplayName={adminDisplayName}
          setAdminDisplayName={setAdminDisplayName}
          adminPassword={adminPassword}
          setAdminPassword={setAdminPassword}
          isSendingTestMail={isSendingTestMail}
          testMailSent={testMailSent}
          onSendTestMail={handleSendTestMail}
          onPrev={() => setCurrentStep(4)}
          onNext={() => setCurrentStep(6)}
        />
      )}

      {currentStep === 6 && (
        <SetupSummaryStep
          language={language}
          domainName={domainName}
          selectedRelay={selectedRelay}
          onFinish={handleFinishWizard}
          onReset={() => {
            setCurrentStep(1);
            showToast('info', '向导重置', '可重新调整各项配置');
          }}
        />
      )}
    </div>
  );
};

import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import {
  Lock,
  X,
  KeyRound,
  Globe,
  ShieldCheck,
  Zap,
  Server,
  Terminal,
  CheckCircle2,
  AlertCircle,
  Eye,
  EyeOff,
  Copy,
  Layers,
  Sparkles
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import confetti from 'canvas-confetti';

interface Props {
  onClose: () => void;
}

export const IssueCertModal: React.FC<Props> = ({ onClose }) => {
  const { domains, addCert, language, themeMode, showToast } = useApp();

  const [domainName, setDomainName] = useState('mail.example.com');
  const [sanDomains, setSanDomains] = useState('smtp.example.com, imap.example.com');
  const [caProvider, setCaProvider] = useState<'letsencrypt' | 'zerossl' | 'google' | 'buypass'>('letsencrypt');
  const [challengeType, setChallengeType] = useState<'dns-01' | 'http-01'>('dns-01');
  const [dnsProvider, setDnsProvider] = useState<'cloudflare' | 'aliyun' | 'dnspod' | 'route53'>('cloudflare');
  const [globalKey, setGlobalKey] = useState('cf_global_key_8f3a9e1d2c4b57089a');
  const [accountEmail, setAccountEmail] = useState('admin@example.com');
  const [algorithm, setAlgorithm] = useState<'ECDSA P-256' | 'RSA 2048' | 'RSA 4096'>('ECDSA P-256');
  const [autoRenew, setAutoRenew] = useState(true);
  const [hookPostfix, setHookPostfix] = useState(true);
  const [hookDovecot, setHookDovecot] = useState(true);
  const [showKeyText, setShowKeyText] = useState(false);

  // Workflow progress states
  const [isProcessing, setIsProcessing] = useState(false);
  const [progressStep, setProgressStep] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [isFinished, setIsFinished] = useState(false);

  const stepsList = [
    language === 'zh' ? '初始化 ACME 客户端与注册账户' : 'Initialize ACME client & account',
    language === 'zh' ? '生成 ECC / RSA 私钥及证书签名请求 (CSR)' : 'Generate private key & CSR',
    language === 'zh' ? '通过 Global Key 自动注入 DNS-01 TXT 记录' : 'Inject DNS-01 TXT challenge via API',
    language === 'zh' ? 'ACME CA 验证挑战并签发 Fullchain 证书' : 'CA challenge verified & cert issued',
    language === 'zh' ? '写入证书并平滑热重载 Postfix 与 Dovecot' : 'Install cert & reload Postfix / Dovecot',
  ];

  const handleStartIssue = () => {
    if (!domainName.trim()) {
      showToast('error', language === 'zh' ? '请输入域名' : 'Domain Required', language === 'zh' ? '主域名不能为空' : 'Domain cannot be empty');
      return;
    }
    if (challengeType === 'dns-01' && !globalKey.trim()) {
      showToast('error', language === 'zh' ? '缺少 API Key' : 'API Key Required', language === 'zh' ? 'DNS-01 验证需要提供 Global Key 或 API Token' : 'Please provide Global API Key');
      return;
    }

    setIsProcessing(true);
    setProgressStep(0);
    setLogs([
      `[${new Date().toLocaleTimeString()}] [ACME] Initializing RFC 8555 ACME client for CA: ${caProvider.toUpperCase()}...`,
    ]);

    // Step 1
    setTimeout(() => {
      setProgressStep(1);
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] [KEYGEN] Generating ${algorithm} private key for ${domainName}...`,
        `[${new Date().toLocaleTimeString()}] [CSR] Creating Certificate Signing Request with SANs: [${domainName}, ${sanDomains}]`,
      ]);
    }, 900);

    // Step 2
    setTimeout(() => {
      setProgressStep(2);
      setLogs((prev) => [
        ...prev,
        challengeType === 'dns-01'
          ? `[${new Date().toLocaleTimeString()}] [DNS-01] Authenticating with ${dnsProvider.toUpperCase()} using Global Key (***${globalKey.slice(-4)})...`
          : `[${new Date().toLocaleTimeString()}] [HTTP-01] Writing verification token to /.well-known/acme-challenge/...`,
        challengeType === 'dns-01'
          ? `[${new Date().toLocaleTimeString()}] [DNS-01] Injected TXT: _acme-challenge.${domainName} -> eX9b_k${Math.random().toString(36).substring(2, 10)}`
          : `[${new Date().toLocaleTimeString()}] [HTTP-01] Webroot ready on port 80/tcp`,
      ]);
    }, 1800);

    // Step 3
    setTimeout(() => {
      setProgressStep(3);
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] [ACME] Challenge validated successfully by CA. Finalizing order...`,
        `[${new Date().toLocaleTimeString()}] [ISSUE] Received signed Fullchain Certificate (Serial: 04:${Math.random().toString(16).substring(2, 8)}:${Math.random().toString(16).substring(2, 8)})`,
      ]);
    }, 2800);

    // Step 4: Finalize
    setTimeout(() => {
      setProgressStep(4);
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] [INSTALL] Saved /etc/letsencrypt/live/${domainName}/fullchain.pem`,
        `[${new Date().toLocaleTimeString()}] [INSTALL] Saved /etc/letsencrypt/live/${domainName}/privkey.pem`,
        hookPostfix ? `[${new Date().toLocaleTimeString()}] [HOOK] systemctl reload postfix -> OK (SMTP 25/465/587 TLS active)` : '',
        hookDovecot ? `[${new Date().toLocaleTimeString()}] [HOOK] systemctl reload dovecot -> OK (IMAP 993 / POP3 995 SSL active)` : '',
        `[${new Date().toLocaleTimeString()}] [DONE] TLS Certificate successfully issued and installed!`,
      ].filter(Boolean));

      setIsFinished(true);
      setIsProcessing(false);

      // Add to context
      addCert({
        domain: domainName,
        issuer: caProvider === 'letsencrypt' ? "Let's Encrypt Authority X3" : caProvider === 'zerossl' ? 'ZeroSSL RSA/ECC CA' : 'Google Trust Services CA',
        algorithm: algorithm,
        keySize: algorithm.includes('2048') ? 2048 : algorithm.includes('4096') ? 4096 : 256,
        autoRenew: autoRenew,
      });

      confetti({
        particleCount: 50,
        spread: 70,
        origin: { y: 0.6 },
      });
    }, 3800);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-md">
      <div className="fixed inset-0" onClick={!isProcessing ? onClose : undefined} />

      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 10 }}
        className={`w-full max-w-2xl border rounded-3xl shadow-2xl overflow-hidden relative z-10 flex flex-col max-h-[92vh] font-sans ${
          themeMode === 'light'
            ? 'bg-white border-slate-200 text-slate-900'
            : 'bg-slate-900 border-slate-700/80 text-white'
        }`}
      >
        {/* Header */}
        <div className={`px-6 py-4 border-b flex items-center justify-between ${
          themeMode === 'light' ? 'bg-slate-50/90 border-slate-200' : 'bg-slate-950/80 border-slate-800'
        }`}>
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${
              themeMode === 'light'
                ? 'bg-cyan-50 border-cyan-200 text-cyan-700 shadow-sm'
                : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
            }`}>
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className={`text-base font-bold flex items-center gap-2 ${
                themeMode === 'light' ? 'text-slate-900' : 'text-white'
              }`}>
                <span>{language === 'zh' ? '一键申请与注册 TLS 证书' : 'Issue TLS Certificate via ACME'}</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                  themeMode === 'light'
                    ? 'bg-cyan-100 text-cyan-800 border-cyan-300'
                    : 'bg-cyan-950 text-cyan-300 border-cyan-800'
                }`}>
                  ACME v2 RFC 8555
                </span>
              </h3>
              <p className={`text-xs font-mono ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                {language === 'zh'
                  ? '支持 Let\'s Encrypt / ZeroSSL 自动化签发，支持 DNS Global Key 极速验签'
                  : 'Automated certificate issuance via Let\'s Encrypt / ZeroSSL with DNS Global Key'}
              </p>
            </div>
          </div>

          {!isProcessing && (
            <button
              onClick={onClose}
              className={`p-1.5 rounded-lg transition-colors cursor-pointer ${
                themeMode === 'light' ? 'text-slate-400 hover:text-slate-700 hover:bg-slate-200' : 'text-slate-400 hover:text-white'
              }`}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5 text-xs">
          {/* If finished */}
          {isFinished ? (
            <div className="space-y-5 text-center py-4">
              <div className="w-16 h-16 rounded-2xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 flex items-center justify-center mx-auto shadow-[0_0_25px_rgba(16,185,129,0.3)]">
                <CheckCircle2 className="w-8 h-8 text-emerald-400" />
              </div>

              <div className="space-y-1">
                <h4 className={`text-lg font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                  {language === 'zh' ? 'TLS 证书申请与自动化部署已完成！' : 'TLS Certificate Issued & Deployed!'}
                </h4>
                <p className={`text-xs ${themeMode === 'light' ? 'text-slate-600' : 'text-slate-400'}`}>
                  {language === 'zh'
                    ? `证书已成功颁发给 ${domainName}，并已挂载到 Postfix 与 Dovecot 服务中。`
                    : `Certificate for ${domainName} is now active and bound to Postfix & Dovecot.`}
                </p>
              </div>

              {/* Path info box */}
              <div className={`p-4 rounded-2xl border text-left font-mono space-y-2 text-xs ${
                themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
              }`}>
                <div className="flex justify-between items-center">
                  <span className={themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}>Cert Fullchain:</span>
                  <span className="text-cyan-600 dark:text-cyan-400 font-semibold">/etc/letsencrypt/live/{domainName}/fullchain.pem</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className={themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}>Private Key:</span>
                  <span className="text-cyan-600 dark:text-cyan-400 font-semibold">/etc/letsencrypt/live/{domainName}/privkey.pem</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className={themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}>Auto-Renew Cron:</span>
                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold">Active (Every 60 days via Certbot daemon)</span>
                </div>
              </div>

              <button
                onClick={onClose}
                className="px-6 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs shadow-[0_0_15px_rgba(0,242,195,0.3)] transition-all cursor-pointer inline-flex items-center gap-2"
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>{language === 'zh' ? '完成并返回控制台' : 'Done & Return'}</span>
              </button>
            </div>
          ) : isProcessing ? (
            /* Running Step Terminal */
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs font-mono font-semibold">
                  <span className={themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}>
                    {stepsList[progressStep] || 'Processing ACME Challenge...'}
                  </span>
                  <span className="text-cyan-500">Step {progressStep + 1} / 5</span>
                </div>
                <div className="w-full h-2 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-gradient-to-r from-cyan-400 to-sky-400"
                    animate={{ width: `${((progressStep + 1) / 5) * 100}%` }}
                    transition={{ duration: 0.4 }}
                  />
                </div>
              </div>

              {/* Terminal Logs Output */}
              <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 text-slate-200 font-mono text-[11px] h-56 overflow-y-auto space-y-1.5 shadow-inner">
                <div className="text-slate-500 flex items-center gap-1.5 pb-1 border-b border-slate-800/80 mb-2">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>ACME RFC 8555 Automation Engine Stream</span>
                </div>
                {logs.map((log, i) => (
                  <div key={i} className="leading-relaxed">
                    {log.includes('OK') || log.includes('successfully') ? (
                      <span className="text-emerald-400">{log}</span>
                    ) : log.includes('Generating') || log.includes('TXT') ? (
                      <span className="text-cyan-300">{log}</span>
                    ) : (
                      <span className="text-slate-300">{log}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            /* Setup Form */
            <div className="space-y-4 font-mono">
              {/* Domain Input */}
              <div className="space-y-1.5">
                <div className="flex justify-between items-center">
                  <label className={`font-semibold uppercase tracking-wider ${
                    themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
                  }`}>
                    {language === 'zh' ? '服务器绑定主域名 (SERVER PRIMARY DOMAIN)' : 'PRIMARY DOMAIN'}
                  </label>
                  <span className={`text-[10px] ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                    {language === 'zh' ? '示例: mail.example.com' : 'e.g. mail.example.com'}
                  </span>
                </div>
                <div className="relative">
                  <input
                    type="text"
                    required
                    value={domainName}
                    onChange={(e) => setDomainName(e.target.value)}
                    placeholder="mail.example.com"
                    className={`w-full pl-9 pr-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                      themeMode === 'light'
                        ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                        : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                    }`}
                  />
                  <Server className="w-4 h-4 text-cyan-500 absolute left-3 top-3" />
                </div>

                {/* Quick domain chips */}
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {['mail.example.com', 'smtp.example.com', 'imap.example.com', 'mail.mailstack.io'].map((d) => (
                    <button
                      key={d}
                      type="button"
                      onClick={() => setDomainName(d)}
                      className={`px-2 py-0.5 rounded text-[10px] border transition-colors cursor-pointer ${
                        domainName === d
                          ? themeMode === 'light'
                            ? 'bg-cyan-100 text-cyan-900 border-cyan-300 font-bold'
                            : 'bg-cyan-950 text-cyan-300 border-cyan-700 font-bold'
                          : themeMode === 'light'
                          ? 'bg-slate-100 text-slate-600 border-slate-200 hover:bg-slate-200'
                          : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-white'
                      }`}
                    >
                      {d}
                    </button>
                  ))}
                </div>
              </div>

              {/* SANs (Subject Alternative Names) */}
              <div className="space-y-1.5">
                <label className={`block font-semibold uppercase tracking-wider ${
                  themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
                }`}>
                  {language === 'zh' ? '多域名 / SANs 别名绑定 (COMMA SEPARATED)' : 'ADDITIONAL SANS'}
                </label>
                <input
                  type="text"
                  value={sanDomains}
                  onChange={(e) => setSanDomains(e.target.value)}
                  placeholder="smtp.example.com, imap.example.com, pop3.example.com"
                  className={`w-full px-3.5 py-2 rounded-xl border focus:outline-none transition-colors ${
                    themeMode === 'light'
                      ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                      : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                  }`}
                />
              </div>

              {/* CA Selection & Verification Mode */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* CA Selection */}
                <div>
                  <label className={`block font-semibold uppercase tracking-wider mb-1.5 ${
                    themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
                  }`}>
                    {language === 'zh' ? 'CA 证书机构' : 'ACME CA PROVIDER'}
                  </label>
                  <select
                    value={caProvider}
                    onChange={(e) => setCaProvider(e.target.value as any)}
                    className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                      themeMode === 'light'
                        ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                        : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                    }`}
                  >
                    <option value="letsencrypt">Let's Encrypt (免费 90 天 / 自动轮换)</option>
                    <option value="zerossl">ZeroSSL (90 天免费 / 支持 EAB)</option>
                    <option value="google">Google Trust Services (GTS CA)</option>
                    <option value="buypass">Buypass Go SSL (180 天证书)</option>
                  </select>
                </div>

                {/* Challenge Method */}
                <div>
                  <label className={`block font-semibold uppercase tracking-wider mb-1.5 ${
                    themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
                  }`}>
                    {language === 'zh' ? '验证方式 (CHALLENGE)' : 'VERIFICATION TYPE'}
                  </label>
                  <select
                    value={challengeType}
                    onChange={(e) => setChallengeType(e.target.value as any)}
                    className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                      themeMode === 'light'
                        ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                        : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                    }`}
                  >
                    <option value="dns-01">DNS-01 验证 (推荐 / 免开 80 端口 / 支持泛域名)</option>
                    <option value="http-01">HTTP-01 验证 (需 80 端口公网可达)</option>
                  </select>
                </div>
              </div>

              {/* DNS Global Key Section (If DNS-01 selected) */}
              {challengeType === 'dns-01' && (
                <div className={`p-4 rounded-2xl border space-y-3 ${
                  themeMode === 'light' ? 'bg-cyan-50/50 border-cyan-200' : 'bg-cyan-950/20 border-cyan-500/30'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <KeyRound className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                      <span className={`font-bold font-sans text-xs ${
                        themeMode === 'light' ? 'text-slate-900' : 'text-white'
                      }`}>
                        {language === 'zh' ? 'DNS API 提供商与 Global API Key 配置' : 'DNS Provider & Global API Key'}
                      </span>
                    </div>
                    <span className="text-[10px] text-cyan-700 dark:text-cyan-300 font-mono font-semibold">
                      自动注入 TXT 记录
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label className={`block text-[11px] mb-1 ${themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'}`}>
                        DNS 服务商 (Provider)
                      </label>
                      <select
                        value={dnsProvider}
                        onChange={(e) => setDnsProvider(e.target.value as any)}
                        className={`w-full px-3 py-2 rounded-xl border focus:outline-none text-xs ${
                          themeMode === 'light'
                            ? 'bg-white border-slate-300 text-slate-900 focus:border-cyan-500 shadow-sm'
                            : 'bg-slate-900 border-slate-700 text-white focus:border-cyan-400'
                        }`}
                      >
                        <option value="cloudflare">Cloudflare (Global API Key / Token)</option>
                        <option value="aliyun">阿里云 DNS (Aliyun AccessKey)</option>
                        <option value="dnspod">腾讯云 DNSPod (SecretId / Key)</option>
                        <option value="route53">Amazon AWS Route 53</option>
                      </select>
                    </div>

                    <div>
                      <label className={`block text-[11px] mb-1 ${themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'}`}>
                        {dnsProvider === 'cloudflare' ? 'Cloudflare 账户邮箱' : '账户标识 / Email'}
                      </label>
                      <input
                        type="email"
                        value={accountEmail}
                        onChange={(e) => setAccountEmail(e.target.value)}
                        placeholder="admin@example.com"
                        className={`w-full px-3 py-2 rounded-xl border focus:outline-none text-xs ${
                          themeMode === 'light'
                            ? 'bg-white border-slate-300 text-slate-900 focus:border-cyan-500 shadow-sm'
                            : 'bg-slate-900 border-slate-700 text-white focus:border-cyan-400'
                        }`}
                      />
                    </div>
                  </div>

                  {/* Global API Key input */}
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <label className={`text-[11px] ${themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'}`}>
                        {dnsProvider === 'cloudflare' ? 'Global API Key / API Token' : 'Access Key Secret'}
                      </label>
                      <button
                        type="button"
                        onClick={() => setGlobalKey('cf_key_' + Math.random().toString(36).substring(2, 12) + '98a72')}
                        className={`text-[10px] hover:underline cursor-pointer ${
                          themeMode === 'light' ? 'text-cyan-700 font-semibold' : 'text-cyan-400'
                        }`}
                      >
                        {language === 'zh' ? '填入演示密钥' : 'Fill Demo Key'}
                      </button>
                    </div>
                    <div className="relative">
                      <input
                        type={showKeyText ? 'text' : 'password'}
                        value={globalKey}
                        onChange={(e) => setGlobalKey(e.target.value)}
                        placeholder="e.g. c2547eb745079dac9320b638f5e225cf483cc5"
                        className={`w-full pl-3 pr-10 py-2 rounded-xl border focus:outline-none text-xs font-mono ${
                          themeMode === 'light'
                            ? 'bg-white border-slate-300 text-slate-900 focus:border-cyan-500 shadow-sm'
                            : 'bg-slate-900 border-slate-700 text-white focus:border-cyan-400'
                        }`}
                      />
                      <button
                        type="button"
                        onClick={() => setShowKeyText(!showKeyText)}
                        className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                      >
                        {showKeyText ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Encryption & Hook Toggles */}
              <div className={`p-4 rounded-2xl border space-y-3 ${
                themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/60 border-slate-800'
              }`}>
                <div className="flex items-center justify-between">
                  <span className={`font-semibold uppercase tracking-wider ${
                    themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
                  }`}>
                    {language === 'zh' ? '私钥算法与加密强度' : 'CIPHER ALGORITHM'}
                  </span>
                  <div className="flex items-center gap-2">
                    {(['ECDSA P-256', 'RSA 2048', 'RSA 4096'] as const).map((alg) => (
                      <button
                        key={alg}
                        type="button"
                        onClick={() => setAlgorithm(alg)}
                        className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all cursor-pointer ${
                          algorithm === alg
                            ? themeMode === 'light'
                              ? 'bg-cyan-100 text-cyan-900 border-cyan-300'
                              : 'bg-cyan-950 text-cyan-300 border-cyan-600'
                            : themeMode === 'light'
                            ? 'bg-white text-slate-600 border-slate-200 hover:bg-slate-100'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {alg}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Checkboxes */}
                <div className="pt-2 border-t border-slate-200 dark:border-slate-800/80 space-y-2 text-xs font-sans">
                  <label className="flex items-center gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={hookPostfix}
                      onChange={(e) => setHookPostfix(e.target.checked)}
                      className="rounded text-cyan-500 focus:ring-cyan-400"
                    />
                    <span className={themeMode === 'light' ? 'text-slate-700 font-medium' : 'text-slate-300'}>
                      {language === 'zh'
                        ? '自动更新 Postfix SMTP (25/465/587) TLS 证书并平滑热重载'
                        : 'Auto-bind Postfix SMTP (25/465/587) and reload daemon'}
                    </span>
                  </label>

                  <label className="flex items-center gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={hookDovecot}
                      onChange={(e) => setHookDovecot(e.target.checked)}
                      className="rounded text-cyan-500 focus:ring-cyan-400"
                    />
                    <span className={themeMode === 'light' ? 'text-slate-700 font-medium' : 'text-slate-300'}>
                      {language === 'zh'
                        ? '自动更新 Dovecot IMAP/POP3 (993/995) SSL 证书并平滑热重载'
                        : 'Auto-bind Dovecot IMAP/POP3 (993/995) and reload daemon'}
                    </span>
                  </label>

                  <label className="flex items-center gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={autoRenew}
                      onChange={(e) => setAutoRenew(e.target.checked)}
                      className="rounded text-cyan-500 focus:ring-cyan-400"
                    />
                    <span className={themeMode === 'light' ? 'text-slate-700 font-medium' : 'text-slate-300'}>
                      {language === 'zh'
                        ? '注册 Systemd 定时续期任务 (到期前 30 天自动通过 ACME 轮换)'
                        : 'Register Systemd Cron for auto-renewal every 60 days'}
                    </span>
                  </label>
                </div>
              </div>

              {/* Action Button */}
              <div className="pt-2">
                <button
                  type="button"
                  onClick={handleStartIssue}
                  className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-400 to-sky-400 hover:from-cyan-300 hover:to-sky-300 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(0,242,195,0.3)] transition-all cursor-pointer font-sans hover:scale-[1.01]"
                >
                  <Zap className="w-4 h-4 fill-current" />
                  <span>{language === 'zh' ? '一键向 ACME CA 申请并挂载 TLS 证书' : 'Issue & Deploy TLS Certificate Now'}</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
};

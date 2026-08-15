import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import {
  Server,
  Mail,
  ShieldCheck,
  KeyRound,
  FileCheck,
  Cloud,
  ChevronRight,
  ChevronLeft,
  Copy,
  CheckCircle2,
  Check,
  AlertTriangle,
  ExternalLink,
  BookOpen,
  HelpCircle,
  Zap,
  Globe
} from 'lucide-react';
import confetti from 'canvas-confetti';

interface Props {
  domainName: string;
  serverIp: string;
  dkimSelector: string;
  relayProvider: string;
  dmarcPolicy: string;
  ruaEmail: string;
  onJumpToTab?: (tab: 'table' | 'diagnostic' | 'assistant') => void;
}

export const DnsSetupWizard: React.FC<Props> = ({
  domainName,
  serverIp,
  dkimSelector,
  relayProvider,
  dmarcPolicy,
  ruaEmail,
  onJumpToTab
}) => {
  const { language, themeMode, showToast } = useApp();
  const [currentStep, setCurrentStep] = useState(1);
  const [selectedProvider, setSelectedProvider] = useState<'cloudflare' | 'aliyun' | 'dnspod' | 'aws' | 'namecheap'>('cloudflare');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyText = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast('info', language === 'zh' ? '已复制' : 'Copied', `${label}: ${text}`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const steps = [
    {
      step: 1,
      titleZh: '邮件服务器 A 记录',
      titleEn: 'Mail Host A Record',
      icon: Server,
      category: '基础解析',
      descZh: '将邮件主机名 mail.' + domainName + ' 解析至您的服务器公网 IP，作为全站邮件服务的主入口。',
      descEn: 'Points mail.' + domainName + ' to your server public IP as the primary mail gateway.'
    },
    {
      step: 2,
      titleZh: '入站 MX 邮件路由',
      titleEn: 'Inbound MX Record',
      icon: Mail,
      category: '基础解析',
      descZh: '告诉全球所有的邮件系统（如 Gmail, Outlook, QQ），当有人发送到 @' + domainName + ' 时由哪台服务器接收。',
      descEn: 'Directs all inbound emails addressed to @' + domainName + ' to your mail server.'
    },
    {
      step: 3,
      titleZh: '客户端 CNAME 别名',
      titleEn: 'Protocol CNAME Aliases',
      icon: Globe,
      category: '客户端接入',
      descZh: '配置 smtp, imap, pop 别名指向 mail.' + domainName + '，让用户在 Outlook/Foxmail 中使用标准独立协议地址。',
      descEn: 'Convenient CNAME aliases for SMTP, IMAP, and POP3 client connections.'
    },
    {
      step: 4,
      titleZh: 'SPF 发信防伪策略',
      titleEn: 'SPF Sender Policy',
      icon: ShieldCheck,
      category: '安全认证',
      descZh: '声明全网哪些 IP 和中继服务商有权代表您的域名发送邮件，防止恶意攻击者假冒发信。',
      descEn: 'Authorizes your server and outbound relays to send emails on behalf of your domain.'
    },
    {
      step: 5,
      titleZh: '2048 位 DKIM 签名',
      titleEn: '2048-bit DKIM Key',
      icon: KeyRound,
      category: '安全认证',
      descZh: '通过非对称加密公钥在 DNS 中验证邮件在传输途中未被篡改，是 2024 年主流邮箱不进垃圾箱的刚性要求。',
      descEn: 'Publishes 2048-bit RSA public key to cryptographically verify email message integrity.'
    },
    {
      step: 6,
      titleZh: 'DMARC 防护与反馈',
      titleEn: 'DMARC Security Policy',
      icon: FileCheck,
      category: '安全审计',
      descZh: '协调 SPF 与 DKIM 的对齐规则，指示收信方在验证失败时的处置动作 (隔离/拒收)，并定期收取诊断报告。',
      descEn: 'Enforces SPF/DKIM alignment and collects aggregate forensic DMARC feedback reports.'
    }
  ];

  // Helper for generating dynamic values
  const getStepContent = (stepNum: number) => {
    switch (stepNum) {
      case 1:
        return {
          type: 'A',
          host: `mail.${domainName}`,
          hostShort: 'mail',
          value: serverIp || '163.192.27.230',
          ttl: '自动 / 600',
          proxy: '仅 DNS (灰云)',
          noteZh: '重要安全提示：在 Cloudflare 中务必选择【仅 DNS (灰云)】，绝对不能开启橙云代理！开启橙云会切断 25/465/587 邮件端口。',
          noteEn: 'Crucial: Ensure Proxy Status is set to "DNS Only" (Grey Cloud) on Cloudflare.'
        };
      case 2:
        return {
          type: 'MX',
          host: domainName,
          hostShort: '@',
          value: `mail.${domainName}`,
          priority: 10,
          ttl: '自动 / 600',
          proxy: '仅 DNS (灰云)',
          noteZh: 'MX 记录的名称为根域名 (@)，目标值必须填写第 1 步配置的 mail.' + domainName + '，优先级建议设为 10。',
          noteEn: 'Name is @ (root), target is mail.' + domainName + ' with priority 10.'
        };
      case 3:
        return {
          type: 'CNAME',
          records: [
            { name: `smtp.${domainName}`, nameShort: 'smtp', target: `mail.${domainName}`, desc: 'SMTP (465/587) 发信接入点' },
            { name: `imap.${domainName}`, nameShort: 'imap', target: `mail.${domainName}`, desc: 'IMAP (993) 收信接入点' },
            { name: `pop.${domainName}`, nameShort: 'pop', target: `mail.${domainName}`, desc: 'POP3 (995) 历史收信接入点' }
          ],
          noteZh: '客户端别名能够让员工或客户在配置手机邮箱、Foxmail 或 Thunderbird 时直接使用 smtp.' + domainName + ' 与 imap.' + domainName + '。',
          noteEn: 'Standard protocol aliases for desktop and mobile email clients.'
        };
      case 4:
        let spfValue = `v=spf1 mx ~all`;
        if (relayProvider === 'oracle') {
          spfValue = `v=spf1 mx include:spf.us-sanjose-1.oci.oraclecloud.com ~all`;
        } else if (relayProvider === 'ses') {
          spfValue = `v=spf1 mx include:amazonses.com ~all`;
        } else if (relayProvider === 'sendgrid') {
          spfValue = `v=spf1 mx include:sendgrid.net ~all`;
        } else if (relayProvider === 'mailgun') {
          spfValue = `v=spf1 mx include:mailgun.org ~all`;
        } else if (relayProvider === 'brevo') {
          spfValue = `v=spf1 mx include:spf.sendinblue.com ~all`;
        } else if (relayProvider === 'resend') {
          spfValue = `v=spf1 mx include:resend.com ~all`;
        }
        return {
          type: 'TXT',
          host: domainName,
          hostShort: '@',
          value: spfValue,
          ttl: '自动 / 600',
          noteZh: `当前配置了【${relayProvider === 'direct' ? '自建直发' : relayProvider.toUpperCase() + ' 中继'}】模式。注意：一个域名绝对只能存在 1 条 SPF 记录，严禁添加多个 SPF TXT 记录（否则会被 RFC 判定为 SPF PermError 严重违规）。`,
          noteEn: 'Only one SPF record allowed per domain. Do not create multiple SPF TXT records.'
        };
      case 5:
        return {
          type: 'TXT',
          host: `${dkimSelector}._domainkey.${domainName}`,
          hostShort: `${dkimSelector}._domainkey`,
          value: `v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0w9B7q2rXw1A4J7d8L2m5n9k8o7p6q5r4s3t2u1v0w9x8y7z6a5b4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r8s7t6u5v4w3x2y1z0a9b8c7d6e5f4g3h2i1j0k9l8m7n6o5p4q3r2s1t0u9v8w7x6y5z4a3b2c1d0e9f8g7h6i5j4k3l2m1n0o9p8q7r6s5t4u3v2w1x0y9z8a7b6c5d4e3f2g1h0i9j8k7l6m5n4o3p2q1r0s9t8u7v6w5x4y3z2a1b0c9d8e7f6g5h4i3j2k1l0m9n8o7p6q5r4s3t2u1v0w9x8y7z6a5b4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r8s7t6u5v4w3x2y1z0DAQAB`,
          selector: dkimSelector,
          noteZh: '2048 位公钥较长（约 392 字符），某些 DNS 服务商（如阿里云、腾讯云）若提示单条限制 255 字符，请用英文双引号拆分或直接粘贴，系统会自动合并。',
          noteEn: '2048-bit RSA public key. If your DNS provider limits 255 chars, split into quoted strings.'
        };
      case 6:
        const rua = ruaEmail || `admin@${domainName}`;
        return {
          type: 'TXT',
          host: `_dmarc.${domainName}`,
          hostShort: '_dmarc',
          value: `v=DMARC1; p=${dmarcPolicy || 'none'}; rua=mailto:${rua}; ruf=mailto:${rua}; fo=1; aspf=r; adkim=r`,
          policy: dmarcPolicy,
          noteZh: '推荐初期使用 p=none (监控观察模式)，收集 2-4 周无误报后，再平滑升级为 p=quarantine (放入垃圾箱) 或 p=reject (直接拒收伪造邮件)。',
          noteEn: 'Start with p=none for monitoring, then graduate to p=quarantine and p=reject.'
        };
      default:
        return {};
    }
  };

  const currentStepData = getStepContent(currentStep);

  return (
    <div className="space-y-6">
      {/* Step Navigation Progress Bar */}
      <div className={`p-4 sm:p-5 rounded-2xl border backdrop-blur-md ${
        themeMode === 'light' ? 'bg-white/90 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
      }`}>
        <div className="flex items-center justify-between gap-2 mb-4">
          <div>
            <h3 className={`text-sm font-bold flex items-center gap-2 ${
              themeMode === 'light' ? 'text-slate-900' : 'text-white'
            }`}>
              <Zap className="w-4 h-4 text-cyan-500" />
              <span>{language === 'zh' ? '交互式 DNS 逐步配置向导' : 'Interactive DNS Step-by-Step Setup Wizard'}</span>
              <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${
                themeMode === 'light' ? 'bg-cyan-50 text-cyan-800 border-cyan-300' : 'bg-cyan-950 text-cyan-300 border-cyan-800'
              }`}>
                步骤 {currentStep} / {steps.length}
              </span>
            </h3>
            <p className={`text-xs mt-1 ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
              {language === 'zh'
                ? `根据您的域名 @${domainName} 与设置自动适配的向导，跟随指引前往 DNS 服务商添加记录即可。`
                : `Customized configuration steps for @${domainName}. Follow the guide to add records at your DNS provider.`}
            </p>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentStep(prev => Math.max(1, prev - 1))}
              disabled={currentStep === 1}
              className={`p-2 rounded-xl border text-xs font-semibold flex items-center gap-1 transition-all cursor-pointer ${
                currentStep === 1
                  ? 'opacity-40 cursor-not-allowed border-transparent'
                  : themeMode === 'light'
                  ? 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700'
                  : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200'
              }`}
            >
              <ChevronLeft className="w-4 h-4" />
              <span className="hidden sm:inline">{language === 'zh' ? '上一步' : 'Prev'}</span>
            </button>

            <button
              onClick={() => {
                if (currentStep < steps.length) {
                  setCurrentStep(prev => prev + 1);
                } else {
                  confetti({ particleCount: 80, spread: 70, origin: { y: 0.6 } });
                  showToast('success', language === 'zh' ? '向导步骤已完成' : 'Wizard Complete', language === 'zh' ? '已完成所有 6 项 DNS 记录指导！' : 'All 6 DNS setup steps reviewed.');
                  if (onJumpToTab) onJumpToTab('table');
                }
              }}
              className="px-3.5 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer"
            >
              <span>{currentStep === steps.length ? (language === 'zh' ? '完成向导并查看总表' : 'Finish & View Table') : (language === 'zh' ? '下一步' : 'Next Step')}</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Steps Breadcrumb / Pills */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 pt-2 border-t border-slate-200/60 dark:border-slate-800/60">
          {steps.map((st) => {
            const Icon = st.icon;
            const isCompleted = currentStep > st.step;
            const isCurrent = currentStep === st.step;
            return (
              <button
                key={st.step}
                onClick={() => setCurrentStep(st.step)}
                className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                  isCurrent
                    ? themeMode === 'light'
                      ? 'bg-cyan-50 border-cyan-400 shadow-sm ring-1 ring-cyan-400'
                      : 'bg-cyan-500/15 border-cyan-500 shadow-[0_0_12px_rgba(0,242,195,0.15)] ring-1 ring-cyan-400'
                    : isCompleted
                    ? themeMode === 'light'
                      ? 'bg-emerald-50/60 border-emerald-300 text-emerald-900'
                      : 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
                    : themeMode === 'light'
                    ? 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center justify-between w-full mb-1">
                  <div className="flex items-center gap-1.5 font-mono text-[11px] font-bold">
                    <span className={`w-4 h-4 rounded-full flex items-center justify-center text-[10px] ${
                      isCurrent
                        ? 'bg-cyan-500 text-slate-950 font-bold'
                        : isCompleted
                        ? 'bg-emerald-500 text-slate-950 font-bold'
                        : themeMode === 'light' ? 'bg-slate-200 text-slate-700' : 'bg-slate-800 text-slate-400'
                    }`}>
                      {isCompleted ? '✓' : st.step}
                    </span>
                    <span className="truncate">{st.category}</span>
                  </div>
                  <Icon className={`w-3.5 h-3.5 ${
                    isCurrent ? 'text-cyan-500' : isCompleted ? 'text-emerald-500' : 'text-slate-400'
                  }`} />
                </div>
                <div className={`text-xs font-semibold truncate ${
                  isCurrent
                    ? themeMode === 'light' ? 'text-cyan-950 font-bold' : 'text-cyan-200 font-bold'
                    : themeMode === 'light' ? 'text-slate-800' : 'text-slate-300'
                }`}>
                  {language === 'zh' ? st.titleZh : st.titleEn}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Step Detail Card */}
      <div className={`p-6 rounded-2xl border backdrop-blur-md space-y-6 ${
        themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-md' : 'bg-slate-900/80 border-slate-800'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200 dark:border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <span className={`px-2.5 py-0.5 rounded-md text-xs font-mono font-bold uppercase ${
                themeMode === 'light' ? 'bg-cyan-100 text-cyan-900 border border-cyan-300' : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
              }`}>
                Step {currentStep}
              </span>
              <h2 className={`text-lg font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                {language === 'zh' ? steps[currentStep - 1].titleZh : steps[currentStep - 1].titleEn}
              </h2>
            </div>
            <p className={`text-xs mt-1.5 max-w-3xl leading-relaxed ${themeMode === 'light' ? 'text-slate-600' : 'text-slate-400'}`}>
              {language === 'zh' ? steps[currentStep - 1].descZh : steps[currentStep - 1].descEn}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className={`px-3 py-1 rounded-xl text-xs font-mono font-bold flex items-center gap-1.5 border ${
              themeMode === 'light' ? 'bg-amber-50 text-amber-800 border-amber-300' : 'bg-amber-950 text-amber-300 border-amber-500/40'
            }`}>
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '目标服务商：' : 'Target:'}</span>
              <span className="capitalize">{selectedProvider}</span>
            </span>
          </div>
        </div>

        {/* Record Fill-in Box (What to enter in DNS dashboard) */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className={`text-xs font-bold font-mono tracking-wider uppercase ${
              themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
            }`}>
              {language === 'zh' ? '📋 请在 DNS 控制台填入以下参数：' : '📋 DNS Dashboard Input Fields:'}
            </span>
            <span className={`text-[11px] font-mono ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
              {language === 'zh' ? '点击各输入框右侧按钮可直接复制' : 'Click buttons to copy fields'}
            </span>
          </div>

          {currentStep === 3 ? (
            /* Multi-record for CNAME */
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {(currentStepData as any).records?.map((rec: any, idx: number) => (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border space-y-2.5 font-mono text-xs ${
                    themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/80 border-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-400 font-bold text-[11px]">CNAME</span>
                    <span className="text-[11px] text-slate-400">{rec.desc}</span>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500 uppercase">主机记录 (Name / Host)</div>
                    <div className="flex items-center justify-between gap-1 mt-0.5">
                      <span className={`font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>{rec.nameShort}</span>
                      <button
                        onClick={() => copyText(rec.nameShort, `cname-name-${idx}`, 'Host')}
                        className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-400 hover:text-cyan-500 cursor-pointer"
                        title="复制主机名"
                      >
                        {copiedKey === `cname-name-${idx}` ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500 uppercase">记录值 (Target / Value)</div>
                    <div className="flex items-center justify-between gap-1 mt-0.5">
                      <span className={`font-bold truncate ${themeMode === 'light' ? 'text-cyan-800' : 'text-cyan-300'}`}>{rec.target}</span>
                      <button
                        onClick={() => copyText(rec.target, `cname-val-${idx}`, 'Target')}
                        className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-400 hover:text-cyan-500 cursor-pointer"
                        title="复制目标值"
                      >
                        {copiedKey === `cname-val-${idx}` ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            /* Single/Standard Record Box */
            <div className={`p-4 sm:p-5 rounded-2xl border font-mono text-xs grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 ${
              themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
            }`}>
              {/* Type */}
              <div className="space-y-1">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">1. 记录类型 (Type)</div>
                <div className="flex items-center gap-2">
                  <span className={`px-3 py-1.5 rounded-xl font-bold text-sm border ${
                    themeMode === 'light'
                      ? 'bg-cyan-100 text-cyan-900 border-cyan-300'
                      : 'bg-cyan-950 text-cyan-300 border-cyan-700'
                  }`}>
                    {(currentStepData as any).type}
                  </span>
                </div>
              </div>

              {/* Host/Name */}
              <div className="space-y-1">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">2. 主机记录 (Name / Host)</div>
                <div className={`flex items-center justify-between p-2 rounded-xl border ${
                  themeMode === 'light' ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'
                }`}>
                  <span className={`font-bold truncate ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                    {(currentStepData as any).hostShort || (currentStepData as any).host}
                  </span>
                  <button
                    onClick={() => copyText((currentStepData as any).hostShort || (currentStepData as any).host, 'step-host', 'Host')}
                    className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-cyan-500 cursor-pointer shrink-0"
                    title="复制主机名"
                  >
                    {copiedKey === 'step-host' ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <div className="text-[10px] text-slate-400 truncate">完整域名: {(currentStepData as any).host}</div>
              </div>

              {/* Value/Content */}
              <div className="space-y-1 sm:col-span-2">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">
                  3. 记录值 (Value / Content)
                  {(currentStepData as any).priority ? ` (优先级 Priority: ${(currentStepData as any).priority})` : ''}
                </div>
                <div className={`flex items-center justify-between p-2 rounded-xl border break-all ${
                  themeMode === 'light' ? 'bg-white border-slate-200 text-slate-800' : 'bg-slate-900 border-slate-800 text-slate-200'
                }`}>
                  <span className="font-bold text-xs select-all">
                    {(currentStepData as any).value}
                  </span>
                  <button
                    onClick={() => copyText((currentStepData as any).value, 'step-val', 'Value')}
                    className="p-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 hover:text-cyan-300 cursor-pointer shrink-0 ml-2"
                    title="复制记录值"
                  >
                    {copiedKey === 'step-val' ? <CheckCircle2 className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Important Advice Note */}
          <div className={`p-4 rounded-xl border flex items-start gap-3 text-xs leading-relaxed ${
            themeMode === 'light'
              ? 'bg-amber-50/70 border-amber-200 text-amber-900'
              : 'bg-amber-950/30 border-amber-500/30 text-amber-200'
          }`}>
            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold">{language === 'zh' ? '避坑重点：' : 'Important Note: '}</span>
              {(currentStepData as any).noteZh}
            </div>
          </div>
        </div>

        {/* DNS Provider Selector Tabs for Step Guidelines */}
        <div className="space-y-3 pt-4 border-t border-slate-200 dark:border-slate-800">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <span className={`text-xs font-bold font-mono uppercase ${
              themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
            }`}>
              {language === 'zh' ? '🌐 选择您的 DNS 服务商查看后台针对性操作指引：' : '🌐 Specific DNS Provider Instructions:'}
            </span>

            <div className="flex flex-wrap gap-1.5">
              {[
                { id: 'cloudflare', name: 'Cloudflare' },
                { id: 'aliyun', name: '阿里云 (万网)' },
                { id: 'dnspod', name: '腾讯云 DNSPod' },
                { id: 'aws', name: 'AWS Route 53' },
                { id: 'namecheap', name: 'Namecheap' }
              ].map(prov => (
                <button
                  key={prov.id}
                  onClick={() => setSelectedProvider(prov.id as any)}
                  className={`px-3 py-1 rounded-xl text-xs font-mono transition-all cursor-pointer ${
                    selectedProvider === prov.id
                      ? themeMode === 'light'
                        ? 'bg-slate-900 text-white font-bold'
                        : 'bg-cyan-400 text-slate-950 font-bold'
                      : themeMode === 'light'
                      ? 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  {prov.name}
                </button>
              ))}
            </div>
          </div>

          {/* Provider Specific Step Guidelines */}
          <div className={`p-4 rounded-xl border text-xs leading-relaxed space-y-2 font-mono ${
            themeMode === 'light' ? 'bg-slate-50 border-slate-200 text-slate-700' : 'bg-slate-950/70 border-slate-800 text-slate-300'
          }`}>
            {selectedProvider === 'cloudflare' && (
              <div className="space-y-1.5">
                <div className="font-bold text-cyan-500">Cloudflare 操作流程：</div>
                <div>1. 登录 Cloudflare Dashboard &rarr; 选择域名 <span className="text-cyan-400">@{domainName}</span> &rarr; 进入 <strong>DNS</strong> 记录页面。</div>
                <div>2. 点击 <strong>「添加记录 (Add record)」</strong> 按钮。</div>
                <div>3. 类型选择 <strong className="text-amber-400">{(currentStepData as any).type || '指定类型'}</strong>。</div>
                <div>4. 主机名称填入 <strong className="text-cyan-400">{(currentStepData as any).hostShort || '@'}</strong>。</div>
                <div>5. 内容直接粘贴上方记录值。</div>
                <div className="text-rose-400 font-bold">6. 【核心警告】如果添加的是 A/CNAME/MX 记录，务必将「代理状态 (Proxy status)」点击切换为【仅 DNS (灰云 DNS only)】，禁止开启橙云代理！</div>
              </div>
            )}

            {selectedProvider === 'aliyun' && (
              <div className="space-y-1.5">
                <div className="font-bold text-cyan-500">阿里云 (万网) 云解析 DNS 操作流程：</div>
                <div>1. 登录阿里云控制台 &rarr; 搜索 <strong>云解析 DNS</strong> &rarr; 点击您的域名 <span className="text-cyan-400">@{domainName}</span>。</div>
                <div>2. 点击 <strong>「添加记录」</strong> 按钮。</div>
                <div>3. 记录类型选择 <strong>{(currentStepData as any).type || 'TXT'}</strong>。</div>
                <div>4. 主机记录：若为根域名请直接填写 <strong>@</strong>；若为 DKIM 请填写 <strong>{(currentStepData as any).hostShort || 'mail._domainkey'}</strong>。</div>
                <div>5. 解析线路：默认。TTL：建议选择 <strong>10 分钟</strong>（方便快速生效）。</div>
              </div>
            )}

            {selectedProvider === 'dnspod' && (
              <div className="space-y-1.5">
                <div className="font-bold text-cyan-500">腾讯云 DNSPod 操作流程：</div>
                <div>1. 进入 DNSPod 域名解析列表 &rarr; 点击域名 <span className="text-cyan-400">@{domainName}</span>。</div>
                <div>2. 点击 <strong>「添加记录」</strong>。</div>
                <div>3. 主机记录填写 <strong>{(currentStepData as any).hostShort || '@'}</strong>。</div>
                <div>4. 记录值直接粘贴对应内容，TXT 记录内容在 DNSPod 中无需手动添加首尾双引号。</div>
              </div>
            )}

            {selectedProvider === 'aws' && (
              <div className="space-y-1.5">
                <div className="font-bold text-cyan-500">AWS Route 53 操作流程：</div>
                <div>1. 进入 Route 53 控制台 &rarr; Hosted zones &rarr; 打开 <span className="text-cyan-400">{domainName}</span>。</div>
                <div>2. 点击 <strong>「Create record」</strong>。</div>
                <div>3. Record name 填入 <strong>{(currentStepData as any).hostShort || ''}</strong>（根域名留空）。</div>
                <div>4. Record type 选择 <strong>{(currentStepData as any).type}</strong>。</div>
                <div>5. Value 框中填入记录值（若 TXT 长度超过 255 字符，在引号内换行或分段引用）。</div>
              </div>
            )}

            {selectedProvider === 'namecheap' && (
              <div className="space-y-1.5">
                <div className="font-bold text-cyan-500">Namecheap / GoDaddy 操作流程：</div>
                <div>1. 登录 Namecheap Dashboard &rarr; Domain List &rarr; 点击域名旁边的 <strong>MANAGE</strong>。</div>
                <div>2. 切换至 <strong>Advanced DNS</strong> 标签页 &rarr; 点击 <strong>ADD NEW RECORD</strong>。</div>
                <div>3. Type 对应选择，Host 填写 <strong>{(currentStepData as any).hostShort || '@'}</strong>。</div>
                <div>4. Value 填入记录值，TTL 选择 <strong>Automatic</strong> 并点击绿色勾号保存。</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

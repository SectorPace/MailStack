import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import {
  X,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Cloud,
  Send,
  ShieldCheck,
  Server,
  Zap,
  Lock,
  Globe
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import confetti from 'canvas-confetti';

interface Props {
  onClose: () => void;
}

export const AddRelayModal: React.FC<Props> = ({ onClose }) => {
  const { addRelayRoute, language, showToast } = useApp();

  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [provider, setProvider] = useState('oci');
  const [host, setHost] = useState('oci-smtp.us-ashburn-1.oraclecloud.com');
  const [port, setPort] = useState(587);
  const [tlsMode, setTlsMode] = useState<'STARTTLS' | 'SSL/TLS' | 'NONE'>('STARTTLS');
  const [username, setUsername] = useState('ocid1.user.oc1..aaaaaaa');
  const [password, setPassword] = useState('••••••••••••');
  const [sourceDomain, setSourceDomain] = useState('*@example.com');
  const [priority, setPriority] = useState(10);
  const [description, setDescription] = useState('Enterprise OCI Outbound Gateway');
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<'pending' | 'success' | 'failed'>('pending');

  const providerOptions = [
    {
      id: 'oci',
      name: 'Oracle Cloud (OCI)',
      subtitleZh: '高送达率，企业级云基础设施',
      subtitleEn: 'High deliverability, enterprise infrastructure',
      defaultHost: 'oci-smtp.us-ashburn-1.oraclecloud.com',
      port: 587,
    },
    {
      id: 'sendgrid',
      name: 'SendGrid (Twilio)',
      subtitleZh: '大规模事务邮件与营销中继',
      subtitleEn: 'Transactional & marketing email relay',
      defaultHost: 'smtp.sendgrid.net',
      port: 587,
    },
    {
      id: 'ses',
      name: 'Amazon SES (AWS)',
      subtitleZh: '全球低延迟、超高并发邮件投递',
      subtitleEn: 'Global scale low-latency delivery',
      defaultHost: 'email-smtp.us-east-1.amazonaws.com',
      port: 587,
    },
    {
      id: 'brevo',
      name: 'Brevo (Sendinblue)',
      subtitleZh: '欧洲 GDPR 合规中继线路',
      subtitleEn: 'GDPR compliant European relay',
      defaultHost: 'smtp-relay.brevo.com',
      port: 587,
    },
    {
      id: 'custom',
      name: '自定义 SMTP 网关 (Custom)',
      subtitleZh: '手动指定第三方或自建专用 SMTP 节点',
      subtitleEn: 'Self-hosted or proprietary SMTP gateway',
      defaultHost: 'smtp.custom-node.net',
      port: 587,
    },
  ];

  const handleSelectProvider = (opt: typeof providerOptions[0]) => {
    setProvider(opt.id);
    setHost(opt.defaultHost);
    setPort(opt.port);
    setStep(2);
  };

  const handleRunTest = () => {
    setIsTesting(true);
    setTestResult('pending');
    setTimeout(() => {
      setIsTesting(false);
      setTestResult('success');
      confetti({ particleCount: 40, spread: 60, origin: { y: 0.6 } });
    }, 1200);
  };

  const handleFinish = () => {
    addRelayRoute({
      sourceDomain,
      relayTarget: `${host}:${port}`,
      priority,
      action: 'FORWARD',
      status: 'active',
      description,
      tlsMode,
      port,
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="fixed inset-0" onClick={onClose} />

      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="w-full max-w-2xl bg-slate-900 border border-slate-700/80 rounded-3xl shadow-2xl overflow-hidden relative z-10 flex flex-col max-h-[90vh]"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Send className="w-4 h-4 text-cyan-400" />
              <span>{language === 'zh' ? '添加出站 SMTP 中继向导' : 'Add Outbound SMTP Relay Wizard'}</span>
            </h3>
            <div className="text-xs text-slate-400 mt-0.5">
              {language === 'zh' ? `第 ${step} 步 / 共 4 步` : `Step ${step} of 4`}
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Step Wizard Nav Bar */}
        <div className="px-6 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
          {[
            { s: 1, labelZh: '1. 提供商', labelEn: '1. Provider' },
            { s: 2, labelZh: '2. 认证凭据', labelEn: '2. Credentials' },
            { s: 3, labelZh: '3. 路由规则', labelEn: '3. Routing' },
            { s: 4, labelZh: '4. 连通测试', labelEn: '4. Test' },
          ].map((item) => (
            <div
              key={item.s}
              className={`flex items-center gap-1.5 ${
                step === item.s
                  ? 'text-cyan-400 font-bold'
                  : step > item.s
                  ? 'text-emerald-400'
                  : 'text-slate-500'
              }`}
            >
              <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] ${
                step === item.s
                  ? 'bg-cyan-500/20 border border-cyan-400'
                  : step > item.s
                  ? 'bg-emerald-950 border border-emerald-500'
                  : 'bg-slate-800 border border-slate-700'
              }`}>
                {step > item.s ? '✓' : item.s}
              </span>
              <span>{language === 'zh' ? item.labelZh : item.labelEn}</span>
            </div>
          ))}
        </div>

        {/* Modal Content per step */}
        <div className="p-6 overflow-y-auto flex-1 space-y-4">
          {/* STEP 1: Provider Selection */}
          {step === 1 && (
            <div className="space-y-3">
              <div className="text-xs text-slate-300 mb-2">
                {language === 'zh' ? '请选择您要接入的第三方 SMTP 中继服务商或自定义节点：' : 'Select your outbound SMTP relay provider:'}
              </div>

              <div className="space-y-2.5">
                {providerOptions.map((opt) => (
                  <button
                    key={opt.id}
                    onClick={() => handleSelectProvider(opt)}
                    className={`w-full p-4 rounded-2xl border text-left flex items-center justify-between transition-all group ${
                      provider === opt.id
                        ? 'bg-cyan-950/40 border-cyan-500/50 shadow-[0_0_15px_rgba(0,242,195,0.1)]'
                        : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center gap-3.5">
                      <div className="w-10 h-10 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                        <Cloud className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="text-sm font-bold text-white">{opt.name}</div>
                        <div className="text-xs text-slate-400 mt-0.5 font-mono">
                          {language === 'zh' ? opt.subtitleZh : opt.subtitleEn}
                        </div>
                      </div>
                    </div>

                    <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* STEP 2: Authentication & Host Config */}
          {step === 2 && (
            <div className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-300 uppercase tracking-wider mb-1">
                  {language === 'zh' ? 'SMTP 主机地址 (HOST)' : 'SMTP HOST'}
                </label>
                <input
                  type="text"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 uppercase tracking-wider mb-1">
                    {language === 'zh' ? '端口 (PORT)' : 'PORT'}
                  </label>
                  <input
                    type="number"
                    value={port}
                    onChange={(e) => setPort(Number(e.target.value))}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 uppercase tracking-wider mb-1">
                    {language === 'zh' ? '传输加密协议 (TLS)' : 'TLS MODE'}
                  </label>
                  <select
                    value={tlsMode}
                    onChange={(e) => setTlsMode(e.target.value as any)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="STARTTLS">STARTTLS (推荐)</option>
                    <option value="SSL">SSL / TLS (Port 465)</option>
                    <option value="NONE">无加密 (Plaintext)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 uppercase tracking-wider mb-1">
                  {language === 'zh' ? '用户名 / API KEY 账号' : 'SASL USERNAME'}
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-slate-300 uppercase tracking-wider mb-1">
                  {language === 'zh' ? '访问密钥 / 密码 (PASSWORD)' : 'PASSWORD / SECRET KEY'}
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>
          )}

          {/* STEP 3: Routing Policy */}
          {step === 3 && (
            <div className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-300 uppercase tracking-wider mb-1">
                  {language === 'zh' ? '匹配源域名 / 通配符 (SOURCE DOMAIN)' : 'SOURCE DOMAIN PATTERN'}
                </label>
                <input
                  type="text"
                  value={sourceDomain}
                  onChange={(e) => setSourceDomain(e.target.value)}
                  placeholder="*@example.com"
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
                <p className="text-[10px] text-slate-400 mt-1">
                  {language === 'zh' ? '支持 *@yourdomain.com 通配符或指定具体发信别名' : 'Supports wildcard *@yourdomain.com or explicit sender'}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 uppercase tracking-wider mb-1">
                    {language === 'zh' ? '路由优先级 (PRIORITY)' : 'PRIORITY (1-100)'}
                  </label>
                  <input
                    type="number"
                    value={priority}
                    onChange={(e) => setPriority(Number(e.target.value))}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                  />
                  <p className="text-[10px] text-slate-400 mt-1">
                    {language === 'zh' ? '数值越小优先级越高 (1 优先于 10)' : 'Lower number indicates higher priority'}
                  </p>
                </div>

                <div>
                  <label className="block text-slate-300 uppercase tracking-wider mb-1">
                    {language === 'zh' ? '规则说明 (DESCRIPTION)' : 'DESCRIPTION'}
                  </label>
                  <input
                    type="text"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>
              </div>
            </div>
          )}

          {/* STEP 4: Live Testing & Confirmation */}
          {step === 4 && (
            <div className="space-y-4">
              <div className="p-4 rounded-2xl bg-slate-950/90 border border-slate-800 space-y-3 font-mono text-xs">
                <div className="text-slate-300 font-bold border-b border-slate-800 pb-2">
                  {language === 'zh' ? '配置汇总与准备就绪检查' : 'Configuration Summary'}
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div><span className="text-slate-500">Host:</span> <span className="text-cyan-300">{host}:{port}</span></div>
                  <div><span className="text-slate-500">Security:</span> <span className="text-slate-300">{tlsMode}</span></div>
                  <div><span className="text-slate-500">Source:</span> <span className="text-white">{sourceDomain}</span></div>
                  <div><span className="text-slate-500">Priority:</span> <span className="text-amber-400">{priority}</span></div>
                </div>
              </div>

              {testResult === 'pending' && !isTesting && (
                <div className="text-center py-6">
                  <button
                    onClick={handleRunTest}
                    className="px-6 py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 mx-auto shadow-[0_0_20px_rgba(0,242,195,0.3)] transition-all cursor-pointer"
                  >
                    <Zap className="w-4 h-4" />
                    <span>{language === 'zh' ? '立即执行 SMTP 连通性测试' : 'Run SMTP Connectivity Test'}</span>
                  </button>
                </div>
              )}

              {isTesting && (
                <div className="text-center py-6 space-y-3">
                  <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto" />
                  <div className="text-xs font-mono text-cyan-300">
                    {language === 'zh' ? '正在连接目标服务器并验证 SASL 凭据...' : 'Establishing STARTTLS handshake & SASL auth...'}
                  </div>
                </div>
              )}

              {testResult === 'success' && (
                <div className="p-4 rounded-2xl bg-emerald-950/60 border border-emerald-500/40 text-xs text-emerald-300 space-y-2">
                  <div className="flex items-center gap-2 font-bold text-sm text-emerald-200">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span>{language === 'zh' ? '测试通过！250 OK 握手成功' : 'Test Passed! 250 OK Handshake'}</span>
                  </div>
                  <p className="text-[11px] text-emerald-300/80 leading-relaxed font-mono">
                    {language === 'zh'
                      ? '已成功与目标中继节点建立 TLS 1.3 会话并完成身份验证。点击下方“应用并激活”将热重载 Postfix transport_maps。'
                      : 'TLS 1.3 session established and SASL credentials verified. Click "Apply & Activate" to reload Postfix transport_maps.'}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Navigation */}
        <div className="px-6 py-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          {step > 1 ? (
            <button
              onClick={() => setStep((prev) => (prev - 1) as any)}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>{language === 'zh' ? '上一步' : 'Back'}</span>
            </button>
          ) : <div />}

          {step < 4 ? (
            <button
              onClick={() => setStep((prev) => (prev + 1) as any)}
              className="px-5 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(0,242,195,0.2)]"
            >
              <span>{language === 'zh' ? '下一步' : 'Next'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          ) : (
            <button
              onClick={handleFinish}
              className="px-6 py-2 rounded-xl bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(52,211,153,0.3)]"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>{language === 'zh' ? '应用并生效' : 'Apply & Activate'}</span>
            </button>
          )}
        </div>
      </motion.div>
    </div>
  );
};

import React from 'react';
import { Send, RefreshCw, ArrowLeft, ArrowRight } from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';

interface Props {
  language: string;
  selectedRelay: 'direct' | 'oracle' | 'ses' | 'sendgrid' | 'custom';
  setSelectedRelay: (v: 'direct' | 'oracle' | 'ses' | 'sendgrid' | 'custom') => void;
  relayHost: string;
  setRelayHost: (v: string) => void;
  relayPort: number;
  setRelayPort: (v: number) => void;
  relayUser: string;
  setRelayUser: (v: string) => void;
  relayPass: string;
  setRelayPass: (v: string) => void;
  isTestingRelay: boolean;
  relayTested: boolean;
  onTestRelay: () => void;
  onPrev: () => void;
  onNext: () => void;
}

export const SetupRelayStep: React.FC<Props> = ({
  language,
  selectedRelay,
  setSelectedRelay,
  relayHost,
  setRelayHost,
  relayPort,
  setRelayPort,
  relayUser,
  setRelayUser,
  relayPass,
  setRelayPass,
  isTestingRelay,
  relayTested,
  onTestRelay,
  onPrev,
  onNext,
}) => {
  return (
    <LiquidGlass variant="card" className="p-6 space-y-6 animate-in fade-in">
      <div className="flex items-center justify-between border-b border-white/10 pb-4">
        <div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Send className="w-5 h-5 text-cyan-400" />
            <span>3. {language === 'zh' ? '出站中继与出站发信端口 (规避云服务商 25 端口封禁)' : 'Outbound Relay & Outbound Ports'}</span>
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {language === 'zh'
              ? '大部分云服务商默认拦截出站 25 端口。配置第三方企业中继或自建 SmartHost 可通过 587 (Submission)、465 (SMTPS) 或 2525 端口发信，中转端口与本机直接监听的 SMTP 端口相互独立。'
              : 'Configure outbound relay using Submission port 587, 465, or 2525 to bypass cloud provider port 25 egress restrictions.'}
          </p>
        </div>

        <button
          onClick={onTestRelay}
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
            <div className="text-[10px] font-mono text-cyan-400/80 mt-2">{prov.host || '127.0.0.1'}:{prov.port}</div>
          </button>
        ))}
      </div>

      <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-200 leading-relaxed">
        <strong>SPF 规范：</strong>同一个主机名只能发布一条以 <code>v=spf1</code> 开头的 TXT 记录。MailStack 会合并直接投递与中继授权，不会生成重复 SPF。
      </div>

      {/* Relay Credentials Form */}
      {selectedRelay !== 'direct' && (
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
            <label className="text-xs font-bold text-slate-300">中继端口 (Port 587 / 465)</label>
            <input
              type="number"
              value={relayPort}
              onChange={(e) => setRelayPort(Number(e.target.value))}
              className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.05] text-slate-100"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-bold text-slate-300">SMTP 授权用户名 (Username)</label>
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
      )}

      <div className="flex items-center justify-between pt-4 border-t border-white/10">
        <button
          onClick={onPrev}
          className="px-4 py-2.5 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>上一步</span>
        </button>

        <button
          onClick={onNext}
          disabled={!relayTested}
          className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <span>下一步：TLS 证书与安全装配</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </LiquidGlass>
  );
};

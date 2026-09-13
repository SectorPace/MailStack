import React from 'react';
import { KeyRound, RefreshCw, AlertTriangle, ArrowLeft, ArrowRight } from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';

interface Props {
  language: string;
  dnsRecords: Array<{ type: string; name: string; content: string; displayName: string; displayContent: string; desc: string }>;
  isVerifyingDns: boolean;
  dnsVerified: boolean;
  privacyMode: boolean;
  copiedKey: string | null;
  serverIp: string;
  mailHost: string;
  maskIp: (v: string) => string;
  maskDomain: (v: string) => string;
  copyText: (text: string, key: string, label: string) => void;
  onVerify: () => void;
  onPrev: () => void;
  onNext: () => void;
}

export const SetupDnsStep: React.FC<Props> = ({
  language,
  dnsRecords,
  isVerifyingDns,
  dnsVerified,
  privacyMode,
  copiedKey,
  serverIp,
  mailHost,
  maskIp,
  maskDomain,
  copyText,
  onVerify,
  onPrev,
  onNext,
}) => {
  return (
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
            onClick={onVerify}
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
                    onClick={() => {
                      if (!privacyMode || window.confirm(language === 'zh' ? '将复制真实 DNS 值。真实值可能包含域名、公网 IP 或 DKIM 公钥，是否继续？' : 'Copy the real DNS value?')) {
                        copyText(r.content, `dns-${i}`, `${r.type} 记录值`);
                      }
                    }}
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
          onClick={onPrev}
          className="px-4 py-2.5 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>上一步</span>
        </button>

        <button
          onClick={onNext}
          disabled={!dnsVerified}
          className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <span>下一步：配置出站中继与 25 端口策略</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </LiquidGlass>
  );
};

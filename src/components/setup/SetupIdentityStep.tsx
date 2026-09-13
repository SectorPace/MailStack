import React from 'react';
import { Globe, ArrowRight } from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';

interface Props {
  domainName: string;
  setDomainName: (v: string) => void;
  mailHost: string;
  setMailHost: (v: string) => void;
  serverIp: string;
  setServerIp: (v: string) => void;
  language: string;
  onNext: () => void;
}

export const SetupIdentityStep: React.FC<Props> = ({
  domainName,
  setDomainName,
  mailHost,
  setMailHost,
  serverIp,
  setServerIp,
  language,
  onNext,
}) => {
  return (
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
            value={domainName ? `postmaster@${domainName}` : ''}
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
          onClick={onNext}
          disabled={!domainName || !mailHost || !serverIp}
          className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <span>{language === 'zh' ? '下一步：配置权威 DNS 防伪记录' : 'Next: Configure DNS Records'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </LiquidGlass>
  );
};

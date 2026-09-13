import React from 'react';
import { Check, ArrowRight, RotateCcw } from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';

interface Props {
  language: string;
  domainName: string;
  selectedRelay: string;
  onFinish: () => void;
  onReset: () => void;
}

export const SetupSummaryStep: React.FC<Props> = ({
  language,
  domainName,
  selectedRelay,
  onFinish,
  onReset,
}) => {
  return (
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
          onClick={onFinish}
          className="w-full sm:w-auto px-8 py-3.5 rounded-2xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-extrabold text-sm flex items-center justify-center gap-2 transition-all shadow-[0_0_25px_rgba(0,242,195,0.4)] cursor-pointer"
        >
          <span>{language === 'zh' ? '进入系统控制台' : 'Launch MailStack Console'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>

        <button
          onClick={onReset}
          className="w-full sm:w-auto px-5 py-3.5 rounded-2xl border border-white/10 text-slate-400 hover:text-slate-200 hover:bg-white/5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>{language === 'zh' ? '重新检查配置' : 'Review Setup'}</span>
        </button>
      </div>
    </LiquidGlass>
  );
};

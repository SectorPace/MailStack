import React from 'react';
import { Mail, Play, CheckCircle2, ArrowLeft, ArrowRight } from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';

interface Props {
  language: string;
  adminUsername: string;
  domainName: string;
  adminDisplayName: string;
  setAdminDisplayName: (v: string) => void;
  adminPassword: string;
  setAdminPassword: (v: string) => void;
  isSendingTestMail: boolean;
  testMailSent: boolean;
  onSendTestMail: () => void;
  onPrev: () => void;
  onNext: () => void;
}

export const SetupMailTestStep: React.FC<Props> = ({
  language,
  adminUsername,
  domainName,
  adminDisplayName,
  setAdminDisplayName,
  adminPassword,
  setAdminPassword,
  isSendingTestMail,
  testMailSent,
  onSendTestMail,
  onPrev,
  onNext,
}) => {
  return (
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
          onClick={onSendTestMail}
          disabled={isSendingTestMail || !adminPassword}
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
          <label className="text-xs font-bold text-slate-300">
            {language === 'zh' ? '初始密码（至少 12 个字符，需含字母与数字）' : 'Initial Password (12+ chars, letters & numbers)'}
          </label>
          <input
            type="password"
            minLength={12}
            placeholder={language === 'zh' ? '至少 12 个字符，需包含字母与数字' : 'At least 12 characters, including letters and numbers'}
            value={adminPassword}
            onChange={(e) => setAdminPassword(e.target.value)}
            className="w-full h-9 px-3 rounded-lg border border-white/10 bg-white/[0.05] text-slate-100 placeholder:text-slate-500"
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
          onClick={onPrev}
          className="px-4 py-2.5 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>上一步</span>
        </button>

        <button
          onClick={onNext}
          disabled={!testMailSent}
          className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <span>下一步：完成部署并生效</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </LiquidGlass>
  );
};

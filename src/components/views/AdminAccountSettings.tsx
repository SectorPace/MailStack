import React, { useEffect, useState } from 'react';
import {
  api,
  beginTwoFactor,
  disableTwoFactor,
  enableTwoFactor,
  getTwoFactorStatus,
  listSessions,
  revokeOtherSessions,
  revokeSession,
} from '../../api';
import {
  Check,
  Copy,
  KeyRound,
  LogOut,
  MonitorSmartphone,
  Save,
  ShieldCheck,
  UserRound,
  X,
} from '@/lib/icons';
import { useApp } from '../../context/AppContext';
import { getErrorMessage } from '../../utils/errors';
import type { SessionInfo, TwoFactorStatus } from '../../types';

export const AdminAccountSettings: React.FC = () => {
  const { language, themeMode, showToast, setIsLoggedIn } = useApp();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);

  // Two-factor authentication state
  const [tfa, setTfa] = useState<TwoFactorStatus | null>(null);
  const [pending, setPending] = useState<{ secret: string; uri: string } | null>(null);
  const [setupCode, setSetupCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [savedAck, setSavedAck] = useState(false);
  const [disableCode, setDisableCode] = useState('');
  const [tfaBusy, setTfaBusy] = useState(false);
  const [copied, setCopied] = useState('');

  // Active sessions state
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [sessBusy, setSessBusy] = useState(false);

  const zh = language === 'zh';
  const otherSessions = sessions.filter(s => !s.current).length;

  useEffect(() => {
    api('/api/admin').then(x => setUsername(x.username)).catch(() => {});
    getTwoFactorStatus().then(setTfa).catch(() => {});
    loadSessions();
  }, []);

  const loadSessions = () => {
    listSessions()
      .then(r => setSessions(Array.isArray(r.sessions) ? r.sessions : []))
      .catch(() => setSessions([]));
  };

  const save = async () => {
    if (password !== confirm) {
      return showToast('error', zh ? '密码不一致' : 'Passwords do not match', '');
    }
    setBusy(true);
    try {
      await api('/api/admin', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      showToast(
        'success',
        zh ? '管理员账户已更新' : 'Administrator updated',
        zh ? '所有会话已注销，请重新登录' : 'All sessions were revoked. Sign in again.'
      );
      setPassword('');
      setConfirm('');
      setTimeout(() => setIsLoggedIn(false), 700);
    } catch (e: unknown) {
      showToast('error', zh ? '更新失败' : 'Update failed', getErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const copyText = (text: string, key: string) => {
    navigator.clipboard
      ?.writeText(text)
      .then(() => {
        setCopied(key);
        setTimeout(() => setCopied(''), 1500);
      })
      .catch(() => {});
  };

  const startSetup = async (code = '') => {
    setTfaBusy(true);
    try {
      const r = await beginTwoFactor(code);
      if (r.reauthenticate) {
        // Re-enrolling over an enabled 2FA revokes every session, exactly
        // like disabling it: the enrollment must be completed after sign-in.
        showToast(
          'warning',
          zh ? '重新绑定已开始' : 'Re-enrollment started',
          zh ? '所有会话已注销，请重新登录后完成绑定' : 'Sessions revoked. Sign in again to finish setup.'
        );
        setDisableCode('');
        setTimeout(() => setIsLoggedIn(false), 900);
        return;
      }
      setPending({ secret: r.secret, uri: r.uri });
      setSetupCode('');
    } catch (e: unknown) {
      showToast('error', zh ? '开始绑定失败' : 'Failed to begin 2FA setup', getErrorMessage(e));
    } finally {
      setTfaBusy(false);
    }
  };

  const confirmEnable = async () => {
    if (!pending) return;
    setTfaBusy(true);
    try {
      const r = await enableTwoFactor(setupCode.trim());
      setPending(null);
      setSetupCode('');
      setRecoveryCodes(r.recoveryCodes);
      setSavedAck(false);
      setTfa({ enabled: true, recoveryCodesRemaining: r.recoveryCodes.length });
    } catch (e: unknown) {
      showToast('error', zh ? '启用失败，验证码不正确' : 'Enabling failed, invalid code', getErrorMessage(e));
    } finally {
      setTfaBusy(false);
    }
  };

  const closeRecoveryCodes = () => {
    if (!savedAck) return;
    setRecoveryCodes(null);
    setSavedAck(false);
    getTwoFactorStatus().then(setTfa).catch(() => {});
  };

  const confirmDisable = async () => {
    setTfaBusy(true);
    try {
      const r = await disableTwoFactor(disableCode.trim());
      setDisableCode('');
      setTfa({ enabled: false, recoveryCodesRemaining: 0 });
      if (r.reauthenticate) {
        showToast(
          'warning',
          zh ? '两步验证已关闭' : 'Two-factor authentication disabled',
          zh ? '当前会话已失效，请重新登录' : 'Session revoked. Sign in again.'
        );
        setTimeout(() => setIsLoggedIn(false), 900);
      } else {
        showToast('success', zh ? '两步验证已关闭' : 'Two-factor authentication disabled', '');
      }
    } catch (e: unknown) {
      showToast('error', zh ? '关闭失败，验证码不正确' : 'Disabling failed, invalid code', getErrorMessage(e));
    } finally {
      setTfaBusy(false);
    }
  };

  const handleRevokeSession = async (id: string) => {
    setSessBusy(true);
    try {
      await revokeSession(id);
      showToast('success', zh ? '会话已吊销' : 'Session revoked', '');
      loadSessions();
    } catch (e: unknown) {
      showToast('error', zh ? '吊销失败' : 'Revoke failed', getErrorMessage(e));
    } finally {
      setSessBusy(false);
    }
  };

  const handleRevokeOthers = async () => {
    setSessBusy(true);
    try {
      const r = await revokeOtherSessions();
      showToast(
        'success',
        zh ? '其他会话已注销' : 'Other sessions revoked',
        zh ? `已注销 ${r.revoked} 个会话` : `${r.revoked} session(s) signed out`
      );
      loadSessions();
    } catch (e: unknown) {
      showToast('error', zh ? '注销失败' : 'Revoke failed', getErrorMessage(e));
    } finally {
      setSessBusy(false);
    }
  };

  const input = `w-full px-3.5 py-2.5 rounded-xl border font-mono text-xs focus:outline-none ${
    themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950/80 border-slate-800 text-white'
  }`;

  const card = `p-6 rounded-2xl liquid-glass-card space-y-4 ${themeMode === 'light' ? 'bg-white/90 border-white/90' : ''}`;

  const secondaryBtn = `px-3 py-2 rounded-xl border text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${
    themeMode === 'light'
      ? 'border-slate-300 text-slate-600 hover:bg-slate-100'
      : 'border-slate-700 text-slate-300 hover:bg-slate-800/60'
  }`;

  const readonlyField = (value: string, key: string) => (
    <div className="flex items-center gap-2">
      <input
        readOnly
        value={value}
        onFocus={e => e.currentTarget.select()}
        className={input + ' flex-1 min-w-0'}
      />
      <button
        type="button"
        onClick={() => copyText(value, key)}
        title={zh ? '复制' : 'Copy'}
        className={`shrink-0 p-2.5 rounded-xl border transition-colors cursor-pointer ${
          themeMode === 'light'
            ? 'border-slate-300 text-slate-600 hover:bg-slate-100'
            : 'border-slate-700 text-slate-300 hover:bg-slate-800/60'
        }`}
      >
        {copied === key ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
      </button>
    </div>
  );

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
      {/* Card 1: Web Administrator Account */}
      <div className={card}>
        <div className="flex items-center gap-2 border-b border-white/10 pb-3">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <h3 className="font-bold">{zh ? 'Web 管理员账户' : 'Web Administrator Account'}</h3>
        </div>
        <div className="grid md:grid-cols-2 gap-4">
          <label className="text-xs space-y-1 md:col-span-2">
            <span>{zh ? '管理员用户名' : 'Administrator username'}</span>
            <div className="relative">
              <UserRound className="absolute left-3 top-3 w-4 h-4 text-slate-400" />
              <input value={username} onChange={e => setUsername(e.target.value)} className={input + ' pl-10'} autoComplete="username" />
            </div>
          </label>
          <label className="text-xs space-y-1">
            <span>{zh ? '新密码，留空仅修改用户名' : 'New password, leave blank to change username only'}</span>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} className={input} autoComplete="new-password" />
          </label>
          <label className="text-xs space-y-1">
            <span>{zh ? '确认新密码' : 'Confirm new password'}</span>
            <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} className={input} autoComplete="new-password" />
          </label>
        </div>
        <div className="text-xs text-amber-600 dark:text-amber-300 flex gap-2">
          <KeyRound className="w-4 h-4 shrink-0" />
          <span>
            {zh
              ? '密码至少 12 个字符，需包含字母与数字。保存后所有 Web 会话立即失效。该账户仅用于 MailStack 后台，不会修改 Linux root 用户。'
              : 'Use at least 12 characters, including letters and numbers. Saving revokes every Web session. This account is independent from the Linux root account.'}
          </span>
        </div>
        <div className="flex justify-end">
          <button disabled={busy} onClick={save} className="px-4 py-2 rounded-xl bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 cursor-pointer">
            <Save className="w-4 h-4" />
            {zh ? '更新并注销会话' : 'Update and revoke sessions'}
          </button>
        </div>
      </div>

      {/* Card 2: Two-Factor Authentication */}
      <div className={card}>
        <div className="flex items-center gap-2 border-b border-white/10 pb-3">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <h3 className="font-bold">{zh ? '两步验证' : 'Two-Factor Authentication'}</h3>
        </div>

        {/* Status */}
        <div className="flex items-center justify-between text-xs">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${tfa?.enabled ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]' : 'bg-slate-400'}`} />
              <span className="font-semibold">
                {tfa?.enabled
                  ? (zh ? '已启用' : 'Enabled')
                  : (zh ? '未启用' : 'Disabled')}
              </span>
            </div>
            {tfa?.enabled && (
              <p className={`text-[11px] ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                {zh ? `剩余恢复码：${tfa.recoveryCodesRemaining} 个` : `Recovery codes remaining: ${tfa.recoveryCodesRemaining}`}
              </p>
            )}
          </div>
        </div>

        {recoveryCodes ? (
          /* One-time recovery codes display */
          <div className="space-y-3">
            <div className="p-3 rounded-xl border border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-300 text-xs flex gap-2">
              <KeyRound className="w-4 h-4 shrink-0" />
              <span>
                {zh
                  ? '恢复码仅显示这一次，关闭后无法再次查看。请立即妥善保存到密码管理器或离线位置。'
                  : 'These recovery codes are shown only once and cannot be retrieved later. Save them now in a password manager or offline storage.'}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {recoveryCodes.map(code => (
                <div
                  key={code}
                  className={`px-3 py-2 rounded-lg border font-mono text-xs select-all ${
                    themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-800' : 'bg-slate-950/80 border-slate-800 text-cyan-300'
                  }`}
                >
                  {code}
                </div>
              ))}
            </div>
            <button type="button" onClick={() => copyText(recoveryCodes.join('\n'), 'all-codes')} className={secondaryBtn + ' w-full flex items-center justify-center gap-2'}>
              {copied === 'all-codes' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
              {zh ? '复制全部恢复码' : 'Copy all recovery codes'}
            </button>
            <label className="flex items-center gap-2 text-xs cursor-pointer select-none">
              <input
                type="checkbox"
                checked={savedAck}
                onChange={e => setSavedAck(e.target.checked)}
                className="w-4 h-4 rounded cursor-pointer accent-cyan-400"
              />
              <span>{zh ? '我已保存恢复码' : 'I have saved my recovery codes'}</span>
            </label>
            <div className="flex justify-end">
              <button
                disabled={!savedAck}
                onClick={closeRecoveryCodes}
                className="px-4 py-2 rounded-xl bg-cyan-400 text-slate-950 font-bold text-xs disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              >
                {zh ? '完成绑定' : 'Finish setup'}
              </button>
            </div>
          </div>
        ) : pending ? (
          /* Enrollment in progress: secret + uri + confirmation code */
          <div className="space-y-3">
            <label className="text-xs space-y-1 block">
              <span className="font-semibold">{zh ? '密钥 (Secret)' : 'Secret Key'}</span>
              {readonlyField(pending.secret, 'secret')}
            </label>
            <label className="text-xs space-y-1 block">
              <span className="font-semibold">{zh ? 'OTPAuth URI' : 'OTPAuth URI'}</span>
              {readonlyField(pending.uri, 'uri')}
            </label>
            <p className={`text-[11px] leading-relaxed ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
              {zh
                ? '在身份验证器应用（如 Google Authenticator、1Password）中添加该账户：粘贴上方 URI 或手动输入密钥，然后输入应用中显示的 6 位验证码完成绑定。'
                : 'Add this account in your authenticator app (e.g. Google Authenticator, 1Password) using the URI or secret above, then enter the 6-digit code to finish.'}
            </p>
            <input
              value={setupCode}
              onChange={e => setSetupCode(e.target.value)}
              placeholder="123456"
              autoFocus
              autoComplete="one-time-code"
              className={input + ' tracking-widest'}
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                disabled={tfaBusy}
                onClick={() => { setPending(null); setSetupCode(''); }}
                className={secondaryBtn + ' flex items-center gap-1.5'}
              >
                <X className="w-3.5 h-3.5" />
                {zh ? '取消' : 'Cancel'}
              </button>
              <button
                disabled={tfaBusy || setupCode.trim().length < 6}
                onClick={confirmEnable}
                className="px-4 py-2 rounded-xl bg-emerald-400 text-slate-950 font-bold text-xs flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              >
                <Check className="w-3.5 h-3.5" />
                {zh ? '确认启用' : 'Confirm & enable'}
              </button>
            </div>
          </div>
        ) : tfa?.enabled ? (
          /* Disable flow */
          <div className="space-y-3">
            <p className={`text-[11px] leading-relaxed ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
              {zh
                ? '输入当前 6 位验证码或任一恢复码以关闭两步验证，或以同一验证码开始重新绑定新的身份验证器。两种操作都会吊销当前会话，需要重新登录。'
                : 'Enter the current 6-digit code or any recovery code to disable two-factor authentication, or use the same code to re-enroll a new authenticator. Both actions revoke this session and require signing in again.'}
            </p>
            <input
              value={disableCode}
              onChange={e => setDisableCode(e.target.value)}
              placeholder={zh ? '6 位验证码或恢复码' : '6-digit code or recovery code'}
              autoComplete="one-time-code"
              className={input + ' tracking-widest'}
            />
            <div className="flex justify-end gap-2">
              <button
                disabled={tfaBusy || !disableCode.trim()}
                onClick={() => startSetup(disableCode.trim())}
                className="px-4 py-2 rounded-xl bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                {zh ? '重新绑定' : 'Re-enroll'}
              </button>
              <button
                disabled={tfaBusy || !disableCode.trim()}
                onClick={confirmDisable}
                className="px-4 py-2 rounded-xl bg-rose-500 text-white font-bold text-xs disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              >
                {zh ? '关闭两步验证' : 'Disable 2FA'}
              </button>
            </div>
          </div>
        ) : (
          /* Idle: begin enrollment */
          <div className="space-y-3">
            <p className={`text-[11px] leading-relaxed ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
              {zh
                ? '为管理员账户启用基于时间的一次性密码（TOTP）两步验证，登录后还需输入身份验证器验证码，显著提升后台安全性。'
                : 'Add time-based one-time password (TOTP) protection to the admin account. A verification code from your authenticator app will be required at login.'}
            </p>
            <div className="flex justify-end">
              <button
                disabled={tfaBusy}
                onClick={() => startSetup()}
                className="px-4 py-2 rounded-xl bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 disabled:opacity-50 cursor-pointer"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                {zh ? '开始绑定' : 'Begin setup'}
              </button>
            </div>
          </div>
        )}

        {/* Active sessions */}
        <div className="pt-4 border-t border-white/10 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold flex items-center gap-2">
              <MonitorSmartphone className="w-4 h-4 text-cyan-400" />
              {zh ? '活跃会话' : 'Active Sessions'}
            </h4>
            <button
              disabled={sessBusy || otherSessions === 0}
              onClick={handleRevokeOthers}
              className={secondaryBtn + ' flex items-center gap-1.5'}
            >
              <LogOut className="w-3.5 h-3.5" />
              {zh ? '注销其他会话' : 'Sign out other sessions'}
            </button>
          </div>
          {sessions.length === 0 ? (
            <p className={`text-[11px] ${themeMode === 'light' ? 'text-slate-400' : 'text-slate-500'}`}>
              {zh ? '暂无会话信息' : 'No session information available'}
            </p>
          ) : (
            <div className="space-y-2">
              {sessions.map(s => (
                <div
                  key={s.id}
                  className={`flex items-center gap-3 p-2.5 rounded-xl border ${
                    themeMode === 'light' ? 'bg-slate-50/80 border-slate-200' : 'bg-slate-950/60 border-slate-800'
                  }`}
                >
                  <div className="flex-1 min-w-0 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold">{s.ip}</span>
                      {s.current && (
                        <span className="px-1.5 py-0.5 rounded bg-cyan-400/15 text-cyan-500 dark:text-cyan-300 text-[10px] font-bold">
                          {zh ? '当前' : 'Current'}
                        </span>
                      )}
                    </div>
                    <p className={`text-[11px] truncate ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>{s.userAgent}</p>
                    <p className={`text-[10px] ${themeMode === 'light' ? 'text-slate-400' : 'text-slate-500'}`}>
                      {new Date(s.createdAt).toLocaleString()}
                    </p>
                  </div>
                  {!s.current && (
                    <button
                      type="button"
                      disabled={sessBusy}
                      onClick={() => handleRevokeSession(s.id)}
                      title={zh ? '吊销该会话' : 'Revoke this session'}
                      className="shrink-0 p-2 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors disabled:opacity-50 cursor-pointer"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { MailStackLogo } from '../common/MailStackLogo';
import { LogoCustomizerModal } from '../modals/LogoCustomizerModal';
import {
  User,
  Lock,
  Eye,
  EyeOff,
  ArrowRight,
  ArrowLeft,
  ShieldCheck,
  KeyRound,
  Palette,
  Sun,
  Moon,
  Globe
} from '@/lib/icons';
import { motion } from '@/lib/motion';
import { login, ApiError } from '../../api';

export const LoginView: React.FC = () => {
  const {
    setIsLoggedIn,
    showToast,
    language,
    setLanguage,
    themeMode,
    setThemeMode
  } = useApp();

  const isLight = themeMode === 'light';
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [keepSignedIn, setKeepSignedIn] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [isLogoModalOpen, setIsLogoModalOpen] = useState(false);
  const [totpStage, setTotpStage] = useState(false);
  const [totpCode, setTotpCode] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    let totpRequired = false;
    try {
      await login(username, password, totpStage ? totpCode.trim() : undefined);
      setTotpStage(false);
      setTotpCode('');
      setIsLoggedIn(true);
      showToast(
        'success',
        language === 'zh' ? '登录成功' : 'Authenticated',
        language === 'zh'
          ? '欢迎回到 MailStack 主控制台'
          : 'Welcome back to MailStack Admin Console'
      );
    } catch (err) {
      if (err instanceof ApiError && err.code === 'TOTP_REQUIRED') {
        totpRequired = true;
        setTotpStage(true);
        setTotpCode('');
        showToast(
          'info',
          language === 'zh' ? '需要两步验证' : 'Two-Factor Code Required',
          language === 'zh'
            ? '请输入身份验证器的 6 位验证码或恢复码'
            : 'Enter the 6-digit authenticator code or a recovery code'
        );
      } else {
        showToast(
          'error',
          language === 'zh' ? (totpStage ? '验证失败' : '登录失败') : (totpStage ? 'Verification failed' : 'Login failed'),
          language === 'zh'
            ? (totpStage ? '验证码不正确或已失效，请重试' : '请检查管理令牌或用户名密码')
            : (totpStage ? 'The verification code is invalid or expired. Try again.' : 'Check the administration credentials')
        );
      }
    } finally {
      setIsLoading(false);
      if (!totpRequired) {
        if (!totpStage) setPassword('');
        setTotpCode('');
      }
    }
  };

  const backToCredentials = () => {
    setTotpStage(false);
    setTotpCode('');
    setPassword('');
  };

  return (
    <div className="min-h-screen w-full bg-transparent flex items-center justify-center p-4 relative z-10 overflow-hidden">
      {/* Background Subtle Grid Lines */}
      <div
        className={`absolute inset-0 bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] pointer-events-none ${
          isLight
            ? 'bg-[linear-gradient(to_right,#cbd5e1_1px,transparent_1px),linear-gradient(to_bottom,#cbd5e1_1px,transparent_1px)] opacity-35'
            : 'bg-[linear-gradient(to_right,#0c1a2d_1px,transparent_1px),linear-gradient(to_bottom,#0c1a2d_1px,transparent_1px)] opacity-30'
        }`}
      />

      {/* Top Bar Quick Utilities (Theme & Language Toggle) */}
      <div className="absolute top-6 right-6 flex items-center gap-2 z-20">
        <button
          type="button"
          onClick={() => setLanguage(language === 'zh' ? 'en' : 'zh')}
          className={`px-3 py-1.5 rounded-full border text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
            isLight
              ? 'bg-white/80 hover:bg-white border-slate-200 text-slate-700 backdrop-blur-md'
              : 'bg-slate-900/80 hover:bg-slate-800 border-slate-700/80 text-slate-300 backdrop-blur-md'
          }`}
          title={language === 'zh' ? '切换语言 / Switch Language' : 'Switch Language'}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>{language === 'zh' ? 'EN' : '中文'}</span>
        </button>

        <button
          type="button"
          onClick={() => setThemeMode(isLight ? 'dark' : 'light')}
          className={`p-2 rounded-full border transition-all cursor-pointer shadow-sm ${
            isLight
              ? 'bg-white/80 hover:bg-white border-slate-200 text-amber-500 backdrop-blur-md'
              : 'bg-slate-900/80 hover:bg-slate-800 border-slate-700/80 text-cyan-400 backdrop-blur-md'
          }`}
          title={language === 'zh' ? '切换浅色/深色主题' : 'Toggle Theme'}
        >
          {isLight ? <Moon className="w-4 h-4 text-slate-700" /> : <Sun className="w-4 h-4 text-amber-400" />}
        </button>
      </div>

      {/* Premium Liquid Glass Card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 12 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.35, ease: 'easeOut' }}
        className={`w-full max-w-[440px] rounded-[32px] border shadow-2xl backdrop-blur-3xl relative overflow-hidden transition-all duration-300 ${
          isLight
            ? 'bg-white/85 border-white/80 shadow-[0_20px_60px_rgba(30,58,138,0.12)] text-slate-900'
            : 'bg-slate-900/85 border-slate-800/90 shadow-2xl text-white'
        }`}
      >
        {/* Card Body */}
        <div className="w-full px-8 py-9 flex flex-col items-center relative overflow-hidden">
          {/* Subtle Ambient Light Sheen */}
          <div
            className={`absolute -top-24 -left-24 w-60 h-60 rounded-full blur-3xl pointer-events-none transition-all ${
              isLight
                ? 'bg-gradient-to-br from-sky-400/20 via-blue-500/15 to-transparent'
                : 'bg-gradient-to-br from-cyan-500/10 via-sky-500/5 to-transparent'
            }`}
          />

          {/* Top Logo Icon */}
          <div
            onClick={() => setIsLogoModalOpen(true)}
            title={language === 'zh' ? '点击定制/更换 Logo 图标' : 'Click to customize/change Logo'}
            className="mb-4 relative group cursor-pointer"
          >
            <MailStackLogo size="xl" theme={themeMode} showHoverEffect />
            <div
              className={`absolute -bottom-1 -right-1 w-5 h-5 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity scale-90 ${
                isLight
                  ? 'bg-sky-600 text-white shadow-[0_0_8px_rgba(2,132,199,0.5)]'
                  : 'bg-cyan-400 text-slate-950 shadow-[0_0_10px_#00f2c3]'
              }`}
            >
              <Palette className="w-3 h-3" />
            </div>
          </div>

          {/* Heading */}
          <h2 className={`text-lg font-bold tracking-wide text-center ${isLight ? 'text-slate-900' : 'text-white'}`}>
            {language === 'zh' ? '登录管理后台' : 'Admin Console Login'}
          </h2>
          <div className={`text-xs font-normal mt-0.5 tracking-wider ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? '(MailStack Admin)' : '(MailStack Management)'}
          </div>

          {/* Hostname Indicator */}
          <div
            className={`flex items-center gap-2 mt-4 mb-6 px-3.5 py-1.5 rounded-full border text-xs font-mono transition-colors ${
              isLight
                ? 'bg-slate-100/90 border-slate-200/80 text-slate-600'
                : 'bg-slate-900/90 border-slate-800 text-slate-400'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                isLight
                  ? 'bg-sky-500 shadow-[0_0_8px_rgba(14,165,233,0.5)]'
                  : 'bg-cyan-400 shadow-[0_0_8px_#00f2c3]'
              }`}
            />
            <span>{language === 'zh' ? '主机名 (Hostname):' : 'Hostname:'}</span>
            <span className={`font-semibold ${isLight ? 'text-sky-600' : 'text-cyan-300'}`}>
              mail.example.com
            </span>
          </div>

          {/* Login Form */}
          <form onSubmit={handleLogin} className="w-full space-y-4">
            {!totpStage ? (
              <>
            {/* Username Input */}
            <div>
              <label
                className={`block text-[11px] font-mono uppercase tracking-wider mb-1.5 ${
                  isLight ? 'text-slate-700 font-semibold' : 'text-slate-300'
                }`}
              >
                {language === 'zh' ? '用户名 (USERNAME)' : 'USERNAME'}
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className={`w-full pl-10 pr-4 py-2.5 border rounded-xl text-sm transition-all font-mono focus:outline-none ${
                    isLight
                      ? 'bg-slate-50/90 border-slate-300 text-slate-900 placeholder-slate-400 focus:bg-white focus:border-sky-500 focus:ring-1 focus:ring-sky-500 shadow-sm'
                      : 'bg-slate-900/90 border-slate-700/80 text-white placeholder-slate-500 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400'
                  }`}
                  placeholder="admin"
                  required
                />
              </div>
            </div>

            {/* Password Input */}
            <div>
              <label
                className={`block text-[11px] font-mono uppercase tracking-wider mb-1.5 ${
                  isLight ? 'text-slate-700 font-semibold' : 'text-slate-300'
                }`}
              >
                {language === 'zh' ? '管理口令 (PASSWORD)' : 'PASSWORD'}
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <KeyRound className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={`w-full pl-10 pr-10 py-2.5 border rounded-xl text-sm transition-all font-mono focus:outline-none ${
                    isLight
                      ? 'bg-slate-50/90 border-slate-300 text-slate-900 placeholder-slate-400 focus:bg-white focus:border-sky-500 focus:ring-1 focus:ring-sky-500 shadow-sm'
                      : 'bg-slate-900/90 border-slate-700/80 text-white placeholder-slate-500 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400'
                  }`}
                  placeholder="••••••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className={`absolute inset-y-0 right-0 pr-3.5 flex items-center transition-colors ${
                    isLight ? 'text-slate-400 hover:text-slate-700' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
              </>
            ) : (
              <>
                {/* TOTP / Recovery Code Input */}
                <div>
                  <label
                    className={`block text-[11px] font-mono uppercase tracking-wider mb-1.5 ${
                      isLight ? 'text-slate-700 font-semibold' : 'text-slate-300'
                    }`}
                  >
                    {language === 'zh' ? '两步验证码 (2FA CODE)' : '2FA VERIFICATION CODE'}
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                      <ShieldCheck className="w-4 h-4" />
                    </div>
                    <input
                      type="text"
                      value={totpCode}
                      onChange={(e) => setTotpCode(e.target.value)}
                      autoFocus
                      autoComplete="one-time-code"
                      className={`w-full pl-10 pr-4 py-2.5 border rounded-xl text-sm transition-all font-mono tracking-widest focus:outline-none ${
                        isLight
                          ? 'bg-slate-50/90 border-slate-300 text-slate-900 placeholder-slate-400 focus:bg-white focus:border-sky-500 focus:ring-1 focus:ring-sky-500 shadow-sm'
                          : 'bg-slate-900/90 border-slate-700/80 text-white placeholder-slate-500 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400'
                      }`}
                      placeholder="123456"
                      required
                    />
                  </div>
                  <p className={`text-[11px] mt-1.5 leading-relaxed ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                    {language === 'zh'
                      ? '输入身份验证器应用的 6 位验证码，或恢复码（形如 xxxxxxxx-xxxxxxxx）。'
                      : 'Enter the 6-digit code from your authenticator app, or a recovery code (xxxxxxxx-xxxxxxxx).'}
                  </p>
                </div>

                {/* Back to credentials */}
                <button
                  type="button"
                  onClick={backToCredentials}
                  className={`flex items-center gap-1.5 text-xs transition-colors cursor-pointer ${
                    isLight ? 'text-slate-500 hover:text-sky-600' : 'text-slate-400 hover:text-cyan-300'
                  }`}
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>{language === 'zh' ? '返回，重新输入用户名与密码' : 'Back, re-enter username & password'}</span>
                </button>
              </>
            )}

            {/* Keep Signed In Checkbox */}
            <div className="flex items-center gap-2 pt-1">
              <input
                id="keep-signed"
                type="checkbox"
                checked={keepSignedIn}
                onChange={(e) => setKeepSignedIn(e.target.checked)}
                className={`w-4 h-4 rounded cursor-pointer ${
                  isLight
                    ? 'bg-slate-100 border-slate-300 text-sky-600 focus:ring-0 accent-sky-600'
                    : 'bg-slate-900 border-slate-700 text-cyan-400 focus:ring-0 accent-cyan-400'
                }`}
              />
              <label
                htmlFor="keep-signed"
                className={`text-xs cursor-pointer select-none transition-colors ${
                  isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-300 hover:text-white'
                }`}
              >
                {language === 'zh' ? '保持登录 (Keep me signed in)' : 'Keep me signed in'}
              </label>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              className={`w-full h-11 mt-2 font-bold text-sm rounded-xl flex items-center justify-center gap-2 transition-all hover:scale-[1.01] active:scale-[0.99] disabled:opacity-70 cursor-pointer shadow-lg ${
                isLight
                  ? 'bg-gradient-to-r from-sky-600 via-blue-600 to-indigo-600 text-white shadow-sky-500/25 hover:shadow-sky-500/35 hover:brightness-105'
                  : 'bg-gradient-to-r from-cyan-400 via-cyan-500 to-sky-500 text-slate-950 shadow-cyan-500/20 hover:opacity-95'
              }`}
            >
              {isLoading ? (
                <div
                  className={`w-5 h-5 border-2 border-t-transparent rounded-full animate-spin ${
                    isLight ? 'border-white' : 'border-slate-950'
                  }`}
                />
              ) : (
                <>
                  <span>{totpStage ? (language === 'zh' ? '验证' : 'Verify') : (language === 'zh' ? '登录' : 'Sign In')}</span>
                  <span className="text-xs opacity-80 font-normal">
                    {totpStage ? '' : (language === 'zh' ? '(Login)' : '')}
                  </span>
                  <ArrowRight className="w-4 h-4 ml-1" />
                </>
              )}
            </button>
          </form>

          {/* Security Notice Box */}
          <div
            className={`w-full mt-7 p-3.5 rounded-2xl border flex items-start gap-3 text-left transition-colors ${
              isLight
                ? 'bg-sky-50/80 border-sky-200/80'
                : 'bg-slate-950/70 border-slate-800/80'
            }`}
          >
            <ShieldCheck className={`w-5 h-5 shrink-0 mt-0.5 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
            <div className="space-y-1 text-[11px] leading-relaxed">
              <p className={`font-medium ${isLight ? 'text-slate-800' : 'text-slate-300'}`}>
                {language === 'zh'
                  ? '安全提示: 建议仅通过 HTTPS、VPN 或 SSH 隧道访问管理后台，以确保数据传输安全。'
                  : 'Security Tip: Access the admin panel only via HTTPS, VPN, or SSH tunnel.'}
              </p>
              <p className={`text-[10px] ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                {language === 'zh'
                  ? 'Security Tip: Access the admin panel via HTTPS, VPN, or SSH tunnel to ensure data security.'
                  : 'Ensure end-to-end transport layer security during administration.'}
              </p>
            </div>
          </div>
        </div>
      </motion.div>

      {isLogoModalOpen && (
        <LogoCustomizerModal onClose={() => setIsLogoModalOpen(false)} />
      )}
    </div>
  );
};


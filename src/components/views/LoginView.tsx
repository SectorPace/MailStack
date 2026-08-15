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
  ShieldCheck,
  Shield,
  KeyRound,
  Download,
  Palette
} from 'lucide-react';
import { motion } from 'motion/react';
import { login } from '../../api';

export const LoginView: React.FC = () => {
  const { setIsLoggedIn, showToast, language } = useApp();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [keepSignedIn, setKeepSignedIn] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [isLogoModalOpen, setIsLogoModalOpen] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault(); setIsLoading(true);
    try { await login(username,password); setIsLoggedIn(true); showToast('success', language === 'zh' ? '登录成功' : 'Authenticated', language === 'zh' ? '欢迎回到 MailStack 主控制台' : 'Welcome back to MailStack Admin Console'); }
    catch { showToast('error', language === 'zh' ? '登录失败' : 'Login failed', language === 'zh' ? '请检查管理令牌' : 'Check the administration token'); }
    finally { setIsLoading(false); setPassword(''); }
  };

  return (
    <div className="min-h-screen w-full bg-[#050811] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background Cyber Grid Lines */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0c1a2d_1px,transparent_1px),linear-gradient(to_bottom,#0c1a2d_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-40 pointer-events-none" />

      {/* Cyber Glowing Card Frame (Matching Image 1) */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-[440px] rounded-[36px] p-[2px] bg-gradient-to-b from-[#00f2c3] via-[#00a896] to-[#0d223a] shadow-[0_0_50px_rgba(0,242,195,0.25)] relative"
      >
        {/* Top Export Badge */}
        <div className="absolute top-0 right-12 -translate-y-1/2 bg-[#00f2c3] text-slate-950 text-[11px] font-black tracking-widest uppercase px-3.5 py-1 rounded-full shadow-[0_0_15px_#00f2c3] flex items-center gap-1 z-20">
          <Download className="w-3 h-3" />
          <span>EXPORT</span>
        </div>

        {/* Card Body with iOS 27 Liquid Glass depth */}
        <div className="w-full bg-[#080d1a]/90 rounded-[34px] px-8 py-9 flex flex-col items-center relative overflow-hidden backdrop-blur-3xl border border-white/10 shadow-[inset_0_2px_2px_rgba(255,255,255,0.35),inset_0_-2px_4px_rgba(0,242,195,0.12)]">
          {/* iOS 27 Liquid Specular Ray Sheen */}
          <div className="absolute -top-24 -left-24 w-60 h-60 bg-gradient-to-br from-white/20 via-cyan-400/10 to-transparent rounded-full blur-2xl pointer-events-none" />
          
          {/* Top Logo Icon */}
          <div
            onClick={() => setIsLogoModalOpen(true)}
            title={language === 'zh' ? '点击定制/更换 Logo 图标' : 'Click to customize/change Logo'}
            className="mb-4 relative group cursor-pointer"
          >
            <MailStackLogo size="xl" showHoverEffect />
            <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-cyan-400 text-slate-950 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity shadow-[0_0_10px_#00f2c3] scale-90">
              <Palette className="w-3 h-3" />
            </div>
          </div>

          {/* Heading */}
          <h2 className="text-lg font-bold text-white tracking-wide text-center">
            登录管理后台
          </h2>
          <div className="text-xs text-slate-400 font-normal mt-0.5 tracking-wider">
            (Admin Login)
          </div>

          {/* Hostname Indicator */}
          <div className="flex items-center gap-2 mt-4 mb-6 px-3.5 py-1.5 rounded-full bg-slate-900/90 border border-slate-800 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#00f2c3]" />
            <span className="text-slate-400">主机名 (Hostname):</span>
            <span className="text-cyan-300 font-semibold">mail.example.com</span>
          </div>

          {/* Login Form */}
          <form onSubmit={handleLogin} className="w-full space-y-4">
            {/* Username Input */}
            <div>
              <label className="block text-[11px] font-mono uppercase tracking-wider text-slate-300 mb-1.5">
                用户名 (USERNAME)
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-900/90 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono"
                  placeholder="admin"
                  required
                />
              </div>
            </div>

            {/* Password Input */}
            <div>
              <label className="block text-[11px] font-mono uppercase tracking-wider text-slate-300 mb-1.5">
                管理口令 (PASSWORD)
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <KeyRound className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-10 py-2.5 bg-slate-900/90 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono"
                  placeholder="••••••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-400 hover:text-slate-200"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Keep Signed In Checkbox */}
            <div className="flex items-center gap-2 pt-1">
              <input
                id="keep-signed"
                type="checkbox"
                checked={keepSignedIn}
                onChange={(e) => setKeepSignedIn(e.target.checked)}
                className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-cyan-400 focus:ring-0 focus:ring-offset-0 cursor-pointer accent-[#00f2c3]"
              />
              <label
                htmlFor="keep-signed"
                className="text-xs text-slate-300 cursor-pointer select-none"
              >
                保持登录 (Keep me signed in)
              </label>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full h-11 mt-2 bg-gradient-to-r from-cyan-300 via-cyan-400 to-sky-300 text-slate-950 font-bold text-sm rounded-xl flex items-center justify-center gap-2 hover:shadow-[0_0_20px_rgba(0,242,195,0.4)] transition-all hover:scale-[1.01] active:scale-[0.99] disabled:opacity-70 cursor-pointer"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
              ) : (
                <>
                  <span>登录</span>
                  <span className="text-xs opacity-75 font-normal">(Login)</span>
                  <ArrowRight className="w-4 h-4 ml-1" />
                </>
              )}
            </button>
          </form>

          {/* Security Notice Box (Matching Bottom of Image 1) */}
          <div className="w-full mt-7 p-3.5 rounded-2xl bg-slate-950/70 border border-slate-800/80 flex items-start gap-3 text-left">
            <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
            <div className="space-y-1 text-[11px] leading-relaxed text-slate-400">
              <p className="text-slate-300 font-medium">
                安全提示: 建议仅通过 HTTPS、VPN 或 SSH 隧道访问管理后台，以确保数据传输安全。
              </p>
              <p className="text-[10px] text-slate-400">
                Security Tip: It is recommended to access the admin panel only via HTTPS, VPN, or SSH tunnel to ensure data transmission security.
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

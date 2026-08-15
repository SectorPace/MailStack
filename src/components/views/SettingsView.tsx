import React, { useState } from 'react';
import { AdminAccountSettings } from './AdminAccountSettings';
import { useApp } from '../../context/AppContext';
import { MailStackLogo } from '../common/MailStackLogo';
import { LogoCustomizerModal } from '../modals/LogoCustomizerModal';
import { BackgroundCustomizerModal } from '../modals/BackgroundCustomizerModal';
import {
  Settings,
  Sliders,
  Eye,
  Sparkles,
  Download,
  RefreshCw,
  Shield,
  Save,
  CheckCircle2,
  Palette,
  Image,
  Compass,
  ArrowRight,
  Zap,
  Layers,
  Wand2
} from 'lucide-react';

export const SettingsView: React.FC = () => {
  const {
    settings,
    updateSettings,
    language,
    showToast,
    logoStyle,
    customLogo,
    themeMode,
    setCurrentSection,
    setIsOnboardingModalOpen,
    backgroundConfig,
  } = useApp();
  const [isLogoModalOpen, setIsLogoModalOpen] = useState(false);
  const [isBgModalOpen, setIsBgModalOpen] = useState(false);

  const handleBackup = () => {
    showToast('success', language === 'zh' ? '备份生成完成' : 'Backup Generated', `mailstack-config-backup-${Date.now()}.tar.gz (${language === 'zh' ? '已保存至本地' : 'saved to local'})`);
  };

  const handleManualSave = () => {
    showToast('success', language === 'zh' ? '设置已保存' : 'Settings Saved', language === 'zh' ? '所有系统参数与外观配置已实时生效' : 'All parameters and styling synced');
  };

  const isLight = themeMode === 'light';

  const getBgPresetName = () => {
    switch (backgroundConfig.preset) {
      case 'aurora_cyan':
        return language === 'zh' ? '极光青蓝 (Aurora Cyan)' : 'Aurora Cyan';
      case 'purple_velvet':
        return language === 'zh' ? '紫晶幻夜 (Purple Velvet)' : 'Purple Velvet';
      case 'matrix_cyber':
        return language === 'zh' ? '赛博矩阵 (Matrix Emerald)' : 'Matrix Emerald';
      case 'minimal_slate':
        return language === 'zh' ? '极简冷灰 (Minimal Slate)' : 'Minimal Slate';
      case 'warm_pearl':
        return language === 'zh' ? '珍珠柔光 (Warm Pearl)' : 'Warm Pearl';
      case 'custom_image':
        return language === 'zh' ? '自定义图片壁纸 (Custom)' : 'Custom Wallpaper';
      case 'default':
      default:
        return language === 'zh' ? '深空流光 (Default)' : 'Deep Space';
    }
  };

  return (
    <div id="settings-view-container" className="p-6 space-y-6 max-w-4xl mx-auto font-sans">
      {/* Top Header */}
      <div className={`p-6 rounded-2xl liquid-glass-card flex items-center justify-between transition-all ${
        isLight ? 'bg-white/90 border-white/90 shadow-[0_10px_30px_rgba(0,0,0,0.04)]' : ''
      }`}>
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
            isLight
              ? 'bg-sky-500/10 border border-sky-500/25 text-sky-600'
              : 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-400'
          }`}>
            <Settings className="w-5 h-5" />
          </div>
          <div>
            <h3 className={`text-base font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {language === 'zh' ? '系统参数与外观配置' : 'System Settings & Appearance'}
            </h3>
            <p className={`text-xs ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              {language === 'zh' ? '个性化管理控制台的视觉效果与交互 (Customize console visual effects)' : 'Customize console appearance and mail daemon parameters'}
            </p>
          </div>
        </div>

        <button
          onClick={handleManualSave}
          className={`h-10 px-4 rounded-xl font-bold text-xs flex items-center gap-2 transition-all cursor-pointer shadow-md ${
            isLight
              ? 'bg-sky-600 hover:bg-sky-500 text-white shadow-sky-600/20'
              : 'bg-cyan-400 hover:bg-cyan-300 text-slate-950 shadow-[0_0_15px_rgba(0,242,195,0.25)]'
          }`}
        >
          <Save className="w-4 h-4" />
          <span>{language === 'zh' ? '保存更改' : 'Save Changes'}</span>
        </button>
      </div>

      {/* NEW: Secondary Menu Entry Point - Add Configuration Guide (添加配置引导) */}
      <div className={`p-6 rounded-2xl liquid-glass-card space-y-4 border transition-all ${
        isLight
          ? 'bg-gradient-to-r from-sky-50/90 to-cyan-50/90 border-sky-200 shadow-sm'
          : 'bg-gradient-to-r from-cyan-950/20 via-slate-900/60 to-blue-950/20 border-cyan-500/30 shadow-[0_0_20px_rgba(0,242,195,0.08)]'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className={`w-11 h-11 rounded-2xl flex items-center justify-center shrink-0 ${
              isLight
                ? 'bg-sky-600 text-white shadow-md'
                : 'bg-gradient-to-tr from-cyan-400 to-blue-500 text-slate-950 font-bold shadow-[0_0_15px_rgba(0,242,195,0.3)]'
            }`}>
              <Compass className="w-6 h-6 animate-spin-slow" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className={`text-sm font-bold tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  {language === 'zh' ? '添加配置引导 (配置向导)' : 'Add Configuration Guide (Setup Wizard)'}
                </h4>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-400/20 text-cyan-400 border border-cyan-400/30">
                  WIZARD
                </span>
              </div>
              <p className={`text-xs mt-1 max-w-xl ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                {language === 'zh'
                  ? '引导添加新的邮件域名、配置权威 DNS 防伪解析、出站中继策略及 TLS 证书签发。适合在日常运维中为新业务开通邮箱。'
                  : 'Step-by-step wizard to register new mail domains, configure DNS security matrix, setup outbound relays, and issue TLS certs.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setCurrentSection('setup_guide')}
              className={`px-4 py-2.5 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-md ${
                isLight
                  ? 'bg-sky-600 hover:bg-sky-500 text-white'
                  : 'bg-cyan-400 hover:bg-cyan-300 text-slate-950 shadow-[0_0_15px_rgba(0,242,195,0.3)]'
              }`}
            >
              <Wand2 className="w-4 h-4" />
              <span>{language === 'zh' ? '启动添加配置引导' : 'Launch Config Wizard'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* NEW: Custom System Background & Wallpaper Section */}
      <div className={`p-6 rounded-2xl liquid-glass-card space-y-4 transition-all ${
        isLight ? 'bg-white/90 border-white/90' : ''
      }`}>
        <div className={`flex items-center justify-between border-b pb-3 ${
          isLight ? 'border-slate-200' : 'border-white/10'
        }`}>
          <div className={`flex items-center gap-2 text-sm font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
            <Palette className={`w-4 h-4 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
            <span>{language === 'zh' ? '自定义系统背景与壁纸 (Custom Wallpaper)' : 'System Background & Wallpaper'}</span>
          </div>

          <button
            onClick={() => setIsBgModalOpen(true)}
            className={`px-3.5 py-1.5 rounded-xl font-bold text-xs flex items-center gap-1.5 shadow-sm transition-all cursor-pointer ${
              isLight
                ? 'bg-sky-600 hover:bg-sky-500 text-white'
                : 'bg-cyan-400 hover:bg-cyan-300 text-slate-950'
            }`}
          >
            <Image className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '切换背景主题 / 上传壁纸' : 'Change Background / Upload Wallpaper'}</span>
          </button>
        </div>

        <div className={`flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl border ${
          isLight
            ? 'bg-slate-50/80 border-slate-200/80'
            : 'bg-slate-950/80 border-slate-800/80'
        }`}>
          <div className="flex items-center gap-4">
            <div
              onClick={() => setIsBgModalOpen(true)}
              className="w-16 h-12 rounded-xl border border-white/20 shadow-md cursor-pointer hover:scale-105 transition-transform flex items-center justify-center relative overflow-hidden bg-cover bg-center"
              style={{
                backgroundImage:
                  backgroundConfig.preset === 'custom_image' && backgroundConfig.customImageUrl
                    ? `url(${backgroundConfig.customImageUrl})`
                    : undefined,
                background:
                  backgroundConfig.preset !== 'custom_image'
                    ? 'linear-gradient(135deg, #041019, #02313d, #00f2c3)'
                    : undefined,
              }}
            >
              <Palette className="w-5 h-5 text-white/90 drop-shadow" />
            </div>
            <div>
              <div className={`text-sm font-bold flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                <span>{getBgPresetName()}</span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                  isLight
                    ? 'bg-sky-50 text-sky-700 border-sky-200'
                    : 'bg-cyan-400/20 text-cyan-400 border-cyan-400/30'
                }`}>
                  {backgroundConfig.preset.toUpperCase()}
                </span>
              </div>
              <p className={`text-xs mt-1 max-w-md ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                {language === 'zh'
                  ? `遮罩深度: ${backgroundConfig.overlayOpacity}% | 高斯模糊: ${backgroundConfig.blur}px (点击右上方按钮可随心定制)`
                  : `Opacity: ${backgroundConfig.overlayOpacity}% | Blur: ${backgroundConfig.blur}px`}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Section 0: Brand Logo Customization */}
      <div className={`p-6 rounded-2xl liquid-glass-card space-y-4 transition-all ${
        isLight ? 'bg-white/90 border-white/90' : ''
      }`}>
        <div className={`flex items-center justify-between border-b pb-3 ${
          isLight ? 'border-slate-200' : 'border-white/10'
        }`}>
          <div className={`flex items-center gap-2 text-sm font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
            <Palette className={`w-4 h-4 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
            <span>{language === 'zh' ? '品牌 Logo 与图标设置 (Brand Logo)' : 'Brand Logo & Icon'}</span>
          </div>

          <button
            onClick={() => setIsLogoModalOpen(true)}
            className={`px-3.5 py-1.5 rounded-xl font-bold text-xs flex items-center gap-1.5 shadow-sm transition-all cursor-pointer ${
              isLight
                ? 'bg-sky-600 hover:bg-sky-500 text-white'
                : 'bg-cyan-400 hover:bg-cyan-300 text-slate-950'
            }`}
          >
            <Image className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '上传原图 / 切换渲染预设' : 'Upload Image / Change Style'}</span>
          </button>
        </div>

        <div className={`flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl border ${
          isLight
            ? 'bg-slate-50/80 border-slate-200/80'
            : 'bg-slate-950/80 border-slate-800/80'
        }`}>
          <div className="flex items-center gap-4">
            <MailStackLogo size="xl" showHoverEffect onClick={() => setIsLogoModalOpen(true)} />
            <div>
              <div className={`text-sm font-bold flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                <span>{customLogo ? (language === 'zh' ? '自定义上传图片 Logo' : 'Custom Uploaded Logo') : (language === 'zh' ? '3D 晶莹分层邮件堆栈 (重构版)' : '3D Glass Layered Stack')}</span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                  isLight
                    ? 'bg-sky-50 text-sky-700 border-sky-200'
                    : 'bg-cyan-400/20 text-cyan-400 border-cyan-400/30'
                }`}>
                  {customLogo ? 'CUSTOM IMAGE' : logoStyle.toUpperCase()}
                </span>
              </div>
              <p className={`text-xs mt-1 max-w-md ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                {language === 'zh'
                  ? '三层递进透光亚克力堆叠与高光折痕，可直接上传您本地的 PNG/SVG 图片进行完美替换。'
                  : 'Three-tier translucent acrylic layered stack with specular reflections. You can also upload your own PNG/SVG image.'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Section 1: Appearance */}
      <div className={`p-6 rounded-2xl liquid-glass-card space-y-5 transition-all ${
        isLight ? 'bg-white/90 border-white/90' : ''
      }`}>
        <div className={`flex items-center gap-2 text-sm font-bold border-b pb-3 ${
          isLight ? 'text-slate-900 border-slate-200' : 'text-white border-white/10'
        }`}>
          <Sliders className={`w-4 h-4 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
          <span>{language === 'zh' ? '界面设置 (Appearance)' : 'Appearance & Glassmorphism'}</span>
        </div>

        <div className="space-y-5">
          {/* Slider 1: Transparency */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className={`font-medium ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
                {language === 'zh' ? '背景透明度 (Transparency)' : 'Card Transparency'}
              </span>
              <span className={`font-mono font-bold ${isLight ? 'text-sky-600' : 'text-cyan-400'}`}>
                {settings.transparency}%
              </span>
            </div>
            <input
              type="range"
              min="20"
              max="100"
              value={settings.transparency}
              onChange={(e) => updateSettings({ transparency: Number(e.target.value) })}
              className="w-full cursor-pointer"
            />
          </div>

          {/* Slider 2: Blur */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className={`font-medium ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
                {language === 'zh' ? '模糊半径 (Backdrop Blur)' : 'Backdrop Blur Radius'}
              </span>
              <span className={`font-mono font-bold ${isLight ? 'text-sky-600' : 'text-cyan-400'}`}>
                {settings.backdropBlur}px
              </span>
            </div>
            <input
              type="range"
              min="0"
              max="32"
              value={settings.backdropBlur}
              onChange={(e) => updateSettings({ backdropBlur: Number(e.target.value) })}
              className="w-full cursor-pointer"
            />
          </div>

          {/* Toggle 1: Reduced Motion */}
          <div className="flex items-center justify-between pt-2">
            <div>
              <div className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-white'}`}>
                {language === 'zh' ? '减少动态效果 (Reduced Motion)' : 'Reduced Motion'}
              </div>
              <div className={`text-[11px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                {language === 'zh' ? '关闭部分呼吸发光与流光过渡动画' : 'Disable non-essential ambient animations'}
              </div>
            </div>
            <input
              type="checkbox"
              checked={settings.reducedMotion}
              onChange={(e) => updateSettings({ reducedMotion: e.target.checked })}
              className={`w-5 h-5 rounded cursor-pointer ${
                isLight ? 'accent-sky-600' : 'accent-[#00f2c3]'
              }`}
            />
          </div>

          {/* Toggle 2: Auto Update */}
          <div className={`flex items-center justify-between pt-2 border-t ${
            isLight ? 'border-slate-200' : 'border-white/10'
          }`}>
            <div>
              <div className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-white'}`}>
                {language === 'zh' ? '自动更新系统 (Auto Update)' : 'Automatic Security Updates'}
              </div>
              <div className={`text-[11px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                {language === 'zh' ? '自动下载并应用 Postfix & Dovecot 紧急安全补丁' : 'Automatically patch critical vulnerabilities'}
              </div>
            </div>
            <input
              type="checkbox"
              checked={settings.autoUpdate}
              onChange={(e) => updateSettings({ autoUpdate: e.target.checked })}
              className={`w-5 h-5 rounded cursor-pointer ${
                isLight ? 'accent-sky-600' : 'accent-[#00f2c3]'
              }`}
            />
          </div>
        </div>
      </div>

      {/* Section 2: Mail Server Daemon Parameters */}
      <div className={`p-6 rounded-2xl liquid-glass-card space-y-4 font-mono text-xs transition-all ${
        isLight ? 'bg-white/90 border-white/90' : ''
      }`}>
        <div className={`flex items-center gap-2 text-sm font-bold border-b pb-3 font-sans ${
          isLight ? 'text-slate-900 border-slate-200' : 'text-white border-white/10'
        }`}>
          <Shield className={`w-4 h-4 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
          <span>{language === 'zh' ? '邮件服务器参数 (Daemon Config)' : 'Daemon Configuration'}</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-sans">
          <div>
            <label className={`block mb-1 text-xs font-medium ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              MAIN HOSTNAME (myhostname)
            </label>
            <input
              type="text"
              value={settings.hostname}
              onChange={(e) => updateSettings({ hostname: e.target.value })}
              className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-all font-mono text-xs ${
                isLight
                  ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-sky-600 focus:bg-white'
                  : 'bg-slate-950/80 border-slate-800 text-white focus:border-cyan-400'
              }`}
            />
          </div>

          <div>
            <label className={`block mb-1 text-xs font-medium ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              POSTMASTER EMAIL
            </label>
            <input
              type="text"
              value={settings.adminEmail}
              onChange={(e) => updateSettings({ adminEmail: e.target.value })}
              className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-all font-mono text-xs ${
                isLight
                  ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-sky-600 focus:bg-white'
                  : 'bg-slate-950/80 border-slate-800 text-white focus:border-cyan-400'
              }`}
            />
          </div>

          <div>
            <label className={`block mb-1 text-xs font-medium ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              MAX MESSAGE SIZE (MB)
            </label>
            <input
              type="number"
              value={settings.maxMessageSizeMb}
              onChange={(e) => updateSettings({ maxMessageSizeMb: Number(e.target.value) })}
              className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-all font-mono text-xs ${
                isLight
                  ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-sky-600 focus:bg-white'
                  : 'bg-slate-950/80 border-slate-800 text-white focus:border-cyan-400'
              }`}
            />
          </div>

          <div>
            <label className={`block mb-1 text-xs font-medium ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              RATE LIMIT (EMAILS/HOUR)
            </label>
            <input
              type="number"
              value={settings.rateLimitPerHour}
              onChange={(e) => updateSettings({ rateLimitPerHour: Number(e.target.value) })}
              className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-all font-mono text-xs ${
                isLight
                  ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-sky-600 focus:bg-white'
                  : 'bg-slate-950/80 border-slate-800 text-white focus:border-cyan-400'
              }`}
            />
          </div>
        </div>
      </div>

      <AdminAccountSettings />

      {/* Section 3: Backup & Snapshot */}
      <div className={`p-6 rounded-2xl liquid-glass-card flex flex-wrap items-center justify-between gap-4 transition-all ${
        isLight ? 'bg-white/90 border-white/90' : ''
      }`}>
        <div>
          <div className={`text-sm font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
            {language === 'zh' ? '系统快照与配置备份' : 'Configuration Snapshot & Backup'}
          </div>
          <div className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? '打包所有域名、用户映射、DKIM 密钥与中继路由策略' : 'Archive all domains, credentials, DKIM keys, and routing rules'}
          </div>
        </div>

        <button
          onClick={handleBackup}
          className={`px-4 py-2.5 rounded-xl border text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
            isLight
              ? 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-800'
              : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200'
          }`}
        >
          <Download className={`w-4 h-4 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
          <span>{language === 'zh' ? '生成全量快照备份' : 'Create Snapshot Backup'}</span>
        </button>
      </div>

      {isLogoModalOpen && (
        <LogoCustomizerModal onClose={() => setIsLogoModalOpen(false)} />
      )}

      {isBgModalOpen && (
        <BackgroundCustomizerModal onClose={() => setIsBgModalOpen(false)} />
      )}
    </div>
  );
};

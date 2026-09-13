import React, { useState, useEffect } from 'react';
import { AdminAccountSettings } from './AdminAccountSettings';
import { AiProviderSettings } from './AiProviderSettings';
import { useApp } from '../../context/AppContext';
import { api } from '../../api';
import { getErrorMessage } from '../../utils/errors';
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
  Wand2,
  RotateCcw,
  Trash2,
  FileArchive,
  Lock,
  AlertCircle
} from '@/lib/icons';

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
    saveSettings,
  } = useApp();
  const [isLogoModalOpen, setIsLogoModalOpen] = useState(false);
  const [isBgModalOpen, setIsBgModalOpen] = useState(false);
  const [backupBusy, setBackupBusy] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const [backups, setBackups] = useState<any[]>([]);
  const [includeMails, setIncludeMails] = useState(false);
  const [backupPassphrase, setBackupPassphrase] = useState('');
  const [restoreConfirmModal, setRestoreConfirmModal] = useState<any | null>(null);
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoreBusy, setRestoreBusy] = useState(false);

  const loadBackups = async () => {
    try {
      const list = await api('/api/backups');
      setBackups(Array.isArray(list) ? list : []);
    } catch {
      setBackups([]);
    }
  };

  useEffect(() => {
    loadBackups();
  }, []);

  const handleBackup = async () => {
    setBackupBusy(true);
    try {
      const passphrase = backupPassphrase.trim();
      const res = await api('/api/backups', {
        method: 'POST',
        body: JSON.stringify({ includeMails, ...(passphrase ? { passphrase } : {}) }),
      });
      showToast(
        'success',
        language === 'zh' ? '备份生成完成' : 'Backup Generated',
        res.backup?.name || 'mailstack-backup.tar.gz'
      );
      setBackupPassphrase('');
      loadBackups();
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '备份生成失败' : 'Backup Failed', getErrorMessage(e));
    } finally {
      setBackupBusy(false);
    }
  };

  const handleRestore = async (b: any) => {
    if (b.encrypted && !restorePassphrase.trim()) {
      return showToast(
        'error',
        language === 'zh' ? '需要解密口令' : 'Passphrase Required',
        language === 'zh' ? '该备份已加密，请先输入口令' : 'This backup is encrypted; enter the passphrase first'
      );
    }
    setRestoreBusy(true);
    try {
      const passphrase = restorePassphrase.trim();
      const res = await api('/api/backups/restore', {
        method: 'POST',
        body: JSON.stringify({ filename: b.name, confirm: true, ...(passphrase ? { passphrase } : {}) }),
      });
      showToast(
        'success',
        language === 'zh' ? '备份已成功还原' : 'Backup Restored',
        res.message || '配置已成功恢复并重新载入服务'
      );
      setRestoreConfirmModal(null);
      setRestorePassphrase('');
      loadBackups();
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '还原失败' : 'Restore Failed', getErrorMessage(e));
    } finally {
      setRestoreBusy(false);
    }
  };

  const handleDeleteBackup = async (name: string) => {
    if (!window.confirm(language === 'zh' ? `确认删除备份 ${name} 吗？` : `Delete backup ${name}?`)) return;
    try {
      await api(`/api/backups/${encodeURIComponent(name)}`, {
        method: 'DELETE',
        body: JSON.stringify({ confirm: true }),
      });
      showToast('success', language === 'zh' ? '备份已删除' : 'Backup Deleted', name);
      loadBackups();
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '删除失败' : 'Delete Failed', getErrorMessage(e));
    }
  };

  const handleManualSave = async () => {
    setSaveBusy(true);
    try {
      await saveSettings(settings);
    } catch (e: unknown) {
      console.error('Failed to save settings:', getErrorMessage(e));
    } finally {
      setSaveBusy(false);
    }
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

      <AiProviderSettings />

      {/* Section 3: Disaster Recovery & Full Backup / Restore Table */}
      <div className={`p-6 rounded-2xl liquid-glass-card space-y-4 transition-all ${
        isLight ? 'bg-white/90 border-white/90' : ''
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4 border-slate-700/40">
          <div>
            <div className={`text-sm font-bold flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
              <FileArchive className={`w-4 h-4 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
              <span>{language === 'zh' ? '系统快照与灾备恢复 (Disaster Recovery & Backups)' : 'Disaster Recovery & Backups'}</span>
            </div>
            <div className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              {language === 'zh' ? '完整备份 /etc/mailstack, Postfix, Dovecot, OpenDKIM 配置与邮箱数据' : 'Full archive of configuration sources and mailbox data'}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={includeMails}
                onChange={(e) => setIncludeMails(e.target.checked)}
                className="rounded text-cyan-400 focus:ring-0"
              />
              <span>{language === 'zh' ? '包含邮箱邮件数据 (/var/vmail)' : 'Include Maildir Data'}</span>
            </label>

            <button
              disabled={backupBusy}
              onClick={handleBackup}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-md ${
                isLight
                  ? 'bg-sky-600 hover:bg-sky-500 text-white'
                  : 'bg-cyan-400 hover:bg-cyan-300 text-slate-950 shadow-[0_0_15px_rgba(0,242,195,0.25)]'
              }`}
            >
              <Download className={backupBusy ? "animate-spin w-4 h-4" : "w-4 h-4"} />
              <span>{backupBusy ? (language === 'zh' ? '正在打包...' : 'Backing up...') : (language === 'zh' ? '创建全量备份' : 'Create Backup')}</span>
            </button>
          </div>
        </div>

        {/* Optional at-rest encryption: filled passphrase triggers gpg symmetric
            encryption server-side; cleared immediately after submission. */}
        <div className={`flex flex-col sm:flex-row sm:items-center gap-2 p-3 rounded-xl border ${
          isLight ? 'bg-slate-50/80 border-slate-200/80' : 'bg-slate-950/80 border-slate-800/80'
        }`}>
          <div className="flex items-center gap-2 text-xs shrink-0">
            <Lock className={`w-3.5 h-3.5 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
            <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>
              {language === 'zh' ? '加密口令（可选）' : 'Encryption passphrase (optional)'}
            </span>
          </div>
          <input
            type="password"
            value={backupPassphrase}
            onChange={(e) => setBackupPassphrase(e.target.value)}
            placeholder={language === 'zh' ? '填写后备份将以 GPG AES256 加密，还原时需要同一口令' : 'When set, the archive is GPG AES256 encrypted; the same passphrase restores it'}
            autoComplete="new-password"
            className={`flex-1 px-3 py-2 rounded-lg border focus:outline-none transition-all text-xs ${
              isLight
                ? 'bg-white border-slate-300 text-slate-900 focus:border-sky-600'
                : 'bg-slate-900/80 border-slate-700 text-white focus:border-cyan-400'
            }`}
          />
        </div>

        {backups.length === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500">
            {language === 'zh' ? '暂无历史备份。点击上方按钮可立即创建安全快照。' : 'No backups found. Click above to create one.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800/60 text-slate-400 font-sans">
                  <th className="pb-2 font-medium">{language === 'zh' ? '备份文件名' : 'Archive Name'}</th>
                  <th className="pb-2 font-medium">{language === 'zh' ? '创建时间' : 'Created At'}</th>
                  <th className="pb-2 font-medium">{language === 'zh' ? '文件大小' : 'Size'}</th>
                  <th className="pb-2 font-medium">{language === 'zh' ? '包含邮件' : 'Mails'}</th>
                  <th className="pb-2 font-medium text-right">{language === 'zh' ? '操作' : 'Actions'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/30">
                {backups.map((b) => (
                  <tr key={b.name} className="hover:bg-slate-800/20">
                    <td className="py-2.5 font-bold text-slate-200">
                      <span className="inline-flex items-center gap-1.5">
                        {b.name}
                        {b.encrypted && (
                          <span
                            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 text-[10px] font-bold"
                            title={language === 'zh' ? '已加密备份，还原需要口令' : 'Encrypted backup; restore requires the passphrase'}
                          >
                            <Lock className="w-2.5 h-2.5" />
                            {language === 'zh' ? '加密' : 'ENC'}
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-400 font-sans">{new Date(b.createdAt).toLocaleString()}</td>
                    <td className="py-2.5 text-slate-400">{(b.size / 1024).toFixed(1)} KB</td>
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] ${b.includeMails ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-700/50 text-slate-400'}`}>
                        {b.includeMails ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td className="py-2.5 text-right font-sans">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          disabled={restoreBusy}
                          onClick={() => setRestoreConfirmModal(b)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 transition-all flex items-center gap-1"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>{language === 'zh' ? '还原' : 'Restore'}</span>
                        </button>
                        <button
                          onClick={() => handleDeleteBackup(b.name)}
                          className="p-1 rounded-lg text-red-400 hover:bg-red-500/20 transition-all"
                          title={language === 'zh' ? '删除' : 'Delete'}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {restoreConfirmModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 max-w-md w-full space-y-4 shadow-2xl font-sans">
            <div className="flex items-center gap-3 text-amber-400">
              <AlertCircle className="w-6 h-6" />
              <h3 className="font-bold text-base text-white">{language === 'zh' ? '确认从备份还原？' : 'Confirm Backup Restore'}</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {language === 'zh'
                ? `即将还原备份文件「${restoreConfirmModal.name}」。系统将在还原前自动生成安全回滚快照，并重新载入邮件服务。`
                : `Restoring from "${restoreConfirmModal.name}". A safety rollback snapshot will be created automatically.`}
            </p>
            {restoreConfirmModal.encrypted && (
              <div className="space-y-1.5">
                <label className="text-xs text-cyan-300 flex items-center gap-1.5 font-semibold">
                  <Lock className="w-3.5 h-3.5" />
                  {language === 'zh' ? '该备份已加密，请输入解密口令' : 'This backup is encrypted; enter the passphrase'}
                </label>
                <input
                  type="password"
                  value={restorePassphrase}
                  onChange={(e) => setRestorePassphrase(e.target.value)}
                  placeholder={language === 'zh' ? '解密口令' : 'Decryption passphrase'}
                  autoComplete="off"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-white text-xs focus:outline-none focus:border-cyan-400"
                />
              </div>
            )}
            <div className="flex items-center justify-end gap-3 pt-2 border-t border-slate-800">
              <button
                onClick={() => { setRestoreConfirmModal(null); setRestorePassphrase(''); }}
                className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white"
              >
                {language === 'zh' ? '取消' : 'Cancel'}
              </button>
              <button
                disabled={restoreBusy || (restoreConfirmModal.encrypted && !restorePassphrase.trim())}
                onClick={() => handleRestore(restoreConfirmModal)}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-amber-500 hover:bg-amber-400 text-slate-950 flex items-center gap-2 shadow-lg disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <RotateCcw className={restoreBusy ? "animate-spin w-3.5 h-3.5" : "w-3.5 h-3.5"} />
                <span>{restoreBusy ? (language === 'zh' ? '正在还原...' : 'Restoring...') : (language === 'zh' ? '立即确认还原' : 'Confirm Restore')}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {isLogoModalOpen && (
        <LogoCustomizerModal onClose={() => setIsLogoModalOpen(false)} />
      )}

      {isBgModalOpen && (
        <BackgroundCustomizerModal onClose={() => setIsBgModalOpen(false)} />
      )}
    </div>
  );
};

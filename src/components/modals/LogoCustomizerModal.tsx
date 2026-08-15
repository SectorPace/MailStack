import React, { useState, useRef } from 'react';
import { useApp } from '../../context/AppContext';
import { MailStackLogo } from '../common/MailStackLogo';
import {
  X,
  Upload,
  Image as ImageIcon,
  Sparkles,
  Check,
  RotateCcw,
  Layers,
  Zap,
  Sliders,
  Sun,
  Moon
} from 'lucide-react';
import { motion } from 'motion/react';

interface Props {
  onClose: () => void;
}

export const LogoCustomizerModal: React.FC<Props> = ({ onClose }) => {
  const {
    customLogo,
    setCustomLogo,
    logoStyle,
    setLogoStyle,
    themeMode,
    language,
    showToast
  } = useApp();

  const [previewStyle, setPreviewStyle] = useState(logoStyle);
  const [previewCustomUrl, setPreviewCustomUrl] = useState(customLogo);
  const [urlInput, setUrlInput] = useState('');
  const [previewTheme, setPreviewTheme] = useState<'light' | 'dark'>(themeMode);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      showToast(
        'error',
        language === 'zh' ? '文件格式错误' : 'Invalid File',
        language === 'zh' ? '请选择图片文件 (PNG, JPG, SVG, WebP)' : 'Please select an image file'
      );
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      setPreviewCustomUrl(result);
      setPreviewStyle('custom');
      showToast(
        'info',
        language === 'zh' ? '图片已读取' : 'Image Loaded',
        language === 'zh' ? '点击下方保存以应用' : 'Click Save to apply changes'
      );
    };
    reader.readAsDataURL(file);
  };

  const handleApplyUrl = () => {
    if (!urlInput.trim()) return;
    setPreviewCustomUrl(urlInput.trim());
    setPreviewStyle('custom');
    setUrlInput('');
  };

  const handleSave = () => {
    if (previewStyle === 'custom' && previewCustomUrl) {
      setCustomLogo(previewCustomUrl);
      setLogoStyle('custom');
    } else {
      setLogoStyle(previewStyle);
      if (previewStyle !== 'custom') {
        setCustomLogo('');
      }
    }

    showToast(
      'success',
      language === 'zh' ? 'Logo 样式已更新' : 'Logo Updated',
      language === 'zh' ? '已全局应用至导航栏、登录页及系统各视图' : 'Applied to sidebar, login & system views'
    );
    onClose();
  };

  const handleResetToDefault = () => {
    setPreviewCustomUrl('');
    setPreviewStyle('3d_glass');
    setCustomLogo('');
    setLogoStyle('3d_glass');
    showToast(
      'info',
      language === 'zh' ? '已恢复默认' : 'Reset to Default',
      language === 'zh' ? '已切换至 3D 晶莹分层邮件堆栈图标' : 'Switched to 3D Glass Layered Stack'
    );
    onClose();
  };

  const styleOptions: {
    id: '3d_glass' | 'neon_cyber' | 'minimal_clean';
    nameZh: string;
    nameEn: string;
    descZh: string;
    descEn: string;
  }[] = [
    {
      id: '3d_glass',
      nameZh: '3D 晶莹分层邮件堆栈 (官方重构版)',
      nameEn: '3D Glass Layered Stack (Refined)',
      descZh: '立体三层递进卡片堆叠，通透亚克力微光与电光折痕，真实还原 DALL-E 原画质感',
      descEn: 'Three-tier layered perspective stack with translucent acrylic glow & specular arc',
    },
    {
      id: 'neon_cyber',
      nameZh: '赛博霓虹全息 (Cyber Neon)',
      nameEn: 'Cyber Neon Hologram',
      descZh: '高对比度矩阵荧光色调，线框全息与数据信号点阵',
      descEn: 'High-contrast glowing wireframe envelope with matrix data pulse',
    },
    {
      id: 'minimal_clean',
      nameZh: '极简几何矢量 (Minimalist)',
      nameEn: 'Minimalist Pure Vector',
      descZh: '克制干净的几何轮廓，适合商务与严肃企业环境',
      descEn: 'Clean continuous curves for corporate enterprise aesthetics',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-md">
      <div className="fixed inset-0" onClick={onClose} />

      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 10 }}
        className={`w-full max-w-xl border rounded-3xl shadow-2xl overflow-hidden relative z-10 flex flex-col max-h-[90vh] font-sans ${
          themeMode === 'light'
            ? 'bg-white border-slate-200 text-slate-900'
            : 'bg-slate-900 border-slate-700/80 text-white'
        }`}
      >
        {/* Header */}
        <div className={`px-6 py-4 border-b flex items-center justify-between ${
          themeMode === 'light' ? 'bg-slate-50/90 border-slate-200' : 'bg-slate-950/80 border-slate-800'
        }`}>
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${
              themeMode === 'light'
                ? 'bg-cyan-50 border-cyan-200 text-cyan-700 shadow-sm'
                : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
            }`}>
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h3 className={`text-base font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                {language === 'zh' ? 'MailStack 品牌 Logo 与图标定制' : 'Brand Logo Customizer'}
              </h3>
              <p className={`text-xs ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                {language === 'zh'
                  ? '上传本地原图、直接替换或切换高精 3D 渲染样式'
                  : 'Upload your original image or switch preset 3D rendering styles'}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className={`p-1.5 rounded-lg transition-colors cursor-pointer ${
              themeMode === 'light' ? 'text-slate-400 hover:text-slate-700 hover:bg-slate-200' : 'text-slate-400 hover:text-white'
            }`}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* Live Preview Box */}
          <div className={`p-5 rounded-2xl border text-center space-y-3 relative ${
            previewTheme === 'light'
              ? 'bg-slate-100/90 border-slate-300'
              : 'bg-slate-950 border-slate-800'
          }`}>
            <div className="flex items-center justify-between">
              <span className={`text-[11px] font-mono font-semibold uppercase ${
                previewTheme === 'light' ? 'text-slate-700' : 'text-slate-400'
              }`}>
                {language === 'zh' ? '实时预览 (LIVE PREVIEW)' : 'LIVE PREVIEW'}
              </span>

              {/* Theme Toggle Button */}
              <button
                type="button"
                onClick={() => setPreviewTheme(previewTheme === 'light' ? 'dark' : 'light')}
                className={`px-2.5 py-1 rounded-lg border text-[10px] font-mono flex items-center gap-1.5 cursor-pointer transition-colors ${
                  previewTheme === 'light'
                    ? 'bg-white border-slate-300 text-slate-700 hover:bg-slate-50 shadow-sm'
                    : 'bg-slate-900 border-slate-700 text-slate-300 hover:text-white'
                }`}
              >
                {previewTheme === 'light' ? <Sun className="w-3 h-3 text-amber-500" /> : <Moon className="w-3 h-3 text-cyan-400" />}
                <span>{previewTheme.toUpperCase()} MODE</span>
              </button>
            </div>

            {/* Logo Preview Stage */}
            <div className="flex items-center justify-center gap-6 py-2">
              <div className="flex flex-col items-center gap-1.5">
                {previewStyle === 'custom' && previewCustomUrl ? (
                  <div className={`w-16 h-16 p-1 rounded-2xl border flex items-center justify-center shadow-lg ${
                    previewTheme === 'light'
                      ? 'bg-white border-sky-200'
                      : 'bg-slate-900 border-cyan-500/40'
                  }`}>
                    <img src={previewCustomUrl} alt="Preview" className="w-full h-full object-contain rounded-xl" />
                  </div>
                ) : (
                  <MailStackLogo size="xl" theme={previewTheme} />
                )}
                <span className={`text-[10px] font-mono ${previewTheme === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                  Large (64px)
                </span>
              </div>

              <div className="flex flex-col items-center gap-1.5">
                {previewStyle === 'custom' && previewCustomUrl ? (
                  <div className={`w-10 h-10 p-0.5 rounded-xl border flex items-center justify-center shadow-md ${
                    previewTheme === 'light'
                      ? 'bg-white border-sky-200'
                      : 'bg-slate-900 border-cyan-500/40'
                  }`}>
                    <img src={previewCustomUrl} alt="Preview" className="w-full h-full object-contain rounded-lg" />
                  </div>
                ) : (
                  <MailStackLogo size="md" theme={previewTheme} />
                )}
                <span className={`text-[10px] font-mono ${previewTheme === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                  Sidebar (40px)
                </span>
              </div>
            </div>
          </div>

          {/* Section 1: Upload Your Custom Logo Image */}
          <div className={`p-4 rounded-2xl border space-y-3 ${
            themeMode === 'light' ? 'bg-cyan-50/60 border-cyan-200' : 'bg-cyan-950/20 border-cyan-500/30'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Upload className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                <span className={`font-bold font-sans text-xs ${
                  themeMode === 'light' ? 'text-slate-900' : 'text-white'
                }`}>
                  {language === 'zh' ? '上传您的专属 Logo 图片文件' : 'Upload Your Own Logo File'}
                </span>
              </div>
              <span className="text-[10px] text-cyan-700 dark:text-cyan-300 font-mono">
                PNG / JPG / SVG
              </span>
            </div>

            <p className={`text-[11px] ${themeMode === 'light' ? 'text-slate-600' : 'text-slate-400'}`}>
              {language === 'zh'
                ? '若您已拥有设计好的 Logo 原图，点击上传即可无缝替换系统全局图标：'
                : 'Upload your original logo image to replace the system icon across all views:'}
            </p>

            <div className="flex flex-wrap items-center gap-3">
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/svg+xml,image/webp"
                onChange={handleFileUpload}
                className="hidden"
              />

              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-sm transition-all cursor-pointer hover:scale-[1.02]"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>{language === 'zh' ? '选择本地文件上传...' : 'Select Local File...'}</span>
              </button>

              {previewCustomUrl && (
                <button
                  type="button"
                  onClick={() => {
                    setPreviewCustomUrl('');
                    setPreviewStyle('3d_glass');
                  }}
                  className={`px-3 py-2 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                    themeMode === 'light'
                      ? 'bg-white hover:bg-slate-100 text-rose-600 border-slate-300'
                      : 'bg-slate-800 hover:bg-slate-700 text-rose-400 border-slate-700'
                  }`}
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>{language === 'zh' ? '移除自定义图片' : 'Remove Image'}</span>
                </button>
              )}
            </div>

            {/* Paste URL */}
            <div className="pt-2 border-t border-cyan-200/60 dark:border-cyan-800/40">
              <label className={`block text-[11px] font-mono mb-1 ${
                themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
              }`}>
                {language === 'zh' ? '或输入网络图片 URL / Base64' : 'Or Paste Image URL'}
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://example.com/my-logo.png"
                  className={`flex-1 px-3 py-1.5 rounded-xl border focus:outline-none text-xs font-mono ${
                    themeMode === 'light'
                      ? 'bg-white border-slate-300 text-slate-900 focus:border-cyan-500'
                      : 'bg-slate-900 border-slate-700 text-white focus:border-cyan-400'
                  }`}
                />
                <button
                  type="button"
                  onClick={handleApplyUrl}
                  disabled={!urlInput.trim()}
                  className="px-3 py-1.5 rounded-xl bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-white font-semibold text-xs cursor-pointer"
                >
                  {language === 'zh' ? '载入' : 'Load'}
                </button>
              </div>
            </div>
          </div>

          {/* Section 2: Preset Built-in Vector Styles */}
          <div className="space-y-2.5">
            <label className={`block font-semibold font-mono uppercase tracking-wider ${
              themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
            }`}>
              {language === 'zh' ? '或选择重构的内置矢量渲染预设' : 'OR SELECT BUILT-IN 3D PRESET'}
            </label>

            <div className="space-y-2">
              {styleOptions.map((opt) => {
                const isSelected = previewStyle === opt.id && !previewCustomUrl;
                return (
                  <div
                    key={opt.id}
                    onClick={() => {
                      setPreviewStyle(opt.id);
                      setPreviewCustomUrl('');
                    }}
                    className={`p-3.5 rounded-2xl border transition-all cursor-pointer flex items-center justify-between gap-4 ${
                      isSelected
                        ? themeMode === 'light'
                          ? 'bg-cyan-50/80 border-cyan-400 shadow-sm ring-1 ring-cyan-300'
                          : 'bg-cyan-950/50 border-cyan-500/60 shadow-[0_0_15px_rgba(0,242,195,0.15)] ring-1 ring-cyan-500/40'
                        : themeMode === 'light'
                        ? 'bg-white border-slate-200 hover:bg-slate-50'
                        : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-5 h-5 rounded-full border flex items-center justify-center shrink-0 ${
                        isSelected
                          ? 'bg-cyan-400 border-cyan-400 text-slate-950'
                          : themeMode === 'light' ? 'border-slate-300' : 'border-slate-700'
                      }`}>
                        {isSelected && <Check className="w-3 h-3 stroke-[3]" />}
                      </div>
                      <div>
                        <div className={`font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                          {language === 'zh' ? opt.nameZh : opt.nameEn}
                        </div>
                        <div className={`text-[11px] ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                          {language === 'zh' ? opt.descZh : opt.descEn}
                        </div>
                      </div>
                    </div>

                    <div className="shrink-0">
                      <MailStackLogo size="sm" theme={previewTheme} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className={`px-6 py-4 border-t flex items-center justify-between gap-3 ${
          themeMode === 'light' ? 'bg-slate-50/90 border-slate-200' : 'bg-slate-950/80 border-slate-800'
        }`}>
          <button
            type="button"
            onClick={handleResetToDefault}
            className={`px-3 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
              themeMode === 'light'
                ? 'text-slate-600 hover:text-slate-900 hover:bg-slate-200'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '重置为默认 3D 渲染' : 'Reset to Default 3D'}</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className={`px-4 py-2 rounded-xl border text-xs font-semibold transition-colors cursor-pointer ${
                themeMode === 'light'
                  ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
              }`}
            >
              {language === 'zh' ? '取消' : 'Cancel'}
            </button>

            <button
              type="button"
              onClick={handleSave}
              className="px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-400 to-sky-400 hover:from-cyan-300 hover:to-sky-300 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all cursor-pointer hover:scale-[1.02]"
            >
              <Check className="w-4 h-4" />
              <span>{language === 'zh' ? '保存并全局应用' : 'Save & Apply Globally'}</span>
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

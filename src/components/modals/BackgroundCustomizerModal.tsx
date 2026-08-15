import React, { useState, useRef } from 'react';
import { useApp } from '../../context/AppContext';
import { BackgroundPreset, BackgroundConfig } from '../../types';
import {
  Sparkles,
  Image as ImageIcon,
  Upload,
  Link,
  Sliders,
  RotateCcw,
  Check,
  X,
  Palette,
  Eye,
  CheckCircle2
} from 'lucide-react';
import { LiquidGlass } from '../common/LiquidGlass';

export const BackgroundCustomizerModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const { backgroundConfig, updateBackgroundConfig, resetBackgroundConfig, language, themeMode, showToast } =
    useApp();
  const isLight = themeMode === 'light';

  const [tempConfig, setTempConfig] = useState<BackgroundConfig>({ ...backgroundConfig });
  const [imageUrlInput, setImageUrlInput] = useState(backgroundConfig.customImageUrl || '');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const presets: { id: BackgroundPreset; nameZh: string; nameEn: string; colorPreview: string; descZh: string }[] = [
    {
      id: 'default',
      nameZh: '深空流光 (Default)',
      nameEn: 'Deep Cosmic Flow',
      colorPreview: 'from-[#050811] via-[#041d27] to-[#060913]',
      descZh: '经典高品质暗夜深空与微弱青光流转',
    },
    {
      id: 'aurora_cyan',
      nameZh: '极光青蓝 (Aurora Cyan)',
      nameEn: 'Aurora Cyan Glow',
      colorPreview: 'from-[#041019] via-[#02313d] to-[#00f2c3]/20',
      descZh: '清透赛博青与多重流体漫射光',
    },
    {
      id: 'purple_velvet',
      nameZh: '紫晶幻夜 (Purple Velvet)',
      nameEn: 'Purple Velvet Twilight',
      colorPreview: 'from-[#0b0717] via-[#2e1065] to-[#7c3aed]/20',
      descZh: '深邃暗夜与天鹅绒紫氖辉光',
    },
    {
      id: 'matrix_cyber',
      nameZh: '赛博矩阵 (Matrix Emerald)',
      nameEn: 'Matrix Emerald Cyber',
      colorPreview: 'from-[#02120e] via-[#064e3b] to-[#10b981]/20',
      descZh: '极客翡翠绿与精密终端氛围',
    },
    {
      id: 'minimal_slate',
      nameZh: '极简冷灰 (Minimal Slate)',
      nameEn: 'Minimal Studio Slate',
      colorPreview: 'from-[#0b0f19] via-[#1e293b] to-[#080c14]',
      descZh: '低调现代的冷碳灰纯净录音室质感',
    },
    {
      id: 'warm_pearl',
      nameZh: '珍珠柔光 (Warm Pearl)',
      nameEn: 'Warm Pearl Light',
      colorPreview: 'from-[#18120b] via-[#451a03] to-[#f59e0b]/20',
      descZh: '温和细腻的暗调琥珀暖光',
    },
    {
      id: 'custom_image',
      nameZh: '自定义图片 / 壁纸 (Custom)',
      nameEn: 'Custom Image Wallpaper',
      colorPreview: 'from-sky-900 via-indigo-900 to-purple-900',
      descZh: '上传本地高清图片或输入壁纸 URL',
    },
  ];

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (file.size > 8 * 1024 * 1024) {
        showToast('error', language === 'zh' ? '图片过大' : 'Image too large', language === 'zh' ? '请选择 8MB 以下的图片' : 'Max file size 8MB');
        return;
      }
      const reader = new FileReader();
      reader.onload = (event) => {
        const result = event.target?.result as string;
        setTempConfig((prev) => ({
          ...prev,
          preset: 'custom_image',
          customImageUrl: result,
        }));
        setImageUrlInput('');
      };
      reader.readAsDataURL(file);
    }
  };

  const handleApplyUrl = () => {
    if (imageUrlInput.trim()) {
      setTempConfig((prev) => ({
        ...prev,
        preset: 'custom_image',
        customImageUrl: imageUrlInput.trim(),
      }));
    }
  };

  const handleSave = () => {
    updateBackgroundConfig(tempConfig);
    showToast(
      'success',
      language === 'zh' ? '背景设置已生效' : 'Background Applied',
      language === 'zh' ? '全局背景渲染与遮罩参数已更新并持久化保存' : 'Background theme saved successfully'
    );
    onClose();
  };

  const handleReset = () => {
    resetBackgroundConfig();
    setTempConfig({
      preset: 'default',
      customImageUrl: '',
      overlayOpacity: 70,
      blur: 0,
    });
    setImageUrlInput('');
    showToast('info', language === 'zh' ? '已恢复默认背景' : 'Reset to Default', language === 'zh' ? '已还原为经典深空流光预设' : 'Restored default background');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md animate-fade-in font-sans">
      <div
        className={`w-full max-w-2xl rounded-3xl border shadow-2xl overflow-hidden flex flex-col max-h-[90vh] ${
          isLight ? 'bg-white/95 border-slate-200 text-slate-900' : 'bg-[#090d19]/95 border-white/10 text-white'
        }`}
      >
        {/* Modal Header */}
        <div className="p-5 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center text-cyan-400">
              <Palette className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold tracking-tight">
                {language === 'zh' ? '自定义系统背景与壁纸' : 'Custom Wallpaper & Background'}
              </h3>
              <p className="text-xs text-slate-400">
                {language === 'zh'
                  ? '挑选动态光泽预设，或上传属于您的个性化背景图片'
                  : 'Choose dynamic optic presets or upload custom wallpaper image'}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-xl flex items-center justify-center text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1 text-xs">
          {/* 1. Presets Grid */}
          <div>
            <div className="font-semibold mb-3 flex items-center justify-between">
              <span>{language === 'zh' ? '1. 选择背景主题预设' : '1. Select Preset Theme'}</span>
              <span className="font-mono text-[10px] text-cyan-400 font-bold">
                {presets.find((p) => p.id === tempConfig.preset)?.nameZh}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {presets.map((preset) => {
                const isSelected = tempConfig.preset === preset.id;
                return (
                  <button
                    key={preset.id}
                    onClick={() => {
                      setTempConfig((prev) => ({
                        ...prev,
                        preset: preset.id,
                      }));
                    }}
                    className={`p-3 rounded-2xl border text-left transition-all relative overflow-hidden group cursor-pointer ${
                      isSelected
                        ? isLight
                          ? 'border-sky-500 ring-2 ring-sky-500/30 bg-sky-50/80 shadow-md'
                          : 'border-cyan-400 ring-2 ring-cyan-400/30 bg-cyan-500/10 shadow-[0_0_15px_rgba(0,242,195,0.2)]'
                        : isLight
                        ? 'border-slate-200 bg-slate-50/80 hover:border-slate-300'
                        : 'border-white/10 bg-white/[0.03] hover:border-white/20'
                    }`}
                  >
                    {/* Thumbnail preview */}
                    <div
                      className={`w-full h-12 rounded-xl bg-gradient-to-br ${preset.colorPreview} border border-white/10 mb-2 relative flex items-center justify-center shadow-inner`}
                    >
                      {preset.id === 'custom_image' && (
                        <ImageIcon className="w-5 h-5 text-white/70" />
                      )}
                      {isSelected && (
                        <div className="absolute top-1.5 right-1.5 w-4 h-4 rounded-full bg-cyan-400 text-slate-950 flex items-center justify-center shadow-md">
                          <Check className="w-2.5 h-2.5 stroke-[3]" />
                        </div>
                      )}
                    </div>

                    <div className="font-bold text-xs truncate">
                      {language === 'zh' ? preset.nameZh : preset.nameEn}
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5 line-clamp-1">
                      {preset.descZh}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* 2. Custom Image Upload / URL Controls (if custom_image selected) */}
          {tempConfig.preset === 'custom_image' && (
            <div
              className={`p-4 rounded-2xl border space-y-3.5 transition-all ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/30 border-white/10'
              }`}
            >
              <div className="flex items-center justify-between font-semibold">
                <span className="flex items-center gap-1.5">
                  <ImageIcon className="w-4 h-4 text-cyan-400" />
                  {language === 'zh' ? '上传或指定壁纸图片' : 'Upload Image or URL'}
                </span>
                {tempConfig.customImageUrl && (
                  <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-mono">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {language === 'zh' ? '已装载图片' : 'Image Loaded'}
                  </span>
                )}
              </div>

              {/* Upload Drop Zone */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="p-4 rounded-xl border border-dashed border-cyan-400/40 bg-cyan-500/5 hover:bg-cyan-500/10 transition-colors flex flex-col items-center justify-center text-center cursor-pointer group"
                >
                  <Upload className="w-5 h-5 text-cyan-400 mb-1 group-hover:scale-110 transition-transform" />
                  <span className="font-bold text-xs">
                    {language === 'zh' ? '点击上传本地图片' : 'Click to Upload Local File'}
                  </span>
                  <span className="text-[10px] text-slate-400 mt-0.5">PNG, JPG, WebP (最大 8MB)</span>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </div>

                {/* Paste URL */}
                <div className="p-3 rounded-xl border border-white/10 flex flex-col justify-between space-y-2">
                  <span className="text-[11px] text-slate-400 flex items-center gap-1">
                    <Link className="w-3.5 h-3.5 text-slate-400" />
                    {language === 'zh' ? '或者输入在线网络图片 URL' : 'Or Paste Web Image URL'}
                  </span>
                  <div className="flex items-center gap-2">
                    <input
                      type="url"
                      placeholder="https://example.com/wallpaper.jpg"
                      value={imageUrlInput}
                      onChange={(e) => setImageUrlInput(e.target.value)}
                      className={`flex-1 px-2.5 py-1.5 rounded-lg border text-xs focus:outline-none ${
                        isLight
                          ? 'bg-white border-slate-300 text-slate-900'
                          : 'bg-black/40 border-white/10 text-white focus:border-cyan-400'
                      }`}
                    />
                    <button
                      onClick={handleApplyUrl}
                      className="px-3 py-1.5 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs cursor-pointer shrink-0"
                    >
                      {language === 'zh' ? '应用' : 'Apply'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Preview Thumbnail */}
              {tempConfig.customImageUrl && (
                <div className="relative h-28 rounded-xl overflow-hidden border border-white/10">
                  <img
                    src={tempConfig.customImageUrl}
                    alt="Custom Wallpaper"
                    className="w-full h-full object-cover"
                    style={{
                      filter: tempConfig.blur > 0 ? `blur(${tempConfig.blur}px)` : 'none',
                    }}
                  />
                  <div
                    className="absolute inset-0"
                    style={{
                      backgroundColor: isLight ? '#ffffff' : '#050811',
                      opacity: tempConfig.overlayOpacity / 100,
                    }}
                  />
                  <div className="absolute bottom-2 left-2 text-[10px] font-mono px-2 py-0.5 rounded bg-black/60 text-white backdrop-blur-sm">
                    {language === 'zh' ? '实时预览效果' : 'Live Preview Overlay'}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 3. Sliders for custom adjustment (Overlay Opacity & Blur) */}
          <div
            className={`p-4 rounded-2xl border space-y-4 ${
              isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/20 border-white/10'
            }`}
          >
            <div className="flex items-center gap-2 font-semibold">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>{language === 'zh' ? '2. 视觉舒适度微调 (Contrast & Blur)' : '2. Overlay Adjustments'}</span>
            </div>

            {/* Overlay opacity slider */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">
                  {language === 'zh' ? '文字对比度遮罩深度 (Overlay Opacity)' : 'Overlay Mask Darkness'}
                </span>
                <span className="font-mono font-bold text-cyan-400">{tempConfig.overlayOpacity}%</span>
              </div>
              <input
                type="range"
                min="10"
                max="95"
                value={tempConfig.overlayOpacity}
                onChange={(e) =>
                  setTempConfig((prev) => ({ ...prev, overlayOpacity: Number(e.target.value) }))
                }
                className="w-full cursor-pointer"
              />
              <div className="text-[10px] text-slate-500">
                {language === 'zh'
                  ? '适当提高遮罩深度可确保文字与图表在任何复杂壁纸上都清晰可读'
                  : 'Higher opacity ensures optimal text readability over detailed wallpapers'}
              </div>
            </div>

            {/* Blur slider */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">
                  {language === 'zh' ? '背景高斯模糊强度 (Background Blur)' : 'Background Blur Radius'}
                </span>
                <span className="font-mono font-bold text-cyan-400">{tempConfig.blur}px</span>
              </div>
              <input
                type="range"
                min="0"
                max="16"
                value={tempConfig.blur}
                onChange={(e) =>
                  setTempConfig((prev) => ({ ...prev, blur: Number(e.target.value) }))
                }
                className="w-full cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-5 border-t border-white/10 flex items-center justify-between gap-3">
          <button
            onClick={handleReset}
            className="px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5 text-slate-400 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '恢复默认背景' : 'Restore Default'}</span>
          </button>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
            >
              {language === 'zh' ? '取消' : 'Cancel'}
            </button>
            <button
              onClick={handleSave}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-md ${
                isLight
                  ? 'bg-sky-600 hover:bg-sky-500 text-white'
                  : 'bg-cyan-400 hover:bg-cyan-300 text-slate-950 shadow-[0_0_15px_rgba(0,242,195,0.3)]'
              }`}
            >
              <Check className="w-4 h-4 stroke-[3]" />
              <span>{language === 'zh' ? '保存并应用' : 'Save & Apply'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

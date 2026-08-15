import React, { useState, useRef } from 'react';
import { X, Upload, Check, Sparkles, User, Image, Trash2, Camera } from 'lucide-react';
import { motion } from 'motion/react';
import { useApp } from '../../context/AppContext';

interface Props {
  userId?: string; // If null, modifying admin avatar
  initialName: string;
  initialAvatar?: string;
  initialColor?: string;
  onSave: (avatarUrl: string, avatarColor?: string) => void;
  onClose: () => void;
}

const PRESET_AVATARS = [
  // Curated modern 3D & minimalist liquid glass style avatars (Unsplash high-res portraits & illustrated vector avatars)
  {
    id: 'p1',
    label: 'Tech Lead',
    url: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
  },
  {
    id: 'p2',
    label: 'Engineer',
    url: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80',
  },
  {
    id: 'p3',
    label: 'Ops Admin',
    url: 'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=150&auto=format&fit=crop&q=80',
  },
  {
    id: 'p4',
    label: 'Security',
    url: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150&auto=format&fit=crop&q=80',
  },
  {
    id: 'p5',
    label: 'Support',
    url: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150&auto=format&fit=crop&q=80',
  },
  {
    id: 'p6',
    label: 'Analyst',
    url: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=150&auto=format&fit=crop&q=80',
  },
];

const GRADIENT_COLORS = [
  { id: 'cyan', bg: 'from-cyan-500 to-blue-600', text: 'text-cyan-200', border: 'border-cyan-400/40' },
  { id: 'purple', bg: 'from-purple-500 to-indigo-600', text: 'text-purple-200', border: 'border-purple-400/40' },
  { id: 'emerald', bg: 'from-emerald-400 to-teal-600', text: 'text-emerald-200', border: 'border-emerald-400/40' },
  { id: 'amber', bg: 'from-amber-400 to-orange-600', text: 'text-amber-200', border: 'border-amber-400/40' },
  { id: 'rose', bg: 'from-rose-500 to-pink-600', text: 'text-rose-200', border: 'border-rose-400/40' },
  { id: 'sky', bg: 'from-sky-400 to-blue-600', text: 'text-sky-200', border: 'border-sky-400/40' },
];

export const AvatarCustomizerModal: React.FC<Props> = ({
  userId,
  initialName,
  initialAvatar,
  initialColor = 'cyan',
  onSave,
  onClose,
}) => {
  const { language, showToast, themeMode } = useApp();
  const [selectedAvatar, setSelectedAvatar] = useState<string>(initialAvatar || '');
  const [selectedColor, setSelectedColor] = useState<string>(initialColor);
  const [activeTab, setActiveTab] = useState<'upload' | 'presets' | 'monogram'>('upload');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const initials = (initialName || 'User')
    .split(' ')
    .map((n) => n[0])
    .join('')
    .substring(0, 2)
    .toUpperCase();

  // Handle local file selection (PNG, JPG, SVG, WebP)
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      showToast('error', language === 'zh' ? '文件过大' : 'File Too Large', language === 'zh' ? '头像图片大小请勿超过 5MB' : 'Max file size is 5MB');
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const base64 = event.target?.result as string;
      if (base64) {
        setSelectedAvatar(base64);
        setActiveTab('upload');
        showToast('success', language === 'zh' ? '图片已载入' : 'Image Loaded', language === 'zh' ? '点击保存即可应用头像' : 'Click save to apply');
      }
    };
    reader.readAsDataURL(file);
  };

  const handleSave = () => {
    onSave(selectedAvatar, selectedColor);
    showToast(
      'success',
      language === 'zh' ? '头像更新成功' : 'Avatar Updated',
      language === 'zh' ? `${initialName} 的头像已生效` : `Avatar updated for ${initialName}`
    );
    onClose();
  };

  const handleRemove = () => {
    setSelectedAvatar('');
    showToast(
      'info',
      language === 'zh' ? '头像已恢复为默认字母缩写' : 'Avatar Reset',
      language === 'zh' ? '将使用首字母艺术标识' : 'Reverted to monogram'
    );
  };

  const currentColorConfig = GRADIENT_COLORS.find((c) => c.id === selectedColor) || GRADIENT_COLORS[0];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-md">
      <div className="fixed inset-0" onClick={onClose} />

      <motion.div
        initial={{ opacity: 0, scale: 0.94, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.94, y: 10 }}
        className={`w-full max-w-md rounded-3xl shadow-2xl overflow-hidden relative z-10 border transition-all ${
          themeMode === 'light'
            ? 'bg-white/95 border-slate-200/90 text-slate-800'
            : 'bg-slate-900/95 border-slate-700/80 text-white'
        }`}
      >
        {/* Header */}
        <div
          className={`px-6 py-4 border-b flex items-center justify-between ${
            themeMode === 'light' ? 'bg-slate-50/80 border-slate-200' : 'bg-slate-950/80 border-slate-800'
          }`}
        >
          <h3 className="text-base font-bold flex items-center gap-2">
            <Camera className="w-4 h-4 text-cyan-500" />
            <span>{language === 'zh' ? '自定义用户头像' : 'Customize User Avatar'}</span>
          </h3>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Avatar Live Preview */}
          <div className="flex flex-col items-center justify-center space-y-3">
            <div className="relative group">
              <div className="w-24 h-24 rounded-3xl overflow-hidden shadow-xl border-2 border-white/40 dark:border-slate-700 flex items-center justify-center relative bg-slate-950/10">
                {selectedAvatar ? (
                  <img
                    src={selectedAvatar}
                    alt={initialName}
                    className="w-full h-full object-cover"
                    referrerPolicy="no-referrer"
                  />
                ) : (
                  <div
                    className={`w-full h-full bg-gradient-to-br ${currentColorConfig.bg} flex items-center justify-center text-white text-3xl font-black font-mono tracking-wider shadow-inner`}
                  >
                    {initials}
                  </div>
                )}
              </div>

              {selectedAvatar && (
                <button
                  onClick={handleRemove}
                  title={language === 'zh' ? '清除图片，使用文字首字母' : 'Remove image'}
                  className="absolute -top-1.5 -right-1.5 w-6 h-6 rounded-full bg-rose-500 hover:bg-rose-600 text-white flex items-center justify-center shadow-md transition-transform hover:scale-110"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="text-center">
              <div className="text-sm font-bold">{initialName}</div>
              <div className="text-xs text-slate-400 font-mono">
                {userId ? (language === 'zh' ? '邮箱账户头像' : 'Mailbox Account') : (language === 'zh' ? '系统管理员头像' : 'Root Administrator')}
              </div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex rounded-xl p-1 bg-slate-100 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 text-xs font-semibold">
            <button
              onClick={() => setActiveTab('upload')}
              className={`flex-1 py-1.5 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
                activeTab === 'upload'
                  ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-400 shadow-xs'
                  : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <Upload className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '本地上传' : 'Upload File'}</span>
            </button>

            <button
              onClick={() => setActiveTab('presets')}
              className={`flex-1 py-1.5 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
                activeTab === 'presets'
                  ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-400 shadow-xs'
                  : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '精选图库' : 'Presets'}</span>
            </button>

            <button
              onClick={() => setActiveTab('monogram')}
              className={`flex-1 py-1.5 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
                activeTab === 'monogram'
                  ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-400 shadow-xs'
                  : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <User className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '字母色彩' : 'Monogram'}</span>
            </button>
          </div>

          {/* Tab 1: Upload File */}
          {activeTab === 'upload' && (
            <div className="space-y-3">
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/svg+xml"
                onChange={handleFileChange}
                className="hidden"
              />

              <div
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-2xl p-6 text-center cursor-pointer transition-all ${
                  themeMode === 'light'
                    ? 'border-slate-300 hover:border-cyan-500 hover:bg-cyan-50/30'
                    : 'border-slate-700 hover:border-cyan-400 hover:bg-cyan-950/20'
                }`}
              >
                <Upload className="w-8 h-8 mx-auto text-cyan-500 mb-2 animate-bounce" />
                <div className="text-xs font-bold text-slate-700 dark:text-slate-200">
                  {language === 'zh' ? '点击或拖拽上传新头像' : 'Click or drop to upload avatar'}
                </div>
                <div className="text-[11px] text-slate-400 mt-1 font-mono">
                  PNG, JPG, WEBP, SVG (Max 5MB)
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Presets Library */}
          {activeTab === 'presets' && (
            <div className="space-y-2">
              <div className="text-xs text-slate-400 mb-2">
                {language === 'zh' ? '选择精选的现代质感头像：' : 'Select a curated preset avatar:'}
              </div>
              <div className="grid grid-cols-3 gap-3">
                {PRESET_AVATARS.map((preset) => (
                  <button
                    key={preset.id}
                    onClick={() => setSelectedAvatar(preset.url)}
                    className={`relative rounded-2xl overflow-hidden border-2 transition-all p-1 group ${
                      selectedAvatar === preset.url
                        ? 'border-cyan-500 scale-105 shadow-md'
                        : 'border-transparent hover:border-slate-300 dark:hover:border-slate-700'
                    }`}
                  >
                    <img
                      src={preset.url}
                      alt={preset.label}
                      className="w-full h-16 object-cover rounded-xl"
                      referrerPolicy="no-referrer"
                    />
                    <div className="text-[10px] text-center mt-1 truncate font-medium text-slate-600 dark:text-slate-300">
                      {preset.label}
                    </div>
                    {selectedAvatar === preset.url && (
                      <div className="absolute top-2 right-2 w-5 h-5 rounded-full bg-cyan-500 text-white flex items-center justify-center shadow-xs">
                        <Check className="w-3 h-3" />
                      </div>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Tab 3: Monogram Palette */}
          {activeTab === 'monogram' && (
            <div className="space-y-3">
              <div className="text-xs text-slate-400">
                {language === 'zh' ? '选择首字母徽章渐变主题：' : 'Select monogram gradient palette:'}
              </div>
              <div className="grid grid-cols-3 gap-3">
                {GRADIENT_COLORS.map((color) => (
                  <button
                    key={color.id}
                    onClick={() => {
                      setSelectedColor(color.id);
                      setSelectedAvatar(''); // Clear photo avatar to show monogram
                    }}
                    className={`p-3 rounded-2xl border-2 flex items-center gap-2.5 transition-all ${
                      selectedColor === color.id && !selectedAvatar
                        ? 'border-cyan-500 scale-105 shadow-md'
                        : 'border-slate-200 dark:border-slate-800 hover:border-slate-400'
                    }`}
                  >
                    <div className={`w-8 h-8 rounded-xl bg-gradient-to-br ${color.bg} flex items-center justify-center text-white text-xs font-bold font-mono`}>
                      {initials}
                    </div>
                    <span className="text-xs font-medium capitalize text-slate-700 dark:text-slate-200">
                      {color.id}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div
          className={`px-6 py-4 border-t flex items-center justify-end gap-3 ${
            themeMode === 'light' ? 'bg-slate-50/80 border-slate-200' : 'bg-slate-950/80 border-slate-800'
          }`}
        >
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-slate-500 hover:text-slate-800 dark:hover:text-white transition-colors"
          >
            {language === 'zh' ? '取消' : 'Cancel'}
          </button>

          <button
            onClick={handleSave}
            className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 shadow-md transition-all hover:scale-[1.02]"
          >
            <Check className="w-3.5 h-3.5" />
            <span>{language === 'zh' ? '保存头像' : 'Save Avatar'}</span>
          </button>
        </div>
      </motion.div>
    </div>
  );
};

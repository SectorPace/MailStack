import React, { useState, useRef } from 'react';
import { useApp } from '../../context/AppContext';
import { User, X, Plus, KeyRound, Mail, HardDrive, Camera, Upload, Check } from 'lucide-react';
import { motion } from 'motion/react';

interface Props {
  onClose: () => void;
}

export const AddUserModal: React.FC<Props> = ({ onClose }) => {
  const { domains, addUser, language, themeMode, showToast } = useApp();
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [selectedDomain, setSelectedDomain] = useState(domains[0]?.name || 'example.com');
  const [password, setPassword] = useState('');
  const [quotaMaxGb, setQuotaMaxGb] = useState(5.0);
  const [role, setRole] = useState<'admin' | 'user' | 'manager'>('user');
  const [avatarUrl, setAvatarUrl] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleAvatarFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      showToast('error', language === 'zh' ? '文件过大' : 'File Too Large', 'Max 5MB');
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      if (ev.target?.result) {
        setAvatarUrl(ev.target.result as string);
      }
    };
    reader.readAsDataURL(file);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim()) return;
    addUser({
      username: username.toLowerCase().trim(),
      displayName: displayName.trim() || username.trim(),
      email: `${username.toLowerCase().trim()}@${selectedDomain}`,
      domain: selectedDomain,
      quotaMaxGb,
      role,
      avatarUrl: avatarUrl || undefined,
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-md">
      <div className="fixed inset-0" onClick={onClose} />

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className={`w-full max-w-md border rounded-3xl shadow-2xl overflow-hidden relative z-10 font-sans ${
          themeMode === 'light'
            ? 'bg-white border-slate-200 text-slate-900'
            : 'bg-slate-900 border-slate-700/80 text-white'
        }`}
      >
        <div className={`px-6 py-4 border-b flex items-center justify-between ${
          themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'border-slate-800 bg-slate-950/80'
        }`}>
          <h3 className={`text-base font-bold flex items-center gap-2 ${
            themeMode === 'light' ? 'text-slate-900' : 'text-white'
          }`}>
            <User className="w-5 h-5 text-cyan-500" />
            <span>{language === 'zh' ? '创建新邮箱账户' : 'Create Mailbox User'}</span>
          </h3>
          <button
            onClick={onClose}
            className={`p-1 rounded-lg transition-colors cursor-pointer ${
              themeMode === 'light' ? 'text-slate-400 hover:text-slate-700 hover:bg-slate-200' : 'text-slate-400 hover:text-white'
            }`}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs font-mono">
          {/* Avatar Quick Upload row */}
          <div className={`flex items-center gap-3 p-3 rounded-2xl border ${
            themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/60 border-slate-800'
          }`}>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              onChange={handleAvatarFile}
              className="hidden"
            />
            <div
              onClick={() => fileInputRef.current?.click()}
              className={`relative w-12 h-12 rounded-xl overflow-hidden border flex items-center justify-center cursor-pointer group shrink-0 ${
                themeMode === 'light'
                  ? 'bg-cyan-50 border-cyan-200 hover:border-cyan-500'
                  : 'bg-cyan-500/10 border-cyan-500/30 hover:border-cyan-400'
              }`}
            >
              {avatarUrl ? (
                <img src={avatarUrl} alt="Avatar" className="w-full h-full object-cover" referrerPolicy="no-referrer" />
              ) : (
                <div className={`font-bold text-xs ${
                  themeMode === 'light' ? 'text-cyan-700' : 'text-cyan-400'
                }`}>
                  {username.substring(0, 2).toUpperCase() || 'AV'}
                </div>
              )}
              <div className="absolute inset-0 bg-slate-950/70 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity text-cyan-300">
                <Camera className="w-4 h-4" />
              </div>
            </div>

            <div className="flex-1">
              <div className={`font-semibold text-xs font-sans ${
                themeMode === 'light' ? 'text-slate-800' : 'text-slate-200'
              }`}>
                {language === 'zh' ? '自定义用户头像' : 'User Avatar'}
              </div>
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className={`text-[11px] hover:underline mt-0.5 flex items-center gap-1 cursor-pointer ${
                  themeMode === 'light' ? 'text-cyan-700 font-semibold' : 'text-cyan-400'
                }`}
              >
                <Upload className="w-3 h-3" />
                <span>{language === 'zh' ? '点击上传本地图片' : 'Upload custom photo'}</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={`block uppercase tracking-wider mb-1.5 ${
                themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
              }`}>
                {language === 'zh' ? '用户名' : 'USERNAME'}
              </label>
              <input
                type="text"
                required
                placeholder="j.smith"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                  themeMode === 'light'
                    ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                    : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                }`}
              />
            </div>

            <div>
              <label className={`block uppercase tracking-wider mb-1.5 ${
                themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
              }`}>
                {language === 'zh' ? '显示名称' : 'DISPLAY NAME'}
              </label>
              <input
                type="text"
                placeholder="John Smith"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                  themeMode === 'light'
                    ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                    : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                }`}
              />
            </div>
          </div>

          <div>
            <label className={`block uppercase tracking-wider mb-1.5 ${
              themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
            }`}>
              {language === 'zh' ? '所属域名' : 'SELECT DOMAIN'}
            </label>
            <select
              value={selectedDomain}
              onChange={(e) => setSelectedDomain(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                  : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
              }`}
            >
              {domains.map((d) => (
                <option key={d.id} value={d.name}>
                  @{d.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className={`block uppercase tracking-wider mb-1.5 ${
              themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
            }`}>
              {language === 'zh' ? '初始登录口令' : 'PASSWORD'}
            </label>
            <input
              type="password"
              required
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                  : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
              }`}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={`block uppercase tracking-wider mb-1.5 ${
                themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
              }`}>
                {language === 'zh' ? '空间配额 (GB)' : 'QUOTA (GB)'}
              </label>
              <input
                type="number"
                step="0.5"
                value={quotaMaxGb}
                onChange={(e) => setQuotaMaxGb(Number(e.target.value))}
                className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                  themeMode === 'light'
                    ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                    : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                }`}
              />
            </div>

            <div>
              <label className={`block uppercase tracking-wider mb-1.5 ${
                themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
              }`}>
                {language === 'zh' ? '角色权限' : 'ROLE'}
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as any)}
                className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                  themeMode === 'light'
                    ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                    : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                }`}
              >
                <option value="user">普通用户 (User)</option>
                <option value="manager">组管理员 (Manager)</option>
                <option value="admin">系统超管 (Admin)</option>
              </select>
            </div>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              className="w-full py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all cursor-pointer font-sans"
            >
              <Plus className="w-4 h-4" />
              <span>{language === 'zh' ? '开通邮箱并下发 Dovecot 凭据' : 'Provision Mailbox Account'}</span>
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
};

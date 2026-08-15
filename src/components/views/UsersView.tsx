import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import {
  Users,
  Plus,
  Search,
  KeyRound,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Shield,
  HardDrive,
  Mail,
  UserCheck,
  Filter,
  Camera,
  Sparkles,
  ShieldAlert
} from 'lucide-react';
import { AddUserModal } from '../modals/AddUserModal';
import { AvatarCustomizerModal } from '../modals/AvatarCustomizerModal';
import { UserItem } from '../../types';
import { LiquidGlass } from '../common/LiquidGlass';

export const UsersView: React.FC = () => {
  const { users, domains, deleteUser, toggleUserStatus, updateUserAvatar, language, showToast, themeMode } = useApp();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDomain, setSelectedDomain] = useState('all');
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingAvatarUser, setEditingAvatarUser] = useState<UserItem | null>(null);

  const filteredUsers = users.filter((u) => {
    if (selectedDomain !== 'all' && u.domain !== selectedDomain) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        u.email.toLowerCase().includes(q) ||
        u.displayName.toLowerCase().includes(q) ||
        u.username.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const totalUsedStorage = users.reduce((acc, u) => acc + u.quotaUsedGb, 0).toFixed(2);
  const totalMaxStorage = users.reduce((acc, u) => acc + u.quotaMaxGb, 0).toFixed(1);

  const handleResetPassword = (email: string) => {
    showToast(
      'info',
      language === 'zh' ? '临时口令已生成' : 'Password Reset',
      `${email} -> TempPass#${Math.random().toString(36).substring(2, 7)}!`
    );
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top 3 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Total Users */}
        <LiquidGlass variant="card" glowColor="cyan" className="p-5">
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '活跃邮箱账户' : 'Active Mailboxes'}
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${
              themeMode === 'light' ? 'text-slate-900' : 'text-white'
            }`}>{users.length}</span>
            <span className={`text-xs font-mono font-semibold ${
              themeMode === 'light' ? 'text-emerald-600' : 'text-emerald-400'
            }`}>
              {users.filter((u) => u.status === 'enabled').length} {language === 'zh' ? '已启用' : 'enabled'}
            </span>
          </div>
        </LiquidGlass>

        {/* Storage Quota Used */}
        <LiquidGlass variant="card" glowColor="sky" className="p-5">
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '已占用存储空间' : 'Storage Quota Used'}
          </div>
          <div className="flex items-baseline gap-1.5 font-mono">
            <span className={`text-3xl font-black ${
              themeMode === 'light' ? 'text-cyan-700' : 'text-cyan-400'
            }`}>{totalUsedStorage}</span>
            <span className={`text-sm ${
              themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
            }`}>/ {totalMaxStorage} GB</span>
          </div>
          <div className={`w-full h-1.5 rounded-full mt-2 overflow-hidden ${
            themeMode === 'light' ? 'bg-slate-200' : 'bg-slate-800'
          }`}>
            <div className="bg-gradient-to-r from-cyan-500 to-sky-400 h-full w-[32%]" />
          </div>
        </LiquidGlass>

        {/* Admins Count */}
        <LiquidGlass variant="card" glowColor="purple" className="p-5">
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '特权管理员' : 'Privileged Admins'}
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${
              themeMode === 'light' ? 'text-slate-900' : 'text-white'
            }`}>
              {users.filter((u) => u.role === 'admin').length}
            </span>
            <span className={`text-xs ${
              themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
            }`}>{language === 'zh' ? '拥有 Root Console 权限' : 'with root access'}</span>
          </div>
        </LiquidGlass>
      </div>

      {/* Filter & Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 flex-1 max-w-lg">
          {/* Domain Filter Dropdown */}
          <select
            value={selectedDomain}
            onChange={(e) => setSelectedDomain(e.target.value)}
            className={`h-10 px-3 rounded-xl border text-xs font-mono focus:outline-none transition-colors ${
              themeMode === 'light'
                ? 'bg-white border-slate-200 text-slate-800 focus:border-cyan-500 shadow-sm'
                : 'bg-slate-900 border-slate-800 text-slate-200 focus:border-cyan-400'
            }`}
          >
            <option value="all">{language === 'zh' ? '全部域名 (All Domains)' : 'All Domains'}</option>
            {domains.map((d) => (
              <option key={d.id} value={d.name}>
                @{d.name}
              </option>
            ))}
          </select>

          {/* Search Box */}
          <div className="relative flex-1">
            <Search className={`w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 ${
              themeMode === 'light' ? 'text-slate-400' : 'text-slate-500'
            }`} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={language === 'zh' ? '搜索用户邮箱、姓名...' : 'Search user email, name...'}
              className={`w-full h-10 pl-10 pr-4 rounded-xl border text-xs font-mono focus:outline-none transition-colors ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-900 placeholder-slate-400 focus:border-cyan-500 shadow-sm'
                  : 'bg-slate-900 border-slate-800 text-white placeholder-slate-500 focus:border-cyan-400'
              }`}
            />
          </div>
        </div>

        <button
          onClick={() => setIsAddModalOpen(true)}
          className="h-10 px-4 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all hover:scale-[1.02] cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>{language === 'zh' ? '添加邮箱用户' : 'Add Mailbox User'}</span>
        </button>
      </div>

      {/* Users Data Table */}
      <LiquidGlass variant="panel" interactive={false} className="rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className={`border-b text-[11px] font-mono uppercase tracking-wider ${
              themeMode === 'light'
                ? 'border-slate-200 bg-slate-50 text-slate-600 font-semibold'
                : 'border-slate-800 bg-slate-950/80 text-slate-400'
            }`}>
              <tr>
                <th className="px-5 py-3.5">{language === 'zh' ? '用户 / 姓名' : 'USER / NAME'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '邮箱地址' : 'EMAIL ADDRESS'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '用户角色 (ROLE)' : 'ROLE'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '已用配额 (QUOTA)' : 'QUOTA USAGE'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '最后登录' : 'LAST LOGIN'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '账号状态' : 'STATUS'}</th>
                <th className="px-5 py-3.5 text-right">{language === 'zh' ? '操作' : 'ACTIONS'}</th>
              </tr>
            </thead>
            <tbody className={`divide-y font-mono ${
              themeMode === 'light' ? 'divide-slate-200' : 'divide-slate-800/60'
            }`}>
              {filteredUsers.map((usr) => {
                const percent = Math.min(100, Math.round((usr.quotaUsedGb / usr.quotaMaxGb) * 100));

                return (
                  <tr key={usr.id} className={`transition-colors group ${
                    themeMode === 'light' ? 'hover:bg-slate-50/80' : 'hover:bg-slate-800/40'
                  }`}>
                    {/* User display with custom avatar */}
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-3">
                        <div
                          onClick={() => setEditingAvatarUser(usr)}
                          title={language === 'zh' ? '点击自定义头像' : 'Click to customize avatar'}
                          className={`relative w-8 h-8 rounded-xl overflow-hidden cursor-pointer group shrink-0 border transition-all shadow-sm ${
                            themeMode === 'light'
                              ? 'border-slate-300 hover:border-cyan-600'
                              : 'border-slate-700/80 hover:border-cyan-400/80'
                          }`}
                        >
                          {usr.avatarUrl ? (
                            <img
                              src={usr.avatarUrl}
                              alt={usr.displayName}
                              className="w-full h-full object-cover"
                              referrerPolicy="no-referrer"
                            />
                          ) : (
                            <div className={`w-full h-full flex items-center justify-center font-bold text-xs uppercase font-mono ${
                              themeMode === 'light'
                                ? 'bg-cyan-100 text-cyan-800'
                                : 'bg-gradient-to-br from-cyan-500/20 to-blue-600/30 text-cyan-300'
                            }`}>
                              {usr.username.substring(0, 2)}
                            </div>
                          )}

                          <div className="absolute inset-0 bg-slate-950/70 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity text-cyan-300">
                            <Camera className="w-3.5 h-3.5" />
                          </div>
                        </div>

                        <div>
                          <div className={`font-semibold flex items-center gap-1.5 ${
                            themeMode === 'light' ? 'text-slate-900' : 'text-white'
                          }`}>
                            <span>{usr.displayName}</span>
                            {usr.avatarUrl && (
                              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 shadow-[0_0_5px_#22d3ee]" />
                            )}
                          </div>
                          <div className={`text-[10px] font-mono ${
                            themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
                          }`}>{usr.username}</div>
                        </div>
                      </div>
                    </td>

                    {/* Email */}
                    <td className={`px-5 py-3.5 font-medium ${
                      themeMode === 'light' ? 'text-cyan-800' : 'text-cyan-300'
                    }`}>
                      {usr.email}
                    </td>

                    {/* Role Badge: Admin vs Normal User (Fixed for Light & Dark) */}
                    <td className="px-5 py-3.5">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[10px] uppercase font-mono font-bold border ${
                        usr.role === 'admin'
                          ? themeMode === 'light'
                            ? 'bg-amber-50 text-amber-800 border-amber-300 shadow-xs'
                            : 'bg-amber-950/80 text-amber-300 border-amber-500/40 shadow-[0_0_8px_rgba(245,158,11,0.15)]'
                          : themeMode === 'light'
                          ? 'bg-slate-100 text-slate-700 border-slate-200'
                          : 'bg-slate-800/80 text-slate-300 border-slate-700'
                      }`}>
                        {usr.role === 'admin' && (
                          <Shield className="w-3 h-3 text-amber-500" />
                        )}
                        <span>{usr.role === 'admin' ? (language === 'zh' ? '管理员' : 'ADMIN') : (language === 'zh' ? '普通用户' : 'USER')}</span>
                      </span>
                    </td>

                    {/* Quota */}
                    <td className="px-5 py-3.5 min-w-[140px]">
                      <div className="flex items-center justify-between text-[11px] mb-1">
                        <span className={`font-semibold ${themeMode === 'light' ? 'text-slate-800' : 'text-white'}`}>
                          {usr.quotaUsedGb} GB
                        </span>
                        <span className={themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}>
                          {usr.quotaMaxGb} GB
                        </span>
                      </div>
                      <div className={`w-full h-1.5 rounded-full overflow-hidden ${
                        themeMode === 'light' ? 'bg-slate-200' : 'bg-slate-800'
                      }`}>
                        <div
                          className={`h-full transition-all ${
                            percent > 85
                              ? 'bg-rose-500'
                              : percent > 60
                              ? 'bg-amber-500'
                              : themeMode === 'light' ? 'bg-cyan-600' : 'bg-cyan-400'
                          }`}
                          style={{ width: `${percent}%` }}
                        />
                      </div>
                    </td>

                    {/* Last login */}
                    <td className={`px-5 py-3.5 text-[11px] ${
                      themeMode === 'light' ? 'text-slate-600' : 'text-slate-400'
                    }`}>
                      <div>{usr.lastLoginTime}</div>
                      <div className={`text-[10px] ${themeMode === 'light' ? 'text-slate-400' : 'text-slate-500'}`}>
                        {usr.lastLoginIp}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="px-5 py-3.5">
                      <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${
                        usr.status === 'enabled'
                          ? themeMode === 'light' ? 'text-emerald-700' : 'text-emerald-400'
                          : 'text-slate-400'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          usr.status === 'enabled'
                            ? themeMode === 'light' ? 'bg-emerald-600' : 'bg-emerald-400 shadow-[0_0_6px_#34d399]'
                            : 'bg-slate-400'
                        }`} />
                        {usr.status === 'enabled' ? (language === 'zh' ? '正常' : 'Enabled') : (language === 'zh' ? '已停用' : 'Disabled')}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="px-5 py-3.5 text-right space-x-1">
                      <button
                        onClick={() => setEditingAvatarUser(usr)}
                        title={language === 'zh' ? '更换用户头像' : 'Customize Avatar'}
                        className={`p-1.5 rounded-lg transition-colors cursor-pointer ${
                          themeMode === 'light'
                            ? 'text-slate-500 hover:text-cyan-700 hover:bg-slate-100'
                            : 'text-slate-400 hover:text-cyan-300 hover:bg-slate-800'
                        }`}
                      >
                        <Camera className="w-4 h-4" />
                      </button>

                      <button
                        onClick={() => handleResetPassword(usr.email)}
                        title={language === 'zh' ? '重置登录口令' : 'Reset Password'}
                        className={`p-1.5 rounded-lg transition-colors cursor-pointer ${
                          themeMode === 'light'
                            ? 'text-slate-500 hover:text-cyan-700 hover:bg-slate-100'
                            : 'text-slate-400 hover:text-cyan-300 hover:bg-slate-800'
                        }`}
                      >
                        <KeyRound className="w-4 h-4" />
                      </button>

                      <button
                        onClick={() => toggleUserStatus(usr.id)}
                        title={usr.status === 'enabled' ? 'Disable Account' : 'Enable Account'}
                        className={`p-1.5 rounded-lg transition-colors cursor-pointer ${
                          themeMode === 'light'
                            ? 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
                            : 'text-slate-400 hover:text-white hover:bg-slate-800'
                        }`}
                      >
                        {usr.status === 'enabled' ? (
                          <ToggleRight className={`w-4 h-4 ${themeMode === 'light' ? 'text-cyan-600' : 'text-cyan-400'}`} />
                        ) : (
                          <ToggleLeft className="w-4 h-4 text-slate-400" />
                        )}
                      </button>

                      <button
                        onClick={() => deleteUser(usr.id)}
                        title="Delete user"
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-500 hover:bg-rose-50 transition-colors cursor-pointer"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </LiquidGlass>

      {isAddModalOpen && <AddUserModal onClose={() => setIsAddModalOpen(false)} />}

      {editingAvatarUser && (
        <AvatarCustomizerModal
          userId={editingAvatarUser.id}
          initialName={editingAvatarUser.displayName || editingAvatarUser.username}
          initialAvatar={editingAvatarUser.avatarUrl}
          initialColor={editingAvatarUser.avatarColor}
          onSave={(url, color) => {
            updateUserAvatar(editingAvatarUser.id, url, color);
          }}
          onClose={() => setEditingAvatarUser(null)}
        />
      )}
    </div>
  );
};

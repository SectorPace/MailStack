import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { api } from '../../api';
import { getErrorMessage } from '../../utils/errors';
import {
  Send,
  Plus,
  ShieldCheck,
  AlertCircle,
  RefreshCw,
  Server,
  Layers,
  Zap,
  Activity,
  CheckCircle2,
  Lock,
  Globe,
  Radio,
  Sliders,
  ExternalLink,
  ChevronRight,
  Shield,
  Clock,
  ArrowRight
} from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';
import { AddRelayModal } from '../modals/AddRelayModal';

export const SmtpRelayView: React.FC = () => {
  const { relayRoutes, language, themeMode, showToast } = useApp();
  const [activeTab, setActiveTab] = useState<'overview' | 'providers' | 'ports' | 'test'>('overview');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Test Delivery State
  const [testHost, setTestHost] = useState('');
  const [testPort, setTestPort] = useState(587);
  const [testUser, setTestUser] = useState('');
  const [testPass, setTestPass] = useState('');
  const [testTlsMode, setTestTlsMode] = useState('STARTTLS');
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<any | null>(null);

  // Direct Port 25 Checker
  const [isCheckingPort25, setIsCheckingPort25] = useState(false);
  const [port25Status, setPort25Status] = useState<'unknown' | 'blocked' | 'open'>('unknown');

  const isLight = themeMode === 'light';

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await api('/api/status');
      showToast('success', language === 'zh' ? '中继状态已同步' : 'Relay State Synced', 'Postfix relayhost refreshed');
    } catch (e) {
      showToast('error', language === 'zh' ? '同步失败' : 'Sync Failed', getErrorMessage(e));
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleRunRelayTest = async () => {
    if (!testHost) {
      showToast('error', language === 'zh' ? '请输入中继主机地址' : 'Host Required', '');
      return;
    }
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await api('/api/setup/relay/test', {
        method: 'POST',
        body: JSON.stringify({
          host: testHost.trim(),
          port: Number(testPort),
          username: testUser,
          password: testPass,
          tlsMode: testTlsMode,
        }),
      });
      setTestResult(res);
      if (res.connected) {
        showToast('success', language === 'zh' ? '中继握手测试成功' : 'Relay Handshake Passed', `RTT: ${Number.isFinite(res.latencyMs) ? res.latencyMs : 0}ms`);
      } else {
        showToast('error', language === 'zh' ? '中继连接失败' : 'Relay Failed', res.error || 'Authentication error');
      }
    } catch (e) {
      setTestResult({ error: getErrorMessage(e) });
      showToast('error', language === 'zh' ? '测试失败' : 'Test Failed', getErrorMessage(e));
    } finally {
      setIsTesting(false);
    }
  };

  const handleCheckPort25 = async () => {
    setIsCheckingPort25(true);
    try {
      const res: any = await api('/api/network/check-port', {
        method: 'POST',
        body: JSON.stringify({ port: 25 }),
      });
      if (res && res.open) {
        setPort25Status('open');
        showToast(
          'success',
          language === 'zh' ? '出站 25 端口畅通' : 'Port 25 Accessible',
          language === 'zh'
            ? `成功连接外发目标 (${res.target})，耗时 ${res.latencyMs}ms，支持直连投递。`
            : `Successfully connected to ${res.target} (${res.latencyMs}ms); direct outbound supported.`
        );
      } else {
        setPort25Status('blocked');
        showToast(
          'info',
          language === 'zh' ? '出站 25 端口受阻' : 'Port 25 Blocked',
          language === 'zh'
            ? '宿主机外发 25 端口无法连通（云厂商/网络策略拦截），推荐启用 587/465 中继'
            : 'Egress 25 blocked by provider firewall/ISP; use 587/465 SMTP relay.'
        );
      }
    } catch (e) {
      setPort25Status('blocked');
      showToast('error', language === 'zh' ? '探测异常' : 'Probe Error', getErrorMessage(e));
    } finally {
      setIsCheckingPort25(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top Header Card */}
      <LiquidGlass variant="panel" glowColor="cyan" className="p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyan-400 to-blue-500 text-slate-950 flex items-center justify-center font-bold shadow-[0_0_20px_rgba(0,242,195,0.3)]">
              <Send className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
                  {language === 'zh' ? '出站中继与出站发信' : 'Outbound SMTP Relay'}
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  {relayRoutes.length > 0 ? (language === 'zh' ? '已启用中继' : 'ACTIVE RELAY') : (language === 'zh' ? '直连发信' : 'DIRECT SMTP')}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {language === 'zh'
                  ? '管理 Postfix 全局 relayhost 智能路由、第三方高信誉企业投递服务商 (SES / SendGrid / Oracle) 及外发端口规避策略。'
                  : 'Manage Postfix relayhost, SASL credentials, trusted relay providers, and outbound port bypass policies.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className={`px-3.5 py-2 rounded-xl border text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                isLight ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300' : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>{language === 'zh' ? '同步状态' : 'Sync'}</span>
            </button>

            <button
              onClick={() => setIsModalOpen(true)}
              className="px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-md"
            >
              <Plus className="w-4 h-4" />
              <span>{language === 'zh' ? '测试并配置中继' : 'Configure Relay'}</span>
            </button>
          </div>
        </div>
      </LiquidGlass>

      {/* Secondary Submenu Navigation Tabs */}
      <div className={`p-1.5 rounded-2xl border flex items-center gap-1.5 backdrop-blur-md overflow-x-auto ${
        isLight ? 'bg-white/90 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
      }`}>
        {[
          { id: 'overview', labelZh: '中继路由与状态', labelEn: 'Relay Overview', icon: <Layers className="w-4 h-4" /> },
          { id: 'providers', labelZh: '主流服务商配置', labelEn: 'Relay Providers', icon: <Server className="w-4 h-4" /> },
          { id: 'ports', labelZh: '出站发信端口策略', labelEn: 'Outbound Ports & Security', icon: <Shield className="w-4 h-4" /> },
          { id: 'test', labelZh: '中继连通性测试', labelEn: 'Live Delivery Probe', icon: <Activity className="w-4 h-4" /> },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-2 rounded-xl text-xs font-bold font-mono flex items-center gap-2 transition-all cursor-pointer shrink-0 ${
              activeTab === tab.id
                ? 'bg-cyan-400 text-slate-950 shadow-sm'
                : isLight ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            {tab.icon}
            <span>{language === 'zh' ? tab.labelZh : tab.labelEn}</span>
          </button>
        ))}
      </div>

      {/* Tab 1: Relay Overview & Routes */}
      {activeTab === 'overview' && (
        <div className="space-y-6 animate-in fade-in">
          {/* Active Global Route Status */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <LiquidGlass variant="card" className="p-4 space-y-2">
              <div className="text-[10px] font-mono uppercase text-slate-400 font-bold">{language === 'zh' ? '当前出站模式' : 'Outbound Mode'}</div>
              <div className="text-lg font-black text-slate-100 flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${relayRoutes.length > 0 ? 'bg-cyan-400 animate-pulse' : 'bg-amber-400'}`} />
                <span>{relayRoutes.length > 0 ? 'Smart Relayhost' : 'Direct Egress (Port 25)'}</span>
              </div>
              <p className="text-[11px] text-slate-400">
                {relayRoutes.length > 0 ? '邮件经由外部授权中继加密外发' : '由本机 Postfix 直接连接接收端 MX 服务器'}
              </p>
            </LiquidGlass>

            <LiquidGlass variant="card" className="p-4 space-y-2">
              <div className="text-[10px] font-mono uppercase text-slate-400 font-bold">{language === 'zh' ? '外发 TLS 加密' : 'Outbound TLS Grade'}</div>
              <div className="text-lg font-black text-slate-100 flex items-center gap-2">
                <Lock className="w-4 h-4 text-emerald-400" />
                <span>STARTTLS (Mandatory)</span>
              </div>
              <p className="text-[11px] text-slate-400">
                强制启用 TLS 加密，防范网络嗅探与中间人攻击
              </p>
            </LiquidGlass>

            <LiquidGlass variant="card" className="p-4 space-y-2">
              <div className="text-[10px] font-mono uppercase text-slate-400 font-bold">{language === 'zh' ? 'SASL 身份鉴权' : 'SASL Authentication'}</div>
              <div className="text-lg font-black text-slate-100 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <span>{relayRoutes.length > 0 ? 'Active / Encrypted' : 'None (Direct MX)'}</span>
              </div>
              <p className="text-[11px] text-slate-400">
                凭证安全保存在 /etc/postfix/sasl_passwd
              </p>
            </LiquidGlass>
          </div>

          {/* Relay Routes List */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className={`text-sm font-bold flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                <Server className="w-4 h-4 text-cyan-400" />
                <span>{language === 'zh' ? '已生效的中继路由表' : 'Active Relay Routes'}</span>
              </h3>
            </div>

            {relayRoutes.length === 0 ? (
              <div className={`p-8 rounded-2xl border text-center space-y-3 ${
                isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'
              }`}>
                <AlertCircle className="w-10 h-10 mx-auto text-amber-400" />
                <h4 className="text-sm font-bold text-slate-200">
                  {language === 'zh' ? '当前未启用全局出站中继 (直连外发模式)' : 'No Outbound Relay Active (Direct Mode)'}
                </h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  {language === 'zh'
                    ? 'Postfix 目前将直接使用出站 25 端口将邮件投递至各目标收件服务器。若您的云厂商 (如阿里云、腾讯云、AWS EC2、Oracle Cloud) 封禁了外发 25 端口，发信将产生超时积压，建议立即配置 587/465 中继。'
                    : 'Emails are dispatched directly to recipient MX records via Port 25. If port 25 is blocked, emails will defer in queue.'}
                </p>
                <button
                  onClick={() => setIsModalOpen(true)}
                  className="px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs inline-flex items-center gap-1.5 cursor-pointer shadow-md"
                >
                  <Plus className="w-4 h-4" />
                  <span>{language === 'zh' ? '添加并应用中继' : 'Configure Relay Now'}</span>
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                {relayRoutes.map((route) => (
                  <div
                    key={route.id}
                    className={`p-5 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all ${
                      isLight ? 'bg-white/90 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-cyan-500/30 shadow-md'
                    }`}
                  >
                    <div className="flex items-center gap-3.5">
                      <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center font-bold">
                        <Send className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm text-slate-100 font-mono">{route.relayTarget}</span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            {route.status || 'CONNECTED'}
                          </span>
                        </div>
                        <div className="text-xs text-slate-400 font-mono mt-0.5 flex items-center gap-3">
                          <span>TLS: {route.tlsMode || 'STARTTLS'}</span>
                          <span>•</span>
                          <span>Auth: SASL PLAIN/LOGIN</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          setTestHost(route.relayTarget.split(':')[0] || route.relayTarget);
                          setTestPort(Number(route.relayTarget.split(':')[1]) || 587);
                          setActiveTab('test');
                        }}
                        className="px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 font-bold text-xs flex items-center gap-1 cursor-pointer"
                      >
                        <Activity className="w-3.5 h-3.5" />
                        <span>{language === 'zh' ? '探测连通性' : 'Probe'}</span>
                      </button>
                      <button
                        onClick={() => setIsModalOpen(true)}
                        className={`px-3 py-1.5 rounded-lg border text-xs cursor-pointer ${
                          isLight ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300' : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
                        }`}
                      >
                        {language === 'zh' ? '重新配置' : 'Edit'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Provider Templates */}
      {activeTab === 'providers' && (
        <div className="space-y-4 animate-in fade-in">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              {
                id: 'oracle',
                name: 'Oracle OCI Email Delivery',
                host: 'smtp.email.us-ashburn-1.oci.oraclecloud.com',
                port: 587,
                tls: 'STARTTLS',
                spf: 'include:oracleemaildelivery.com',
                desc: 'Oracle Cloud 官方邮件外发服务，提供高信誉 IP 池与免费每月 3000 封额度。',
              },
              {
                id: 'ses',
                name: 'Amazon Simple Email Service (SES)',
                host: 'email-smtp.us-east-1.amazonaws.com',
                port: 587,
                tls: 'STARTTLS',
                spf: 'include:amazonses.com',
                desc: 'AWS 企业级邮件投递引擎，高送达率，支持专属 IP 与按需弹性扩容。',
              },
              {
                id: 'sendgrid',
                name: 'Twilio SendGrid',
                host: 'smtp.sendgrid.net',
                port: 587,
                tls: 'STARTTLS',
                spf: 'include:sendgrid.net',
                desc: '业界成熟的交易邮件中继，支持 API Token 鉴权与实时投递分析看板。',
              },
              {
                id: 'brevo',
                name: 'Brevo (Sendinblue)',
                host: 'smtp-relay.brevo.com',
                port: 587,
                tls: 'STARTTLS',
                spf: 'include:spf.brevo.com',
                desc: '欧洲高隐私合规邮件中继，每日提供 300 封免费发信额度。',
              },
              {
                id: 'resend',
                name: 'Resend SMTP',
                host: 'smtp.resend.com',
                port: 465,
                tls: 'SSL/TLS',
                spf: 'include:resend.com',
                desc: '极简现代开发者邮件平台，支持 SMTPS 465 与现代化 TLSv1.3 加密。',
              },
              {
                id: 'custom',
                name: '自建 SmartHost / 独立中转服务器',
                host: '',
                port: 2525,
                tls: 'STARTTLS',
                spf: '',
                desc: '填写您实际控制的 SmartHost 主机、端口和凭据；系统不会预填示例地址或 SPF。',
              },
            ].map((prov) => (
              <div
                key={prov.id}
                className={`p-5 rounded-2xl border space-y-3 flex flex-col justify-between ${
                  isLight ? 'bg-white/90 border-slate-200' : 'bg-slate-900/70 border-slate-800'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <h4 className="font-bold text-sm text-slate-100">{prov.name}</h4>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                      Port {prov.port}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                    {prov.desc}
                  </p>
                  <div className="mt-3 p-2.5 rounded-xl bg-slate-950 font-mono text-xs space-y-1 text-slate-300 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Endpoint:</div>
                    <div className="text-cyan-300 break-all">{prov.host}:{prov.port}</div>
                    <div className="text-[10px] text-slate-500 uppercase mt-1">Recommended SPF:</div>
                    <div className="text-amber-300 text-[11px]">{prov.spf}</div>
                  </div>
                </div>

                <button
                  onClick={() => {
                    setTestHost(prov.host);
                    setTestPort(prov.port);
                    setTestTlsMode(prov.tls);
                    setIsModalOpen(true);
                  }}
                  className="w-full py-2 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-bold transition-all cursor-pointer flex items-center justify-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>{language === 'zh' ? '套用此服务商模板' : 'Use Template'}</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Outbound Ports & Security Policy */}
      {activeTab === 'ports' && (
        <div className="space-y-6 animate-in fade-in">
          {/* Port 25 Probe Banner */}
          <div className={`p-5 rounded-2xl border flex flex-col md:flex-row md:items-center justify-between gap-4 ${
            port25Status === 'blocked'
              ? 'bg-amber-950/20 border-amber-500/40 text-amber-200'
              : isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'
          }`}>
            <div className="flex items-center gap-3.5">
              <div className="w-10 h-10 rounded-xl bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold">
                <Radio className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-100">
                  {language === 'zh' ? '本地外发 25 端口连通性探测' : 'Direct Egress Port 25 Status'}
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  {port25Status === 'blocked'
                    ? '探测结果：当前宿主机外发 25 端口已被云厂商屏蔽，所有直连外部 MX 的邮件将无法送达，必须配置中继。'
                    : '检测当前服务器是否具有向全球公网 25 端口直接建立 TCP 握手的权限。'}
                </p>
              </div>
            </div>

            <button
              onClick={handleCheckPort25}
              disabled={isCheckingPort25}
              className="px-4 py-2 rounded-xl bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 cursor-pointer transition-all shrink-0 shadow-md"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isCheckingPort25 ? 'animate-spin' : ''}`} />
              <span>{isCheckingPort25 ? (language === 'zh' ? '探测中...' : 'Probing...') : (language === 'zh' ? '立即探测 25 端口' : 'Test Port 25')}</span>
            </button>
          </div>

          {/* Modern Outbound Ports Matrix */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className={`p-5 rounded-2xl border space-y-2 ${isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cyan-400 font-mono">Port 587 (Submission)</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">推荐</span>
              </div>
              <h5 className="font-bold text-sm text-slate-200">STARTTLS 标准提交端口</h5>
              <p className="text-xs text-slate-400 leading-relaxed">
                RFC 6409 标准邮件中继提交端口，先明文建立连接随后通过 STARTTLS 升级为 TLSv1.3 加密，适用于绝大多数企业中继。
              </p>
            </div>

            <div className={`p-5 rounded-2xl border space-y-2 ${isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-purple-400 font-mono">Port 465 (SMTPS)</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30">纯隐式加密</span>
              </div>
              <h5 className="font-bold text-sm text-slate-200">Implicit TLS 隐式加密端口</h5>
              <p className="text-xs text-slate-400 leading-relaxed">
                RFC 8314 推荐的标准端口，连接建立瞬间立即进行 TLS 握手，无需明文协商，安全性与抗劫持能力极强。
              </p>
            </div>

            <div className={`p-5 rounded-2xl border space-y-2 ${isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-amber-400 font-mono">Port 2525 (Alternate)</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">备用绕行</span>
              </div>
              <h5 className="font-bold text-sm text-slate-200">备选高兼容中继端口</h5>
              <p className="text-xs text-slate-400 leading-relaxed">
                被 SendGrid、Mailgun 等广泛支持的备选端口，专用于在极端严苛、封禁 587 端口的专有网络环境中顺畅发信。
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Live Delivery Probe */}
      {activeTab === 'test' && (
        <div className="space-y-6 animate-in fade-in">
          <LiquidGlass variant="card" className="p-6 space-y-5">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Activity className="w-5 h-5 text-cyan-400" />
                <span>{language === 'zh' ? '中继真实连通性与握手诊断' : 'Live Relay Handshake Probe'}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                向指定中继发起真实 DNS 解析、TCP 握手、EHLO 协商、TLS 证书校验以及 SASL 凭证校验，诊断结果完全对齐 Postfix 行为。
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="lg:col-span-2">
                <label className="block text-xs font-mono font-bold text-slate-400 mb-1.5">{language === 'zh' ? '中继主机 (Relay Host)' : 'Relay Host'}</label>
                <input
                  type="text"
                  value={testHost}
                  onChange={(e) => setTestHost(e.target.value)}
                  placeholder="smtp.example.com"
                  className="w-full px-3.5 py-2 rounded-xl border bg-slate-950 border-slate-700 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-mono font-bold text-slate-400 mb-1.5">{language === 'zh' ? '端口 (Port)' : 'Port'}</label>
                <input
                  type="number"
                  value={testPort}
                  onChange={(e) => setTestPort(Number(e.target.value))}
                  className="w-full px-3.5 py-2 rounded-xl border bg-slate-950 border-slate-700 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-mono font-bold text-slate-400 mb-1.5">{language === 'zh' ? '加密协议 (TLS Mode)' : 'TLS Mode'}</label>
                <select
                  value={testTlsMode}
                  onChange={(e) => setTestTlsMode(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl border bg-slate-950 border-slate-700 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
                >
                  <option value="STARTTLS">STARTTLS</option>
                  <option value="SSL/TLS">SSL/TLS (Port 465)</option>
                  <option value="NONE">NONE (Plain)</option>
                </select>
              </div>

              <div className="sm:col-span-2">
                <label className="block text-xs font-mono font-bold text-slate-400 mb-1.5">{language === 'zh' ? 'SASL 用户名 (Username)' : 'SASL User'}</label>
                <input
                  type="text"
                  value={testUser}
                  onChange={(e) => setTestUser(e.target.value)}
                  placeholder="apikey / username"
                  className="w-full px-3.5 py-2 rounded-xl border bg-slate-950 border-slate-700 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div className="sm:col-span-2">
                <label className="block text-xs font-mono font-bold text-slate-400 mb-1.5">{language === 'zh' ? 'SASL 密码 (Password)' : 'SASL Password'}</label>
                <input
                  type="password"
                  value={testPass}
                  onChange={(e) => setTestPass(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full px-3.5 py-2 rounded-xl border bg-slate-950 border-slate-700 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={handleRunRelayTest}
                disabled={isTesting || !testHost}
                className="px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${isTesting ? 'animate-spin' : ''}`} />
                <span>{isTesting ? (language === 'zh' ? '正在连接中继...' : 'Connecting...') : (language === 'zh' ? '开始真实握手测试' : 'Run Handshake Test')}</span>
              </button>
            </div>

            {testResult && (
              <div className={`p-4 rounded-xl border font-mono text-xs space-y-2 ${
                testResult.error || !testResult.connected
                  ? 'bg-rose-950/40 border-rose-500/40 text-rose-200'
                  : 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
              }`}>
                <div className="flex items-center justify-between font-bold">
                  <span className="flex items-center gap-1.5">
                    {testResult.connected ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4 text-rose-400" />}
                    <span>{testResult.connected ? '握手成功 (All Stages Passed)' : '连接异常'}</span>
                  </span>
                  <span>{testResult.latencyMs ? `${testResult.latencyMs}ms` : ''}</span>
                </div>
                <pre className="p-3 rounded-lg bg-black/50 overflow-x-auto text-[11px] leading-relaxed">
                  {JSON.stringify(testResult, null, 2)}
                </pre>
              </div>
            )}
          </LiquidGlass>
        </div>
      )}

      {isModalOpen && <AddRelayModal onClose={() => setIsModalOpen(false)} />}
    </div>
  );
};

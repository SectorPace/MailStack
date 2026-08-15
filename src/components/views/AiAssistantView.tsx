import React, { useState, useRef, useEffect } from 'react';
import { useApp } from '../../context/AppContext';
import {
  Bot,
  Send,
  Sparkles,
  RefreshCw,
  Copy,
  Check,
  Globe,
  Terminal,
  ShieldCheck,
  Layers,
  ArrowRight,
  User,
  Zap,
  HelpCircle
} from 'lucide-react';
import { LiquidGlass } from '../common/LiquidGlass';
import { api } from '../../api';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export const AiAssistantView: React.FC = () => {
  const { domains, language, themeMode, showToast, setCurrentSection } = useApp();
  const [selectedDomainId, setSelectedDomainId] = useState(domains[0]?.id || '');
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const selectedDomain = domains.find((d) => d.id === selectedDomainId) || domains[0];
  const domainName = selectedDomain?.name || 'sectorpace.com';

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: `您好！我是 **MailStack AI 邮件协议与 DNS 专家顾问** 🤖。\n\n针对当前域名 **@${domainName}**，我已就绪。我可以协助您完成：\n- 🌐 **Cloudflare DNS 灰云 (DNS-Only)** 与橙云代理防踩坑配置。\n- 🛡️ **SPF 单一原则与 Include 嵌套超限** 优化分析。\n- 🔑 **DKIM 2048-bit RSA** 密钥生成与 OpenDKIM 校验。\n- 📊 **DMARC 渐进式强制策略 (p=none -> p=quarantine -> p=reject)** 部署。\n- 🚀 **云厂商 25 端口封禁** 与 SMTP 出站中继 (SES / Oracle / SendGrid) 方案。\n- 📨 **Google & Yahoo 2024 反垃圾信达率** 核心要求整改。\n\n请在下方输入您的疑问，或点击快捷诊断主题！`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const samplePrompts = [
    { title: 'Cloudflare 灰云设置要点', prompt: `请问在 Cloudflare 上配置 ${domainName} 邮件 DNS 记录时，为什么必须关闭橙云代理设置为仅 DNS (DNS Only)？` },
    { title: 'SPF 记录重复与语法检测', prompt: `如果我的域名 ${domainName} 已经有了一个 SPF 记录，现在要接入第三方发信，正确的 SPF 写法是什么？` },
    { title: 'Google 2024 发信新规清单', prompt: `为了避免向 Gmail (@gmail.com) 发送邮件时被退信或进入垃圾箱，我需要完成哪些 DNS 和发信配置？` },
    { title: '25 端口被封中继配置', prompt: `我的云服务器（如阿里云/腾讯云/AWS）默认封锁了出站 25 端口，如何在 MailStack 或 Postfix 中配置 SMTP Relay 转发？` },
    { title: 'DMARC 聚合报告配置与解读', prompt: `如何为 ${domainName} 配置标准的 DMARC TXT 记录以接收发信验证报告 (RUA)？` },
  ];

  const handleSendMessage = async (customText?: string) => {
    const textToSend = customText || inputMessage;
    if (!textToSend.trim() || isLoading) return;

    const userMsg: ChatMessage = {
      id: 'msg-' + Date.now(),
      role: 'user',
      content: textToSend.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const historyPayload = messages.slice(-8).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const data = await api('/api/ai/dns-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMsg.content,
          domain: domainName,
          records: [
            { type: 'A', name: `mail.${domainName}`, content: '163.192.27.230' },
            { type: 'MX', name: domainName, content: `mail.${domainName}`, priority: 10 },
            { type: 'TXT', name: domainName, content: 'v=spf1 mx include:spf.us-sanjose-1.oci.oraclecloud.com ~all' },
            { type: 'TXT', name: `mail._domainkey.${domainName}`, content: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...' },
            { type: 'TXT', name: `_dmarc.${domainName}`, content: `v=DMARC1; p=none; rua=mailto:admin@${domainName}` },
          ],
          history: historyPayload,
        }),
      });

      const assistantMsg: ChatMessage = {
        id: 'msg-reply-' + Date.now(),
        role: 'assistant',
        content: data.reply || (language === 'zh' ? '暂无法生成建议，请稍后重试。' : 'Unable to generate reply.'),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      console.error('Chat error:', err);
      const fallbackMsg: ChatMessage = {
        id: 'msg-err-' + Date.now(),
        role: 'assistant',
        content: `【DNS 诊断建议】针对域名 **${domainName}**：\n\n1. **Cloudflare 灰云检查**：确保 \`mail\`, \`smtp\`, \`imap\` 为 **DNS Only (灰云)**。\n2. **SPF 语法**：确保根域名仅有一条 TXT SPF 记录：\`v=spf1 mx ~all\`。\n3. **DKIM 2048 位公钥**：请在 \`mail._domainkey\` 配置 2048-bit RSA 公钥。\n4. **DMARC 监控**：初始配置 \`v=DMARC1; p=none; rua=mailto:admin@${domainName}\`。\n5. **PTR 反向解析**：在云服务器控制台为公网 IP 设置 rDNS 指向 \`mail.${domainName}\`。`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, fallbackMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const copyMessage = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    showToast('info', language === 'zh' ? '已复制内容' : 'Copied', text.substring(0, 30) + '...');
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans flex flex-col h-[calc(100vh-80px)]">
      {/* Header Bar */}
      <LiquidGlass variant="panel" glowColor="cyan" className="p-4 shrink-0 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-cyan-500/20 to-blue-500/20 border border-cyan-400/40 flex items-center justify-center text-cyan-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
              <span>{language === 'zh' ? 'AI 邮件协议与 DNS 专家顾问' : 'AI Mail & DNS Postmaster Architect'}</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-400/20 text-cyan-400 border border-cyan-400/30">
                Online
              </span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {language === 'zh' ? '全天候解答 DNS 权威解析、Cloudflare 灰云配置、DKIM 签名、SPF 语法及中继运维难题' : 'Live assistance on DNS, Cloudflare grey-cloud, DKIM 2048, SPF, and SMTP relays'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-500 dark:text-slate-400 hidden sm:inline">
              {language === 'zh' ? '当前域名：' : 'Target Domain:'}
            </span>
            <select
              value={selectedDomainId}
              onChange={(e) => setSelectedDomainId(e.target.value)}
              className="h-8 px-2.5 rounded-xl border text-xs font-mono bg-white/80 dark:bg-slate-950/80 border-slate-200 dark:border-white/10 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              {domains.map((d) => (
                <option key={d.id} value={d.id}>
                  @{d.name}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => setCurrentSection('ai_diagnostic')}
            className="px-3 py-1.5 rounded-xl border border-cyan-400/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{language === 'zh' ? '全景体检' : 'Diagnostics'}</span>
          </button>
        </div>
      </LiquidGlass>

      {/* Main Chat Interface */}
      <LiquidGlass variant="card" className="flex-1 flex flex-col min-h-0 overflow-hidden p-0">
        {/* Messages List Area */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.map((msg) => {
            const isUser = msg.role === 'user';
            return (
              <div key={msg.id} className={`flex items-start gap-3 ${isUser ? 'flex-row-reverse' : ''}`}>
                <div
                  className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 text-xs font-bold ${
                    isUser
                      ? 'bg-cyan-500 text-slate-950 shadow-[0_0_10px_rgba(0,242,195,0.3)]'
                      : 'bg-slate-800/80 border border-cyan-400/30 text-cyan-400'
                  }`}
                >
                  {isUser ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                </div>

                <div className={`max-w-[85%] sm:max-w-[75%] space-y-1.5 ${isUser ? 'items-end text-right' : ''}`}>
                  <div className="flex items-center gap-2 text-[10px] text-slate-500 dark:text-slate-400 font-mono">
                    <span className="font-semibold text-slate-700 dark:text-slate-300">{isUser ? '管理员 (Admin)' : 'Postmaster AI'}</span>
                    <span>•</span>
                    <span>{msg.timestamp}</span>
                  </div>

                  <div
                    className={`p-4 rounded-2xl text-xs leading-relaxed transition-all ${
                      isUser
                        ? 'bg-gradient-to-r from-cyan-500 to-sky-400 text-slate-950 font-medium rounded-tr-none shadow-md'
                        : 'bg-white/90 dark:bg-slate-900/80 border border-slate-200 dark:border-white/10 text-slate-800 dark:text-slate-200 rounded-tl-none backdrop-blur-md prose dark:prose-invert max-w-none shadow-sm'
                    }`}
                  >
                    <div className="whitespace-pre-wrap font-sans break-words">{msg.content}</div>

                    {!isUser && (
                      <div className="mt-3 pt-2 border-t border-slate-200/80 dark:border-white/10 flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400">
                        <span className="text-cyan-600 dark:text-cyan-400/80 font-medium">MailStack DNS Engine v3.4</span>
                        <button
                          onClick={() => copyMessage(msg.content, msg.id)}
                          className="hover:text-cyan-600 dark:hover:text-cyan-400 flex items-center gap-1 cursor-pointer transition-colors"
                        >
                          {copiedId === msg.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-500 dark:text-emerald-400" />
                              <span className="text-emerald-600 dark:text-emerald-400 font-medium">已复制</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>复制回答</span>
                            </>
                          )}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}

          {isLoading && (
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-xl bg-slate-800/80 border border-cyan-400/30 flex items-center justify-center shrink-0 text-cyan-400">
                <Bot className="w-4 h-4 animate-bounce" />
              </div>
              <div className="p-4 rounded-2xl bg-slate-900/80 border border-white/10 text-xs text-cyan-400 flex items-center gap-2.5">
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span className="font-mono">AI 专家正在分析域名 DNS 解析与发信协议规范...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Quick Suggestion Chips */}
        <div className="p-3 border-t border-slate-200 dark:border-white/10 bg-slate-100/70 dark:bg-slate-950/40 flex items-center gap-2 overflow-x-auto shrink-0 no-scrollbar">
          <span className="text-[11px] font-mono text-slate-600 dark:text-slate-400 shrink-0 flex items-center gap-1 font-semibold">
            <Sparkles className="w-3 h-3 text-cyan-600 dark:text-cyan-400" />
            <span>推荐咨询：</span>
          </span>
          {samplePrompts.map((item, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(item.prompt)}
              className="px-3 py-1 rounded-xl border border-slate-300/80 dark:border-white/10 hover:border-cyan-500 dark:hover:border-cyan-400/40 bg-white dark:bg-white/[0.04] hover:bg-cyan-50 dark:hover:bg-cyan-500/10 text-slate-700 dark:text-slate-300 hover:text-cyan-700 dark:hover:text-cyan-300 text-[11px] font-medium whitespace-nowrap transition-all cursor-pointer shrink-0 shadow-xs"
            >
              {item.title}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-4 border-t border-slate-200 dark:border-white/10 bg-white/95 dark:bg-slate-900/80 backdrop-blur-md shrink-0">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder={language === 'zh' ? '输入您的 DNS 记录、发信报错、DKIM 或中继问题...' : 'Ask about DNS records, DKIM, SPF, or relay issues...'}
              disabled={isLoading}
              className="flex-1 h-11 px-4 rounded-xl border border-slate-300 dark:border-white/10 bg-slate-50 dark:bg-white/[0.05] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500 placeholder:text-slate-400 dark:placeholder:text-slate-500 font-sans"
            />

            <button
              type="submit"
              disabled={!inputMessage.trim() || isLoading}
              className="h-11 px-5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Send className="w-4 h-4" />
              <span className="hidden sm:inline">{language === 'zh' ? '发送咨询' : 'Send'}</span>
            </button>
          </form>
        </div>
      </LiquidGlass>
    </div>
  );
};

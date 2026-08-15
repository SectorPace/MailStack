import React, { useState, useRef, useEffect } from 'react';
import { useApp } from '../../context/AppContext';
import { api } from '../../api';
import {
  Sparkles,
  Send,
  RefreshCw,
  Bot,
  User,
  Copy,
  Check,
  Zap,
  HelpCircle,
  ShieldAlert,
  Server,
  Cloud,
  Mail
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';

interface Props {
  domainName: string;
  serverIp: string;
  relayProvider: string;
  records: any[];
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  time: string;
}

export const AiDnsAssistant: React.FC<Props> = ({
  domainName,
  serverIp,
  relayProvider,
  records
}) => {
  const { language, themeMode, showToast } = useApp();

  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: `您好！我是 **MailStack AI DNS 与邮件送达率专家顾问**。

当前针对您的域名 **\`${domainName}\`**（发信 IP: \`${serverIp}\`，中继: \`${relayProvider}\`），我可以协助您：
- 🔍 **排查邮件进垃圾箱 / 拒信原因**（如 550 SPF 验证失败、DKIM 签名失效）
- ☁️ **Cloudflare 灰云 (DNS Only) 防坑指南**
- 🛡️ **Google / Yahoo 2024+ 发信新规认证策略与 DMARC 报告解读**
- 🌐 **各大云厂商 (Oracle/腾讯云/阿里云/AWS) 反向解析 (PTR/rDNS) 配置**
- 🚀 **Oracle Cloud / Amazon SES / SendGrid 免费出站中继一键配置**

您可以随时在下方输入任何疑问，或直接点击预设热点问题进行咨询！`,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  const copyCode = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast('info', language === 'zh' ? '已复制' : 'Copied', text);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleSendMessage = async (customPrompt?: string) => {
    const text = customPrompt || inputMessage;
    if (!text.trim() || isLoading) return;

    const userMsg: Message = {
      role: 'user',
      content: text,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    if (!customPrompt) setInputMessage('');
    setIsLoading(true);

    try {
      const data = await api('/api/ai/dns-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          domain: domainName,
          records: records,
          history: messages.slice(-6)
        })
      });

      const resJson = data;
      if (resJson.success && resJson.reply) {
        const assistantMsg: Message = {
          role: 'assistant',
          content: resJson.reply,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        setMessages(prev => [...prev, assistantMsg]);
      } else {
        throw new Error('Chat failed');
      }
    } catch (err: any) {
      console.error('Chat error:', err);
      const fallbackMsg: Message = {
        role: 'assistant',
        content: `【DNS 诊断建议】针对域名 **${domainName}**：\n\n1. **Cloudflare 灰云检查**：请确保 \`mail\`, \`smtp\`, \`imap\` 等子域名均为 **仅 DNS (DNS Only / 灰云)** 状态。\n2. **SPF 语法**：确保根域名只有一个 TXT SPF 记录，例如：\`v=spf1 mx ~all\`。\n3. **DKIM 完整性**：Selector 记录需配置 2048 位 RSA 公钥。\n4. **DMARC 部署**：配置 \`v=DMARC1; p=none; rua=mailto:admin@${domainName}\`。\n5. **PTR 反向解析**：登录服务器提供商控制台为发信公网 IP 设置 rDNS 指向 \`mail.${domainName}\`。`,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, fallbackMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const presetQuestions = [
    {
      labelZh: '如何确保发往 Gmail / Outlook 100% 进收件箱？',
      labelEn: 'How to achieve 100% Gmail/Outlook Inbox rate?',
      icon: Mail,
      prompt: `请针对我的域名 ${domainName} (IP: ${serverIp})，给出最详细的确保发往 Gmail 与 Outlook 不进垃圾箱的清单与操作步骤。`
    },
    {
      labelZh: '为什么在 Cloudflare 不能给 mail 开启橙云代理？',
      labelEn: 'Why Cloudflare Orange Cloud breaks mail servers?',
      icon: Cloud,
      prompt: `请详细解释在 Cloudflare 为 mail.${domainName} 开启橙云代理会导致什么严重后果？为什么必须设置成灰云 (DNS Only)？`
    },
    {
      labelZh: '如何配置 VPS 的 PTR (反向 DNS) 解析？',
      labelEn: 'How to set up PTR / rDNS record on VPS?',
      icon: Server,
      prompt: `如何为服务器公网 IP ${serverIp} 设置 PTR 反向解析到 mail.${domainName}？各大主流 VPS（如 Oracle、腾讯云、阿里云、DigitalOcean）具体在哪里配置？`
    },
    {
      labelZh: '出站 25 端口被云服务商封锁，如何零成本解决？',
      labelEn: 'How to bypass outbound Port 25 blocking for free?',
      icon: ShieldAlert,
      prompt: `云服务器服务商封禁了 TCP 25 出口端口，如何使用 Oracle Cloud Email Delivery / Amazon SES 免费中继实现稳定发信？`
    }
  ];

  return (
    <div className="space-y-4">
      {/* Preset Fast Prompt Chips */}
      <div className={`p-4 rounded-2xl border backdrop-blur-md space-y-2.5 ${
        themeMode === 'light' ? 'bg-white/90 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
      }`}>
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-cyan-500" />
          <span className={`text-xs font-bold font-mono uppercase ${themeMode === 'light' ? 'text-slate-800' : 'text-slate-200'}`}>
            {language === 'zh' ? '💡 快速提问专区 (点击一键咨询 AI 专家)：' : '💡 Quick AI Guidance Topics:'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {presetQuestions.map((q, idx) => {
            const Icon = q.icon;
            return (
              <button
                key={idx}
                onClick={() => handleSendMessage(q.prompt)}
                disabled={isLoading}
                className={`p-2.5 rounded-xl border text-left text-xs flex items-center gap-2.5 transition-all cursor-pointer ${
                  themeMode === 'light'
                    ? 'bg-slate-50 hover:bg-cyan-50 hover:border-cyan-300 border-slate-200 text-slate-700'
                    : 'bg-slate-950/60 hover:bg-cyan-950/40 hover:border-cyan-500/40 border-slate-800 text-slate-300'
                }`}
              >
                <Icon className="w-4 h-4 text-cyan-500 shrink-0" />
                <span className="truncate">{language === 'zh' ? q.labelZh : q.labelEn}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Chat Messages Log Container */}
      <div className={`rounded-2xl border backdrop-blur-md overflow-hidden flex flex-col h-[520px] ${
        themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-md' : 'bg-slate-900/90 border-slate-800'
      }`}>
        {/* Chat Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-500 flex items-center justify-center text-slate-950 font-bold">
              <Bot className="w-4 h-4" />
            </div>
            <div>
              <div className={`text-xs font-bold flex items-center gap-2 ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                <span>MailStack AI DNS 领航顾问</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </div>
              <div className="text-[10px] text-slate-400 font-mono">
                Gemini 3.7 Flash &bull; Context: @{domainName}
              </div>
            </div>
          </div>

          <button
            onClick={() => setMessages([messages[0]])}
            className={`p-1.5 rounded-lg border text-xs font-mono flex items-center gap-1 cursor-pointer ${
              themeMode === 'light' ? 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-600' : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
            }`}
            title="清空历史对话"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{language === 'zh' ? '重置会话' : 'Reset'}</span>
          </button>
        </div>

        {/* Scrollable messages */}
        <div className="flex-1 p-4 sm:p-5 overflow-y-auto space-y-4 font-sans text-xs">
          {messages.map((msg, idx) => {
            const isAi = msg.role === 'assistant';
            return (
              <div
                key={idx}
                className={`flex items-start gap-3 ${isAi ? '' : 'flex-row-reverse'}`}
              >
                <div className={`w-7 h-7 rounded-xl flex items-center justify-center shrink-0 text-xs ${
                  isAi
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                    : 'bg-blue-600 text-white'
                }`}>
                  {isAi ? <Bot className="w-3.5 h-3.5" /> : <User className="w-3.5 h-3.5" />}
                </div>

                <div className={`max-w-[85%] rounded-2xl p-4 space-y-2 border ${
                  isAi
                    ? themeMode === 'light'
                      ? 'bg-slate-50 border-slate-200 text-slate-800 shadow-sm'
                      : 'bg-slate-950/80 border-slate-800/80 text-slate-200'
                    : themeMode === 'light'
                    ? 'bg-cyan-500 text-slate-950 font-medium border-cyan-400'
                    : 'bg-cyan-500/20 border-cyan-500/40 text-cyan-100'
                }`}>
                  <div className="flex items-center justify-between gap-4 text-[10px] text-slate-400 font-mono">
                    <span className="font-bold">{isAi ? 'AI DNS Architect' : 'You'}</span>
                    <span>{msg.time}</span>
                  </div>

                  <div className="prose prose-sm dark:prose-invert max-w-none text-xs leading-relaxed space-y-2 font-sans">
                    <ReactMarkdown>{msg.content}</ReactMarkdown>
                  </div>
                </div>
              </div>
            );
          })}

          {isLoading && (
            <div className="flex items-center gap-3 animate-in fade-in">
              <div className="w-7 h-7 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 flex items-center justify-center">
                <Bot className="w-3.5 h-3.5 animate-spin" />
              </div>
              <div className={`p-3.5 rounded-2xl border flex items-center gap-2 text-xs font-mono ${
                themeMode === 'light' ? 'bg-slate-50 border-slate-200 text-slate-600' : 'bg-slate-950 border-slate-800 text-cyan-300'
              }`}>
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                <span>{language === 'zh' ? 'AI 专家正在深度分析并撰写解答...' : 'AI Architect is analyzing...'}</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-3 border-t border-slate-200 dark:border-slate-800 flex items-center gap-2">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage();
              }
            }}
            placeholder={language === 'zh' ? `向 AI 咨询关于 @${domainName} 的任意 DNS / 中继 / 垃圾邮件问题...` : `Ask AI anything about DNS, SPF, DKIM, DMARC, or Relays...`}
            className={`flex-1 px-4 py-2.5 rounded-xl border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
              themeMode === 'light'
                ? 'bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400'
                : 'bg-slate-950 border-slate-800 text-slate-200 placeholder:text-slate-500'
            }`}
          />

          <button
            onClick={() => handleSendMessage()}
            disabled={isLoading || !inputMessage.trim()}
            className="px-4 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-sm cursor-pointer disabled:opacity-50"
          >
            <Send className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{language === 'zh' ? '发送' : 'Send'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

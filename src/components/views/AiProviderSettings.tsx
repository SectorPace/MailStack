import React, { useEffect, useState } from "react";
import { api } from "../../api";
import { PlugZap, ShieldCheck, RefreshCw, Save, CheckCircle2, KeyRound, Globe, Sparkles, ChevronDown, ChevronUp, Search, Check } from "@/lib/icons";
import { useApp } from "../../context/AppContext";
import { LiquidGlass } from "../common/LiquidGlass";
import { getErrorMessage } from "../../utils/errors";

export const AiProviderSettings: React.FC = () => {
  const { language, showToast, themeMode } = useApp();
  const isLight = themeMode === "light";
  const [provider, setProvider] = useState<string>("bigmodel");
  const [model, setModel] = useState<string>("glm-4-flash");
  const [baseUrl, setBaseUrl] = useState<string>("https://open.bigmodel.cn/api/paas/v4");
  const [apiKey, setApiKey] = useState<string>("");
  const [credentialConfigured, setCredentialConfigured] = useState<boolean>(true);
  const [configuredProvider, setConfiguredProvider] = useState<string>("bigmodel");
  const [allowPrivateNetwork, setAllowPrivateNetwork] = useState<boolean>(false);
  const [insecureTls, setInsecureTls] = useState<boolean>(false);
  const [busy, setBusy] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  // Model Fetching State
  const [fetchingModels, setFetchingModels] = useState(false);
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [isModelsExpanded, setIsModelsExpanded] = useState(false);
  const [modelSearchQuery, setModelSearchQuery] = useState("");

  const providerPresets: Record<string, { name: string; baseUrl: string; defaultModel: string }> = {
    bigmodel: { name: language === "zh" ? "智谱 BigModel (GLM-4)" : "Zhipu BigModel (GLM-4)", baseUrl: "https://open.bigmodel.cn/api/paas/v4", defaultModel: "glm-4-flash" },
    deepseek: { name: "DeepSeek (V3 / R1)", baseUrl: "https://api.deepseek.com/v1", defaultModel: "deepseek-chat" },
    openai: { name: "OpenAI (GPT-4o)", baseUrl: "https://api.openai.com/v1", defaultModel: "gpt-4o-mini" },
    gemini: { name: "Google Gemini", baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai", defaultModel: "gemini-2.0-flash" },
    claude: { name: "Anthropic Claude", baseUrl: "https://api.anthropic.com/v1", defaultModel: "claude-3-5-haiku-20241022" },
    custom: { name: language === "zh" ? "自定义 OpenAI 兼容接口" : "Custom OpenAI API", baseUrl: "https://api.openai.com/v1", defaultModel: "gpt-4o-mini" },
  };

  const loadConfig = () => {
    api("/api/ai/config")
      .then((data) => {
        setProvider(data.provider || "bigmodel");
        setConfiguredProvider(data.provider || "bigmodel");
        setModel(data.model || "glm-4-flash");
        setBaseUrl(data.baseUrl || "https://open.bigmodel.cn/api/paas/v4");
        setCredentialConfigured(!!data.credentialConfigured);
        setAllowPrivateNetwork(!!data.allowPrivateNetwork);
        setInsecureTls(!!data.insecureTls);
      })
      .catch((e: unknown) => showToast("error", "AI config", getErrorMessage(e)));
  };

  useEffect(() => {
    loadConfig();
  }, []);

  const handleProviderChange = (newP: string) => {
    setProvider(newP);
    const preset = providerPresets[newP];
    if (preset) {
      setBaseUrl(preset.baseUrl);
      setModel(preset.defaultModel);
    }
    setAvailableModels([]);
    setIsModelsExpanded(false);
  };

  const handleFetchModels = async () => {
    if (!baseUrl.trim()) {
      showToast("warning", language === "zh" ? "请输入 Base URL" : "Base URL Required", language === "zh" ? "获取可用模型需要提供 API Base URL" : "API Base URL is required to query models");
      return;
    }
    setFetchingModels(true);
    try {
      const res = await api("/api/ai/models", {
        method: "POST",
        body: JSON.stringify({
          baseUrl: baseUrl.trim(),
          apiKey: apiKey.trim() || undefined,
          provider,
          allowPrivateNetwork,
          insecureTls,
        }),
      });
      const models = Array.isArray(res.models) ? res.models : [];
      setAvailableModels(models);
      setIsModelsExpanded(true);
      if (models.length > 0) {
        showToast(
          "success",
          language === "zh" ? "已获取可用模型" : "Models Fetched",
          language === "zh" ? `成功从接口获取到 ${models.length} 个模型` : `Found ${models.length} available models`
        );
      } else {
        showToast("info", language === "zh" ? "未找到模型列表" : "No Models Found", language === "zh" ? "接口返回空模型列表，可手动输入模型名称" : "The provider returned an empty list");
      }
    } catch (e: unknown) {
      showToast("error", language === "zh" ? "获取模型列表失败" : "Failed to Fetch Models", getErrorMessage(e));
    } finally {
      setFetchingModels(false);
    }
  };

  const handleSave = async () => {
    setSaveBusy(true);
    try {
      await api("/api/ai/config", {
        method: "POST",
        body: JSON.stringify({
          provider,
          model,
          baseUrl,
          apiKey: apiKey || undefined,
          allowPrivateNetwork,
          insecureTls,
        }),
      });
      showToast(
        "success",
        language === "zh" ? "AI 网关配置已保存" : "AI Gateway Config Saved",
        language === "zh" ? `当前已切换至 ${provider} (${model})` : `Switched to ${provider} (${model})`,
      );
      setApiKey("");
      loadConfig();
    } catch (e: unknown) {
      showToast("error", language === "zh" ? "保存配置失败" : "Failed to Save", getErrorMessage(e));
    } finally {
      setSaveBusy(false);
    }
  };

  const testConnection = async () => {
    setBusy(true);
    setTestResult(null);
    try {
      const x = await api("/api/ai/test", {
        method: "POST",
        body: JSON.stringify({
          provider,
          baseUrl: baseUrl.trim(),
          model: model.trim(),
          apiKey: apiKey.trim() || undefined,
          allowPrivateNetwork,
          insecureTls,
        }),
      });
      setTestResult(x.reply);
      showToast(
        "success",
        language === "zh" ? "AI 网关连通测试成功" : "AI Gateway Connected",
        x.reply,
      );
    } catch (e: unknown) {
      showToast(
        "error",
        language === "zh" ? "连接测试失败" : "Connection failed",
        getErrorMessage(e),
      );
    } finally {
      setBusy(false);
    }
  };

  const filteredModels = availableModels.filter((m) =>
    m.toLowerCase().includes(modelSearchQuery.toLowerCase())
  );

  return (
    <LiquidGlass variant="panel" glowColor="cyan" className="p-6 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4 border-slate-700/40">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-bold text-sm text-slate-900 dark:text-white">
              {language === "zh" ? "多模型 AI 智能中枢网关" : "Multi-Model AI Gateway Hub"}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {language === "zh" ? "支持智谱 GLM-4、DeepSeek、Gemini、OpenAI 与 Claude 自由切换" : "Supports Zhipu GLM-4, DeepSeek, Gemini, OpenAI & Claude"}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            disabled={busy}
            onClick={testConnection}
            className="px-3.5 py-2 rounded-xl border text-xs font-semibold flex items-center gap-2 bg-slate-800/80 hover:bg-slate-700 text-cyan-300 border-cyan-500/30 transition-all cursor-pointer shadow-sm"
          >
            <RefreshCw className={busy ? "animate-spin w-3.5 h-3.5" : "w-3.5 h-3.5"} />
            <span>{busy ? (language === "zh" ? "正在探测..." : "Testing...") : (language === "zh" ? "测试连通性" : "Test Connection")}</span>
          </button>
          <button
            disabled={saveBusy}
            onClick={handleSave}
            className="px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 shadow-md transition-all cursor-pointer"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saveBusy ? (language === "zh" ? "保存中..." : "Saving...") : (language === "zh" ? "保存配置" : "Save Config")}</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        <div>
          <label className="block mb-1.5 font-medium text-slate-700 dark:text-slate-300">
            {language === "zh" ? "AI 模型服务商 (Provider)" : "AI Provider"}
          </label>
          <select
            value={provider}
            onChange={(e) => handleProviderChange(e.target.value)}
            className="w-full px-3.5 py-2.5 rounded-xl border bg-slate-950/80 border-slate-800 text-white focus:border-cyan-400 focus:outline-none"
          >
            {Object.entries(providerPresets).map(([k, v]) => (
              <option key={k} value={k}>{v.name}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="block mb-1.5 font-medium text-slate-700 dark:text-slate-300">
            {language === "zh" ? "模型标识 (Model ID)" : "Model ID"}
          </label>
          <input
            type="text"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder="e.g. gpt-4o-mini, deepseek-chat, glm-4-flash"
            className="w-full px-3.5 py-2.5 rounded-xl border bg-slate-950/80 border-slate-800 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
          />
        </div>

        {/* API BASE URL with Fetch Available Models Button */}
        <div className="md:col-span-2">
          <label className="block mb-1.5 font-medium text-slate-700 dark:text-slate-300">
            API BASE URL
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.openai.com/v1 or http://localhost:11434/v1"
              className="flex-1 px-3.5 py-2.5 rounded-xl border bg-slate-950/80 border-slate-800 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
            />
            <button
              type="button"
              disabled={fetchingModels}
              onClick={handleFetchModels}
              className="px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-400/30 transition-all cursor-pointer whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${fetchingModels ? "animate-spin text-cyan-400" : ""}`} />
              <span>{fetchingModels ? (language === "zh" ? "正在获取..." : "Fetching...") : (language === "zh" ? "获取可用模型" : "Fetch Models")}</span>
            </button>
          </div>
        </div>

        {/* Collapsible Model List Selector */}
        {availableModels.length > 0 && (
          <div className="md:col-span-2 rounded-xl border border-cyan-500/30 bg-slate-950/90 overflow-hidden shadow-lg transition-all">
            <button
              type="button"
              onClick={() => setIsModelsExpanded(!isModelsExpanded)}
              className="w-full px-4 py-2.5 bg-cyan-950/30 hover:bg-cyan-950/50 flex items-center justify-between text-xs font-semibold text-cyan-300 border-b border-cyan-500/20 cursor-pointer"
            >
              <span className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                {language === "zh" ? `模型提供商返回的可用模型 (${availableModels.length})` : `Available Models (${availableModels.length})`}
              </span>
              <span className="flex items-center gap-1 text-[11px] text-cyan-400">
                {isModelsExpanded ? (language === "zh" ? "收起列表" : "Collapse") : (language === "zh" ? "展开选择" : "Expand")}
                {isModelsExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </span>
            </button>

            {isModelsExpanded && (
              <div className="p-3 space-y-2.5 max-h-56 overflow-y-auto">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                  <input
                    type="text"
                    value={modelSearchQuery}
                    onChange={(e) => setModelSearchQuery(e.target.value)}
                    placeholder={language === "zh" ? "过滤搜索模型标识..." : "Filter models..."}
                    className="w-full pl-8 pr-3 py-1.5 rounded-lg border bg-slate-900 border-slate-700 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-1.5">
                  {filteredModels.map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => {
                        setModel(m);
                        showToast("info", language === "zh" ? "已选择模型" : "Model Selected", m);
                      }}
                      className={`p-2 rounded-lg border text-left text-xs font-mono transition-all flex items-center justify-between cursor-pointer ${
                        model === m
                          ? "bg-cyan-500/20 border-cyan-400 text-cyan-200 font-bold"
                          : "bg-slate-900/80 border-slate-800 text-slate-300 hover:border-cyan-500/40 hover:text-white"
                      }`}
                    >
                      <span className="truncate mr-1">{m}</span>
                      {model === m && <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />}
                    </button>
                  ))}
                  {filteredModels.length === 0 && (
                    <div className="col-span-full py-4 text-center text-xs text-slate-500">
                      {language === "zh" ? "未匹配到相关模型" : "No matching models found"}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        <div className="md:col-span-2">
          <label className="block mb-1.5 font-medium text-slate-700 dark:text-slate-300">
            {language === "zh" ? "API KEY (留空则保持现有或使用预置密钥)" : "API KEY (Leave blank to keep existing)"}
          </label>
          <input
            type="password"
            placeholder={credentialConfigured ? "•••••••••••••••••••••••• (已配置并隔离存储)" : "请输入 API Key..."}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="w-full px-3.5 py-2.5 rounded-xl border bg-slate-950/80 border-slate-800 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
          />
        </div>

        {/* Advanced AI Security Controls */}
        <div className="md:col-span-2 pt-2 border-t border-slate-800/40 grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label className="flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-950/40 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition-all">
            <input
              type="checkbox"
              checked={allowPrivateNetwork}
              onChange={(e) => setAllowPrivateNetwork(e.target.checked)}
              className="mt-0.5 rounded border-slate-700 text-cyan-500 focus:ring-cyan-400 focus:ring-offset-0 bg-slate-900"
            />
            <div className="space-y-0.5">
              <span className="text-xs font-semibold text-slate-200 block">
                {language === "zh" ? "允许访问局域网私有网络 (SSRF 放行)" : "Allow Local / Private Network"}
              </span>
              <span className="text-[11px] text-slate-400 block leading-tight">
                {language === "zh" ? "仅在连接内网自建 Ollama / LocalAI 等本地模型时勾选" : "Enable only when connecting to LAN or self-hosted models"}
              </span>
            </div>
          </label>

          <label className="flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-950/40 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition-all">
            <input
              type="checkbox"
              checked={insecureTls}
              onChange={(e) => setInsecureTls(e.target.checked)}
              className="mt-0.5 rounded border-slate-700 text-amber-500 focus:ring-amber-400 focus:ring-offset-0 bg-slate-900"
            />
            <div className="space-y-0.5">
              <span className="text-xs font-semibold text-slate-200 block">
                {language === "zh" ? "跳过 TLS 证书验证 (不安全)" : "Skip TLS Verification (Insecure)"}
              </span>
              <span className="text-[11px] text-amber-400/80 block leading-tight">
                {language === "zh" ? "默认严格校验 HTTPS 证书。自签名测试证书方可临时开启" : "Default strict verification prevents MITM attacks"}
              </span>
            </div>
          </label>
        </div>
      </div>

      {testResult && (
        <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{testResult}</span>
        </div>
      )}

      <div className="text-xs text-slate-400 flex items-center gap-2 pt-2 border-t border-slate-800/40">
        <ShieldCheck className="w-4 h-4 text-cyan-400" />
        <span>
          {language === "zh"
            ? "API 凭据安全存储于服务端 /etc/mailstack/ai.json (权限 0600)，绝不暴露给普通客户端。"
            : "Credentials safely stored in /etc/mailstack/ai.json with 0600 permissions."}
        </span>
      </div>
    </LiquidGlass>
  );
};


// AI 智能中心 —— 助手对话 + 一键诊断 + 模型配置（ai.chat / ai.diagnose / ai.models.list / ai.config.*）
import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { PageHeader, Card, GlassSelect, toast } from "../components/ui";
import { IconSparkles, IconSend, IconRefresh, IconCheck, IconX, IconShield } from "../components/icons";

type ChatMsg = { role: "user" | "assistant"; text: string };
type DiagItem = { ok: boolean; text: string };
// 后端 ai.models.list 返回 { models:[string], count, baseUrl }；mock 回对象数组，故两者兼容。
type AiModel = { id: string; label: string; context?: string };
// 后端 ai.config.get 返回 provider/providerName/model/baseUrl/hasKey/maskedKey/configured，
// 没有 endpoint/enabled，也绝不返回明文 apiKey。保留 endpoint 仅是兼容 mock。
type AiConfig = {
  provider?: string;
  providerName?: string;
  model?: string;
  baseUrl?: string;
  endpoint?: string;
  hasKey?: boolean;
  maskedKey?: string;
  configured?: boolean;
  apiKey?: string;
};
// 后端 ai.test 返回 { status, provider, model, reply, latencyMs, usage }（没有 models）。
type AiTest = { ok?: boolean; latencyMs?: number; reply?: string; provider?: string; model?: string; status?: string };

export default function AiSuite() {
  const { t, prefs } = useSettings();
  const zh = prefs.lang === "zh";
  const [msgs, setMsgs] = useState<ChatMsg[]>([
    { role: "assistant", text: "MailStack AI ready · snapshot 读取完成。可以询问队列、证书、安全状态，或执行一键诊断。" },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [models, setModels] = useState<AiModel[]>([]);
  const [cfg, setCfg] = useState<AiConfig | null>(null);
  const [diag, setDiag] = useState<{ summary: string; items: DiagItem[] } | null>(null);
  const [test, setTest] = useState<AiTest | null>(null);
  const [testing, setTesting] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // 后端 AI 预设键是 bigmodel/deepseek/openai/anthropic/custom；mock 的 provider
  // （如 openai-compatible）不在其中时，把当前值也补进选项，避免选择框显示空白。
  const providerOptions = (() => {
    const opts = [
      { value: "bigmodel", label: "GLM (BigModel)" },
      { value: "deepseek", label: "DeepSeek" },
      { value: "openai", label: "OpenAI" },
      { value: "anthropic", label: "Anthropic Claude" },
      { value: "custom", label: zh ? "自定义" : "Custom" },
    ];
    if (cfg?.provider && !opts.some((o) => o.value === cfg.provider)) opts.push({ value: cfg.provider, label: cfg.provider });
    return opts;
  })();

  useEffect(() => {
    rpc<{ models?: (string | AiModel)[] }>("ai.models.list").then((r) => {
      if (!r.ok) return;
      // 后端给的是字符串数组，mock 给的是 {id,label,context}，统一成 AiModel。
      setModels((r.data?.models ?? []).map((m) => (typeof m === "string" ? { id: m, label: m } : m)));
    });
    rpc<AiConfig>("ai.config.get").then((r) => r.ok && setCfg(r.data));
    rpc<AiTest>("ai.test", {}).then((r) => r.ok && setTest(r.data));
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [msgs]);

  // 后端 ai.chat 需要 messages（非空数组），不接受单个 message；同时带 message
  // 只为兼容 mock 演示。ai.config.set / ai.test 只认 provider/baseUrl/model/apiKey。
  function aiPayload() {
    return {
      provider: cfg?.provider,
      model: cfg?.model,
      baseUrl: cfg?.baseUrl ?? cfg?.endpoint,
      apiKey: cfg?.apiKey,
    };
  }

  async function send() {
    const q = input.trim();
    if (!q || busy) return;
    setInput("");
    setMsgs((m) => [...m, { role: "user", text: q }]);
    setBusy(true);
    const r = await rpc<{ reply?: string }>("ai.chat", {
      messages: [{ role: "user", content: q }],
      message: q,
    });
    setBusy(false);
    if (r.ok) setMsgs((m) => [...m, { role: "assistant", text: r.data.reply ?? "" }]);
    else setMsgs((m) => [...m, { role: "assistant", text: `error: ${r.error}` }]);
  }

  async function testConn() {
    if (!cfg) return;
    setTesting(true);
    const r = await rpc<AiTest>("ai.test", aiPayload());
    setTesting(false);
    if (r.ok) {
      setTest(r.data);
      toast("AI ✓ " + (r.data.latencyMs ?? 0) + "ms");
    } else toast(r.error, "err");
  }

  async function diagnose() {
    setBusy(true);
    const r = await rpc<{ summary?: string; items?: DiagItem[]; reply?: string }>("ai.diagnose", {});
    setBusy(false);
    if (r.ok) {
      const d = r.data;
      // mock 回 {summary, items}；真后端 ai.diagnose 回的是 chat 结果（只有 reply）。
      const summary = d.summary ?? d.reply ?? "";
      const items = d.items ?? [];
      setDiag({ summary, items });
      const text = items.length ? `${summary}\n${items.map((i) => `${i.ok ? "✓" : "✕"} ${i.text}`).join("\n")}` : summary;
      setMsgs((m) => [...m, { role: "assistant", text }]);
    } else toast(r.error, "err");
  }

  return (
    <div className="p-4">
      <PageHeader
        title={t("ai_title")}
        sub={t("ai_sub")}
        right={
          <>
            {cfg && (
              <GlassSelect
                value={cfg.model ?? ""}
                onChange={(v) => {
                  setCfg({ ...cfg, model: v });
                  rpc("ai.config.set", { model: v });
                }}
                options={models.map((m) => ({ value: m.id, label: m.context ? `${m.label} · ${m.context}` : m.label }))}
                ariaLabel={t("ai_models")}
                width={210}
              />
            )}
            <button className="btn btn-accent" onClick={diagnose} disabled={busy}>
              <IconShield size={14} /> {t("ai_diagnose")}
            </button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_320px]">
        {/* 对话 */}
        <Card padding={false} className="flex min-h-[540px] flex-col">
          <div className="flex items-center gap-2.5 border-b px-4 py-3" style={{ borderColor: "var(--hairline)" }}>
            <span className="flex h-8 w-8 items-center justify-center rounded-[10px]" style={{ background: "rgb(var(--accent-rgb) / 0.12)", color: "rgb(var(--accent-rgb))" }}>
              <IconSparkles size={16} />
            </span>
            <div>
              <div className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("ai_assistant")}</div>
              <div className="text-[11px] text-[var(--text-3)]">{cfg?.provider ?? "…"} · {cfg?.model ?? "—"}</div>
            </div>
          </div>

          <div ref={scrollRef} className="page-scroll min-h-0 flex-1 space-y-3 p-4">
            <AnimatePresence initial={false}>
              {msgs.map((m, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ type: "spring", stiffness: 400, damping: 32 }}
                  className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
                >
                  <div
                    className={`max-w-[78%] whitespace-pre-wrap rounded-[16px] px-3.5 py-2.5 text-[13px] leading-relaxed ${
                      m.role === "user" ? "text-white" : "glass--well text-[var(--text-1)]"
                    }`}
                    style={
                      m.role === "user"
                        ? { background: "linear-gradient(180deg, rgb(var(--accent-rgb)), rgb(var(--accent-deep-rgb)))", borderBottomRightRadius: 6 }
                        : { borderBottomLeftRadius: 6 }
                    }
                  >
                    {m.text}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
            {busy && (
              <div className="glass--well inline-flex items-center gap-1.5 rounded-full px-3.5 py-2">
                {[0, 1, 2].map((i) => (
                  <motion.span
                    key={i}
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ background: "var(--text-3)" }}
                    animate={{ opacity: [0.3, 1, 0.3] }}
                    transition={{ duration: 1.1, repeat: Infinity, delay: i * 0.18 }}
                  />
                ))}
              </div>
            )}
          </div>

          <form
            className="flex items-center gap-2 border-t p-3"
            style={{ borderColor: "var(--hairline)" }}
            onSubmit={(e) => {
              e.preventDefault();
              send();
            }}
          >
            <input className="input flex-1" value={input} onChange={(e) => setInput(e.target.value)} placeholder={t("ai_placeholder")} />
            <button type="submit" className="btn btn-accent" disabled={busy || !input.trim()} aria-label={t("ai_send")}>
              <IconSend size={14} />
            </button>
          </form>
          <div className="px-4 pb-3 text-[11px] text-[var(--text-3)]">{t("ai_disclaimer")}</div>
        </Card>

        {/* 右列：诊断结果 + 配置 */}
        <div className="flex flex-col gap-3">
          <Card>
            <div className="mb-2.5 flex items-center justify-between">
              <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("ai_diagnose")}</h2>
              <button className="icon-btn" style={{ width: 28, height: 28 }} onClick={diagnose} aria-label={t("ai_diagnose")}>
                <IconRefresh size={14} />
              </button>
            </div>
            {diag ? (
              <div className="space-y-2">
                <div className="text-[12.5px] font-medium text-[var(--text-1)]">{diag.summary}</div>
                {diag.items.map((it, i) => (
                  <div key={i} className="flex items-start gap-2 text-[12px]">
                    <span className="mt-0.5" style={{ color: it.ok ? "rgb(var(--ok-rgb))" : "rgb(var(--err-rgb))" }}>
                      {it.ok ? <IconCheck size={13} /> : <IconX size={13} />}
                    </span>
                    <span className="text-[var(--text-2)]">{it.text}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-[12px] text-[var(--text-3)]">{t("select_log_hint")}</div>
            )}
          </Card>

          {cfg && (
            <Card>
              <div className="mb-2.5 flex items-center justify-between">
                <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("ai_config")}</h2>
                <span className={`badge ${test ? "badge-ok" : "badge-neutral"}`}>
                  <span className="dot" />
                  {test ? "✓ " + (test.latencyMs ?? 0) + "ms" : zh ? "未测试" : "Untested"}
                </span>
              </div>
              <label className="mb-2.5 block">
                <span className="mb-1.5 block text-[12px] font-medium text-[var(--text-2)]">{zh ? "服务商" : "Provider"}</span>
                <GlassSelect
                  value={cfg.provider ?? ""}
                  onChange={(v) => {
                    setCfg({ ...cfg, provider: v });
                    rpc("ai.config.set", { provider: v });
                  }}
                  options={providerOptions}
                  ariaLabel="provider"
                />
              </label>
              <label className="mb-2.5 block">
                <span className="mb-1.5 block text-[12px] font-medium text-[var(--text-2)]">Endpoint</span>
                <input
                  className="input"
                  value={cfg.baseUrl ?? cfg.endpoint ?? ""}
                  onChange={(e) => setCfg({ ...cfg, baseUrl: e.target.value })}
                  onBlur={() => rpc("ai.config.set", { baseUrl: cfg.baseUrl ?? cfg.endpoint })}
                />
              </label>
              <label className="mb-2.5 block">
                <span className="mb-1.5 block text-[12px] font-medium text-[var(--text-2)]">API Key</span>
                <input
                  className="input font-mono"
                  type="password"
                  value={cfg.apiKey ?? ""}
                  onChange={(e) => setCfg({ ...cfg, apiKey: e.target.value })}
                  onBlur={() => rpc("ai.config.set", { apiKey: cfg.apiKey })}
                  placeholder={cfg.maskedKey || "sk-…"}
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-[12px] font-medium text-[var(--text-2)]">{t("ai_models")}</span>
                <GlassSelect
                  value={cfg.model ?? ""}
                  onChange={(v) => {
                    setCfg({ ...cfg, model: v });
                    rpc("ai.config.set", { model: v });
                  }}
                  options={models.map((m) => ({ value: m.id, label: m.label }))}
                  ariaLabel={t("ai_models")}
                />
              </label>
              <div className="mt-3 flex gap-2">
                <button className="btn glass--control" disabled={testing} onClick={testConn}>
                  {testing ? "…" : zh ? "测试连通" : "Test connection"}
                </button>
                <button
                  className="btn btn-accent"
                  onClick={async () => {
                    const r = await rpc("ai.config.set", aiPayload());
                    toast(r.ok ? t("saved") : r.error, r.ok ? "ok" : "err");
                  }}
                >
                  {zh ? "保存配置" : "Save"}
                </button>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

// 出站中继 —— 对齐原版 SmtpRelayView 功能：服务商卡片 / 凭据表单 / 中继连通测试 / 端口检测 / 应用
//
// 真实数据源：当前中继 host 在 `snapshot.queue.relayHost`（crates/priv/src/readers.rs
// queue_summary，读 relay.json；空 = 直接投递）。settings.get 的 Settings 结构体里
// **没有** relay* 字段，此页不再把「当前配置」寄托在它上面。
import { useEffect, useState } from "react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { PageHeader, Card, ToggleRow, toast } from "../components/ui";
import { IconSend, IconCheck } from "../components/icons";

// settings.get 只取可能存在的凭据用户名（真后端没有该字段 → 空串）。
type Settings = { relayAuthUser?: string };
type SnapshotRelay = { queue?: { relayHost?: string } };
// setup.relay.apply 成功：{ applied, relayhost(回读值), wrappermode, mode?, test? }；
// 「先测后写」失败：200 + { applied:false, rolledBack, test:{ error:{ message } } }。
type ApplyResult = {
  applied?: boolean;
  mode?: string;
  relayhost?: string;
  error?: { message?: string };
  test?: { error?: { message?: string } };
};
type RelayId = "direct" | "oracle" | "ses" | "sendgrid" | "custom";

export default function Relay() {
  const { t, prefs } = useSettings();
  const zh = prefs.lang === "zh";
  const [form, setForm] = useState<Settings | null>(null);
  const [relayId, setRelayId] = useState<RelayId>("direct");
  // 服务器当前生效的中继 host（snapshot.queue.relayHost；null = 尚未加载）。
  const [currentHost, setCurrentHost] = useState<string | null>(null);
  const [relayHost, setRelayHost] = useState("");
  const [relayPort, setRelayPort] = useState(587);
  const [relayPass, setRelayPass] = useState("");
  const [applying, setApplying] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [ports, setPorts] = useState<{ port: number; open: boolean; latencyMs: number; err: boolean }[] | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    let live = true;
    rpc<Settings>("settings.get").then((r) => {
      // {ok:true} 无载荷时保持 form=null（骨架屏），不把 undefined 塞进 state。
      if (!live || !r.ok || !r.data) return;
      setForm(r.data);
    });
    // 当前生效的中继只认 snapshot：settings.get 没有该数据（绝不显示编造值）。
    rpc<SnapshotRelay>("snapshot").then((r) => {
      if (!live) return;
      const host = r.ok ? (r.data?.queue?.relayHost ?? "") : "";
      setCurrentHost(host);
      // 有中继 → 选中「自定义」卡并回填。apply 落盘的是 Postfix 方括号语法
      // `[host]:port`（不做 MX 解析）；表单字段是主机名 + 端口，回填前拆开，
      // 否则二次应用会把整串再包一层括号。凭据不回显（后端不返回明文密码）。
      if (host) {
        const m = /^\[(.+)\]:(\d+)$/.exec(host);
        setRelayId("custom");
        if (m) {
          setRelayHost(m[1]);
          setRelayPort(Number(m[2]) || 587);
        } else {
          setRelayHost(host);
        }
      }
    });
    return () => {
      live = false;
    };
  }, []);

  if (currentHost === null) return <div className="p-4"><div className="skeleton h-64" /></div>;

  const providers: { id: RelayId; name: string; desc: string; host: string; port: number }[] = [
    { id: "direct", name: zh ? "直接投递" : "Direct delivery", desc: zh ? "使用本机 Postfix；需云厂商开放出站 25 端口" : "Local Postfix; requires outbound port 25", host: "", port: 25 },
    { id: "oracle", name: "Oracle OCI Email Delivery", desc: zh ? "SPF 按发送大区使用 rp / ap.rp / eu.rp" : "SPF per region: rp / ap.rp / eu.rp", host: "smtp.email.ap-seoul-1.oci.oraclecloud.com", port: 587 },
    { id: "ses", name: "Amazon SES", desc: zh ? "需要区域 SMTP Endpoint" : "Regional SMTP endpoint required", host: "email-smtp.us-east-1.amazonaws.com", port: 587 },
    { id: "sendgrid", name: "Twilio SendGrid", desc: zh ? "优先使用 Domain Authentication 记录" : "Use Domain Authentication records", host: "smtp.sendgrid.net", port: 587 },
  ];

  // 后端 setup.relay.test / setup.relay.apply 读取的是 host/port/tlsMode/username/
  // password（不是前端内部状态用的 relayHost/relayPort/relayAuthUser/relayPass），
  // 且 tlsMode 只接受 STARTTLS / SSL/TLS（后端枚举值带斜杠，见
  // crates/smtp/src/validate.rs:16,82；明文中继一律被拒）。
  function relayPayload() {
    return {
      host: relayHost || "127.0.0.1",
      port: relayPort,
      tlsMode: relayPort === 465 ? "SSL/TLS" : "STARTTLS",
      username: form?.relayAuthUser ?? "",
      password: relayPass,
    };
  }

  /**
   * 应用出站配置。选中「直接投递」即**撤销语义**：发 {direct: true} 清除已配置的
   * 中继（幂等、不连通远端），成功回 {applied, mode:"direct", relayhost:""}。
   * 「先测后写」：测试不过时后端回 200 + applied:false + 失败详情，一行配置都没写 ——
   * 必须显式检视 applied，applied:false 一律报错 toast，绝不显示「已保存」。
   */
  async function applyRelay() {
    setApplying(true);
    const direct = relayId === "direct";
    const r = await rpc<ApplyResult>("setup.relay.apply", direct ? { direct: true } : relayPayload());
    setApplying(false);
    if (r.ok && r.data?.applied === false) {
      toast(
        r.data.error?.message ?? r.data.test?.error?.message ?? (zh ? "中继测试未通过，配置未写入" : "relay test failed, nothing written"),
        "err",
      );
      return;
    }
    if (!r.ok) {
      toast(r.error, "err");
      return;
    }
    if (direct) {
      setCurrentHost("");
      setRelayPass("");
      toast(zh ? "已清除中继，回到直接投递" : "Relay cleared — direct delivery");
    } else {
      // apply 的 relayhost 是**回读**得到的观察值（含 [host]:port 方括号语法），
      // 以它为当前真相，不拿表单值冒充。
      setCurrentHost(r.data?.relayhost || relayHost);
      toast(t("saved"));
    }
  }

  async function runTest() {
    setTesting(true);
    // 动作名用 `relay.test`（不是 setup.relay.test）：前端的传输层按**动作名**查
    // `REST` 映射表，`relay.test` 与 `setup.relay.test` 都映射到 `/api/setup/relay/test`。
    // 用哪个都能通，但保持与映射表的键一致才不会在表被改名时静默掉进 RPC 桥
    // （桥只放行后端契约里已有的动作名，未登记的键会直接 400 unknown action）。
    const r = await rpc<{ connected?: boolean; success?: boolean; latencyMs?: number; message?: string; stage?: string; error?: { message?: string } }>(
      "relay.test",
      relayPayload(),
    );
    setTesting(false);
    if (r.ok) {
      // 真后端回 connected 且失败时 error 是对象；mock 回 success + message。
      const ok = r.data.connected ?? r.data.success ?? false;
      const detail = r.data.connected
        ? zh ? "中继连通" : "relay connected"
        : r.data.error?.message ?? r.data.stage ?? r.data.message ?? "failed";
      setTestResult({ ok, text: `${ok ? "✓" : "✕"} ${detail} · ${r.data.latencyMs ?? 0}ms` });
    } else {
      setTestResult({ ok: false, text: r.error });
    }
  }

  async function checkPorts() {
    setChecking(true);
    const out: { port: number; open: boolean; latencyMs: number; err: boolean }[] = [];
    for (const p of [25, 465, 587]) {
      const r = await rpc<{ open?: boolean; latencyMs?: number }>("network.check_port", { port: p, host: relayHost || "127.0.0.1" });
      // 请求失败 ≠ 端口被拦截：err 单列，界面显示「—」而不是把传输失败渲染成
      // 「拦截」（那会引导用户去查防火墙，方向完全错）。{ok:true} 无载荷同理。
      const err = !r.ok || r.data == null;
      out.push({ port: p, open: !err && r.data.open === true, latencyMs: !err ? r.data.latencyMs ?? 0 : 0, err });
    }
    setPorts(out);
    setChecking(false);
  }

  return (
    <div className="p-4">
      <PageHeader title={t("relay_title")} sub={t("relay_sub")} />

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Card>
          <h2 className="mb-2.5 text-[14px] font-semibold text-[var(--text-1)]">{zh ? "出站通道" : "Outbound Channel"}</h2>
          {/* 当前生效值来自 snapshot.queue.relayHost（读 relay.json 的真实回读），
              空 = 直接投递。这是「现在是什么」，下面卡片选择是「想改成什么」。 */}
          <div className="glass--well mb-3 flex items-center justify-between gap-3 rounded-[12px] p-3 text-[12px]">
            <span className="text-[var(--text-3)]">{zh ? "当前生效" : "Currently active"}</span>
            <span className="mono truncate text-[var(--text-1)]" title={currentHost || undefined}>
              {currentHost || (zh ? "直接投递" : "Direct delivery")}
            </span>
          </div>
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            {providers.map((p) => (
              <button
                key={p.id}
                onClick={() => {
                  setRelayId(p.id);
                  setRelayHost(p.host);
                  setRelayPort(p.port);
                }}
                className="rounded-[12px] p-3.5 text-left transition-all"
                style={{
                  background: relayId === p.id ? "rgb(var(--accent-rgb) / 0.1)" : "rgb(var(--text-1) / 0.04)",
                  boxShadow: relayId === p.id ? "inset 0 0 0 1.5px rgb(var(--accent-rgb))" : "inset 0 0 0 1px var(--hairline)",
                }}
              >
                <div className="text-[12.5px] font-semibold text-[var(--text-1)]">{p.name}</div>
                <div className="mt-1 text-[11px] leading-relaxed text-[var(--text-3)]">{p.desc}</div>
                <div className="mono mt-1.5 text-[10.5px]" style={{ color: "rgb(var(--accent-rgb))" }}>
                  {p.host || "127.0.0.1"}:{p.port}
                </div>
              </button>
            ))}
          </div>

          {relayId !== "direct" && (
            <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
              <FieldL label={zh ? "中继 SMTP 服务器" : "Relay host"} value={relayHost} onChange={setRelayHost} />
              <FieldL label={zh ? "中继端口（587 / 465）" : "Relay port"} value={String(relayPort)} onChange={(v) => setRelayPort(Number(v) || 587)} />
              <FieldL label={t("auth_user")} value={form?.relayAuthUser ?? ""} onChange={(v) => setForm({ ...(form ?? {}), relayAuthUser: v })} />
              <FieldL label={zh ? "SMTP 授权密码" : "SMTP password"} type="password" value={relayPass} onChange={setRelayPass} />
            </div>
          )}

          {/* 原先是「TLS required/may」开关（smtp_tls_security_level）：form.relayTls 只写
              本地 state，relayPayload() 的 tlsMode 由端口推导、Apply 从不携带该值，且
              后端 setup.relay.apply 只接受 STARTTLS / SSL/TLS 两种枚举（明文中继一律被拒，
              见 crates/smtp/src/validate.rs，Relay.tsx 契约注释）—— 纯死控件。改为诚实
              展示：禁用 + 提示真实生效的 TLS 模式随端口决定。 */}
          <div
            className="mt-3"
            title={zh ? "TLS 模式由端口决定：587 → STARTTLS，465 → SSL/TLS（后端仅接受这两种，不支持手工覆写）" : "TLS mode follows the port: 587 → STARTTLS, 465 → SSL/TLS. The backend accepts no manual override."}
          >
            <ToggleRow
              title={`${t("tls_mode")}: ${relayPort === 465 ? "SSL/TLS" : "STARTTLS"}`}
              sub="smtp_tls_security_level"
              checked
              disabled
              onChange={() => {}}
            />
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            {/* 选中「直接投递」时按钮即撤销入口：显式发 {direct: true} 清除中继。 */}
            <button className="btn btn-accent" disabled={applying} onClick={() => void applyRelay()}>
              <IconCheck size={14} />
              {applying
                ? "…"
                : relayId === "direct"
                  ? zh ? "直接投递（清除中继）" : "Direct delivery (clear relay)"
                  : t("apply")}
            </button>
            <button className="btn glass--control" disabled={testing} onClick={runTest}>
              <IconSend size={14} /> {testing ? "…" : zh ? "测试中继连通性" : "Test relay"}
            </button>
            <button className="btn glass--control" disabled={checking} onClick={checkPorts}>
              {checking ? "…" : zh ? "检测 25/465/587" : "Check ports"}
            </button>
          </div>
        </Card>

        <div className="flex flex-col gap-3">
          <Card>
            <h2 className="mb-2.5 text-[14px] font-semibold text-[var(--text-1)]">{zh ? "连通性结果" : "Connectivity"}</h2>
            <div className="glass--well mono min-h-[96px] rounded-[12px] p-3 text-[12px] leading-relaxed text-[var(--text-2)]">
              {testResult ? (
                <span style={{ color: testResult.ok ? "rgb(var(--ok-rgb))" : "rgb(var(--err-rgb))" }}>{testResult.text}</span>
              ) : (
                "$ mailstack relay test …"
              )}
            </div>
            {ports && (
              <div className="mt-3 space-y-2">
                {ports.map((p) => (
                  <div key={p.port} className="flex items-center justify-between text-[12.5px]">
                    <span className="mono text-[var(--text-1)]">:{p.port}</span>
                    <span className="badge" style={p.err ? { background: "rgb(var(--text-1) / 0.08)", color: "var(--text-3)" } : p.open ? { background: "rgb(var(--ok-rgb) / 0.13)", color: "rgb(var(--ok-rgb))" } : { background: "rgb(var(--err-rgb) / 0.12)", color: "rgb(var(--err-rgb))" }}>
                      <span className="dot" />
                      {p.err ? "—" : p.open ? (zh ? "开放" : "Open") : zh ? "拦截" : "Blocked"}{p.err ? "" : ` · ${p.latencyMs}ms`}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card>
            <h2 className="mb-2.5 text-[14px] font-semibold text-[var(--text-1)]">SPF</h2>
            <p className="text-[12px] leading-relaxed text-[var(--text-2)]">
              {zh ? "同一主机名只能发布一条 v=spf1 开头的 TXT 记录；MailStack 会合并直接投递与中继授权，不会生成重复 SPF。" : "Only one v=spf1 record per name; MailStack merges direct and relay authorization."}
            </p>
          </Card>
        </div>
      </div>
    </div>
  );
}

function FieldL({ label, value, onChange, type = "text" }: { label: string; value: string; onChange: (v: string) => void; type?: string }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[11.5px] font-semibold text-[var(--text-2)]">{label}</span>
      <input className="input" type={type} value={value} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

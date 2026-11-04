import { useEffect, useState } from "react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { PageHeader, Card, ToggleRow, toast } from "../components/ui";
import { IconSend, IconCheck } from "../components/icons";
type Settings = {
    relayAuthUser?: string;
};
type SnapshotRelay = {
    queue?: {
        relayHost?: string;
    };
};
type ApplyResult = {
    applied?: boolean;
    mode?: string;
    relayhost?: string;
    error?: {
        message?: string;
    };
    test?: {
        error?: {
            message?: string;
        };
    };
};
type RelayId = "direct" | "oracle" | "ses" | "sendgrid" | "custom";
export default function Relay() {
    const { t, prefs } = useSettings();
    const zh = prefs.lang === "zh";
    const [form, setForm] = useState<Settings | null>(null);
    const [relayId, setRelayId] = useState<RelayId>("direct");
    const [currentHost, setCurrentHost] = useState<string | null>(null);
    const [relayHost, setRelayHost] = useState("");
    const [relayPort, setRelayPort] = useState(587);
    const [relayPass, setRelayPass] = useState("");
    const [applying, setApplying] = useState(false);
    const [testing, setTesting] = useState(false);
    const [testResult, setTestResult] = useState<{
        ok: boolean;
        text: string;
    } | null>(null);
    const [ports, setPorts] = useState<{
        port: number;
        open: boolean;
        latencyMs: number;
        err: boolean;
    }[] | null>(null);
    const [checking, setChecking] = useState(false);
    useEffect(() => {
        let live = true;
        rpc<Settings>("settings.get").then((r) => {
            if (!live || !r.ok || !r.data)
                return;
            setForm(r.data);
        });
        rpc<SnapshotRelay>("snapshot").then((r) => {
            if (!live)
                return;
            const host = r.ok ? (r.data?.queue?.relayHost ?? "") : "";
            setCurrentHost(host);
            if (host) {
                const m = /^\[(.+)\]:(\d+)$/.exec(host);
                setRelayId("custom");
                if (m) {
                    setRelayHost(m[1]);
                    setRelayPort(Number(m[2]) || 587);
                }
                else {
                    setRelayHost(host);
                }
            }
        });
        return () => {
            live = false;
        };
    }, []);
    if (currentHost === null)
        return <div className="p-4"><div className="skeleton h-64"/></div>;
    const providers: {
        id: RelayId;
        name: string;
        desc: string;
        host: string;
        port: number;
    }[] = [
        { id: "direct", name: zh ? "直接投递" : "Direct delivery", desc: zh ? "使用本机 Postfix；需云厂商开放出站 25 端口" : "Local Postfix; requires outbound port 25", host: "", port: 25 },
        { id: "oracle", name: "Oracle OCI Email Delivery", desc: zh ? "SPF 按发送大区使用 rp / ap.rp / eu.rp" : "SPF per region: rp / ap.rp / eu.rp", host: "smtp.email.ap-seoul-1.oci.oraclecloud.com", port: 587 },
        { id: "ses", name: "Amazon SES", desc: zh ? "需要区域 SMTP Endpoint" : "Regional SMTP endpoint required", host: "email-smtp.us-east-1.amazonaws.com", port: 587 },
        { id: "sendgrid", name: "Twilio SendGrid", desc: zh ? "优先使用 Domain Authentication 记录" : "Use Domain Authentication records", host: "smtp.sendgrid.net", port: 587 },
    ];
    function relayPayload() {
        return {
            host: relayHost || "127.0.0.1",
            port: relayPort,
            tlsMode: relayPort === 465 ? "SSL/TLS" : "STARTTLS",
            username: form?.relayAuthUser ?? "",
            password: relayPass,
        };
    }
    async function applyRelay() {
        setApplying(true);
        const direct = relayId === "direct";
        const r = await rpc<ApplyResult>("setup.relay.apply", direct ? { direct: true } : relayPayload());
        setApplying(false);
        if (r.ok && r.data?.applied === false) {
            toast(r.data.error?.message ?? r.data.test?.error?.message ?? (zh ? "中继测试未通过，配置未写入" : "relay test failed, nothing written"), "err");
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
        }
        else {
            setCurrentHost(r.data?.relayhost || relayHost);
            toast(t("saved"));
        }
    }
    async function runTest() {
        setTesting(true);
        const r = await rpc<{
            connected?: boolean;
            success?: boolean;
            latencyMs?: number;
            message?: string;
            stage?: string;
            error?: {
                message?: string;
            };
        }>("relay.test", relayPayload());
        setTesting(false);
        if (r.ok) {
            const ok = r.data.connected ?? r.data.success ?? false;
            const detail = r.data.connected
                ? zh ? "中继连通" : "relay connected"
                : r.data.error?.message ?? r.data.stage ?? r.data.message ?? "failed";
            setTestResult({ ok, text: `${ok ? "✓" : "✕"} ${detail} · ${r.data.latencyMs ?? 0}ms` });
        }
        else {
            setTestResult({ ok: false, text: r.error });
        }
    }
    async function checkPorts() {
        setChecking(true);
        const out: {
            port: number;
            open: boolean;
            latencyMs: number;
            err: boolean;
        }[] = [];
        for (const p of [25, 465, 587]) {
            const r = await rpc<{
                open?: boolean;
                latencyMs?: number;
            }>("network.check_port", { port: p, host: relayHost || "127.0.0.1" });
            const err = !r.ok || r.data == null;
            out.push({ port: p, open: !err && r.data.open === true, latencyMs: !err ? r.data.latencyMs ?? 0 : 0, err });
        }
        setPorts(out);
        setChecking(false);
    }
    return (<div className="p-4">
      <PageHeader title={t("relay_title")} sub={t("relay_sub")}/>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Card>
          <h2 className="mb-2.5 text-[14px] font-semibold text-[var(--text-1)]">{zh ? "出站通道" : "Outbound Channel"}</h2>

          <div className="glass--well mb-3 flex items-center justify-between gap-3 rounded-[12px] p-3 text-[12px]">
            <span className="text-[var(--text-3)]">{zh ? "当前生效" : "Currently active"}</span>
            <span className="mono truncate text-[var(--text-1)]" title={currentHost || undefined}>
              {currentHost || (zh ? "直接投递" : "Direct delivery")}
            </span>
          </div>
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            {providers.map((p) => (<button key={p.id} onClick={() => {
                setRelayId(p.id);
                setRelayHost(p.host);
                setRelayPort(p.port);
            }} className="rounded-[12px] p-3.5 text-left transition-all" style={{
                background: relayId === p.id ? "rgb(var(--accent-rgb) / 0.1)" : "rgb(var(--text-1) / 0.04)",
                boxShadow: relayId === p.id ? "inset 0 0 0 1.5px rgb(var(--accent-rgb))" : "inset 0 0 0 1px var(--hairline)",
            }}>
                <div className="text-[12.5px] font-semibold text-[var(--text-1)]">{p.name}</div>
                <div className="mt-1 text-[11px] leading-relaxed text-[var(--text-3)]">{p.desc}</div>
                <div className="mono mt-1.5 text-[10.5px]" style={{ color: "rgb(var(--accent-rgb))" }}>
                  {p.host || "127.0.0.1"}:{p.port}
                </div>
              </button>))}
          </div>

          {relayId !== "direct" && (<div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
              <FieldL label={zh ? "中继 SMTP 服务器" : "Relay host"} value={relayHost} onChange={setRelayHost}/>
              <FieldL label={zh ? "中继端口（587 / 465）" : "Relay port"} value={String(relayPort)} onChange={(v) => setRelayPort(Number(v) || 587)}/>
              <FieldL label={t("auth_user")} value={form?.relayAuthUser ?? ""} onChange={(v) => setForm({ ...(form ?? {}), relayAuthUser: v })}/>
              <FieldL label={zh ? "SMTP 授权密码" : "SMTP password"} type="password" value={relayPass} onChange={setRelayPass}/>
            </div>)}

          <div className="mt-3" title={zh ? "TLS 模式由端口决定：587 → STARTTLS，465 → SSL/TLS（后端仅接受这两种，不支持手工覆写）" : "TLS mode follows the port: 587 → STARTTLS, 465 → SSL/TLS. The backend accepts no manual override."}>
            <ToggleRow title={`${t("tls_mode")}: ${relayPort === 465 ? "SSL/TLS" : "STARTTLS"}`} sub="smtp_tls_security_level" checked disabled onChange={() => { }}/>
          </div>

          <div className="mt-3 flex flex-wrap gap-2">

            <button className="btn btn-accent" disabled={applying} onClick={() => void applyRelay()}>
              <IconCheck size={14}/>
              {applying
            ? "…"
            : relayId === "direct"
                ? zh ? "直接投递（清除中继）" : "Direct delivery (clear relay)"
                : t("apply")}
            </button>
            <button className="btn glass--control" disabled={testing} onClick={runTest}>
              <IconSend size={14}/> {testing ? "…" : zh ? "测试中继连通性" : "Test relay"}
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
              {testResult ? (<span style={{ color: testResult.ok ? "rgb(var(--ok-rgb))" : "rgb(var(--err-rgb))" }}>{testResult.text}</span>) : ("$ mailstack relay test …")}
            </div>
            {ports && (<div className="mt-3 space-y-2">
                {ports.map((p) => (<div key={p.port} className="flex items-center justify-between text-[12.5px]">
                    <span className="mono text-[var(--text-1)]">:{p.port}</span>
                    <span className="badge" style={p.err ? { background: "rgb(var(--text-1) / 0.08)", color: "var(--text-3)" } : p.open ? { background: "rgb(var(--ok-rgb) / 0.13)", color: "rgb(var(--ok-rgb))" } : { background: "rgb(var(--err-rgb) / 0.12)", color: "rgb(var(--err-rgb))" }}>
                      <span className="dot"/>
                      {p.err ? "—" : p.open ? (zh ? "开放" : "Open") : zh ? "拦截" : "Blocked"}{p.err ? "" : ` · ${p.latencyMs}ms`}
                    </span>
                  </div>))}
              </div>)}
          </Card>

          <Card>
            <h2 className="mb-2.5 text-[14px] font-semibold text-[var(--text-1)]">SPF</h2>
            <p className="text-[12px] leading-relaxed text-[var(--text-2)]">
              {zh ? "同一主机名只能发布一条 v=spf1 开头的 TXT 记录；MailStack 会合并直接投递与中继授权，不会生成重复 SPF。" : "Only one v=spf1 record per name; MailStack merges direct and relay authorization."}
            </p>
          </Card>
        </div>
      </div>
    </div>);
}
function FieldL({ label, value, onChange, type = "text" }: {
    label: string;
    value: string;
    onChange: (v: string) => void;
    type?: string;
}) {
    return (<label className="block">
      <span className="mb-1.5 block text-[11.5px] font-semibold text-[var(--text-2)]">{label}</span>
      <input className="input" type={type} value={value} onChange={(e) => onChange(e.target.value)}/>
    </label>);
}

import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { toast } from "../components/ui";
import { BrandLogo } from "../components/BrandLogo";
import { IconGlobe, IconKey, IconRelay, IconShield, IconMail, IconCheck, IconChevronRight, IconChevronDown, IconPlus, IconUser, } from "../components/icons";
type RelayId = "direct" | "oracle" | "ses" | "sendgrid" | "custom";
const STEPS_ZH = ["身份标识", "DNS 记录", "出站中继", "TLS 证书", "管理员与发信测试", "完成"];
const STEPS_EN = ["Identity", "DNS Records", "Outbound Relay", "TLS Certificate", "Admin & Mail Test", "Done"];
function maskIp(ip: string): string {
    const parts = ip.split(".");
    if (parts.length !== 4)
        return "•••.•••.•••.•••";
    return `${parts[0]}.${parts[1].slice(0, 1)}••.•••.${parts[3] === "1" ? "1" : "•••"}`;
}
function maskDomain(d: string): string {
    const i = d.indexOf(".");
    if (i <= 0)
        return "•••••";
    return d.slice(0, 2) + "••••" + d.slice(i);
}
function maskKey(k: string): string {
    return k.length < 16 ? "••••••••" : k.slice(0, 12) + "•••…" + k.slice(-8);
}
function hasWeakRun(password: string): boolean {
    const cps = Array.from(password).map((c) => c.codePointAt(0) ?? 0);
    for (let i = 0; i + 2 < cps.length; i++) {
        const a = cps[i];
        const b = cps[i + 1];
        const c = cps[i + 2];
        if ((a === b && b === c) || (b === a + 1 && c === b + 1) || (b + 1 === a && c + 1 === b))
            return true;
    }
    return false;
}
export default function Setup({ onDone }: {
    onDone: () => void;
}) {
    const { t, prefs } = useSettings();
    const zh = prefs.lang === "zh";
    const [step, setStep] = useState(0);
    const [domain, setDomain] = useState("");
    const [mailHost, setMailHost] = useState("");
    const [serverIp, setServerIp] = useState("");
    const [dnsVerified, setDnsVerified] = useState(false);
    const [verifying, setVerifying] = useState(false);
    const [privacy, setPrivacy] = useState(true);
    const [copied, setCopied] = useState<number | null>(null);
    const [relayId, setRelayId] = useState<RelayId>("direct");
    const [relayHost, setRelayHost] = useState("");
    const [relayPort, setRelayPort] = useState(587);
    const [relayUser, setRelayUser] = useState("");
    const [relayPass, setRelayPass] = useState("");
    const [relayTested, setRelayTested] = useState(false);
    const [testing, setTesting] = useState(false);
    const [dkim, setDkim] = useState<{
        selector: string;
        publicKey: string;
    } | null>(null);
    const [certIssued, setCertIssued] = useState(false);
    const [issuing, setIssuing] = useState(false);
    const [certInfo, setCertInfo] = useState<{
        domain: string;
        issuer: string;
        notAfter: string;
        daysLeft: number | null;
        keyMode: string | null;
    } | null>(null);
    const [adminName, setAdminName] = useState(zh ? "管理员" : "Administrator");
    const [adminPass, setAdminPass] = useState("");
    const [testSent, setTestSent] = useState(false);
    const [sending, setSending] = useState(false);
    const [mailboxReady, setMailboxReady] = useState(false);
    const [phase, setPhase] = useState<"" | "account" | "mail">("");
    const [busy, setBusy] = useState(false);
    const dNorm = domain.trim().toLowerCase();
    const hNorm = mailHost.trim().toLowerCase();
    const s1ok = dNorm.length > 3 && hNorm.length > 3 && serverIp.trim().length > 6 && hNorm.endsWith(`.${dNorm}`);
    const ADMIN_ACCOUNT = "admin";
    const adminEmailForPass = `admin@${domain}`.toLowerCase();
    const passHasContext = !adminPass.toLowerCase().includes(ADMIN_ACCOUNT) &&
        !adminPass.toLowerCase().includes(adminEmailForPass);
    const s5ok = adminPass.length >= 12 &&
        /[a-zA-Z]/.test(adminPass) &&
        /[0-9]/.test(adminPass) &&
        !hasWeakRun(adminPass) &&
        passHasContext;
    const spf = `v=spf1 mx ip4:${serverIp || "203.0.113.10"} -all`;
    const records = [
        { type: "A", name: mailHost || "mail.example.com", content: serverIp || "203.0.113.10" },
        { type: "MX", name: domain || "example.com", content: `${mailHost || "mail.example.com"}. (10)` },
        { type: "TXT", name: domain || "example.com", content: spf },
        { type: "TXT", name: `_dmarc.${domain || "example.com"}`, content: `v=DMARC1; p=quarantine; rua=mailto:postmaster@${domain || "example.com"}` },
        { type: "TXT", name: `${dkim?.selector ?? "mail"}._domainkey.${domain || "example.com"}`, content: dkim?.publicKey ? `v=DKIM1; h=sha256; k=rsa; p=${dkim.publicKey}` : "" },
    ];
    const providers: {
        id: RelayId;
        name: string;
        desc: string;
        host: string;
        port: number;
    }[] = [
        { id: "direct", name: zh ? "直接投递" : "Direct delivery", desc: zh ? "使用本机 Postfix；需云厂商开放出站 25 端口" : "Local Postfix; requires outbound port 25", host: "", port: 25 },
        { id: "oracle", name: "Oracle OCI Email Delivery", desc: zh ? "SPF 按发送大区使用 rp / ap.rp / eu.rp" : "SPF per region: rp / ap.rp / eu.rp", host: "smtp.email.ap-seoul-1.oci.oraclecloud.com", port: 587 },
        { id: "ses", name: "Amazon SES", desc: zh ? "需要区域 SMTP Endpoint；自定义 MAIL FROM 另配 MX + SPF" : "Regional SMTP endpoint required", host: "email-smtp.us-east-1.amazonaws.com", port: 587 },
        { id: "sendgrid", name: "Twilio SendGrid", desc: zh ? "应优先使用控制台生成的 Domain Authentication 记录" : "Use Domain Authentication records", host: "smtp.sendgrid.net", port: 587 },
    ];
    async function copyText(text: string, i: number) {
        if (privacy && !window.confirm(zh ? "将复制真实 DNS 值（可能包含域名 / 公网 IP / DKIM 公钥），是否继续？" : "Copy the real DNS value?"))
            return;
        try {
            await navigator.clipboard.writeText(text);
        }
        catch {
            const ta = document.createElement("textarea");
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            ta.remove();
        }
        setCopied(i);
        setTimeout(() => setCopied(null), 2000);
    }
    async function next() {
        setBusy(true);
        try {
            if (step === 0) {
                const r = await rpc<{
                    dkimPublicKey?: string;
                    identity?: {
                        dkimSelector?: string;
                    };
                }>("setup.identity.apply", {
                    domain,
                    mailHost,
                    serverIp,
                    expectedSpf: spf,
                });
                if (!r.ok)
                    throw new Error(r.error);
                if (r.data?.dkimPublicKey) {
                    setDkim({ selector: r.data.identity?.dkimSelector ?? "mail", publicKey: r.data.dkimPublicKey });
                }
                const d = await rpc("domains.add", { domain });
                if (!d.ok)
                    throw new Error(d.error);
            }
            if (step === 2 && relayId !== "direct") {
                const r = await rpc<{
                    applied?: boolean;
                    rolledBack?: boolean;
                    error?: {
                        message?: string;
                    };
                    test?: {
                        error?: {
                            message?: string;
                        };
                    };
                }>("setup.relay.apply", {
                    host: relayHost,
                    port: relayPort,
                    tlsMode: relayPort === 465 ? "SSL/TLS" : "STARTTLS",
                    username: relayUser,
                    password: relayPass,
                });
                if (!r.ok)
                    throw new Error(r.error);
                if (r.data?.applied === false) {
                    throw new Error(r.data.error?.message ?? r.data.test?.error?.message ?? (zh ? "中继测试未通过，配置未写入" : "relay test failed, nothing written"));
                }
            }
            setStep((s) => s + 1);
        }
        catch (e) {
            toast(e instanceof Error ? e.message : String(e), "err");
        }
        finally {
            setBusy(false);
        }
    }
    const [finishing, setFinishing] = useState(false);
    async function finish() {
        if (finishing)
            return;
        setFinishing(true);
        const r = await rpc<{
            completed?: boolean;
        }>("setup.wizard.complete");
        setFinishing(false);
        if (r.ok && r.data?.completed === true) {
            onDone();
            return;
        }
        toast(r.ok ? (zh ? "服务器未确认向导完成，请重试" : "The server did not confirm wizard completion — retry") : r.error, "err");
    }
    const stepsZh = STEPS_ZH;
    const stepsEn = STEPS_EN;
    return (<div className="relative mx-auto flex min-h-full max-w-[860px] flex-col p-4 sm:p-6">

      <div className="mb-5 flex flex-col items-center">
        <BrandLogo size={44} radius={12}/>
        <h1 className="mt-3 text-[20px] font-semibold tracking-[-0.01em] text-[var(--text-1)]">
          {zh ? "初始设置向导" : "Setup Wizard"}
        </h1>
        <p className="mt-0.5 text-[12.5px] text-[var(--text-2)]">
          {zh ? "完成以下 6 步即可上线您的邮件服务" : "Six steps to bring your mail server online"}
        </p>
        <div className="mt-4 flex flex-wrap items-center justify-center gap-1.5">
          {stepsZh.map((label, i) => {
            const done = i < step;
            const cur = i === step;
            return (<button key={label} onClick={() => i < step && setStep(i)} className="badge" style={{
                    height: 26,
                    background: cur ? "rgb(var(--accent-rgb))" : done ? "rgb(var(--ok-rgb) / 0.14)" : "rgb(var(--text-1) / 0.05)",
                    color: cur ? "#fff" : done ? "rgb(var(--ok-rgb))" : "var(--text-3)",
                    boxShadow: cur ? "0 2px 8px rgb(var(--accent-rgb) / 0.3)" : "inset 0 0 0 1px var(--hairline)",
                    cursor: done ? "pointer" : "default",
                }}>
                {done && <IconCheck size={11}/>}
                <span className="tnum">{i + 1}</span>
                <span className="hidden sm:inline">{zh ? label : stepsEn[i]}</span>
              </button>);
        })}
        </div>
      </div>

      <AnimatePresence mode="wait" initial={false}>
        <motion.div key={step} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6, transition: { duration: 0.12 } }} transition={{ type: "spring", stiffness: 420, damping: 36 }}>
          <section className="glass edge-lens rounded-[var(--r-panel)] p-5 sm:p-6">

            {step === 0 && (<>
                <StepHead icon={<IconGlobe size={16}/>} n={1} title={zh ? "定义邮件主域名与主机标识" : "Domain & Hostname Identity"} sub={zh ? "指定业务邮件域名与 Postfix HELO/EHLO 识别主机名。" : "Specify your primary email domain and server hostname."}/>
                <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
                  <Field label={zh ? "主邮件域名" : "Primary Domain"} req placeholder="example.com" value={domain} onChange={setDomain} hint={zh ? "用户邮箱将为 user@你的域名" : "Mailboxes become user@yourdomain"}/>
                  <Field label={zh ? "邮件主机名（HELO）" : "Mail Hostname / HELO"} req placeholder="mail.example.com" value={mailHost} onChange={setMailHost} hint={zh ? "Postfix 对外发信使用的 FQDN，且必须是主域名的子域（后端会校验）" : "FQDN used by Postfix; must be a subdomain of the primary domain"}/>
                  <Field label={zh ? "服务器公网 IP" : "Server IPv4"} req placeholder="203.0.113.10" value={serverIp} onChange={setServerIp} hint={zh ? "用于 A 记录与 PTR 反向解析对齐" : "Used for A record and PTR alignment"}/>
                  <Field label={zh ? "管理员联系邮箱（Postmaster）" : "Postmaster"} value={`postmaster@${domain || "example.com"}`} disabled hint={zh ? "用于 DMARC 聚合报告与证书通知" : "For DMARC reports and cert notices"}/>
                </div>
              </>)}

            {step === 1 && (<>
                <StepHead icon={<IconKey size={16}/>} n={2} title={zh ? "配置权威 DNS 记录" : "DNS Records"} sub={zh ? "将下列 5 项核心记录添加至 DNS 服务商。Cloudflare 代理状态必须为【仅 DNS / 灰云】。" : "Add these 5 core records. Cloudflare must be DNS-Only (grey cloud)."} right={<button className="btn glass--control" style={{ color: "rgb(var(--accent-rgb))" }} disabled={verifying} onClick={async () => {
                    setVerifying(true);
                    const r = await rpc<{
                        verified: boolean;
                        checks?: Record<string, boolean>;
                    }>("setup.dns.verify", {
                        domain,
                        mailHost,
                        serverIp,
                        ...(dkim?.selector ? { dkimSelector: dkim.selector } : {}),
                        expectedSpf: spf,
                        ...(relayId === "ses" ? { selectedRelay: relayId } : {}),
                    });
                    setVerifying(false);
                    if (r.ok && r.data?.verified) {
                        setDnsVerified(true);
                        toast(zh ? "DNS 验证通过" : "DNS verified");
                    }
                    else if (r.ok) {
                        const failed = Object.entries(r.data?.checks ?? {}).filter(([, v]) => !v).map(([k]) => k);
                        toast(zh ? `DNS 未通过${failed.length ? "：" + failed.join(" / ") : ""}` : `DNS unverified${failed.length ? ": " + failed.join(" / ") : ""}`, "err");
                    }
                    else
                        toast(r.error, "err");
                }}>
                      {verifying ? "…" : dnsVerified ? "✓ " + (zh ? "已验证" : "Verified") : zh ? "一键验证解析" : "Verify DNS"}
                    </button>}/>
                <div className="mt-4 flex items-center justify-between text-[12px] text-[var(--text-2)]">
                  <span>{zh ? "隐私遮蔽（复制真实值需确认）" : "Privacy masking (confirm to copy real values)"}</span>
                  <button role="switch" aria-checked={privacy} data-checked={String(privacy)} className="radix-switch" style={{ height: 22, width: 38 }} onClick={() => setPrivacy(!privacy)}>
                    <span className="knob" style={{ width: 18, height: 18, transform: privacy ? "translateX(17px)" : "translateX(2px)" }}/>
                  </button>
                </div>
                <div className="mt-2 overflow-x-auto rounded-[12px]" style={{ boxShadow: "inset 0 0 0 1px var(--hairline)" }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Name</th>
                        <th>Content</th>
                        <th>{zh ? "代理" : "Proxy"}</th>
                        <th className="text-right">{zh ? "操作" : "Action"}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {records.map((r0, i) => (<tr key={i}>
                          <td><span className="badge badge-info" style={{ height: 20, fontSize: 11 }}>{r0.type}</span></td>
                          <td className="mono">{privacy ? maskDomain(r0.name) : r0.name}</td>

                          {r0.content ? (<>
                              <td className="mono max-w-[260px] truncate text-[var(--text-2)]" title={r0.content}>
                                {r0.type === "TXT" && r0.name.includes("_domainkey") ? (privacy ? maskKey(r0.content) : r0.content) : privacy && r0.type === "A" ? maskIp(r0.content) : r0.content}
                              </td>
                              <td><span className="badge badge-warn" style={{ height: 20, fontSize: 10.5 }}>{zh ? "仅 DNS" : "DNS only"}</span></td>
                              <td className="text-right">
                                <button className="btn glass--control" style={{ height: 26, fontSize: 11, padding: "0 10px" }} onClick={() => copyText(r0.content, i)}>
                                  {copied === i ? "✓" : zh ? "复制" : "Copy"}
                                </button>
                              </td>
                            </>) : (<>
                              <td className="text-[var(--text-3)]" colSpan={3}>{zh ? "第 1 步完成后由服务器生成" : "generated on the server after step 1"}</td>
                            </>)}
                        </tr>))}
                    </tbody>
                  </table>
                </div>
                <div className="mt-3 rounded-[12px] p-3.5 text-[12px] leading-relaxed" style={{ background: "rgb(var(--warn-rgb) / 0.1)", boxShadow: "inset 0 0 0 1px rgb(var(--warn-rgb) / 0.3)", color: "rgb(var(--warn-rgb))" }}>
                  <strong>{zh ? "反向解析（PTR / rDNS）提醒：" : "PTR / rDNS reminder:"}{" "}
                    {zh ? "请在主机商后台为公网 IP 设置 PTR 指向邮件主机名。" : "Set PTR of your server IP to the mail hostname at your provider."}
                  </strong>
                </div>
              </>)}

            {step === 2 && (<>
                <StepHead icon={<IconRelay size={16}/>} n={3} title={zh ? "出站中继与 25 端口策略" : "Outbound Relay & Ports"} sub={zh ? "多数云厂商拦截出站 25 端口；可通过 587 / 465 / 2525 经第三方中继发信。" : "Bypass cloud port-25 blocks via relay on 587 / 465 / 2525."} right={<button className="btn glass--control" style={{ color: "rgb(var(--accent-rgb))" }} disabled={testing || relayId === "direct"} onClick={async () => {
                    setTesting(true);
                    const r = await rpc<{
                        connected?: boolean;
                        success?: boolean;
                        stage?: string;
                        latencyMs?: number;
                        error?: {
                            message?: string;
                        };
                    }>("setup.relay.test", {
                        host: relayHost,
                        port: relayPort,
                        tlsMode: relayPort === 465 ? "SSL/TLS" : "STARTTLS",
                        username: relayUser,
                        password: relayPass,
                    });
                    setTesting(false);
                    if (r.ok && (r.data?.connected ?? r.data?.success)) {
                        setRelayTested(true);
                        toast(`${zh ? "中继鉴权成功" : "Relay authenticated"}${r.data?.latencyMs != null ? ` · ${r.data.latencyMs}ms` : ""}`);
                    }
                    else if (r.ok) {
                        toast(r.data?.error?.message ?? r.data?.stage ?? (zh ? "中继测试失败" : "Relay test failed"), "err");
                    }
                    else
                        toast(r.error, "err");
                }}>
                      {testing ? "…" : relayTested ? "✓ " + (zh ? "中继鉴权成功" : "Relay OK") : zh ? "测试中继连通性" : "Test relay"}
                    </button>}/>
                <div className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  {providers.map((p) => (<button key={p.id} onClick={() => {
                    setRelayId(p.id);
                    setRelayHost(p.host);
                    setRelayPort(p.port);
                    setRelayTested(false);
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
                <div className="mt-3 rounded-[12px] p-3 text-[11.5px] leading-relaxed" style={{ background: "rgb(var(--warn-rgb) / 0.1)", boxShadow: "inset 0 0 0 1px rgb(var(--warn-rgb) / 0.3)", color: "rgb(var(--warn-rgb))" }}>
                  <strong>SPF：</strong>
                  {zh ? "同一主机名只能发布一条 v=spf1 开头的 TXT 记录；MailStack 会合并直接投递与中继授权，不会生成重复 SPF。" : "Only one v=spf1 TXT record per name; MailStack merges direct and relay authorization."}
                </div>
                {relayId !== "direct" && (<div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">

                    <Field label={zh ? "中继 SMTP 服务器" : "Relay host"} value={relayHost} onChange={(v) => { setRelayHost(v); setRelayTested(false); }}/>
                    <Field label={zh ? "中继端口（587 / 465）" : "Relay port"} value={String(relayPort)} onChange={(v) => { setRelayPort(Number(v) || 587); setRelayTested(false); }}/>
                    <Field label={zh ? "SMTP 授权用户名" : "SMTP username"} value={relayUser} onChange={(v) => { setRelayUser(v); setRelayTested(false); }}/>
                    <Field label={zh ? "SMTP 授权密码" : "SMTP password"} type="password" value={relayPass} onChange={(v) => { setRelayPass(v); setRelayTested(false); }}/>
                  </div>)}
              </>)}

            {step === 3 && (<>
                <StepHead icon={<IconShield size={16}/>} n={4} title={zh ? "TLS 证书自动签发" : "TLS Certificate"} sub={zh ? "自动申请 Let's Encrypt ECC 证书，为 SMTP 465/587 与 IMAP 993 提供 TLS 1.3 加密。" : "Automated Let's Encrypt issuance with TLS 1.3."} right={<button className="btn glass--control" style={{ color: "rgb(var(--ok-rgb))" }} disabled={issuing || certIssued} onClick={async () => {
                    setIssuing(true);
                    const r = await rpc<{
                        status?: string;
                        method?: string;
                        reloaded?: boolean;
                        cert?: {
                            domain?: string;
                            issuer?: string | null;
                            notAfter?: string | null;
                            daysUntilExpiry?: number | null;
                            keyMode?: string | null;
                            error?: string | null;
                        };
                    }>("setup.cert.issue", { domain: mailHost, email: `postmaster@${domain}` });
                    setIssuing(false);
                    if (r.ok) {
                        const d = r.data;
                        const c = d?.cert;
                        const okIssue = d?.status != null ? d.status === "ok" : !!d?.cert && !d.cert.error;
                        if (!okIssue) {
                            setCertIssued(false);
                            const msg = c?.error ?? (d?.status != null ? `status: ${d.status}` : zh ? "服务器未返回证书" : "no certificate in response");
                            toast(zh ? `证书签发失败：${msg}` : `Certificate issuance failed: ${msg}`, "err");
                        }
                        else {
                            setCertInfo({
                                domain: c?.domain ?? mailHost,
                                issuer: c?.issuer ?? "",
                                notAfter: c?.notAfter ?? "",
                                daysLeft: c?.daysUntilExpiry ?? null,
                                keyMode: c?.keyMode ?? null,
                            });
                            setCertIssued(true);
                            toast(zh ? "证书签发成功" : "Certificate issued");
                        }
                    }
                    else
                        toast(r.error, "err");
                }}>
                      {issuing ? "ACME …" : certIssued ? "✓ " + (zh ? "证书已挂载" : "Issued") : zh ? "一键签发证书" : "Issue certificate"}
                    </button>}/>

                <div className="glass--well mt-4 space-y-2.5 rounded-[12px] p-4 text-[12.5px]">
                  {[
                [zh ? "证书域名" : "Domain", certInfo ? certInfo.domain : mailHost || "—"],
                [zh ? "签发机构" : "Issuer", certInfo ? certInfo.issuer || "—" : "—"],
                [zh ? "到期时间" : "Expires", certInfo ? certInfo.notAfter || "—" : "—"],
                [zh ? "剩余天数" : "Days left", certInfo ? (certInfo.daysLeft == null ? "—" : String(certInfo.daysLeft)) : "—"],
                [zh ? "私钥权限" : "Key mode", certInfo ? certInfo.keyMode ?? "—" : "—"],
            ].map(([k, v]) => (<div key={k} className="flex items-baseline justify-between gap-4">
                      <span className="shrink-0 text-[var(--text-3)]">{k}</span>
                      <span className="truncate text-right font-medium text-[var(--text-1)]">{v}</span>
                    </div>))}
                  {!certInfo && (<div className="text-[11px] leading-relaxed text-[var(--text-3)]">
                      {zh ? "尚未签发，暂无实际数据。签发需服务器已安装 acme.sh，并能用 80 端口完成 standalone 校验。" : "Not issued yet. Issuance requires acme.sh on the server and port 80 for the standalone challenge."}
                    </div>)}
                </div>
              </>)}

            {step === 4 && (<>
                <StepHead icon={<IconMail size={16}/>} n={5} title={zh ? "初始管理员邮箱与端到端发信测试" : "Admin Mailbox & End-to-End Test"} sub={zh ? "先创建首个管理员邮箱，再发送一封全链路诊断测试邮件。" : "Create the primary admin mailbox first, then run a live delivery test."} right={<button className="btn btn-accent" disabled={sending || !s5ok} onClick={async () => {
                    const adminEmail = `admin@${domain}`;
                    setSending(true);
                    setPhase("account");
                    const add = await rpc<unknown[]>("users.add", {
                        address: adminEmail,
                        username: ADMIN_ACCOUNT,
                        password: adminPass,
                        name: adminName.trim(),
                    });
                    if (!add.ok && !/already exists/i.test(add.error)) {
                        setPhase("");
                        setSending(false);
                        setMailboxReady(false);
                        toast(add.error, "err");
                        return;
                    }
                    setMailboxReady(true);
                    setPhase("mail");
                    const r = await rpc<{
                        queued?: boolean;
                        roundTripVerified?: boolean;
                        scope?: string;
                        code?: number;
                    }>("setup.mail.test", { sender: adminEmail, recipient: adminEmail, username: ADMIN_ACCOUNT, password: adminPass });
                    setPhase("");
                    setSending(false);
                    if (r.ok && r.data?.queued) {
                        setTestSent(true);
                        toast(`${zh ? "测试邮件已入队" : "Test mail queued"}${r.data?.code != null ? ` · ${r.data.code}` : ""}`);
                    }
                    else {
                        const msg = r.ok ? `code ${r.data?.code ?? "?"}` : r.error;
                        if (/managed mailbox/i.test(msg)) {
                            toast(`${zh ? "管理员邮箱尚未建好，无法作为发件人——请修正上面的问题后重试建号：" : "Admin mailbox is not registered yet and cannot be the sender — fix the fields above and retry: "}${msg}`, "err");
                        }
                        else
                            toast(msg, "err");
                        setTestSent(false);
                    }
                }}>
                      {phase === "account"
                    ? zh ? "① 创建邮箱…" : "① Creating mailbox…"
                    : phase === "mail"
                        ? zh ? "② 发送测试信…" : "② Sending test…"
                        : sending
                            ? "…"
                            : testSent
                                ? "✓ " + (zh ? "已入队" : "Queued")
                                : zh ? "① 建号 → ② 发信测试" : "① Create mailbox → ② Send test"}
                    </button>}/>
                <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
                  <Field label={zh ? "管理员邮箱" : "Mailbox"} value={`admin@${domain || "example.com"}`} disabled hint={zh ? "固定为 admin@主域名，对应系统账号 admin" : "admin@<domain>, backed by the system account admin"}/>
                  <Field label={zh ? "管理员姓名" : "Display name"} value={adminName} onChange={setAdminName}/>
                  <Field label={zh ? "初始密码（≥12 位，含字母与数字）" : "Initial password (12+ chars)"} type="password" value={adminPass} onChange={setAdminPass} req placeholder="••••••••••••" hint={zh ? "不得包含 admin 或完整邮箱地址，也不能有 3 个连续/重复字符" : "must not contain admin or the full address, nor 3 consecutive/equal chars"}/>
                </div>

                <div className="mt-3 space-y-2">
                  {[
                {
                    key: "account",
                    label: zh ? "① 创建受管邮箱 admin@" + (domain || "example.com") : "① Create managed mailbox admin@" + (domain || "example.com"),
                    done: mailboxReady,
                    active: phase === "account",
                    hint: zh ? "users.add：建系统账号、写口令与 Maildir、登记受管邮箱表" : "users.add: system account + Maildir + managed-mailbox registry",
                },
                {
                    key: "mail",
                    label: zh ? "② 发送端到端测试信" : "② Send end-to-end test mail",
                    done: testSent,
                    active: phase === "mail",
                    hint: zh ? "setup.mail.test：向本机提交端点投信并检查应答码" : "setup.mail.test: submit to the local MTA and read the reply code",
                },
            ].map((s) => (<div key={s.key} className="flex items-start gap-2.5 rounded-[12px] p-3 text-[12px]" style={{ background: "rgb(var(--text-1) / 0.03)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}>
                      <span style={{ color: s.done ? "rgb(var(--ok-rgb))" : s.active ? "rgb(var(--accent-rgb))" : "var(--text-3)" }}>
                        {s.done ? <IconCheck size={13}/> : s.active ? "…" : <IconUser size={13}/>}
                      </span>
                      <span className="min-w-0">
                        <span className="font-medium text-[var(--text-1)]">{s.label}</span>
                        <span className="mt-0.5 block text-[11px] leading-relaxed text-[var(--text-3)]">{s.hint}</span>
                      </span>
                    </div>))}
                </div>
                {testSent && (<div className="mt-3 rounded-[12px] p-3.5 text-[12px] leading-relaxed" style={{ background: "rgb(var(--ok-rgb) / 0.1)", boxShadow: "inset 0 0 0 1px rgb(var(--ok-rgb) / 0.3)", color: "rgb(var(--ok-rgb))" }}>
                    <strong>{zh ? "端到端全链路诊断：" : "End-to-end diagnostic:"}</strong>{" "}
                    {zh ? "本机 MTA 已接受测试邮件进入队列。该结果不代表收件方已接收，也不代表 SPF/DKIM/DMARC 已通过，请继续查看队列与邮件头。" : "The local MTA accepted the test message. Delivery and SPF/DKIM/DMARC still need verification via headers."}
                  </div>)}
              </>)}

            {step === 5 && (<div className="flex flex-col items-center py-4 text-center">
                <span className="flex h-16 w-16 items-center justify-center rounded-full" style={{
                background: "linear-gradient(135deg, rgb(var(--ok-rgb)), rgb(var(--accent-rgb)))",
                color: "#fff",
                boxShadow: "0 8px 24px rgb(var(--accent-rgb) / 0.35), inset 0 1px 0 rgba(255,255,255,.4)",
            }}>
                  <IconCheck size={30}/>
                </span>
                <h2 className="mt-4 text-[22px] font-bold tracking-[-0.01em] text-[var(--text-1)]">
                  {zh ? "配置步骤已完成" : "Setup Complete"}
                </h2>
                <p className="mt-2 max-w-[520px] text-[12.5px] leading-relaxed text-[var(--text-2)]">
                  {zh ? "邮件域名已完成服务器写入与在线检测。邮件送达与信誉仍需通过真实收发和邮件头持续验证。" : "Your domain is configured. Deliverability still requires real-world verification."}
                </p>
                <div className="mt-5 grid w-full max-w-[560px] grid-cols-1 gap-2.5 sm:grid-cols-3">
                  {[
                [zh ? "当前域名" : "Domain", "@" + (domain || "example.com")],
                [zh ? "出站通道" : "Relay", relayId.toUpperCase()],
                [zh ? "向导状态" : "Status", zh ? "已完成" : "Completed"],
            ].map(([k, v]) => (<div key={k} className="glass--well rounded-[12px] p-3 text-left">
                      <div className="text-[10px] uppercase tracking-wider text-[var(--text-3)]">{k}</div>
                      <div className="mt-0.5 truncate text-[13px] font-bold text-[var(--text-1)]">{v}</div>
                    </div>))}
                </div>
                <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
                  <button className="btn btn-accent h-11 px-7 text-[14px] font-bold" disabled={finishing} onClick={() => void finish()}>
                    {finishing ? "…" : zh ? "进入系统控制台" : "Launch MailStack Console"}
                    <IconChevronRight size={15}/>
                  </button>
                  <button className="btn glass--control h-11" onClick={() => setStep(0)}>
                    {zh ? "重新检查配置" : "Review Setup"}
                  </button>
                </div>
              </div>)}

            {step < 5 && (<div className="mt-6 flex items-center justify-between border-t pt-4" style={{ borderColor: "var(--hairline)" }}>
                <button className="btn glass--control" onClick={() => setStep((s) => Math.max(0, s - 1))} style={{ visibility: step === 0 ? "hidden" : "visible" }}>
                  ← {zh ? "上一步" : "Back"}
                </button>
                <button className="btn btn-accent" disabled={busy ||
                (step === 0 && !s1ok) ||
                (step === 1 && !dnsVerified) ||
                (step === 2 && !relayTested && relayId !== "direct") ||
                (step === 3 && !certIssued) ||
                (step === 4 && !testSent)} onClick={next}>
                  {[
                zh ? "下一步：配置 DNS 记录" : "Next: DNS records",
                zh ? "下一步：配置出站中继" : "Next: Outbound relay",
                zh ? "下一步：TLS 证书" : "Next: TLS certificate",
                zh ? "下一步：管理员与发信测试" : "Next: Admin & test",
                zh ? "下一步：完成部署" : "Next: Finish",
            ][step]}
                  <IconChevronRight size={14}/>
                </button>
              </div>)}
          </section>
        </motion.div>
      </AnimatePresence>

      <div className="mt-4 flex items-center justify-center gap-2 text-[11px] text-[var(--text-3)]">
        <IconPlus size={11} style={{ transform: "rotate(45deg)" }}/>
        {zh ? "所有写入都会先在服务器执行真实操作，成功后才反馈" : "Every write runs on the server before success is reported"}
      </div>
      <div className="mt-1 flex items-center justify-center gap-1.5 text-[11px] text-[var(--text-3)]">
        <IconUser size={11}/> {zh ? "需要管理员权限" : "Administrator privileges required"} · RW channel
      </div>
      <div className="mb-2 mt-3 flex items-center justify-center gap-1.5 text-[11px] text-[var(--text-3)]">
        <IconChevronDown size={11}/> {t("settings_title")} · setup.status / setup.identity.apply / domains.add / setup.dns.verify / setup.relay.apply / setup.cert.issue / users.add / setup.mail.test / setup.wizard.complete
      </div>
    </div>);
}
function StepHead({ icon, n, title, sub, right }: {
    icon: React.ReactNode;
    n: number;
    title: string;
    sub: string;
    right?: React.ReactNode;
}) {
    return (<div className="flex flex-wrap items-start justify-between gap-3 border-b pb-4" style={{ borderColor: "var(--hairline)" }}>
      <div className="min-w-0">
        <h2 className="flex items-center gap-2 text-[15px] font-bold text-[var(--text-1)]">
          <span className="flex h-7 w-7 items-center justify-center rounded-[9px]" style={{ background: "rgb(var(--accent-rgb) / 0.12)", color: "rgb(var(--accent-rgb))" }}>
            {icon}
          </span>
          <span>
            <span className="tnum mr-1.5 text-[var(--text-3)]">{n}.</span>
            {title}
          </span>
        </h2>
        <p className="mt-1 text-[12px] leading-relaxed text-[var(--text-2)]">{sub}</p>
      </div>
      {right}
    </div>);
}
function Field({ label, value, onChange, placeholder, hint, req, disabled, type = "text", }: {
    label: string;
    value: string;
    onChange?: (v: string) => void;
    placeholder?: string;
    hint?: string;
    req?: boolean;
    disabled?: boolean;
    type?: string;
}) {
    return (<label className="block">
      <span className="mb-1.5 block text-[11.5px] font-semibold text-[var(--text-2)]">
        {label} {req && <b style={{ color: "rgb(var(--err-rgb))" }}>*</b>}
      </span>
      <input className={"input" + (disabled ? " opacity-60" : "")} type={type} value={value} placeholder={placeholder} disabled={disabled} onChange={(e) => onChange?.(e.target.value)}/>
      {hint && <span className="mt-1 block text-[10.5px] leading-relaxed text-[var(--text-3)]">{hint}</span>}
    </label>);
}

import { useCallback, useEffect, useState, useContext } from "react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { RefreshContext } from "../App";
import { PageHeader, Card, DataPanel, StatusBadge, LoadError, toast } from "../components/ui";
import { DataTable, type Column } from "../components/DataTable";
import { IconShield, IconCheck, IconX, IconWarn } from "../components/icons";
import { formatDayTime } from "../lib/format";
type Finding = {
    id?: string;
    path?: string;
    severity?: string;
    title?: string;
    issue?: string;
    detail?: string;
    note?: string;
    advice?: string;
};
type Ban = {
    ip: string;
    reason?: string;
    jail?: string;
    time?: string;
    until?: string;
    fails?: number | null;
};
type Scan = {
    score?: number;
    scanned?: number;
    scannedAt?: string;
    lastScan?: string;
    findings?: Finding[];
    bans?: Ban[];
    bannedIps?: Ban[] | null;
    failedLogins24h?: number;
};
type DnsRecord = {
    type?: string;
    name?: string;
    value?: string;
    ok?: boolean;
};
type ServiceRow = {
    key?: string;
    running?: boolean;
    detail?: string;
};
type CheckState = boolean | null;
function recordsCheck(records: DnsRecord[] | null, match: (r: DnsRecord) => boolean): CheckState {
    if (!records)
        return null;
    const matched = records.filter(match);
    if (matched.length === 0)
        return null;
    return matched.every((r) => r.ok === true);
}
function failedOf(records: DnsRecord[] | null, match: (r: DnsRecord) => boolean): number {
    if (!records)
        return 0;
    return records.filter((r) => match(r) && r.ok !== true).length;
}
function sevKind(sev?: string): "err" | "warn" | "info" {
    switch (sev) {
        case "high":
        case "err":
            return "err";
        case "medium":
        case "warn":
            return "warn";
        default:
            return "info";
    }
}
export default function Security() {
    const { t } = useSettings();
    const refreshN = useContext(RefreshContext);
    const [scan, setScan] = useState<Scan | null>(null);
    const [scanErr, setScanErr] = useState<string | null>(null);
    const [dns, setDns] = useState<DnsRecord[] | null>(null);
    const [services, setServices] = useState<ServiceRow[] | null>(null);
    const load = useCallback(() => {
        rpc<Scan>("security.scan").then((r) => {
            if (r.ok && r.data) {
                setScan(r.data);
                setScanErr(null);
            }
            else if (!r.ok)
                setScanErr(r.error);
        });
        rpc<DnsRecord[]>("dns.records").then((r) => r.ok && setDns(Array.isArray(r.data) ? r.data : null));
        rpc<ServiceRow[]>("services.list").then((r) => r.ok && setServices(Array.isArray(r.data) ? r.data : null));
    }, []);
    useEffect(() => {
        load();
    }, [load, refreshN]);
    async function unban(ip: string) {
        const r = await rpc("security.unban", { ip });
        if (r.ok) {
            toast(`${ip} · ${t("unbanned")}`);
            setScan((s) => (s ? { ...s, bannedIps: (s.bannedIps ?? []).filter((b) => b.ip !== ip), bans: (s.bans ?? []).filter((b) => b.ip !== ip) } : s));
        }
        else
            toast(r.error, "err");
    }
    if (!scan)
        return (<div className="p-4">
        {scanErr ? (<Card>
            <LoadError message={scanErr} onRetry={load}/>
          </Card>) : (<div className="skeleton h-64"/>)}
      </div>);
    const findings = scan.findings ?? [];
    const bans = scan.bans ?? scan.bannedIps ?? [];
    const score = scan.score ?? (scan.scanned ? Math.round(((scan.scanned - findings.length) / scan.scanned) * 100) : null);
    const lastScan = scan.scannedAt ?? scan.lastScan ?? "";
    const spfMatch = (r: DnsRecord) => (r.value ?? "").trim().startsWith("v=spf1");
    const dmarcMatch = (r: DnsRecord) => (r.name ?? "").trim().startsWith("_dmarc.");
    const dkimMatch = (r: DnsRecord) => (r.name ?? "").includes("._domainkey.");
    const f2b = services?.find((s) => s.key === "fail2ban" || s.key === "fail2ban-server");
    const rows: {
        label: string;
        state: CheckState;
        failed: number;
    }[] = [
        { label: "SPF", state: recordsCheck(dns, spfMatch), failed: failedOf(dns, spfMatch) },
        { label: "DMARC", state: recordsCheck(dns, dmarcMatch), failed: failedOf(dns, dmarcMatch) },
        { label: "DKIM", state: recordsCheck(dns, dkimMatch), failed: failedOf(dns, dkimMatch) },
        { label: "fail2ban", state: f2b ? f2b.running === true : null, failed: 0 },
    ];
    return (<div className="p-4">
      <PageHeader title={t("security_title")} sub={t("security_sub")} right={<span className="badge badge-neutral">{t("last_scan")} · {lastScan ? formatDayTime(lastScan) : "—"}</span>}/>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[300px_minmax(0,1fr)]">

        <div className="flex flex-col gap-3">
          <Card className="flex flex-col items-center py-6">
            <ScoreRing score={score}/>
            <div className="mt-3 text-[13px] font-semibold text-[var(--text-1)]">{t("threat_scan")}</div>
            <div className="text-[11.5px] text-[var(--text-3)]">
              {scan.failedLogins24h != null ? `${scan.failedLogins24h} ${t("failed_logins")} · 24h` : t("findings_count", { n: findings.length })}
            </div>
          </Card>
          <Card>
            <div className="space-y-2.5 text-[12.5px]">
              {rows.map((row) => (<div key={row.label} className="flex items-center justify-between">
                  <span className="text-[var(--text-2)]">{row.label}</span>
                  {row.state == null ? (<span className="text-[var(--text-3)]" title={t("unverified")}>—</span>) : row.state ? (<span className="inline-flex items-center gap-1 font-medium" style={{ color: "rgb(var(--ok-rgb))" }}>
                      <IconCheck size={13}/> {t("verified")}
                    </span>) : (<span className="inline-flex items-center gap-1 font-medium" style={{ color: "rgb(var(--err-rgb))" }}>
                      <IconX size={13}/> {t("unverified")}
                      {row.failed > 0 && <span className="tnum text-[11px] text-[var(--text-3)]">({row.failed})</span>}
                    </span>)}
                </div>))}
            </div>
          </Card>
        </div>

        <div className="flex min-w-0 flex-col gap-3">

          <Card>
            <h2 className="mb-2.5 text-[13.5px] font-semibold text-[var(--text-1)]">{t("threat_scan")}</h2>
            <div className="space-y-2">
              {findings.map((f, i) => {
            const kind = sevKind(f.severity);
            return (<div key={f.id ?? `${f.path ?? "finding"}-${i}`} className="glass--well flex items-start gap-3 rounded-[12px] p-3">
                    <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-[9px]" style={{
                    background: kind === "err" ? "rgb(var(--err-rgb) / 0.12)" : kind === "warn" ? "rgb(var(--warn-rgb) / 0.14)" : "rgb(var(--accent-rgb) / 0.10)",
                    color: kind === "err" ? "rgb(var(--err-rgb))" : kind === "warn" ? "rgb(var(--warn-rgb))" : "rgb(var(--accent-rgb))",
                }}>
                      {kind === "info" ? <IconShield size={14}/> : <IconWarn size={14}/>}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[13px] font-medium text-[var(--text-1)]">{f.issue ?? f.title ?? "—"}</span>
                        <StatusBadge kind={kind} label={(f.severity ?? "info").toUpperCase()}/>
                      </div>
                      <div className="mt-0.5 text-[12px] text-[var(--text-2)]">{f.detail ?? ""}</div>
                      {(f.note ?? f.advice) && <div className="mt-0.5 text-[11.5px] text-[var(--text-3)]">→ {f.note ?? f.advice}</div>}
                      {f.path && <div className="mono mt-0.5 text-[11px] text-[var(--text-3)]">{f.path}</div>}
                    </div>
                  </div>);
        })}
            </div>
          </Card>

          <DataPanel>
            <div className="px-3 pt-3 pb-1.5 text-[13.5px] font-semibold text-[var(--text-1)]">{t("banned_ips")}</div>
            <BansTable bans={bans} onUnban={unban}/>
          </DataPanel>
        </div>
      </div>
    </div>);
}
function ScoreRing({ score }: {
    score: number | null;
}) {
    const R = 52;
    const C = 2 * Math.PI * R;
    const pct = score == null ? 0 : score / 100;
    const color = score == null ? "var(--text-3)" : score >= 80 ? "rgb(var(--ok-rgb))" : score >= 60 ? "rgb(var(--warn-rgb))" : "rgb(var(--err-rgb))";
    return (<div className="relative" style={{ width: 132, height: 132 }}>
      <svg viewBox="0 0 132 132" width={132} height={132}>
        <circle cx="66" cy="66" r={R} fill="none" stroke="var(--bar-track)" strokeWidth="10"/>
        <circle cx="66" cy="66" r={R} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${C * pct} ${C}`} transform="rotate(-90 66 66)" style={{ transition: "stroke-dasharray .8s cubic-bezier(.32,.72,0,1)" }}/>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="tnum text-[30px] font-semibold leading-none text-[var(--text-1)]">{score ?? "—"}</span>
        <span className="mt-1 text-[11px] text-[var(--text-3)]">/ 100</span>
      </div>
    </div>);
}
function BansTable({ bans, onUnban }: {
    bans: Ban[];
    onUnban: (ip: string) => void;
}) {
    const { t } = useSettings();
    const cols: Column<Ban>[] = [
        { key: "ip", header: "IP", sortValue: (r) => r.ip, render: (r) => <span className="mono font-medium">{r.ip}</span>, width: 150 },
        { key: "reason", header: t("reason"), render: (r) => <span className="text-[var(--text-2)]">{r.reason || "—"}</span> },
        { key: "fails", header: t("failed_logins"), align: "right", sortValue: (r) => r.fails ?? -1, render: (r) => <span className="tnum">{r.fails ?? "—"}</span>, width: 110 },
        { key: "until", header: t("expires"), sortValue: (r) => r.until ?? r.time ?? "", render: (r) => <span className="tnum text-[var(--text-2)]">{r.until ?? r.time ?? "—"}</span>, width: 160 },
        {
            key: "act",
            header: "",
            align: "right",
            render: (r) => (<button className="btn glass--control" style={{ height: 28, fontSize: 12, color: "rgb(var(--accent-rgb))" }} onClick={() => onUnban(r.ip)}>
          {t("unban")}
        </button>),
            width: 90,
        },
    ];
    return <DataTable columns={cols} rows={bans} rowKey={(r) => r.ip} pageSize={5} filterKeys={(r) => `${r.ip} ${r.reason ?? ""}`} filterPlaceholder="IP"/>;
}

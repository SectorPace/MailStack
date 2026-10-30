// 安全中心 —— 威胁扫描结果 / 封禁列表解封（security.scan / security.unban）
//
// 后端 security.scan 的真实形状：{ ok, scannedAt, scanned, absent, findings:
// [{ path, severity(high|medium|info), issue, mode, maxMode, note, detail }],
// summary:{high,medium,info}, highestSeverity, bannedIps:[{ip,jail,time,reason}],
// bannedIpScope:"manual" }。它**没有** score / lastScan / failedLogins24h，
// 封禁条目也没有 fails/until —— 这些一律显示占位符或按真实数据推导，绝不编造。
// 下面的类型与读取同时兼容 mock 的旧形状。
import { useEffect, useState, useContext } from "react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { RefreshContext } from "../App";
import { PageHeader, Card, DataPanel, StatusBadge, toast } from "../components/ui";
import { DataTable, type Column } from "../components/DataTable";
import { IconShield, IconCheck, IconX, IconWarn } from "../components/icons";

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

type Ban = { ip: string; reason?: string; jail?: string; time?: string; until?: string; fails?: number | null };

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

/** 后端 dns.records 的条目：ok 是**实查**结果，value 是应发布值。 */
type DnsRecord = { type?: string; name?: string; value?: string; ok?: boolean };
/** 后端 services.list 的条目。 */
type ServiceRow = { key?: string; running?: boolean; detail?: string };

/** 三态：true = 已验证，false = 未验证，null = 后端没有该项数据（显示 —）。 */
type CheckState = boolean | null;

function recordsCheck(records: DnsRecord[] | null, match: (r: DnsRecord) => boolean): CheckState {
  if (!records) return null;
  const matched = records.filter(match);
  if (matched.length === 0) return null; // 后端没列出该记录 → 未知，绝不当作已验证
  return matched.every((r) => r.ok === true);
}

function failedOf(records: DnsRecord[] | null, match: (r: DnsRecord) => boolean): number {
  if (!records) return 0;
  return records.filter((r) => match(r) && r.ok !== true).length;
}

/** high/medium/info（后端）与 err/warn/info（mock）统一为 UI 三态。 */
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
  // SPF / DMARC / DKIM 只能从 dns.records 的**实查结果**得到（security.scan 的 findings
  // 是文件系统审计项）；fail2ban 状态来自 services.list。两者都缺失时显示 —。
  const [dns, setDns] = useState<DnsRecord[] | null>(null);
  const [services, setServices] = useState<ServiceRow[] | null>(null);

  useEffect(() => {
    rpc<Scan>("security.scan").then((r) => r.ok && setScan(r.data));
    rpc<DnsRecord[]>("dns.records").then((r) => r.ok && setDns(Array.isArray(r.data) ? r.data : null));
    rpc<ServiceRow[]>("services.list").then((r) => r.ok && setServices(Array.isArray(r.data) ? r.data : null));
  }, [refreshN]);

  async function unban(ip: string) {
    const r = await rpc("security.unban", { ip });
    if (r.ok) {
      toast(`${ip} · ${t("unbanned")}`);
      setScan((s) => (s ? { ...s, bannedIps: (s.bannedIps ?? []).filter((b) => b.ip !== ip), bans: (s.bans ?? []).filter((b) => b.ip !== ip) } : s));
    } else toast(r.error, "err");
  }

  if (!scan) return <div className="p-4"><div className="skeleton h-64" /></div>;

  const findings = scan.findings ?? [];
  const bans = scan.bans ?? scan.bannedIps ?? [];
  // 后端不给「分数」；用「已扫描路径中没有问题的比例」作为唯一由真实数据推导的指标。
  const score = scan.score ?? (scan.scanned ? Math.round(((scan.scanned - findings.length) / scan.scanned) * 100) : null);
  const lastScan = scan.scannedAt ?? scan.lastScan ?? "";

  const spfMatch = (r: DnsRecord) => (r.value ?? "").trim().startsWith("v=spf1");
  const dmarcMatch = (r: DnsRecord) => (r.name ?? "").trim().startsWith("_dmarc.");
  const dkimMatch = (r: DnsRecord) => (r.name ?? "").includes("._domainkey.");
  const f2b = services?.find((s) => s.key === "fail2ban" || s.key === "fail2ban-server");
  const rows: { label: string; state: CheckState; failed: number }[] = [
    { label: "SPF", state: recordsCheck(dns, spfMatch), failed: failedOf(dns, spfMatch) },
    { label: "DMARC", state: recordsCheck(dns, dmarcMatch), failed: failedOf(dns, dmarcMatch) },
    { label: "DKIM", state: recordsCheck(dns, dkimMatch), failed: failedOf(dns, dkimMatch) },
    { label: "fail2ban", state: f2b ? f2b.running === true : null, failed: 0 },
  ];

  return (
    <div className="p-4">
      <PageHeader
        title={t("security_title")}
        sub={t("security_sub")}
        right={<span className="badge badge-neutral">{t("last_scan")} · {lastScan ? lastScan.slice(5, 16) : "—"}</span>}
      />

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[300px_minmax(0,1fr)]">
        {/* 健康分 */}
        <div className="flex flex-col gap-3">
          <Card className="flex flex-col items-center py-6">
            <ScoreRing score={score} />
            <div className="mt-3 text-[13px] font-semibold text-[var(--text-1)]">{t("threat_scan")}</div>
            <div className="text-[11.5px] text-[var(--text-3)]">
              {scan.failedLogins24h != null ? `${scan.failedLogins24h} ${t("failed_logins")} · 24h` : `${findings.length} findings`}
            </div>
          </Card>
          <Card>
            <div className="space-y-2.5 text-[12.5px]">
              {rows.map((row) => (
                <div key={row.label} className="flex items-center justify-between">
                  <span className="text-[var(--text-2)]">{row.label}</span>
                  {row.state == null ? (
                    <span className="text-[var(--text-3)]" title={t("unverified")}>—</span>
                  ) : row.state ? (
                    <span className="inline-flex items-center gap-1 font-medium" style={{ color: "rgb(var(--ok-rgb))" }}>
                      <IconCheck size={13} /> {t("verified")}
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 font-medium" style={{ color: "rgb(var(--err-rgb))" }}>
                      <IconX size={13} /> {t("unverified")}
                      {row.failed > 0 && <span className="tnum text-[11px] text-[var(--text-3)]">({row.failed})</span>}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div className="flex min-w-0 flex-col gap-3">
          {/* 扫描发现 */}
          <Card>
            <h2 className="mb-2.5 text-[13.5px] font-semibold text-[var(--text-1)]">{t("threat_scan")}</h2>
            <div className="space-y-2">
              {findings.map((f, i) => {
                const kind = sevKind(f.severity);
                return (
                  <div key={f.id ?? `${f.path ?? "finding"}-${i}`} className="glass--well flex items-start gap-3 rounded-[12px] p-3">
                    <span
                      className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-[9px]"
                      style={{
                        background: kind === "err" ? "rgb(var(--err-rgb) / 0.12)" : kind === "warn" ? "rgb(var(--warn-rgb) / 0.14)" : "rgb(var(--accent-rgb) / 0.10)",
                        color: kind === "err" ? "rgb(var(--err-rgb))" : kind === "warn" ? "rgb(var(--warn-rgb))" : "rgb(var(--accent-rgb))",
                      }}
                    >
                      {kind === "info" ? <IconShield size={14} /> : <IconWarn size={14} />}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[13px] font-medium text-[var(--text-1)]">{f.issue ?? f.title ?? "—"}</span>
                        <StatusBadge kind={kind} label={(f.severity ?? "info").toUpperCase()} />
                      </div>
                      <div className="mt-0.5 text-[12px] text-[var(--text-2)]">{f.detail ?? ""}</div>
                      {(f.note ?? f.advice) && <div className="mt-0.5 text-[11.5px] text-[var(--text-3)]">→ {f.note ?? f.advice}</div>}
                      {f.path && <div className="mono mt-0.5 text-[11px] text-[var(--text-3)]">{f.path}</div>}
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>

          {/* 封禁列表 */}
          <DataPanel>
            <div className="px-3 pt-3 pb-1.5 text-[13.5px] font-semibold text-[var(--text-1)]">{t("banned_ips")}</div>
            <BansTable bans={bans} onUnban={unban} />
          </DataPanel>
        </div>
      </div>
    </div>
  );
}

function ScoreRing({ score }: { score: number | null }) {
  const R = 52;
  const C = 2 * Math.PI * R;
  const pct = score == null ? 0 : score / 100;
  const color = score == null ? "var(--text-3)" : score >= 80 ? "rgb(var(--ok-rgb))" : score >= 60 ? "rgb(var(--warn-rgb))" : "rgb(var(--err-rgb))";
  return (
    <div className="relative" style={{ width: 132, height: 132 }}>
      <svg viewBox="0 0 132 132" width={132} height={132}>
        <circle cx="66" cy="66" r={R} fill="none" stroke="var(--bar-track)" strokeWidth="10" />
        <circle
          cx="66"
          cy="66"
          r={R}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${C * pct} ${C}`}
          transform="rotate(-90 66 66)"
          style={{ transition: "stroke-dasharray .8s cubic-bezier(.32,.72,0,1)" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="tnum text-[30px] font-semibold leading-none text-[var(--text-1)]">{score ?? "—"}</span>
        <span className="mt-1 text-[11px] text-[var(--text-3)]">/ 100</span>
      </div>
    </div>
  );
}

function BansTable({ bans, onUnban }: { bans: Ban[]; onUnban: (ip: string) => void }) {
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
      render: (r) => (
        <button className="btn glass--control" style={{ height: 28, fontSize: 12, color: "rgb(var(--accent-rgb))" }} onClick={() => onUnban(r.ip)}>
          {t("unban")}
        </button>
      ),
      width: 90,
    },
  ];
  return <DataTable columns={cols} rows={bans} rowKey={(r) => r.ip} pageSize={5} filterKeys={(r) => `${r.ip} ${r.reason ?? ""}`} filterPlaceholder="IP" />;
}

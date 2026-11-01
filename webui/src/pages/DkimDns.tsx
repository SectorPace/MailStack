// DKIM 与 DNS —— 域名密钥（轮换/发布状态）+ DNS 解析记录清单（dkim.rotate / dns.records）
import { useCallback, useEffect, useRef, useState, useContext } from "react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { RefreshContext } from "../App";
import { PageHeader, Card, DataPanel, StatusBadge, LoadError, toast } from "../components/ui";
import { IconKey, IconRefresh, IconCheck, IconX } from "../components/icons";

type DkimKey = { domain: string; selector: string; keySize: number; lastRotated: string; published: boolean };
type DnsRecord = { type: string; name: string; value: string; ttl: number; required: boolean; ok: boolean };

export default function DkimDns() {
  const { t } = useSettings();
  const refreshN = useContext(RefreshContext);
  const [keys, setKeys] = useState<DkimKey[]>([]);
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  // seq 请求序守卫：轮换后的补拉与并发刷新竞速时，只让最新一次响应落地。
  const seq = useRef(0);

  // dkim.rotate 会生成新 selector → DKIM TXT 记录内容随之改变，因此密钥与 DNS
  // 记录**必须一起**重拉（原先只刷 keys，DNS 面板停在旧公钥上）。
  const loadAll = useCallback(() => {
    const id = ++seq.current;
    rpc<DkimKey[]>("dkim.keys").then((r) => {
      if (seq.current !== id) return;
      if (r.ok) setKeys(r.data ?? []);
      else setLoadErr(r.error);
    });
    rpc<DnsRecord[]>("dns.records").then((r) => {
      if (seq.current !== id) return;
      if (r.ok) setRecords(r.data ?? []);
      else setLoadErr(r.error);
    });
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll, refreshN]);

  async function rotate(domain: string) {
    const r = await rpc<{ selector: string }>("dkim.rotate", { domain });
    if (r.ok) {
      toast(`${domain} · s/${r.data?.selector ?? "?"} ✓`);
      loadAll();
    } else toast(r.error, "err");
  }

  return (
    <div className="p-4">
      <PageHeader title={t("dkim_title")} sub={t("dkim_sub")} />
      {loadErr && <div className="mb-3"><LoadError message={loadErr} onRetry={loadAll} /></div>}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        {/* DKIM 密钥 */}
        <Card padding={false}>
          <div className="flex items-center justify-between px-4 pt-4 pb-2">
            <h2 className="text-[14px] font-semibold text-[var(--text-1)]">{t("dkim_keys")}</h2>
            <span className="badge badge-neutral">
              <IconKey size={12} /> RSA 2048
            </span>
          </div>
          <div className="space-y-2.5 px-4 pb-4">
            {keys.map((k) => (
              <div key={k.domain} className="glass--well rounded-[12px] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="leading-tight">
                    <div className="text-[13px] font-medium text-[var(--text-1)]">{k.domain}</div>
                    <div className="mono text-[11px] text-[var(--text-3)]">
                      {k.selector}._domainkey.{k.domain}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <StatusBadge kind={k.published ? "ok" : "err"} label={k.published ? t("verified") : t("unverified")} />
                    <button className="icon-btn glass--control" style={{ width: 30, height: 30 }} title={t("rotate")} aria-label={t("rotate")} onClick={() => rotate(k.domain)}>
                      <IconRefresh size={14} />
                    </button>
                  </div>
                </div>
                <div className="mt-2 flex items-center gap-4 text-[11.5px] text-[var(--text-3)]">
                  <span>{t("key_size")}: {k.keySize}</span>
                  <span>{t("last_rotated")}: {k.lastRotated.slice(0, 10)}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* DNS 记录 */}
        <DataPanel>
          <div className="px-3 pt-3 pb-1.5 text-[14px] font-semibold text-[var(--text-1)]">{t("dns_records")}</div>
          <div className="overflow-x-auto px-1.5 pb-2">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>Type</th>
                  <th>Name</th>
                  <th>Value</th>
                  <th style={{ width: 70 }}>TTL</th>
                  <th style={{ width: 80 }}>{t("status")}</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.name + r.type}>
                    <td><span className="badge badge-info" style={{ height: 20, fontSize: 11 }}>{r.type}</span></td>
                    <td className="mono text-[11.5px]">{r.name}</td>
                    <td className="mono max-w-[220px] truncate text-[11.5px] text-[var(--text-2)]" title={r.value}>{r.value}</td>
                    <td className="tnum text-[var(--text-2)]">{r.ttl}</td>
                    <td>
                      <span style={{ color: r.ok ? "rgb(var(--ok-rgb))" : "rgb(var(--err-rgb))" }} className="inline-flex items-center gap-1 text-[12px] font-medium">
                        {r.ok ? <IconCheck size={13} /> : <IconX size={13} />}
                        {r.ok ? t("verified") : t("unverified")}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </DataPanel>
      </div>
    </div>
  );
}

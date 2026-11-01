// 邮件队列与日志 —— 严格对齐示意图：Mail Queue / Logs 双 Tab + 高密度队列表 + 日志详情。
// 侧边栏「邮件队列」与「日志中心」都指向本页（初始 Tab 不同），与产品信息架构一致。
import { useCallback, useEffect, useMemo, useState, useContext } from "react";
import * as RTabs from "@radix-ui/react-tabs";
import { useSettings } from "../store/settings";
import { rpc, type RpcResult } from "../api/client";
import { useApiList } from "../hooks/useApiList";
import { RefreshContext } from "../App";
import { PageHeader, DataPanel, QueueStatus, GlassSelect, ConfirmDialog, LoadError, toast } from "../components/ui";
import { DataTable, type Column } from "../components/DataTable";
import { IconFilter, IconTrash, IconSend } from "../components/icons";
import { normalizeLog, type LogRow, type RawLog } from "../lib/logs";

// queue.list（readers.rs queue_list）的 status 只会发 sending（active 映射）与
// pending（deferred 映射）；delivered/failed/hold 在本仓库队列模型里不存在
// （已投递的条目离开队列、没有挂起位、永久失败无独立状态）。保留旧值仅为
// mock 演示数据兼容。
type QueueRow = {
  id: string;
  sender: string;
  recipient: string;
  domain: string;
  status: "delivered" | "sending" | "failed" | "pending" | "hold";
  retry: number;
  time: string;
  service: string;
};

const RANGE_MS: Record<string, number> = {
  "24h": 24 * 3600_000,
  "7d": 7 * 24 * 3600_000,
  "30d": 30 * 24 * 3600_000,
};

/** 解析后端 ISO8601 或 mock 的 "YYYY-MM-DD HH:mm:ss"；解析不了返回 null。 */
function parseTime(s?: string): number | null {
  if (!s) return null;
  const raw = s.includes("T") ? s : s.replace(" ", "T");
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? ms : null;
}

/** 时间范围过滤：解析失败时**保留**该行（宁可多显示，也不因时间格式差异误删数据）。 */
function withinRange(time: string | undefined, range: string): boolean {
  const windowMs = RANGE_MS[range];
  const ts = parseTime(time);
  if (!windowMs || ts == null) return true;
  return Date.now() - ts <= windowMs;
}

export default function MailQueue({ initialTab = "queue" }: { initialTab?: "queue" | "logs" }) {
  const { t } = useSettings();
  const refreshN = useContext(RefreshContext);
  const [tab, setTab] = useState(initialTab);
  // useApiList：undefined 载荷兜底 []、失败显示重试横幅、seq 守卫防竞态 ——
  // queue.list 失败原先静默，页面长得像「队列为空」。
  const { rows: queue, setRows: setQueue, error: queueError, reload: reloadQueue } = useApiList<QueueRow>("queue.list", [refreshN]);
  const [logs, setLogs] = useState<LogRow[]>([]);
  const [logsError, setLogsError] = useState<string | null>(null);
  const [sel, setSel] = useState<LogRow | null>(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [confirm, setConfirm] = useState<{ id: string; op: string } | null>(null);
  const [timeRange, setTimeRange] = useState("24h");

  useEffect(() => setTab(initialTab), [initialTab]);

  // logs.list 加载（可重试）：失败不再静默 —— logsError 驱动重试横幅，
  // 而不是让页面伪装成「没有日志」。
  const loadLogs = useCallback(() => {
    // {ok:true} 无载荷时 r.data 为 undefined → normalize 崩溃；兜底空数组。
    rpc<RawLog[]>("logs.list").then((r: RpcResult<RawLog[]>) => {
      if (!r.ok) {
        setLogsError(r.error);
        return;
      }
      setLogsError(null);
      const rows = (r.data ?? []).map(normalizeLog);
      setLogs(rows);
      setSel((s) => s ?? rows.find((x) => x.level === "error") ?? rows[0] ?? null);
    });
  }, []);

  useEffect(() => {
    loadLogs();
  }, [loadLogs, refreshN]);

  async function doAction(id: string, op: string) {
    const r = await rpc("queue.action", { id, op });
    if (r.ok) {
      toast(op === "delete" ? t("deleted") : t("action_submitted"));
      // 乐观更新按 queue.list 的真实枚举：非删除动作 = 清零重试预算 → sending
      // （后端把 deliver 映射为 retry）。hold 在后端队列模型里不存在、被显式拒绝。
      setQueue((q) => (op === "delete" ? q.filter((x) => x.id !== id) : q.map((x) => (x.id === id ? { ...x, status: "sending" } : x))));
    } else {
      toast(r.error, "err");
    }
  }

  // 时间范围原先只是一个纯装饰性下拉框（state 从不参与查询）。这里让它真正过滤
  // 队列与日志：后端 action 不接受 range 参数，按条目的时间戳在客户端裁剪。
  const filteredQueue = useMemo(
    () =>
      queue.filter(
        (x) => (statusFilter === "all" || x.status === statusFilter) && withinRange(x.time, timeRange),
      ),
    [queue, statusFilter, timeRange],
  );

  const filteredLogs = useMemo(() => logs.filter((l) => withinRange(l.time, timeRange)), [logs, timeRange]);

  const qCols: Column<QueueRow>[] = [
    { key: "sender", header: t("sender"), render: (r) => r.sender, sortValue: (r) => r.sender, width: 190 },
    { key: "recipient", header: t("recipient"), render: (r) => r.recipient, sortValue: (r) => r.recipient, width: 170 },
    { key: "domain", header: t("domain"), render: (r) => <span className="text-[var(--text-2)]">{r.domain}</span>, sortValue: (r) => r.domain, width: 130 },
    {
      key: "status",
      header: t("status"),
      sortValue: (r) => r.status,
      render: (r) => <QueueStatus s={r.status} />,
      width: 110,
    },
    { key: "retry", header: t("retry"), align: "center", sortValue: (r) => r.retry, render: (r) => <span className="tnum">{r.retry}</span>, width: 64 },
    { key: "time", header: t("time"), sortValue: (r) => r.time, render: (r) => <span className="tnum text-[var(--text-2)]">{r.time}</span>, width: 158 },
    { key: "service", header: t("service"), render: (r) => <span className="mono text-[11.5px] text-[var(--text-2)]">{r.service}</span>, width: 84 },
    {
      key: "act",
      header: t("actions"),
      align: "right",
      render: (r) => (
        <span className="inline-flex items-center gap-1">
          {/* deliver = 后端 retry（清零重试预算立刻再试）：只对 deferred（pending）
              有意义；sending 本就在投，delivered/failed/hold 不会出现在 queue.list。 */}
          {r.status === "pending" && (
            <IconBtn title={t("deliver_now")} onClick={() => doAction(r.id, "deliver")}>
              <IconSend size={14} />
            </IconBtn>
          )}
          <IconBtn title={t("delete_item")} danger onClick={() => setConfirm({ id: r.id, op: "delete" })}>
            <IconTrash size={14} />
          </IconBtn>
        </span>
      ),
      width: 92,
    },
  ];

  const logCols: Column<LogRow>[] = [
    { key: "time", header: t("time"), sortValue: (r) => r.time, render: (r) => <span className="tnum text-[var(--text-2)]">{r.time}</span>, width: 158 },
    { key: "level", header: t("level"), sortValue: (r) => r.level, render: (r) => <LevelBadge level={r.level} />, width: 90 },
    { key: "service", header: t("service"), render: (r) => <span className="mono text-[11.5px]">{r.service}</span>, width: 90 },
    { key: "message", header: t("message"), render: (r) => <span className="mono block max-w-[560px] truncate text-[11.5px]" title={r.message}>{r.message}</span> },
  ];

  return (
    <div className="p-4">
      <PageHeader
        title={tab === "logs" ? t("logs_title") : t("queue_title")}
        sub={tab === "logs" ? t("logs_sub") : t("queue_sub")}
        right={
          <>
            <GlassSelect
              value={timeRange}
              onChange={setTimeRange}
              options={[
                { value: "24h", label: t("last_24h") },
                { value: "7d", label: t("last_7d") },
                { value: "30d", label: t("last_30d") },
              ]}
              ariaLabel="range"
              width={124}
            />
            <button className="btn glass--control" onClick={() => setStatusFilter("all")}>
              <IconFilter size={14} /> {t("filter")}
            </button>
          </>
        }
      />

      <RTabs.Root value={tab} onValueChange={(v) => setTab(v as "queue" | "logs")}>
        <RTabs.List className="tabs-pill mb-3 flex w-fit items-center" aria-label="queue sections">
          <RTabs.Trigger value="queue" className="tab-trigger" data-state={tab === "queue" ? "active" : undefined}>
            {t("mail_queue")}
          </RTabs.Trigger>
          <RTabs.Trigger value="logs" className="tab-trigger" data-state={tab === "logs" ? "active" : undefined}>
            {t("nav_logs")}
          </RTabs.Trigger>
        </RTabs.List>

        {/* Mail Queue Tab：表格在上，日志详情在下（对齐示意图） */}
        <RTabs.Content value="queue" className="flex flex-col gap-3 focus-visible:outline-none">
          <DataPanel>
            {queueError && <div className="px-3 pt-3"><LoadError message={queueError} onRetry={reloadQueue} /></div>}
            <DataTable
              columns={qCols}
              rows={filteredQueue}
              rowKey={(r) => r.id}
              pageSize={10}
              filterKeys={(r) => `${r.sender} ${r.recipient} ${r.domain} ${r.status} ${r.service}`}
              filterPlaceholder={t("search_messages")}
              toolbar={
                <GlassSelect
                  value={statusFilter}
                  onChange={setStatusFilter}
                  // 只提供真的会出现的状态：queue.list 只发 sending/pending
                  //（delivered/failed/hold 在本仓库队列模型里不存在）。
                  options={[
                    { value: "all", label: `${t("status")}: ${t("total")}` },
                    { value: "sending", label: t("sending") },
                    { value: "pending", label: t("pending") },
                  ]}
                  ariaLabel="status filter"
                  width={148}
                />
              }
            />
          </DataPanel>
          <DataPanel>
            {logsError && <div className="px-3 pt-3"><LoadError message={logsError} onRetry={loadLogs} /></div>}
            <LogDetailsPanel log={sel ?? logs[0] ?? null} />
          </DataPanel>
        </RTabs.Content>

        {/* Logs Tab */}
        <RTabs.Content value="logs" className="flex flex-col gap-3 focus-visible:outline-none">
          <DataPanel>
            {logsError && <div className="px-3 pt-3"><LoadError message={logsError} onRetry={loadLogs} /></div>}
            <DataTable
              columns={logCols}
              rows={filteredLogs}
              rowKey={(r) => r.id}
              pageSize={12}
              filterKeys={(r) => `${r.message} ${r.service} ${r.level} ${r.domain ?? ""}`}
              filterPlaceholder={t("search_messages")}
              onRowClick={(r) => setSel(r)}
              activeRowKey={sel?.id}
            />
          </DataPanel>
          <DataPanel>
            <LogDetailsPanel log={sel} />
          </DataPanel>
        </RTabs.Content>
      </RTabs.Root>

      <ConfirmDialog
        open={!!confirm}
        title={t("delete_item")}
        body={`${confirm?.id ?? ""} — ${t("queue_title")}`}
        danger
        onOpenChange={(o) => !o && setConfirm(null)}
        onConfirm={() => confirm && doAction(confirm.id, "delete")}
      />
    </div>
  );
}

function IconBtn({
  children,
  title,
  onClick,
  danger,
}: {
  children: React.ReactNode;
  title: string;
  onClick: () => void;
  danger?: boolean;
}) {
  return (
    <button
      title={title}
      aria-label={title}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      className="flex h-7 w-7 items-center justify-center rounded-[8px] transition-colors"
      style={{
        color: danger ? "rgb(var(--err-rgb))" : "var(--text-2)",
        background: "rgb(var(--text-1) / 0.05)",
      }}
    >
      {children}
    </button>
  );
}

function LevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = { info: "badge-info", warn: "badge-warn", error: "badge-err" };
  return <span className={`badge ${map[level] ?? "badge-neutral"}`} style={{ height: 20, fontSize: 11 }}>{level.toUpperCase()}</span>;
}

function LogDetailsPanel({ log }: { log: LogRow | null }) {
  const { t } = useSettings();
  if (!log) {
    return <div className="flex h-40 items-center justify-center text-[12.5px] text-[var(--text-3)]">{t("select_log_hint")}</div>;
  }
  const fields: [string, string | undefined][] = [
    [t("retry_count"), log.retry != null ? String(log.retry) : undefined],
    [t("service"), log.service],
    [t("level"), log.level.toUpperCase()],
    [t("message"), log.message],
    [t("from"), log.from],
    [t("to"), log.to],
    [t("domain"), log.domain],
  ];
  return (
    <div className="p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("log_details")}</h3>
        <span className="mono text-[11px] text-[var(--text-3)]">{log.id}</span>
      </div>
      <div className="mt-2.5 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
        {/* 左：时间戳 + 级别 + 原始日志 */}
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="tnum text-[12px] text-[var(--text-2)]">{log.time}</span>
            <span className="badge badge-neutral" style={{ height: 20, fontSize: 11 }}>{log.service}</span>
            <LevelBadge level={log.level} />
          </div>
          <div className="glass--well mono mt-2.5 rounded-[12px] p-3 text-[12px] leading-relaxed" style={{ color: log.level === "error" ? "rgb(var(--err-rgb))" : "var(--text-1)" }}>
            {log.message}
            {log.from && <div className="mt-1.5 text-[var(--text-2)]">From: {log.from}</div>}
            {log.to && <div className="text-[var(--text-2)]">To: {log.to}</div>}
            {log.domain && <div className="text-[var(--text-2)]">Domain: {log.domain}</div>}
          </div>
        </div>
        {/* 右：字段表 */}
        <dl className="space-y-1.5 text-[12px] lg:justify-self-end lg:w-full">
          {fields.filter(([, v]) => v != null && v !== "").map(([k, v]) => (
            <div key={k as string} className="flex items-baseline justify-between gap-4">
              <dt className="shrink-0 text-[var(--text-3)]">{k}</dt>
              <dd className="truncate text-right text-[var(--text-1)]" title={String(v)}>{v}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}

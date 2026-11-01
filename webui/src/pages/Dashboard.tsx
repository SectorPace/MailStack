// 仪表盘 —— 对齐三张参考图：
//   图 1：状态卡片组 / 服务状态分布环形图 / 资源使用情况（CPU·内存·磁盘）
//   图 2：右侧信息栏（快捷操作 / 最近动态 / 综合健康度 / 最新日志）
//   展板：六项 Liquid Glass 设计语言
//
// 数据来源：snapshot / activity.list / logs.list / metrics.system / users.list。
// 注意：Rust 后端的 snapshot 形状与前端早期假想的不同（domains 是数组、没有
// users/smtp/dovecot/latency），凡是后端没有的数据一律显示占位符"—"，绝不编造
// 数字；mock 演示数据仍是旧的富形状，下面的 buildVM 同时兼容两者。
import { useEffect, useState, useContext } from "react";
import { useSettings } from "../store/settings";
import { RefreshContext } from "../App";
import { rpc } from "../api/client";
import { Card, PageHeader, GlassSelect, StatusBadge } from "../components/ui";
import { LineChart, type ChartPoint } from "../components/LineChart";
import { DonutChart, GaugeRing } from "../components/Donut";
import { normalizeLog, type RawLog, type LogRow } from "../lib/logs";
import { formatTime } from "../lib/format";
import {
  IconCheck,
  IconGlobe,
  IconUsers,
  IconQueue,
  IconCalendar,
  IconMail,
  IconGear,
  IconShield,
} from "../components/icons";
import type { DictKey } from "../i18n";
import { DICT } from "../i18n";

type Num = number | null;

/** 兼容真后端 snapshot 与 mock 富快照的原始形状。 */
type SnapRaw = {
  // 真后端
  domains?: { name: string; target?: string }[] | { total: number; active: number; disabled: number };
  queues?: { status?: string }[];
  services?: { id?: string; name?: string; status?: string }[];
  queue?: {
    // 真后端 queue_summary：backlog = 全部条目数（含 active），另有 corrupt / relayHost。
    backlog?: number;
    corrupt?: number;
    // mock 的富队列字段
    pending?: number;
    sending?: number;
    failed?: number;
    delivered?: number;
    bounced?: number;
    hold?: number;
  };
  unavailable?: string[];
  // mock
  users?: { total: number; active: number; disabled: number };
  smtp?: { running: boolean; connections: number; sentToday: number; successRate: number; ports: number[] };
  dovecot?: { running: boolean; connections: number; loggedIn: number; successRate: number; ports: number[] };
  latency?: { points: ChartPoint[] };
  serviceDist?: { total: number; running: number; alert: number; offline: number };
  resources?: { cpu: number; memory: number; disk: number };
  healthPanel?: { overall: number; items: { key: string; label: string; status: string; value?: number }[] };
};

type ActivityItem = { kind: string; title: string; sub: string; time: string };
type UserRow = { address: string; name: string; active: boolean };

type VM = {
  domains: { total: Num; active: Num; disabled: Num };
  users: { total: Num; active: Num; disabled: Num };
  queue: { pending: Num; sending: Num; failed: Num; delivered: Num; bounced: Num; hold: Num };
  latency: ChartPoint[];
  dist: { total: number; running: number; alert: number; offline: number };
  healthPanel: { overall: number; items: { key: string; label: string; status: string; value?: number }[] } | null;
  smtp: { running: boolean; connections: Num; sentToday: Num; successRate: Num; ports: number[] } | null;
  dovecot: { running: boolean; connections: Num; loggedIn: Num; successRate: Num; ports: number[] } | null;
  // snapshot.resources 与 metrics.system 都拿不到时为 null：渲染 —，绝不编 0%。
  resources: { cpu: number; memory: number; disk: number } | null;
};

/** 数字 → 展示串；后端没有该数据时显示占位符而不是编造一个 0。 */
const nz = (v: Num): string => (v == null ? "—" : v.toLocaleString());

/** 由原始快照 + 独立拉取的 users/metrics 组装视图模型。 */
function buildVM(raw: SnapRaw, users: UserRow[], metrics: { cpu: number; memory: number; disk: number } | null): VM {
  let domains: { total: Num; active: Num; disabled: Num };
  if (Array.isArray(raw.domains)) {
    domains = { total: raw.domains.length, active: raw.domains.length, disabled: 0 };
  } else if (raw.domains) {
    domains = raw.domains;
  } else {
    domains = { total: null, active: null, disabled: null };
  }

  const usersVm = raw.users
    ? { total: raw.users.total, active: raw.users.active, disabled: raw.users.disabled }
    : users.length
      ? { total: users.length, active: users.filter((u) => u.active).length, disabled: users.filter((u) => !u.active).length }
      : { total: null, active: null, disabled: null };

  // 真后端的 queues 是队列条目数组，status 只有 active（到期在投）与 deferred
  // （等下次重试）两种（readers.rs queue_item_json）；snapshot.queue 只有
  // backlog/corrupt/relayHost，没有 sending/pending 计数。sending/pending 唯一
  // 的来源是 mock 富快照的字段 —— 真数据按真实 status 值统计，不用 backlog
  // （它是含 active 的总数，拿来当「待处理」是错位）。
  const sending = raw.queue?.sending ?? (raw.queues ? raw.queues.filter((q) => q.status === "active").length : null);
  const pending = raw.queue?.pending ?? (raw.queues ? raw.queues.filter((q) => q.status === "deferred").length : null);
  const queue = {
    pending,
    sending,
    failed: raw.queue?.failed ?? null,
    delivered: raw.queue?.delivered ?? null,
    bounced: raw.queue?.bounced ?? null,
    hold: raw.queue?.hold ?? null,
  };

  // 服务分布：真后端有 services 数组（status 为 ACTIVE/STOPPED），mock 直接给 serviceDist。
  let dist = raw.serviceDist ?? null;
  if (!dist && raw.services) {
    const total = raw.services.length;
    const running = raw.services.filter((s) => s.status === "ACTIVE").length;
    dist = { total, running, alert: 0, offline: total - running };
  }

  return {
    domains,
    users: usersVm,
    queue,
    latency: raw.latency?.points ?? [],
    dist: dist ?? { total: 0, running: 0, alert: 0, offline: 0 },
    healthPanel: raw.healthPanel ?? null,
    smtp: raw.smtp ? { running: raw.smtp.running, connections: raw.smtp.connections, sentToday: raw.smtp.sentToday, successRate: raw.smtp.successRate, ports: raw.smtp.ports } : null,
    dovecot: raw.dovecot ? { running: raw.dovecot.running, connections: raw.dovecot.connections, loggedIn: raw.dovecot.loggedIn, successRate: raw.dovecot.successRate, ports: raw.dovecot.ports } : null,
    // 原先兜底 {cpu:0,memory:0,disk:0}：两个数据源都失败时凭空渲染「CPU 0% / 内存 0% /
    // 磁盘 0%」，看起来像真实读数。改为 null → 渲染占位符。
    resources: raw.resources ?? metrics,
  };
}

export default function Dashboard() {
  const { t, prefs } = useSettings();
  const refreshN = useContext(RefreshContext);
  const [raw, setRaw] = useState<SnapRaw | null>(null);
  const [vm, setVm] = useState<VM | null>(null);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [logs, setLogs] = useState<LogRow[]>([]);
  const [resRange, setResRange] = useState("7d");
  // 延迟图与资源图原先共用 resRange：改一个连带另一个。拆成两个独立状态。
  const [latencyRange, setLatencyRange] = useState("24h");
  const [err, setErr] = useState("");

  useEffect(() => {
    let live = true;
    Promise.all([
      rpc<SnapRaw>("snapshot"),
      rpc<UserRow[]>("users.list"),
      rpc<{ cpu: number; memory: number; disk: number }>("metrics.system"),
    ]).then(([snapR, usersR, metricsR]) => {
      if (!live) return;
      if (!snapR.ok) {
        setErr(snapR.error);
        return;
      }
      const s = snapR.data ?? {};
      setRaw(s);
      setVm(buildVM(s, usersR.ok ? usersR.data ?? [] : [], metricsR.ok ? metricsR.data ?? null : null));
    });
    rpc<ActivityItem[]>("activity.list").then((r) => live && r.ok && setActivity(r.data ?? []));
    rpc<RawLog[]>("logs.list").then((r) => live && r.ok && setLogs((r.data ?? []).map(normalizeLog).slice(0, 5)));
    return () => {
      live = false;
    };
  }, [refreshN]);

  function go(hash: string) {
    location.hash = hash;
  }

  /* ---------- 右侧信息栏数据 ---------- */
  const quickActions: { icon: React.ReactNode; tint: string; label: string; to: string }[] = [
    { icon: <IconGlobe size={17} />, tint: "rgb(var(--accent-rgb))", label: t("qa_create_domain"), to: "#/domains" },
    { icon: <IconUsers size={17} />, tint: "rgb(var(--accent-rgb))", label: t("qa_add_user"), to: "#/users" },
    { icon: <IconMail size={17} />, tint: "rgb(var(--accent-rgb))", label: t("qa_add_alias"), to: "#/aliases" },
    { icon: <IconQueue size={17} />, tint: "rgb(var(--accent-rgb))", label: t("qa_import_mail"), to: "#/queue" },
  ];

  const ACT_ICON: Record<string, React.ReactNode> = {
    user: <IconUsers size={13} />,
    domain: <IconGlobe size={13} />,
    queue: <IconMail size={13} />,
    service: <IconGear size={13} />,
    cert: <IconShield size={13} />,
  };

  /* ---------- 加载态 ---------- */
  if (err) {
    return (
      <div className="p-4">
        <PageHeader title={t("dash_title")} sub={t("dash_sub")} />
        <Card>{err}</Card>
      </div>
    );
  }

  if (!vm) {
    return (
      <div className="p-4">
        <div className="skeleton mb-4 h-8 w-56" />
        <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="skeleton h-[92px]" />
          ))}
        </div>
      </div>
    );
  }

  const healthItems = vm.healthPanel?.items ?? [];
  const unavailableUsers = Array.isArray(raw?.unavailable) && raw!.unavailable!.includes("users");
  // 真后端的 activity.title 是原始动作名（如 users.add），不在词典里；直接 t() 会因
  // DICT[key] 未定义而抛错，故仅对已知词典键做翻译，其余原样展示。
  const actLabel = (title: string) => (Object.prototype.hasOwnProperty.call(DICT, title) ? t(title as DictKey) : title);

  const dist = vm.dist;
  const res = vm.resources;
  // 系统健康卡与「服务状态分布」徽标都从真实服务状态推导：
  // 原实现恒为「运行正常 / 所有服务运行正常」，与后端状态无关（WEBUI_AUDIT §1.3）。
  // 后端没给服务清单（dist.total === 0）时显示 —，不编造。
  const distKnown = dist.total > 0;
  const distBad = dist.alert + dist.offline;
  const healthOk = distKnown && distBad === 0;
  const healthValue = !distKnown ? "—" : healthOk ? t("running_normal") : t("system_degraded");
  const healthSub = distKnown ? `${t("svc_running")} ${dist.running}/${dist.total}` : "—";
  // 队列占比条的时间范围：所有已知计数之和（后端只给 sending/pending 时其余显示 —）。
  const queueTotal = [vm.queue.pending, vm.queue.sending, vm.queue.failed, vm.queue.delivered, vm.queue.bounced, vm.queue.hold].reduce<number>(
    (sum, n) => sum + (n ?? 0),
    0,
  );

  const statCards = [
    {
      icon: <IconCheck size={22} />,
      iconBg: healthOk
        ? "linear-gradient(180deg, rgb(var(--ok-rgb) / 0.96), rgb(var(--ok-rgb) / 0.8))"
        : distKnown
          ? "linear-gradient(180deg, rgb(var(--warn-rgb) / 0.96), rgb(var(--warn-rgb) / 0.8))"
          : "linear-gradient(180deg, rgb(var(--text-3) / 0.55), rgb(var(--text-3) / 0.4))",
      iconColor: "#fff",
      label: t("system_health"),
      value: healthValue,
      valueStyle: { color: healthOk ? "rgb(var(--ok-rgb))" : distKnown ? "rgb(var(--warn-rgb))" : "var(--text-3)" } as React.CSSProperties,
      sub: healthSub,
      smallValue: false,
    },
    {
      icon: <IconGlobe size={20} />,
      iconBg: "linear-gradient(180deg, rgb(var(--accent-rgb) / 0.95), rgb(var(--accent-deep-rgb) / 0.92))",
      iconColor: "#fff",
      label: t("total_domains"),
      value: nz(vm.domains.total),
      sub: t("active_domains"),
      smallValue: true,
    },
    {
      icon: <IconUsers size={20} />,
      iconBg: "linear-gradient(180deg, rgb(var(--accent-rgb) / 0.95), rgb(var(--accent-deep-rgb) / 0.92))",
      iconColor: "#fff",
      label: t("mailbox_users"),
      value: nz(vm.users.total),
      sub: t("active_accounts"),
      smallValue: true,
    },
    {
      icon: <IconQueue size={20} />,
      iconBg: "linear-gradient(180deg, rgb(var(--accent-rgb) / 0.95), rgb(var(--accent-deep-rgb) / 0.92))",
      iconColor: "#fff",
      label: t("mail_queue"),
      value: nz(vm.queue.pending),
      sub: t("pending_mail"),
      smallValue: true,
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-3 p-4 xl:grid-cols-[minmax(0,1fr)_312px]">
      {/* ============ 主区 ============ */}
      <div className="min-w-0 space-y-3">
        <PageHeader
          title={t("dash_title")}
          sub={t("dash_sub")}
          right={
            <span className="badge badge-neutral" style={{ height: 30, fontSize: 12 }}>
              <IconCalendar size={13} />
              {dayStamp()} 00:00 → {dayStamp()} 23:59
            </span>
          }
        />

        {/* 状态卡片组 */}
        <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
          {statCards.map((c) => (
            <Card key={c.label} className="glass-hover">
              <div className="flex items-start gap-2.5 sm:gap-3">
              <span
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full sm:h-12 sm:w-12"
                style={{ background: c.iconBg, color: c.iconColor, boxShadow: "inset 0 1px 0 rgba(255,255,255,.4), 0 3px 8px rgb(var(--accent-rgb) / 0.18)" }}
              >
                {c.icon}
              </span>
                <div className="min-w-0">
                  <div className="text-[12px] font-medium text-[var(--text-2)]">{c.label}</div>
                  <div
                    className="mt-0.5 truncate font-semibold leading-tight tracking-[-0.01em] text-[var(--text-1)]"
                    style={{ fontSize: c.smallValue ? "clamp(19px, 5.4vw, 26px)" : "clamp(16px, 4vw, 18px)", ...c.valueStyle }}
                  >
                    {c.value}
                  </div>
                  <div className="mt-0.5 truncate text-[11.5px] text-[var(--text-3)]">{c.sub}</div>
                </div>
              </div>
            </Card>
          ))}
        </div>

        {/* 服务状态分布 + 资源使用情况（参考图 1） */}
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <Card>
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("service_distribution")}</h2>
              <StatusBadge
                kind={!distKnown ? "neutral" : distBad === 0 ? "ok" : dist.running > 0 ? "warn" : "err"}
                label={!distKnown ? "—" : distBad === 0 ? t("running_normal") : t("system_degraded")}
              />
            </div>
            <div className="flex items-center gap-5">
              <DonutChart
                segments={[
                  { value: dist.running, color: "rgb(var(--accent-rgb))" },
                  { value: dist.alert, color: "rgb(var(--err-rgb))" },
                  { value: dist.offline, color: "rgb(var(--text-1) / 0.22)" },
                ]}
                centerTop={String(dist.total)}
                centerSub={t("running_total")}
              />
              <div className="min-w-0 flex-1 space-y-2.5">
                {[
                  { label: t("svc_running"), n: dist.running, color: "rgb(var(--accent-rgb))" },
                  { label: t("svc_alert"), n: dist.alert, color: "rgb(var(--err-rgb))" },
                  { label: t("svc_offline"), n: dist.offline, color: "rgb(var(--text-1) / 0.3)" },
                ].map((s) => (
                  <div key={s.label} className="flex items-center gap-2 text-[12.5px]">
                    <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: s.color }} />
                    <span className="flex-1 truncate text-[var(--text-2)]">{s.label}</span>
                    <span className="tnum font-medium text-[var(--text-1)]">{s.n}</span>
                    <span className="tnum w-10 text-right text-[var(--text-3)]">
                      {dist.total ? Math.round((s.n / dist.total) * 100) : 0}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </Card>

          <Card>
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("resource_usage")}</h2>
              <GlassSelect
                value={resRange}
                onChange={setResRange}
                options={[
                  { value: "24h", label: t("last_24h") },
                  { value: "7d", label: t("last_7d") },
                  { value: "30d", label: t("last_30d") },
                ]}
                ariaLabel="resource range"
                width={96}
              />
            </div>
            <div className="space-y-4">
              {[
                { label: t("cpu_usage"), v: res?.cpu ?? null },
                { label: t("mem_usage"), v: res?.memory ?? null },
                { label: t("disk_usage"), v: res?.disk ?? null },
              ].map((r0) => (
                <div key={r0.label} className="flex items-center gap-3">
                  <span
                    className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[11px]"
                    style={{ background: "rgb(var(--accent-rgb) / 0.10)", color: "rgb(var(--accent-rgb))" }}
                  >
                    <IconGear size={16} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="mb-1.5 flex items-center justify-between text-[12.5px]">
                      <span className="text-[var(--text-2)]">{r0.label}</span>
                      {/* 数据源失败时显示 —（绝不虚假 UI），条形宽度归零 */}
                      <span className="tnum font-medium text-[var(--text-1)]">{r0.v == null ? "—" : `${r0.v}%`}</span>
                    </div>
                    <div className="bar">
                      <i style={{ width: r0.v == null ? "0%" : `${Math.min(100, Math.max(0, r0.v))}%` }} className={r0.v == null ? "" : r0.v > 85 ? "err" : r0.v > 70 ? "warn" : ""} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* SMTP / Dovecot / 延迟图：真后端 snapshot 不提供这三项，显示占位卡片 */}
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          {vm.smtp ? (
            <ServiceCard
              title={t("smtp_service")}
              running={vm.smtp.running}
              rows={[
                [t("connections"), nz(vm.smtp.connections)],
                [t("sent_today"), nz(vm.smtp.sentToday)],
                [t("success_rate"), vm.smtp.successRate == null ? "—" : `${vm.smtp.successRate}%`],
              ]}
              ports={vm.smtp.ports}
            />
          ) : (
            <UnavailableCard title={t("smtp_service")} />
          )}
          {vm.dovecot ? (
            <ServiceCard
              title={t("dovecot_service")}
              running={vm.dovecot.running}
              rows={[
                [t("connections"), nz(vm.dovecot.connections)],
                [t("logged_in_users"), nz(vm.dovecot.loggedIn)],
                [t("success_rate"), vm.dovecot.successRate == null ? "—" : `${vm.dovecot.successRate}%`],
              ]}
              ports={vm.dovecot.ports}
            />
          ) : (
            <UnavailableCard title={t("dovecot_service")} />
          )}
          <Card>
            <div className="mb-1 flex items-center justify-between">
              <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("delivery_latency")}</h2>
              <GlassSelect
                value={latencyRange}
                onChange={setLatencyRange}
                options={[
                  { value: "24h", label: t("last_24h") },
                  { value: "7d", label: t("last_7d") },
                ]}
                ariaLabel="latency range"
                width={104}
              />
            </div>
            {vm.latency.length ? (
              <LineChart points={vm.latency} height={150} />
            ) : (
              <div className="flex h-[150px] items-center justify-center text-[12px] text-[var(--text-3)]">—</div>
            )}
          </Card>
        </div>

        {/* 三栏统计 */}
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          <Card>
            <StatsHeader title={t("domain_stats")} icon={<IconGlobe size={15} />} />
            <TripleStat
              cols={[
                { v: nz(vm.domains.total), l: t("total"), color: "var(--text-1)" },
                { v: nz(vm.domains.active), l: t("enabled"), color: "var(--text-1)" },
                { v: nz(vm.domains.disabled), l: t("disabled"), color: "rgb(var(--err-rgb))" },
              ]}
            />
          </Card>

          <Card>
            <StatsHeader title={t("user_stats")} icon={<IconUsers size={15} />} />
            <TripleStat
              cols={[
                { v: nz(vm.users.total), l: t("total_users"), color: "var(--text-1)" },
                { v: nz(vm.users.active), l: t("enabled"), color: "var(--text-1)" },
                { v: nz(vm.users.disabled), l: t("disabled"), color: "rgb(var(--err-rgb))" },
              ]}
            />
            {unavailableUsers && <div className="mt-2 text-[11px] text-[var(--text-3)]">{prefs.lang === "zh" ? "后端未提供该部分数据" : "Not provided by the backend"}</div>}
          </Card>

          <Card>
            <StatsHeader title={t("queue_stats")} icon={<IconMail size={15} />} />
            <TripleStat
              cols={[
                { v: nz(vm.queue.pending), l: t("pending"), color: "var(--text-1)" },
                { v: nz(vm.queue.sending), l: t("sending"), color: "var(--text-1)" },
                { v: nz(vm.queue.failed), l: t("failed"), color: "rgb(var(--err-rgb))" },
              ]}
            />
            <div className="mt-3 space-y-2.5">
              <QueueBar label={t("delivered")} n={vm.queue.delivered} total={queueTotal} cls="ok" />
              <QueueBar label={t("bounced")} n={vm.queue.bounced} total={queueTotal} cls="warn" />
              <QueueBar label={t("hold")} n={vm.queue.hold} total={queueTotal} cls="err" />
            </div>
          </Card>
        </div>
      </div>

      {/* ============ 右侧信息栏（参考图 2） ============ */}
      <aside className="min-w-0 space-y-3">
        {/* 快捷操作 */}
        <Card>
          <h2 className="mb-2.5 text-[13.5px] font-semibold text-[var(--text-1)]">{t("qa_title")}</h2>
          <div className="grid grid-cols-2 gap-2">
            {quickActions.map((qa) => (
              <button
                key={qa.label}
                className="glass--control glass-hover flex items-center gap-1.5 rounded-[12px] px-2 py-2.5 text-left"
                onClick={() => go(qa.to)}
              >
                <span
                  className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[8px]"
                  style={{ background: "rgb(var(--accent-rgb) / 0.13)", color: qa.tint }}
                >
                  {qa.icon}
                </span>
                <span className="min-w-0 flex-1 truncate text-[11.5px] font-medium text-[var(--text-1)]">{qa.label}</span>
              </button>
            ))}
          </div>
        </Card>

        {/* 最近动态 */}
        <Card>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("recent_activity")}</h2>
            <a href="#/logs" className="text-[12px] font-medium transition-opacity hover:opacity-75" style={{ color: "rgb(var(--accent-rgb))" }}>
              {t("view_all")}
            </a>
          </div>
          <div className="space-y-1">
            {activity.map((a, i) => (
              <div key={i} className="flex items-center gap-2.5 rounded-[10px] px-1 py-1.5">
                <span
                  className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full"
                  style={{ background: "rgb(var(--accent-rgb) / 0.10)", color: "rgb(var(--accent-rgb))" }}
                >
                  {ACT_ICON[a.kind] ?? <IconMail size={13} />}
                </span>
                <div className="min-w-0 flex-1 leading-tight">
                  <div className="truncate text-[12.5px] font-medium text-[var(--text-1)]">{actLabel(a.title)}</div>
                  <div className="truncate text-[11px] text-[var(--text-3)]">{a.sub}</div>
                </div>
                <span className="tnum shrink-0 text-[11px] text-[var(--text-3)]">{a.time}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* 综合健康度 */}
        <Card>
          <h2 className="mb-3 text-[13.5px] font-semibold text-[var(--text-1)]">{t("system_health")}</h2>
          <div className="flex items-center gap-4">
            {/* 后端不提供 overall 时传 null → 环显示 —（原实现 `?? 98` 会凭空显示 98 分） */}
            <GaugeRing value={vm.healthPanel?.overall ?? null} label={t("overall_health")} size={118} />
            <div className="min-w-0 flex-1 space-y-2">
              {healthItems.map((it) => (
                <div key={it.key} className="leading-tight">
                  <div className="flex items-center justify-between gap-2 text-[12px]">
                    <span className="truncate text-[var(--text-1)]">{dictItemLabel(it.key, t)}</span>
                    {it.key === "disk" ? (
                      <span className="tnum text-[var(--text-2)]">{it.value == null ? "—" : `${it.value}%`}</span>
                    ) : (
                      <span
                        className="text-[11.5px] font-medium"
                        style={{ color: it.status === "ok" ? "rgb(var(--ok-rgb))" : "rgb(var(--err-rgb))" }}
                      >
                        {it.status === "ok" ? t("running_normal") : t("stopped")}
                      </span>
                    )}
                  </div>
                  {it.key === "disk" && (
                    <div className="bar mt-1 h-1">
                      <i style={{ width: `${it.value ?? 0}%` }} className={(it.value ?? 0) > 85 ? "warn" : "ok"} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </Card>

        {/* 最新日志 */}
        <Card>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("recent_logs")}</h2>
            <a href="#/logs" className="text-[12px] font-medium transition-opacity hover:opacity-75" style={{ color: "rgb(var(--accent-rgb))" }}>
              {t("view_all")}
            </a>
          </div>
          <div className="space-y-2">
            {logs.map((l) => (
              <div key={l.id} className="flex items-start gap-2.5">
                <span
                  className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
                  style={{
                    background:
                      l.level === "error" ? "rgb(var(--err-rgb))" : l.level === "warn" ? "rgb(var(--warn-rgb))" : "rgb(var(--accent-rgb))",
                  }}
                />
                <div className="min-w-0 flex-1 leading-tight">
                  <div className="truncate text-[12px] text-[var(--text-1)]" title={l.message}>{l.message}</div>
                  {/* 后端是 ISO8601（UTC）：slice(11,16) 会把 UTC 当本地时间展示，用共享助手转本地时区 */}
                  <div className="tnum text-[10.5px] text-[var(--text-3)]">{formatTime(l.time)}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </aside>
    </div>
  );
}

function dictItemLabel(key: string, t: (k: DictKey) => string): string {
  switch (key) {
    case "smtp": return "SMTP";
    case "dovecot": return "Dovecot";
    case "queue": return t("queue_label");
    case "database": return t("database_label");
    case "disk": return t("disk_label");
    default: return key;
  }
}

function dayStamp(): string {
  const d = new Date();
  const p = (x: number) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** 统计面板头：标题 + 右上彩色图标（展板形态） */
function StatsHeader({ title, icon }: { title: string; icon: React.ReactNode }) {
  return (
    <div className="mb-2 flex items-center justify-between">
      <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{title}</h2>
      <span
        className="flex h-7 w-7 items-center justify-center rounded-[9px]"
        style={{ background: "rgb(var(--accent-rgb) / 0.11)", color: "rgb(var(--accent-rgb))" }}
      >
        {icon}
      </span>
    </div>
  );
}

function TripleStat({ cols }: { cols: { v: string; l: string; color: string }[] }) {
  return (
    <div className="grid grid-cols-3 rounded-[12px] px-1 py-3" style={{ background: "rgb(var(--text-1) / 0.04)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}>
      {cols.map((c, i) => (
        <div key={c.l} className="text-center" style={i > 0 ? { borderLeft: "1px solid var(--hairline)" } : undefined}>
          <div className="tnum text-[22px] font-semibold leading-none" style={{ color: c.color }}>
            {c.v}
          </div>
          <div className="mt-1.5 text-[11px] text-[var(--text-3)]">{c.l}</div>
        </div>
      ))}
    </div>
  );
}

/** 队列占比条；后端没有该计数时显示占位符与空条，而不是编造一个比例。 */
function QueueBar({ label, n, total, cls }: { label: string; n: Num; total: number; cls: "ok" | "warn" | "err" }) {
  // 原实现宽度恒为 0%、右侧百分比恒为 100%，两个都是占位符；现在按真实计数计算。
  const pct = n == null || total <= 0 ? null : Math.round((n / total) * 100);
  return (
    <div className="flex items-center gap-2 text-[12px]">
      <span className="w-[104px] shrink-0 truncate text-[var(--text-1)]">{label}</span>
      <span className="tnum w-10 shrink-0 text-right text-[var(--text-2)]">{n ?? "—"}</span>
      <div className="bar min-w-0 flex-1">
        <i style={{ width: pct == null ? "0%" : `${pct}%` }} className={cls === "err" ? "err" : cls === "warn" ? "warn" : ""} />
      </div>
      <span className="tnum w-11 shrink-0 text-right text-[var(--text-3)]">{pct == null ? "—" : `${pct}%`}</span>
    </div>
  );
}

/** 后端不提供该面板数据时的占位卡片。 */
function UnavailableCard({ title }: { title: string }) {
  return (
    <Card>
      <div className="mb-2.5 flex items-center justify-between">
        <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{title}</h2>
        <StatusBadge kind="neutral" label="—" />
      </div>
      <div className="flex h-[104px] items-center justify-center text-[12px] text-[var(--text-3)]">—</div>
    </Card>
  );
}

function ServiceCard({
  title,
  running,
  rows,
  ports,
}: {
  title: string;
  running: boolean;
  rows: [string, string][];
  ports: number[];
}) {
  const { t } = useSettings();
  return (
    <Card>
      <div className="mb-2.5 flex items-center justify-between">
        <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{title}</h2>
        <StatusBadge kind={running ? "ok" : "err"} label={running ? t("running") : t("stopped")} />
      </div>
      <div className="space-y-2">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-center justify-between text-[12.5px]">
            <span className="text-[var(--text-2)]">{k}</span>
            <span className="tnum font-medium text-[var(--text-1)]">{v}</span>
          </div>
        ))}
        <div className="flex items-center justify-between text-[12.5px]">
          <span className="text-[var(--text-2)]">{t("port")}</span>
          <span className="tnum font-medium text-[var(--text-1)]">{ports.length ? ports.join(" / ") : "—"}</span>
        </div>
      </div>
    </Card>
  );
}

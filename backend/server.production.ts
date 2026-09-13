import express, {
  type Request,
  type Response,
  type NextFunction,
} from "express";
import path from "path";
import fs from "fs";
import os from "os";
import net from "net";
import crypto from "crypto";
import { spawn, spawnSync } from "child_process";

import pkg from "../package.json";
/**
 * One-shot stderr warning.
 *
 * The telemetry sampler runs every 2 seconds and every sampler here falls back
 * to zero on failure. Zero is a plausible reading, so a broken `postqueue` is
 * indistinguishable from an idle machine unless something is written down.
 * Deduped by context so a permanently broken sampler logs once, not 43k times
 * a day.
 */
const warnedOnce = new Set<string>();
function warnOnce(context: string, error?: unknown): void {
  try {
    const kind = error instanceof Error ? error.constructor.name : typeof error;
    const key = error === undefined ? context : `${context}|${kind}`;
    if (warnedOnce.has(key)) return;
    let detail = "";
    if (error !== undefined) {
      try {
        detail = `: ${error instanceof Error ? error.message : String(error)}`;
      } catch {
        // `error.message` can be a getter that throws. Losing the detail is
        // fine; losing the context is not, because that is what gets grepped.
        detail = `: ${kind}`;
      }
    }
    process.stderr.write(`mailstack: ${context} failed${detail}\n`);
    // Mark reported only after the line is written -- marking first meant a
    // failed write permanently silenced that context.
    warnedOnce.add(key);
  } catch {
    /* Reporting a problem must never become the reason a request fails. */
  }
}

export type TelemetryTimeframe = '1m' | '5m' | '30m' | '1h' | '6h' | '24h' | '3d';

export interface TelemetryPoint {
  timestamp: string;
  cpuPercent: number;
  memoryMb: number;
  systemMemoryPercent: number;
  systemMemoryUsedMb: number;
  systemMemoryTotalMb: number;
  load1: number;
  load5: number;
  load15: number;
  queueTotal: number;
  queueDeferred: number;
  daemons: Record<string, { memoryMb: number; cpuPercent: number; status: string; pid: number }>;
}

export class SystemMetricsCollector {
  private prevCpuTimes: { idle: number; total: number }[] = [];
  private ring1m: TelemetryPoint[] = [];
  private ring5m: TelemetryPoint[] = [];
  private ring30m: TelemetryPoint[] = [];
  private ring1h: TelemetryPoint[] = [];
  private ring6h: TelemetryPoint[] = [];
  private ring24h: TelemetryPoint[] = [];
  private ring3d: TelemetryPoint[] = [];
  private lastSampleTime = 0;
  private diskInfo = { totalGb: 0, usedGb: 0, percent: 0 };

  /** pid -> daemon key, carried between samples. See the scan in getDaemonsInfo. */
  private pidCache = new Map<number, string>();
  private seenPids = new Set<number>();
  private cyclesSinceFullScan = 0;

  /** Full /proc walk every N samples. At a 2s interval this is 30 seconds. */
  private static readonly FULL_SCAN_EVERY_CYCLES = 15;

  /**
   * Exact process name -> daemon key.
   *
   * This used to be a substring test against the process name, which matched
   * any process whose name merely contained one of these words and, at the same
   * time, missed most of the real ones: Postfix runs cleanup, trivial-rewrite,
   * smtp, local, virtual, pipe and bounce, none of which contain "master",
   * "smtpd", "qmgr", "pickup" or "postfix". Reported daemon memory was therefore
   * both inflated by unrelated processes and short by the majority of the mail
   * stack.
   *
   * Deliberately excluded because the comm is too generic to attribute safely:
   * `config`, `log`, `stats` (Dovecot) and `node` (the webmail service, which
   * cannot be distinguished from any other Node process by name).
   */
  private static readonly COMM_TO_DAEMON: Record<string, string> = {
    // Postfix
    master: "postfix", pickup: "postfix", qmgr: "postfix", cleanup: "postfix",
    smtpd: "postfix", smtp: "postfix", showq: "postfix", flush: "postfix",
    local: "postfix", virtual: "postfix", pipe: "postfix", bounce: "postfix",
    defer: "postfix", trace: "postfix", verify: "postfix", scache: "postfix",
    proxymap: "postfix", tlsmgr: "postfix", postscreen: "postfix", dnsblog: "postfix",
    "trivial-rewrite": "postfix",
    // Dovecot
    dovecot: "dovecot", doveadm: "dovecot", dsync: "dovecot", director: "dovecot",
    anvil: "dovecot", auth: "dovecot", imap: "dovecot", "imap-login": "dovecot",
    pop3: "dovecot", "pop3-login": "dovecot", managesieve: "dovecot",
    "managesieve-login": "dovecot",
    // OpenDKIM
    opendkim: "opendkim",
    // Fail2ban
    fail2ban: "fail2ban", "fail2ban-server": "fail2ban",
  };

  constructor() {
    this.initCpu();
    this.updateDiskInfo();
    this.sample();
    setInterval(() => this.sample(), 2000).unref();
    setInterval(() => this.updateDiskInfo(), 60000).unref();
  }

  private readCpuCounters(): { idle: number; total: number }[] {
    return os.cpus().map((cpu) => {
      let total = 0;
      for (const t of Object.keys(cpu.times) as (keyof typeof cpu.times)[]) total += cpu.times[t];
      return { idle: cpu.times.idle, total };
    });
  }

  private initCpu() {
    this.prevCpuTimes = this.readCpuCounters();
  }

  /**
   * Differential CPU sample. This consumes the previous snapshot, so call it
   * once per reporting cycle and reuse the result -- calling it twice in a row
   * makes the second value measure only the gap between the two calls, which
   * rounds to zero.
   */
  private sampleCpu(): { avg: number; perCore: number[] } {
    const now = this.readCpuCounters();
    if (now.length === 0) return { avg: 0, perCore: [] };
    // Core count can change (CPU hotplug, cgroup resize). Fall back to a
    // zero-delta baseline rather than reading past the end of the array.
    const prev = this.prevCpuTimes.length === now.length ? this.prevCpuTimes : now;
    this.prevCpuTimes = now;

    const usage = (cur: { idle: number; total: number }, old: { idle: number; total: number }) => {
      const diffTotal = cur.total - old.total;
      const diffIdle = cur.idle - old.idle;
      if (diffTotal <= 0) return 0;
      return Math.max(0, Math.min(100, Math.round(((diffTotal - diffIdle) / diffTotal) * 1000) / 10));
    };

    const perCore = now.map((cur, i) => usage(cur, prev[i]));
    const avg = usage(
      { idle: now.reduce((a, c) => a + c.idle, 0), total: now.reduce((a, c) => a + c.total, 0) },
      { idle: prev.reduce((a, c) => a + c.idle, 0), total: prev.reduce((a, c) => a + c.total, 0) },
    );
    return { avg, perCore };
  }

  private getCpuUsage(): number {
    return this.sampleCpu().avg;
  }

  private getMemInfo() {
    let totalMb = Math.round(os.totalmem() / 1048576);
    let freeMb = Math.round(os.freemem() / 1048576);
    let cachedMb = 0;
    try {
      if (fs.existsSync("/proc/meminfo")) {
        const lines = fs.readFileSync("/proc/meminfo", "utf8").split("\n");
        const map: Record<string, number> = {};
        for (const line of lines) {
          const m = line.match(/^([A-Za-z_]+):\s+(\d+)/);
          if (m) map[m[1]] = parseInt(m[2], 10);
        }
        if (map.MemTotal) totalMb = Math.round(map.MemTotal / 1024);
        if (map.MemAvailable) freeMb = Math.round(map.MemAvailable / 1024);
        if (map.Cached) cachedMb = Math.round(map.Cached / 1024);
      }
    } catch (error) {
      warnOnce("read /proc/meminfo", error);
    }
    const usedMb = Math.max(0, totalMb - freeMb);
    const percent = totalMb > 0 ? Math.round((usedMb / totalMb) * 1000) / 10 : 0;
    return { totalMb, usedMb, freeMb, cachedMb, percent };
  }

  private getDaemonsInfo(): { totalDaemonMemoryMb: number; daemons: Record<string, { memoryMb: number; cpuPercent: number; status: string; pid: number }> } {
    const daemons: Record<string, { memoryMb: number; cpuPercent: number; status: string; pid: number }> = {
      postfix: { memoryMb: 0, cpuPercent: 0, status: "STOPPED", pid: 0 },
      dovecot: { memoryMb: 0, cpuPercent: 0, status: "STOPPED", pid: 0 },
      opendkim: { memoryMb: 0, cpuPercent: 0, status: "STOPPED", pid: 0 },
      "mailstack-web": { memoryMb: Math.round(process.memoryUsage().rss / 1048576 * 10) / 10, cpuPercent: 0, status: "ACTIVE", pid: process.pid },
      "mailstack-webmail": { memoryMb: 0, cpuPercent: 0, status: "STOPPED", pid: 0 },
      fail2ban: { memoryMb: 0, cpuPercent: 0, status: "STOPPED", pid: 0 }
    };

    if (process.platform === "linux") {
      try {
        const allPids = new Set(
          fs.readdirSync("/proc").filter((p) => /^\d+$/.test(p)).map((p) => Number(p)),
        );
        // A full walk costs two reads per process, every two seconds. Mail
        // daemons are re-read every cycle; everything else is only re-examined
        // on the periodic full scan or when it is a pid we have never seen.
        const fullScan = this.cyclesSinceFullScan >= SystemMetricsCollector.FULL_SCAN_EVERY_CYCLES;
        const candidates: number[] = [];
        for (const pid of allPids) {
          if (fullScan || this.pidCache.has(pid) || !this.seenPids.has(pid)) candidates.push(pid);
        }

        for (const pid of candidates) {
          try {
            const commPath = `/proc/${pid}/comm`;
            if (!fs.existsSync(commPath)) {
              this.pidCache.delete(pid);
              continue;
            }
            const comm = fs.readFileSync(commPath, "utf8").trim().toLowerCase();
            const key = SystemMetricsCollector.COMM_TO_DAEMON[comm];
            if (!key) {
              this.pidCache.delete(pid);
              continue;
            }
            const statmPath = `/proc/${pid}/statm`;
            if (!fs.existsSync(statmPath)) {
              this.pidCache.delete(pid);
              continue;
            }
            const statm = fs.readFileSync(statmPath, "utf8").trim().split(/\s+/);
            const rssPages = parseInt(statm[1], 10) || 0;
            const rssMb = Math.round((rssPages * 4096 / 1048576) * 10) / 10;
            this.pidCache.set(pid, key);

            const entry = daemons[key];
            if (!entry) continue;
            entry.memoryMb = Math.round((entry.memoryMb + rssMb) * 10) / 10;
            entry.status = "ACTIVE";
            if (!entry.pid) entry.pid = pid;
          } catch {
            /* Expected: /proc/<pid> disappears between readdirSync and the
               read. A process exiting mid-scan is normal, not a failure. */
            this.pidCache.delete(pid);
          }
        }

        // Forget pids that are gone so the cache does not grow for the lifetime
        // of the process.
        for (const pid of [...this.pidCache.keys()]) {
          if (!allPids.has(pid)) this.pidCache.delete(pid);
        }
        this.seenPids = allPids;
        this.cyclesSinceFullScan = fullScan ? 1 : this.cyclesSinceFullScan + 1;
      } catch (error) {
        warnOnce("scan /proc for mail daemons", error);
      }
    }

    let totalDaemonMemoryMb = 0;
    for (const k in daemons) {
      totalDaemonMemoryMb += daemons[k].memoryMb;
    }
    totalDaemonMemoryMb = Math.round(totalDaemonMemoryMb * 10) / 10;
    return { totalDaemonMemoryMb, daemons };
  }

  private queueMetrics(): { total: number; deferred: number } {
    if (process.platform !== "linux") return { total: 0, deferred: 0 };
    try {
      const r = spawnSync("postqueue", ["-j"], { encoding: "utf8", timeout: 2000 });
      if (r.status !== 0) {
        warnOnce("run postqueue -j", new Error(`exit ${r.status}: ${String(r.stderr || "").trim()}`));
        return { total: 0, deferred: 0 };
      }
      let total = 0, deferred = 0;
      for (const line of String(r.stdout || "").split("\n")) {
        if (!line.trim()) continue;
        try {
          const item = JSON.parse(line);
          total++;
          if ((item.recipients || []).some((x: any) => x.delay_reason)) deferred++;
        } catch (error) {
          warnOnce("parse a postqueue -j line", error);
        }
      }
      return { total, deferred };
    } catch (error) {
      warnOnce("collect queue metrics", error);
      return { total: 0, deferred: 0 };
    }
  }

  private updateDiskInfo() {
    try {
      const r = spawnSync("df", ["-k", "/"], { encoding: "utf8", timeout: 2000 });
      if (r.status === 0) {
        const lines = r.stdout.trim().split("\n");
        if (lines.length > 1) {
          const parts = lines[1].trim().split(/\s+/);
          if (parts.length >= 5) {
            const totalKb = parseInt(parts[1], 10) || 1;
            const usedKb = parseInt(parts[2], 10) || 0;
            const totalGb = Math.round(totalKb / 1048576 * 10) / 10;
            const usedGb = Math.round(usedKb / 1048576 * 10) / 10;
            const percent = Math.round(usedKb / totalKb * 1000) / 10;
            this.diskInfo = { totalGb, usedGb, percent };
          }
        }
      } else {
        warnOnce("run df -k /", new Error(`exit ${r.status}: ${String(r.stderr || "").trim()}`));
      }
    } catch (error) {
      warnOnce("collect disk usage", error);
    }
  }

  public sample(): TelemetryPoint {
    const now = Date.now();
    this.lastSampleTime = now;
    const cpu = this.getCpuUsage();
    const mem = this.getMemInfo();
    const daemonsInfo = this.getDaemonsInfo();
    const queues = this.queueMetrics();
    const loads = os.loadavg();

    const point: TelemetryPoint = {
      timestamp: new Date(now).toISOString(),
      cpuPercent: cpu,
      memoryMb: daemonsInfo.totalDaemonMemoryMb,
      systemMemoryPercent: mem.percent,
      systemMemoryUsedMb: mem.usedMb,
      systemMemoryTotalMb: mem.totalMb,
      load1: Math.round(loads[0] * 100) / 100,
      load5: Math.round(loads[1] * 100) / 100,
      load15: Math.round(loads[2] * 100) / 100,
      queueTotal: queues.total,
      queueDeferred: queues.deferred,
      daemons: daemonsInfo.daemons
    };

    // 1m ring (2s interval, max 30)
    this.ring1m.push(point);
    if (this.ring1m.length > 30) this.ring1m.shift();

    // 5m ring (5s interval, max 60)
    if (this.ring5m.length === 0 || now - new Date(this.ring5m[this.ring5m.length - 1].timestamp).getTime() >= 5000) {
      this.ring5m.push(point);
      if (this.ring5m.length > 60) this.ring5m.shift();
    }

    // 30m ring (30s interval, max 60)
    if (this.ring30m.length === 0 || now - new Date(this.ring30m[this.ring30m.length - 1].timestamp).getTime() >= 30000) {
      this.ring30m.push(point);
      if (this.ring30m.length > 60) this.ring30m.shift();
    }

    // 1h ring (60s interval, max 60)
    if (this.ring1h.length === 0 || now - new Date(this.ring1h[this.ring1h.length - 1].timestamp).getTime() >= 60000) {
      this.ring1h.push(point);
      if (this.ring1h.length > 60) this.ring1h.shift();
    }

    // 6h ring (5m interval, max 72)
    if (this.ring6h.length === 0 || now - new Date(this.ring6h[this.ring6h.length - 1].timestamp).getTime() >= 300000) {
      this.ring6h.push(point);
      if (this.ring6h.length > 72) this.ring6h.shift();
    }

    // 24h ring (15m interval, max 96)
    if (this.ring24h.length === 0 || now - new Date(this.ring24h[this.ring24h.length - 1].timestamp).getTime() >= 900000) {
      this.ring24h.push(point);
      if (this.ring24h.length > 96) this.ring24h.shift();
    }

    // 3d ring (1h interval, max 72)
    if (this.ring3d.length === 0 || now - new Date(this.ring3d[this.ring3d.length - 1].timestamp).getTime() >= 3600000) {
      this.ring3d.push(point);
      if (this.ring3d.length > 72) this.ring3d.shift();
    }

    return point;
  }

  public getTelemetry(range: TelemetryTimeframe = "1h") {
    let rawPoints: TelemetryPoint[];
    let intervalMs = 60000;

    switch (range) {
      case "1m":
        rawPoints = this.ring1m;
        intervalMs = 2000;
        break;
      case "5m":
        rawPoints = this.ring5m;
        intervalMs = 5000;
        break;
      case "30m":
        rawPoints = this.ring30m;
        intervalMs = 30000;
        break;
      case "1h":
        rawPoints = this.ring1h;
        intervalMs = 60000;
        break;
      case "6h":
        rawPoints = this.ring6h;
        intervalMs = 300000;
        break;
      case "24h":
        rawPoints = this.ring24h;
        intervalMs = 900000;
        break;
      case "3d":
        rawPoints = this.ring3d;
        intervalMs = 3600000;
        break;
      default:
        rawPoints = this.ring1h;
        intervalMs = 60000;
    }

    const points = [...rawPoints];
    const latest = points[points.length - 1] || this.sample();
    const mem = this.getMemInfo();
    const daemonsInfo = this.getDaemonsInfo();
    const loads = os.loadavg();

    let sumCpu = 0, maxCpu = 0;
    let sumMem = 0, maxMem = 0;
    let sumSysMem = 0, maxSysMem = 0;

    for (const p of points) {
      sumCpu += p.cpuPercent;
      if (p.cpuPercent > maxCpu) maxCpu = p.cpuPercent;
      sumMem += p.memoryMb;
      if (p.memoryMb > maxMem) maxMem = p.memoryMb;
      sumSysMem += p.systemMemoryPercent;
      if (p.systemMemoryPercent > maxSysMem) maxSysMem = p.systemMemoryPercent;
    }

    const count = points.length || 1;
    const avgCpu = Math.round((sumCpu / count) * 10) / 10;
    const avgMemoryMb = Math.round((sumMem / count) * 10) / 10;
    const avgSystemMemPercent = Math.round((sumSysMem / count) * 10) / 10;

    const daemonMetricsList = Object.entries(daemonsInfo.daemons).map(([id, d]) => ({
      id,
      name: id,
      pid: d.pid,
      memoryMb: d.memoryMb,
      cpuPercent: d.cpuPercent,
      status: d.status as "ACTIVE" | "STOPPED",
    }));

    return {
      timeframe: range,
      intervalMs,
      samplingCount: points.length,
      current: {
        cpuPercent: latest.cpuPercent,
        totalDaemonMemoryMb: daemonsInfo.totalDaemonMemoryMb,
        systemMemoryUsedMb: mem.usedMb,
        systemMemoryTotalMb: mem.totalMb,
        systemMemoryPercent: mem.percent,
        loadAvg: [Math.round(loads[0] * 100) / 100, Math.round(loads[1] * 100) / 100, Math.round(loads[2] * 100) / 100] as [number, number, number],
        uptimeSec: Math.floor(os.uptime()),
        daemons: daemonMetricsList,
        cores: os.cpus().length,
        hostname: os.hostname(),
        diskTotalGb: this.diskInfo.totalGb,
        diskUsedGb: this.diskInfo.usedGb,
        diskUsagePercent: this.diskInfo.percent
      },
      summary: {
        avgCpu,
        maxCpu: Math.round(maxCpu * 10) / 10,
        currentCpu: latest.cpuPercent,
        avgMemoryMb,
        maxMemoryMb: Math.round(maxMem * 10) / 10,
        currentMemoryMb: daemonsInfo.totalDaemonMemoryMb,
        avgSystemMemPercent,
        maxSystemMemPercent: Math.round(maxSysMem * 10) / 10,
        currentSystemMemPercent: mem.percent,
        currentLoad: [Math.round(loads[0] * 100) / 100, Math.round(loads[1] * 100) / 100, Math.round(loads[2] * 100) / 100] as [number, number, number]
      },
      points
    };
  }

  public getRealtime() {
    const mem = this.getMemInfo();
    const daemonsInfo = this.getDaemonsInfo();
    const loads = os.loadavg();
    const cpus = os.cpus();
    const cpuSample = this.sampleCpu();

    const daemonMetricsList = Object.entries(daemonsInfo.daemons).map(([id, d]) => ({
      id,
      name: id,
      pid: d.pid,
      memoryMb: d.memoryMb,
      cpuPercent: d.cpuPercent,
      status: d.status as "ACTIVE" | "STOPPED",
    }));

    return {
      timestamp: new Date().toISOString(),
      cpuPercent: cpuSample.avg,
      cores: cpus.length,
      coreUsage: cpuSample.perCore,
      systemMemoryUsedMb: mem.usedMb,
      systemMemoryTotalMb: mem.totalMb,
      systemMemoryPercent: mem.percent,
      systemMemoryFreeMb: mem.freeMb,
      systemMemoryCachedMb: mem.cachedMb,
      loadAvg: [Math.round(loads[0] * 100) / 100, Math.round(loads[1] * 100) / 100, Math.round(loads[2] * 100) / 100] as [number, number, number],
      uptimeSec: Math.floor(os.uptime()),
      daemons: daemonMetricsList,
      diskTotalGb: this.diskInfo.totalGb,
      diskUsedGb: this.diskInfo.usedGb,
      diskUsagePercent: this.diskInfo.percent
    };
  }
}

const metricsCollector = new SystemMetricsCollector();

const app = express();
const PKG_VERSION = String(pkg.version || "0.0.0").trim();
const PORT = Number(String(process.env.ADMIN_PORT || process.env.PORT || 8787).trim());
const HOST = String(process.env.ADMIN_HOST || process.env.HOST || "127.0.0.1").trim();
function resolveDistDir() {
  const envDist = process.env.DIST_DIR;
  if (envDist && fs.existsSync(envDist)) return envDist;
  const directDist = path.join(process.cwd(), "dist");
  if (fs.existsSync(path.join(directDist, "index.html"))) return directDist;
  const relativeDist = path.resolve(__dirname, "../ui/dist");
  if (fs.existsSync(path.join(relativeDist, "index.html"))) return relativeDist;
  const uiDist = path.resolve(__dirname, "ui/dist");
  if (fs.existsSync(path.join(uiDist, "index.html"))) return uiDist;
  const cwdUiDist = path.join(process.cwd(), "ui/dist");
  if (fs.existsSync(path.join(cwdUiDist, "index.html"))) return cwdUiDist;
  const bundledDist = path.resolve(__dirname, "dist");
  if (fs.existsSync(path.join(bundledDist, "index.html"))) return bundledDist;
  const optDist = "/opt/mailstack/ui/dist";
  if (fs.existsSync(path.join(optDist, "index.html"))) return optDist;
  return directDist;
}
const DIST = resolveDistDir();
app.disable("x-powered-by");
if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);
app.use((req, res, next) => {
  const reqId = crypto.randomBytes(8).toString("hex");
  res.setHeader("X-Request-Id", reqId);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  );
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  next();
});
app.use(express.json({ limit: "256kb" }));

/**
 * A1: Enroll window gate. When public mode is active but 2FA is not yet
 * enabled, only login and 2FA enrollment endpoints are reachable. Everything
 * else gets a hard 403 -- including /api/domains, /api/users, etc.
 * The window binds to 127.0.0.1 only (see listen logic below).
 */
const ENROLL_ALLOWED_PATHS = new Set([
  "/api/auth/login",
  "/api/auth/logout",
  "/api/auth/session",
  "/api/health",
  "/api/admin/2fa",
  "/api/admin/2fa/begin",
  "/api/admin/2fa/enable",
  "/api/admin/2fa/disable",
]);
app.use((req, res, next) => {
  if (!enrollWindowActive) return next();
  // Window expired → hard exit (systemd will restart, same gate re-applies).
  if (enrollWindowExpired()) {
    console.error("mailstack: enroll window expired without 2FA being enabled. Exiting.");
    process.exit(1);
  }
  const urlPath = req.path.split("?")[0];
  if (ENROLL_ALLOWED_PATHS.has(urlPath)) return next();
  return res.status(403).json({
    error: { code: "ENROLL_WINDOW_ACTIVE", message: "Server is in 2FA enrollment window. Only login and 2FA endpoints are available." },
  });
});
type AdminSession = { created: number; expires: number; csrf: string; user: string; ip?: string; userAgent?: string };
type AuthenticatedRequest = Request & { session: AdminSession };
const ADMIN_FILE = process.env.ADMIN_FILE || "/etc/mailstack/admin.json";
const INSTALL_ARGS_CONF = process.env.INSTALL_ARGS_CONF || "/etc/mailstack/install-args.conf";

/**
 * Read ACCESS_MODE from install-args.conf.
 * Mirrors core.py read_access_mode() -- keep in sync.
 * Returns 'local' when the file or key is missing.
 */
function readAccessMode(): string {
  try {
    const text = fs.readFileSync(INSTALL_ARGS_CONF, "utf8");
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.startsWith("ACCESS_MODE=")) {
        const value = trimmed.slice("ACCESS_MODE=".length).trim().replace(/^['"]|['"]$/g, "");
        return value || "local";
      }
    }
  } catch { /* file missing or unreadable */ }
  return "local";
}

/**
 * True when the deployment is internet-facing (caddy/direct) or the
 * security profile is explicitly set to high.
 * Mirrors core.py is_public_mode() -- keep in sync.
 */
function isPublicMode(): boolean {
  const mode = readAccessMode();
  if (mode === "caddy" || mode === "direct") return true;
  const profile = String(process.env.MAILSTACK_SECURITY_PROFILE || "").trim().toLowerCase();
  return profile === "high";
}

const PUBLIC_MODE = isPublicMode();

/**
 * Enroll window state: when public mode is active but 2FA is not enabled,
 * the server binds to 127.0.0.1 only and restricts API access to login +
 * 2FA enrollment endpoints. All other API calls return 403.
 */
let enrollWindowActive = false;
let enrollWindowDeadline = 0;
const ENROLL_WINDOW_MS = Math.max(1000, Number(process.env.MAILSTACK_ENROLL_WINDOW_MS || 900000));

/** Check if 2FA is enabled in admin.json */
function isTotpEnabled(): boolean {
  try {
    const cfg = JSON.parse(fs.readFileSync(ADMIN_FILE, "utf8"));
    return Boolean(cfg?.totp?.enabled);
  } catch { return false; }
}

/** Enter enroll window state */
function enterEnrollWindow(): void {
  if (!PUBLIC_MODE) return;
  enrollWindowActive = true;
  enrollWindowDeadline = Date.now() + ENROLL_WINDOW_MS;
  console.error(`mailstack: public mode without 2FA -- entering enroll window (${ENROLL_WINDOW_MS}ms). Only login and 2FA endpoints are available on 127.0.0.1.`);
}

/** Exit enroll window (2FA was enabled) */
function exitEnrollWindow(): void {
  if (enrollWindowActive) {
    enrollWindowActive = false;
    console.error("mailstack: 2FA enabled -- exiting enroll window, full API access restored.");
  }
}

/** Check if enroll window has expired */
function enrollWindowExpired(): boolean {
  return enrollWindowActive && Date.now() > enrollWindowDeadline;
}
const sessions = new Map<string, AdminSession>();
const MAX_SESSIONS = Number(process.env.MAX_SESSIONS || 5000);
const ABSOLUTE_SESSION_MAX_MS = 7 * 24 * 3600e3; // 7 days absolute lifetime
function credentials() {
  try {
    return JSON.parse(fs.readFileSync(ADMIN_FILE, "utf8"));
  } catch {
    return null;
  }
}
function verify(user: string, password: string) {
  const c = credentials();
  if (!c || user !== c.username || c.algorithm !== "pbkdf2-sha256")
    return false;
  const got = crypto.pbkdf2Sync(
      password,
      Buffer.from(c.salt, "hex"),
      Number(c.iterations),
      32,
      "sha256",
    ),
    expected = Buffer.from(c.hash, "hex");
  return (
    got.length === expected.length && crypto.timingSafeEqual(got, expected)
  );
}
// --- TOTP replay guard (A3) ---
// Login-time codes are verified inside the privileged helper via the
// `admin.totp.verify` action, which holds the AES-256-GCM envelope. The secret
// never reaches this process (it cannot even read it: admin.json stores only
// {enc, nonce, tag} and the master key is root-only). Node keeps the replay
// guard alone: each 30s step is accepted at most once per account, so the
// helper's +/-1 window cannot be replayed for ~90 seconds.
const TOTP_STEP_SECONDS = 30;
/**
 * Replay guard: each TOTP step is accepted at most once per account. The
 * +/-1 window would otherwise let one code be replayed for ~90 seconds.
 * Keyed by the (single) admin username, so this stays tiny.
 */
const totpLastAcceptedCounter = new Map<string, number>();
function cookies(req: Request): Record<string, string> {
  return Object.fromEntries(
    String(req.headers.cookie || "")
      .split(";")
      .map((x: string) => x.trim().split(/=(.*)/s))
      .filter((x): x is [string, string] => Boolean(x[0])),
  );
}
function auth(req: Request, res: Response, next: NextFunction) {
  const sid = cookies(req).mailstack_session,
    s = sessions.get(sid);
  if (
    !s ||
    s.expires < Date.now() ||
    (s.created && Date.now() - s.created > ABSOLUTE_SESSION_MAX_MS)
  ) {
    if (sid) sessions.delete(sid);
    return res.status(401).json({ error: { code: "AUTH_REQUIRED", message: "Authentication required or session expired." } });
  }
  if (
    !["GET", "HEAD"].includes(req.method) &&
    req.headers["x-csrf-token"] !== s.csrf
  )
    return res.status(403).json({ error: { code: "CSRF_INVALID", message: "Invalid or missing CSRF token." } });
  s.expires = Date.now() + 8 * 3600e3;
  (req as AuthenticatedRequest).session = s;
  next();
}
// ACME issuance can legitimately take 30-90s; default raised from 30s and
// overridable via MAILSTACK_HELPER_TIMEOUT_MS.
const HELPER_TIMEOUT_MS = Math.max(
  5000,
  Number(String(process.env.MAILSTACK_HELPER_TIMEOUT_MS || 120000).trim()) || 120000,
);
// B1: Node 直连的是【只读面】socket（helper-ro.sock, 0660 root:mailstack-admin）。
// 变更面 helper.sock 是 0600 root:root，本进程（mailstack-admin）连不上——变更动作
// 恒经 sudo `mailstack-privileged` 包装器（见 ctl()）。环境变量随之改名，避免与
// daemon 的 MAILSTACK_HELPER_SOCKET（变更面）撞名。
const HELPER_SOCKET = String(process.env.MAILSTACK_HELPER_RO_SOCKET || "/run/mailstack/helper-ro.sock").trim();
const HELPER_UNAVAILABLE = "PRIVILEGED_HELPER_UNAVAILABLE";

/**
 * B1 变更面 action 集合。必须与 backend/mailstackctl/core.py 的 ALLOWED_ACTIONS_RW
 * 逐项一致（两处互相指向；tests/security-static.test.mjs 的一致性门禁解析两文件
 * 集合并比对，任何漂移都会红）。ctl() 据此为未显式指定 kind 的调用自动选通道：
 * 命中此集合 => rw => 恒走 sudo 包装器；否则 => ro => 直连 helper-ro.sock。
 */
const RW_ACTIONS = new Set<string>([
  // setup 流程（写配置 / 签发证书 / 发测试信；dns.verify、relay.test 保守归 rw）
  "setup.identity.apply", "setup.dns.verify", "setup.relay.test", "setup.relay.apply",
  "setup.cert.issue", "setup.mail.test",
  // 发信
  "mail.test_loopback",
  // 域名 / 邮箱 / 别名 / 队列变更（users.status 锁解账号，属变更）
  "domains.add", "domains.delete",
  "users.add", "users.delete", "users.status", "users.password",
  "aliases.add", "aliases.delete", "queue.action",
  // 服务启停重载
  "services.action",
  // fail2ban 封禁 / 解封
  "security.unban", "security.ban",
  // 证书续期 / DKIM 轮换
  "certs.renew", "dkim.rotate",
  // 写 settings
  "settings.set",
  // 备份创建 / 恢复 / 删除
  "backup.create", "backup.restore", "backup.delete",
  // 管理员凭证变更
  "admin.set",
  // TOTP 全生命周期（verify 在迁移路径会重新封装 admin.json，有写副作用）
  "admin.totp.begin", "admin.totp.enable", "admin.totp.disable",
  "admin.totp.consume_recovery", "admin.totp.verify",
  // AI 配置写入与出站对话 / 诊断 / 解析
  "ai.config.set", "ai.test", "ai.chat", "ai.diagnose", "ai.parse",
]);

/**
 * Primary transport: the long-running privileged helper daemon.
 * Protocol: uint32be(length) + utf-8 JSON in both directions. One root
 * process serves every request, so the 5s `logs.list` poll no longer costs a
 * sudo+python fork per call.
 */
function ctlViaSocket(action: string, data: unknown): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err?: Error, val?: Record<string, unknown>) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch { /* already closed */ }
      err ? reject(err) : resolve(val || {});
    };
    let sock: net.Socket;
    try {
      sock = net.connect(HELPER_SOCKET);
    } catch {
      return finish(new Error(HELPER_UNAVAILABLE));
    }
    const timer = setTimeout(() => finish(new Error("PRIVILEGED_HELPER_TIMEOUT")), HELPER_TIMEOUT_MS);
    let buf = Buffer.alloc(0);
    let expected = -1;
    sock.on("error", () => finish(new Error(HELPER_UNAVAILABLE)));
    sock.on("connect", () => {
      const payload = Buffer.from(JSON.stringify({ action, data }), "utf8");
      const header = Buffer.alloc(4);
      header.writeUInt32BE(payload.length, 0);
      sock.write(Buffer.concat([header, payload]));
    });
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (expected < 0 && buf.length >= 4) expected = buf.readUInt32BE(0);
      if (buf.length > 16 * 1048576) return finish(new Error("PRIVILEGED_OPERATION_FAILED"));
      if (expected >= 0 && buf.length >= 4 + expected) {
        try {
          const j = JSON.parse(buf.subarray(4, 4 + expected).toString("utf8"));
          j.ok
            ? finish(undefined, j.data)
            : finish(new Error(String(j.error || "PRIVILEGED_OPERATION_FAILED")));
        } catch {
          finish(new Error("PRIVILEGED_OPERATION_FAILED"));
        }
      }
    });
    sock.on("close", () => finish(new Error(HELPER_UNAVAILABLE)));
  });
}

/**
 * One-shot transport: `sudo` + the root-owned wrapper, matched exactly by
 * the one and only sudoers rule. Two roles after the B1 split:
 *   1. PRIMARY transport for mutating (rw) actions, on public and local
 *      mode alike -- the rw socket is 0600 root:root and Node cannot
 *      connect, so the sudoers-gated wrapper IS the change surface;
 *   2. local-mode fallback for read-only (ro) actions when the helper
 *      daemon is down (non-systemd deployments, or the window between a
 *      daemon crash and its systemd restart).
 * There is deliberately no fallback to the raw python entrypoint -- a
 * "helpful" fallback was a second root channel with a wider path, which is
 * exactly what the sudoers allowlist is supposed to rule out.
 */
function ctlViaSudo(action: string, data: unknown): Promise<Record<string, unknown>> {
  const HELPER_PATH = "/usr/local/libexec/mailstack-privileged";
  return new Promise<Record<string, unknown>>((resolve, reject) => {
    let settled = false,
      o = "",
      e = "",
      p: ReturnType<typeof spawn>;
    const finish = (err?: Error, val?: Record<string, unknown>) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      err ? reject(err) : resolve(val || {});
    };
    try {
      p = spawn("sudo", [HELPER_PATH], {
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      return finish(new Error(HELPER_UNAVAILABLE));
    }
    const timer = setTimeout(() => {
      p.kill("SIGKILL");
      finish(new Error("PRIVILEGED_HELPER_TIMEOUT"));
    }, HELPER_TIMEOUT_MS);
    p.on("error", () => finish(new Error(HELPER_UNAVAILABLE)));
    p.stdout.on("data", (d: Buffer) => {
      if (o.length < 1048576) o += d;
    });
    p.stderr.on("data", (d: Buffer) => {
      if (e.length < 16384) e += d;
    });
    p.on("close", (c: number) => {
      try {
        const j = JSON.parse(o);
        j.ok
          ? finish(undefined, j.data)
          : finish(new Error(String(j.error || "PRIVILEGED_OPERATION_FAILED")));
      } catch {
        console.error("helper failure", {
          action,
          code: c,
          stderr: e.slice(-2000),
        });
        finish(new Error("PRIVILEGED_OPERATION_FAILED"));
      }
    });
    p.stdin.on("error", () => {});
    p.stdin.end(JSON.stringify({ action, data }));
  });
}

/**
 * Privileged helper call, routed by the B1 dual-socket split.
 *
 * Routing (kind is derived from the action name unless the caller overrides):
 *   - rw  (action ∈ RW_ACTIONS): ALWAYS `sudo /usr/local/libexec/
 *     mailstack-privileged` -- the single sudoers rule is the root change
 *     surface, identical on public and local mode. The rw socket
 *     (helper.sock, 0600 root:root) is a root-only defense-in-depth channel
 *     this process cannot and does not connect to.
 *   - ro  (everything else): the read-only socket (helper-ro.sock, 0660
 *     root:mailstack-admin) via ctlViaSocket.
 *
 * Fallback policy (ro channel only; the A2 invariant scoped to the ro
 * channel): Public mode (caddy/direct/high) NEVER falls back to sudo for a
 * read-only action. If the read-only socket is down, the caller gets a
 * 503-semantic error (HELPER_UNAVAILABLE) rather than spawning sudo. This
 * keeps "Node RCE -> sudo -> full root" out of internet-facing deployments.
 * Local mode retains the one-shot fallback for non-systemd hosts. rw calls
 * never enter that branch: the sudo wrapper is their primary transport, not
 * a fallback.
 *
 * @param kind optional channel override; when omitted, routing follows
 *   RW_ACTIONS so it cannot drift from the core.py ALLOWED_ACTIONS_RO/RW
 *   split (guarded by tests/security-static.test.mjs).
 */
function ctl(action: string, data: Record<string, unknown> | unknown = {}, kind?: 'ro' | 'rw'): Promise<Record<string, unknown>> {
  // B1: derive the channel from the action name. RW_ACTIONS mirrors
  // ALLOWED_ACTIONS_RW in core.py; unknown actions default to the ro socket,
  // where the daemon refuses them (a read-only surface cannot widen silently).
  const effectiveKind: 'ro' | 'rw' = kind ?? (RW_ACTIONS.has(action) ? "rw" : "ro");
  if (effectiveKind === "rw") {
    // Mutating actions always travel through the sudo wrapper (public and
    // local alike): the wrapper IS the change surface, gated by the single
    // sudoers rule. No socket-first attempt for rw -- helper.sock is 0600
    // root:root and this process could not connect anyway.
    return ctlViaSudo(action, data);
  }
  return ctlViaSocket(action, data).catch((err: Error) => {
    // Only a transport-level failure (daemon down / socket missing) may fall
    // back to the one-shot path. A business error or a mid-operation timeout
    // must not be retried blindly -- retrying a half-finished ACME issuance
    // or a backup restore would execute it twice.
    if (err.message !== HELPER_UNAVAILABLE) throw err;
    // A2 (B1-scoped to the ro channel): public mode MUST NOT fall back to
    // sudo for a read-only action. The ro helper socket is the only
    // privileged read channel; if it is unavailable the operation fails with
    // a 503-semantic error. rw calls never reach this branch.
    if (PUBLIC_MODE) throw err;
    return ctlViaSudo(action, data);
  });
}
const attempts = new Map<string, { count: number; until: number; lastAttempt: number }>();
const MAX_ATTEMPT_KEYS = 5000;

// Fixed-window rate buckets, aligned with the webmail login policy:
// global + per-IP + per-account, on top of the 5-strikes account lockout.
// The 401 INVALID_CREDENTIALS body stays undifferentiated (no remaining
// attempts, no hint which factor failed) because it is returned only when the
// PASSWORD check fails -- an undifferentiated refusal is enumeration defence,
// and it shares the same rate buckets as the TOTP step. A correct password
// with 2FA enabled returns 401 TOTP_REQUIRED instead: that deliberate,
// documented exception is required by the handover spec and does not weaken
// the bucketed 401 path above.
const rateBuckets = new Map<string, { count: number; resetAt: number }>();
function consumeRate(key: string, limit: number, windowMs: number): number | null {
  const t = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= t) bucket = { count: 0, resetAt: t + windowMs };
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  return bucket.count <= limit ? null : Math.max(1, Math.ceil((bucket.resetAt - t) / 1000));
}

setInterval(() => {
  const n = Date.now();
  for (const [k, v] of sessions) if (v.expires < n) sessions.delete(k);
  for (const [k, v] of attempts) {
    if (v.until && v.until < n) attempts.delete(k);
    else if (!v.until && n - v.lastAttempt > 900000) attempts.delete(k); // 15-minute sliding window cleanup
  }
}, 60000).unref();

app.post("/api/auth/login", async (req, res) => {
  const ip = req.ip || "unknown",
    user = String(req.body?.username || ""),
    key = `${ip}:${user}`,
    a = attempts.get(key);
  const bucketRetry = Math.max(
    consumeRate("login:global", 500, 60_000) || 0,
    consumeRate(`login:ip:${ip}`, 30, 15 * 60_000) || 0,
    consumeRate(`login:account:${user.toLowerCase()}`, 10, 15 * 60_000) || 0,
  );
  if (bucketRetry || (a && a.until > Date.now())) {
    const retryAfter = Math.max(
      bucketRetry || 0,
      a && a.until > Date.now() ? Math.ceil((a.until - Date.now()) / 1000) : 0,
      1,
    );
    res.setHeader("Retry-After", String(retryAfter));
    return res.status(429).json({
      error: {
        code: "RATE_LIMITED",
        message: "Too many login attempts. Please try again later.",
      },
    });
  }
  const password = String(req.body?.password || "");
  if (!verify(user, password)) {
    const count = (a?.count || 0) + 1;
    const until = count >= 5 ? Date.now() + 300000 : 0;
    if (attempts.size >= MAX_ATTEMPT_KEYS && !attempts.has(key)) {
      const firstKey = attempts.keys().next().value;
      if (firstKey) attempts.delete(firstKey);
    }
    attempts.set(key, { count, until, lastAttempt: Date.now() });
    return res.status(401).json({
      error: {
        code: "INVALID_CREDENTIALS",
        message: "Invalid username or password.",
      },
    });
  }
  // --- Two-factor gate (v0.5.2). Runs only after the password check passed.
  // attempts.delete(key) deliberately sits BELOW this block: clearing the
  // strike ledger on the password alone would let a password holder brute
  // force the 6-digit code outside the 5-strikes lockout.
  const totpCfg = credentials()?.totp;
  if (totpCfg && totpCfg.enabled) {
    const code = String(req.body?.code || "");
    if (!code) {
      // Password was correct but the second factor is still missing. This is
      // a normal UI round-trip, not a failed attempt, so no strike is added;
      // the three rate buckets above still apply.
      return res.status(401).json({
        error: { code: "TOTP_REQUIRED", message: "Two-factor code required." },
      });
    }
    let secondFactorOk = false;
    if (/^\d{6}$/.test(code)) {
      // A3: TOTP verification is delegated to the privileged helper which
      // holds the AES-256-GCM envelope. The secret never leaves the helper.
      // Node retains only the replay guard (per-user 30s step counter).
      try {
        const result = await ctl("admin.totp.verify", { code });
        secondFactorOk = result?.ok === true;
      } catch {
        secondFactorOk = false;
      }
      // Replay guard: reject a counter already accepted for this account.
      if (secondFactorOk) {
        const counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
        const lastAccepted = totpLastAcceptedCounter.get(user);
        if (lastAccepted !== undefined && counter <= lastAccepted) {
          secondFactorOk = false;
        } else {
          totpLastAcceptedCounter.set(user, counter);
        }
      }
    } else {
      // Anything else can only be a one-time recovery code. Consuming it
      // mutates admin.json, which this process cannot write, so it goes
      // through the privileged helper; business errors are never retried.
      try {
        const consumed = await ctl("admin.totp.consume_recovery", { code });
        secondFactorOk = consumed?.consumed === true;
      } catch {
        secondFactorOk = false;
      }
    }
    if (!secondFactorOk) {
      // A wrong second factor joins the same strike/lockout ledger as a wrong
      // password (structure mirrored from the password branch above).
      const count = (a?.count || 0) + 1;
      const until = count >= 5 ? Date.now() + 300000 : 0;
      if (attempts.size >= MAX_ATTEMPT_KEYS && !attempts.has(key)) {
        const firstKey = attempts.keys().next().value;
        if (firstKey) attempts.delete(firstKey);
      }
      attempts.set(key, { count, until, lastAttempt: Date.now() });
      return res.status(401).json({
        error: {
          code: "INVALID_CREDENTIALS",
          message: "Invalid username or password.",
        },
      });
    }
  }
  attempts.delete(key);

  // Enforce MAX_SESSIONS hard limit: sweep every expired session, then evict the
  // entry closest to expiry. The old loop bailed out after the first expired entry,
  // so a backlog of dead sessions could survive and the oldest-live tracking was
  // left half-computed.
  if (sessions.size >= MAX_SESSIONS) {
    const now = Date.now();
    let oldestKey: string | null = null;
    let oldestExpires = Infinity;
    for (const [k, v] of sessions) {
      if (v.expires < now) {
        sessions.delete(k);
        continue;
      }
      if (v.expires < oldestExpires) {
        oldestExpires = v.expires;
        oldestKey = k;
      }
    }
    if (sessions.size >= MAX_SESSIONS && oldestKey) {
      sessions.delete(oldestKey);
    }
  }

  const sid = crypto.randomBytes(32).toString("hex"),
    csrf = crypto.randomBytes(24).toString("hex");
  sessions.set(sid, {
    created: Date.now(),
    expires: Date.now() + 8 * 3600e3,
    csrf,
    user,
    ip,
    // Truncated: sessions are in-memory and UAs are untrusted client input.
    userAgent: String(req.headers["user-agent"] || "").slice(0, 512),
  });
  const isHttps = req.secure || req.headers["x-forwarded-proto"] === "https";
  const secureCookie = process.env.COOKIE_SECURE === "1" || (process.env.COOKIE_SECURE !== "0" && isHttps);
  res.setHeader(
    "Set-Cookie",
    `mailstack_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secureCookie ? "; Secure" : ""}`,
  );
  res.json({ ok: true, csrf, username: user });
});
app.post("/api/auth/logout", auth, (req, res) => {
  sessions.delete(cookies(req).mailstack_session);
  res.setHeader(
    "Set-Cookie",
    "mailstack_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
  );
  res.json({ ok: true });
});
app.get("/api/auth/session", auth, (req, res) => {
  const session = (req as AuthenticatedRequest).session;
  res.json({ ok: true, csrf: session.csrf, username: session.user });
});
app.get("/api/health", (_q, res) => {
  let manifestInfo: any = null;
  try {
    const mf = path.join(DIST, "build-manifest.json");
    if (fs.existsSync(mf)) manifestInfo = JSON.parse(fs.readFileSync(mf, "utf8"));
  } catch (error) {
    warnOnce("read build-manifest.json", error);
  }
  return res.json({
    status: "ok",
    version: PKG_VERSION,
    service: "mailstack-admin-api",
    builtAt: manifestInfo?.builtAt || null,
    node: process.version,
    uptimeSec: Math.floor(process.uptime()),
    time: new Date().toISOString(),
  });
});
app.use("/api", auth);
const get = (url: string, action: string) =>
  app.get(url, async (_q, res) => {
    try {
      res.json(await ctl(action));
    } catch (e: any) {
      const unavailable = e.message === "PRIVILEGED_HELPER_UNAVAILABLE";
      const code = unavailable ? 503 : 500;
      res.status(code).json({
        ok: false,
        error: {
          code: unavailable ? e.message : "OPERATION_FAILED",
          message: unavailable ? "Privileged helper unavailable." : "Operation failed."
        }
      });
    }
  });
/**
 * True only when the client explicitly asked for a destructive operation.
 * The privileged helper refuses domains.delete / users.delete / backup.delete
 * without it; the API layer must never manufacture consent on the client's behalf.
 */
const confirmRequested = (body: unknown): boolean =>
  Boolean(body && typeof body === "object" && (body as { confirm?: unknown }).confirm === true);

const post = (url: string, action: string) =>
  app.post(url, async (req, res) => {
    try {
      const payload = (typeof req.body === 'object' && req.body !== null ? req.body : {}) as Record<string, unknown>;
      res.json(await ctl(action, payload));
    } catch (e: any) {
      const unavailable = e.message === "PRIVILEGED_HELPER_UNAVAILABLE";
      const code = unavailable ? 503 : 422;
      res.status(code).json({
        ok: false,
        error: {
          code: unavailable ? e.message : "OPERATION_FAILED",
          message: unavailable ? "Privileged helper unavailable." : "Operation failed."
        }
      });
    }
  });
get("/api/snapshot", "snapshot");
get("/api/status", "snapshot");
post("/api/network/check-port", "network.check_port");
app.get("/api/metrics/telemetry", (req, res) => {
  const range = String(req.query.range || "1h").trim().toLowerCase() as TelemetryTimeframe;
  const validRanges: TelemetryTimeframe[] = ["1m", "5m", "30m", "1h", "6h", "24h", "3d"];
  const targetRange = validRanges.includes(range) ? range : "1h";
  res.json(metricsCollector.getTelemetry(targetRange));
});
app.get("/api/metrics/realtime", (_req, res) => {
  res.json(metricsCollector.getRealtime());
});
get("/api/domains", "domains.list");
post("/api/domains", "domains.add");
app.delete("/api/domains/:id", async (req, res) => {
  try {
    res.json(
      await ctl("domains.delete", {
        id: req.params.id,
        confirm: confirmRequested(req.body),
      }),
    );
  } catch (e: any) {
    res.status(422).json({ ok: false, error: { code: "OPERATION_FAILED", message: e.message } });
  }
});
post("/api/users", "users.add");
post("/api/users/status", "users.status");
post("/api/users/password", "users.password");
app.delete("/api/users/:id", async (req, res) => {
  try {
    res.json(
      await ctl("users.delete", {
        id: req.params.id,
        confirm: confirmRequested(req.body),
      }),
    );
  } catch (e: any) {
    res.status(422).json({ ok: false, error: { code: "OPERATION_FAILED", message: e.message } });
  }
});
post("/api/aliases", "aliases.add");
app.delete("/api/aliases/:id", async (req, res) => {
  try {
    res.json(
      await ctl("aliases.delete", {
        id: req.params.id,
        confirm: confirmRequested(req.body),
      }),
    );
  } catch (e: any) {
    res.status(422).json({ ok: false, error: { code: "OPERATION_FAILED", message: e.message } });
  }
});
post("/api/services/action", "services.action");
post("/api/queue/action", "queue.action");
get("/api/logs", "logs.list");
post("/api/security/scan", "security.scan");
post("/api/security/unban", "security.unban");
post("/api/security/ban", "security.ban");
get("/api/certificates", "certs.list");
post("/api/certificates/renew", "certs.renew");
get("/api/setup/status", "setup.status");
post("/api/setup/identity", "setup.identity.apply");
post("/api/setup/dns/verify", "setup.dns.verify");
post("/api/setup/relay/test", "setup.relay.test");
post("/api/setup/relay/apply", "setup.relay.apply");
post("/api/setup/cert/issue", "setup.cert.issue");
post("/api/setup/mail/test", "setup.mail.test");
post("/api/dkim/rotate", "dkim.rotate");
get("/api/doctor", "system.doctor");
get("/api/system/doctor", "system.doctor");
post("/api/mail/test-loopback", "mail.test_loopback");
get("/api/settings", "settings.get");
post("/api/settings", "settings.set");
post("/api/backups", "backup.create");
get("/api/backups", "backup.list");
post("/api/backups/restore", "backup.restore");
app.delete("/api/backups/:name", async (req, res) => {
  try {
    res.json(
      await ctl("backup.delete", {
        name: req.params.name,
        confirm: confirmRequested(req.body),
      }),
    );
  } catch (e: any) {
    res.status(422).json({ ok: false, error: { code: "OPERATION_FAILED", message: e.message } });
  }
});
get("/api/admin", "admin.get");
app.post("/api/admin", async (req, res) => {
  try {
    const result = await ctl("admin.set", req.body);
    sessions.clear();
    res.setHeader(
      "Set-Cookie",
      "mailstack_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
    );
    res.json({ ...result, reauthenticate: true });
  } catch (e: any) {
    res.status(422).json({ error: { code: "OPERATION_FAILED", message: "Operation failed." } });
  }
});
/**
 * Two-factor administration (v0.5.2). The Node process has read-only access
 * to /etc/mailstack/admin.json, so every 2FA mutation is delegated to the
 * privileged helper (`admin.totp.*`); the status read stays local and never
 * exposes the TOTP secret.
 */
app.get("/api/admin/2fa", (_req, res) => {
  const totp = credentials()?.totp;
  res.json({
    enabled: Boolean(totp?.enabled),
    recoveryCodesRemaining: Array.isArray(totp?.recovery) ? totp.recovery.length : 0,
  });
});
app.post("/api/admin/2fa/begin", async (req, res) => {
  try {
    // Re-enrollment while 2FA is enabled downgrades the account to single
    // factor until the new secret is confirmed, so the helper gates it on a
    // valid code and we treat it like enable/disable here: every session is
    // revoked and the caller must re-authenticate. First-time enrollment
    // keeps the live session -- without it the confirm step could never run
    // and every fresh begin would invalidate the session all over again.
    const wasEnabled = Boolean(credentials()?.totp?.enabled);
    const result = await ctl("admin.totp.begin", { code: String(req.body?.code || "") });
    if (wasEnabled) {
      sessions.clear();
      res.setHeader(
        "Set-Cookie",
        "mailstack_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
      );
      res.json({ ...result, reauthenticate: true });
    } else {
      res.json(result);
    }
  } catch (e: any) {
    res.status(422).json({ error: { code: "OPERATION_FAILED", message: "Operation failed." } });
  }
});
app.post("/api/admin/2fa/enable", async (req, res) => {
  try {
    const result = await ctl("admin.totp.enable", { code: String(req.body?.code || "") });
    // A1: 2FA successfully enabled → exit enroll window if active.
    exitEnrollWindow();
    if (enrollTimer) { clearTimeout(enrollTimer); enrollTimer = null; }
    sessions.clear();
    res.setHeader(
      "Set-Cookie",
      "mailstack_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
    );
    res.json({ ...result, reauthenticate: true });
  } catch (e: any) {
    res.status(422).json({ error: { code: "OPERATION_FAILED", message: "Operation failed." } });
  }
});
app.post("/api/admin/2fa/disable", async (req, res) => {
  try {
    const result = await ctl("admin.totp.disable", { code: String(req.body?.code || "") });
    // A1: 2FA disabled in public mode → immediately enter enroll window.
    // The process does NOT restart; the in-memory flag restricts the API.
    if (PUBLIC_MODE) {
      enterEnrollWindow();
      if (!enrollTimer) {
        enrollTimer = setTimeout(() => {
          console.error("mailstack: enroll window deadline reached without 2FA enablement. Exiting.");
          process.exit(1);
        }, ENROLL_WINDOW_MS);
        enrollTimer.unref();
      }
    }
    sessions.clear();
    res.setHeader(
      "Set-Cookie",
      "mailstack_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
    );
    res.json({ ...result, reauthenticate: true });
  } catch (e: any) {
    res.status(422).json({ error: { code: "OPERATION_FAILED", message: "Operation failed." } });
  }
});
/**
 * Session visibility and revocation (v0.5.2). Listings never expose the raw
 * session id or CSRF token: each entry is identified by the first 16 hex
 * chars of sha256(sid), and revocation matches on that fingerprint.
 */
const sessionIdFingerprint = (sid: string): string =>
  crypto.createHash("sha256").update(sid).digest("hex").slice(0, 16);
const sessionIsLive = (s: AdminSession, now: number): boolean =>
  s.expires >= now && (!s.created || now - s.created <= ABSOLUTE_SESSION_MAX_MS);
app.get("/api/auth/sessions", (req, res) => {
  const currentSid = cookies(req).mailstack_session;
  const now = Date.now();
  const list: { id: string; createdAt: number; ip: string | null; userAgent: string | null; current: boolean }[] = [];
  for (const [sid, s] of sessions) {
    if (!sessionIsLive(s, now)) continue;
    list.push({
      id: sessionIdFingerprint(sid),
      createdAt: s.created,
      ip: s.ip ?? null,
      userAgent: s.userAgent ?? null,
      current: sid === currentSid,
    });
  }
  res.json({ ok: true, sessions: list });
});
app.post("/api/auth/sessions/revoke", (req, res) => {
  const wanted = String(req.body?.id || "").toLowerCase();
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (!sessionIsLive(s, now)) continue;
    if (sessionIdFingerprint(sid) === wanted) {
      sessions.delete(sid);
      return res.json({ ok: true });
    }
  }
  return res.status(404).json({ ok: false, error: { code: "SESSION_NOT_FOUND", message: "Session not found." } });
});
app.delete("/api/auth/sessions", (req, res) => {
  const currentSid = cookies(req).mailstack_session;
  const now = Date.now();
  let revoked = 0;
  for (const [sid, s] of sessions) {
    if (sid === currentSid) continue; // never lock the caller out
    if (sessionIsLive(s, now)) revoked += 1;
    sessions.delete(sid);
  }
  res.json({ ok: true, revoked });
});
const aiRateMap = new Map<string, { count: number; resetAt: number }>();
const aiRateLimit = (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const entry = aiRateMap.get(ip);
  if (!entry || entry.resetAt < now) {
    aiRateMap.set(ip, { count: 1, resetAt: now + 60000 });
    return next();
  }
  if (entry.count >= 20) {
    return res.status(429).json({
      error: {
        code: "RATE_LIMITED",
        message: "Too many AI diagnostic requests. Please wait a moment.",
      },
    });
  }
  entry.count++;
  next();
};

app.use("/api/ai", aiRateLimit);
get("/api/ai/config", "ai.config.get");
post("/api/ai/config", "ai.config.set");
post("/api/ai/models", "ai.models.list");
post("/api/ai/test", "ai.test");
post("/api/ai/chat", "ai.chat");
post("/api/ai/dns-chat", "ai.chat");
post("/api/ai/diagnose", "ai.diagnose");
post("/api/ai/diagnose-dns", "ai.diagnose");
post("/api/ai/parse", "ai.parse");
post("/api/ai/parse-dns-raw", "ai.parse");
app.use("/api", (_req, res) =>
  res.status(404).json({ error: { code: "API_NOT_FOUND" } }),
);
// Periodically clean up expired sessions and rate limit records
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (s.expires < now) sessions.delete(sid);
  }
  for (const [k, a] of attempts) {
    if (a.until && a.until < now) attempts.delete(k);
  }
  for (const [k, b] of rateBuckets) {
    if (b.resetAt < now) rateBuckets.delete(k);
  }
  for (const [ip, entry] of aiRateMap) {
    if (entry.resetAt < now) aiRateMap.delete(ip);
  }
}, 60000).unref();

app.use(express.static(DIST, { index: false, maxAge: "1h" }));
app.get("*", (_q, res) => {
  const indexPath = path.join(DIST, "index.html");
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  return res.status(503).send("MailStack UI is initializing or building. Please refresh in a moment.");
});
app.use((err: any, _req: any, res: any, _next: any) => {
  if (err?.type === "entity.too.large")
    return res.status(413).json({ error: { code: "PAYLOAD_TOO_LARGE" } });
  console.error(err);
  res.status(500).json({ error: { code: "INTERNAL_ERROR" } });
});
/**
 * A5: Production escape-hatch hard close.
 *
 * On an internet-facing deployment (access-mode caddy/direct, or
 * MAILSTACK_SECURITY_PROFILE=high) the following "escape hatch" switches each
 * drag an exposed host back into an unsafe state, so the process refuses to
 * listen when any of them is set:
 *   - COOKIE_SECURE=0            : session cookie loses the Secure flag; a public
 *                                  plain-text hop lets a MITM lift the session.
 *   - HOST/ADMIN_HOST=0.0.0.0     : the admin port binds the public interface
 *                                  directly. The correct production model keeps the
 *                                  panel on 127.0.0.1 and lets Caddy / a front proxy
 *                                  terminate TLS in front of it.
 *   - MAILSTACK_AUDIT_FAILOPEN=1  : placeholder prohibition -- no "audit failed, so
 *                                  allow" path exists today, and none may ever be
 *                                  added; setting it on a public host is refused.
 *   - MAILSTACK_ALLOW_UNSAFE_GIT=1: the unsafe git-clone upgrade hatch (see
 *                                  mailstack.sh). Its presence in a public process
 *                                  environment is a misconfiguration; refuse to start.
 * The ONLY exemption is MAILSTACK_I_AM_A_DEVELOPER=1 AND access-mode local.
 *
 * HOST is the value already resolved at the top of this file from
 * ADMIN_HOST || HOST || 127.0.0.1, so a single comparison covers both env names.
 */
function assertNoEscapeHatches(): void {
  if (!PUBLIC_MODE) return;
  const developerLocal =
    process.env.MAILSTACK_I_AM_A_DEVELOPER === "1" && readAccessMode() === "local";
  if (developerLocal) return;
  const offenders: string[] = [];
  if (process.env.COOKIE_SECURE === "0") offenders.push("COOKIE_SECURE=0");
  if (HOST === "0.0.0.0") offenders.push(`HOST/ADMIN_HOST=${HOST}`);
  if (process.env.MAILSTACK_AUDIT_FAILOPEN === "1") offenders.push("MAILSTACK_AUDIT_FAILOPEN=1");
  if (process.env.MAILSTACK_ALLOW_UNSAFE_GIT === "1") offenders.push("MAILSTACK_ALLOW_UNSAFE_GIT=1");
  if (offenders.length > 0) {
    console.error(
      `mailstack: refusing to start -- public mode with production escape hatch(es) set: ${offenders.join(", ")}. ` +
      `The admin panel must bind 127.0.0.1 only, session cookies must be Secure, audit must never fail open, ` +
      `and the unsafe git upgrade channel must stay off. ` +
      `(Only exemption: MAILSTACK_I_AM_A_DEVELOPER=1 with access-mode local.)`,
    );
    process.exit(1);
  }
}
assertNoEscapeHatches();

/**
 * A1: Startup gate. Public mode without 2FA enters the enroll window:
 * bind 127.0.0.1 only, restrict API to login + 2FA endpoints, and start
 * a deadline timer. If the window expires without 2FA being enabled the
 * process exits non-zero (systemd restarts it, same gate re-applies).
 */
const EFFECTIVE_HOST = (PUBLIC_MODE && !isTotpEnabled()) ? "127.0.0.1" : HOST;
if (PUBLIC_MODE && !isTotpEnabled()) {
  enterEnrollWindow();
}
const server = app.listen(PORT, EFFECTIVE_HOST, () => {
  console.log(`MailStack API on ${EFFECTIVE_HOST}:${PORT}${enrollWindowActive ? " [ENROLL WINDOW]" : ""}`);
});

/** Enroll window deadline timer: hard exit when time runs out. */
let enrollTimer: ReturnType<typeof setTimeout> | null = null;
if (enrollWindowActive) {
  enrollTimer = setTimeout(() => {
    console.error("mailstack: enroll window deadline reached without 2FA enablement. Exiting.");
    process.exit(1);
  }, ENROLL_WINDOW_MS);
  enrollTimer.unref();
}

/**
 * A1: 30s periodic poll of admin.json totp.enabled.
 * Covers the CLI-side disable scenario (helper disables 2FA outside Node).
 * Public mode + totp.enabled becomes false → enter enroll window.
 * Public mode + totp.enabled becomes true → exit enroll window.
 */
setInterval(() => {
  if (!PUBLIC_MODE) return;
  const enabled = isTotpEnabled();
  if (!enabled && !enrollWindowActive) {
    enterEnrollWindow();
    if (!enrollTimer) {
      enrollTimer = setTimeout(() => {
        console.error("mailstack: enroll window deadline reached without 2FA enablement. Exiting.");
        process.exit(1);
      }, ENROLL_WINDOW_MS);
      enrollTimer.unref();
    }
  } else if (enabled && enrollWindowActive) {
    exitEnrollWindow();
    if (enrollTimer) { clearTimeout(enrollTimer); enrollTimer = null; }
  }
}, 30000).unref();

const shutdown = () => {
  server.close(() => {
    process.exit(0);
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

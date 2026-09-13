import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readMailstackctl, rootDir } from "./_source.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test("types.ts contains all 7 telemetry timeframes and response types", () => {
  const types = fs.readFileSync(path.join(rootDir, "src", "types.ts"), "utf8");
  assert.match(types, /'1m' \| '5m' \| '30m' \| '1h' \| '6h' \| '24h' \| '3d'/);
  assert.match(types, /interface DaemonMetric/);
  assert.match(types, /interface TelemetryPoint/);
  assert.match(types, /interface TelemetrySummary/);
  assert.match(types, /interface TelemetryResponse/);
  assert.match(types, /interface SystemRealtimeMetrics/);
});

test("server.production.ts contains SystemMetricsCollector with multi-tier ring buffers", () => {
  const ts = fs.readFileSync(path.join(rootDir, "backend", "server.production.ts"), "utf8");
  assert.match(ts, /class SystemMetricsCollector/);
  assert.match(ts, /ring1m/);
  assert.match(ts, /ring5m/);
  assert.match(ts, /ring30m/);
  assert.match(ts, /ring1h/);
  assert.match(ts, /ring6h/);
  assert.match(ts, /ring24h/);
  assert.match(ts, /ring3d/);
  assert.match(ts, /getTelemetry/);
  assert.match(ts, /getRealtime/);
  assert.match(ts, /\/api\/metrics\/telemetry/);
  assert.match(ts, /\/api\/metrics\/realtime/);
});

test("privileged helper supports metrics.realtime action", () => {
  const py = readMailstackctl();
  assert.match(py, /'metrics\.realtime'/);
  assert.match(py, /systemMemoryTotalMb/);
  assert.match(py, /systemMemoryUsedMb/);
});

test("Frontend components exist and have proper props and structure", () => {
  const rangeDropdown = fs.readFileSync(
    path.join(rootDir, "src", "components", "telemetry", "TelemetryRangeDropdown.tsx"),
    "utf8"
  );
  assert.match(rangeDropdown, /最近 1 小时 \(默认\)/);
  assert.match(rangeDropdown, /'1m'/);
  assert.match(rangeDropdown, /'5m'/);
  assert.match(rangeDropdown, /'30m'/);
  assert.match(rangeDropdown, /'1h'/);
  assert.match(rangeDropdown, /'6h'/);
  assert.match(rangeDropdown, /'24h'/);
  assert.match(rangeDropdown, /'3d'/);

  const chart = fs.readFileSync(
    path.join(rootDir, "src", "components", "telemetry", "SystemTelemetryChart.tsx"),
    "utf8"
  );
  assert.match(chart, /TelemetryRangeDropdown/);
  assert.match(chart, /\/api\/metrics\/telemetry\?range=/);
  assert.match(chart, /daemon_memory/);
  assert.match(chart, /cpu_percent/);
  assert.match(chart, /system_memory/);
  assert.match(chart, /load_average/);

  const modal = fs.readFileSync(
    path.join(rootDir, "src", "components", "modals", "SystemTelemetryModal.tsx"),
    "utf8"
  );
  assert.match(modal, /\/api\/metrics\/realtime/);
  assert.match(modal, /系统深度监测与守护进程分析工具/);
  assert.match(modal, /handleExportJson/);
});

test("DashboardView and ServicesView wire telemetry components", () => {
  const dash = fs.readFileSync(
    path.join(rootDir, "src", "components", "views", "DashboardView.tsx"),
    "utf8"
  );
  assert.match(dash, /SystemTelemetryChart/);
  assert.match(dash, /SystemTelemetryModal/);

  const srv = fs.readFileSync(
    path.join(rootDir, "src", "components", "views", "ServicesView.tsx"),
    "utf8"
  );
  assert.match(srv, /SystemTelemetryModal/);
});

/**
 * Non-fatal failures must be visible.
 *
 * These tests exist because "the dashboard says 0 messages in the queue" was,
 * for a while, indistinguishable from "postqueue is broken". The fixes are small
 * (a deduped stderr line at each catch site) and small things get reverted by
 * accident, so they get a test.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readSource, rootDir } from "./_source.mjs";
import path from "node:path";
import fs from "node:fs";

const PYTHON = process.env.PYTHON || "python3";

test("core.warn exists, dedupes by context, and writes to stderr", () => {
  const script = `
import io, sys, contextlib
sys.path.insert(0, ${JSON.stringify(path.join(rootDir, "backend"))})
from mailstackctl.core import warn

first = io.StringIO()
second = io.StringIO()
with contextlib.redirect_stderr(first):
    warn("probe context", RuntimeError("boom"))
    warn("probe context", RuntimeError("boom"))
    warn("probe context", ValueError("different exception type"))
with contextlib.redirect_stderr(second):
    warn("probe context", RuntimeError("boom"))

lines = first.getvalue().strip().splitlines()
assert len(lines) == 2, f"expected 2 lines (one per exception type), got {len(lines)}: {lines}"
assert "probe context failed" in lines[0], lines[0]
assert "boom" in lines[0], lines[0]
assert second.getvalue() == "", f"second call must be deduped, got {second.getvalue()!r}"
`;
  execFileSync(PYTHON, ["-c", script], { stdio: "pipe" });
});

test("core.warn survives being handed a broken __str__", () => {
  const script = `
import io, sys, contextlib
sys.path.insert(0, ${JSON.stringify(path.join(rootDir, "backend"))})
from mailstackctl.core import warn

class Nasty(Exception):
    def __str__(self): raise RuntimeError("no")

buf = io.StringIO()
with contextlib.redirect_stderr(buf):
    warn("nasty context", Nasty())
assert "nasty context" in buf.getvalue(), buf.getvalue()
`;
  execFileSync(PYTHON, ["-c", script], { stdio: "pipe" });
});

test("no undocumented silent exception handlers remain in the helper", () => {
  // Two categories are allowed: `except Exception: pass` with an explanatory
  // comment on the line above, and closing/cleanup calls whose failure carries
  // no information. Everything else must route through warn().
  const dir = path.join(rootDir, "backend", "mailstackctl");
  const offenders = [];
  for (const name of fs.readdirSync(dir).filter((f) => f.endsWith(".py"))) {
    const lines = fs.readFileSync(path.join(dir, name), "utf8").split(/\r?\n/);
    lines.forEach((line, i) => {
      if (!/except\s+(Exception|BaseException)\s*(as\s+\w+)?\s*:\s*pass\b/.test(line)) return;
      // A bare `except X: pass` on its own line is only acceptable if the
      // preceding non-empty line explains why.
      let j = i - 1;
      while (j >= 0 && !lines[j].trim()) j -= 1;
      const excuse = j >= 0 ? lines[j].trim() : "";
      if (excuse.startsWith("#")) return;
      offenders.push(`${name}:${i + 1}: ${line.trim()}`);
    });
  }
  assert.deepEqual(offenders, [], `silent handlers without a justification comment:\n${offenders.join("\n")}`);
});

test("backend telemetry sampler reports failures instead of degrading to zero silently", () => {
  const source = readSource("backend", "server.production.ts");
  assert.match(source, /function warnOnce\(/, "warnOnce helper must exist");

  // Each of these used to be `catch {}` around a call whose failure made a
  // metric read a plausible-looking zero.
  for (const context of [
    "read /proc/meminfo",
    "scan /proc for mail daemons",
    "run postqueue -j",
    "parse a postqueue -j line",
    "collect queue metrics",
    "collect disk usage",
    "read build-manifest.json",
  ]) {
    assert.ok(
      source.includes(`warnOnce("${context}"`),
      `server.production.ts must report a failure to ${context}`,
    );
  }
});

test("webmail logs the cause behind its two generic 500s", () => {
  const source = readSource("webmail", "server.mjs");
  assert.match(source, /function warnOnce\(/, "warnOnce helper must exist");
  for (const handler of ["read mailbox listing", "read message"]) {
    assert.ok(
      source.includes(`warnOnce('${handler}', error)`),
      `webmail must log the cause of a ${handler} failure`,
    );
  }
  // The generic response must stay generic -- the browser must not learn
  // anything new from these errors.
  assert.match(source, /fail\(res, 500, 'READ_ERROR', 'Unable to read mailbox'\)/);
  assert.match(source, /fail\(res, 500, 'READ_ERROR', 'Unable to read message'\)/);
});

test("daemon detection matches whole process names, not substrings", () => {
  const source = readSource("backend", "server.production.ts");
  assert.ok(
    !/comm\.includes\(/.test(source),
    "daemon classification must not use substring matching: it matched unrelated processes",
  );
  assert.match(source, /COMM_TO_DAEMON: Record<string, string>/);

  // Process names the old substring matcher silently missed. Postfix runs most
  // of its pipeline under names that contain none of "master"/"smtpd"/"qmgr"/
  // "pickup"/"postfix", so reported memory covered a fraction of the stack.
  for (const comm of [
    "cleanup", "trivial-rewrite", "smtp", "local", "virtual", "pipe", "bounce",
    "proxymap", "tlsmgr", "scache", "showq", "flush", "postscreen",
    "imap-login", "pop3-login", "managesieve", "dsync", "doveadm",
  ]) {
    assert.match(
      source,
      new RegExp(`["']?${comm.replace("-", "\\-")}["']?: "\\w+"`),
      `COMM_TO_DAEMON must classify '${comm}'`,
    );
  }

  // Names too generic to attribute: matching them would over-report.
  for (const ambiguous of ['"config"', '"log"', '"stats"']) {
    assert.ok(
      !source.includes(`${ambiguous}:`),
      `${ambiguous} is too generic a process name to attribute to a mail daemon`,
    );
  }
});

test("the /proc walk is bounded instead of re-reading every process every 2s", () => {
  const source = readSource("backend", "server.production.ts");
  assert.match(source, /FULL_SCAN_EVERY_CYCLES/);
  assert.match(source, /private pidCache = new Map<number, string>\(\)/);
  // Stale entries must be pruned or the cache grows for the life of the process.
  assert.match(source, /for \(const pid of \[\.\.\.this\.pidCache\.keys\(\)\]\)/);
});

test("telemetry samplers never log more than once per context", () => {
  // A 2-second sampler that logs on every tick produces ~43k lines a day.
  const source = readSource("backend", "server.production.ts");
  assert.match(source, /const warnedOnce = new Set<string>\(\)/);
  assert.match(source, /if \(warnedOnce\.has\(key\)\) return;/);
  assert.match(source, /warnedOnce\.add\(key\)/);
});

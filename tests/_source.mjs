/**
 * Shared source readers for the static test suite.
 *
 * The privileged helper used to be one file, backend/mailstackctl.py. It is now a
 * package (backend/mailstackctl/) fronted by a thin shim. Tests that assert on
 * "does this symbol exist" must read both, or they go green while the behaviour
 * they are supposed to guard has quietly moved somewhere they never look.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

export const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const CTL_SHIM = path.join(rootDir, "backend", "mailstackctl.py");
export const CTL_PACKAGE_DIR = path.join(rootDir, "backend", "mailstackctl");

/**
 * Every Python source file that makes up the privileged helper, concatenated.
 * Read-only assertions should use this rather than the shim on its own.
 */
export function readMailstackctl() {
  if (!fs.existsSync(CTL_SHIM)) {
    throw new Error(`privileged helper entrypoint missing: ${CTL_SHIM}`);
  }
  let source = fs.readFileSync(CTL_SHIM, "utf8");
  if (fs.existsSync(CTL_PACKAGE_DIR)) {
    const modules = fs
      .readdirSync(CTL_PACKAGE_DIR)
      .filter((name) => name.endsWith(".py"))
      .sort();
    if (modules.length === 0) {
      throw new Error(`privileged helper package is empty: ${CTL_PACKAGE_DIR}`);
    }
    for (const name of modules) {
      source += `\n# ---- ${name} ----\n`;
      source += fs.readFileSync(path.join(CTL_PACKAGE_DIR, name), "utf8");
    }
  }
  return source;
}

/**
 * The interpreter the Python-side scripts run under.
 *
 * Debian and Ubuntu do not provide a bare `python` command, and relying on one
 * existing -- as CI's setup-python quietly arranges -- hides a failure that
 * then surfaces on a real machine. PYTHON wins when set, so a caller can pin
 * an interpreter explicitly.
 */
export const pythonBin =
  process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");


/** The version package.json declares. Tests compare against this, never a literal. */
export function readPackageVersion() {
  const version = JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf8")).version;
  if (typeof version !== "string" || !version.trim()) {
    throw new Error("package.json must declare a non-empty version");
  }
  return version.trim();
}

/** Read a repo-relative text file. */
export function readSource(...segments) {
  return fs.readFileSync(path.join(rootDir, ...segments), "utf8");
}

/**
 * Resolve a usable bash executable, or null when none is reachable.
 *
 * On Windows we prefer the WSL launcher (System32\bash.exe) and fall back to
 * whatever `bash` resolves to (Git-Bash, or System32 again via PATH). Callers
 * that cannot run without bash should skip with an explicit reason and record
 * it, then re-run under WSL.
 */
export function resolveBash() {
  const candidates =
    process.platform === "win32"
      ? [`${(process.env.SystemRoot || "C:\\Windows").replace(/\\/g, "/")}/System32/bash.exe`, "bash"]
      : ["bash"];
  for (const exe of candidates) {
    const probe = spawnSync(exe, ["-c", "echo ok"], { encoding: "utf8" });
    if (probe.status === 0 && /ok/.test(probe.stdout || "")) return exe;
  }
  return null;
}

/**
 * The repo root expressed in every path form a resolved bash might understand:
 * the raw POSIX-ish Windows form (e:/...), the WSL mount (/mnt/e/...) and the
 * Git-Bash mount (/e/...). A driver picks the first one that actually exists.
 */
export function repoPathCandidates() {
  const posix = rootDir.replace(/\\/g, "/");
  const cands = [posix];
  const m = /^([A-Za-z]):\/(.*)$/.exec(posix);
  if (m) {
    cands.push(`/mnt/${m[1].toLowerCase()}/${m[2]}`);
    cands.push(`/${m[1].toLowerCase()}/${m[2]}`);
  }
  return cands;
}

/**
 * A single-quoted, space-separated bash token list of repoPathCandidates(),
 * safe to interpolate straight into a driver script (paths carry no quote/$/
 * backtick). Used as: `for cand in ${bashRepoCandidates()}; do ...`.
 */
export function bashRepoCandidates() {
  return repoPathCandidates().map((p) => `'${p}'`).join(" ");
}

/**
 * Run a bash driver fed through STDIN (`bash -s`), never `bash -c <script>`.
 *
 * The WSL bash.exe launcher re-quotes the Windows command line and strips
 * single-quoted tokens inside a `-c` script, so quoted paths arrive empty.
 * stdin reaches Linux bash verbatim, which keeps the driver's quoting intact.
 */
export function runBashStdin(bashExe, driver, opts = {}) {
  return spawnSync(bashExe, ["-s"], {
    encoding: "utf8",
    input: driver,
    timeout: opts.timeout ?? 30000,
  });
}

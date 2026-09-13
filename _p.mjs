import { spawnSync } from "node:child_process";

const candidates =
  process.platform === "win32"
    ? [`${(process.env.SystemRoot || "C:\\Windows").replace(/\\/g, "/")}/System32/bash.exe`, "bash"]
    : ["bash"];
console.log("candidates=", candidates);
for (const exe of candidates) {
  const probe = spawnSync(exe, ["-c", "echo ok"], { encoding: "utf8" });
  console.log("exe=", exe, "status=", probe.status, "stdout=", JSON.stringify(probe.stdout), "err=", probe.error && probe.error.code);
  if (probe.status === 0 && /ok/.test(probe.stdout || "")) { console.log("PICKED", exe); break; }
}

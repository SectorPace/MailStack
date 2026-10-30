#!/usr/bin/env bash
# 只在本机生效的构建瘦身（不写入仓库的 Cargo.toml）：
# 关掉 dev/test profile 的调试信息与增量编译。9.8G 的根分区装不下带调试信息的
# 全量调试产物（deps 一度 4.5G）；关掉后同样的测试仍然全跑，只是产物小得多。
set -uo pipefail
echo "=== before ==="
df -h / | tail -1
for f in /var/log/syslog.1 /var/log/syslog /var/log/kern.log.1; do
  [ -f "$f" ] && truncate -s 0 "$f"
done
journalctl --vacuum-size=16M >/dev/null 2>&1
echo "--- 清理 target ---"
rm -rf /root/.cache/mailstack-target/debug/incremental
rm -rf /root/.cache/mailstack-target/debug/build
echo "=== after ==="
df -h / | tail -1
du -sh /root/.cache/mailstack-target 2>/dev/null

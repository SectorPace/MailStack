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

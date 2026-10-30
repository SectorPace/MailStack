#!/usr/bin/env bash
# 回收 WSL 根分区空间：先量，再做**可再生成**的清理，最后再量。
#
# 刻意不碰的东西：
#   * Docker 基础镜像 ubuntu:24.04 / rockylinux:9-ci / alpine:3.20（后续 install-matrix 要用）
#   * ~/.cache/mailstack-target 整体（那是编译缓存，删了要全量重建）
set -euo pipefail

echo "=== 清理前 ==="
df -h / | tail -1

echo
echo "=== 占用分布 ==="
for p in "$HOME/.cache/mailstack-target" "$HOME/.cargo" /var/lib/docker /var/lib/containerd /var/log /var/lib/apt /var/cache/apt; do
  if [ -e "$p" ]; then
    printf '  %-40s %s\n' "$p" "$(du -sh "$p" 2>/dev/null | cut -f1)"
  fi
done
echo "  --- target 内部 ---"
for p in "$HOME/.cache/mailstack-target/debug/incremental" "$HOME/.cache/mailstack-target/debug/deps" "$HOME/.cache/mailstack-target/debug/build"; do
  [ -e "$p" ] && printf '    %-38s %s\n' "$(basename "$p")" "$(du -sh "$p" 2>/dev/null | cut -f1)"
done

echo
echo "=== 1) apt 缓存 ==="
apt-get clean 2>/dev/null
rm -rf /var/lib/apt/lists/* 2>/dev/null
echo "  done"

echo
echo "=== 2) journald 日志（保留 50M） ==="
journalctl --vacuum-size=50M 2>&1 | tail -2

echo
echo "=== 3) Docker 未使用资源（保留基础镜像） ==="
if command -v docker >/dev/null 2>&1; then
  docker system prune -f 2>&1 | tail -3
  echo "  --- 现存镜像 ---"
  docker images --format '    {{.Repository}}:{{.Tag}} {{.Size}}' 2>/dev/null
else
  echo "  (无 docker)"
fi

echo
echo "=== 4) 增量编译缓存（可再生成） ==="
rm -rf "$HOME/.cache/mailstack-target/debug/incremental" 2>/dev/null
echo "  done"

echo
echo "=== 清理后 ==="
df -h / | tail -1

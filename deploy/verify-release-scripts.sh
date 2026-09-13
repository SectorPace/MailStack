#!/usr/bin/env bash
# 发布门禁：检测 shell 脚本中"被调用但从未定义"的函数。
# 背景：install.sh 曾在三处调用 warn() 但从未定义，set -e 下 caddy 降级场景
# 安装必崩，且连续两个 RC 都漏网。本脚本让这类 bug 在打包前失败。
# 用法: bash deploy/verify-release-scripts.sh [根目录]
set -Eeuo pipefail

ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
FAIL=0

# 常见辅助函数名单（跨脚本约定俗成的 helper 命名空间）
KNOWN_HELPERS='say die fail warn usage info note error red green yellow cyan need_root fetch_and_run'

scripts=(
  "$ROOT/mailstack.sh"
  "$ROOT/deploy/install.sh"
  "$ROOT/deploy/install-mail-stack.sh"
  "$ROOT/deploy/install-v05.sh"
  "$ROOT/deploy/verify-source-build.sh"
  "$ROOT/deploy/privacy-audit.sh"
  "$ROOT/deploy/mailstack-privileged"
)

for f in "${scripts[@]}"; do
  [[ -f "$f" ]] || continue
  # grep 无匹配返回 1，pipefail+set -e 会静默中止，故用 { ...|| true; } 兜底
  defined=$({ grep -hoE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)' "$f" || true; } | sed -E 's/^[[:space:]]*//;s/[[:space:]]*\(\)//' | sort -u)
  for helper in $KNOWN_HELPERS; do
    # 只统计"命令位置"的调用（行首或 ; & | 之后），并排除变量赋值（helper=...），
    # 避免嵌入的 Python/注释文本造成误报。
    calls=$(grep -nE "(^|[;&|])[[:space:]]*${helper}([[:space:]]|$)" "$f" | grep -vE "[[:space:]]${helper}[[:space:]]*=" || true)
    [[ -n "$calls" ]] || continue
    if ! grep -qx "$helper" <<<"$defined"; then
      echo "✗ $f: 调用了 ${helper}() 但该函数未在本文件中定义" >&2
      FAIL=1
    fi
  done
done

# 附加检查：dist/ 与发布树中不应再有未被任何安装器引用的可执行脚本
if [[ -x "$ROOT/deploy/mailstack-cli" ]]; then
  echo "✗ deploy/mailstack-cli 是死文件（无任何安装器引用），应从发布包移除" >&2
  FAIL=1
fi

if ((FAIL)); then
  echo '发布脚本检查未通过。' >&2
  exit 1
fi
echo '发布脚本检查通过：无未定义函数调用、无死文件。'

#!/usr/bin/env bash
# 校验构建与 CI 交付物的语法，避免把明显坏掉的配置推进仓库。
set -u
cd /mnt/e/MailStack/mailstack-rust || exit 1
FAIL=0

echo "=== Cargo.lock 是否存在（--locked 构建的前提） ==="
if [ -f Cargo.lock ]; then
  echo "OK   Cargo.lock ($(wc -l < Cargo.lock) 行)"
else
  echo "FAIL Cargo.lock 缺失"; FAIL=1
fi

echo
echo "=== CI YAML 语法 ==="
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY' || FAIL=1
import sys
try:
    import yaml
except ImportError:
    print("SKIP pyyaml 未安装")
    sys.exit(0)
for path in [".github/workflows/ci.yml"]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except Exception as exc:
        print(f"FAIL {path}: {exc}")
        sys.exit(1)
    jobs = doc.get("jobs", {})
    print(f"OK   {path} (jobs: {', '.join(jobs)})")
    for name, job in jobs.items():
        if not isinstance(job.get("steps"), list) or not job["steps"]:
            print(f"FAIL {name}: 缺少 steps")
            sys.exit(1)
PY
else
  echo "SKIP 无 python3"
fi

echo
echo "=== shell 脚本语法 ==="
for script in deploy/*.sh; do
  if bash -n "$script" 2>/dev/null; then
    echo "OK   $script"
  else
    echo "FAIL $script"; bash -n "$script"; FAIL=1
  fi
done

echo
echo "=== 版本一致性 ==="
V_FILE=$(tr -d '[:space:]' < VERSION)
V_CARGO=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
echo "VERSION=$V_FILE  Cargo.toml=$V_CARGO"
[ "$V_FILE" = "$V_CARGO" ] || { echo "FAIL 版本不一致"; FAIL=1; }

echo
[ "$FAIL" -eq 0 ] && echo "DELIVERABLES_OK" || echo "DELIVERABLES_FAIL"
exit "$FAIL"
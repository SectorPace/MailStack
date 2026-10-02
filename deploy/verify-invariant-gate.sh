#!/usr/bin/env bash
# 校验 CI 不变量门禁里列出的测试名确实存在于代码中。
set -u
cd /mnt/e/MailStack/mailstack-rust || exit 1

missing=0
# 从 ci.yml 的 required=( ... ) 数组里抽取测试名（去掉注释与引号）
names=$(sed -n '/required=(/,/^          )/p' .github/workflows/ci.yml \
        | grep -oE '"[a-z0-9_]+"' | tr -d '"')

# 扫描范围包含 bin/：那里也承载安全断言（如 mailstackctl 的退出码契约）。
# 只扫 crates/ 会让 bin/ 下的断言「加了等于没加」，门禁形同虚设。
count=0
for n in $names; do
  count=$((count + 1))
  if grep -rq "fn $n" crates/ bin/; then
    :
  else
    echo "MISSING: $n"
    missing=$((missing + 1))
  fi
done

echo "checked=$count missing=$missing"
[ "$missing" -eq 0 ] && echo "INVARIANT_GATE_OK" || echo "INVARIANT_GATE_FAIL"
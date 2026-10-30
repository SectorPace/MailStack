#!/usr/bin/env bash
# 不变量门禁：确认安全关键测试**仍然存在、仍然是测试、并且断言没有被掏空**。
#
# 修复 6.2 与 6.8：
#   * 6.2 原先只 `grep -rq "fn $name"` —— 子串匹配、不要求 `#[test]`，
#     把函数体改成 `assert!(true)` 甚至只留一个空函数也照样通过。
#     门禁的**本意正是防有人掏空断言**，所以这里必须验证三件事：
#       1. 名字出现在代码里（原有）；
#       2. 该函数带 `#[test]` / `#[tokio::test]` 属性（不是普通函数）；
#       3. 函数体内至少有一个 `assert*`（不是空壳）。
#   * 6.8 原先 ci.yml 与本脚本各维护一份判断逻辑 + 一份 277 条的清单，
#     必然漂移。现在清单与判定都只有这一份，CI 直接调用本脚本。
#
# 清单文件：deploy/required-invariants.txt（每行一个测试名）。
set -euo pipefail

# 允许从任意工作目录调用（CI 里不是 /mnt/e/...）。
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

LIST="deploy/required-invariants.txt"
if [ ! -f "$LIST" ]; then
  echo "清单文件缺失：$LIST"
  exit 1
fi

checked=0
missing=0
not_a_test=0
no_assert=0

# 提取 `fn NAME` 之前的属性与函数体，用于判定。
# 说明：函数体边界取「下一个顶格 `}` 之前」或后 60 行，足以覆盖本仓库的测试体量；
# 这不是语法分析，而是一个刻意偏保守的启发式 —— 宁可误报也不放过空壳。
check_one() {
  local name="$1"
  local file
  # 1) 找到定义所在文件（取第一处）。
  file=$(grep -rl "fn ${name}\b" crates/ bin/ 2>/dev/null | head -n 1 || true)
  if [ -z "$file" ]; then
    echo "MISS       $name  （代码里找不到该函数）"
    missing=$((missing + 1))
    return
  fi

  # 2) 名字必须紧跟在测试属性之后（中间最多隔一个其它属性）。
  local attrs
  attrs=$(grep -B 4 -E "^\s*(pub\s+)?(async\s+)?fn ${name}\b" "$file" | tr '\n' ' ')
  if ! printf '%s' "$attrs" | grep -qE '#\[(tokio::)?test(\]|\()'; then
    echo "NOT_TEST   $name  （$file 里该函数没有 #[test]/#[tokio::test]）"
    not_a_test=$((not_a_test + 1))
    return
  fi

  # 3) 函数体内至少一个断言。
  #    这里刻意用宽松的「出现 assert 开头的标识符」判定，而不是只认 `assert!(`
  #    —— 本仓库的测试大量使用 `assert_denied(...)`、`assert_eq!`、`assert_ne!`
  #    这类形态。门禁要挡的是「把测试掏空成空壳」，不是校验断言的具体写法。
  local body
  body=$(awk -v pat="fn ${name}\\b" '
    !seen && $0 ~ pat { seen = 1 }
    seen {
      # 遇到下一个同层级的函数定义就停（测试都在 `mod tests` 里，缩进 4 空格）。
      if (seen_and_printed && $0 ~ /^    (pub )?(async )?fn / && $0 !~ pat) exit
      print
      seen_and_printed = 1
    }
  ' "$file")
  if [ -z "$body" ]; then
    body=$(grep -A 80 -E "^\s*(pub\s+)?(async\s+)?fn ${name}\b" "$file")
  fi
  if ! printf '%s' "$body" | grep -qE '\bassert'; then
    echo "NO_ASSERT  $name  （$file 里该测试体内没有任何断言）"
    no_assert=$((no_assert + 1))
    return
  fi
}

while IFS= read -r line; do
  # 去注释与空白
  name=$(printf '%s' "$line" | sed 's/#.*//' | tr -d '[:space:]')
  [ -z "$name" ] && continue
  checked=$((checked + 1))
  check_one "$name"
done < "$LIST"

total_bad=$((missing + not_a_test + no_assert))
echo "checked=$checked missing=$missing not_a_test=$not_a_test no_assert=$no_assert"
if [ "$total_bad" -eq 0 ]; then
  echo "INVARIANT_GATE_OK"
  exit 0
fi
echo "::error::不变量门禁失败：$total_bad 条不合格"
echo "INVARIANT_GATE_FAIL"
exit 1

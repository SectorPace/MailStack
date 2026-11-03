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
# v1.0.0 加固（R7-004，外部审查发现四条真实绕过路径）：
#   a) **清空清单** → checked=0 → 旧脚本直接 OK。现在要求清单至少
#      `MIN_INVARIANTS` 条，低于下限即失败（防"删清单即通过"）。
#   b) **mawk 的 `\b`**：GNU awk 支持 `\b`，mawk（Ubuntu 默认）把它当退格，
#      `fn name\b` 匹配不到任何东西 → 函数体恒空 → 旧脚本回退 `grep -A 80`，
#      于是「函数体里没断言」可能被相邻测试的 assert 代偿。现在不用 `\b`：
#      名字边界用 `grep -E "fn NAME([^A-Za-z0-9_]|$)"` 与 awk 的字段切分。
#   c) **注释伪造**：`// #[test]` 或 `// assert!` 也能被 grep 命中。现在属性与
#      断言判定都先剔除纯注释行。
#   d) **空壳测试体**：函数体解析失败时**不再回退**到宽松的 `grep -A 80`
#      （那会把邻居的 assert 算进来），而是直接判 `NO_BODY` 失败。
#   另外：`#[ignore]` / `#[ignore = "..."]` 与 `#[cfg(any())]` 一律判失败 ——
#   这两者都能让测试"存在但永远不跑"。
#
# 清单文件：deploy/required-invariants.txt（每行一个测试名；`#` 开头为注释）。
set -euo pipefail

# 允许从任意工作目录调用（CI 里不是 /mnt/e/...）。
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

LIST="deploy/required-invariants.txt"
# 清单下限：只减不增的"清空式绕过"在这里被挡住。当前 v1.0.0 约 292 条。
# 下调此值必须同时说明原因（这是一条安全门禁，不是风格参数）。
MIN_INVARIANTS="${MIN_INVARIANTS:-250}"

if [ ! -f "$LIST" ]; then
  echo "清单文件缺失：$LIST"
  exit 1
fi

checked=0
missing=0
not_a_test=0
no_assert=0
ignored=0
commented_out=0

# 剔除纯注释行（`//`、`///`、`//!`），保留代码行。
strip_comments() {
  grep -vE '^[[:space:]]*//' || true
}

# 提取 `fn NAME` 的函数体（到**与函数同缩进**的收尾 `}` 或下一个同缩进 fn）。
#
# 关键：收尾括号的缩进必须取**函数自身的缩进**，不能写死 `^    }`。
# 集成测试（如 `crates/smtpd/tests/inbound.rs`）的测试函数在**顶层**（缩进 0），
# 但函数体内的 `for`/`if` 块收尾是 `    }` —— 写死四空格会把函数体截断在第一个
# 内层 for 循环处，于是 `assert!` 落在「函数体」之外，门禁误报 NO_ASSERT。
# 用 `index()` 精确匹配 `fn NAME` 并以非标识符结尾，兼容 mawk（不用 `\b`）。
extract_body() {
  local file="$1" name="$2"
  awk -v target="fn ${name}" '
    function is_target(line,    i) {
      i = index(line, target)
      if (i == 0) return 0
      if (i + length(target) > length(line)) return 1
      return substr(line, i + length(target), 1) !~ /[A-Za-z0-9_]/
    }
    !seen {
      if (is_target($0)) {
        seen = 1
        # 函数缩进 = 行首空格数（awk 的 RLENGTH 才是匹配长度；RSTART 恒为 1）。
        # 收尾 `}` 必须正好在这个缩进上。
        match($0, /^ */)
        indent = RLENGTH
        print
        next
      }
      next
    }
    seen {
      # 同缩进的 `}`：函数收尾。
      if (substr($0, 1, indent) ~ /^ *$/ && substr($0, indent + 1) == "}") {
        print
        exit
      }
      # 同缩进的下一个函数定义：上一个函数没有正常收尾（也停止，避免吞下一个测试）。
      if (substr($0, 1, indent) ~ /^ *$/ && substr($0, indent + 1) ~ /^(pub )?(async )?fn /) {
        exit
      }
      print
    }
  ' "$file"
}

check_one() {
  local name="$1"
  local file
  # 1) 找到定义所在文件（名字必须是完整标识符，不是 `foo_<name>_bar` 的子串）。
  file=$(grep -rlE "fn[[:space:]]+${name}([^A-Za-z0-9_]|$)" crates/ bin/ 2>/dev/null | head -n 1 || true)
  if [ -z "$file" ]; then
    echo "MISS       $name  （代码里找不到该函数）"
    missing=$((missing + 1))
    return
  fi

  # 2) 名字必须紧跟在测试属性之后（中间最多隔 3 行其它属性），且属性行不是注释。
  local attrs
  attrs=$(grep -B 4 -E "^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+${name}([^A-Za-z0-9_]|$)" "$file" \
    | strip_comments | tr '\n' ' ')
  if ! printf '%s' "$attrs" | grep -qE '#\[(tokio::)?test(\]|\()'; then
    echo "NOT_TEST   $name  （$file 里该函数没有 #[test]/#[tokio::test]）"
    not_a_test=$((not_a_test + 1))
    return
  fi
  if printf '%s' "$attrs" | grep -qE '#\[ignore'; then
    echo "IGNORED    $name  （$file 里该测试被 #[ignore] 标记：存在但永远不跑）"
    ignored=$((ignored + 1))
    return
  fi
  if printf '%s' "$attrs" | grep -qE '#\[cfg\(any\(\)\)\]'; then
    echo "DEAD       $name  （$file 里该测试被 #[cfg(any())] 编译期剔除）"
    commented_out=$((commented_out + 1))
    return
  fi

  # 3) 解析函数体：解析不出来就是失败，不再宽松回退到 `grep -A 80`。
  local body
  body=$(extract_body "$file" "$name")
  if [ -z "$body" ]; then
    echo "NO_BODY    $name  （$file 里无法解析函数体）"
    no_assert=$((no_assert + 1))
    return
  fi
  # 4) 函数体内至少一个断言（剔除纯注释行后再判，防 `// assert` 伪造）。
  if ! printf '%s\n' "$body" | strip_comments | grep -qE '\bassert'; then
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

total_bad=$((missing + not_a_test + no_assert + ignored + commented_out))
echo "checked=$checked missing=$missing not_a_test=$not_a_test no_assert=$no_assert ignored=$ignored dead=$commented_out"

if [ "$checked" -lt "$MIN_INVARIANTS" ]; then
  echo "::error::不变量清单只有 $checked 条，低于下限 $MIN_INVARIANTS —— 清单被删减或路径不对"
  echo "INVARIANT_GATE_FAIL"
  exit 1
fi
if [ "$total_bad" -eq 0 ]; then
  echo "INVARIANT_GATE_OK"
  exit 0
fi
echo "::error::不变量门禁失败：$total_bad 条不合格"
echo "INVARIANT_GATE_FAIL"
exit 1

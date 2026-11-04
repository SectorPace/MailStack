set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

LIST="deploy/required-invariants.txt"
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

strip_comments() {
  grep -vE '^[[:space:]]*//' || true
}

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
        match($0, /^ */)
        indent = RLENGTH
        print
        next
      }
      next
    }
    seen {
      if (substr($0, 1, indent) ~ /^ *$/ && substr($0, indent + 1) == "}") {
        print
        exit
      }
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
  file=$(grep -rlE "fn[[:space:]]+${name}([^A-Za-z0-9_]|$)" crates/ bin/ 2>/dev/null | head -n 1 || true)
  if [ -z "$file" ]; then
    echo "MISS       $name  （代码里找不到该函数）"
    missing=$((missing + 1))
    return
  fi

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

  local body
  body=$(extract_body "$file" "$name")
  if [ -z "$body" ]; then
    echo "NO_BODY    $name  （$file 里无法解析函数体）"
    no_assert=$((no_assert + 1))
    return
  fi
  if ! printf '%s\n' "$body" | strip_comments | grep -qE '\bassert'; then
    echo "NO_ASSERT  $name  （$file 里该测试体内没有任何断言）"
    no_assert=$((no_assert + 1))
    return
  fi
}

while IFS= read -r line; do
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

#!/usr/bin/env bash
# 完整质量门禁：格式 + lint（warnings 即错误）+ 测试。
# 与 CI 使用同一条命令链，确保本地与 CI 判定一致。
set -u

cd /mnt/e/MailStack/mailstack-rust || exit 1
export PATH="$HOME/.cargo/bin:$PATH"

RUNNER="bash deploy/wsl-cargo.sh"
FAILED=0

echo "================ 1/3 rustfmt ================"
if $RUNNER fmt --all -- --check; then
  echo "rustfmt: PASS"
else
  echo "rustfmt: FAIL" >&2
  FAILED=1
fi

echo
echo "================ 2/3 clippy (-D warnings) ================"
if $RUNNER clippy --all-targets -- -D warnings; then
  echo "clippy: PASS"
else
  echo "clippy: FAIL" >&2
  FAILED=1
fi

echo
echo "================ 3/3 cargo test ================"
if $RUNNER test; then
  echo "test: PASS"
else
  echo "test: FAIL" >&2
  FAILED=1
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "QUALITY_GATE=PASS"
else
  echo "QUALITY_GATE=FAIL"
fi
exit "$FAILED"
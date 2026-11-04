set -euo pipefail
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HTTP_PROXY="${MAILSTACK_PROXY:-http://127.0.0.1:7890}"
export HTTPS_PROXY="$HTTP_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTP_PROXY"

for attempt in 1 2 3 4 5; do
  echo "=== attempt $attempt ==="
  if rustup component add rustfmt clippy 2>&1 | tail -5; then
    if cargo fmt --version >/dev/null 2>&1 && cargo clippy --version >/dev/null 2>&1; then
      echo "COMPONENTS_OK"
      cargo fmt --version
      cargo clippy --version
      exit 0
    fi
  fi
  echo "attempt $attempt 未成功，重试..."
  sleep 3
done

echo "COMPONENTS_FAILED"
exit 1

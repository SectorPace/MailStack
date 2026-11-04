set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="$HOME/.cargo/bin:$PATH"
TEST_TARGET="postfix_integration"
IMAGE="${MAILSTACK_TEST_IMAGE:-ubuntu:24.04}"
PROXY_PORT="${CLASH_PROXY_PORT:-7890}"
PROXY="http://127.0.0.1:${PROXY_PORT}"

step() { printf '\n=== %s ===\n' "$1"; }
die()  { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

step "0/5 前置检查"
command -v docker >/dev/null || die "未找到 docker"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "镜像 $IMAGE 不存在；请先 docker pull $IMAGE"
command -v python3 >/dev/null || die "需要 python3 解析 cargo 的 JSON 输出"

step "1/5 构建集成测试二进制"
BUILD_JSON="$(cargo test -p mailstack-smtp --test "$TEST_TARGET" --no-run --message-format=json 2>/dev/null || true)"
[ -n "$BUILD_JSON" ] || die "cargo 构建失败（没有 JSON 输出）"

BIN="$(printf '%s\n' "$BUILD_JSON" | python3 -c '
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    exe = msg.get("executable")
    name = (msg.get("target") or {}).get("name", "")
    if exe and name == "postfix_integration":
        print(exe)
        break
')"

[ -n "$BIN" ] || die "未能定位测试二进制"
[ -x "$BIN" ] || die "测试二进制不可执行: $BIN"
echo "二进制: $BIN ($(stat -c%s "$BIN") 字节)"

step "2/5 在容器中安装 Postfix（经 $PROXY）"
echo "镜像: $IMAGE"

step "3/5 运行真实集成测试"
set +e
docker run --rm --network host \
  -v "$BIN:/testbin:ro" \
  -e "http_proxy=$PROXY" -e "https_proxy=$PROXY" \
  -e "HTTP_PROXY=$PROXY" -e "HTTPS_PROXY=$PROXY" \
  -e "DEBIAN_FRONTEND=noninteractive" \
  -e "MAILSTACK_REQUIRE_POSTFIX=1" \
  -e "MAILSTACK_POSTFIX_INTEGRATION=1" \
  "$IMAGE" bash -c '
set -e
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

if command -v debconf-set-selections >/dev/null 2>&1; then
  echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
  echo "postfix postfix/mailname string mailstack.test" | debconf-set-selections
fi

apt-get update -qq
apt-get install -y -qq postfix >/dev/null

echo "--- 版本 ---"
postconf -d mail_version 2>/dev/null || true

postfix start 2>&1 || echo "(postfix start 未成功，reload 路径将如实报错)"

echo "--- 运行测试 ---"
/testbin --nocapture --test-threads=1
'
RC=$?
set -e

step "4/5 结果"
if [ "$RC" -eq 0 ]; then
  echo "POSTFIX_INTEGRATION=PASS"
else
  echo "POSTFIX_INTEGRATION=FAIL (rc=$RC)" >&2
fi

step "5/5 清理"
docker ps -aq --filter "ancestor=$IMAGE" | head -5 >/dev/null 2>&1 || true
echo "容器使用 --rm，已自动清理"

exit "$RC"

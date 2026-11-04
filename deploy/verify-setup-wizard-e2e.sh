set -uo pipefail

ROOT="${ROOT:-/root/mailstack-wizard}"
BIN="${BIN:-/root/.cache/mailstack-target/debug/mailstackd}"
CTL="${CTL:-/root/.cache/mailstack-target/debug/mailstackctl}"
DOMAIN="${DOMAIN:-example.com}"
ACCOUNT="admin"
GOOD_PASS="${GOOD_PASS:-Zx7Qm2Vt9Kp4}"
BAD_PASS="admin1234"

say() { printf '\n=== %s ===\n' "$1"; }
rpc() { "$CTL" "$1" "$2" --config-dir "$ROOT" 2>&1; }

say "0. 前置条件"
for f in "$BIN" "$CTL"; do
  [ -x "$f" ] || { echo "  **缺失**: $f"; exit 1; }
done
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ':25[[:space:]]'; then
  echo "  **25 端口已被占用**（可能装着 Postfix）。请先停它。"; exit 1
fi
echo "  25 空闲；磁盘: $(df -h / | tail -1 | awk '{print $4}') 可用"

WRAPPER="${WRAPPER:-/usr/local/libexec/mailstack-privileged}"
RW_OK=0
if [ ! -r "$WRAPPER" ]; then
  echo "  RW 通道：包装器 $WRAPPER 不可读"
elif grep -qE 'mailstack-privileged-helper|mailstackctl-helper|bin/mailstackctl|/mailstackctl"' "$WRAPPER" 2>/dev/null; then
  RW_OK=1
  echo "  RW 通道：包装器指向本仓库的助手，可用"
else
  echo "  **RW 通道不可用**：$WRAPPER 指向的是旧 Python 助手"
  echo "     （/opt/mailstack/backend/mailstackctl.py 仍存在，但它不认识本项目的动作名，"
  echo "     对任何 RW 动作都 exit 1 —— 于是表现为 PRIVILEGED_OPERATION_FAILED）"
  echo "     这不是本仓库的缺陷，恰恰说明 RW 动作确实无法绕过包装器。"
  echo "     已验证到的部分：fail-closed 装配、监听、RO 动作、SIGTERM 停机。"
  echo "     未验证：setup.mail.test 的四步校验与入队（全部经包装器下发）。"
  echo "     要跑完整链路：先把包装器换成指向本仓库的 mailstackctl。"
fi

say "1. 生成夹具（fail-closed 启动所需）"
case "$ROOT" in
  ""|"/"|"/root"|"/home"|"/usr"|"/etc"|"/var"|"/opt"|"/srv"|"/tmp"|"/mnt"|"/boot"|"/bin"|"/sbin"|"/lib"|"/lib64"|"/dev"|"/proc"|"/sys"|"/run")
    echo "  **ROOT 非法（'$ROOT'），拒绝 rm -rf**" >&2; exit 1 ;;
esac
[ -f "$ROOT/Cargo.toml" ] || { echo "  **ROOT 不是 MailStack 仓库根（缺 Cargo.toml）：'$ROOT'，拒绝 rm -rf**" >&2; exit 1; }
rm -rf "$ROOT"
mkdir -p "$ROOT/etc/mailstack" "$ROOT/etc/postfix" "$ROOT/var/lib/mailstack/queue" "$ROOT/etc/mailstack/tls/$DOMAIN"
printf '%s OK\n' "$DOMAIN" > "$ROOT/etc/postfix/mailstack_domains"
: > "$ROOT/etc/postfix/mailstack_aliases"
cat > "$ROOT/etc/mailstack/setup.json" <<JSON
{ "domain": "$DOMAIN", "mailHost": "mail.$DOMAIN", "serverIp": "192.0.2.10",
  "dkimSelector": "mail", "expectedSpf": "v=spf1 mx -all",
  "updatedAt": "2026-10-03T00:00:00+00:00" }
JSON
chmod 0600 "$ROOT/etc/mailstack/setup.json"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$ROOT/etc/mailstack/tls/$DOMAIN/privkey.pem" \
  -out  "$ROOT/etc/mailstack/tls/$DOMAIN/fullchain.pem" \
  -days 30 -subj "/CN=mail.$DOMAIN" -addext "subjectAltName=DNS:mail.$DOMAIN" \
  1>/dev/null
chmod 0600 "$ROOT/etc/mailstack/tls/$DOMAIN/privkey.pem"
[ -s "$ROOT/etc/mailstack/tls/$DOMAIN/fullchain.pem" ] \
  || { echo "  **openssl 未生成证书**（上面应有它的错误输出）"; exit 1; }
echo "  夹具就绪"

say "2. 启动 mailstackd（setup.mail.test 要经 127.0.0.1:25 提交）"
"$BIN" --port 25 --port 587 --config-dir "$ROOT" --log info > "$ROOT/daemon.log" 2>&1 &
DAEMON_PID=$!
cleanup() {
  if kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$DAEMON_PID" 2>/dev/null
  fi
}
trap cleanup EXIT
for _ in $(seq 1 40); do
  grep -q "服务已就绪" "$ROOT/daemon.log" 2>/dev/null && break
  kill -0 "$DAEMON_PID" 2>/dev/null || break
  sleep 0.25
done
kill -0 "$DAEMON_PID" 2>/dev/null || { echo "  **启动失败**"; cat "$ROOT/daemon.log"; exit 1; }
echo "  已就绪：$(grep -o '服务已就绪' "$ROOT/daemon.log" | head -1)"

say "3. 先证明「受管邮箱表是空的」—— 此时发信必然失败"
if [ "$RW_OK" -eq 0 ]; then
  echo "  跳过：RW 通道不可用（见步骤 0）。这一步需要经包装器下发。"
else
  OUT=$(rpc setup.mail.test "{\"sender\":\"$ACCOUNT@$DOMAIN\",\"recipient\":\"$ACCOUNT@$DOMAIN\",\"username\":\"$ACCOUNT\",\"password\":\"$GOOD_PASS\"}")
  echo "  响应：$(echo "$OUT" | head -3 | tr '\n' ' ')"
  case "$OUT" in
    *"managed mailbox"*) echo "  => 符合预期：未建号时被拒（受管邮箱表为空）" ;;
    *) echo "  => **注意**：未建号竟然通过了，说明受管邮箱表不是空的" ;;
  esac
fi

say "4. 第 1 步：domains.add（identity.apply 不写域名表，users.add 要求域名在表里）"
OUT=$(rpc domains.add "{\"domain\":\"$DOMAIN\"}")
echo "  响应：$(echo "$OUT" | head -3 | tr '\n' ' ')"

if [ "$RW_OK" -eq 0 ]; then
  say "5-9. RW 步骤（建号 / 幂等 / 发信 / 入队）"
  echo "  **全部跳过**：RW 通道不可用（见步骤 0）。"
  echo "  已验证到的部分：fail-closed 装配、监听、RO 动作（domains.add）、SIGTERM 停机。"
  echo "  未验证：setup.mail.test 的四步校验与入队 —— 它们全部经包装器下发。"
else

say "5. 反例：先用**不合格口令**建号（应被拒，证明校验真的在生效）"
OUT=$(rpc users.add "{\"address\":\"$ACCOUNT@$DOMAIN\",\"username\":\"$ACCOUNT\",\"password\":\"$BAD_PASS\"}")
echo "  响应：$(echo "$OUT" | head -3 | tr '\n' ' ')"
case "$OUT" in
  *"password must not contain"*) echo "  => 符合预期：口令上下文校验拒绝了它" ;;
  *) echo "  => 注意：不合格口令竟然被接受了" ;;
esac

say "6. 第 5 步 ①：users.add 用合格口令建号"
OUT=$(rpc users.add "{\"address\":\"$ACCOUNT@$DOMAIN\",\"username\":\"$ACCOUNT\",\"password\":\"$GOOD_PASS\"}")
echo "  响应类型：$(echo "$OUT" | head -1)"
FIRST=$(echo "$OUT" | head -1)
case "$FIRST" in
  \[*) echo "  => 是裸数组（与 Users::list 的返回一致）" ;;
  *)   echo "  => **注意**：不是裸数组，实际是 ${FIRST:0:60}" ;;
esac
echo "  受管邮箱表：$(cat "$ROOT/etc/mailstack/managed-users.json" 2>/dev/null | tr -d '\n ' )"

say "7. 幂等：重复建号应回「已存在」，向导据此放行"
OUT=$(rpc users.add "{\"address\":\"$ACCOUNT@$DOMAIN\",\"username\":\"$ACCOUNT\",\"password\":\"$GOOD_PASS\"}")
echo "  响应：$(echo "$OUT" | head -2 | tr '\n' ' ')"
case "$OUT" in
  *"already exists"*) echo "  => 符合预期：向导会把它当成功继续发信" ;;
  *) echo "  => 注意：重复建号没有回「already exists」" ;;
esac

say "8. 第 5 步 ②：setup.mail.test（这次应通过并真的入队）"
OUT=$(rpc setup.mail.test "{\"sender\":\"$ACCOUNT@$DOMAIN\",\"recipient\":\"$ACCOUNT@$DOMAIN\",\"username\":\"$ACCOUNT\",\"password\":\"$GOOD_PASS\"}")
echo "  响应：$(echo "$OUT" | head -5 | tr '\n' ' ')"

say "9. 队列落盘（真正的证据）"
ENTRIES=$(find "$ROOT/var/lib/mailstack/queue/entries" -type f -name '*.json' 2>/dev/null | wc -l)
echo "  邮件条目数：$ENTRIES"
if [ "$ENTRIES" -gt 0 ]; then
  echo "  => **向导第 5 步在真实后端上完整走通**：建号 → 发信 → 入队"
  F=$(find "$ROOT/var/lib/mailstack/queue/entries" -type f -name '*.json' | head -1)
  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
for k in ('id','kind','recipients','attempts'):
    if k in d: print(f'    {k} = {d[k]}')
" "$F" 2>/dev/null
else
  echo "  => 队列为空：发信未真正入队"
fi

fi # RW_OK

say "10. 停机"
cleanup; trap - EXIT
echo "  已停"

say "结论"
echo "  这条链路在真实后端上的三个前置条件是："
echo "    ① 域名在受管域名表里（domains.add 写，identity.apply **不写**）"
echo "    ② 邮箱在受管邮箱表里（**只有 users.add 会写**）"
echo "    ③ 口令不含 admin/完整邮箱、不连续重复（后端会拒）"
echo "  前端向导现在按 ①→②→③ 顺序串行执行，并把后端原文错误透传给用户。"
echo
echo "  另：写动作全部经 sudo 包装器下发，因此**真实部署必须先把"
echo "  /usr/local/libexec/mailstack-privileged 指向本仓库的 mailstackctl**。"
echo "  本机那个仍指向重写前的 Python 助手（文件还在，但它不认识本项目的动作名），"
echo "  故 RW 步骤被跳过 —— 换成新包装器后重跑本脚本即可覆盖完整链路。"

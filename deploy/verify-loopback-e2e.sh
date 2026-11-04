set -uo pipefail

ROOT="${ROOT:-/root/mailstack-loopback}"
BIN="${BIN:-/root/.cache/mailstack-target/debug/mailstackd}"
CTL="${CTL:-/root/.cache/mailstack-target/debug/mailstackctl}"
PORT_SMTP=25
PORT_SUB=587
DOMAIN="${DOMAIN:-example.com}"
MAIL_HOST="mail.$DOMAIN"

say() { printf '\n=== %s ===\n' "$1"; }

say "0. 前置条件"
for f in "$BIN" "$CTL"; do
  if [ -x "$f" ]; then echo "  可执行: $f"; else echo "  **缺失**: $f（先跑 deploy/wsl-cargo.sh build -p mailstackd -p mailstackctl）"; exit 1; fi
done
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ':25[[:space:]]'; then
  echo "  **25 端口已被占用** —— 本机可能装着 Postfix。请先停它，否则 mailstackd 起不来，"
  echo "     且失败原因会被误报成代码问题。"
  exit 1
fi
echo "  25 空闲"
echo "  磁盘: $(df -h / | tail -1 | awk '{print $4" 可用"}')"

say "1. 生成 fail-closed 夹具（字段判据见 crates/core/src/config.rs 与 smtpd/src/tls.rs）"
case "$ROOT" in
  ""|"/"|"/root"|"/home"|"/usr"|"/etc"|"/var"|"/opt"|"/srv"|"/tmp"|"/mnt"|"/boot"|"/bin"|"/sbin"|"/lib"|"/lib64"|"/dev"|"/proc"|"/sys"|"/run")
    echo "  **ROOT 非法（'$ROOT'），拒绝 rm -rf**" >&2; exit 1 ;;
esac
[ -f "$ROOT/Cargo.toml" ] || { echo "  **ROOT 不是 MailStack 仓库根（缺 Cargo.toml）：'$ROOT'，拒绝 rm -rf**" >&2; exit 1; }
rm -rf "$ROOT"
mkdir -p "$ROOT/etc/mailstack" "$ROOT/etc/postfix" "$ROOT/var/lib/mailstack/queue" "$ROOT/etc/opendkim/keys" "$ROOT/etc/mailstack/tls/$DOMAIN"

printf '%s OK\n' "$DOMAIN" > "$ROOT/etc/postfix/mailstack_domains"
: > "$ROOT/etc/postfix/mailstack_aliases"

cat > "$ROOT/etc/mailstack/setup.json" <<JSON
{
  "domain": "$DOMAIN",
  "mailHost": "$MAIL_HOST",
  "serverIp": "192.0.2.10",
  "dkimSelector": "mail",
  "expectedSpf": "v=spf1 mx -all",
  "updatedAt": "2026-10-03T00:00:00+00:00"
}
JSON
chmod 0600 "$ROOT/etc/mailstack/setup.json"

cat > "$ROOT/etc/mailstack/settings.json" <<JSON
{ "serverName": "$MAIL_HOST", "hostname": "mx1.$DOMAIN", "adminEmail": "postmaster@$DOMAIN" }
JSON

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$ROOT/etc/mailstack/tls/$DOMAIN/privkey.pem" \
  -out "$ROOT/etc/mailstack/tls/$DOMAIN/fullchain.pem" \
  -days 30 -subj "/CN=$MAIL_HOST" \
  -addext "subjectAltName=DNS:$MAIL_HOST" 1>/dev/null
chmod 0600 "$ROOT/etc/mailstack/tls/$DOMAIN/privkey.pem"
[ -s "$ROOT/etc/mailstack/tls/$DOMAIN/fullchain.pem" ] \
  || { echo "  **openssl 未生成证书**（上面应有它的错误输出）"; exit 1; }
echo "  夹具就绪：$(find "$ROOT" -type f | wc -l) 个文件"

say "2. 启动 mailstackd（监听 $PORT_SMTP / $PORT_SUB），日志见 $ROOT/daemon.log"
"$BIN" --port "$PORT_SMTP" --port "$PORT_SUB" --config-dir "$ROOT" --log info \
  > "$ROOT/daemon.log" 2>&1 &
DAEMON_PID=$!
cleanup() {
  if kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$DAEMON_PID" 2>/dev/null
    echo "  已停 mailstackd（pid $DAEMON_PID）"
  fi
}
trap cleanup EXIT

for i in $(seq 1 40); do
  grep -q "listening\|started\|启动" "$ROOT/daemon.log" 2>/dev/null && break
  kill -0 "$DAEMON_PID" 2>/dev/null || break
  sleep 0.25
done

if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
  echo "  **启动失败**，daemon.log："; cat "$ROOT/daemon.log"; exit 1
fi
echo "  进程存活 (pid $DAEMON_PID)"
sed 's/^/  | /' "$ROOT/daemon.log" | head -20
LOG_BASE=$(wc -l < "$ROOT/daemon.log")

say "3. 真实 SMTP 握手：EHLO → MAIL FROM → RCPT TO → DATA（收件方是受管域名）"
python3 - "$PORT_SMTP" "$DOMAIN" <<'PY'
import socket, sys
port, domain = int(sys.argv[1]), sys.argv[2]
try:
    s = socket.create_connection(('127.0.0.1', port), timeout=15)
    # 客户端超时要**大于**服务端的 data_timeout（默认 600 秒，connection.rs:49），
    # 否则会看到「发完正文就超时、服务端日志一行没有」的现象 ——
    # 那其实是服务端还在正常等待，是我们先放弃了。反过来看：症状与「服务端卡住」
    # 完全一样，唯一的区别就是这个值。所以这里留足余量。
    s.settimeout(90)
    # **关键**：`makefile()` 只能建一次并复用。
    # 每读一行都新建 makefile 会各自带一层读缓冲 —— 第一次调用就把 socket 里的
    # 后续字节读进了自己的缓冲，那些字节随对象一起被丢掉，于是表现为「发完命令就超时」。
    # 这个坑很隐蔽：连接与问候语都正常，只有第一次读命令应答时才暴露。
    rf = s.makefile('rb')
    def read_reply():
        """读一条 SMTP 应答：多行以 'nnn-' 续行，末行 'nnn ' 结束。"""
        lines = []
        while True:
            raw = rf.readline()
            if not raw:
                break
            line = raw.decode('utf-8', 'replace').rstrip('\r\n')
            lines.append(line)
            if len(line) < 4 or line[3] != '-':
                break
        return lines
    def cmd(text):
        s.sendall(text.encode() + b'\r\n')   # 必须是 CRLF：裸 LF 会被判为协议走私
        return read_reply()

    print("  S:", read_reply())
    for text in [
        "EHLO prober.example.net",
        "MAIL FROM:<probe@prober.example.net>",
        f"RCPT TO:<postmaster@{domain}>",
    ]:
        r = cmd(text)
        print(f"  C: {text}")
        print("  S:", r)
        # 收件人被拒就直接收尾：继续发 DATA 只会被服务端当成协议错，
        # 拿到的结论反而会掩盖「是谁拒的」。
        if r and r[-1][:1] in ('4', '5') and text.startswith('RCPT'):
            print(f"  => 收件人被拒：{r[-1]}")
            s.sendall(b'QUIT\r\n'); rf.readline(); s.close()
            sys.exit(0)
    print("  => 收件人已被接受（250）")
    r = cmd("DATA")
    print("  C: DATA"); print("  S:", r)
    if r and r[-1].startswith('354'):
        # 正文末尾**不要**自己加 CRLF：结束序列本身就是 `CRLF . CRLF`。
        #
        # 本文件用 heredoc（<<'PY'，引号版）把 Python 源码交给解释器，内容不经
        # shell 预处理，所以源码里的 "\r\n" 就是真正的回车换行。若写成 "\\r\\n"，
        # 发出的是**字面反斜杠+r+反斜杠+n** 四个字符 —— 服务端匹配不到结束标记，
        # DataSink 一直返回 NeedMore 并**静默**等待（connection.rs:342），
        # 客户端表现为超时，且服务端日志一行都没有。这类错误只能靠回显字节发现。
        lines = [
            f"From: probe@prober.example.net",
            f"To: postmaster@{domain}",
            "Subject: mailstack loopback e2e",
            "",
            "real end-to-end probe",
        ]
        # 逐行发，每行都以 CRLF 结束；点行单独发。
        # 分开发而不是一次性 sendall，是为了让「服务器读到哪一行出问题」可定位。
        for ln in lines:
            s.sendall(ln.encode() + b"\r\n")
        wire = b".\r\n"
        s.sendall(wire)
        print(f"  C: 正文 {len(lines)} 行 + 结束序列 {wire!r}")
        r = read_reply()
        print("  S:", r)
        accepted = bool(r) and r[-1].startswith('250')
        print(f"  => 投递请求{'已接受（250）' if accepted else '被拒绝'}")
    s.sendall(b'QUIT\r\n'); rf.readline(); s.close()
except Exception as e:
    print("  **握手失败**:", repr(e))
    sys.exit(1)
PY

say "4. 队列状态（真实落盘：这封信应由 sink 入队，这是环路闭合的证据）"
echo "  服务端在 DATA 阶段的判断（daemon.log 新增行）："
tail -n +"$((LOG_BASE + 1))" "$ROOT/daemon.log" | sed 's/^/  | /' || true
ENTRIES=$(find "$ROOT/var/lib/mailstack/queue/entries" -type f -name '*.json' 2>/dev/null | wc -l)
echo "  队列根内容：$(ls "$ROOT/var/lib/mailstack/queue" 2>/dev/null | tr '\n' ' ')"
echo "  邮件条目数（queue/entries/*.json）: $ENTRIES"
if [ "$ENTRIES" -gt 0 ]; then
  echo "  => **入队成功**：sink 接收并落盘了投递请求"
  find "$ROOT/var/lib/mailstack/queue/entries" -type f -name '*.json' | head -3 | while read -r f; do
    echo "  | $(basename "$f")"
  done
  FIRST=$(find "$ROOT/var/lib/mailstack/queue/entries" -type f -name '*.json' | head -1)
  echo "  首条目摘要："
  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
for k in ('id','kind','mail_from','recipients','created_at','attempts'):
    if k in d: print(f'    {k} = {d[k]}')
" "$FIRST" 2>/dev/null | sed 's/^/  /'
else
  echo "  => 队列为空（收信被接受但未入队，或 DATA 未完成）"
fi

say "5. 特权 RPC 双通道（RO/RW unix socket，由 mailstackd 建立）"
ls -l "$ROOT/run/mailstack/"*.sock 2>/dev/null || echo "  （无 socket —— 见下方说明）"
say "5b. mailstackctl 走 RO socket 取只读动作"
"$CTL" snapshot --config-dir "$ROOT" 2>&1 | head -20 || true

say "6. 停机（SIGTERM 扇出）"
cleanup
trap - EXIT
echo "  daemon.log 尾部："; tail -6 "$ROOT/daemon.log" | sed 's/^/  | /'

say "完成"
echo "夹具保留在 $ROOT 供复查。"

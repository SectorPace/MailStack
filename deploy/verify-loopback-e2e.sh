#!/usr/bin/env bash
# 真实环路验证：一条命令完成「建夹具 → 起 mailstackd → 验证 → 停机 → 报告」。
#
# ## 为什么必须是一条命令（这是本轮最大的教训）
#
# WSL 的 `/tmp` **在每次 `wsl` 命令启动时被清理** —— 实测：建标记文件后，下一条
# 独立的 wsl 命令读同一路径已是 No such file or directory。因此
# 「生成夹具」与「使用夹具」分成两条命令的做法**必然失败**。
#
# 此前连续三轮的失败看起来互不相关（启动失败 → 文件不见了 → 还是启动失败），
# 根因却是同一个。教训：**跨 wsl 命令的临时状态必须落持久目录**（这里用
# /root/mailstack-loopback），或者干脆让生成与消费在同一条命令内完成。
#
# ## 为什么这个验证只在「回环 + 受管域名」范围内
#
# `mail.test_loopback` 的提交端点是**硬编码常量** `127.0.0.1:25`（接受请求体里的
# 主机等于开一个任意发信器）。所以：需要 mailstackd 监听 25，而本机 25 端口必须
# 空闲（装了 Postfix 的话它会抢走）。本脚本会先探测并如实报告，不擅自停 Postfix。
set -uo pipefail

# ── 持久根目录（不可用 /tmp，理由见文件头） ──
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
# ROOT 可被环境变量覆盖；rm -rf 之前守住：空值与 / 一律拒绝执行。
case "$ROOT" in
  ""|"/") echo "  **ROOT 非法（'$ROOT'），拒绝 rm -rf**" >&2; exit 1 ;;
esac
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

# **不写 relay.json**：`load_relay` 读的是 `relayhost` 键，键不存在即 `Ok(None)`
# ——「尚未配置中继」是合法状态（bin/mailstackd/src/config.rs:230）。写一个空对象
# 反而会被解析成 `BTreeMap<String,String>` 失败（值必须是字符串），报出的错误指向
# relay.json 损坏，读起来像是配置写错了，实际只是「多写了一个本不该存在的文件」。
# 缺它 = 直投，正合本验证的意图：不中继、不出网。
cat > "$ROOT/etc/mailstack/settings.json" <<JSON
{ "serverName": "$MAIL_HOST", "hostname": "mx1.$DOMAIN", "adminEmail": "postmaster@$DOMAIN" }
JSON

# 证书文件名是 **fullchain.pem / privkey.pem**（`CertPaths::for_domain`）。
# 曾经命名成 cert.pem/key.pem，结果 TLS 装载失败而错误消息指向「证书缺失」，
# 读起来像是配置写错了 —— 实际只是文件名不对。
#
# 别用 openssl 的 `-quiet`：本机 openssl 不认这个选项，会报 Unknown option 然后
# 什么也不生成。它的点阵进度走 **stderr**，但那里同时还有真正的错误信息，
# 所以只能丢 stdout（`1>/dev/null`），不能丢 stderr。
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$ROOT/etc/mailstack/tls/$DOMAIN/privkey.pem" \
  -out "$ROOT/etc/mailstack/tls/$DOMAIN/fullchain.pem" \
  -days 30 -subj "/CN=$MAIL_HOST" \
  -addext "subjectAltName=DNS:$MAIL_HOST" 1>/dev/null
chmod 0600 "$ROOT/etc/mailstack/tls/$DOMAIN/privkey.pem"
# 立刻验证证书真的生成了：否则报错会出现在后面「TLS 材料不可用」处，
# 指向一个与真实原因毫无关系的方向。
[ -s "$ROOT/etc/mailstack/tls/$DOMAIN/fullchain.pem" ] \
  || { echo "  **openssl 未生成证书**（上面应有它的错误输出）"; exit 1; }
echo "  夹具就绪：$(find "$ROOT" -type f | wc -l) 个文件"

say "2. 启动 mailstackd（监听 $PORT_SMTP / $PORT_SUB），日志见 $ROOT/daemon.log"
"$BIN" --port "$PORT_SMTP" --port "$PORT_SUB" --config-dir "$ROOT" --log info \
  > "$ROOT/daemon.log" 2>&1 &
DAEMON_PID=$!
# 优雅停机：无论下面哪一步失败都要收掉它，否则端口会一直被占住，
# 下一次运行就会以「25 已被占用」失败 —— 一个自造的死循环。
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
# 把 daemon.log 的行数记下来：第 3 步之后再看新增的行，就能确切知道
# 服务端对 DATA 到底做了什么判断，而不是只能从客户端的超时反推。
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
# 队列布局：条目在 **queue/entries/*.json**（`QueueStore::entries_dir`），
# 队列根下只有 outbound-health.json 与它的锁。
# 早先查的是 queue/*.json，于是永远得到 0 条 —— 看起来像「邮件没入队」，
# 实际上只是**找错了目录**。这类假阴性比假阳性危险：它会让人以为功能没实现。
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
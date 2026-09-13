# MailStack long-running privileged helper daemon.
#
# The one-shot `sudo helper` path spawns a fresh python process per RPC, which
# is fine for a button click and wrong for the 5-second `logs.list` poll. This
# daemon serves the same action allowlist over root-owned unix sockets with a
# length-prefixed JSON protocol:
#
#   request : uint32be(length) + utf-8 JSON {"action": str, "data": object}
#   response: uint32be(length) + utf-8 JSON {"ok": bool, "data"|"error": ...}
#
# B1 dual-socket split (reduce the blast radius of a Node RCE):
#
#   /run/mailstack/helper-ro.sock  0660 root:mailstack-admin  -- read-only面
#       Node (mailstack-admin) connects here directly, but ONLY for actions in
#       ALLOWED_ACTIONS_RO. A mutating action arriving on this socket is refused
#       and audited as `ro_channel_violation` -- the channel, not the peer uid,
#       decides the action subset, so even root must use the change surface for
#       writes.
#
#   /run/mailstack/helper.sock     0600 root:root             -- 变更面
#       Node cannot connect at all (it is not root and not in a group with
#       access). Mutating actions from the admin console therefore travel over
#       `sudo /usr/local/libexec/mailstack-privileged` (the single sudoers rule,
#       stdin JSON unchanged). This socket is the root-only change surface: a
#       defense-in-depth channel whose peercred gate re-verifies uid==0 even
#       though 0600 already excludes everyone else.
#
# Filesystem permissions are the primary access control; SO_PEERCRED is the
# second layer on both sockets.
import json
import os
import signal
import socket
import socketserver
import struct
import sys
import threading

try:
    import grp
except ImportError:  # pragma: no cover - development hosts only; production is Linux
    grp = None

try:
    import pwd
except ImportError:  # pragma: no cover - development hosts only
    pwd = None

from .core import audit, warn, ALLOWED_ACTIONS, ALLOWED_ACTIONS_RO, ALLOWED_ACTIONS_RW
from .dispatcher import dispatch

SOCKET_DIR = os.environ.get('MAILSTACK_HELPER_DIR', '/run/mailstack')
# 变更面 (RW)：0600 root:root。既有环境变量名保持不变（现网/测试可能已设置）。
SOCKET_PATH = os.environ.get('MAILSTACK_HELPER_SOCKET', os.path.join(SOCKET_DIR, 'helper.sock'))
# 只读面 (RO)：0660 root:mailstack-admin。Node 直连此 socket 下发只读 action。
RO_SOCKET_PATH = os.environ.get('MAILSTACK_HELPER_RO_SOCKET', os.path.join(SOCKET_DIR, 'helper-ro.sock'))
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 16 * 1_048_576
READ_TIMEOUT_SECONDS = 30
# 两个 socket 共用一个 MAX_WORKERS 信号量：只读轮询（logs.list 每 5s）与 root 变更
# 动作共享同一进程的处理并发上限。8 足以覆盖单管理面板的并发；共用而非各自限额是
# 现场保守选择——避免为几乎无生产消费者的变更面单独放大线程数，同时让只读洪峰不会
# 因变更面独占线程而饿死。若日后需要隔离，把 semaphore 拆成两个即可（handler 通过
# self.server.semaphore 取用，天然按 server 实例区分）。
MAX_WORKERS = 8


def _recvn(conn, count):
    chunks = []
    remaining = count
    while remaining > 0:
        try:
            chunk = conn.recv(min(remaining, 65536))
        except (socket.timeout, TimeoutError):
            return None
        except OSError:
            return None
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _allowed_uids(channel):
    """Peer uids permitted on *channel*.

    ro: root plus the mailstack-admin service account (Node connects here).
    rw: root only -- 0600 already excludes everyone else, and peercred re-verifies
        uid==0 as defense in depth (a stray group membership or a mis-set mode must
        not widen the change surface).
    """
    uids = {0}
    if channel == 'ro' and pwd is not None:
        try:
            uids.add(pwd.getpwnam('mailstack-admin').pw_uid)
        except KeyError:
            pass
    return uids


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.semaphore.acquire()
        try:
            self._serve()
        finally:
            self.server.semaphore.release()

    def _serve(self):
        # The channel and its action subset ride on the server instance, so one
        # handler class serves both sockets without ambiguity about which surface
        # a connection arrived on.
        channel = getattr(self.server, 'channel', 'rw')
        allowed_actions = getattr(self.server, 'allowed_actions', ALLOWED_ACTIONS)

        # A2/B1: SO_PEERCRED gate, per channel. ro accepts uid==0 or the
        # mailstack-admin service account; rw accepts uid==0 only. Any other uid
        # gets the connection closed immediately with a peer_denied audit entry.
        # On non-Linux hosts (development) SO_PEERCRED is unavailable; skip the
        # check with a one-time warning.
        if hasattr(socket, 'SO_PEERCRED'):
            try:
                cred = self.request.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')
                )
                pid, uid, gid = struct.unpack('3i', cred)
                if uid not in _allowed_uids(channel):
                    audit('peer_denied', False, f'channel={channel} uid={uid} pid={pid} gid={gid}')
                    warn(f'helper socket peer denied: channel={channel} uid={uid} pid={pid}')
                    return
            except OSError as exc:
                # getsockopt failed (e.g. socket already closed) -- deny.
                warn('SO_PEERCRED getsockopt', exc)
                return
        else:
            # Non-Linux development host: SO_PEERCRED does not exist.
            warn('SO_PEERCRED unavailable (non-Linux), peer check skipped')

        try:
            self.request.settimeout(READ_TIMEOUT_SECONDS)
            header = _recvn(self.request, 4)
            if header is None:
                return
            (length,) = struct.unpack('>I', header)
            if length <= 0 or length > MAX_REQUEST_BYTES:
                return
            payload = _recvn(self.request, length)
            if payload is None:
                return
            action = 'unknown'
            data = {}
            try:
                request = json.loads(payload.decode('utf-8'))
                if not isinstance(request, dict):
                    raise ValueError('request must be an object')
                action = str(request.get('action') or '')
                data = request.get('data') if isinstance(request.get('data'), dict) else {}
                # B1 通道 action 子集门禁：只读面 (ro) 只放行 ALLOWED_ACTIONS_RO。
                # 收到已知变更 action（∈ ALLOWED_ACTIONS_RW）一律拒绝并审计
                # ro_channel_violation——通道而非 uid 决定子集，即便对端是 root 也
                # 必须改走变更面。未知 action 沿用 dispatch 的 unsupported 语义。
                if action not in allowed_actions:
                    if action in ALLOWED_ACTIONS_RW:
                        audit('ro_channel_violation', False,
                              f'action={action} channel={channel}', req_data=data)
                        response = {'ok': False, 'error': (
                            f'action {action} is not permitted on the read-only '
                            f'helper channel')}
                    else:
                        audit(action, False, 'unsupported action on this channel', req_data=data)
                        response = {'ok': False, 'error': f'unsupported action: {action}'}
                else:
                    result = dispatch(action, data)
                    audit(action, True, req_data=data)
                    response = {'ok': True, 'data': result}
            except Exception as exc:
                audit(action, False, exc, req_data=data)
                response = {'ok': False, 'error': str(exc) or 'OPERATION_FAILED'}
            body = json.dumps(response, ensure_ascii=False).encode('utf-8')
            if len(body) > MAX_RESPONSE_BYTES:
                body = json.dumps({'ok': False, 'error': 'response too large'}).encode('utf-8')
            self.request.sendall(struct.pack('>I', len(body)) + body)
        except Exception as exc:
            # A handler must never take the daemon down with it.
            warn('helper daemon connection', exc)


if hasattr(socketserver, 'UnixStreamServer'):
    class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

        def __init__(self, socket_path, handler, *, channel, allowed_actions,
                     mode, group, semaphore):
            # Set the per-socket policy BEFORE super().__init__, because that call
            # binds and activates the socket, which invokes server_bind() below.
            self.channel = channel
            self.allowed_actions = allowed_actions
            self._socket_path = socket_path
            self._mode = mode
            self._group = group
            self.semaphore = semaphore
            super().__init__(socket_path, handler)

        def server_bind(self):
            super().server_bind()
            # Apply the channel-specific ownership/mode. ro: 0660 root:mailstack-admin
            # so the admin web service reaches it via its primary group. rw: 0600
            # root:root so nothing unprivileged (including Node) can connect.
            os.chmod(self._socket_path, self._mode)
            if self._group is not None:
                if grp is not None:
                    try:
                        os.chown(self._socket_path, 0, grp.getgrnam(self._group).gr_gid)
                    except (KeyError, OSError) as exc:
                        warn(f'chown {self.channel} helper socket to {self._group}', exc)
            else:
                # rw surface: explicitly root:root (the daemon already runs as root,
                # so this is belt-and-braces against an inherited umask/group).
                try:
                    os.chown(self._socket_path, 0, 0)
                except OSError as exc:
                    warn(f'chown {self.channel} helper socket to root:root', exc)
else:  # pragma: no cover - Windows development hosts
    _Server = None


def main():
    if _Server is None:
        sys.stderr.write('mailstack-helper daemon requires unix socket support (Linux)\n')
        return 1
    if os.geteuid() != 0:
        sys.stderr.write('mailstack-helper daemon must run as root\n')
        return 1
    os.makedirs(SOCKET_DIR, exist_ok=True)
    # 目录 0750 root:mailstack-admin：mailstack-admin 需要 x（搜索）权限才能连到
    # 目录内的 helper-ro.sock；helper.sock 自身 0600 root:root 仍把 Node 挡在外面。
    os.chmod(SOCKET_DIR, 0o750)
    if grp is not None:
        try:
            os.chown(SOCKET_DIR, 0, grp.getgrnam('mailstack-admin').gr_gid)
        except (KeyError, OSError) as exc:
            warn('chown helper socket directory', exc)
    for path in (SOCKET_PATH, RO_SOCKET_PATH):
        if os.path.exists(path):
            os.unlink(path)

    # 两个 socket 共用一个信号量（见 MAX_WORKERS 注释）。
    semaphore = threading.Semaphore(MAX_WORKERS)
    # 变更面 (rw)：0600 root:root，全 action 子集（与 root 一次性包装器同等面），仅 uid==0。
    rw_server = _Server(SOCKET_PATH, _Handler, channel='rw', allowed_actions=ALLOWED_ACTIONS,
                        mode=0o600, group=None, semaphore=semaphore)
    # 只读面 (ro)：0660 root:mailstack-admin，仅 ALLOWED_ACTIONS_RO，uid∈{0, mailstack-admin}。
    ro_server = _Server(RO_SOCKET_PATH, _Handler, channel='ro', allowed_actions=ALLOWED_ACTIONS_RO,
                        mode=0o660, group='mailstack-admin', semaphore=semaphore)

    def _shutdown(signum, frame):
        # shutdown() must run off each serve thread, or it deadlocks. Both servers
        # are signalled from dedicated threads so neither serve_forever blocks the
        # other's teardown.
        threading.Thread(target=rw_server.shutdown, daemon=True).start()
        threading.Thread(target=ro_server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # rw 面在独立守护线程 serve_forever，主线程 serve ro 面；两者共用信号量。
    rw_thread = threading.Thread(
        target=rw_server.serve_forever, kwargs={'poll_interval': 0.5}, daemon=True)
    rw_thread.start()
    try:
        ro_server.serve_forever(poll_interval=0.5)
    finally:
        ro_server.server_close()
        rw_server.server_close()
        for path in (SOCKET_PATH, RO_SOCKET_PATH):
            try:
                os.unlink(path)
            except OSError:
                pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

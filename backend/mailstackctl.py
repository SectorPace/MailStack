#!/usr/bin/env python3
"""Production RPC entrypoint.

The implementation lives in the sibling ``mailstackctl`` package. This file
only owns the bounded JSON stdin/stdout protocol used by sudo and the admin API,
plus three CLI modes: ``--daemon`` (long-running dual-socket helper),
``--rw-forward`` (B4: forward the one-shot request over the rw change socket
with a direct local fallback) and ``audit-verify`` (B3: verify the audit hash
chain, non-zero exit on truncation/tamper).
"""
import json
import os
import sys

from mailstackctl import dispatch
from mailstackctl.core import audit

MAX_REQUEST_BYTES = 262_144
# B4 --rw-forward: 变更面 socket 转发的总超时。115s 略低于 admin 侧
# HELPER_TIMEOUT_MS 的 120s 默认，让转发错误先于 Node 的 SIGKILL 到达。
FORWARD_TIMEOUT_SECONDS = 115


def _dispatch_one_shot(raw) -> int:
    """Parse the one-shot JSON request, dispatch it, audit, print the result."""
    action = 'unknown'
    data = {}
    try:
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError('request too large')
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError('request must be an object')
        action = str(request.get('action') or '')
        data = request.get('data') if isinstance(request.get('data'), dict) else {}
        result = dispatch(action, data)
        audit(action, True, req_data=data)
        print(json.dumps({'ok': True, 'data': result}, ensure_ascii=False))
        return 0
    except Exception as exc:
        audit(action, False, exc, req_data=data)
        print(json.dumps({'ok': False, 'error': str(exc) or 'OPERATION_FAILED'}, ensure_ascii=False))
        return 1


def _recv_all(sock, count):
    chunks = []
    remaining = count
    while remaining > 0:
        try:
            chunk = sock.recv(min(remaining, 65536))
        except OSError:
            return None
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _forward_over_rw_socket(raw):
    """B4: 把一次性请求经变更面 socket (helper.sock) 转发给 helper daemon。

    daemon 运行在自己的 systemd 单元里（ProtectSystem=full + 显式
    ReadWritePaths），拥有变更动作所需的写权限；一次性包装器所在的
    mailstack-web 单元在 B4 后是 ProtectSystem=strict（/etc 全只读），
    不再依赖本进程命名空间可写。socket 不存在/连接失败/协议错误一律
    返回 None，交由直跑兜底——一次性包装器「stdout 单行 JSON」的契约
    不能被半途错误破坏。
    """
    import socket as socket_module
    import struct as struct_module
    sock_path = os.environ.get('MAILSTACK_HELPER_SOCKET', '/run/mailstack/helper.sock')
    try:
        if not os.path.exists(sock_path):
            return None
        with socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM) as sock:
            sock.settimeout(FORWARD_TIMEOUT_SECONDS)
            sock.connect(sock_path)
            sock.sendall(struct_module.pack('>I', len(raw)) + raw)
            header = _recv_all(sock, 4)
            if header is None or len(header) != 4:
                return None
            (length,) = struct_module.unpack('>I', header)
            if length <= 0 or length > 16 * 1024 * 1024:
                return None
            body = _recv_all(sock, length)
            if body is None or len(body) != length:
                return None
            return body.decode('utf-8', errors='replace')
    except OSError:
        return None


def rw_forward() -> int:
    """B4 --rw-forward：mailstack-privileged 包装器的主模式。

    读 stdin 的单行 JSON 请求，优先经变更面 socket 转发给 daemon（audit
    记录由 daemon 侧写入，与本进程直跑语义一致）；socket 不可用（daemon
    未运行/非 systemd 环境）时本进程直跑，与历史一次性 sudo 行为一致。
    """
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        print(json.dumps({'ok': False, 'error': 'request too large'}, ensure_ascii=False))
        return 1
    response = _forward_over_rw_socket(raw)
    if response is not None:
        sys.stdout.write(response.rstrip('\n') + '\n')
        sys.stdout.flush()
        try:
            return 0 if json.loads(response).get('ok') else 1
        except Exception:
            return 1
    return _dispatch_one_shot(raw)


def main() -> int:
    return _dispatch_one_shot(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))


if __name__ == '__main__':
    argv = sys.argv[1:]
    if argv and argv[0] == 'audit-verify':
        # B3: ms audit-verify —— 校验审计哈希链（截尾/篡改 → 非零退出）。
        # 非 RPC action，不进 dispatch；复用 core 的 CLI 实现（doctor 同源）。
        from mailstackctl.core import audit_verify_cli
        raise SystemExit(audit_verify_cli())
    if argv and argv[0] == '--daemon':
        # Long-running mode: serve the same action allowlist over the
        # root-owned unix sockets (see mailstackctl/daemon.py).
        from mailstackctl.daemon import main as daemon_main
        raise SystemExit(daemon_main())
    if argv and argv[0] == '--rw-forward':
        # B4: mailstack-privileged 的转发模式（变更面 socket 优先，直跑兜底）。
        raise SystemExit(rw_forward())
    raise SystemExit(main())

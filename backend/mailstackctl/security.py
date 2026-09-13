# MailStack Security Policy and Fail2ban Engine
import re, shutil, ipaddress
from .core import run, is_service_active, validate_mailbox_password

__all__ = ['validate_mailbox_password', 'valid_ip', 'valid_cidr']

def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise ValueError(f'invalid IP address: {value}')

def fail2ban_banned():
    out = []
    if shutil.which('fail2ban-client') and is_service_active('fail2ban'):
        p = run(['fail2ban-client', 'status'], check=False)
        if p.returncode == 0:
            m = re.search(r'Jail list:\s*(.*)', p.stdout)
            if m:
                for j in [x.strip() for x in m.group(1).split(',') if x.strip()]:
                    jp = run(['fail2ban-client', 'status', j], check=False)
                    if jp.returncode == 0:
                        im = re.search(r'Banned IP list:\s*(.*)', jp.stdout)
                        if im and im.group(1).strip():
                            for ip in im.group(1).split():
                                out.append({'ip': ip.strip(), 'jail': j, 'time': 'Active', 'reason': 'Failed authentication threshold'})
    return out

# 枚举白名单，不是格式白名单：rc.4 之前用 `^[A-Za-z0-9_.-]{1,64}$` 只约束了
# 字符集，任意合法格式的 jail 名都能传给 fail2ban-client。这里只放行安装器
# 实际写入 jail.d 的 jail（sshd 是发行版默认自带的，运维顺手管理它属于合理用途）。
# 仅当无法向本机 fail2ban 求证活动 jail 列表时作为兜底使用；可求证时以运行
# 时列表为准（否则 recidive 等自定义 jail 在 UI 里无法解封，rc.4 是支持的）。
ALLOWED_JAILS = frozenset({'postfix-sasl', 'dovecot', 'sshd'})

# Character-set guard applied before any jail name reaches fail2ban-client as
# a single argv element; it mirrors the pre-rc.5 format whitelist.
JAIL_NAME_RE = re.compile(r'[A-Za-z0-9_.-]{1,64}')

def _active_jails():
    """The jail names the local fail2ban reports as active, or None when they
    cannot be established (binary missing, service down, unparseable output).

    Server-side ground truth beats a hardcoded list: it both blocks fabricated
    names and keeps operator-defined jails (recidive etc.) manageable."""
    if not (shutil.which('fail2ban-client') and is_service_active('fail2ban')):
        return None
    p = run(['fail2ban-client', 'status'], check=False)
    if p.returncode != 0:
        return None
    m = re.search(r'Jail list:\s*(.*)', p.stdout)
    if not m:
        return None
    return {j.strip() for j in m.group(1).split(',') if j.strip()}

def _valid_jail(value):
    jail = str(value or 'postfix-sasl').strip()
    if not JAIL_NAME_RE.fullmatch(jail):
        raise ValueError(f'invalid fail2ban jail name: {jail}')
    active = _active_jails()
    allowed = active if active is not None else ALLOWED_JAILS
    if jail not in allowed:
        raise ValueError(
            f'unsupported fail2ban jail: {jail} (not an active jail on this host)'
        )
    return jail

def fail2ban_jail_enabled(jail):
    """True when fail2ban is running and knows the jail (exit 0 from `status`)."""
    jail = _valid_jail(jail)
    if not (shutil.which('fail2ban-client') and is_service_active('fail2ban')):
        return False
    return run(['fail2ban-client', 'status', jail], check=False).returncode == 0

def fail2ban_jail_operational(jail):
    """Prove the jail can actually act: ban then unban an RFC 5737 address.

    192.0.2.1 is documentation-only space, so briefly banning it can never
    disturb a real peer. A jail that is "enabled" but whose banip/unbanip
    round-trip fails is not brute-force protection.
    """
    if not fail2ban_jail_enabled(jail):
        return False
    probe_ip = '192.0.2.1'
    banned = run(['fail2ban-client', 'set', jail, 'banip', probe_ip], check=False)
    unbanned = run(['fail2ban-client', 'set', jail, 'unbanip', probe_ip], check=False)
    return banned.returncode == 0 and unbanned.returncode == 0

def fail2ban_unban(data):
    ip = valid_ip(data.get('ip', ''))
    jail = _valid_jail(data.get('jail', 'postfix-sasl'))
    if shutil.which('fail2ban-client'):
        run(['fail2ban-client', 'set', jail, 'unbanip', ip], check=False)
    return {'unbanned': ip}

def fail2ban_ban(data):
    ip = valid_ip(data.get('ip', ''))
    jail = _valid_jail(data.get('jail', 'postfix-sasl'))
    if shutil.which('fail2ban-client'):
        run(['fail2ban-client', 'set', jail, 'banip', ip], check=False)
    return {'banned': ip}

def security_scan(certs_fn=None):
    import datetime, os
    events = []
    def add(t, m, s='medium'):
        events.append({'id': str(len(events) + 1), 'timestamp': datetime.datetime.now().isoformat(), 'type': t, 'message': m, 'severity': s})
    relay = run(['postconf', '-h', 'smtpd_relay_restrictions'], check=False).stdout
    if 'reject_unauth_destination' not in relay and 'defer_unauth_destination' not in relay:
        add('AUTH_FAIL', 'Postfix relay restrictions may be unsafe', 'high')
    if not is_service_active('fail2ban'):
        add('AUTH_FAIL', 'Fail2ban is not active', 'medium')
    for p in ['/etc/postfix/sasl_passwd']:
        if os.path.exists(p) and os.stat(p).st_mode & 0o077:
            add('AUTH_FAIL', p + ' permissions are too broad', 'high')
    if certs_fn:
        if not certs_fn():
            add('DNS_WARN', 'No MailStack-managed TLS certificate found', 'medium')
    return {'score': max(0, 100 - len(events) * 12), 'events': events, 'bannedIps': fail2ban_banned()}

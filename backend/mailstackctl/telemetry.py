# MailStack system doctor, metrics and log engine.
import datetime
import json
import os
import pathlib
import re
import shutil
import socket
import time

try:
    import grp
except ImportError:  # pragma: no cover - development hosts only
    grp = None

from .ai import ai_public_config
from .certs import certs
from .version import __version__
from .backup import plaintext_backup_scan
from .core import (
    ADMIN_CONFIG, AI_CONFIG, ADDRESS_RE, AUDIT_LOG, ETC, PBKDF2_ITERATIONS, SERVICES,
    audit_verify, atomic, is_public_mode, is_service_active, run, safe_int, service_ctl,
)
from .mail import aliases, domain_list, queue, users
from .security import security_scan, fail2ban_jail_enabled, fail2ban_jail_operational
from .totp import AESGCM, TOTP_KEY_PATH

SETTINGS_FILE = ETC / 'settings.json'
_previous_cpu = None


def services():
    result = []
    for ident, unit in SERVICES.items():
        pid = 0
        memory_mb = 0.0
        active = False
        uptime = ''
        if shutil.which('systemctl') and os.path.isdir('/run/systemd/system'):
            probe = run(['systemctl', 'show', unit, '--property=ActiveState,MainPID,MemoryCurrent,ActiveEnterTimestamp', '--no-pager'], check=False)
            values = dict(item.split('=', 1) for item in probe.stdout.splitlines() if '=' in item)
            active = values.get('ActiveState') == 'active'
            pid = safe_int(values.get('MainPID'))
            memory_mb = round(safe_int(values.get('MemoryCurrent')) / 1048576, 1)
            uptime = values.get('ActiveEnterTimestamp', '')
        else:
            active = is_service_active(unit)
        result.append({
            'id': ident,
            'name': unit,
            'description': unit,
            'type': unit + '.service',
            'pid': pid,
            'uptime': uptime,
            'memoryMb': memory_mb,
            'cpuPercent': 0,
            'status': 'ACTIVE' if active else 'STOPPED',
            'ports': [],
        })
    return result


def logs(limit=200):
    limit = max(1, min(int(limit), 1000))
    lines = []
    if shutil.which('journalctl') and os.path.isdir('/run/systemd/system'):
        probe = run(['journalctl', '-u', 'postfix', '-u', 'dovecot', '-u', 'opendkim', '-u', 'fail2ban', '-u', 'mailstack-web', '-u', 'mailstack-webmail', '-n', str(limit), '--no-pager', '-o', 'short-iso'], check=False)
        lines = list(reversed(probe.stdout.splitlines()))
    else:
        for log_path in ('/var/log/mail.log', '/var/log/maillog', '/var/log/messages', '/var/log/mailstack-web.log', '/var/log/mailstack-webmail.log'):
            if not os.path.isfile(log_path):
                continue
            try:
                with open(log_path, 'r', encoding='utf-8', errors='replace') as handle:
                    lines.extend(reversed(handle.readlines()[-limit:]))
            except OSError:
                continue
    output = []
    for index, line in enumerate(lines[:limit]):
        lower = line.lower()
        service = 'postfix/smtpd'
        if 'dovecot' in lower:
            service = 'dovecot'
        elif 'opendkim' in lower:
            service = 'opendkim'
        elif 'fail2ban' in lower:
            service = 'fail2ban'
        elif 'mailstack' in lower:
            service = 'mailstack-web'
        output.append({
            'id': str(index),
            'timestamp': line[:25] if len(line) >= 25 else datetime.datetime.now(datetime.timezone.utc).isoformat()[:19],
            'service': service,
            'level': 'ERR' if any(word in lower for word in ('error', 'failed', 'panic')) else 'INFO',
            'processId': 0,
            'details': line[26:] if len(line) > 26 else line,
        })
    return output


def settings():
    persisted = {}
    if SETTINGS_FILE.exists():
        try:
            persisted = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
        except (OSError, ValueError, TypeError):
            persisted = {}
    message_limit = safe_int(run(['postconf', '-h', 'message_size_limit'], check=False).stdout.strip(), 52428800) // 1048576
    base = {
        'transparency': 70,
        'backdropBlur': 16,
        'reducedMotion': False,
        'autoUpdate': False,
        'version': __version__,
        'hostname': socket.getfqdn(),
        'adminEmail': '',
        'timezone': time.tzname[0] if time.tzname else 'UTC',
        'maxMessageSizeMb': max(1, min(1024, message_limit)),
        'relayConcurrency': 20,
        'rateLimitPerHour': 500,
        'spamThreshold': 6,
        'colorTheme': 'cyan',
    }
    if isinstance(persisted, dict):
        base.update(persisted)
    return base


def settings_set(data):
    clean = {key: data[key] for key in ('transparency', 'backdropBlur', 'reducedMotion', 'autoUpdate', 'adminEmail', 'maxMessageSizeMb', 'rateLimitPerHour', 'spamThreshold', 'colorTheme', 'hostname', 'timezone') if key in data}
    admin_email = str(clean.get('adminEmail', '')).strip()
    if admin_email and not ADDRESS_RE.fullmatch(admin_email):
        raise ValueError('invalid administrator email')
    if 'maxMessageSizeMb' in clean:
        size = int(clean['maxMessageSizeMb'])
        if not 1 <= size <= 1024:
            raise ValueError('invalid maximum message size')
        run(['postconf', '-e', f'message_size_limit = {size * 1048576}'], check=False)
        if shutil.which('postfix'):
            run(['postfix', 'check'], check=False)
        service_ctl('postfix', 'reload')
    current = {}
    if SETTINGS_FILE.exists():
        try:
            current = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
        except (OSError, ValueError, TypeError):
            current = {}
    if not isinstance(current, dict):
        current = {}
    current.update(clean)
    atomic(SETTINGS_FILE, json.dumps(current, indent=2) + '\n', 0o600)
    return settings()


def status():
    return {
        'domains': domain_list(),
        'users': users(),
        'aliases': aliases(),
        'relayRoutes': [],
        'relayProviders': [],
        'logs': logs(100),
        'services': services(),
        'queues': queue(),
        'certs': certs(),
        'anomalies': security_scan(certs_fn=certs)['events'],
        'settings': settings(),
    }


def _cpu_percent():
    global _previous_cpu
    if not os.path.isfile('/proc/stat'):
        return 0.0
    try:
        fields = open('/proc/stat', encoding='ascii').readline().split()[1:]
        values = [int(value) for value in fields]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        current = (idle, total)
        if _previous_cpu is None:
            _previous_cpu = current
            return 0.0
        previous_idle, previous_total = _previous_cpu
        _previous_cpu = current
        total_delta = total - previous_total
        idle_delta = idle - previous_idle
        if total_delta <= 0:
            return 0.0
        return round(max(0.0, min(100.0, (total_delta - idle_delta) * 100 / total_delta)), 1)
    except (OSError, IndexError, ValueError):
        return 0.0


def metrics_realtime():
    load = os.getloadavg() if hasattr(os, 'getloadavg') else (0.0, 0.0, 0.0)
    memory_total = 0
    memory_available = 0
    try:
        with open('/proc/meminfo', encoding='ascii') as handle:
            for line in handle:
                if line.startswith('MemTotal:'):
                    memory_total = int(line.split()[1]) // 1024
                elif line.startswith('MemAvailable:'):
                    memory_available = int(line.split()[1]) // 1024
    except (OSError, ValueError):
        pass
    used = max(0, memory_total - memory_available)
    return {
        'cpuPercent': _cpu_percent(),
        'loadAvg': list(load),
        'systemMemoryTotalMb': memory_total,
        'systemMemoryUsedMb': used,
        'systemMemoryPercent': round(used * 100 / memory_total, 1) if memory_total else 0,
        'services': services(),
    }


def escape_hatch_scan(public_mode, unit_env=None, proc_environ=None):
    """A5: production escape-hatch scan.

    Inspects the mailstack-web unit's ``Environment=`` lines and, when readable,
    the running process' ``/proc/<pid>/environ``. In public mode any of the
    following is a FAIL:

      COOKIE_SECURE=0 / HOST=0.0.0.0 / ADMIN_HOST=0.0.0.0 /
      MAILSTACK_ALLOW_UNSAFE_GIT=1 / MAILSTACK_AUDIT_FAILOPEN=1

    It also asserts the admin panel actually binds a loopback address (direct
    mode only faces the internet behind a TLS reverse proxy; the panel itself
    stays on 127.0.0.1 -- the current production model).

    All inputs are pre-parsed text/values so the unit test can feed fabricated
    data directly (T-ESC-1 runs this for real). Returns check dicts shaped like
    system_doctor's add_check output.
    """
    checks = []

    def add(name, state, message, fix=''):
        checks.append({'category': 'security', 'name': name, 'status': state, 'message': message, 'fixSuggestion': fix})

    env = {}
    for line in (unit_env or []):
        line = line.strip()
        if line.startswith('Environment='):
            kv = line[len('Environment='):]
            if '=' in kv:
                key, val = kv.split('=', 1)
                env[key.strip()] = val.strip().strip('\'"')
    if proc_environ:
        for chunk in proc_environ.split('\x00'):
            if '=' in chunk:
                key, val = chunk.split('=', 1)
                env.setdefault(key.strip(), val.strip())

    hatches = {
        'COOKIE_SECURE': lambda v: v == '0',
        'HOST': lambda v: v == '0.0.0.0',
        'ADMIN_HOST': lambda v: v == '0.0.0.0',
        'MAILSTACK_ALLOW_UNSAFE_GIT': lambda v: v == '1',
        'MAILSTACK_AUDIT_FAILOPEN': lambda v: v == '1',
    }
    offenders = [k for k, bad in hatches.items() if k in env and bad(env[k])]
    if public_mode and offenders:
        add('Escape hatches', 'FAIL',
            'public mode with unsafe switch(es): ' + ', '.join(f'{k}={env[k]}' for k in offenders),
            'remove these Environment= lines from the mailstack-web unit and unset them from the process environment')
    elif offenders:
        # Local mode: COOKIE_SECURE=0 over loopback/SSH is the correct config, so
        # it is not surfaced. Only a genuinely non-loopback admin bind or an
        # absolute-prohibition switch (unsafe-git / audit-failopen) earns a WARN.
        serious = [k for k in offenders
                   if k in ('MAILSTACK_ALLOW_UNSAFE_GIT', 'MAILSTACK_AUDIT_FAILOPEN')
                   or (k in ('HOST', 'ADMIN_HOST') and env[k] == '0.0.0.0')]
        if serious:
            add('Escape hatches', 'WARN',
                'local mode but risky switch(es) present: ' + ', '.join(f'{k}={env[k]}' for k in serious),
                'avoid HOST=0.0.0.0 / UNSAFE_GIT / AUDIT_FAILOPEN even in local mode')
        else:
            add('Escape hatches', 'PASS', 'no public-mode escape hatch (local mode; COOKIE_SECURE=0 permitted)')
    else:
        add('Escape hatches', 'PASS', 'no production escape hatch is set')

    listen_host = env.get('HOST') or env.get('ADMIN_HOST')
    if listen_host:
        if listen_host in ('127.0.0.1', '::1', 'localhost'):
            add('Admin bind address', 'PASS', f'admin panel binds {listen_host} (loopback)')
        elif public_mode:
            add('Admin bind address', 'FAIL',
                f'admin panel binds {listen_host}; public deployments must keep it on 127.0.0.1 behind a TLS reverse proxy',
                'set HOST/ADMIN_HOST to 127.0.0.1 in the mailstack-web unit')
        else:
            add('Admin bind address', 'WARN',
                f'admin panel binds {listen_host} (non-loopback) in local mode',
                'prefer 127.0.0.1 and reach the panel via an SSH tunnel')
    return checks


# rsyslog 传统转发 action：@host（UDP）或 @@host[:port]（TCP），前面必须是
# 空白/行首（不匹配邮箱地址或模板里的 user@host）。
RSYSLOG_FORWARD_RE = re.compile(r'(?<![\S])(?:@@|@)(?![\s@])[A-Za-z0-9._:-]+')


def remote_syslog_scan(public_mode, config_paths=None):
    """B3: 探测 rsyslog 是否配置了远程转发 target（audit 异地副本）。

    config_paths 显式传入供测试注入；缺省扫描 /etc/rsyslog.conf 与
    /etc/rsyslog.d/*.conf。识别传统 @/@@ 转发 action 与 omfwd action。
    公网模式缺失转发 → WARN（不 FAIL，属纵深防御而非硬约束）；local
    模式不产生 check。返回 check dict 列表（shape 同 system_doctor）。
    """
    checks = []

    def add(name, state, message, fix=''):
        checks.append({'category': 'security', 'name': name, 'status': state, 'message': message, 'fixSuggestion': fix})

    if not public_mode:
        return checks
    if config_paths is None:
        paths = [pathlib.Path('/etc/rsyslog.conf')]
        try:
            paths += sorted(pathlib.Path('/etc/rsyslog.d').glob('*.conf'))
        except OSError:
            pass
    else:
        paths = [pathlib.Path(p) for p in config_paths]
    detected = None
    for conf in paths:
        try:
            for line in conf.read_text(encoding='utf-8', errors='replace').splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                match = RSYSLOG_FORWARD_RE.search(line)
                if match:
                    detected = (conf.name, match.group(0))
                    break
                if 'omfwd' in line and 'target' in line:
                    detected = (conf.name, 'omfwd action')
                    break
        except OSError:
            continue
        if detected:
            break
    if detected:
        add('Remote syslog', 'PASS', f'forwarding target detected in {detected[0]} ({detected[1]})')
    else:
        add('Remote syslog', 'WARN',
            'public mode without remote syslog forwarding: audit records stay local-only',
            'add a forwarding action under /etc/rsyslog.d/ (e.g. authpriv.* @@loghost.example:6514)')
    return checks


def key_permission_scan(sasl_passwd=None, dkim_key_dir=None, backup_dir=None):
    """B5: 密钥材料权限全表扫描（密钥/凭证文件是 FAIL 级，非通用 WARN）。

    覆盖：sasl_passwd 0600；DKIM *.private 0640 root:opendkim；备份目录
    mailstack-backup-*（含 gpg 密文归档与 metadata）0600。路径均可显式
    传入供测试；缺省用生产路径，文件不存在则跳过。开发机无 opendkim
    组时仅校验 mode 与 uid。返回 check dict 列表（shape 同 system_doctor）。
    """
    checks = []

    def add(name, state, message, fix=''):
        checks.append({'category': 'security', 'name': name, 'status': state, 'message': message, 'fixSuggestion': fix})

    sasl = pathlib.Path(sasl_passwd if sasl_passwd is not None else '/etc/postfix/sasl_passwd')
    if sasl.exists():
        try:
            mode = sasl.stat().st_mode & 0o777
            if mode == 0o600:
                add('sasl_passwd', 'PASS', f'SMTP relay credentials are {oct(mode)}')
            else:
                add('sasl_passwd', 'FAIL', f'SMTP relay credentials are {oct(mode)}; expected 0600', f'chmod 600 {sasl}')
        except OSError:
            add('sasl_passwd', 'INFO', 'SMTP relay credentials are not readable')

    gid_opendkim = None
    if grp is not None:
        try:
            gid_opendkim = grp.getgrnam('opendkim').gr_gid
        except (KeyError, OSError):
            gid_opendkim = None
    dkim_root = pathlib.Path(dkim_key_dir if dkim_key_dir is not None else '/etc/opendkim/keys')
    try:
        dkim_keys = sorted(dkim_root.rglob('*.private'))
    except OSError:
        dkim_keys = []
    if dkim_keys:
        for key in dkim_keys:
            try:
                stat = key.stat()
            except OSError:
                continue
            mode = stat.st_mode & 0o777
            owner_ok = stat.st_uid == 0 and (gid_opendkim is None or stat.st_gid == gid_opendkim)
            if mode == 0o640 and owner_ok:
                add(f'DKIM key {key.name}', 'PASS', 'DKIM private key is 0640 root:opendkim')
            else:
                add(f'DKIM key {key.name}', 'FAIL',
                    f'DKIM private key is {oct(mode)} uid={stat.st_uid} gid={stat.st_gid}; expected 0640 root:opendkim',
                    f'chown root:opendkim {key}; chmod 640 {key}')
    else:
        add('DKIM keys', 'INFO', 'no DKIM private keys found under ' + str(dkim_root))

    bdir = pathlib.Path(backup_dir if backup_dir is not None else '/var/backups/mailstack')
    try:
        backup_entries = sorted(bdir.glob('mailstack-backup-*'))
    except OSError:
        backup_entries = []
    for entry in backup_entries:
        try:
            mode = entry.stat().st_mode & 0o777
        except OSError:
            continue
        if mode == 0o600:
            add(f'backup {entry.name}', 'PASS', f'{oct(mode)}')
        else:
            add(f'backup {entry.name}', 'FAIL',
                f'backup file is {oct(mode)}; expected 0600 (secrets and gpg ciphertext)',
                f'chmod 600 {entry}')
    return checks


def system_doctor():
    checks = []

    def add_check(category, name, state, message, fix=''):
        checks.append({'category': category, 'name': name, 'status': state, 'message': message, 'fixSuggestion': fix})

    os_name = 'Linux'
    if os.path.isfile('/etc/os-release'):
        try:
            for line in pathlib.Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
                if line.startswith('PRETTY_NAME='):
                    os_name = line.split('=', 1)[1].strip().strip('"')
                    break
        except OSError:
            pass
    kernel = os.uname().release if hasattr(os, 'uname') else 'unknown'
    add_check('system', 'Operating system', 'PASS', f'{os_name} (kernel {kernel})')

    try:
        load = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        state = 'PASS' if load[0] < cpu_count * 2 else 'WARN'
        add_check('system', 'Load average', state, f'1m: {load[0]:.2f}, 5m: {load[1]:.2f}, 15m: {load[2]:.2f} ({cpu_count} CPUs)')
    except OSError:
        add_check('system', 'Load average', 'INFO', 'Load average is unavailable on this platform')

    try:
        disk = shutil.disk_usage('/')
        used_percent = disk.used * 100 / disk.total if disk.total else 0
        state = 'FAIL' if used_percent > 95 else ('WARN' if used_percent > 85 else 'PASS')
        add_check('system', 'Root filesystem', state, f'{disk.free / 1024**3:.1f} GB free of {disk.total / 1024**3:.1f} GB ({used_percent:.1f}% used)')
    except OSError:
        add_check('system', 'Root filesystem', 'INFO', 'Disk usage is unavailable')

    memory_total = memory_available = 0
    try:
        with open('/proc/meminfo', encoding='ascii') as handle:
            for line in handle:
                if line.startswith('MemTotal:'): memory_total = int(line.split()[1]) // 1024
                elif line.startswith('MemAvailable:'): memory_available = int(line.split()[1]) // 1024
        state = 'FAIL' if memory_available < 150 else ('WARN' if memory_available < 300 else 'PASS')
        add_check('system', 'Available memory', state, f'{memory_available} MB available of {memory_total} MB')
    except (OSError, ValueError):
        add_check('system', 'Available memory', 'INFO', 'Memory information is unavailable')

    required_services = {'postfix': True, 'dovecot': True, 'opendkim': False, 'mailstack-web': True, 'mailstack-webmail': False, 'fail2ban': False}
    for service_id, required in required_services.items():
        active = is_service_active(service_id)
        add_check('services', service_id, 'PASS' if active else ('FAIL' if required else 'WARN'), 'Active and running' if active else 'Inactive or stopped', f'systemctl restart {service_id}' if not active else '')

    if shutil.which('postfix'):
        result = run(['postfix', 'check'], check=False)
        add_check('services', 'Postfix configuration', 'PASS' if result.returncode == 0 else 'FAIL', 'postfix check passed' if result.returncode == 0 else 'postfix check reported an error')
    if shutil.which('dovecot'):
        result = run(['dovecot', '-n'], check=False)
        add_check('services', 'Dovecot configuration', 'PASS' if result.returncode == 0 else 'FAIL', 'dovecot configuration is valid' if result.returncode == 0 else 'dovecot configuration reported an error')

    ports = [(25, False), (587, False), (465, False), (143, False), (993, False), (8787, True), (18788, False)]
    for port, required in ports:
        open_port = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.6)
                open_port = sock.connect_ex(('127.0.0.1', port)) == 0
        except OSError:
            pass
        add_check('ports', str(port), 'PASS' if open_port else ('FAIL' if required else 'WARN'), f'127.0.0.1:{port} is reachable' if open_port else f'127.0.0.1:{port} is not reachable')

    try:
        queue_count = len(queue())
        add_check('queue', 'Postfix queue', 'PASS' if queue_count < 20 else 'WARN', f'{queue_count} queued messages')
    except Exception:
        add_check('queue', 'Postfix queue', 'INFO', 'Queue information is unavailable')

    domains = domain_list()
    add_check('dns', 'Managed domains', 'PASS' if domains else 'WARN', f'{len(domains)} managed domain(s)' if domains else 'No managed domain has been configured')

    permission_targets = [(ETC, 0o750), (ADMIN_CONFIG, 0o640), (pathlib.Path('/etc/postfix/sasl_passwd'), 0o600), (pathlib.Path('/etc/sudoers.d/mailstack-web'), 0o440)]
    for target, expected in permission_targets:
        if not target.exists():
            add_check('security', target.name, 'INFO', 'Not present on this host')
            continue
        actual = target.stat().st_mode & 0o777
        unsafe = actual & (~expected & 0o777)
        add_check('security', target.name, 'WARN' if unsafe else 'PASS', f'permissions {oct(actual)}', f'chmod {oct(expected)[2:]} {target}' if unsafe else '')

    # Fail2ban 必须真拦截：「装了但没 jail」与「jail 在但 banip 不生效」都是 FAIL，
    # 不是黄灯。operational 探针用 192.0.2.1 (TEST-NET-1, RFC 5737) 做 ban/unban
    # 往返，不会误伤任何真实对端。
    if not shutil.which('fail2ban-client'):
        add_check('security', 'Fail2ban', 'WARN', 'fail2ban is not installed on this platform', 'install fail2ban with the system package manager')
    elif not is_service_active('fail2ban'):
        add_check('security', 'Fail2ban', 'FAIL', 'fail2ban is installed but not running', 'systemctl restart fail2ban')
    else:
        for jail in ('postfix-sasl', 'dovecot'):
            if not fail2ban_jail_enabled(jail):
                add_check('security', f'fail2ban jail: {jail}', 'FAIL', f'jail {jail} is not active', 'check /etc/fail2ban/jail.d/mailstack.conf and log paths')
            elif not fail2ban_jail_operational(jail):
                add_check('security', f'fail2ban jail: {jail}', 'FAIL', f'jail {jail} ban/unban round-trip failed', 'fail2ban-client status ' + jail)
            else:
                add_check('security', f'fail2ban jail: {jail}', 'PASS', 'jail active; ban/unban round-trip verified with TEST-NET-1 probe')

    try:
        ai_config = ai_public_config()
        add_check('ai', 'AI provider', 'PASS' if ai_config.get('credentialConfigured') or ai_config.get('configured') else 'INFO', 'Provider credentials are configured' if ai_config.get('credentialConfigured') or ai_config.get('configured') else 'No AI credentials are configured')
    except Exception:
        add_check('ai', 'AI provider', 'INFO', 'AI provider configuration is unavailable')

    # --- 2FA / TOTP envelope checks (A1 enforcement + A3 secret-at-rest) ---
    # Public access mode without 2FA is a FAIL (the server refuses to serve
    # until enrollment completes); local mode without 2FA is only a WARN.
    public_mode = is_public_mode()
    try:
        admin_cfg = json.loads(ADMIN_CONFIG.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        admin_cfg = {}
    totp_cfg = admin_cfg.get('totp') if isinstance(admin_cfg, dict) else None
    totp_cfg = totp_cfg if isinstance(totp_cfg, dict) else {}
    totp_enabled = bool(totp_cfg.get('enabled'))

    # A3: python3-cryptography gates every 2FA operation (fail-closed, no
    # self-made encryption). Missing backend makes 2FA impossible: FAIL when
    # public (2FA is mandatory), WARN when local (2FA is defense-in-depth).
    if AESGCM is None:
        add_check('security', '2FA crypto backend', 'FAIL' if public_mode else 'WARN',
                  'python3-cryptography is not installed; 2FA operations fail-closed',
                  'install python3-cryptography via the distribution package manager')
    else:
        add_check('security', '2FA crypto backend', 'PASS', 'python3-cryptography is available')

    if totp_enabled:
        add_check('security', 'Two-factor authentication', 'PASS', 'TOTP two-factor authentication is enabled')
    elif public_mode:
        add_check('security', 'Two-factor authentication', 'FAIL',
                  'public access mode is active but 2FA is not enabled; the server only serves the enrollment window',
                  'log in and complete 2FA enrollment (Admin \u2192 Security \u2192 2FA)')
    else:
        add_check('security', 'Two-factor authentication', 'WARN',
                  'two-factor authentication is not enabled (local mode)',
                  'enable 2FA under Admin \u2192 Security for defense in depth')

    # A3: the master key must be 0600 root:root so only the helper can read it.
    if TOTP_KEY_PATH.exists():
        try:
            key_stat = TOTP_KEY_PATH.stat()
            key_mode = key_stat.st_mode & 0o777
            if key_mode == 0o600 and key_stat.st_uid == 0 and key_stat.st_gid == 0:
                add_check('security', 'totp.key', 'PASS', 'TOTP master key is 0600 root:root')
            else:
                add_check('security', 'totp.key', 'FAIL',
                          f'TOTP master key is {oct(key_mode)} uid={key_stat.st_uid} gid={key_stat.st_gid}; expected 0600 root:root',
                          f'chown root:root {TOTP_KEY_PATH}; chmod 600 {TOTP_KEY_PATH}')
        except OSError:
            add_check('security', 'totp.key', 'INFO', 'TOTP master key is not readable')
    else:
        add_check('security', 'totp.key', 'INFO', 'TOTP master key not present (generated on first 2FA enrollment)')

    # A3: admin.json must carry only the {enc, nonce, tag} envelope, never a
    # plaintext TOTP secret. A leftover "secret": field means migration has
    # not run (or an old build wrote it back).
    if ADMIN_CONFIG.exists():
        try:
            admin_text = ADMIN_CONFIG.read_text(encoding='utf-8')
        except OSError:
            admin_text = ''
        if '"secret":' in admin_text:
            add_check('security', 'TOTP secret at rest', 'FAIL',
                      'admin.json still contains a plaintext "secret" field',
                      'restart the helper to trigger automatic re-seal, or re-enroll 2FA')
        else:
            add_check('security', 'TOTP secret at rest', 'PASS', 'no plaintext TOTP secret in admin.json')

    # --- A5: production escape-hatch scan ---
    # Read the mailstack-web unit's Environment= lines and, when the process is
    # running and readable, its /proc/<pid>/environ. In public mode any unsafe
    # switch (COOKIE_SECURE=0 / HOST=0.0.0.0 / UNSAFE_GIT / AUDIT_FAILOPEN) is a
    # FAIL; the scan also asserts the admin panel binds a loopback address.
    unit_env = []
    try:
        web_unit = pathlib.Path('/etc/systemd/system/mailstack-web.service')
        if web_unit.exists():
            unit_env = [ln for ln in web_unit.read_text(encoding='utf-8').splitlines()
                        if ln.strip().startswith('Environment=')]
    except OSError:
        unit_env = []
    proc_environ = None
    try:
        pid = 0
        if shutil.which('systemctl') and os.path.isdir('/run/systemd/system'):
            probe = run(['systemctl', 'show', 'mailstack-web', '--property=MainPID', '--no-pager'], check=False)
            for item in probe.stdout.split():
                if item.startswith('MainPID='):
                    pid = safe_int(item.split('=', 1)[1])
        if pid:
            ep = pathlib.Path(f'/proc/{pid}/environ')
            if ep.exists():
                proc_environ = ep.read_text(encoding='utf-8', errors='replace')
    except (OSError, ValueError):
        proc_environ = None
    for chk in escape_hatch_scan(public_mode, unit_env=unit_env, proc_environ=proc_environ):
        checks.append(chk)

    # --- B3: audit hash chain + remote syslog forwarding ---
    # 复用 core.audit_verify（同一函数也驱动 ms audit-verify CLI），
    # 不 shell 出去贴 python 一行。
    if not AUDIT_LOG.exists():
        add_check('security', 'Audit chain', 'INFO', 'audit log not present yet (written on first privileged action)')
    else:
        audit_result = audit_verify()
        if audit_result.get('ok'):
            anchor_note = '' if audit_result.get('anchor') else ' (no anchor yet)'
            add_check('security', 'Audit chain', 'PASS',
                      f'audit hash chain verified: {audit_result.get("entries", 0)} chained entries{anchor_note}')
        else:
            add_check('security', 'Audit chain', 'FAIL',
                      f'audit hash chain verification failed: {audit_result.get("error") or "unknown error"}',
                      'run ms audit-verify for details; cross-check with the remote syslog copy before trusting the log')
    for chk in remote_syslog_scan(public_mode):
        checks.append(chk)

    # --- B2: plaintext backup scan (public mode only) ---
    # 公网模式下备份目录存在未加密 mailstack-backup-*.tar.gz（非 gpg 密文）
    # 是 FAIL：B2 只在 local 模式允许明文归档。
    backup_scan = plaintext_backup_scan()
    if backup_scan.get('publicMode'):
        plaintext_names = backup_scan.get('plaintext') or []
        if plaintext_names:
            add_check('security', 'Backup encryption', 'FAIL',
                      f'plaintext backup archive(s) present in public mode: {", ".join(plaintext_names[:5])}',
                      'remove or re-create them with a passphrase (backup.create in public mode requires one)')
        else:
            add_check('security', 'Backup encryption', 'PASS', 'no plaintext backup archive in public mode')

    # --- B5: crypto policy + key material permissions ---
    # 算法清单写死并运行时自检：PBKDF2 迭代数被改小或 AESGCM 信封缺失
    # 都直接 FAIL；清单与 tests/security-static.test.mjs 的静态门禁互为镜像
    # （仓库再出现 XOR/自制流密码会被静态门禁打回）。
    crypto_ok = PBKDF2_ITERATIONS == 310000 and AESGCM is not None
    if crypto_ok:
        add_check('security', 'Crypto policy', 'PASS',
                  'password hashing PBKDF2-SHA256 (310k iterations); TOTP envelope AES-256-GCM; TLS terminated by Caddy/OpenSSL')
    else:
        add_check('security', 'Crypto policy', 'FAIL',
                  f'crypto policy violation: PBKDF2_ITERATIONS={PBKDF2_ITERATIONS}, AESGCM={"available" if AESGCM is not None else "missing"}',
                  'restore PBKDF2_ITERATIONS=310000 and install python3-cryptography')
    for chk in key_permission_scan():
        checks.append(chk)

    failures = [item for item in checks if item['status'] == 'FAIL']
    warnings = [item for item in checks if item['status'] == 'WARN']
    overall = 'CRITICAL' if failures else ('WARNING' if warnings else 'HEALTHY')
    return {
        'overall': overall,
        'summary': f'{len(checks)} checks, {len(failures)} failures, {len(warnings)} warnings',
        'errorCount': len(failures),
        'warningCount': len(warnings),
        'checks': checks,
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

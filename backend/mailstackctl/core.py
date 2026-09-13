# MailStack Core Utilities, Constants and Runtime Dispatcher
import contextlib
import json, os, re, subprocess, sys, pathlib, datetime, ssl, socket, urllib.request, urllib.parse, urllib.error, ipaddress, hashlib, secrets, getpass, shutil
try:
    import pwd, grp
except ImportError:
    pwd = grp = None

ETC = pathlib.Path('/etc/mailstack')
DOM = pathlib.Path('/etc/postfix/mailstack_domains')
ALS = pathlib.Path('/etc/postfix/mailstack_aliases')
DOMAIN_RE = re.compile(r'^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,30}$')
ADDRESS_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@[A-Za-z0-9.-]+$')
QUEUE_RE = re.compile(r'^[A-F0-9]{5,20}[*!]?$')
ADMIN_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{2,31}$')

ADMIN_CONFIG = ETC / 'admin.json'
AI_CONFIG = ETC / 'ai-provider.json'
# B5: 公网模式 ai.* 出站 action 的显式总闸文件（KEY=VALUE 行，enabled=true 开启）。
AI_OUTBOUND_CONF = ETC / 'ai.conf'
# B5: 环境变量形式的总闸（显式 1/true 开，显式 0/false 关；未设置走 ai.conf）。
AI_OUTBOUND_ENV = 'MAILSTACK_AI_OUTBOUND'
# B3: PBKDF2-SHA256 迭代次数是密码政策的一部分，写成常量供 doctor 断言。
PBKDF2_ITERATIONS = 310000
AUDIT_LOG = pathlib.Path('/var/log/mailstack-rpc-audit.log')
INSTALL_ARGS_CONF = ETC / 'install-args.conf'


def read_access_mode() -> str:
    """Read ACCESS_MODE from /etc/mailstack/install-args.conf.

    Returns 'local' when the file or key is missing. The file is written by
    install.sh with `printf 'ACCESS_MODE=%q\n'`, so the value may be shell-
    quoted; strip surrounding quotes for robustness.
    """
    try:
        text = INSTALL_ARGS_CONF.read_text(encoding='utf-8')
    except (OSError, FileNotFoundError):
        return 'local'
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('ACCESS_MODE='):
            value = line.split('=', 1)[1].strip().strip('\'"')
            return value if value else 'local'
    return 'local'


def is_public_mode() -> bool:
    """True when the deployment is internet-facing (caddy/direct) or the
    security profile is explicitly set to high.

    All callers must use this function -- never parse install-args.conf or
    the environment variable independently.
    """
    mode = read_access_mode()
    if mode in ('caddy', 'direct'):
        return True
    profile = os.environ.get('MAILSTACK_SECURITY_PROFILE', '').strip().lower()
    return profile == 'high'


def ai_outbound_enabled() -> bool:
    """B5 密码与密钥政策：公网模式下 ai.* 出站 action 的默认关闸。

    local 模式保持历史行为（恒开）。公网模式（caddy/direct/high）下必须
    显式开启才放行出站 AI 调用：环境变量 MAILSTACK_AI_OUTBOUND=1/true，
    或 /etc/mailstack/ai.conf 中 enabled=true。环境变量一旦设置即以其
    为准（含显式关闭 0/false）；未设置时公网读 ai.conf，缺失/未开启
    一律 False（fail-closed）。
    """
    flag = os.environ.get(AI_OUTBOUND_ENV, '').strip().lower()
    if flag:
        return flag not in ('0', 'false', 'no', 'off')
    if not is_public_mode():
        return True
    try:
        text = AI_OUTBOUND_CONF.read_text(encoding='utf-8')
    except (OSError, FileNotFoundError):
        return False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('enabled') and '=' in line:
            value = line.split('=', 1)[1].strip().strip('\'"').lower()
            return value in ('1', 'true', 'yes', 'on')
    return False

# B1 双 socket：action 按「是否改变本机状态」拆成只读面 (RO) 与变更面 (RW)。
#
#   RO -> /run/mailstack/helper-ro.sock（0660 root:mailstack-admin，Node 直连）
#   RW -> /run/mailstack/helper.sock（0600 root:root，Node 连不上；变更动作恒经
#         sudo `mailstack-privileged` 包装器下发）
#
# 归类纪律：逐个核对 dispatcher.py 与实现函数的副作用，纯读者入 RO，凡写文件 /
# 改 postfix·dovecot·fail2ban 状态 / 发信 / 锁账号 / 消费 TOTP 恢复码者入 RW；
# 「拿不准」一律归 RW（宁可多付一次 sudo fork，不可把副作用暴露在只读面上）。
#
# 该划分必须与 backend/server.production.ts 的 RW_ACTIONS 常量逐项一致——
# tests/security-static.test.mjs 的一致性门禁会解析两处集合并比对，防漂移。
ALLOWED_ACTIONS_RO = {
    # 纯读聚合：status() 汇总 domains/users/aliases/queue/certs/logs 的只读列表。
    'snapshot',
    # 诊断只读：仅读配置 + 对 TEST-NET-1(192.0.2.1) 做 fail2ban ban/unban 往返探针，
    # 不落任何持久状态（清单明示「只读 doctor」入 RO）。
    'system.doctor',
    # 读 setup.json 与服务活性。
    'setup.status',
    # 读 journal / 日志文件。
    'logs.list',
    # 读 /proc + 服务状态。
    'metrics.realtime',
    # 读域名表。
    'domains.list',
    # 读证书文件。
    'certs.list',
    # 读 settings.json + postconf -h。
    'settings.get',
    # 只读扫描：postconf -h / stat / fail2ban status / certs 列表，无副作用。
    'security.scan',
    # 列出备份归档。
    'backup.list',
    # 读 admin.json 的公开字段（绝不含 secret）。
    'admin.get',
    # 读 ai-provider.json 的公开配置。
    'ai.config.get',
    # 读配置 + 出站列模型，不写本机状态（清单明示入 RO）。
    'ai.models.list',
    # 仅出站 TCP 端口探测，不写本机状态。
    'network.check_port',
}
ALLOWED_ACTIONS_RW = {
    # setup 流程：写 postfix/opendkim 配置、签发证书、发测试信。dns.verify / relay.test
    # 虽以出站查询为主，但不在清单只读白名单内且属 setup 流程，按纪律保守归 RW。
    'setup.identity.apply', 'setup.dns.verify', 'setup.relay.test', 'setup.relay.apply',
    'setup.cert.issue', 'setup.mail.test',
    # 发信（本机投递副作用）。
    'mail.test_loopback',
    # 域名 / 邮箱 / 别名 / 队列变更。users.status 会 passwd -l/-u 锁解账号，属 RW。
    'domains.add', 'domains.delete',
    'users.add', 'users.delete', 'users.status', 'users.password',
    'aliases.add', 'aliases.delete', 'queue.action',
    # 服务启停重载。
    'services.action',
    # fail2ban 封禁 / 解封。
    'security.unban', 'security.ban',
    # 证书续期 / DKIM 轮换（写密钥与配置）。
    'certs.renew', 'dkim.rotate',
    # 写 settings.json + postconf -e。
    'settings.set',
    # 备份创建 / 恢复 / 删除。
    'backup.create', 'backup.restore', 'backup.delete',
    # 管理员凭证变更。
    'admin.set',
    # TOTP 全生命周期：begin/enable/disable 写信封，consume_recovery 消费恢复码，
    # verify 在迁移路径会重新封装 admin.json（有写副作用），故 admin.totp.* 全归 RW。
    'admin.totp.begin', 'admin.totp.enable', 'admin.totp.disable',
    'admin.totp.consume_recovery', 'admin.totp.verify',
    # AI 配置写入与出站对话 / 诊断 / 解析（非只读白名单成员，保守归 RW）。
    'ai.config.set', 'ai.test', 'ai.chat', 'ai.diagnose', 'ai.parse',
}
# 既有消费方（dispatcher 白名单、test_every_allowed_action_is_reachable、
# mailstackctl-modular.test.mjs 的 hasattr 断言）继续读 ALLOWED_ACTIONS：
# 它恒为两通道之并集，拆分对它们透明。
ALLOWED_ACTIONS = ALLOWED_ACTIONS_RO | ALLOWED_ACTIONS_RW
DESTRUCTIVE_ACTIONS = {'domains.delete', 'users.delete', 'backup.delete'}
SERVICES = {
    'postfix': 'postfix', 'dovecot': 'dovecot', 'opendkim': 'opendkim', 'fail2ban': 'fail2ban',
    'mailstack-web': 'mailstack-web', 'mailstack-webmail': 'mailstack-webmail',
    'rspamd': 'rspamd', 'clamav': 'clamav-daemon', 'redis': 'redis-server'
}

# B3 审计哈希链：每条记录带 prev_hash（前一条记录的 hash，链首为创世值）
# 与 hash（本条规范化 JSON 的 SHA256）。文件旁维护 .head 锚（最后一条的
# hash），用于检测「删掉尾部若干条」这类纯链校验无法发现的截尾。
AUDIT_GENESIS = '0' * 64
AUDIT_HEAD_SUFFIX = '.head'


def audit_head_path(log_path=None):
    p = pathlib.Path(log_path if log_path is not None else AUDIT_LOG)
    return p.with_name(p.name + AUDIT_HEAD_SUFFIX)


def _audit_record_hash(record):
    """SHA256 over the canonical JSON of a record (hash field excluded)."""
    payload = {k: v for k, v in record.items() if k != 'hash'}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _read_last_audit_hash(log_path):
    """Return the hash of the last chained record, or None if none exists.

    Only the tail of the file is read (a single audit line is well under 2 KB,
    256 KB covers thousands of entries). A trailing partial line -- possible
    when a concurrent writer is mid-append -- is dropped instead of parsed.
    """
    try:
        data = pathlib.Path(log_path).read_bytes()[-262144:]
    except (OSError, FileNotFoundError):
        return None
    if not data:
        return None
    if not data.endswith(b'\n'):
        cut = data.rfind(b'\n')
        data = data[:cut + 1] if cut >= 0 else b''
    for raw in reversed(data.splitlines()):
        try:
            record = json.loads(raw.decode('utf-8'))
        except Exception:
            continue
        if isinstance(record, dict) and isinstance(record.get('hash'), str):
            return record['hash']
    return None


_syslog_state = {'ready': False, 'failed': False}


def _audit_syslog(line):
    """Mirror one audit JSON line to syslog with LOG_AUTHPRIV (B3).

    Python's syslog module is POSIX-only; on Windows/hosts without syslog the
    first failure flips the module to degraded and every later call is a no-op
    -- audit persistence must never depend on the forwarder.
    """
    if _syslog_state['failed']:
        return
    try:
        import syslog
        if not _syslog_state['ready']:
            syslog.openlog('mailstackctl', 0, syslog.LOG_AUTHPRIV)
            _syslog_state['ready'] = True
        syslog.syslog(syslog.LOG_INFO, line.rstrip('\n'))
    except Exception as exc:
        _syslog_state['failed'] = True
        _syslog_state['ready'] = False
        warn('audit syslog forward', exc)


def audit(action, ok, error='', req_data=None):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        target = ''
        if isinstance(req_data, dict):
            target = req_data.get('domain') or req_data.get('username') or req_data.get('address') or req_data.get('ip') or req_data.get('service') or req_data.get('queueId') or req_data.get('filename') or ''
        current_uid = os.getuid() if hasattr(os, 'getuid') else 0
        # The whole read-tail -> append -> re-anchor sequence runs under the
        # audit lock sidecar so a concurrent one-shot CLI and the daemon cannot
        # interleave and fork the hash chain.
        with locked(AUDIT_LOG):
            prev_hash = _read_last_audit_hash(AUDIT_LOG) or AUDIT_GENESIS
            record = {
                'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'uid': current_uid,
                'action': action,
                'target': str(target)[:120],
                'ok': ok,
                'error': str(error)[:500],
                'prev_hash': prev_hash,
            }
            record['hash'] = _audit_record_hash(record)
            line = json.dumps(record, ensure_ascii=False) + '\n'
            with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
                f.write(line)
            atomic(audit_head_path(), record['hash'] + '\n', 0o600)
        _audit_syslog(line)
        if hasattr(os, 'chmod'):
            try:
                os.chmod(AUDIT_LOG, 0o600)
            except Exception as exc:
                warn(f'chmod {AUDIT_LOG} to 0600', exc)
    except Exception as exc:
        try:
            sys.stderr.write(f'mailstack: audit write failed: {exc}\n')
        except Exception:
            pass


def audit_verify(log_path=None):
    """Verify the audit prev_hash chain and the .head anchor (B3).

    Returns {'ok': bool, 'entries': int, 'anchor': bool, 'error': str}.
    Rules:
      - Records written before B3 (no hash/prev_hash fields) are skipped as
        legacy; once a chained record has been seen, any later unhashed record
        is a failure (format rollback would break the chain).
      - The first chained record's prev_hash must equal the genesis constant.
      - Each record's prev_hash must equal the previous record's hash, and its
        own hash must recompute correctly (tamper detection).
      - When the .head anchor exists and is non-empty it must equal the last
        chained record's hash (truncation detection). An empty anchor is the
        post-logrotate state and is not compared; a missing anchor skips the
        check (pre-B3 logs never wrote one).
    """
    log_path = pathlib.Path(log_path if log_path is not None else AUDIT_LOG)
    head_path = audit_head_path(log_path)
    errors = []
    entries = 0
    chain_started = False
    prev_hash = AUDIT_GENESIS
    last_hash = None
    try:
        text = log_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        text = ''
    except OSError as exc:
        return {'ok': False, 'entries': 0, 'anchor': False, 'error': f'read audit log failed: {exc}'}
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except Exception:
            errors.append(f'line {lineno}: record is not valid JSON')
            continue
        if not isinstance(record, dict):
            errors.append(f'line {lineno}: record is not a JSON object')
            continue
        if not isinstance(record.get('hash'), str) or not isinstance(record.get('prev_hash'), str):
            if chain_started:
                errors.append(f'line {lineno}: unhashed record after chained record')
            continue
        chain_started = True
        if record['prev_hash'] != prev_hash:
            errors.append(f'line {lineno}: prev_hash mismatch (chain broken, reordered or spliced)')
        if record['hash'] != _audit_record_hash(record):
            errors.append(f'line {lineno}: record hash mismatch (record tampered)')
        prev_hash = record['hash']
        last_hash = record['hash']
        entries += 1
    anchor_value = None
    try:
        anchor_value = head_path.read_text(encoding='utf-8').strip()
    except FileNotFoundError:
        anchor_value = None
    except OSError as exc:
        errors.append(f'read audit head anchor failed: {exc}')
    if anchor_value:
        if last_hash is None:
            errors.append('audit head anchor present but no chained record survives (tail fully truncated)')
        elif anchor_value != last_hash:
            errors.append('audit head anchor mismatch (truncated tail)')
    return {
        'ok': not errors,
        'entries': entries,
        'anchor': bool(anchor_value),
        'error': '; '.join(errors) if errors else '',
    }


def audit_verify_cli(log_path=None):
    """ms audit-verify implementation: print the verdict, return exit code."""
    result = audit_verify(log_path)
    if result.get('ok'):
        anchor = 'anchored' if result.get('anchor') else 'no anchor (pre-B3 log)'
        print(f"audit chain OK: {result.get('entries', 0)} chained entries ({anchor})")
        return 0
    print(f"audit chain FAILED: {result.get('error') or 'unknown error'}", file=sys.stderr)
    return 1

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
FORBIDDEN_PASSWORD_CHARS = ('\r', '\n', '\x00')


def _password_context_tokens(context):
    """Identifiers a password must not embed: username, email, local part."""
    values = context if isinstance(context, (list, tuple, set)) else (context,)
    tokens = set()
    for value in values:
        if not value:
            continue
        value = str(value).lower()
        tokens.add(value)
        if '@' in value:
            local, _, domain = value.partition('@')
            if len(local) >= 3:
                tokens.add(local)
            if len(domain) >= 3:
                tokens.add(domain)
    return {t for t in tokens if len(t) >= 3}


def _has_weak_run(password):
    """Three or more equal or consecutive (asc/desc) code points, e.g. aaa/123/cba."""
    for i in range(len(password) - 2):
        a, b, c = (ord(ch) for ch in password[i:i + 3])
        if a == b == c or (b == a + 1 and c == b + 1) or (b == a - 1 and c == b - 1):
            return True
    return False


def validate_mailbox_password(password, context=None):
    """Single source of truth for the mailbox and administrator password policy.

    Previously spelled out inline in three modules, with only one of them also
    rejecting control characters -- so a password containing a NUL byte was
    accepted on the admin path and rejected on the mailbox path.

    Policy: 12-256 characters, at least one letter and one digit, no control
    characters, no 3+ equal/sequential run, and none of the identity tokens
    from *context* (username / email / local part) embedded in it. `context`
    may be a single string or an iterable of them.
    """
    if not isinstance(password, str) or not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(
            f'password must contain {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters'
        )
    if any(ch in password for ch in FORBIDDEN_PASSWORD_CHARS):
        raise ValueError('password contains forbidden control characters')
    if not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
        raise ValueError('password must contain both letters and digits')
    if _has_weak_run(password):
        raise ValueError('password must not contain three or more equal or consecutive characters')
    lowered = password.lower()
    for token in _password_context_tokens(context):
        if token in lowered:
            raise ValueError('password must not contain the account name or email address')
    return password


def validate_legacy_password_input(password):
    """Format-only check for paths that *authenticate* with an already-set
    password rather than choosing a new one.

    Tightening the set-time policy must not lock out mailboxes created under
    the old 8-character minimum: their existing passwords stay usable, only
    newly chosen ones have to meet the current bar.
    """
    if not isinstance(password, str) or not 1 <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(f'password must contain 1-{MAX_PASSWORD_LENGTH} characters')
    if any(ch in password for ch in FORBIDDEN_PASSWORD_CHARS):
        raise ValueError('password contains forbidden control characters')
    return password


_warned = set()


def warn(context: str, exc: BaseException | None = None) -> None:
    """Report a non-fatal failure once per unique context.

    The helper runs one action per process and its stderr goes straight to the
    caller's journal, so this is observable. It exists because swallowing these
    is how a corrupt config file degrades into "not configured", with nothing
    anywhere saying the file could not be parsed.
    """
    try:
        key = context if exc is None else f'{context}|{type(exc).__name__}'
        if key in _warned:
            return
        detail = ''
        if exc is not None:
            try:
                detail = f': {exc}'
            except Exception:
                # An exception whose __str__ raises must not take the whole
                # report down with it. Losing the detail line is acceptable;
                # losing the context is not, because the context is what an
                # operator greps the journal for.
                detail = f': {type(exc).__name__}'
        sys.stderr.write(f'mailstack: {context} failed{detail}\n')
        try:
            sys.stderr.flush()
        except Exception:
            pass
        # Only mark it reported once the line has actually been written. Marking
        # it first meant a failed write permanently silenced that context.
        _warned.add(key)
    except Exception:
        pass


def safe_int(val, default=0):
    if val is None: return default
    try: return int(str(val).strip())
    except (ValueError, TypeError): return default

def password_record(username, password):
    if not ADMIN_RE.fullmatch(username): raise ValueError('administrator name must be 3-32 safe characters')
    validate_mailbox_password(password, context=username)
    salt = secrets.token_bytes(16); iterations = PBKDF2_ITERATIONS
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, 32)
    return {
        'username': username,
        'algorithm': 'pbkdf2-sha256',
        'iterations': iterations,
        'salt': salt.hex(),
        'hash': digest.hex(),
        'updatedAt': datetime.datetime.now().isoformat()
    }

def admin_public():
    fallback = {
        'username': 'admin', 'passwordConfigured': False,
        'twoFactorEnabled': False, 'recoveryCodesRemaining': 0,
    }
    try:
        c = json.loads(ADMIN_CONFIG.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return fallback
    except Exception as exc:
        # A missing file legitimately means "never configured". A file we cannot
        # parse means the same thing to the caller but is a bug, and it used to be
        # indistinguishable -- the operator just sees a fresh setup screen.
        warn(f'parse admin config {ADMIN_CONFIG}', exc)
        return fallback
    totp_cfg = c.get('totp')
    if not isinstance(totp_cfg, dict):
        totp_cfg = {}
    recovery = totp_cfg.get('recovery')
    return {
        'username': c.get('username', 'admin'),
        'passwordConfigured': bool(c.get('hash')),
        # Read-only 2FA state for the login screen. The TOTP secret itself
        # never appears here: it is returned exactly once, at enrollment.
        'twoFactorEnabled': bool(totp_cfg.get('enabled')),
        'recoveryCodesRemaining': len(recovery) if isinstance(recovery, list) else 0,
    }

def admin_set(data):
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    # locked() uses the `<name>.lock` sidecar while atomic() uses `.<name>.lock`,
    # so holding the lock across the whole read-modify-write cannot deadlock.
    with locked(ADMIN_CONFIG):
        if not password:
            try:
                old = json.loads(ADMIN_CONFIG.read_text(encoding='utf-8'))
                old['username'] = username
                if not ADMIN_RE.fullmatch(username): raise ValueError('invalid administrator name')
                atomic(ADMIN_CONFIG, json.dumps(old, indent=2) + '\n', 0o640)
                return admin_public()
            except FileNotFoundError:
                raise ValueError('password is required for initial setup')
        record = password_record(username, password)
        # A password change must not clobber the 2FA block: the old code wrote
        # the credential-only record over the whole file, silently disabling
        # two-factor on every ordinary password rotation.
        try:
            old = json.loads(ADMIN_CONFIG.read_text(encoding='utf-8'))
            if isinstance(old, dict) and isinstance(old.get('totp'), dict):
                record['totp'] = old['totp']
        except FileNotFoundError:
            pass
        atomic(ADMIN_CONFIG, json.dumps(record, indent=2) + '\n', 0o640)
        try:
            if grp:
                gid = grp.getgrnam('mailstack-admin').gr_gid
                os.chown(ADMIN_CONFIG, 0, gid)
        except Exception as exc:
            # If this fails the admin config can end up unreadable by the service,
            # which surfaces much later as "cannot log in" with no obvious cause.
            warn(f'chown {ADMIN_CONFIG} to group mailstack-admin', exc)
        return admin_public()

def run(args, input=None, timeout=45, check=True):
    bin_name = args[0]
    if not os.path.isabs(bin_name):
        resolved = shutil.which(bin_name)
        if not resolved:
            for sbin in ['/usr/sbin', '/sbin', '/usr/local/sbin', '/usr/local/bin']:
                cand = os.path.join(sbin, bin_name)
                if os.path.exists(cand):
                    resolved = cand; break
        if not resolved:
            if check: raise FileNotFoundError(f"Command '{bin_name}' not found")
            return subprocess.CompletedProcess(args, 1, stdout='', stderr=f"Command '{bin_name}' not found")
        args = [resolved] + list(args[1:])
    try:
        p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as e:
        if check: raise
        return subprocess.CompletedProcess(args, 1, stdout='', stderr=str(e))
    if check and p.returncode: raise RuntimeError((p.stderr or p.stdout or 'command failed')[-2000:])
    return p

def service_ctl(unit, verb):
    if shutil.which('systemctl') and os.path.isdir('/run/systemd/system'):
        return run(['systemctl', verb, unit], check=False)
    elif shutil.which('service'):
        return run(['service', unit, verb], check=False)
    elif shutil.which('rc-service'):
        rc_verb = 'restart' if verb == 'reload' else verb
        return run(['rc-service', unit, rc_verb], check=False)
    elif os.path.exists(f'/etc/init.d/{unit}'):
        return run([f'/etc/init.d/{unit}', verb], check=False)
    elif unit == 'postfix' and shutil.which('postfix'):
        return run(['postfix', verb], check=False)
    elif unit == 'dovecot' and shutil.which('dovecot'):
        return run(['dovecot', verb if verb != 'restart' else 'reload'], check=False)
    elif unit == 'fail2ban' and shutil.which('fail2ban-client'):
        if verb in ('start', 'restart'):
            return run(['fail2ban-client', 'start'], check=False)
        elif verb == 'stop':
            return run(['fail2ban-client', 'stop'], check=False)
        elif verb == 'reload':
            return run(['fail2ban-client', 'reload'], check=False)
    return run(['true'], check=False)

def is_service_active(unit):
    if shutil.which('systemctl') and os.path.isdir('/run/systemd/system'):
        p = run(['systemctl', 'is-active', '--quiet', unit], check=False)
        if p.returncode == 0: return True
    if shutil.which('service'):
        p = run(['service', unit, 'status'], check=False)
        if p.returncode == 0 or 'running' in (p.stdout + p.stderr).lower() or 'is running' in (p.stdout + p.stderr).lower():
            return True
    if shutil.which('rc-service'):
        p = run(['rc-service', unit, 'status'], check=False)
        if p.returncode == 0: return True
    if unit == 'fail2ban':
        if os.path.exists('/var/run/fail2ban/fail2ban.sock') or os.path.exists('/run/fail2ban/fail2ban.sock'):
            return True
        p = run(['fail2ban-client', 'ping'], check=False)
        if p.returncode == 0 and 'pong' in p.stdout.lower(): return True
    p = run(['pgrep', '-f', unit], check=False)
    return p.returncode == 0

def atomic(path, data, mode=0o640):
    """Write *data* to *path* atomically.

    The advisory lock is taken on a sidecar next to the real destination, so
    concurrent writers serialise against each other instead of each locking its
    own private temp file. The requested mode is applied before the rename --
    previously it was accepted and ignored, leaving secret material at the
    process umask.
    """
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name('.' + path.name + '.lock')
    tmp = path.with_suffix(path.suffix + '.tmp')
    lock_handle = None
    try:
        import fcntl
        lock_handle = open(lock_path, 'a+')
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
    except Exception:
        lock_handle = None
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(data)
            f.flush()
            if hasattr(os, 'fsync'):
                os.fsync(f.fileno())
        os.chmod(tmp, mode)
        try:
            if grp:
                gid = grp.getgrnam('mailstack-admin').gr_gid
                os.chown(tmp, -1, gid)
        except Exception:
            pass
        os.replace(tmp, path)
    finally:
        if lock_handle is not None:
            try:
                import fcntl
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_handle.close()

@contextlib.contextmanager
def locked(path):
    """Hold an exclusive advisory lock across a full read-modify-write of *path*.

    atomic() serialises only the final write phase; a load-modify-save sequence
    can still lose updates -- two concurrent recovery-code consumptions could
    each write back a file where the code is still present ("double spend").
    The lock is taken on the sidecar ``<path>.lock`` (a different file from the
    ``.<name>.lock`` sidecar atomic() uses, so holding this lock while atomic()
    writes cannot self-deadlock) and spans the whole critical section.

    POSIX hosts get fcntl.flock; hosts without fcntl fall back to msvcrt byte
    locking, and hosts with neither degrade to no locking (the interface stays
    identical).
    """
    path = pathlib.Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    lock_path = path.with_name(path.name + '.lock')
    handle = None
    acquired = False
    try:
        handle = open(lock_path, 'a+')
    except OSError as exc:
        warn(f'open lock sidecar {lock_path}', exc)
    if handle is not None:
        try:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            acquired = True
        except ImportError:
            try:
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                acquired = True
            except (ImportError, OSError) as exc:
                warn(f'lock {lock_path}', exc)
        except OSError as exc:
            warn(f'lock {lock_path}', exc)
    try:
        yield
    finally:
        if handle is not None:
            if acquired:
                try:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except ImportError:
                    try:
                        import msvcrt
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                except Exception:
                    pass
            handle.close()

def set_dkim_key_permissions(path):
    """Apply the production hardening to a DKIM private key: root:opendkim 0640.

    The OpenDKIM signer needs read access, nobody else does. On development
    hosts without the opendkim group this degrades gracefully but loudly:
    every failure is reported through warn() instead of being swallowed, which
    is how a key silently left at 0600 opendkim:opendkim went unnoticed.
    """
    path = pathlib.Path(path)
    try:
        os.chmod(path, 0o640)
    except OSError as exc:
        warn(f'chmod {path} to 0640', exc)
    if grp is None or not hasattr(os, 'chown'):
        return
    try:
        gid = grp.getgrnam('opendkim').gr_gid
        os.chown(path, 0, gid)
    except (KeyError, OSError) as exc:
        warn(f'chown {path} to root:opendkim', exc)

def file_snapshot(path):
    p = pathlib.Path(path)
    return {'exists': p.exists(), 'content': p.read_bytes() if p.exists() else b'', 'mode': p.stat().st_mode & 0o777 if p.exists() else None}

def file_restore(path, snapshot, mode=None):
    p = pathlib.Path(path)
    if not snapshot['exists']:
        p.unlink(missing_ok=True); return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(snapshot['content'])
    if hasattr(os, 'chmod'):
        os.chmod(p, mode or snapshot['mode'] or 0o640)

def rows(path):
    try:
        return [x.split() for x in pathlib.Path(path).read_text(encoding='utf-8').splitlines() if x.strip() and not x.lstrip().startswith('#')]
    except FileNotFoundError:
        return []

def postmap(path):
    postmap_bin = shutil.which('postmap') or '/usr/sbin/postmap'
    if os.path.exists(postmap_bin) or shutil.which('postmap'):
        run([postmap_bin, str(path)], check=False)
    postfix_bin = shutil.which('postfix') or '/usr/sbin/postfix'
    if os.path.exists(postfix_bin) or shutil.which('postfix'):
        run([postfix_bin, 'check'], check=False)
        service_ctl('postfix', 'reload')

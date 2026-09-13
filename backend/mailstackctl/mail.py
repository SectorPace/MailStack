# MailStack Mail, Domain, User, Alias, Queue and Loopback Engine
import os, pathlib, re, json, datetime, secrets, shutil, time
try:
    import pwd, grp
except ImportError:
    pwd = grp = None
from .core import warn
from .core import (
    ETC, DOM, ALS, DOMAIN_RE, USER_RE, ADDRESS_RE, QUEUE_RE,
    rows, atomic, postmap, run, service_ctl
)
from .security import validate_mailbox_password

MANAGED_USERS = ETC / 'managed-users.json'
# The email→unixUser registry must be readable by the webmail process (login
# lookup), which is deliberately NOT in the mailstack-admin group -- putting it
# in /etc/mailstack (0750 root:mailstack-admin) made every webmail login fail
# closed. It contains no secrets (addresses and account names only), so it
# lives in a world-traversable dir as root:mailstack-webmail 0640.
VAR_LIB = pathlib.Path('/var/lib/mailstack')
MANAGED_MAILBOXES = VAR_LIB / 'managed-mailboxes.json'
PROTECTED_USERS = {'root', 'daemon', 'bin', 'sys', 'sync', 'mail', 'postfix', 'dovecot', 'nobody', 'mailstack-admin'}
SESSION_EPOCH_FILE = pathlib.Path('/var/lib/mailstack/webmail-session-epoch.json')


def _bump_webmail_session_epoch(user):
    """Invalidate every outstanding webmail session for *user*.

    Password changes and account lock/unlock must kill live sessions, not just
    future logins. The webmail process polls this epoch map and drops any
    session minted before the user's epoch. Failure is non-fatal (the session
    TTL still bounds lifetime) but always reported.
    """
    try:
        SESSION_EPOCH_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            epochs = json.loads(SESSION_EPOCH_FILE.read_text(encoding='utf-8'))
            if not isinstance(epochs, dict):
                epochs = {}
        except Exception:
            epochs = {}
        epochs[str(user)] = int(time.time())
        atomic(SESSION_EPOCH_FILE, json.dumps(epochs, indent=2) + '\n', 0o640)
        if grp:
            try:
                os.chown(SESSION_EPOCH_FILE, 0, grp.getgrnam('mailstack-webmail').gr_gid)
            except Exception as exc:
                warn('chown webmail session epoch file to mailstack-webmail', exc)
    except Exception as exc:
        warn('bump webmail session epoch', exc)

def managed_users():
    try: return set(json.loads(MANAGED_USERS.read_text(encoding='utf-8')))
    except Exception: return set()

def save_managed(items):
    atomic(MANAGED_USERS, json.dumps(sorted(items), indent=2) + '\n', 0o640)

def managed_mailboxes():
    try: return json.loads(MANAGED_MAILBOXES.read_text(encoding='utf-8'))
    except Exception: return []

def save_mailboxes(items):
    atomic(MANAGED_MAILBOXES, json.dumps(items, indent=2) + '\n', 0o640)
    if grp:
        try:
            os.chown(MANAGED_MAILBOXES, 0, grp.getgrnam('mailstack-webmail').gr_gid)
        except Exception as exc:
            warn('chown managed mailboxes registry to mailstack-webmail', exc)

def account_locked(name):
    p = run(['passwd', '-S', name], check=False)
    fields = p.stdout.split()
    return len(fields) > 1 and fields[1] in ('L', 'LK')

def domain_list():
    aliases_list = rows(ALS)
    out = []
    for i, r in enumerate(rows(DOM)):
        d = r[0]
        alias_count = sum(1 for a in aliases_list if a and a[0].endswith('@' + d))
        mailbox_count = sum(1 for x in managed_mailboxes() if str(x.get('email', '')).endswith('@' + d))
        out.append({
            'id': d, 'name': d, 'createdAt': '', 'mxStatus': 'pending', 'spfStatus': 'pending',
            'dkimStatus': 'pending', 'dmarcStatus': 'pending', 'mailboxesCount': mailbox_count,
            'mailboxesMax': 0, 'aliasesCount': alias_count, 'status': 'pending',
            'statusTextZh': '等待 DNS 校验', 'statusTextEn': 'DNS check pending',
            'dkimSelector': 'mail', 'dkimKeySize': 2048
        })
    return out

def domain_add(data):
    d = str(data.get('name') or data.get('domain') or '').strip().lower()
    if not DOMAIN_RE.fullmatch(d): raise ValueError('invalid domain')
    rr = rows(DOM)
    atomic(DOM, '\n'.join(' '.join(x) for x in rr if x[0] != d) + ('\n' if rr else '') + d + ' OK\n')
    postmap(DOM)
    return domain_list()

def domain_delete(data):
    d = str(data.get('id') or data.get('domain') or data.get('name') or '').strip().lower()
    if not DOMAIN_RE.fullmatch(d): raise ValueError('invalid domain')
    atomic(DOM, '\n'.join(' '.join(x) for x in rows(DOM) if x[0] != d) + '\n')
    atomic(ALS, '\n'.join(' '.join(x) for x in rows(ALS) if not x[0].endswith('@' + d)) + '\n')
    postmap(DOM)
    postmap(ALS)
    return domain_list()

def users():
    out = []
    for item in managed_mailboxes():
        name = str(item.get('unixUser', ''))
        email = str(item.get('email', ''))
        if pwd:
            try: u = pwd.getpwnam(name)
            except KeyError: continue
        out.append({
            'id': name, 'username': name, 'displayName': item.get('displayName') or name,
            'email': email, 'domain': email.split('@')[-1] if '@' in email else '',
            'aliasesCount': 0, 'quotaUsedGb': 0, 'quotaMaxGb': 0, 'lastLoginTime': '',
            'lastLoginIp': '', 'status': 'disabled' if account_locked(name) else 'enabled',
            'role': 'mailbox'
        })
    return out

def user_add(data):
    email = str(data.get('email', '')).strip().lower()
    u = str(data.get('username') or (email.split('@')[0] if '@' in email else '')).strip().lower()
    if not USER_RE.fullmatch(u) or not ADDRESS_RE.fullmatch(email): raise ValueError('invalid mailbox identity')
    # 上下文 = 用户名与完整地址：密码里出现两者任一即拒绝
    password = validate_mailbox_password(data.get('password', ''), context=(u, email))
    if email.split('@', 1)[1] not in {x[0] for x in rows(DOM)}: raise ValueError('mailbox domain is not managed')
    if any(str(x.get('email', '')).lower() == email for x in managed_mailboxes()): raise ValueError('mailbox already exists')
    
    mail_group = 'mail'
    if grp:
        mail_group = 'mail' if 'mail' in [g.gr_name for g in grp.getgrall()] else 'users'
    nologin_bin = shutil.which('nologin') or ('/usr/sbin/nologin' if os.path.exists('/usr/sbin/nologin') else '/sbin/nologin' if os.path.exists('/sbin/nologin') else '/bin/false')
    useradd_bin = shutil.which('useradd')
    adduser_bin = shutil.which('adduser')
    if useradd_bin:
        r = run([useradd_bin, '-m', '-N', '-g', mail_group, '-s', nologin_bin, u], check=False)
        if r.returncode != 0:
            r = run([useradd_bin, '-m', '-s', nologin_bin, u], check=False)
        if r.returncode != 0:
            raise RuntimeError(f"useradd failed to create mailbox user: {r.stderr or r.stdout}")
    elif adduser_bin:
        r = run([adduser_bin, '-D', '-s', nologin_bin, '-G', mail_group, u], check=False)
        if r.returncode != 0:
            r = run([adduser_bin, '-D', '-s', nologin_bin, u], check=False)
        if r.returncode != 0:
            raise RuntimeError(f"adduser failed to create mailbox user: {r.stderr or r.stdout}")
    else:
        raise RuntimeError('Neither useradd nor adduser command found')
        
    chpasswd_bin = shutil.which('chpasswd')
    if chpasswd_bin:
        run([chpasswd_bin], input=u + ':' + password + '\n')
    else:
        run(['passwd', u], input=password + '\n' + password + '\n')
    if pwd:
        try:
            info = pwd.getpwnam(u)
            md = pathlib.Path(info.pw_dir) / 'Maildir'
            for d in ('cur', 'new', 'tmp'):
                (md / d).mkdir(parents=True, exist_ok=True)
            os.chmod(info.pw_dir, 0o750)
            for root_dir, dirs, files in os.walk(str(md)):
                os.chown(root_dir, info.pw_uid, info.pw_gid)
                os.chmod(root_dir, 0o770)
                for filename in files:
                    file_path = os.path.join(root_dir, filename)
                    os.chown(file_path, info.pw_uid, info.pw_gid)
                    os.chmod(file_path, 0o660)
        except Exception as exc:
            warn(f'set Maildir ownership for {u}', exc)
    managed = managed_users()
    managed.add(u)
    save_managed(managed)
    boxes = managed_mailboxes()
    boxes.append({'email': email, 'unixUser': u, 'displayName': str(data.get('displayName', ''))[:80]})
    save_mailboxes(boxes)
    return users()

def user_del(data):
    u = str(data.get('id', ''))
    if not USER_RE.fullmatch(u) or u in PROTECTED_USERS or u not in managed_users():
        raise ValueError('user is protected or not managed by MailStack')
    if pwd:
        info = pwd.getpwnam(u)
        if info.pw_uid < 1000: raise ValueError('system account deletion is forbidden')
    userdel_bin = shutil.which('userdel')
    if userdel_bin:
        r = run([userdel_bin, '-r', u], check=False)
        if r.returncode != 0: run([userdel_bin, u], check=False)
    elif shutil.which('deluser'):
        deluser_bin = shutil.which('deluser')
        r = run([deluser_bin, '--remove-home', u], check=False)
        if r.returncode != 0: run([deluser_bin, u], check=False)
    managed = managed_users()
    managed.discard(u)
    save_managed(managed)
    save_mailboxes([x for x in managed_mailboxes() if x.get('unixUser') != u])
    return users()

def user_status(data):
    u = str(data.get('id', ''))
    enabled = bool(data.get('enabled'))
    if u not in managed_users() or u in PROTECTED_USERS:
        raise ValueError('user is protected or not managed by MailStack')
    run(['passwd', '-u' if enabled else '-l', u])
    _bump_webmail_session_epoch(u)
    return users()

def user_password(data):
    u = str(data.get('id', ''))
    if u in PROTECTED_USERS or u not in managed_users():
        raise ValueError('mailbox is protected or not managed by MailStack')
    password = validate_mailbox_password(data.get('password', ''), context=u)
    chpasswd_bin = shutil.which('chpasswd')
    if chpasswd_bin:
        run([chpasswd_bin], input=u + ':' + password + '\n')
    else:
        run(['passwd', u], input=password + '\n' + password + '\n')
    _bump_webmail_session_epoch(u)
    return {'updated': True}

def aliases():
    return [{'id': r[0], 'source': r[0], 'domain': r[0].split('@')[-1], 'destinations': r[1:], 'description': 'Postfix virtual alias', 'enabled': True, 'createdAt': ''} for r in rows(ALS) if len(r) > 1]

def alias_add(data):
    src = str(data.get('source', '')).strip().lower()
    raw_dests = data.get('destinations')
    # A bare string would iterate character by character, and single letters
    # satisfy USER_RE, so "ab" silently became two destinations "a" and "b".
    if isinstance(raw_dests, (list, tuple)):
        dests = [str(item).strip().lower() for item in raw_dests]
    else:
        dests = []
    if not ADDRESS_RE.fullmatch(src):
        raise ValueError('invalid alias')
    # ADDRESS_RE has no capturing group; the domain has to be split out by hand.
    if not DOMAIN_RE.fullmatch(src.rsplit('@', 1)[1]):
        raise ValueError('invalid alias domain')
    if not dests:
        raise ValueError('invalid alias: at least one destination is required')
    # Validating each destination also rules out the newline and space injection
    # that would add arbitrary entries to the Postfix alias table.
    if not all(USER_RE.fullmatch(x) or ADDRESS_RE.fullmatch(x) for x in dests):
        raise ValueError('invalid alias destination')
    if len(dests) > 50:
        raise ValueError('invalid alias: too many destinations')
    rr = [x for x in rows(ALS) if x[0] != src]
    rr.append([src] + dests)
    atomic(ALS, '\n'.join(' '.join(x) for x in rr) + '\n')
    postmap(ALS)
    return aliases()

def alias_del(data):
    src = str(data.get('id', '')).strip().lower()
    # Validated like alias_add: an unvalidated id is written straight into the
    # alias table, and a newline in it injects entries rather than removing one.
    if not ADDRESS_RE.fullmatch(src) or not DOMAIN_RE.fullmatch(src.rsplit('@', 1)[1]):
        raise ValueError('invalid alias')
    atomic(ALS, '\n'.join(' '.join(x) for x in rows(ALS) if x[0] != src) + '\n')
    postmap(ALS)
    return aliases()

def queue():
    if shutil.which('postqueue'):
        p = run(['postqueue', '-j'], check=False)
        out = []
        for line in p.stdout.splitlines():
            try:
                q = json.loads(line)
                rec = (q.get('recipients') or [{}])[0]
                out.append({
                    'id': q.get('queue_id'), 'queueId': q.get('queue_id'), 'sender': q.get('sender', ''),
                    'recipient': rec.get('address', ''), 'sizeBytes': q.get('message_size', 0),
                    'arrivalDate': datetime.datetime.fromtimestamp(q.get('arrival_time', 0)).isoformat() if q.get('arrival_time') else '',
                    'status': 'deferred' if rec.get('delay_reason') else 'active',
                    'errorReason': rec.get('delay_reason', ''), 'retryCount': 0
                })
            except Exception as exc:
                warn('parse a mailq queue entry', exc)
        return out
    return []

def queue_action(data):
    qid = str(data.get('id', '')).rstrip('*!')
    verb = str(data.get('verb', 'retry'))
    if verb not in ('retry', 'delete', 'flush'): raise ValueError('invalid queue action')
    # flush 是全队列操作，不针对单个 id；其余 verb 必须带合法 id。
    # 此前空 id 会跳过校验直接落到 `postsuper -d ''`（等价于对空 id 执行删除）。
    if verb == 'flush':
        run(['postqueue', '-f'])
        return queue()
    if not qid or not QUEUE_RE.fullmatch(qid): raise ValueError('invalid queue id')
    if verb == 'retry': run(['postqueue', '-i', qid])
    else: run(['postsuper', '-d', qid])
    return queue()

def mail_test_loopback(data):
    recipient = str(data.get('recipient', '')).strip().lower()
    managed = [x.get('email', '').lower() for x in managed_mailboxes() if x.get('email')]
    domains = [d.get('name', '').lower() for d in domain_list() if d.get('name')]
    if not recipient:
        if managed: recipient = managed[0]
        else:
            recipient = f"postmaster@{domains[0]}" if domains else "test@localhost"
    if not ADDRESS_RE.fullmatch(recipient): raise ValueError('invalid recipient email address')
    
    # Strict loopback scope.
    #
    # The old guard was `if managed and ...`. On a fresh install -- no mailboxes
    # yet -- `managed` was empty, so the anti-relay check was skipped entirely
    # and this action would deliver to any address on the internet. It is a
    # loopback test: its job is to prove local delivery works, so the recipient
    # domain must be one this server is authoritative for, regardless of
    # whether any mailbox happens to exist yet.
    rec_domain = recipient.split('@')[1] if '@' in recipient else 'localhost'
    if not domains:
        raise ValueError('Loopback test requires at least one managed domain')
    if rec_domain != 'localhost' and rec_domain not in domains:
        raise ValueError(f'Loopback test recipient must belong to a managed domain ({recipient})')
            
    sender = f"mailer-daemon@{recipient.split('@')[1]}" if '@' in recipient else "mailer-daemon@localhost"
    token = f"ms-loopback-{secrets.token_hex(12)}"
    subject = f"MailStack Loopback Verification [{token}]"
    body = f"From: MailStack Diagnostic <{sender}>\nTo: <{recipient}>\nSubject: {subject}\nX-MailStack-Test-Token: {token}\nContent-Type: text/plain; charset=utf-8\nDate: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')}\n\nThis is an automated loopback test message generated by MailStack Doctor.\nToken: {token}\nTimestamp: {datetime.datetime.now().isoformat()}\n"
    
    sendmail_bin = shutil.which('sendmail') or ('/usr/sbin/sendmail' if os.path.exists('/usr/sbin/sendmail') else '/usr/lib/sendmail')
    if not sendmail_bin: raise RuntimeError('sendmail binary is not installed')
    
    start_t = datetime.datetime.now()
    p = run([sendmail_bin, '-f', sender, '--', recipient], input=body, timeout=20, check=False)
    if p.returncode != 0: raise RuntimeError(f"sendmail failed: {p.stderr or p.stdout}")
    
    maildir_found = False
    u = recipient.split('@')[0]
    possible_maildirs = [pathlib.Path(f'/home/{u}/Maildir/new'), pathlib.Path(f'/home/{u}/Maildir/cur')]
    if '@' in recipient: possible_maildirs.append(pathlib.Path(f'/var/vmail/{recipient.split("@")[1]}/{u}/new'))
    for md in [p for p in possible_maildirs if p and p.exists()]:
        for mf in md.glob('*'):
            try:
                if token in mf.read_text(encoding='utf-8', errors='replace'): maildir_found = True; break
            except Exception:
                # Expected: Maildir contents churn during the scan and spool files
                # may be unreadable. An unreadable file means "no match", not error.
                pass
        if maildir_found: break
    elapsed_ms = max(1, round((datetime.datetime.now() - start_t).total_seconds() * 1000))
    return {'success': True, 'token': token, 'sender': sender, 'recipient': recipient, 'deliveryTimeMs': elapsed_ms, 'maildirDelivered': maildir_found, 'message': f'Loopback message submitted to Postfix ({elapsed_ms}ms)'}

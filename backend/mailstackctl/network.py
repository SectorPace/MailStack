# MailStack network probes, identity setup and authoritative DNS verification.
import datetime
import ipaddress
import json
import os
import pathlib
import re
import shutil
import smtplib
import socket
import ssl
import time

from .ai import private_network_enabled, validate_outbound_ip
from .certs import certs
from .core import ADDRESS_RE, DOMAIN_RE, ETC, USER_RE, atomic, is_service_active, run, service_ctl, set_dkim_key_permissions, validate_legacy_password_input
from .mail import account_locked, domain_list, managed_mailboxes

SETUP_CONFIG = ETC / 'setup.json'
OPENDKIM_ROOT = pathlib.Path('/etc/opendkim')


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise ValueError('invalid server IP address') from exc


def dig(name, record_type):
    if not shutil.which('dig'):
        return []
    result = run(['dig', '+short', record_type, name], check=False, timeout=15)
    return [line.strip().strip('"') for line in result.stdout.splitlines() if line.strip()]


def _resolve_probe_targets(host, port, allow_private=False):
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f'Unable to resolve probe target: {host}') from exc
    resolved = []
    for item in addresses:
        address = validate_outbound_ip(item[4][0], allow_private=allow_private, context_name='probe target')
        if address not in resolved:
            resolved.append(address)
    return resolved


def network_check_port(data):
    port = int(data.get('port') or 25)
    if port <= 0 or port > 65535:
        raise ValueError('invalid port')
    host = str(data.get('host', '')).strip()
    if host:
        targets = [host]
    else:
        configured = os.environ.get('MAILSTACK_PORT_PROBE_TARGETS', '')
        targets = [item.strip() for item in configured.split(',') if item.strip()] or ['smtp.gmail.com', 'smtp.qq.com', 'outlook-com.olc.protection.outlook.com']
    results = []
    for target in targets[:8]:
        started = time.monotonic()
        try:
            addresses = _resolve_probe_targets(target, port, allow_private=False)
        except ValueError as exc:
            results.append({'target': target, 'port': port, 'open': False, 'error': str(exc), 'latencyMs': round((time.monotonic() - started) * 1000)})
            continue
        for address in addresses:
            sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            try:
                sock.connect((address, port))
                results.append({'target': target, 'ip': address, 'port': port, 'open': True, 'latencyMs': max(1, round((time.monotonic() - started) * 1000))})
                break
            except OSError as exc:
                results.append({'target': target, 'ip': address, 'port': port, 'open': False, 'error': type(exc).__name__, 'latencyMs': max(1, round((time.monotonic() - started) * 1000))})
            finally:
                sock.close()
        if any(item.get('target') == target and item.get('open') for item in results):
            break
    best = next((item for item in results if item.get('open')), results[0] if results else {'open': False, 'port': port})
    is_open = bool(best.get('open'))
    return {
        'port': port,
        'open': is_open,
        'status': 'open' if is_open else 'blocked',
        'target': best.get('target', ''),
        'latencyMs': best.get('latencyMs', 0),
        'details': results,
        'message': f'Outbound port {port} is {"OPEN" if is_open else "BLOCKED"}',
    }


def setup_identity(data):
    domain = str(data.get('domain', '')).strip().lower()
    host = str(data.get('mailHost', '')).strip().lower()
    ip = valid_ip(data.get('serverIp', ''))
    if not DOMAIN_RE.fullmatch(domain) or not DOMAIN_RE.fullmatch(host) or not host.endswith('.' + domain):
        raise ValueError('invalid domain or mail hostname')
    run(['postconf', '-e', f'myhostname = {host}'])
    run(['postconf', '-e', f'mydomain = {domain}'])
    if shutil.which('postfix'):
        run(['postfix', 'check'], check=False)
    service_ctl('postfix', 'reload')
    keydir = OPENDKIM_ROOT / 'keys' / domain
    keydir.mkdir(parents=True, exist_ok=True)
    public_key = ''
    if shutil.which('opendkim-genkey'):
        run(['opendkim-genkey', '-b', '2048', '-D', str(keydir), '-d', domain, '-s', 'mail'], check=False)
        private_key = keydir / 'mail.private'
        if private_key.exists():
            set_dkim_key_permissions(private_key)
        public_file = keydir / 'mail.txt'
        if public_file.exists():
            # rc2: strip quotes/whitespace first -- opendkim-genkey splits long
            # keys across quoted lines, and a naive match on the raw text used
            # to truncate the public key (breaking DKIM DNS records).
            flat = re.sub(r'["\s]', '', public_file.read_text(encoding='utf-8'))
            match = re.search(r'p=([A-Za-z0-9+/=]+)', flat)
            public_key = match.group(1) if match else ''
        atomic(OPENDKIM_ROOT / 'key.table', f'mail._domainkey.{domain} {domain}:mail:{keydir}/mail.private\n', 0o640)
        atomic(OPENDKIM_ROOT / 'signing.table', f'*@{domain} mail._domainkey.{domain}\n', 0o640)
        trusted_file = OPENDKIM_ROOT / 'trusted.hosts'
        current = trusted_file.read_text(encoding='utf-8') if trusted_file.exists() else '127.0.0.1\n::1\nlocalhost\n'
        if domain not in current.splitlines():
            atomic(trusted_file, current.rstrip() + '\n' + domain + '\n', 0o640)
        service_ctl('opendkim', 'restart')
        service_ctl('postfix', 'reload')
    config = {
        'domain': domain,
        'mailHost': host,
        'serverIp': ip,
        'postmaster': str(data.get('postmaster') or 'postmaster@' + domain),
        'dkimSelector': 'mail',
        'dkimPublicKey': public_key,
        'updatedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    atomic(SETUP_CONFIG, json.dumps(config, indent=2) + '\n', 0o600)
    return {'applied': True, 'identity': config, 'dkimPublicKey': public_key}


def setup_dns_verify(data):
    domain = str(data.get('domain', '')).strip().lower()
    host = str(data.get('mailHost', '')).strip().lower()
    ip = valid_ip(data.get('serverIp', ''))
    selector = str(data.get('dkimSelector', 'mail')).strip()
    if not DOMAIN_RE.fullmatch(domain) or not DOMAIN_RE.fullmatch(host) or not host.endswith('.' + domain):
        raise ValueError('invalid domain or mail hostname')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', selector):
        raise ValueError('invalid DKIM selector')
    expected_spf = str(data.get('expectedSpf', '')).strip()
    relay = str(data.get('selectedRelay', 'direct')).strip().lower()
    ses_from = str(data.get('sesMailFrom', '')).strip()
    ses_region = str(data.get('sesRegion', 'us-east-1')).strip()
    observed = {
        'a': dig(host, 'A'),
        'mx': dig(domain, 'MX'),
        'spf': dig(domain, 'TXT'),
        'dkim': dig(f'{selector}._domainkey.{domain}', 'TXT'),
        'dmarc': dig(f'_dmarc.{domain}', 'TXT'),
    }
    spf_records = [item for item in observed['spf'] if item.startswith('v=spf1')]
    checks = {
        'a': ip in observed['a'],
        'mx': any(host in item for item in observed['mx']),
        'spfSingle': len(spf_records) == 1,
        'spfExpected': bool(expected_spf) and expected_spf in spf_records,
        'dkim': any('v=DKIM1' in item and re.search(r'p=[A-Za-z0-9+/]{100,}={0,2}', item) for item in observed['dkim']),
        'dmarc': any(item.startswith('v=DMARC1') and 'rua=mailto:' in item for item in observed['dmarc']),
    }
    if relay == 'ses':
        observed['sesMx'] = dig(ses_from, 'MX')
        observed['sesSpf'] = dig(ses_from, 'TXT')
        ses_spf = [item for item in observed['sesSpf'] if item.startswith('v=spf1')]
        checks['sesMailFromMx'] = any(f'feedback-smtp.{ses_region}.amazonses.com' in item for item in observed['sesMx'])
        checks['sesMailFromSpf'] = len(ses_spf) == 1 and 'include:amazonses.com' in ses_spf[0]
    return {'verified': all(checks.values()), 'checks': checks, 'observed': observed, 'spfRecordCount': len(spf_records)}


def validate_relay(data):
    host = str(data.get('host', '')).strip().lower()
    port = int(data.get('port', 587))
    user = str(data.get('username', ''))
    password = str(data.get('password', ''))
    mode = str(data.get('tlsMode', 'STARTTLS')).upper()
    requested_private = bool(data.get('allowPrivateNetwork', False))
    if requested_private and not private_network_enabled():
        raise ValueError('Private SMTP relay access is disabled by deployment policy')
    allow_private = private_network_enabled()
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host) or host.startswith('.') or host.endswith('.') or '..' in host:
        raise ValueError('invalid relay host')
    if port not in (25, 465, 587, 2525) or mode not in ('STARTTLS', 'SSL/TLS'):
        raise ValueError('TLS is required for relay endpoint')
    if len(user) > 256 or len(password) > 4096 or any(char in user + password for char in ('\r', '\n', '\x00')):
        raise ValueError('invalid relay credentials')
    addresses = _resolve_probe_targets(host, port, allow_private=allow_private)
    return host, port, user, password, mode, allow_private, addresses


def _direct_delivery_probe():
    """rc2: direct-delivery connectivity probe.

    Probes the LOCAL Postfix on the fixed loopback endpoint. This target is a
    hardcoded constant owned by the deployment, not user input, so the SSRF
    guard does not apply. Uses plain SMTP (EHLO only) because the local TLS
    certificate may not be issued yet (wizard step order).
    """
    started = time.monotonic()
    stages = []
    client = None
    try:
        client = smtplib.SMTP('127.0.0.1', 25, timeout=10)
        code, message = client.ehlo()
        stages.append({'stage': 'connect', 'ok': 200 <= code < 400, 'code': code, 'banner': str(message)[:200]})
        client.quit()
        connected = all(item.get('ok') for item in stages)
        return {'connected': connected, 'stage': stages[-1]['stage'], 'direct': True,
                'latencyMs': round((time.monotonic() - started) * 1000), 'stages': stages}
    except Exception as exc:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        stages.append({'stage': 'failed', 'ok': False, 'message': type(exc).__name__})
        raise RuntimeError(f'local Postfix probe failed: {exc}') from exc


def setup_relay(data):
    if data.get('direct') is True:
        return _direct_delivery_probe()
    host, port, user, password, mode, allow_private, addresses = validate_relay(data)
    pinned_ip = addresses[0]
    stages = [{'stage': 'dns', 'ok': True, 'addresses': addresses[:8], 'pinnedAddress': pinned_ip}]
    started = time.monotonic()

    class PinnedSMTP(smtplib.SMTP):
        def _get_socket(self, connect_host, connect_port, timeout):
            return socket.create_connection((pinned_ip, connect_port), timeout, self.source_address)

    class PinnedSMTPSSL(smtplib.SMTP_SSL):
        def _get_socket(self, connect_host, connect_port, timeout):
            raw = socket.create_connection((pinned_ip, connect_port), timeout, self.source_address)
            return self.context.wrap_socket(raw, server_hostname=host)

    client = None
    try:
        client = PinnedSMTPSSL(host, port, timeout=20, context=ssl.create_default_context()) if mode == 'SSL/TLS' or port == 465 else PinnedSMTP(host, port, timeout=20)
        code, message = client.ehlo()
        stages.append({'stage': 'connect', 'ok': 200 <= code < 400, 'code': code, 'banner': str(message)[:200]})
        if mode == 'STARTTLS':
            code, _ = client.starttls(context=ssl.create_default_context())
            stages.append({'stage': 'tls', 'ok': 200 <= code < 400, 'code': code})
            client.ehlo()
        else:
            stages.append({'stage': 'tls', 'ok': True, 'implicit': True})
        if user or password:
            if not user or not password:
                raise ValueError('SMTP username and password must be provided together')
            client.login(user, password)
            stages.append({'stage': 'auth', 'ok': True})
        else:
            stages.append({'stage': 'auth', 'ok': True, 'skipped': True})
        client.quit()
        return {'connected': all(item['ok'] for item in stages), 'stage': stages[-1]['stage'], 'latencyMs': round((time.monotonic() - started) * 1000), 'stages': stages}
    except Exception as exc:
        if client is not None:
            try:
                client.close()
            except Exception:
                # Best effort: the connection that failed is the one being closed,
                # and the original failure is re-raised below with its own detail.
                pass
        stages.append({'stage': 'failed', 'ok': False, 'message': type(exc).__name__})
        raise RuntimeError('SMTP relay test failed') from exc


def setup_relay_apply(data):
    host, port, user, password, mode, allow_private, _addresses = validate_relay(data)
    tested = setup_relay(data)
    relay = f'[{host}]:{port}'
    secret_path = pathlib.Path('/etc/postfix/sasl_passwd')
    backup = secret_path.read_bytes() if secret_path.exists() else None
    prior = {key: run(['postconf', '-h', key], check=False).stdout.strip() for key in ('relayhost', 'smtp_sasl_auth_enable', 'smtp_sasl_password_maps', 'smtp_sasl_security_options', 'smtp_tls_security_level')}
    try:
        atomic(secret_path, f'{relay} {user}:{password}\n', 0o600)
        run(['postmap', str(secret_path)], check=False)
        os.chmod(secret_path, 0o600)
        database = pathlib.Path(str(secret_path) + '.db')
        if database.exists(): os.chmod(database, 0o600)
        values = {'relayhost': relay, 'smtp_sasl_auth_enable': 'yes' if user else 'no', 'smtp_sasl_password_maps': 'hash:/etc/postfix/sasl_passwd' if user else '', 'smtp_sasl_security_options': 'noanonymous', 'smtp_tls_security_level': 'encrypt'}
        for key, value in values.items(): run(['postconf', '-e', f'{key} = {value}'], check=False)
        if shutil.which('postfix'): run(['postfix', 'check'], check=False)
        service_ctl('postfix', 'reload')
        observed = run(['postconf', '-h', 'relayhost'], check=False).stdout.strip()
        if observed != relay: raise RuntimeError('Postfix relayhost verification failed')
        return {'applied': True, 'relayhost': observed, 'test': tested}
    except Exception:
        if backup is None: secret_path.unlink(missing_ok=True)
        else:
            secret_path.write_bytes(backup)
            os.chmod(secret_path, 0o600)
            run(['postmap', str(secret_path)], check=False)
        for key, value in prior.items(): run(['postconf', '-e', f'{key} = {value}'], check=False)
        if shutil.which('postfix'): run(['postfix', 'check'], check=False)
        service_ctl('postfix', 'reload')
        raise


def setup_send_test(data):
    sender = str(data.get('sender', ''))
    recipient = str(data.get('recipient', ''))
    username = str(data.get('username', ''))
    password = str(data.get('password', ''))
    if not ADDRESS_RE.fullmatch(sender) or not ADDRESS_RE.fullmatch(recipient) or not USER_RE.fullmatch(username):
        raise ValueError('invalid mailbox or sender')
    # This is an *existing* password being replayed to send a test message, not a
    # newly chosen one: apply the format-only check, or mailboxes created under
    # the old 8-character policy could never run the connectivity test.
    validate_legacy_password_input(password)
    if not any(item.get('unixUser') == username and item.get('email') == sender for item in managed_mailboxes()):
        raise ValueError('mail test requires an explicit managed mailbox matching sender')
    if account_locked(username):
        raise ValueError('mailbox is disabled')
    body = f'From: {sender}\nTo: {recipient}\nSubject: MailStack connectivity test\n\nThis message was sent by MailStack setup verification.\n'
    sendmail_bin = shutil.which('sendmail') or '/usr/sbin/sendmail'
    result = run([sendmail_bin, '-f', sender, '--', recipient], input=body, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError('sendmail submission failed')
    return {'queued': True, 'roundTripVerified': False, 'scope': 'local Postfix submission', 'sender': sender, 'recipient': recipient}


def setup_status():
    try:
        config = json.loads(SETUP_CONFIG.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        config = {}
    domains = domain_list()
    payload = {
        'identityConfigured': bool(config),
        'identity': config,
        'postfixActive': is_service_active('postfix'),
        'dovecotActive': is_service_active('dovecot'),
        'dnsVerified': bool(config and domains),
        'tlsInstalled': bool(certs()) or (ETC / 'tls').exists(),
        'mailTestQueued': bool(managed_mailboxes()),
        'pending': [],
    }
    complete = all(payload[key] for key in ('identityConfigured', 'postfixActive', 'dovecotActive', 'dnsVerified', 'tlsInstalled', 'mailTestQueued'))
    return {'status': 'complete' if complete else 'incomplete', 'complete': complete, **payload}

# MailStack TLS certificates and DKIM management.
import datetime
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from .core import DOMAIN_RE, ETC, atomic, run, service_ctl, set_dkim_key_permissions


def parse_cert_openssl(path):
    cert_path = pathlib.Path(path)
    if not cert_path.is_file() or cert_path.is_symlink():
        return None
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-in', str(cert_path), '-noout', '-dates', '-subject', '-issuer'],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode != 0:
            return None
        output = result.stdout
        not_after = re.search(r'notAfter=(.*)', output)
        not_before = re.search(r'notBefore=(.*)', output)
        subject = re.search(r'subject=(.*)', output)
        issuer = re.search(r'issuer=(.*)', output)
        domain = cert_path.parent.name if cert_path.parent.name != 'tls' else 'default'
        if subject and 'CN =' in subject.group(1):
            domain = subject.group(1).split('CN =', 1)[1].split('/', 1)[0].strip()
        valid_to = not_after.group(1).strip() if not_after else ''
        days_left = 0
        if valid_to:
            try:
                expiry = datetime.datetime.strptime(valid_to, '%b %d %H:%M:%S %Y %Z')
                days_left = max(0, (expiry - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days)
            except (TypeError, ValueError):
                pass
        return {
            'domain': domain,
            'issuer': (issuer.group(1).strip() if issuer else 'Unknown CA')[:80],
            'validFrom': not_before.group(1).strip() if not_before else '',
            'validTo': valid_to,
            'daysLeft': days_left,
            'autoRenew': True,
            'status': 'valid' if days_left > 15 else ('expiring' if days_left > 0 else 'expired'),
        }
    except (OSError, subprocess.SubprocessError):
        return None


def certs():
    output = []
    tls_dir = ETC / 'tls'
    if not tls_dir.is_dir():
        return output
    for domain_dir in sorted(tls_dir.iterdir()):
        if not domain_dir.is_dir():
            continue
        certificate = parse_cert_openssl(domain_dir / 'fullchain.pem')
        if certificate:
            if certificate['domain'] in ('default', ''):
                certificate['domain'] = domain_dir.name
            output.append(certificate)
    return output


def cert_renew(data):
    domain = str(data.get('domain', '')).strip().lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError('invalid domain format')
    acme = pathlib.Path('/root/.acme.sh/acme.sh')
    if not acme.is_file():
        return {'status': 'failed', 'domain': domain, 'error': 'acme.sh is not installed'}
    result = run([str(acme), '--renew', '-d', domain, '--force', '--home', '/root/.acme.sh'], check=False, timeout=180)
    if result.returncode != 0:
        return {'status': 'failed', 'domain': domain, 'error': 'certificate renewal failed'}
    return {'status': 'ok', 'domain': domain, 'certificates': certs()}


def _openssl(args, input_data=None, timeout=10):
    if not shutil.which('openssl'):
        raise RuntimeError('openssl is required for certificate validation')
    result = subprocess.run(
        ['openssl', *args], input=input_data, capture_output=True, text=True,
        timeout=timeout, check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or 'openssl validation failed').strip()
        raise ValueError(detail[-500:])
    return result.stdout


def _validate_custom_certificate(cert_pem, key_pem, domain):
    with tempfile.TemporaryDirectory(prefix='mailstack-cert-') as temp_dir:
        temp = pathlib.Path(temp_dir)
        cert_file = temp / 'certificate.pem'
        key_file = temp / 'private-key.pem'
        cert_file.write_text(cert_pem + '\n', encoding='utf-8')
        key_file.write_text(key_pem + '\n', encoding='utf-8')
        os.chmod(cert_file, 0o600)
        os.chmod(key_file, 0o600)
        _openssl(['x509', '-in', str(cert_file), '-noout'])
        _openssl(['x509', '-in', str(cert_file), '-checkend', '0', '-noout'])
        host_check = _openssl(['x509', '-in', str(cert_file), '-checkhost', domain, '-noout'])
        if 'does match' not in host_check.lower():
            raise ValueError(f'certificate SAN/CN does not match {domain}')
        certificate_public = _openssl(['x509', '-in', str(cert_file), '-pubkey', '-noout']).strip()
        key_public = _openssl(['pkey', '-in', str(key_file), '-pubout']).strip()
        if certificate_public != key_public:
            raise ValueError('certificate and private key do not match')


def setup_cert_issue(data):
    domain = str(data.get('domain') or data.get('mailHost') or data.get('customDomain') or '').strip().lower()
    method = str(data.get('method', 'standalone')).strip().lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError('invalid certificate domain')
    out_dir = ETC / 'tls' / domain
    out_dir.mkdir(parents=True, exist_ok=True)
    fullchain = out_dir / 'fullchain.pem'
    privkey = out_dir / 'privkey.pem'

    if method == 'custom':
        cert_pem = str(data.get('certPem') or data.get('customCertPem') or '').strip()
        key_pem = str(data.get('keyPem') or data.get('customKeyPem') or '').strip()
        if not cert_pem or 'BEGIN CERTIFICATE' not in cert_pem:
            raise ValueError('Invalid certificate PEM format (missing BEGIN CERTIFICATE)')
        if not key_pem or 'PRIVATE KEY' not in key_pem:
            raise ValueError('Invalid private key PEM format (missing PRIVATE KEY)')
        _validate_custom_certificate(cert_pem, key_pem, domain)
        atomic(fullchain, cert_pem + '\n', 0o644)
        atomic(privkey, key_pem + '\n', 0o600)
    else:
        email = str(data.get('email', '')).strip()
        if not email or '@' not in email:
            raise ValueError('invalid certificate email for ACME')
        acme = pathlib.Path('/root/.acme.sh/acme.sh')
        if not acme.is_file():
            raise RuntimeError('acme.sh is not installed')
        issue = [str(acme), '--issue', '-d', domain, '--accountemail', email, '--server', 'letsencrypt', '--keylength', 'ec-256', '--home', '/root/.acme.sh']
        if method == 'webroot':
            webroot = str(data.get('webroot', '')).strip()
            if not webroot.startswith('/') or not pathlib.Path(webroot).is_dir():
                raise ValueError('invalid ACME webroot')
            issue.extend(['--webroot', webroot])
        elif method == 'standalone':
            issue.append('--standalone')
        else:
            raise ValueError(f'unsupported ACME method: {method}')
        result = run(issue, check=False, timeout=300)
        if result.returncode != 0:
            raise RuntimeError('ACME certificate issue failed')
        reload_script = pathlib.Path('/usr/local/sbin/mailstack-reload-certificates')
        atomic(reload_script, '#!/bin/sh\npostfix check 2>/dev/null && (systemctl reload postfix 2>/dev/null || rc-service postfix reload 2>/dev/null || postfix reload 2>/dev/null)\ndoveconf >/dev/null 2>&1 && (systemctl reload dovecot 2>/dev/null || rc-service dovecot reload 2>/dev/null || dovecot reload 2>/dev/null)\n', 0o750)
        result = run([str(acme), '--install-cert', '-d', domain, '--ecc', '--key-file', str(privkey), '--fullchain-file', str(fullchain), '--reloadcmd', str(reload_script), '--home', '/root/.acme.sh'], check=False, timeout=120)
        if result.returncode != 0:
            raise RuntimeError('ACME certificate installation failed')
        os.chmod(privkey, 0o600)
        os.chmod(fullchain, 0o644)

    if shutil.which('postconf'):
        run(['postconf', '-e', f'smtpd_tls_cert_file = {fullchain}'], check=False)
        run(['postconf', '-e', f'smtpd_tls_key_file = {privkey}'], check=False)
        run(['postconf', '-e', 'smtpd_tls_security_level = may'], check=False)
    service_ctl('postfix', 'reload')
    service_ctl('dovecot', 'reload')
    return {'status': 'ok', 'method': method, 'reloaded': True, 'cert': parse_cert_openssl(fullchain)}


def dkim_rotate(data):
    domain = str(data.get('domain', '')).strip().lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError('invalid domain format')
    selector = str(data.get('selector', 'mailstack')).strip().lower() or 'mailstack'
    if not re.fullmatch(r'[a-z0-9_-]{1,63}', selector):
        raise ValueError('invalid DKIM selector')
    if not shutil.which('opendkim-genkey'):
        raise RuntimeError('opendkim-genkey is not installed')
    dkim_dir = ETC / 'dkim' / domain
    dkim_dir.mkdir(parents=True, exist_ok=True)
    private_key = dkim_dir / f'{selector}.private'
    txt_record = dkim_dir / f'{selector}.txt'
    result = run(['opendkim-genkey', '-D', str(dkim_dir), '-d', domain, '-s', selector, '-b', '2048'], check=False)
    if result.returncode != 0 or not private_key.is_file() or not txt_record.is_file():
        raise RuntimeError('OpenDKIM key generation failed')
    set_dkim_key_permissions(private_key)
    record = txt_record.read_text(encoding='utf-8').strip()
    return {'status': 'ok', 'domain': domain, 'selector': selector, 'record': record}

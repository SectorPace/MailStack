# Ubuntu 24.04 Verification Record

This document is a release-candidate checklist. It is not a claim that a machine was tested until the record section is filled by the operator.

## Record

- Distribution: Ubuntu 24.04 LTS
- Architecture: `x86_64`
- Node.js: `node --version`
- Python: `python3 --version`
- Kernel: `uname -sr`
- Date (UTC): `date -u +%FT%TZ`
- Artifact: `0.5.1-beta.1`
- Artifact SHA256: record the detached release checksum

## Installation modes

```bash
sudo ./deploy/install.sh --access-mode local --non-interactive
```

Local mode must bind both services to loopback. Verify access through an SSH tunnel:

```bash
ssh -N -L 8787:127.0.0.1:8787 -L 18788:127.0.0.1:18788 root@server
```

For public access, use `--access-mode caddy` or a separately managed HTTPS reverse proxy. Confirm `COOKIE_SECURE=1` whenever HTTPS terminates in front of MailStack. The `plain` mode is an explicit test-only exception and must not be used for production credentials.

## Functional and security checks

```bash
npm test
python3 scripts/test_mail_path_e2e.py
systemctl is-active mailstack-web mailstack-webmail
curl -fsS http://127.0.0.1:8787/api/health
curl -fsS http://127.0.0.1:18788/api/webmail/health
```

Verify the exact artifact version, account separation, privileged helper ownership, Dovecot socket permissions, backup SHA256 validation, and clean uninstall before marking the candidate approved.

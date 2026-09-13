# Debian 12 Verification Record

This document is a release-candidate checklist. Replace the values in the record section only after running the commands on a clean Debian 12 host.

## Record

- Distribution: Debian 12 Bookworm
- Architecture: `x86_64`
- Node.js: `node --version`
- Python: `python3 --version`
- Kernel: `uname -sr`
- Date (UTC): `date -u +%FT%TZ`
- Artifact: `0.5.1-beta.1`
- Artifact SHA256: record the detached release checksum

## Installation

```bash
sudo ./deploy/install.sh --access-mode local --non-interactive
```

Verify all of the following:

- `mailstack-admin` and `mailstack-webmail` exist, have no login shell and are separate accounts.
- `mailstack-webmail` has no sudo rule and the exact privileged helper is root-owned.
- `mailstack-web` and `mailstack-webmail` are active systemd services.
- Admin listens on `127.0.0.1:8787` and Webmail on `127.0.0.1:18788` in local mode.
- `/etc/mailstack` is `0750`, `admin.json` is `0640`, relay credentials are `0600`, and sudoers is `0440`.
- `/api/health` and `/api/webmail/health` return version `0.5.1-beta.1`.

## Functional checks

```bash
npm test
python3 scripts/test_mail_path_e2e.py
curl -fsS http://127.0.0.1:8787/api/health
curl -fsS http://127.0.0.1:18788/api/webmail/health
```

Record failures and logs with the release candidate; do not mark this document as passed from a source-only build.

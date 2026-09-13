# MailStack v0.5.2-rc.5 Release Checklist

## Version and source

- [ ] `VERSION`, `package.json`, lockfile, `mailstack.sh` VERSION, README and release notes use `0.5.2-rc.5`.
- [ ] No debug password, host-specific absolute path, cache, bytecode, source map or previous archive is included.
- [ ] Every `*.sh` file is UTF-8 with LF endings and passes `bash -n`; `deploy/mailstack-privileged` and `deploy/mailstack.logrotate` are LF-only.
- [ ] Original source and release staging trees are kept separate during packaging.

## Security

- [ ] Admin and Webmail bind to `127.0.0.1` by default on `8787` and `18788`.
- [ ] Public deployments terminate TLS at Caddy or another reverse proxy; secure cookies are enabled for HTTPS.
- [ ] `mailstack-admin` and `mailstack-webmail` are separate no-login users.
- [ ] Webmail has no sudo permission and cannot modify the backend/helper.
- [ ] **Sudoers has exactly one rule** (`/etc/sudoers.d/mailstack-web` → `/usr/local/libexec/mailstack-privileged`, no argument wildcard); `mailstack-web-ctl` does not exist anywhere (code, docs, or servers upgraded from older RCs — the installer deletes it).
- [ ] Privileged RPC reaches root via the long-running `mailstack-helper.service` unix socket (`0660 root:mailstack-admin`, length-prefixed JSON); the one-shot sudo wrapper is only a fallback, and `HELPER_PATH` never falls back to the raw python entrypoint.
- [ ] Webmail login uses the Dovecot `auth-client` socket; no password appears in any process argv (`ps auxww | grep doveadm` is empty during a login).
- [ ] `ms upgrade` refuses `git clone` unless `MAILSTACK_ALLOW_UNSAFE_GIT=1`; default path verifies `SHA256SUMS.sig` with `ssh-keygen -Y verify` against `deploy/mailstack-release.allowed_signers` before any script runs.
- [ ] Node.js, Caddy repo key, and acme.sh are installed from pinned SHA256 / GPG fingerprint constants and fail closed on mismatch.
- [ ] Admin login 401 carries no `remainingAttempts`; rate limiting is global + per-IP + per-account.
- [ ] Caddy `--domain` / `--webmail-domain` / `--email` pass the strict whitelist regex before anything is written (see `scripts/ci_domain_injection_test.sh`).
- [ ] Fail2ban jails `postfix-sasl` and `dovecot` exist in `/etc/fail2ban/jail.d/mailstack.conf`; `ms doctor` asserts ban/unban round-trip.
- [ ] Backup restore requires a local filename matching `BACKUP_FILENAME_RE`, metadata SHA256, explicit confirmation and safe archive members.
- [ ] AI and SMTP outbound requests validate all resolved addresses (incl. CGNAT and IPv4-mapped forms) and connect to a pinned address.

## Build and verification

- [ ] `npm ci --include=optional --no-audit --no-fund` succeeds on Node.js 20, 22 and 24.
- [ ] `npm run lint`, `npm test`, `npm run test:frontend`, `npm run test:helper`, `npm run test:backup` succeed.
- [ ] `node --check` passes for both bundled server entrypoints.
- [ ] Manifest hashes every distribution artifact except the manifest itself.
- [ ] Standalone smoke tests pass without `node_modules`.
- [ ] Dependency audit and privacy scan pass.
- [ ] Install-matrix passes on Ubuntu 24.04/22.04, Debian 12, Rocky 9 — including the privilege-escalation probe, sudoers-single-rule assertion, fail2ban jail presence, and the `ms test-mail` loopback delivery.

## Reproducible and signed archives

```sh
export SOURCE_DATE_EPOCH=1704067200
python3 scripts/package.py
(cd release && sha256sum -c SHA256SUMS)
# Sign the checksum manifest with the release key (kept OUTSIDE the repo):
ssh-keygen -Y sign -f <release-private-key> -n file release/SHA256SUMS
# Verify exactly what a server running `ms upgrade` will verify:
ssh-keygen -Y verify -f deploy/mailstack-release.allowed_signers -I mailstack-release -n file -s release/SHA256SUMS.sig < release/SHA256SUMS
```

- [ ] A second clean packaging run produces identical archive hashes.
- [ ] Upload the TAR.GZ, ZIP, `SHA256SUMS` **and `SHA256SUMS.sig`** together (the upgrade path refuses releases without a signature).
- [ ] The checksum file is outside the archives to avoid self-reference; the signature covers `SHA256SUMS`, not the archives directly.
- [ ] The release private key is stored only as a GitHub Actions secret / maintainer-held file, never committed.

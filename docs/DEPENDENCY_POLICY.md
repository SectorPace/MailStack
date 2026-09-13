# MailStack Dependency Policy

## Runtime model

The release contains two standalone Node.js bundles:

- `dist/server.cjs` for the administrator API and web shell.
- `dist/webmail.cjs` for the standalone Webmail service.

Both bundles are produced with esbuild and are intended to start without a runtime `node_modules` directory. The privileged helper uses Python 3 standard-library modules, with one sanctioned exception: the AES-256-GCM envelope that protects the admin TOTP secret at rest uses `cryptography`, installed **only** from the distribution repository (never `pip`, never a wheel, never a vendored copy). Self-made or hand-rolled encryption is forbidden. The sanctioned distribution packages are:

- Debian: `python3-cryptography`
- Ubuntu: `python3-cryptography`
- Fedora: `python3-cryptography`
- RHEL: `python3-cryptography`
- CentOS / Rocky / AlmaLinux: `python3-cryptography`
- openSUSE: `python3-cryptography`
- Arch Linux: `python-cryptography`
- Alpine Linux: `py3-cryptography`
- Amazon Linux: `python3-cryptography`

When `cryptography` is unavailable the helper fails closed: all 2FA operations return an explicit error and `ms doctor` reports the missing backend (FAIL in public mode, WARN in local mode). The source tree still includes `package.json` and `package-lock.json` for development and source builds.

## Supported toolchain

- Node.js: `>=20 <25`.
- Python: `>=3.9` for the helper and release tooling.
- Linux production target: systemd distributions with Postfix, Dovecot, OpenDKIM and optional Fail2ban.
- Shell installers require Bash and run with root privileges.

## Dependency rules

- Runtime dependencies belong in `dependencies`; build and test tools belong in `devDependencies`.
- Lockfile changes must accompany dependency changes.
- CI runs `npm ci`, `npm run lint`, `npm test`, `npm run build:all`, standalone smoke tests and `npm audit --omit=dev`.
- New network-facing dependencies require a security review, a pinned version range and a release-note entry.
- Release archives exclude `node_modules`, Python caches, bytecode, source maps, VCS metadata and nested archives.

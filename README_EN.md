<p align="center">
  <img src="assets/mailstack-logo.png" alt="MailStack Logo" width="180">
</p>

<h1 align="center">MailStack</h1>

<p align="center">
  Multi-platform Linux mail server deployment and administration suite<br>
  Postfix · Dovecot · OpenDKIM · Liquid Glass admin console · Standalone Webmail · 2FA · Signed upgrades · Docker · Unified ops CLI
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="https://github.com/SectorPace/MailStack">GitHub Repository</a> ·
  <a href="https://github.com/SectorPace/MailStack/releases">Releases</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.8.0--beta.7-2476ff">
  <img alt="Status" src="https://img.shields.io/badge/status-public%20beta-f0a53a">
  <img alt="Security" src="https://img.shields.io/badge/security-hardened-27b36a">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-27b36a">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Docker-22c7d6">
  <img alt="Node.js" src="https://img.shields.io/badge/Node.js-20%20%7C%2022%20%7C%2024-3c873a">
</p>

> **Release status: v0.8.0-beta.7 (public beta).** This is a CI/installer fix release on top of v0.8-beta.6: source files needed by the from-source build path (scripts/deploy/VERSION) are now copied into /opt/mailstack/ui (clean-checkout container installs previously failed), the rockylinux:9 curl-minimal package conflict no longer blocks installation, non-systemd minimal containers get /etc/init.d pre-created, the unit-test Path.stat mock no longer breaks glob on Python 3.11/3.12, and the production dependency qs is upgraded to 6.16.0 (CVE fixes). No interface or data-format changes.
>
> **Important disclaimer: MailStack does not guarantee inbox placement.** Actual deliverability depends on IP and domain reputation, DNS authentication (MX / SPF / DKIM / DMARC / PTR), message content, bounce and complaint rates, relay provider policies, and recipient-side rules.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Feature Overview](#feature-overview)
- [Architecture](#architecture)
- [Deployment: Bare Metal and Docker](#deployment-bare-metal-and-docker)
- [Supported Platforms](#supported-platforms)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Access Modes and the Public-Deployment Security Baseline](#access-modes-and-the-public-deployment-security-baseline)
- [Non-Interactive Installation](#non-interactive-installation)
- [Setup Wizard](#setup-wizard)
- [DNS Record Guide](#dns-record-guide)
- [Admin 2FA and Session Management](#admin-2fa-and-session-management)
- [Using Webmail](#using-webmail)
- [CLI Reference](#cli-reference)
- [Updates and Upgrades (Signed Channel)](#updates-and-upgrades-signed-channel)
- [Backups and Disaster Recovery](#backups-and-disaster-recovery)
- [Uninstallation](#uninstallation)
- [Ports and Environment Variables](#ports-and-environment-variables)
- [Security Model](#security-model)
- [AI Mail Advisor](#ai-mail-advisor)
- [Testing and Quality Assurance](#testing-and-quality-assurance)
- [Project Structure](#project-structure)
- [Development Guide](#development-guide)
- [Known Limitations](#known-limitations)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Reporting Security Issues](#reporting-security-issues)
- [Documentation Index](#documentation-index)
- [License](#license)

## Project Overview

MailStack bundles everything needed to run your own mail system on a Linux server (or Docker container) — Postfix (SMTP), Dovecot (IMAP and local delivery), OpenDKIM (signing), Fail2ban — together with a Liquid Glass web admin console, a standalone Webmail client, a long-lived privileged Python helper, and a unified `ms` operations CLI. A single install completes deployment, build, systemd / OpenRC / Docker service orchestration, permission and sandbox configuration, and provides day-to-day management: DNS guidance, TLS certificates, SMTP relay, mail queue, logs, security checks, and a configurable AI mail advisor.

Design goals:

- **One-command readiness**: from one `curl` line (or `git clone`) to all three services passing health checks in one command; dependencies such as Node.js are pinned and installed automatically — or just `docker compose up`.
- **Secure by default**: web services listen on `127.0.0.1` only; public mode enforces 2FA and encrypted backups and disables AI outbound by default; privileged operations go through a dual-channel allowlisted helper; upgrades only accept signature-verified release assets.
- **Operable**: health checks (with live Fail2ban probes), roundtrip mail delivery verification, config backup / restore / rollback, and audit-chain verification are all built in.
- **Auditable**: every privileged RPC is audited with a prev_hash tamper-evident chain mirrored to syslog AUTHPRIV; release artifacts carry SHA256 manifests plus ssh-keygen signatures; dependency downloads are pinned.

## Feature Overview

### Admin Console (Liquid Glass Web Console)

- Liquid Glass single-page console built with React 19 + TypeScript + Vite + Tailwind CSS 4
- Simplified Chinese / English UI, Light and Dark themes
- Customizable avatar, logo style, and background rendering; global search, toasts, error boundary
- System telemetry: realtime metrics and history charts (CPU / load / memory / disk / queue)
- Admin TOTP two-factor authentication and active session management (see [below](#admin-2fa-and-session-management))

### Mail Core Capabilities

| Capability | Description |
|---|---|
| Mail domains | Multi-domain add / remove, Postfix domain registration and validation |
| Mailbox users | Creates Linux mailbox users (nologin + Maildir); enable/disable status, password reset, deletion; registry lives in `/var/lib/mailstack` (readable by webmail, separated from config) |
| Address aliases | Alias add / remove with explicit domain split validation |
| Mail queue | Postfix queue inspection and queue actions (queue-ID allowlist validation) |
| Service management | start / stop / restart / reload / status for Postfix / Dovecot / OpenDKIM / Fail2ban / Rspamd / ClamAV / Redis |
| TLS certificates | Certificate listing, renewal, wizard-driven issuance (acme.sh pinned at 3.1.4) |
| DKIM | Key generation, DNS public key display (correctly handles RFC multi-line splitting), key rotation; private key policy `root:opendkim 0640` asserted by the doctor scan |
| SMTP relay | One-step relay configuration writing `sasl_passwd` (0600); presets for Oracle OCI / Amazon SES / SendGrid / Brevo / Resend plus a custom smart host |
| Security center | Security score and event scanning (relay restrictions, Fail2ban status, `sasl_passwd` permissions, missing certificates, plaintext backup archives), Fail2ban ban / unban (runtime jail allowlist, supports custom jails like `recidive`) |
| Domain DNS checks | MX / SPF / DKIM / DMARC / PTR guidance with per-record status (including relay-provider-specific checks) |

### Standalone Webmail Client

- Separate `mailstack-webmail` systemd service, fully isolated from the admin console (dedicated system account, dedicated port, stricter sandbox, no sudo at all)
- Mailbox authentication goes through the **Dovecot `auth-client` unix socket protocol** (`webmail/dovecot-auth.mjs`): passwords only ever enter the socket payload, **never a process argv**; fail-closed when the socket is unavailable; wrong password and nonexistent user return the identical 401 (no user enumeration)
- Inbox listing, search, MIME / encoded-word / multi-charset parsing, read marking; outbound mail is submitted via the local `sendmail` (Postfix)
- Sessions: sliding TTL plus a **7-day absolute cap**; password change / account lock bumps a per-user session epoch, invalidating all existing sessions
- CSRF protection, login attempt throttling (5 strikes, 15-minute lock), and per-endpoint rate limits
- Safe mail file reads: `O_NOFOLLOW` symlink protection, size caps, path normalization

### Setup Wizard

A step-by-step first-login wizard: server identity → DNS verification → delivery method (relay test / direct EHLO probe) → TLS certificate issuance → send test → summary. Every step calls the privileged helper for real validation.

### Unified Operations CLI (`ms`)

`ms doctor` full-stack health check (with live Fail2ban ban/unban probes), `ms audit-verify` audit hash-chain verification, `ms test-mail` roundtrip delivery verification, `ms backup / restore / rollback` config disaster recovery (encrypted backups supported), `ms upgrade` signed upgrades (version pinning, downgrade refusal) — see the [CLI Reference](#cli-reference).

### Disaster Recovery and Observability

- Backups support **gpg symmetric encryption (AES256)**; the passphrase only travels via stdin; public mode enforces encryption
- Audit log: prev_hash hash chain + `.head` anchor (truncation detection), mirrored to syslog `AUTHPRIV`; `ms audit-verify` re-checks the chain for monitoring integrations
- Realtime metrics, service logs, install logs, and an explicit degraded-components summary

## Architecture

```text
                        ┌────────────────────────────────────────────────┐
                        │           Browser (admin / mailbox user)       │
                        └────────────┬──────────────────────┬────────────┘
                                     │ HTTPS / SSH tunnel   │
                   ┌─────────────────▼──────────┐  ┌────────▼─────────┐
                   │  mailstack-web (Admin)     │  │ mailstack-webmail │
   Access modes    │  Express + React static    │  │ Dovecot auth-     │
  local/caddy/     │  127.0.0.1:8787            │  │ client socket auth│
  direct/plain     │  2FA forced in public mode │  │ 127.0.0.1:18788   │
                   └───────┬───────────┬────────┘  └────────┬─────────┘
                           │           │                    │ controlled Maildir reads
              RO: unix socket│           │ RW: sudo wrapper   │
                           ▼           ▼                    │
                   ┌────────────────────────────────┐          │
                   │  mailstack-helper (root daemon) │          │
                   │  helper-ro.sock 0660 read-only  │          │
                   │  helper.sock    0600 mutation   │          │
                   │  SO_PEERCRED + action allowlist │          │
                   │  audit hash chain → file+syslog │          │
                   └───────────────┬────────────────┘          │
                                   │ postconf / doveadm / opendkim-genkey /
                                   │ fail2ban-client / systemctl / acme.sh ...
                        ┌──────────┼───────────────┬───────────────┐
                        ▼          ▼               ▼               ▼
                   ┌────────┐ ┌─────────┐  ┌────────────┐  ┌────────────┐
                   │Postfix │ │Dovecot  │  │ OpenDKIM   │  │ Fail2ban   │
                   └────────┘ └─────────┘  └────────────┘  └────────────┘
```

Component responsibilities:

| Component | Process / file | System account | Responsibility |
|---|---|---|---|
| Admin console | `mailstack-web.service` → `/opt/mailstack/server.cjs` | `mailstack-admin` (nologin) | Login (password + TOTP), sessions, static assets; read-only RPCs connect directly to `helper-ro.sock`, mutations go through the sudo wrapper |
| Privileged helper | `mailstack-helper.service` (root daemon) + one-shot sudo wrapper `/usr/local/libexec/mailstack-privileged` | root | Everything that needs root: RO/RW dual socket channels, SO_PEERCRED peer checks, action allowlist, destructive-action confirmation, audit hash chain |
| Webmail | `mailstack-webmail.service` → `/opt/mailstack/webmail.cjs` | `mailstack-webmail` (nologin, in dovecot/mail groups) | Mailbox login (Dovecot auth socket), Maildir reads, outbound submission; **no sudo at all** |
| Mail stack | Postfix / Dovecot / OpenDKIM / Fail2ban | system services | Actual mail transfer, local delivery, DKIM signing, brute-force protection |
| Ops CLI | `/usr/local/bin/ms` → `/opt/mailstack-source/mailstack.sh` | root (self-escalating) | install / upgrade / uninstall / doctor / backup / restore / rollback / audit-verify |

Privileged actions are split by "does it change host state":

- **RO channel** (`/run/mailstack/helper-ro.sock`, 0660 root:mailstack-admin, direct from Node): 14 read-only actions (snapshot, doctor, logs, metrics, listing queries, etc.)
- **RW channel** (`/run/mailstack/helper.sock`, 0600 root:root, reachable only via the sudo wrapper): all mutating actions (domains / users / aliases / queue / backups / 2FA / AI config, etc.)
- The channel — not the uid — decides the action subset: an RW action received on the RO socket is refused even with uid=0 and audited as `ro_channel_violation`; every connection is checked with `getsockopt(SO_PEERCRED)` and unauthorized peers are disconnected immediately

## Deployment: Bare Metal and Docker

### Bare metal (systemd / OpenRC / init.d)

The full mail stack lands directly on the host; three systemd services are registered (`mailstack-helper`, `mailstack-web`, `mailstack-webmail`). On systems without systemd (e.g. Alpine) the OpenRC / init.d branch is used (services detached with `setsid`).

### Docker single container

For systemd-less environments (NAS, container platforms, quick evaluations), use the official orchestration — see [docs/DOCKER.md](docs/DOCKER.md):

```bash
# Build (requires network: apt + npm registry + pinned nodejs.org download)
docker compose build

# First start: provide the admin password explicitly (12-256 chars, letters and digits)
MAILSTACK_ADMIN_PASSWORD='Your-Strong-Admin-Pass-7' docker compose up -d
# Or leave empty: entrypoint generates a random password and prints it once in the logs
docker compose up -d
docker compose logs mailstack | grep -A4 '随机管理员口令'

# Verify (compose binds admin/webmail to the host loopback by default)
curl http://127.0.0.1:8787/api/health
curl http://127.0.0.1:18788/api/webmail/health
```

Key points:

- **6-process foreground model** (helper / postfix / dovecot / opendkim optional / admin / webmail); any process exiting exits the whole container; `tini` as PID 1
- Image baseline `ubuntu:24.04`; the build reuses the bare-metal installer (same path as the CI install matrix); the build-time password is generated at random, deleted after install, and **plaintext passwords never enter any image layer** — the real password is initialized by the entrypoint on first start into a data volume
- 8 data volumes: `/etc/mailstack`, `/var/lib/mailstack`, `/home` (Maildir), `/var/spool/postfix`, `/var/backups/mailstack`, `/etc/postfix`, `/etc/dovecot`, `/etc/opendkim`
- Ports: admin 8787 / webmail 18788 (bound to host loopback by default); SMTP 25 / 465 / 587; IMAP 143 / 993; POP3 110 / 995
- **A6 admin-port gate**: a non-loopback admin binding inside the container requires both `MAILSTACK_LISTEN_HOST=0.0.0.0` and `MAILSTACK_I_PUBLISH_ADMIN=1`; otherwise startup is refused
- ⚠️ Residential / business broadband usually blocks outbound port 25, so outbound delivery tests from home networks will likely fail; for local verification focus on 587 (submission) / 143 (IMAP) / 8787 / 18788

## Supported Platforms

The tier table comes from [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) (authoritative per release artifact):

| Distribution | Versions | Tier | Installer path | Verification |
|---|---|---|---|---|
| Ubuntu | 22.04 / 24.04 LTS | **Tier 1** | APT + systemd | real-machine records + CI install matrix |
| Debian | 12 (Bookworm) | **Tier 1** | APT + systemd | real-machine records + CI install matrix |
| RHEL / Rocky / AlmaLinux | 9.x | Tier 2 | DNF + systemd | `scripts/test_distro_matrix.py` |
| openSUSE Leap / Tumbleweed | 15.x / rolling | Tier 2 | Zypper + systemd | `scripts/test_distro_matrix.py` |
| Alpine Linux | 3.19+ | Experimental | APK + OpenRC | verify manually before production |

Platform capability notes (see SUPPORT_MATRIX for details):

- **musl systems (Alpine)**: when the distro repo cannot satisfy Node 20-24, the installer falls back to the official unofficial-builds `linux-x64-musl` build (v22.20.0, SHA256 pinned); that channel has no arm64-musl, so musl + arm64 relies on distro packages
- **OpenDKIM optional on dnf systems**: when a repo has no opendkim package (e.g. openEuler 25.09) the install degrades gracefully — mail flow is unaffected; install opendkim later and run `dkim.rotate` to enable signing
- **EL9 Python ≥3.10 hard gate**: the backend uses PEP 604 syntax; if the interpreter still reports below 3.10 the install fails early instead of producing a stack whose helper crashes on import
- **Arch old-snapshot self-healing**: `archlinux-keyring` is refreshed before installing; missing icu SONAMEs are restored from the local cache or archive.archlinux.org
- **fail2ban pip fallback**: when no repo package exists, fail2ban installs from the pinned GitHub 1.1.0 tarball (SHA256) with the `/etc/fail2ban` tree unpacked manually
- **Orphan listener cleanup**: before starting services the installer kills only processes actually listening on 8787 / 18788 (`fuser -k`), preventing EADDRINUSE restart loops on interrupted-then-rerun installs

**Live testing record**: this release line passed two rounds of installation verification on **Ubuntu / Debian / Kali / AlmaLinux 10 / OracleLinux 9.5 / openEuler 25.09 / openSUSE Tumbleweed / Arch / Alpine 3.24** (including interrupted reruns and uninstall-reinstall; 8/9 systemd + Alpine OpenRC/init.d).

## Requirements

| Item | Requirement |
|---|---|
| Deployment form | Bare-metal Linux (systemd / OpenRC / init.d) or Docker (`ubuntu:24.04` baseline image) |
| Privileges | root (the installer self-escalates via `sudo`); Docker + docker compose for container mode |
| Shell | Bash |
| Node.js | **20 – 24** (`engines: >=20 <25`); auto-installed pinned official builds when unmet |
| Python | **≥ 3.10 (hard gate)** (privileged helper and ops tooling, stdlib only) |
| Other commands | `python3`, `sudo`, `rsync`, `tar`; `git` (developer git upgrade channel only); `curl` + `ssh-keygen` (one-liner install and the `ms upgrade` signed-release channel only, OpenSSH ≥ 8.0) |
| Optional | `gpg` (backup encryption; required in public mode), `fail2ban` (security center and doctor probes) |
| Ports | 25 (SMTP inbound); admin 8787 and webmail 18788 listen on loopback only by default |
| DNS | For `caddy` public mode, domain A/AAAA must point at the server's public IP (80/443 free for certificate issuance) |

## Quick Start

### One-liner installation (recommended)

Run as root (`sudo -i` or `su -`):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh)
```

`curl -fsSL` can be swapped for `wget -qO-` (the bootstrap itself still needs curl, so install curl first on minimal systems). If you would rather not switch to root first, this `bash -c` form is an equivalent one-liner:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh)"
```

> **Do not write `sudo bash <(curl …)`**: sudo closes file descriptors above 3, so bash cannot reach `/dev/fd/63` — measured on sudo 1.9.15 it fails with `bash: /dev/fd/63: No such file or directory`, exit code 127. Process substitution has to be performed by **the shell that will execute the script**.

Process substitution only hangs the script body off one fd, so **stdin stays the terminal**: interactive prompts, admin password entry and `--admin-password-stdin` all work. That is exactly why it beats `curl … | sudo bash`, where stdin *is* the script body and the installer's `read` only sees EOF (the script reattaches stdin to `/dev/tty` as a fallback, and fails loudly instead of hanging when there is genuinely no controlling terminal).

`deploy/install.sh` contains no source code and no installation logic. It runs standalone because it bootstraps with exactly the same trust model as `ms upgrade`: it pulls the `MailStack-<tag>.tar.gz` + `SHA256SUMS` + `SHA256SUMS.sig` trio from the GitHub Release, verifies the detached signature with `ssh-keygen -Y verify`, checks `sha256sum -c`, and only then extracts to `/opt/mailstack-source` and `exec`s the real installer — **the bootstrap itself never runs unverified remote content**.

Shells without process substitution (`sh`/`dash`/`csh`) use the equivalent two-step form:

```bash
curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh -o /tmp/mailstack-install.sh
sudo bash /tmp/mailstack-install.sh
```

### Installing from source (contributors)

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

The installer will:

1. Install and verify the full mail base stack (Postfix / Dovecot / OpenDKIM / Fail2ban; uninstallable components degrade by design and are listed in the final "degraded components" summary)
2. Check the Node.js runtime (auto-installs a SHA256-pinned official build when unmet; third-party dependencies are all version-pinned — no "download and execute")
3. Ask for the access mode and the admin username / password (**12-256 chars, must contain both letters and digits**)
4. Build (uses the prebuilt artifacts after SHA256 manifest validation when present, otherwise `npm run build:all` from source)
5. Create dedicated system accounts, write the single sudoers rule, the Dovecot auth socket, logrotate (three-segment copytruncate policy), and generate the TOTP master-key envelope (AES-256-GCM, root:root 0600)
6. Register and start the `mailstack-helper`, `mailstack-web`, and `mailstack-webmail` systemd services
7. Run health checks: installation only succeeds when `/api/health` and `/api/webmail/health` both pass
8. Persist install arguments to `/etc/mailstack/install-args.conf` and place the upgrade trust anchor at `/etc/mailstack/release-allowed-signers`

Install log: `/var/log/mailstack-install.log`.

### Accessing after install (local mode)

Defaults: `127.0.0.1:8787` (console) and `127.0.0.1:18788` (webmail). Recommended access via SSH tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 -L 18788:127.0.0.1:18788 root@server-ip
```

Then open `http://127.0.0.1:8787` locally. In `caddy` mode the installer configures Caddy and issues Let's Encrypt certificates automatically — just visit your domain over HTTPS. If Caddy is unavailable it degrades safely back to local listening with a clear notice.

## Access Modes and the Public-Deployment Security Baseline

| Mode | Listening | Use case | Security | Access |
|---|---|---|:---:|---|
| **`local`** | `127.0.0.1` | Secure default baseline | 🟢 High | SSH tunnel / VPN forwarding |
| **`caddy`** | `127.0.0.1` + Caddy | Public multi-domain production | 🟢 High | Automatic Let's Encrypt TLS, direct domain access |
| **`direct`** | `127.0.0.1` | Existing reverse proxy | 🟡 Medium | Bring your own proxy and HTTPS certificate (example: [deploy/reverse-proxy-nginx.example.conf](deploy/reverse-proxy-nginx.example.conf)) |
| **`plain`** | `0.0.0.0` | Isolated internal testing | 🔴 Very low | Plaintext HTTP on the public internet; interactive mode requires typing `yes`, non-interactive requires `--i-understand-plain-http` |

**Public-deployment security baseline**: when the access mode is `caddy` / `direct` (or `MAILSTACK_SECURITY_PROFILE=high` is set), the following controls apply fail-closed —

1. **2FA is mandatory**: before TOTP is enabled the console serves only login + enrollment endpoints (everything else 403), binds back to `127.0.0.1`, and hard-exits when the enrollment window lapses
2. **Backups are encrypted**: `backup.create` without a passphrase is refused before anything is written; missing `gpg` never silently falls back to plaintext; `ms doctor` marks plaintext archives FAIL
3. **Audit chain integrity is enforced**: `MAILSTACK_AUDIT_FAILOPEN=1` is a doctor FAIL in public mode; hash chain + `.head` anchor + syslog mirroring are always on
4. **AI outbound is off by default**: all `ai.*` outbound actions are refused unless explicitly enabled (`MAILSTACK_AI_OUTBOUND=1` or `enabled=true` in `/etc/mailstack/ai.conf`)
5. **Escape hatches are hard-off**: any of `MAILSTACK_ALLOW_UNSAFE_GIT=1`, `COOKIE_SECURE=0`, `HOST=0.0.0.0`, `MAILSTACK_AUDIT_FAILOPEN=1` (scanned from both the systemd unit and `/proc/<pid>/environ`) is a doctor FAIL; the git-clone upgrade channel is unreachable in public mode (the only developer exemption requires `MAILSTACK_I_AM_A_DEVELOPER=1` plus local mode)

## Non-Interactive Installation

The password travels via stdin (then into an environment variable and immediately `unsetenv`), never into shell history or `/proc/<pid>/cmdline`. The download-then-run form below is used because long flag lists read better and scripting it into config management is easier; running it as a one-liner from root, `printf '%s\n' 'pass' | bash <(curl -fsSL …) --non-interactive …`, works just as well (process substitution does not claim stdin):

```bash
curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh -o /tmp/mailstack-install.sh
printf '%s\n' 'YourStrongPass123' | sudo bash /tmp/mailstack-install.sh \
  --access-mode caddy \
  --domain mail.example.com \
  --webmail-domain webmail.example.com \
  --email ops@example.com \
  --admin-user admin \
  --admin-port 8787 \
  --admin-host 127.0.0.1 \
  --admin-password-stdin \
  --non-interactive
```

When installing from a source checkout, replace the command with `sudo bash ./mailstack.sh install`; the flags are identical.

All installer flags:

| Flag | Description | Default |
|---|---|---|
| `--access-mode <mode>` | `local` / `caddy` / `direct` / `plain` | interactive choice; non-interactive picks `caddy` with a domain, else `local` |
| `--domain <DOMAIN>` | Console / primary mail domain | empty |
| `--webmail-domain <DOMAIN>` | Webmail domain | same as primary |
| `--email <EMAIL>` | Let's Encrypt notification email | empty |
| `--admin-user <NAME>` | Admin username | `admin` |
| `--admin-port <PORT>` | Console internal port (1024–65535) | `8787` |
| `--admin-host <HOST>` | Console bind address | `127.0.0.1` |
| `--webmail-port <PORT>` | Webmail internal port | `18788` |
| `--webmail-host <HOST>` | Webmail bind address | `127.0.0.1` |
| `--admin-password-stdin` | Read admin password from stdin (12-char policy) | interactive |
| `--non-interactive` | Silent installation | off |
| `--reuse-admin` | Reuse existing admin credentials (for upgrades) | off |
| `--https` | Force HTTPS secure-cookie flag | mode-dependent |
| `--i-understand-plain-http` | Explicit risk acknowledgment for non-interactive plain mode | off |
| `--i-have-external-tls` | direct mode: TLS is terminated by an external proxy (skip certificate-evidence probing) | off |

## Setup Wizard

After the first login, follow the wizard (each step calls the privileged helper for real validation):

1. **Server identity**: hostname, timezone, admin email, etc.
2. **DNS verification**: add the mail domain, verify MX / SPF / DKIM / DMARC / PTR; the AI assistant can explain records and suggest fixes
3. **Delivery method**: SMTP relay (presets for Oracle OCI / SES / SendGrid / Brevo / Resend) or direct delivery; relay runs a real TLS-authenticated test, direct mode probes the local Postfix with a plain EHLO
4. **TLS certificate**: ACME issuance (privileged calls default to a 120 s timeout, adjustable via `MAILSTACK_HELPER_TIMEOUT_MS`)
5. **Send test**: roundtrip delivery verification
6. **Summary**: confirm everything

Re-run any time from the Setup Guide page, or re-test delivery with `ms test-mail`.

## DNS Record Guide

| Record | Host | Example value | Purpose |
|---|---|---|---|
| A / AAAA | `mail.example.com` | server public IP | host resolution |
| MX | `example.com` | `mail.example.com.` (priority 10) | inbound mail |
| SPF | `example.com` | `v=spf1 mx -all` (use the relay's `include:` when relaying) | authorized senders |
| DKIM | `default._domainkey.example.com` | OpenDKIM public key (copy from the console) | signature verification |
| DMARC | `_dmarc.example.com` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com` | policy and reports |
| PTR | reverse DNS | → `mail.example.com` | recipient-side reputation (set at your VPS provider) |

## Admin 2FA and Session Management

- **TOTP two-factor**: bind from the 2FA card in Account Settings (otpauth URI / secret display, enable / disable / re-bind); re-binding requires passing TOTP or a recovery code first, preventing silent downgrade to single-factor
- **One-time recovery codes**: stored hashed, consumed once, with a file lock on the consumption path for atomicity against concurrent replay
- **Login flow**: after the password passes, an enabled-2FA login without a code returns `TOTP_REQUIRED`; TOTP verifies locally, recovery codes go through the privileged helper
- **Shared lockout ledger**: TOTP failures and password failures share the same strike/lockout ledger — a password holder cannot brute-force the 6-digit code during a lockout window
- **Three-layer login throttling**: global 500/min + per-IP 30/15 min + per-account 10/15 min, combined with the 5-strike lock (5 minutes); every 401 returns only `INVALID_CREDENTIALS` with no attempt counters (anti-enumeration)
- **Active session management**: list and revoke sessions one by one (`GET/DELETE /api/auth/sessions`, `POST /api/auth/sessions/revoke`); a password change clears all admin sessions
- The TOTP master key is sealed with AES-256-GCM (root:root 0600, readable only by the privileged helper)

## Using Webmail

- Visit `http://127.0.0.1:18788` (SSH tunnel), `https://webmail.example.com` (caddy mode), or the Docker-exposed port
- Log in with a **mailbox user** (the Linux mailbox account created on the console's Users page); authentication goes through the Dovecot auth socket — passwords never enter a process parameter
- Inbox listing and search, message reading (MIME / multi-charset), read marking, and sending (submitted to local Postfix)
- 7-day absolute session cap; a password change / account lock invalidates all of that user's webmail sessions (epoch mechanism)

## CLI Reference

After installation `/usr/local/bin/ms` is linked. Run `ms` anywhere on the server for help.

### Common commands

| Command | Description |
|---|---|
| `ms doctor` | Full-stack health check: system, load, disk, memory, core services, Postfix/Dovecot config, port reachability, queue backlog, managed domains, key permission policy (KeyPermissionScan), **live Fail2ban probe** (ban/unban round-trip against TEST-NET-1; a non-acting jail is FAIL), plaintext-backup archive scan, dual-source public escape-hatch scan; prints overall HEALTHY/WARNING/CRITICAL |
| `ms audit-verify` | Verify audit log hash-chain integrity (truncation / tampering → non-zero exit; wire it into monitoring) |
| `ms test-mail [mailbox]` | Roundtrip delivery verification: real send → receive → Maildir landing confirmation, with tracking token and round-trip latency |
| `ms status` | Status of `mailstack-helper` / `mailstack-web` / `mailstack-webmail` |
| `ms logs [admin\|webmail]` | Follow service logs |
| `ms version` | Show the installed version |

### Backup / restore / rollback

| Command | Description |
|---|---|
| `ms backup create [--include-mails] [--encrypt]` | Create a config backup; `--encrypt` prompts for a passphrase (or takes `MAILSTACK_BACKUP_PASSPHRASE`) and encrypts with gpg AES256 — the passphrase never enters argv; public mode enforces encryption |
| `ms backup list` | List backups (name, time, size, includes-mail, encrypted) |
| `ms restore <archive>` | Safe restore: prompts for the passphrase on encrypted archives; auto-generates a pre-restore rollback snapshot; triple validation (filename / SHA256 / explicit confirm); refuses out-of-allowlist paths (e.g. unmanaged users' `.ssh`) and symlink/hardlink/device members |
| `ms rollback` | Roll back to the latest pre-restore snapshot |

### Install and maintenance

| Command | Description |
|---|---|
| `bash <(curl -fsSL .../deploy/install.sh)` | One-liner install (see [Quick Start](#quick-start)); runs as a single file and fetches the source from the signed release |
| `sudo bash mailstack.sh install [flags]` | Install from a source checkout (identical flags) |
| `ms upgrade [tag]` | Upgrade from the official **signed release trio** (tar.gz + SHA256SUMS + SHA256SUMS.sig); a missing `.sig` is an instant refusal; pin a specific tag |
| `ms upgrade --allow-downgrade` | Explicitly allow downgrading (refused by default; the allowance is audited as `downgrade_allowed`) |
| `ms uninstall --dry-run` | Uninstall dry-run: lists services to stop, files to delete, data to keep |
| `ms uninstall [--purge]` | Uninstall (see [Uninstallation](#uninstallation)) |
| `ms help` | Command help |

## Updates and Upgrades (Signed Channel)

```bash
ms upgrade              # upgrade to the latest signed release
ms upgrade v0.8.0-beta.7  # pin to a specific version
```

Channel design:

- **Signed release assets only**: downloads `MailStack-<tag>.tar.gz` + `SHA256SUMS` + `SHA256SUMS.sig`, verifies with `ssh-keygen -Y verify` against the on-host trust anchor (`/etc/mailstack/release-allowed-signers`, self-verified by the release pipeline with the same anchor), checks SHA256, and only then executes anything — **upgrades never run unverified remote code**
- **Downgrade refusal**: a target below the installed version is refused; a hijacked "latest" pointing at an older signed package is blocked too; the gate sits after signature + checksum verification and before any install action
- **Non-official sources refused**: a `MAILSTACK_REPO_URL` other than the official repository is rejected outright
- **Argument passthrough**: the persisted install arguments in `/etc/mailstack/install-args.conf` (access mode, domains, ports, HTTPS behavior) are passed through verbatim; explicit user flags override them
- **Developer git channel**: `MAILSTACK_ALLOW_UNSAFE_GIT=1` opts into clone-HEAD upgrades; hard-off in public mode (see the [security baseline](#access-modes-and-the-public-deployment-security-baseline))
- Release-side closure: `.github/workflows/release.yml` signs on tag push with an out-of-repo private key (GitHub Secret), re-verifies, and uploads the four assets; `scripts/package.py` supports gated local signing

Still recommended before upgrading: `ms backup create` and a VPS snapshot.

## Backups and Disaster Recovery

- Backups live in `/var/backups/mailstack`, files 0600; filenames and SHA256 are recorded in metadata; encrypted archives carry a lock marker
- **Encryption**: `--encrypt` uses gpg symmetric encryption (AES256); the passphrase only travels via stdin / environment; a missing `gpg` refuses the request (fail-closed, never silent plaintext); any encryption failure also removes the plaintext archive; public mode enforces encryption
- **Restore generates a rollback point**: `ms restore` snapshots the current state before restoring (encrypted with the same passphrase); corrupted snapshots are not registered as rollback points and produce a warning
- **Restore allowlist**: only allowlisted paths can be written (admin.json permission semantics preserved, key files restored 0600, `.ssh`, symlinks / hardlinks / device members refused)
- `/var/lib/mailstack` (the mailbox registry) is included in backup sources and the restore allowlist, so webmail logins survive disaster recovery
- Full runbook (with a one-minute quick reference): [docs/DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md)

## Uninstallation

```bash
sudo bash ./mailstack.sh uninstall --dry-run   # dry run
sudo bash ./mailstack.sh uninstall             # keep /etc/mailstack
sudo bash ./mailstack.sh uninstall --purge     # also remove admin config
```

Uninstalling stops and disables `mailstack-helper`, `mailstack-web`, and `mailstack-webmail`, removes service units, the `ms` link, the privileged wrapper and sudoers rules, and cleans MailStack-written component config; it **never** removes Postfix / Dovecot themselves, Linux mailbox users, or `/home/*/Maildir` and `/var/vmail` mailbox data.

## Ports and Environment Variables

| Service / module | Default port | Env vars | Default bind | Notes |
|---|---|---|---|---|
| **Admin console** | `8787` | `PORT`, `HOST` (legacy `ADMIN_PORT`, `ADMIN_HOST` accepted) | `127.0.0.1:8787` | Admin panel and privileged RPC dispatch endpoint |
| **Webmail** | `18788` | `WEBMAIL_PORT`, `WEBMAIL_HOST` | `127.0.0.1:18788` | Standalone webmail service |
| **Secure cookie** | - | `COOKIE_SECURE` | `0` (local) / `1` (caddy, direct) | `Secure; SameSite=Strict` |
| **Runtime** | - | `NODE_ENV` | `production` | Production mode |

Other environment variables:

| Variable | Default | Description |
|---|---|---|
| `MAILSTACK_SECURITY_PROFILE` | empty | `high` applies the public security baseline (same level as caddy/direct) |
| `MAILSTACK_HELPER_TIMEOUT_MS` | `120000` | Privileged RPC timeout (floor 5000; ACME issuance takes 30–90 s) |
| `MAILSTACK_HELPER_RO_SOCKET` | `/run/mailstack/helper-ro.sock` | Read-only socket path used by Node |
| `MAILSTACK_AI_OUTBOUND` | unset | Public-mode AI outbound master switch (`1`/`true` enables; explicit `0`/`false` disables); alternatively `enabled=true` in `/etc/mailstack/ai.conf` |
| `MAILSTACK_BACKUP_PASSPHRASE` | - | CLI backup passphrase (with `--encrypt`, never in argv) |
| `MAILSTACK_ALLOW_UNSAFE_GIT` | unset | Developer git-clone upgrade escape hatch; hard-off in public mode |
| `MAILSTACK_I_AM_A_DEVELOPER` | unset | The only public-mode exemption for the escape hatch (also requires local mode) |
| `MAILSTACK_AUDIT_FAILOPEN` | unset | Fail-open on audit errors; doctor FAIL in public mode |
| `MAILSTACK_SIGNING_KEY` | - | Packaging signing private key path (release-side only, `scripts/package.py`) |
| `MAILSTACK_ADMIN_PASSWORD` | empty | **Docker only**: first-start admin password (first start only; change via console afterwards) |
| `MAILSTACK_ADMIN_USER` | `admin` | **Docker only**: first-start admin username |
| `MAILSTACK_HOSTNAME` / `MAILSTACK_BIND` / `MAILSTACK_LISTEN_HOST` / `MAILSTACK_I_PUBLISH_ADMIN` | see compose | **Docker only**: container hostname / host bind / in-container listen / A6 publish acknowledgment |

Environment variables can go into `.env` (template in [.env.example](.env.example)) or systemd unit `Environment=`. The installer writes the units for production, so manual edits are usually unnecessary.

## Security Model

### Process and account isolation

- `mailstack-admin` and `mailstack-webmail` are separate no-login system accounts; `/opt/mailstack` is owned `root:root 0755` and not writable by service accounts (eliminating the "service account replaces the backend and uses sudoers to run forged code as root" local privilege-escalation chain)
- The webmail account has **no sudo rights at all**; it authenticates via the Dovecot auth socket and reads Maildir under controlled conditions
- Since rc.5 the sudoers policy is a **single rule** (pinned to the privileged wrapper, no argument wildcards), with legacy rules cleaned up on old machines

### Privileged operation minimization (RO/RW dual channels + peer checks)

- The privileged helper is a root daemon (`mailstack-helper.service`) serving RPC over unix sockets; the one-shot sudo wrapper remains as the mutation-channel entry and fallback
- The RO channel (14 read-only actions) and RW channel (all mutating actions) are separated by socket; an RW action on the RO socket is refused even with uid=0
- Every connection verifies the peer uid with `SO_PEERCRED`: the ro channel allows `{0, mailstack-admin}`, the rw channel only root; a failed getsockopt is also a refusal
- Actions outside the allowlist (`ALLOWED_ACTIONS_RO | ALLOWED_ACTIONS_RW`) are rejected; deleting domains / users / backups requires an explicit `confirm: true`

### Authentication, sessions, and credentials

- Admin password: PBKDF2-SHA256 (310000 iterations, 16-byte salt) in `/etc/mailstack/admin.json` (0640); TOTP master key sealed AES-256-GCM (root:root 0600); recovery codes stored hashed
- **Password policy**: 12–256 chars, must contain letters and digits, no 3+ identical/sequential characters, no account-identity tokens; authentication-only paths use legacy validation so existing passwords are never locked out
- Cookies are `HttpOnly; SameSite=Strict` plus `Secure` in HTTPS modes; sliding TTL with a 7-day absolute cap; password / 2FA changes clear sessions
- Dedicated rate limit on AI endpoints; 256 KB JSON body cap; information-free login errors

### systemd sandboxing

- `mailstack-helper`: the full hardening set (`ProtectSystem` / `PrivateTmp` / `NoNewPrivileges` etc.), with only the necessary `/etc` subtrees writable
- `mailstack-web`: `ProtectSystem=strict` with `/etc/mailstack` not writable (the rc.5 B4 tightening)
- `mailstack-webmail`: `ProtectSystem=strict`, `NoNewPrivileges`, `RestrictSUIDSGID`, with only `/home` and `/var/vmail` writable

### Outbound request hardening (anti-SSRF / DNS rebinding)

- AI and SMTP outbound: resolve, validate every resolved IP (loopback / private / link-local / CGNAT 100.64.0.0/10 / multicast / reserved), unwrap `::ffff:*` IPv4-mapped / sixtofour / teredo addresses before applying v4 rules (closing the mapping bypass), then pin the connection to the validated address
- Custom AI endpoints require HTTPS, reject embedded credentials, cap responses at 2 MB, reject cross-origin redirects; **AI outbound is fully off by default in public mode**

### Audit and tamper evidence

- Every privileged RPC audit record carries `prev_hash` (hash chain) + a `.head` anchor: truncation, tampering, and reordering are all detectable by `ms audit-verify`
- Audit records mirror to syslog `AUTHPRIV` (the off-host log channel for containers / diskless setups)
- The `MAILSTACK_AUDIT_FAILOPEN` escape hatch is a doctor FAIL in public mode

### Supply chain and releases

- **Node.js**: distro packages first; fallback to official tarballs verified against SHA256 constants (musl automatically switches to the `linux-x64-musl` channel); NodeSource `curl | bash` is gone
- **Install bootstrap**: `deploy/install.sh` runs standalone (it fetches the source from the signed release), but the bootstrap only does "download → `ssh-keygen -Y verify` → `sha256sum -c` → extract → hand off to the installer" and contains no installation logic; a failed signature or checksum aborts before anything is executed — unverified remote content is never run
- **Caddy**: Cloudsmith fallback verifies the GPG fingerprint first; **acme.sh**: pinned 3.1.4 tarball + SHA256; **fail2ban** pip fallback: pinned 1.1.0 tarball SHA256
- **Release signing**: `scripts/package.py` gated signing (`MAILSTACK_SIGNING_KEY`); `release.yml` signs in CI with an out-of-repo key and re-verifies; the upgrade side verifies byte-for-byte identically
- Prebuilt artifacts carry `build-manifest.json` with per-file SHA256; reproducible packaging (fixed `SOURCE_DATE_EPOCH`, two builds must hash identically); CI `npm audit` hard gate on high + CycloneDX SBOM

### External review record

[docs/pentest-2026-09.md](docs/pentest-2026-09.md) holds a six-area review test record (login brute force / user enumeration / CSRF; helper socket peer and channel abuse; backup path traversal and plaintext archives; AI SSRF; upgrade signature / downgrade / UNSAFE_GIT; webmail argv / Maildir permissions): every "fixed" item lists its implementation location and test names, residual risks are recorded honestly, and the methodology statement is public and re-runnable. The STRIDE deep-dive lives in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## AI Mail Advisor

| Provider | Preset endpoint | Default model | Protocol |
|---|---|---|---|
| **GLM (BigModel)** (default) | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-flash` (also `glm-4-plus` / `glm-4-air` / `glm-4-long`) | OpenAI-compatible |
| **DeepSeek** | `https://api.deepseek.com/v1` | `deepseek-chat` | OpenAI-compatible |
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o-mini` | OpenAI-compatible |
| **Anthropic Claude** | `https://api.anthropic.com/v1` | `claude-3-5-sonnet-20241022` | Anthropic Messages |
| **Custom** | any public HTTPS OpenAI-compatible / Anthropic endpoint | user-supplied | OpenAI / Anthropic |

- Chat assistant, DNS / TLS / relay / bounce-log diagnostics, structured parsing; falls back to local rule-based diagnostics without any external API key
- API keys are stored server-side in `/etc/mailstack/ai-provider.json` and never returned to the browser
- AI outbound is off by default in public mode (see the [security baseline](#access-modes-and-the-public-deployment-security-baseline)); local mode keeps the historical behavior
- Provider quotas, models, and data policies may change — defer to their current terms; **AI advice is not a substitute for admin review and does not guarantee delivery**

## Testing and Quality Assurance

### Baseline gates (measured on this release)

| Gate | Result |
|---|---|
| Python privileged-helper behavioral tests | **106 tests passing** (environment-dependent half skipped on Windows, skip=9) |
| Node contract / integration / security-static tests | **86 passing** |
| Frontend Vitest | **12 passing** |
| `tsc --noEmit` | zero errors |
| shellcheck `-S warning` | zero warnings across all 12 deployment/verification scripts |
| `verify_release_consistency` | 100% |

Behavioral assertion system (T-*): public-mode 2FA gate (T-2FA-1a/1b/2), SO_PEERCRED peers (T-PEER-2), dual-socket channels (T-SOCK-1/2), escape hatches (T-ESC-1), sandbox (T-PERM-1 helper/web), backup encryption (T-BKP-1), audit chain (T-AUD-1), downgrade gate (T-UP-1), Docker admin port (T-DOCK-1) and more — 14 in total — plus dedicated tests for login brute force / user enumeration / CSRF, backup path traversal, AI SSRF, and the webmail auth socket.

### Local test commands

| Command | Content |
|---|---|
| `npm run lint` | Full TypeScript type check |
| `npm test` | Node built-in test runner: API contract, business integration, lifecycle, security-static, observability, public-mode gate, upgrade/downgrade, webmail auth socket, Docker entrypoint and more — 17 suites |
| `npm run test:frontend` | Vitest + Testing Library frontend tests |
| `npm run test:helper` | Python privileged-helper behavioral tests |
| `npm run test:backup` | Backup / restore end-to-end (including encrypted round-trip and `.ssh` restore refusal) |
| `npm run test:all` | All of the above + build |
| `npm run build:all` | Frontend + console + webmail + artifact manifest |

### CI (GitHub Actions)

| Job | Content |
|---|---|
| **build** | Node 20 / 22 / 24 matrix: type check, Python helper tests, Node contract and integration, frontend tests, `build:all`, artifact checks, version consistency, reproducible packaging |
| **shell-gate** | shellcheck (error-level hard gate + zero-warning target) + undefined-function scan of release scripts |
| **install-matrix** | Real non-interactive installs in clean ubuntu:24.04 / ubuntu:22.04 / debian:12 / rockylinux:9 containers + health assertions + privilege probes + single-sudoers + jail presence + trust anchor + loopback send (`scripts/ci_install_assertions.sh`) + **malicious domain Caddyfile injection gate** (`scripts/ci_domain_injection_test.sh`) |
| **supply-chain** | `npm audit` high-severity hard gate + fixable-moderate gate + CycloneDX SBOM |
| **release** (tag-triggered) | tag must match VERSION → build → gated signing → re-verify → archive layout assertion → upload tar.gz / zip / SHA256SUMS / SHA256SUMS.sig |

## Project Structure

```text
mailstack.sh                      Unified entry: install / update(upgrade) / doctor / audit-verify /
                                  test-mail / backup / restore / rollback / uninstall / status / logs
├── deploy/
│   ├── install.sh                Interactive and non-interactive installer (access modes, build, accounts, systemd, Caddy)
│   ├── install-mail-stack.sh     Mail base stack installation and verification (with degraded-component registry)
│   ├── install-v05.sh            Installer entry for release archives
│   ├── mailstack-privileged      Root privileged wrapper (the only sudoers target)
│   ├── mailstack-release.pub / .allowed_signers   Release-signature trust anchors
│   ├── init.d-mailstack.in.sh    init.d template for systemd-less branches (shellcheck-covered)
│   ├── mailstack.logrotate       Log rotation (three-segment copytruncate policy)
│   ├── reverse-proxy-nginx.example.conf   Nginx reverse-proxy example (direct mode)
│   ├── verify-release-scripts.sh Undefined-function scan for release scripts
│   ├── verify-source-build.sh / privacy-audit.sh
├── backend/
│   ├── server.production.ts      Express console: auth + TOTP branching, session management, public-mode gate, RPC proxy
│   └── mailstackctl/
│       ├── core.py               Constants, RO/RW allowlists, audit hash chain + syslog mirror, password policy
│       ├── dispatcher.py         RPC action dispatch
│       ├── daemon.py             Root-resident helper (dual sockets, SO_PEERCRED, concurrency cap)
│       ├── mail.py / network.py / certs.py / backup.py / security.py / telemetry.py / ai.py
│       └── totp.py               TOTP and recovery codes (envelope encryption, atomic consumption)
├── webmail/
│   ├── server.mjs                Standalone webmail (epoch sessions, 7-day cap, rate limits)
│   ├── dovecot-auth.mjs          Dovecot auth-client socket protocol (passwords never in argv)
│   └── public/                   Webmail frontend
├── docker/
│   └── entrypoint.sh             Container first-start orchestration (volume seeding, password init, A6 gate)
├── Dockerfile / docker-compose.yml / .dockerignore
├── src/                          React admin console source (views / setup / dns / telemetry)
├── scripts/                      Packaging, manifests, CI assertion and E2E test scripts
├── tests/                        Node / Vitest / Python suites (17 Node suites)
├── docs/
│   ├── SUPPORT_MATRIX.md         Distribution support matrix and capability notes
│   ├── DOCKER.md                 Docker deployment guide
│   ├── THREAT_MODEL.md           STRIDE threat model
│   ├── DISASTER_RECOVERY.md      Disaster recovery runbook
│   ├── DATA_PRIVACY.md           Data residency and log red lines
│   ├── VULNERABILITY_RESPONSE.md Vulnerability response SLA and VEX (single authoritative source)
│   ├── pentest-2026-09.md        Six-area external review test record
│   ├── RELEASE_CHECKLIST.md / DEPENDENCY_POLICY.md
│   └── verification/             Ubuntu 24.04 / Debian 12 real-machine records, mail delivery E2E
├── .github/workflows/ci.yml / release.yml
├── .env.example
└── CHANGELOG.md                  v0.1.0-beta.1 → v0.8.0-beta.7 full changelog
```

## Development Guide

Stack: React 19, TypeScript 5.8, Vite 6, Tailwind CSS 4, Express 4, esbuild, the Node built-in test runner, Vitest, Python 3 standard library (≥3.10, PEP 604).

```bash
npm install          # install dependencies
npm run dev          # Vite dev server (frontend)
npm run lint         # type check
npm run build:all    # frontend + console + webmail + artifact manifest
npm start            # run the packaged console
npm test             # Node tests
```

Dependency policy ([docs/DEPENDENCY_POLICY.md](docs/DEPENDENCY_POLICY.md)): the release artifacts `dist/server.cjs` and `dist/webmail.cjs` are self-contained esbuild bundles that need no runtime `node_modules`; the privileged helper uses only the Python standard library; new network-facing dependencies require a security review, a pinned version range, and a release-note entry.

For container development / verification use `docker compose build && docker compose up` — the image build runs the same installer path as CI.

## Known Limitations

- Public beta: end-to-end coverage of Tier 2 / experimental platforms relies on CI and live testing; rehearse on a clean machine before production
- The 5-second frontend polling remains (RPCs now ride the resident helper socket, far cheaper than the early per-call sudo + Python spawns; a push mechanism is planned)
- Advanced relay failover and duplicate-delivery prevention state machines need further validation; ACME issuance, DNS API credential rotation, and multi-CA rollback need strengthening
- Residual risks from the review are published honestly in [docs/pentest-2026-09.md](docs/pentest-2026-09.md) and are not presented as verified
- Demo / mock data does not represent real server state; AI advice is not a substitute for admin review

## FAQ

**Q: Why is 2FA mandatory in public mode?**
The public admin console is the control plane of the whole server. A leaked single factor means full takeover, so under `caddy` / `direct` (or `MAILSTACK_SECURITY_PROFILE=high`) the console serves only login and TOTP enrollment until 2FA is enabled, and binds back to `127.0.0.1` — this is fail-closed by design, not a hint.

**Q: What is the Docker first-start password?**
Provide `MAILSTACK_ADMIN_PASSWORD` and it is used directly (a value failing the 12-char letters-and-digits policy fails startup); leave it empty and a random password is generated and printed exactly once in `docker compose logs`. The variable only takes effect on first start (no admin.json in the volume yet).

**Q: Can I downgrade to an older version?**
Refused by default. `ms upgrade --allow-downgrade` explicitly allows it and writes a `downgrade_allowed` audit record; a hijacked "latest" pointing at an older signed package is blocked by the downgrade gate too.

**Q: Why are AI features unavailable in public mode?**
The public baseline turns AI outbound fully off by default (preventing the outbound channel that sends log / config excerpts to third-party APIs from being abused). If you confirm you need it, set `MAILSTACK_AI_OUTBOUND=1` or write `enabled=true` in `/etc/mailstack/ai.conf`.

**Q: Why does backup require a passphrase?**
Backups contain Postfix config, DKIM private keys, and credential hashes — plaintext on disk is the control plane in a tarball. Public mode enforces encryption (gpg AES256) and refuses rather than degrading to plaintext when `gpg` is missing; in local mode encryption is optional.

**Q: I forgot to expose a port and cannot open the console?**
Run `ssh -L 8787:127.0.0.1:8787 -L 18788:127.0.0.1:18788 root@server-ip` locally, then open `http://127.0.0.1:8787`.

**Q: Can you guarantee inbox placement?**
No. Deliverability depends on IP / domain reputation, DNS authentication completeness, content quality, and recipient policies. MailStack helps you get the controllable parts right and ships diagnostics to locate problems.

## Contributing

Welcome to report reproducible issues via GitHub Issues. Please include: OS and version, MailStack version, installation method, `ms status` / `ms doctor` output, redacted logs, and reproduction steps.

**Never post publicly**: SMTP passwords, admin hashes, AI keys, DKIM private keys, TLS private keys, ACME DNS credentials, backup passphrases, mailbox content, or unredacted production logs.

Before opening a PR, make sure `npm run test:all` passes; deployment-script changes go through the shell-gate and install-matrix gates; security-relevant changes should be checked against the non-goals and trust boundaries in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting Security Issues

Do **not** disclose vulnerabilities in public issues. Use GitHub Private Vulnerability Reporting or the maintainer's private channel; the single authoritative source for SLA and VEX policy is [docs/VULNERABILITY_RESPONSE.md](docs/VULNERABILITY_RESPONSE.md). Supported version lines and the threat-model summary are in [SECURITY.md](SECURITY.md).

## Documentation Index

| Document | Content |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | v0.1.0-beta.1 → v0.8.0-beta.7 per-version changes, with the full background of every security fix |
| [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) | Distribution support matrix and capability notes |
| [docs/DOCKER.md](docs/DOCKER.md) | Docker deployment: port model, volume layout, first-start password |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | STRIDE threat model (asset tiers, trust boundaries, non-goals) |
| [docs/DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md) | Disaster recovery runbook (with a one-minute quick reference) |
| [docs/DATA_PRIVACY.md](docs/DATA_PRIVACY.md) | Data residency (where data lives, who can read it) and log red lines |
| [docs/VULNERABILITY_RESPONSE.md](docs/VULNERABILITY_RESPONSE.md) | Vulnerability response SLA and VEX policy |
| [docs/pentest-2026-09.md](docs/pentest-2026-09.md) | Six-area review test record (fixed items and residuals, honestly) |
| [docs/verification](docs/verification) | Ubuntu 24.04 / Debian 12 real-machine records, mail delivery E2E |
| [README.md](README.md) | 简体中文 README |
| [.env.example](.env.example) | Environment variable template |

## License

MailStack is released under the [MIT License](LICENSE).

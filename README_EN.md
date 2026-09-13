<p align="center">
  <img src="assets/mailstack-logo.png" alt="MailStack Logo" width="180">
</p>

<h1 align="center">MailStack</h1>

<p align="center">
  Multi-Domain Mail Server Deployment and Administration for systemd Linux
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="https://github.com/SectorPace/MailStack">GitHub Repository</a> ·
  <a href="https://github.com/SectorPace/MailStack/releases">Releases</a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.5.0--beta.2-2476ff">
  <img alt="Status" src="https://img.shields.io/badge/status-public%20beta-f0a53a">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-27b36a">
  <img alt="Platform" src="https://img.shields.io/badge/platform-systemd%20Linux-22c7d6">
</p>

> **Release status: v0.5.1-beta.1.** This is a public beta. Test it on a fresh VPS before considering any production deployment.

## Overview

MailStack integrates Postfix, Dovecot, a Liquid Glass Web administration console, outbound SMTP relay support, TLS, DKIM and DNS guidance, mail queue and log administration, security checks, and a configurable AI mail assistant.

MailStack cannot guarantee inbox placement. Delivery depends on IP and domain reputation, authentication, message content, bounces and complaints, relay-provider policies, and recipient-side filtering.

## Features

- Liquid Glass React administration console
- Simplified Chinese and English interfaces
- Light and Dark themes
- Custom Web administrator username, password, port, and listening address
- `mailstack` VPS management command
- Domain, local mailbox user, and alias administration
- Postfix and Dovecot service status management
- Outbound SMTP Relay configuration and provider presets
- TLS certificate, DKIM, and DNS management views
- Mail Queue, logs, services, and Security Center
- HttpOnly session cookie and CSRF protection
- Restricted privileged helper instead of arbitrary shell execution
- Gemini, Groq, OpenRouter, Mistral, Cerebras, and custom compatible APIs
- Local rule-based diagnostics when no external AI API is configured

## Service Ports & Environment Variables

| Service / Module | Default Port | Env Variable | Default Bind | Description |
|---|---|---|---|---|
| **Admin Console** | `8787` | `PORT`, `HOST` | `127.0.0.1:8787` | Web control plane & privileged RPC dispatcher |
| **Webmail Client** | `18788` | `WEBMAIL_PORT`, `WEBMAIL_HOST` | `127.0.0.1:18788` | Standalone Webmail client |
| **Secure Cookie** | - | `COOKIE_SECURE` | `0` (local) / `1` (caddy/direct) | Enables `Secure; SameSite=Strict` flags |
| **Node Environment** | - | `NODE_ENV` | `production` | Production runtime |

## Access & Deployment Modes

| Mode | Bind Address | Use Case | Security | Recommended Access |
|---|---|---|:---:|---|
| **`local`** | `127.0.0.1` | Default baseline | 🟢 **High** | Local SSH Port Forwarding (`ssh -L 8787:...`) |
| **`caddy`** | `127.0.0.1` + Caddy | Public multi-domain | 🟢 **High** | Fully automated Let's Encrypt TLS certificates |
| **`direct`** | `127.0.0.1` | Custom Nginx/Proxy | 🟡 **Medium** | User-managed reverse proxy & TLS termination |
| **`plain`** | `0.0.0.0` | Isolated testing | 🔴 **Low** | Plaintext HTTP, requires `--i-understand-plain-http` |

## Quick Start

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

The installer asks for the Web administrator username, password, management port, and listening address. The default endpoint is `127.0.0.1:8787`.

```bash
ssh -L 8787:127.0.0.1:8787 root@SERVER_IP
```

Open `http://127.0.0.1:8787` locally after establishing the tunnel.

## VPS Commands

```bash
mailstack
mailstack admin
mailstack port
mailstack status
mailstack logs
```

## Update

```bash
cd MailStack
git pull
sudo bash ./mailstack.sh update
```

Create a VPS snapshot and back up MailStack, Postfix, Dovecot, DKIM, and mailbox data before updating.

## Uninstall

Preserve MailStack administration settings:

```bash
sudo bash ./mailstack.sh uninstall
```

Remove `/etc/mailstack` as well:

```bash
sudo bash ./mailstack.sh uninstall --purge
```

The uninstall flow does not automatically remove Postfix, Dovecot, Linux mailbox users, or mailbox data.

## AI Diagnostics

The AI Center supports DNS and delivery configuration guidance, TLS and relay troubleshooting, log analysis, Gemini REST, OpenAI-compatible endpoints, provider presets, custom public HTTPS endpoints, and an offline rule-based mode.

API keys remain on the server and are not returned to the browser. Custom API endpoints reject loopback, private, link-local, multicast, and reserved targets to reduce SSRF risk.

Third-party free quotas, model availability, regional restrictions, and data policies may change. Verify the provider's current console and terms before relying on a free tier.

## Security Recommendations

- Keep the Web console on `127.0.0.1` by default
- Use an SSH tunnel, VPN, or HTTPS reverse proxy
- Do not expose the management port directly to the public Internet
- Protect SMTP, AI, ACME DNS, and DKIM credentials
- Never commit `.env`, `/etc/mailstack`, `sasl_passwd`, or private keys
- Configure MX, SPF, DKIM, DMARC, and PTR
- Monitor certificate expiry, disk space, queues, and failed logins
- Back up configuration and create a VPS snapshot before dangerous operations

## Administrator Two-Factor Authentication (2FA)

The admin console supports time-based one-time passwords (TOTP, RFC 6238): after a correct password, a 6-digit authenticator code is required.

**Enrollment:**

1. Open the 2FA card on the Account Settings page and start the enrollment (the server generates a fresh TOTP secret);
2. Add the account in your authenticator app (e.g. Google Authenticator, 1Password) by pasting the displayed `otpauth://` URI or entering the secret manually;
3. Enter the current 6-digit code to confirm and enable 2FA;
4. Enabling shows **10 one-time recovery codes** (`xxxxxxxx-xxxxxxxx`) exactly once. Store them offline immediately: only their hashes are kept server-side, and they cannot be shown again after closing the dialog.

**Recovery-code sign-in:** when 2FA is enabled and no authenticator code is available, enter any unused recovery code in the code field at login. Each code is consumed once; the remaining count is visible on the Account Settings page.

**Disabling:** click disable on the 2FA card and provide a current TOTP code or an unused recovery code.

Additional behavior: enabling/disabling 2FA or changing the admin password revokes all existing sessions; codes are replay-protected (each 30-second step is accepted at most once); a server clock skew beyond roughly 30 seconds will keep codes failing — enable NTP (see `docs/DISASTER_RECOVERY.md`).

## Signed Upgrade Channel

`ms upgrade` now uses the **official signed Release assets** by default and exclusively:

- Downloads the triple: `MailStack-<tag>.tar.gz` + `SHA256SUMS` + `SHA256SUMS.sig`;
- Verifies the detached signature on `SHA256SUMS` with `ssh-keygen -Y verify` (ed25519, identity `mailstack-release`, trust anchor at `/etc/mailstack/release-allowed-signers` installed at setup time), then checks the archive checksum;
- **Releases without a signature are refused outright**; any signature or checksum failure aborts before any install script runs;
- `ms upgrade <tag>` pins a specific release instead of unconditionally following latest;
- A non-official `MAILSTACK_REPO_URL` is rejected.

```bash
ms upgrade             # upgrade to the latest signed release (signature verified)
ms upgrade v0.5.2-rc.5 # pin a specific release tag (signature verified)
```

Developer mode: setting `MAILSTACK_ALLOW_UNSAFE_GIT=1` switches to a `git clone` upgrade path. **Never use it in production**: it executes the remote repository's `install.sh` as root without any signature verification, effectively handing the host to that git remote.

## Project Structure

```text
mailstack.sh                  Unified install, update, and uninstall entry point
deploy/install.sh             Interactive and non-interactive installer
deploy/mailstack-cli          VPS management menu
backend/server.production.ts  Authenticated Web API
backend/mailstackctl.py       Restricted privileged helper
src/                          React administration console
assets/mailstack-logo.png     Project logo
```

## Development

```bash
npm install
npm run lint
npm run build
```

## Docker Deployment (Optional)

MailStack can also run as a single container (`ubuntu:24.04` base, reusing the same
non-interactive installer):

```bash
docker compose build
MAILSTACK_ADMIN_PASSWORD='Your-Strong-Admin-Pass-7' docker compose up -d
```

There is no systemd inside the container: the six core processes are orchestrated by
the entrypoint (`docker/entrypoint.sh` + tini). The admin password is initialized on
first boot via environment variable or generated randomly and printed once — plaintext
passwords never enter any image layer. Ports, volumes, upgrades, differences from the
bare-metal install, and known limitations (outbound port 25, WSL2) are documented in
[docs/DOCKER.md](docs/DOCKER.md).

## Known Limitations

- This is a Beta release without complete end-to-end validation across every distribution
- Advanced relay failover and duplicate-delivery prevention require more testing
- Initial ACME issuance, DNS API credential rotation, and multi-CA rollback require further work
- DKIM, Rspamd, ClamAV, Fail2ban, and firewall behavior varies by distribution
- AI guidance requires administrator review and cannot guarantee delivery
- Demo or Mock data must not be interpreted as live server state

## Contributing

Please include the operating system, MailStack version, installation method, relevant service state, redacted logs, and reproducible steps. Never post SMTP passwords, administrator hashes, AI keys, DKIM or TLS private keys, ACME DNS credentials, mailbox content, or unredacted production logs.

## License

MailStack is released under the MIT License. See [LICENSE](LICENSE).

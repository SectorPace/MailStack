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
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1--beta1-2476ff">
  <img alt="Status" src="https://img.shields.io/badge/status-public%20beta-f0a53a">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-27b36a">
  <img alt="Platform" src="https://img.shields.io/badge/platform-systemd%20Linux-22c7d6">
</p>

> **Release status: v0.1-beta1.** This is a public beta. Test it on a fresh VPS before considering any production deployment.

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

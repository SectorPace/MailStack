<p align="center">
  <img src="assets/mailstack-logo.png" alt="MailStack Logo" width="180">
</p>

<h1 align="center">MailStack</h1>

<p align="center">
  Multi-domain mail server deployment and visual administration for Linux VPS environments
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="https://github.com/SectorPace/MailStack/issues">Issue Tracker</a> ·
  <a href="https://github.com/SectorPace/MailStack/releases">Releases</a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1--beta1-2476ff">
  <img alt="Status" src="https://img.shields.io/badge/status-public%20beta-f0a53a">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-27b36a">
  <img alt="Platform" src="https://img.shields.io/badge/platform-systemd%20Linux-22c7d6">
</p>

> [!WARNING]
> **MailStack v0.1-beta1 is a public beta.** Test it on a fresh VPS first. Do not install it over an existing production mail server. Create a VPS snapshot and back up all mail data and configuration before updating, restoring, or uninstalling.

## Overview

MailStack combines common mail server capabilities, a Web administration console, and a VPS terminal management menu in one project. Its goal is to simplify the deployment and administration of Postfix, Dovecot, outbound SMTP Relay, TLS, DKIM, DNS, mail queues, and service logs.

The Web console is built with React, TypeScript, Vite, and a Liquid Glass visual design. It supports Chinese, English, Light mode, and Dark mode. After installation, administrators can sign in through the VPS public IP and management port, or manage the service from the terminal with the `ms` command.

MailStack cannot guarantee inbox placement. Delivery also depends on IP and domain reputation, PTR, SPF, DKIM, DMARC, message content, complaint rates, bounce rates, SMTP Relay provider policies, and recipient-side filtering.

## Main Features

### Web Administration Console

- Administrator username and password authentication
- HttpOnly session cookie
- CSRF request protection
- Login failure rate limiting
- Administrator username and password changes
- Automatic revocation of all existing sessions after credentials change
- Custom management port and listening address
- Public listening by default for VPS administration
- Chinese and English interfaces
- Light and Dark themes
- Liquid Glass visual style

### Mail System Administration

- Mail domain management
- Linux mailbox user management
- Mail address alias management
- Postfix and Dovecot service status
- SMTP Relay configuration and provider presets
- TLS certificate administration interface
- DKIM and DNS setup guidance
- MX, SPF, DKIM, DMARC, and PTR recommendations
- Mail queue inspection and flushing
- Deferred queue cleanup
- Mail service log inspection
- Security status and basic diagnostics

### AI Mail Assistant

- Mail DNS configuration analysis
- TLS and SMTP Relay troubleshooting
- Bounce and log excerpt explanation
- Gemini REST API
- OpenAI-compatible API
- Groq, OpenRouter, Mistral, and Cerebras presets
- Custom public HTTPS API endpoints
- Local rule-based mode without an external API

AI API keys remain on the server and are never returned to the browser. Custom API endpoints reject loopback, private, link-local, and reserved addresses to reduce SSRF risk.

Third-party free quotas, models, regional restrictions, and data policies may change. Always verify the provider's current console and terms before relying on a free tier.

## System Requirements

Recommended test environment:

- A fresh Debian or Ubuntu VPS
- systemd
- Root or sudo access
- At least 1 GB RAM, with 2 GB or more recommended
- A usable public IPv4 address
- A domain with manageable DNS records
- Access to the cloud security group or VPS firewall

The installer attempts to install base dependencies on supported systems. On Debian and Ubuntu, if Node.js 20 or later is unavailable, the installer attempts to install Node.js 22.

Other Linux distributions may require additional adaptation because package names, systemd units, log paths, and mail component versions differ.

## Quick Installation

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

The installer asks for:

- Web administrator username
- Web administrator password
- Management port
- Listening address

Default values:

```text
Listening address: 0.0.0.0
Management port: 8787
```

After installation, open:

```text
http://VPS_PUBLIC_IP:8787
```

The corresponding TCP management port must also be allowed in the cloud security group and the Linux firewall.

> [!IMPORTANT]
> Public access is enabled by default for convenient VPS administration. For production use, configure HTTPS, a strong password, firewall controls, and source IP restrictions as soon as possible. Do not use an unencrypted HTTP login page on the public Internet long-term.

## Non-Interactive Installation

The password is passed through standard input to avoid exposing it in shell history or process arguments:

```bash
printf '%s\n' 'YourStrongPasswordHere' | sudo bash ./mailstack.sh install \
  --admin-user admin \
  --admin-port 8787 \
  --admin-host 0.0.0.0 \
  --admin-password-stdin \
  --non-interactive
```

The administrator password must contain at least 12 characters.

## The `ms` VPS Command

After installation, run the following command from any directory on the VPS:

```bash
ms
```

`ms` is the official MailStack management command. The project also keeps `mailstack` as a compatibility alias, but all new documentation uses `ms`.

Common subcommands:

```bash
ms status
ms logs
ms health
ms admin
ms port
ms backup
ms update
ms repair
ms uninstall
ms purge
ms version
```

If the current account is not root, add `sudo`:

```bash
sudo ms
```

## VPS Management Menu

Run:

```bash
ms
```

The menu provides the following operations.

### Web Console Management

```text
1) Show Web console status
2) Start the Web console
3) Stop the Web console
4) Restart the Web console
5) Show recent Web logs
6) Follow live Web logs
7) Change administrator credentials
8) Change listening address and port
9) Run Web console health diagnostics
```

### Mail System

```text
10) Show mail service status
11) Restart installed mail services
12) Show the mail queue
13) Flush the mail queue
14) Delete the deferred queue
15) Show mail service logs
```

### Security and Network

```text
16) Run a security scan
17) Show firewall status
18) Show network interfaces and listening ports
```

### Backup and Maintenance

```text
19) Create a configuration backup
20) List backups
21) Restore a backup
22) Update MailStack
23) Repair or reinstall MailStack
24) Update system packages
```

### Uninstall and Cleanup

```text
25) Uninstall the program and preserve configuration
26) Purge MailStack administration components
```

Dangerous operations require an explicit confirmation phrase to reduce accidental deletion.

## Updating MailStack

After installation, update MailStack from any directory on the VPS:

```bash
sudo ms update
```

The updater attempts to:

- Retrieve the latest source
- Preserve the administrator account
- Preserve the management port and listening address
- Update the front end and production API
- Update the `ms` command
- Restart `mailstack-web`
- Verify the systemd service and health endpoint

Create a backup before updating:

```bash
sudo ms backup
```

If an update fails or the installation becomes inconsistent:

```bash
sudo ms repair
```

Check status and logs:

```bash
sudo ms status
sudo ms logs
```

If the `ms` command itself is accidentally removed, restore it from the source directory:

```bash
cd ~/MailStack
sudo cp deploy/mailstack-cli /usr/local/bin/ms
sudo chmod 0755 /usr/local/bin/ms
sudo ln -sfn /usr/local/bin/ms /usr/local/bin/mailstack
```

## Changing the Administrator Account

Run on the VPS:

```bash
sudo ms admin
```

Alternatively, sign in to the Web console and change the administrator username and password in System Settings.

After new credentials are saved, all existing Web sessions are revoked. Sign in again with the new credentials.

The MailStack administrator account is independent from:

- The Linux root account
- SSH accounts
- Mailbox users
- Postfix SASL users
- Dovecot mailbox authentication users

Administrator credentials are stored in:

```text
/etc/mailstack/admin.json
```

Passwords are derived with PBKDF2-SHA256, a random salt, and repeated iterations. Plaintext passwords are not stored.

## Changing the Management Port

```bash
sudo ms port
```

The command can configure:

- The management port
- `0.0.0.0` for public listening
- `127.0.0.1` for IPv4 loopback-only listening
- `::1` for IPv6 loopback-only listening

After a change, the script reloads systemd and restarts the Web console.

When changing the port, also update:

- The cloud security group
- UFW, firewalld, or nftables
- The HTTPS reverse proxy
- Monitoring and access URLs

## Backup and Restore

Create a backup:

```bash
sudo ms backup
```

Default backup directory:

```text
/var/backups/mailstack/
```

Depending on what exists on the system, a backup may include:

```text
/etc/mailstack
/etc/postfix
/etc/dovecot
/etc/opendkim
/etc/systemd/system/mailstack-web.service
/opt/mailstack
```

Use the `ms` menu to list and restore backups.

> [!CAUTION]
> Restoring a backup overwrites current configuration. Create a separate VPS snapshot and verify that the backup archive is complete before restoring.

## Uninstallation

### Uninstall the Program and Keep Configuration

```bash
sudo ms uninstall
```

This mode removes the MailStack Web application, systemd service, and command shortcuts, while preserving `/etc/mailstack` and mail data.

### Purge MailStack Administration Components

```bash
sudo ms purge
```

This mode also removes the administrator and MailStack management configuration under `/etc/mailstack`.

By default, neither mode automatically removes:

- Postfix
- Dovecot
- Linux mailbox users
- Mailbox data
- The mail queue

This behavior reduces the risk of accidentally deleting real mailbox data.

## Installation Paths

```text
/opt/mailstack                  MailStack runtime directory
/opt/mailstack/ui               Front-end source and build output
/opt/mailstack/server.cjs       Production Web API
/opt/mailstack/backend          Restricted privileged helper
/opt/mailstack-source           Source copy used for updates and repairs
/etc/mailstack                  Administrator and MailStack configuration
/usr/local/bin/ms               Official command shortcut
/usr/local/bin/mailstack        Compatibility alias
/var/backups/mailstack          Default backup directory
```

## Project Structure

```text
mailstack.sh                    Install, update, and uninstall entry point
deploy/install.sh               System installer
deploy/mailstack-cli            VPS management menu and ms command
backend/server.production.ts    Authentication and Web API
backend/mailstackctl.py         Restricted privileged helper
src/                            React administration console source
assets/mailstack-logo.png       Project logo
```

## Development Build

Install dependencies:

```bash
npm install --include=optional
```

Run type checking:

```bash
npm run lint
```

Build the front end:

```bash
npm run build
```

The installer builds the authenticated production API separately from:

```text
backend/server.production.ts
```

This separation prevents the old development server from being confused with the authenticated production API.

## Security Recommendations

- Use a strong, unique password for the Web administrator
- Configure HTTPS for the public Web endpoint as soon as possible
- Restrict the Web console by source IP where practical
- Never commit SMTP passwords, AI keys, DKIM private keys, or ACME DNS credentials
- Never commit `.env`, `admin.json`, `ai-provider.json`, or `sasl_passwd`
- Monitor certificate expiration
- Monitor disk usage and mail queue growth
- Configure MX, SPF, DKIM, DMARC, and PTR
- Create a VPS snapshot and MailStack backup before updating
- Redact logs before posting them in an Issue

## Known Limitations

- This is still a Beta release
- End-to-end validation is not complete across every Linux distribution
- Advanced SMTP Relay failover and duplicate-delivery prevention require further testing
- Initial ACME issuance, DNS-01 automation, and certificate rollback require further development
- DKIM, Rspamd, ClamAV, Fail2ban, and firewall behavior may require distribution-specific adaptation
- AI guidance does not replace administrator review
- AI diagnostics cannot guarantee inbox placement
- Mock or demonstration data must not be interpreted as live server state

## Reporting Issues

When opening an Issue, include:

- Linux distribution and version
- CPU architecture
- MailStack version
- Installation or update method
- Relevant systemd service status
- Redacted logs
- Reproducible steps

Do not publicly submit:

- SMTP passwords
- Administrator passwords or hashes
- AI API keys
- DKIM or TLS private keys
- ACME DNS credentials
- Mailbox content
- Unredacted production logs

## License

MailStack is released under the [MIT License](LICENSE).

# MailStack Admin Console Integration Preview

This package combines the generated React Liquid Glass console with an authenticated production API and a restricted privileged helper.

## Implemented backend integration

- HttpOnly administration session cookie
- CSRF token for state-changing API calls
- Real snapshot loading from Linux services
- Postfix virtual domain management
- Local Linux mailbox user creation and deletion
- Postfix alias mapping
- systemd service inspection and restart
- Postfix queue listing, retry, flush and deletion
- journald mail log loading
- MailStack-managed TLS certificate inspection
- ACME renewal hook invocation
- Basic open-relay, Fail2ban, credential-permission and TLS checks

## Safety model

The Node service runs as `mailstack-admin`. Only `/opt/mailstack/backend/mailstackctl.py` is allowed through sudo. The helper uses fixed argument arrays, identifier validation, atomic file writes, Postfix syntax checks and service reloads. SMTP credentials and private keys are not returned to the browser.

## Install

This is an integration preview. Test on a disposable server first.

```bash
sudo bash deploy/install.sh
```

The Web service listens on `127.0.0.1:8787`. Read the administration token with:

```bash
sudo cat /etc/mailstack/admin.token
```

Use an SSH tunnel, VPN, or HTTPS reverse proxy. Do not expose port 8787 directly to the public Internet.

## Known incomplete UI connections

The UI design contains advanced screens for multi-provider relay failover, DNS automation, full ACME issuance, DKIM key rotation, Rspamd, ClamAV, and AI assistance. The backend currently exposes safe read states and a first set of real operations. Unsupported operations must remain disabled until their server-side implementation, rollback plan, and audit behavior are complete.

## AI provider configuration

The AI Center now supports an offline rule engine plus server-side presets for Gemini, Groq, OpenRouter, Mistral, Cerebras, and custom OpenAI-compatible HTTPS endpoints. API keys are submitted to the authenticated backend and stored in `/etc/mailstack/ai-provider.json` with mode `0600`. The browser receives only `credentialConfigured: true/false`.

Custom API endpoints are restricted to public HTTPS destinations. Loopback, private, link-local, multicast, and reserved addresses are rejected to reduce SSRF risk. Provider free quotas are not guaranteed and can change. The offline rule engine remains available without an external API.

## Administrator account and management endpoint

The Web administrator is independent from Linux root and mailbox users. Installation asks for a username, password, listening address, and port. Passwords are stored as PBKDF2-SHA256 records with a random salt and 310,000 iterations in `/etc/mailstack/admin.json`; plaintext passwords are not retained.

After installation, run `mailstack` on the VPS to open the management menu. Direct subcommands include `mailstack admin`, `mailstack port`, `mailstack status`, and `mailstack logs`.

The default listener is `127.0.0.1:8787`. Choosing `0.0.0.0` requires an explicit warning acknowledgement and still requires HTTPS, firewall restrictions, and preferably an IP allowlist.

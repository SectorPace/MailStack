# Security Policy

## Reporting a Vulnerability

Do **not** report vulnerabilities in public issues. Use GitHub private
vulnerability reporting when enabled, or contact the repository owner
privately. Response-time commitments (triage/fix SLA) and the VEX policy
are defined solely in [`docs/VULNERABILITY_RESPONSE.md`](docs/VULNERABILITY_RESPONSE.md)
— the single authoritative source; no other document restates them.

Never attach SMTP credentials, administrator hashes, DKIM private keys, ACME
DNS credentials, mailbox content, or unredacted production logs to a report.

## Supported Versions

| Version            | Supported          |
| ------------------ | ------------------ |
| 0.5.x (latest RC)  | ✅ security fixes   |
| < 0.5.0            | ❌ upgrade required |

Only the newest release line receives security fixes. `ms upgrade` verifies
the detached ssh-keygen signature on `SHA256SUMS` before executing anything
from a release, so keeping current is itself part of the security model.

## Threat Model

Assets, from most to least sensitive:

1. **Root on the host** — the privileged helper (`mailstack-helper.service`
   and the one-shot sudo wrapper) executes as root. Every RPC it serves is
   drawn from a closed allowlist (`ALLOWED_ACTIONS`), every input that can
   reach a shell or a config file passes an allowlist regex, and the
   service account that talks to it cannot modify its code
   (`/opt/mailstack` is root-owned; sudoers has exactly one rule, no
   argument wildcard).
2. **Mail content** — mailbox Maildirs are owned by their mailbox accounts;
   the admin web process cannot read them; the webmail process reads only
   the logged-in mailbox and authenticates through the Dovecot
   `auth-client` unix socket, so passwords never enter a process argv.
3. **Credentials at rest** — admin PBKDF2 hash and relay passwords
   (`0640 root:mailstack-admin` / `0600`), SASL maps (`0600`), DKIM private
   keys (not group/world readable), backups (`0600`, optional GPG
   encryption), AI provider keys (excluded from backups unless
   `includeSecrets`).
4. **Sessions** — admin and webmail cookies are `HttpOnly; SameSite=Strict`,
   `Secure` under HTTPS modes, with sliding TTL plus a 7-day absolute cap.
   Password changes invalidate all sessions (admin: full clear; webmail:
   per-user epoch bump). TOTP 2FA with one-time recovery codes is available
   for the admin console.

Trust boundaries: the browser (untrusted), the admin Node process
(`mailstack-admin`, unprivileged), the webmail Node process
(`mailstack-webmail`, unprivileged, no sudo), the privileged helper
(root, allowlisted RPC only), and the MTA stack itself (Postfix/Dovecot/
OpenDKIM, distribution-maintained).

Out of scope by design (known non-goals):

- **Compromise of an account that already holds `mailstack-admin`** — that
  account is the control plane; protect it like root. 2FA exists for the
  web login; sudo access to the machine is out of scope entirely.
- **Vulnerabilities inside Postfix/Dovecot/OpenDKIM/Caddy themselves** —
  this project configures them; it cannot vouch for their code. Track
  distribution security updates. The helper only writes configuration
  through allowlisted fields.
- **Denial of service against SMTP/IMAP** — rate limiting covers the admin
  and webmail login/API surfaces; MTA-level flooding is an operational
  concern (fail2ban covers auth brute force only).
- **Physical access and malicious kernel/hypervisor** — no userspace
  installer can defend these.

## Hardening Guarantees (what the installer asserts, not hopes)

- `ps` shows no mailbox or admin password: webmail auth uses the Dovecot
  `auth-client` socket; admin passwords reach the host via stdin/env only.
- Upgrades execute no remote code: only detached-signature-verified release
  archives run (`ssh-keygen -Y verify` against a committed public key).
- Third-party installers (Node.js, Caddy repo key, acme.sh) are pinned by
  SHA256 or GPG fingerprint constants and fail closed on mismatch.
- Restore of a backup cannot write outside an allowlist (no
  `/home/<unmanaged-user>/.ssh`, no symlink/hardlink/device members, SHA256
  metadata check first).
- Fail2ban jails (`postfix-sasl`, `dovecot`) are written by the installer
  and asserted operational by `ms doctor` (ban/unban round-trip on a
  TEST-NET-1 probe).

## Public-Deployment Security Baseline (v0.5.2)

Internet-facing deployments (access mode `caddy`/`direct`, or security
profile `high`) are gated fail-closed on four controls:

- **2FA is mandatory.** Public mode without an enabled TOTP factor serves
  only login + 2FA enrollment endpoints (everything else 403), binds the
  console to `127.0.0.1`, and hard-exits when the enrollment window lapses
  without 2FA being enabled.
- **Backups are encrypted.** `backup.create` without a passphrase is
  refused before the archive is ever written; `ms doctor` flags plaintext
  archives in public mode as FAIL; restores require the passphrase (the
  pre-restore snapshot is encrypted with it).
- **The audit trail is tamper-evident and mirrored.** Every privileged RPC
  appends to a `prev_hash` hash chain with a `.head` anchor (truncation
  detection), mirrored to syslog `AUTHPRIV`; `ms audit-verify` re-checks
  the chain and exits non-zero for monitoring.
- **AI outbound is off by default.** All `ai.*` outbound actions are
  refused in public mode unless explicitly enabled
  (`MAILSTACK_AI_OUTBOUND=1` or `/etc/mailstack/ai.conf`).

A reviewable test record covering these controls — login brute force /
user enumeration / CSRF, helper-socket peer & channel abuse, backup path
traversal & plaintext archives, AI SSRF, upgrade signature / downgrade /
UNSAFE_GIT, and webmail argv / Maildir permissions — is maintained at
[`docs/pentest-2026-09.md`](docs/pentest-2026-09.md).

See `docs/THREAT_MODEL.md` for the STRIDE breakdown and
`docs/DATA_PRIVACY.md` for data-residency rules.

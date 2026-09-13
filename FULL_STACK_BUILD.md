# MailStack full-stack cumulative build

This build replaces all earlier uncommitted patch packages.

## Includes

- Postfix, Dovecot, OpenDKIM, SASL, DNS, TLS and acme.sh from the official repository
- Dovecot 2.3 and 2.4 configuration branches
- Pre-change backups under `/var/backups/mailstack`
- Configuration checks before success is reported
- React/Vite front end and bundled Express production API
- Public Web listener default `0.0.0.0`
- Official `ms` command and `mailstack` compatibility alias
- Real setup APIs, standards-aware DNS records, relay-specific SPF and privacy mode

## Apply to repository

Copy this directory over the repository root, preserving paths, then run:

```bash
git add mailstack.sh index.html src backend deploy FULL_STACK_BUILD.md
git commit -m "Build integrated MailStack mail and Web stack"
git pull --rebase origin main
git push origin main
```

## Fresh VPS install

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
sudo bash ./mailstack.sh install
```

Use a fresh VPS or create a snapshot first. The installer backs up existing mail component configuration, but it intentionally replaces the active Postfix, Dovecot and OpenDKIM configuration baseline.


## ACME certificate lifecycle

The full installer clones the official `acmesh-official/acme.sh` repository, installs the client under `/root/.acme.sh`, enables automatic renewal, and uses `--install-cert` to deploy certificates into `/etc/mailstack/tls/<mail-host>/`. Renewal reloads Postfix and Dovecot through `/usr/local/sbin/mailstack-reload-certificates`.

The setup wizard supports HTTP-01 standalone issuance. Port 80 must be publicly reachable and the mail hostname A/AAAA record must resolve to the VPS. DNS-01 provider automation is intentionally not enabled until provider credentials are entered and stored securely.

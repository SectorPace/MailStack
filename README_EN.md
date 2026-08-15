# MailStack


> **Release status: v0.1-beta1.** This is a public beta. Test it on a fresh VPS before considering any production deployment.

[中文](README.md) | [English](README_EN.md)

MailStack is a multi-domain mail server deployment and administration suite for systemd-based Linux servers. It integrates Postfix, Dovecot, a Liquid Glass Web console, outbound SMTP relay, TLS, DKIM, queue and log administration, security checks, and a configurable AI mail assistant.

> This release is intended for testing and continued development. Production use still requires DNS, PTR, TLS, backup, monitoring, firewall, and security review. MailStack cannot guarantee inbox placement.

## Quick start

```bash
git clone https://github.com/SectorPace/MailStack.git
cd debian-mail-server
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

The installer asks for the Web administrator username, password, management port, and listening address. It listens on `127.0.0.1:8787` by default.

```bash
ssh -L 8787:127.0.0.1:8787 root@SERVER_IP
```

## Non-interactive installation

```bash
printf '%s\n' 'YourStrongPasswordHere' | sudo bash ./mailstack.sh install \
  --admin-user admin \
  --admin-port 8787 \
  --admin-host 127.0.0.1 \
  --admin-password-stdin \
  --non-interactive
```

## VPS commands

```bash
mailstack
mailstack admin
mailstack port
mailstack status
mailstack logs
```

## Update and uninstall

```bash
sudo bash ./mailstack.sh update
sudo bash ./mailstack.sh uninstall
sudo bash ./mailstack.sh uninstall --purge
```

## Security

- The Web administrator is independent from Linux root and mailbox users.
- Passwords are derived with PBKDF2-SHA256 and are not stored as plaintext.
- The API uses an HttpOnly session cookie and CSRF protection.
- AI API keys remain on the server and are never returned to the browser.
- The console listens on loopback by default.

## License

MIT. See [LICENSE](LICENSE).

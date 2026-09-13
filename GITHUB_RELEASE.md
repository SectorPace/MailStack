# GitHub release checklist

Tag: `v0.5.1-beta.1`

Release files:

- `mailstack-v0.5.1 beta1.zip`
- `mailstack-v0.5.1 beta1.tar.gz`
- `SHA256SUMS` (detached checksums)

Install:

```bash
unzip 'mailstack-v0.5.1 beta1.zip'
cd MailStack-v0.5.1-beta.1
sudo bash deploy/install-v05.sh
```

Suggested DNS and reverse proxy mapping:

```text
mail.example.com       -> 127.0.0.1:8787
webmail.example.com    -> 127.0.0.1:18788
```

Both application ports are configurable. Admin and Webmail bind to `127.0.0.1` by default; expose them only through a TLS reverse proxy or an SSH/VPN tunnel. HTTPS modes set secure cookies.

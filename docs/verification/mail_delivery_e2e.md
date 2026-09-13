# MailStack Mail Delivery E2E Verification

The mail-path test must run on a Linux host with Postfix, Dovecot and managed mailbox state configured. A green source build alone does not prove delivery.

## Test matrix

| Scenario | Expected result | Test |
|---|---|---|
| Managed loopback delivery | Message is accepted only for a managed local recipient and appears in that Maildir | `scripts/test_mail_path_e2e.py` |
| External relay rejection | Unmanaged external recipients are rejected by the loopback action | `scripts/test_mail_path_e2e.py` |
| DNS identity | A, MX, SPF, DKIM and DMARC are checked through authoritative DNS queries | `backend/mailstackctl/network.py` and setup API |
| SMTP relay | STARTTLS or implicit TLS is required; credentials are never logged | `tests/security-static.test.mjs` |
| Webmail read/send | Session, CSRF, pagination, read state and message submission work for a managed mailbox | clean-machine browser/API check |

## Commands

```bash
python3 scripts/test_mail_path_e2e.py
npm test
```

Record the host distribution, artifact SHA256, service logs and the exact recipient addresses used. Never use a real external recipient in an automated test unless the operator explicitly opts in.

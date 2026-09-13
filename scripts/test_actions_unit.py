#!/usr/bin/env python3
"""Behavioural unit tests for the privileged helper.

The rest of the suite largely asserts on source text -- "does this symbol
appear", "does this regex get applied". That catches deletions but not logic.
These tests call the real functions against a throwaway /etc and a recorded
subprocess, so they fail when the behaviour changes, not when a file moves.

They exist because of `alias_add`. It called `ADDRESS_RE.fullmatch(src)` and
then asked for `m.group(1)` on a pattern with no capturing group, so every
genuine alias creation raised `IndexError: no such group`. The 45-action
empty-payload probe could not see it: with an empty source `not m`
short-circuits first and raises a clean ValueError. The one input the probe
uses was the one input that happened to work.
"""
import contextlib
import io
import itertools
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

BACKEND = pathlib.Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND))

from mailstackctl import core, mail, dispatcher, security, ai, backup, totp, certs, network, daemon  # noqa: E402
from mailstackctl import telemetry  # noqa: E402  (A5/T-ESC-1 escape-hatch scan)


class FakeShutil:
    """Report every binary as present, so the code under test takes its
    "normal" branch rather than the fallback one."""

    @staticmethod
    def which(name):
        return f"/usr/sbin/{name}"


# One temporary root, reused by every case.
#
# A directory per case looked tidier and made the suite take half a minute for
# about two seconds of real work: `nt.rmdir` costs ~0.4s here, and tearing down
# thirty directories dominated the run. Every case now shares one tree and the
# sandbox clears the files it owns on entry, so cleanup is a handful of unlinks
# in three already-known directories.
_SHARED_TMP = None
LAYOUT = None


def setUpModule():
    global _SHARED_TMP, LAYOUT
    _SHARED_TMP = tempfile.TemporaryDirectory(prefix="mailstack-unit-")
    root = pathlib.Path(_SHARED_TMP.name)
    etc = root / "etc" / "mailstack"
    dom = root / "etc" / "postfix" / "mailstack_domains"
    als = root / "etc" / "postfix" / "mailstack_aliases"
    # The two containers, not the tables inside them: atomic() would create
    # those on demand, but sandbox() has to be able to list the containers.
    etc.mkdir(parents=True, exist_ok=True)
    dom.parent.mkdir(parents=True, exist_ok=True)
    LAYOUT = types.SimpleNamespace(root=root, etc=etc, dom=dom, als=als)


def tearDownModule():
    _SHARED_TMP.cleanup()


@contextlib.contextmanager
def sandbox():
    """Repoint the mail modules at a throwaway /etc and record every command.

    Each module binds its own copy of the path constants at import time
    (`from .core import DOM`), so redirecting core alone would leave the others
    writing to the real /etc/postfix. They all have to be redirected.
    """
    root, etc, dom, als = LAYOUT.root, LAYOUT.etc, LAYOUT.dom, LAYOUT.als
    # Start from an empty tree rather than a new one: atomic() leaves .lock and
    # .tmp sidecars behind, and a stale domain table would make one test see the
    # previous test's domains.
    for path in (etc, dom.parent):
        for leftover in path.iterdir():
            if leftover.is_file():
                leftover.unlink()

    commands = []

    def fake_run(args, input=None, timeout=45, check=True):
        commands.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    def fake_postmap(path):
        commands.append(["postmap", str(path)])

    saved = {
        "ETC": mail.ETC, "DOM": mail.DOM, "ALS": mail.ALS,
        "MANAGED_USERS": mail.MANAGED_USERS,
        "MANAGED_MAILBOXES": mail.MANAGED_MAILBOXES,
        "run": mail.run, "postmap": mail.postmap,
        "pwd": mail.pwd, "grp": mail.grp, "shutil": mail.shutil,
        "core_audit_log": core.AUDIT_LOG,
        "core_admin_config": core.ADMIN_CONFIG,
        "core_install_args_conf": core.INSTALL_ARGS_CONF,
        "core_ai_outbound_conf": core.AI_OUTBOUND_CONF,
        "backup_dir": backup.BACKUP_DIR,
        "totp_admin_config": totp.ADMIN_CONFIG,
        "totp_key_path": totp.TOTP_KEY_PATH,
    }
    mail.ETC = etc
    mail.DOM = dom
    mail.ALS = als
    mail.MANAGED_USERS = etc / "managed-users.json"
    mail.MANAGED_MAILBOXES = etc / "managed-mailboxes.json"
    mail.run = fake_run
    mail.postmap = fake_postmap
    # Skip the passwd/group lookups: they need root and add nothing here.
    mail.pwd = None
    mail.grp = None
    mail.shutil = FakeShutil()
    core.AUDIT_LOG = root / "audit.log"
    # The TOTP module binds ADMIN_CONFIG at import time, just like the mail
    # modules bind DOM/ALS, so it needs its own redirect to the throwaway /etc.
    core.ADMIN_CONFIG = etc / "admin.json"
    # B2/B5: is_public_mode() reads core.INSTALL_ARGS_CONF at call time, so
    # tests can flip the access mode by writing a sandboxed install-args.conf;
    # the backup directory redirect keeps plaintext_backup_scan/doctor off
    # the real /var/backups.
    core.INSTALL_ARGS_CONF = etc / "install-args.conf"
    core.AI_OUTBOUND_CONF = etc / "ai.conf"
    backup.BACKUP_DIR = root / "backups"
    totp.ADMIN_CONFIG = etc / "admin.json"
    # A3: the AES-256-GCM master key must also land in the throwaway /etc, not
    # the real /etc/mailstack/totp.key. Bound at import time like ADMIN_CONFIG.
    totp.TOTP_KEY_PATH = etc / "totp.key"
    try:
        yield types.SimpleNamespace(root=root, dom=dom, als=als, commands=commands)
    finally:
        for key, value in saved.items():
            if key == "core_audit_log":
                core.AUDIT_LOG = value
            elif key == "core_admin_config":
                core.ADMIN_CONFIG = value
            elif key == "core_install_args_conf":
                core.INSTALL_ARGS_CONF = value
            elif key == "core_ai_outbound_conf":
                core.AI_OUTBOUND_CONF = value
            elif key == "backup_dir":
                backup.BACKUP_DIR = value
            elif key == "totp_admin_config":
                totp.ADMIN_CONFIG = value
            elif key == "totp_key_path":
                totp.TOTP_KEY_PATH = value
            else:
                setattr(mail, key, value)


def seed_domains(*names):
    mail.atomic(mail.DOM, "".join(f"{name} OK\n" for name in names))


def seed_admin():
    """Write a minimal already-configured administrator account."""
    core.atomic(core.ADMIN_CONFIG, json.dumps({"username": "admin", "hash": "ab" * 32}) + "\n", 0o640)


def live_totp_code(secret_b32):
    """A genuine current-step TOTP code for *secret_b32*."""
    return totp._hotp(totp._b32decode(secret_b32), int(time.time()) // totp.TOTP_STEP_SECONDS)


def enroll_totp():
    """begin + enable inside an active sandbox; returns the recovery codes."""
    begin = dispatcher.dispatch("admin.totp.begin", {})
    enabled = dispatcher.dispatch("admin.totp.enable", {"code": live_totp_code(begin["secret"])})
    return enabled["recoveryCodes"]


class DomainValidation(unittest.TestCase):
    def test_valid_domain_is_accepted_and_listed(self):
        with sandbox() as box:
            result = mail.domain_add({"name": "Example.COM"})
            self.assertEqual([d["name"] for d in result], ["example.com"])
            self.assertIn("postmap", box.commands[0][0])

    def test_malformed_domains_are_rejected(self):
        for bad in ["", "localhost", "example..com", "-example.com", "example.com.",
                    "exam ple.com", "example.com/x", "a" * 300, "ex!ample.com"]:
            with sandbox():
                with self.assertRaises(ValueError, msg=f"{bad!r} must be rejected"):
                    mail.domain_add({"name": bad})

    def test_newline_in_domain_is_rejected(self):
        # fullmatch anchors the whole string, so a trailing newline cannot smuggle
        # an extra row into the Postfix domain table.
        with sandbox():
            with self.assertRaises(ValueError):
                mail.domain_add({"name": "example.com\nexample.org OK"})

    def test_domain_list_reports_readable_status_text(self):
        with sandbox():
            mail.domain_add({"name": "example.com"})
            listing = mail.domain_list()
            self.assertEqual(listing[0]["statusTextZh"], "等待 DNS 校验")
            for field in ("statusTextZh", "statusTextEn"):
                self.assertNotIn("?", listing[0][field], f"{field} contains a placeholder")


class AliasValidation(unittest.TestCase):
    """Regression cover for the IndexError that broke every alias creation."""

    def test_valid_alias_is_created(self):
        with sandbox():
            result = mail.alias_add(
                {"source": "Postmaster@Example.com", "destinations": ["alice", "bob@example.com"]}
            )
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["source"], "postmaster@example.com")
            self.assertEqual(result[0]["destinations"], ["alice", "bob@example.com"])

    def test_alias_creation_does_not_raise_indexerror(self):
        # The exact call that used to crash: a well-formed address, so `not m`
        # does not short-circuit and the missing capture group was reached.
        with sandbox():
            try:
                mail.alias_add({"source": "postmaster@example.com", "destinations": ["alice"]})
            except IndexError as exc:  # pragma: no cover
                self.fail(f"alias_add raised IndexError: {exc}")

    def test_destinations_must_be_a_list(self):
        # A bare string used to iterate character by character, and single
        # letters satisfy USER_RE, so "ab" became two destinations.
        with sandbox():
            with self.assertRaises(ValueError):
                mail.alias_add({"source": "postmaster@example.com", "destinations": "alice"})

    def test_destination_is_required(self):
        with sandbox():
            with self.assertRaises(ValueError):
                mail.alias_add({"source": "postmaster@example.com", "destinations": []})
            with self.assertRaises(ValueError):
                mail.alias_add({"source": "postmaster@example.com"})

    def test_newline_in_source_cannot_inject_an_alias_row(self):
        with sandbox():
            with self.assertRaises(ValueError):
                mail.alias_add(
                    {"source": "a@example.com\nattacker@evil.com root", "destinations": ["alice"]}
                )
            self.assertEqual(mail.aliases(), [])

    def test_invalid_destination_is_rejected(self):
        with sandbox():
            for bad in ["not an address", "a b", "x" * 300, "../etc/passwd"]:
                with self.assertRaises(ValueError, msg=f"{bad!r} must be rejected"):
                    mail.alias_add(
                        {"source": "postmaster@example.com", "destinations": ["alice", bad]}
                    )

    def test_alias_delete_validates_its_input(self):
        with sandbox():
            mail.alias_add({"source": "postmaster@example.com", "destinations": ["alice"]})
            with self.assertRaises(ValueError):
                mail.alias_del({"id": "postmaster@example.com\nattacker@evil.com root"})
            # The legitimate entry survived the rejected delete.
            self.assertEqual(len(mail.aliases()), 1)
            mail.alias_del({"id": "postmaster@example.com"})
            self.assertEqual(mail.aliases(), [])


class MailboxValidation(unittest.TestCase):
    def test_mailbox_needs_a_managed_domain(self):
        with sandbox():
            seed_domains("example.com")
            with self.assertRaises(ValueError):
                mail.user_add({"email": "alice@elsewhere.com", "password": "correct-horse"})

    def test_mailbox_password_policy_is_enforced(self):
        with sandbox():
            seed_domains("example.com")
            for bad in ["", "short", "x" * 257, None, 12345]:
                with self.assertRaises(ValueError, msg=f"{bad!r} must be rejected"):
                    mail.user_add({"email": "alice@example.com", "password": bad})

    def test_mailbox_password_rejects_control_characters(self):
        with sandbox():
            seed_domains("example.com")
            for bad in ["abcdefg\rhij", "abcdefg\nhij", "abcdefg\x00hij"]:
                with self.assertRaises(ValueError, msg=f"{bad!r} must be rejected"):
                    mail.user_add({"email": "alice@example.com", "password": bad})

    def test_protected_accounts_cannot_have_their_password_reset(self):
        with sandbox():
            for user in ("root", "postfix", "mailstack-admin"):
                with self.assertRaises(ValueError, msg=f"{user} must be protected"):
                    mail.user_password({"id": user, "password": "correct-horse"})

    def test_unmanaged_user_cannot_be_deleted(self):
        with sandbox():
            with self.assertRaises(ValueError):
                mail.user_del({"id": "somebody", "confirm": True})


class LoopbackRelay(unittest.TestCase):
    """The loopback test must not become an open relay.

    The guard used to be `if managed and ...`, so on a fresh install -- before
    any mailbox existed -- the anti-relay check was skipped entirely and this
    action would deliver to any address on the internet.
    """

    def test_external_recipient_is_rejected(self):
        with sandbox():
            seed_domains("example.com")
            with self.assertRaises(ValueError):
                mail.mail_test_loopback({"recipient": "attacker@external-unmanaged-domain.com"})

    def test_fresh_install_with_no_domains_rejects_outbound(self):
        # The regression itself: no mailboxes, no domains, and the old guard
        # let everything through.
        with sandbox():
            with self.assertRaises(ValueError):
                mail.mail_test_loopback({"recipient": "attacker@external-unmanaged-domain.com"})

    def test_recipient_on_a_managed_domain_is_allowed(self):
        with sandbox():
            seed_domains("example.com")
            result = mail.mail_test_loopback({"recipient": "alice@example.com"})
            self.assertTrue(result["success"])
            self.assertTrue(result["recipient"].endswith("@example.com"))

    def test_invalid_address_is_rejected_before_anything_is_sent(self):
        with sandbox() as box:
            seed_domains("example.com")
            with self.assertRaises(ValueError):
                mail.mail_test_loopback({"recipient": "invalid@@example.com"})
            self.assertEqual(box.commands, [], "nothing must be submitted to sendmail")


class QueueValidation(unittest.TestCase):
    def test_invalid_queue_id_is_rejected(self):
        with sandbox():
            for bad in ["not-a-qid", "abc", "LOWERCASE1", "A1B2C3; rm -rf /"]:
                with self.assertRaises(ValueError, msg=f"{bad!r} must be rejected"):
                    mail.queue_action({"id": bad, "verb": "retry"})

    def test_unknown_queue_verb_is_rejected(self):
        with sandbox():
            with self.assertRaises(ValueError):
                mail.queue_action({"id": "A1B2C3D4E5", "verb": "destroy"})

    def test_empty_queue_id_cannot_delete_anything(self):
        # The whole-queue footgun: an empty id used to reach `postsuper -d ''`.
        with sandbox() as box:
            for verb in ("delete", "retry"):
                with self.assertRaises(ValueError, msg=f"empty id + {verb} must be rejected"):
                    mail.queue_action({"id": "", "verb": verb})
            self.assertFalse(
                any("postsuper" in str(cmd) for cmd in box.commands),
                "postsuper must never run without a validated queue id",
            )

    def test_flush_is_a_separate_verb_and_needs_no_id(self):
        with sandbox() as box:
            mail.queue_action({"id": "", "verb": "flush"})
            self.assertIn(["postqueue", "-f"], box.commands)


class AtomicWrites(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not honoured by os.chmod on Windows")
    def test_atomic_applies_the_requested_mode(self):
        with sandbox():
            target = LAYOUT.etc / "mode-probe.json"
            mail.atomic(target, "{}\n", 0o640)
            mode = target.stat().st_mode & 0o777
            self.assertEqual(
                mode, 0o640,
                f"atomic() accepted a mode and must apply it, got {oct(mode)}",
            )


class Fail2banJailAllowlist(unittest.TestCase):
    def test_jail_names_with_metacharacters_are_rejected(self):
        for bad in ["postfix-sasl; id", "postfix-sasl;id", "dovecot$(id)", "x`id`",
                    "postfix-sasl\nsshd", "not-a-jail", "POSTFIX-SASL", "../jail"]:
            with self.assertRaises(ValueError, msg=f"{bad!r} must be rejected"):
                security._valid_jail(bad)

    def test_only_the_installer_jails_are_allowed(self):
        # Without a reachable fail2ban the static installer list is the
        # fallback ground truth.
        for good in ["postfix-sasl", "dovecot", "sshd"]:
            self.assertEqual(security._valid_jail(good), good)

    def test_runtime_jail_list_overrides_the_static_allowlist(self):
        # When the local fail2ban can be asked, its active jail list decides:
        # custom jails like recidive become manageable (rc.4 behaviour) while
        # fabricated names are still rejected -- server-side verification.
        status_output = (
            "Status\n"
            "|- Number of jail:\t3\n"
            "`- Jail list:\tpostfix-sasl, dovecot, recidive\n"
        )

        def fake_run(args, input=None, timeout=45, check=True):
            return subprocess.CompletedProcess(args, 0, stdout=status_output, stderr="")

        saved = {
            "run": security.run,
            "shutil": security.shutil,
            "is_service_active": security.is_service_active,
        }
        try:
            security.run = fake_run
            security.shutil = FakeShutil()
            security.is_service_active = lambda unit: True
            self.assertEqual(security._valid_jail("recidive"), "recidive")
            self.assertEqual(security._valid_jail("postfix-sasl"), "postfix-sasl")
            # sshd is on the static list but not active on this host: the
            # runtime list wins.
            with self.assertRaises(ValueError):
                security._valid_jail("sshd")
            with self.assertRaises(ValueError):
                security._valid_jail("not-a-jail")
        finally:
            security.run = saved["run"]
            security.shutil = saved["shutil"]
            security.is_service_active = saved["is_service_active"]


class SsrfScreening(unittest.TestCase):
    def test_cgnat_range_is_restricted(self):
        # 100.64.0.0/10 is NOT covered by ipaddress.is_private.
        for addr in ["100.64.0.1", "100.127.255.254"]:
            self.assertTrue(ai.is_ip_restricted(addr), f"{addr} (CGNAT) must be restricted")

    def test_ipv4_mapped_forms_are_unwrapped_before_screening(self):
        # ::ffff:100.64.0.1 reports is_private=False -- without unwrapping it
        # sails straight past every v4 rule into internal CGNAT services.
        for addr in ["::ffff:100.64.0.1", "::ffff:7f00:1", "::ffff:192.168.1.1",
                     "::ffff:a9fe:1", "::ffff:0.0.0.0"]:
            self.assertTrue(ai.is_ip_restricted(addr), f"{addr} must be restricted")

    def test_all_restricted_ipv4_classes(self):
        for addr in ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1",
                     "169.254.169.254", "0.0.0.0", "224.0.0.1", "::1", "fe80::1"]:
            self.assertTrue(ai.is_ip_restricted(addr), f"{addr} must be restricted")

    def test_public_addresses_are_not_restricted(self):
        for addr in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]:
            self.assertFalse(ai.is_ip_restricted(addr), f"{addr} is public and must pass")


class BackupNaming(unittest.TestCase):
    def test_rollback_snapshot_name_matches_the_restore_allowlist(self):
        # `ms rollback` globs mailstack-backup-*-pre-restore.tar.gz and hands the
        # basename to backup_restore, which fullmatches BACKUP_FILENAME_RE.
        import datetime as _dt
        name = f"mailstack-backup-{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}-pre-restore.tar.gz"
        self.assertIsNotNone(
            backup.BACKUP_FILENAME_RE.fullmatch(name),
            "rollback snapshot naming must satisfy BACKUP_FILENAME_RE or rollback can never work",
        )

    def test_resolve_archive_rejects_foreign_names_before_touching_the_disk(self):
        for bad in ["../../etc/cron.d/x.tar.gz", "/etc/passwd",
                    "mailstack-backup-20240101-010101.tar.gz.evil",
                    "..\\..\\windows\\system32", "random-file.tar.gz"]:
            with self.assertRaises(ValueError, msg=f"{bad!r} must be rejected"):
                backup._resolve_archive(bad)


class DispatchGate(unittest.TestCase):
    def test_unknown_action_is_rejected(self):
        with sandbox():
            with self.assertRaises(ValueError):
                dispatcher.dispatch("domains.nuke", {})

    def test_data_must_be_an_object(self):
        with sandbox():
            for bad in ["string", 42, ["a"]]:
                with self.assertRaises(ValueError, msg=f"{bad!r} must be rejected"):
                    dispatcher.dispatch("domains.list", bad)

    def test_destructive_actions_require_explicit_confirmation(self):
        with sandbox():
            for action in sorted(core.DESTRUCTIVE_ACTIONS):
                with self.assertRaises(ValueError, msg=f"{action} must require confirmation"):
                    dispatcher.dispatch(action, {})
                # Anything other than the boolean True is a refusal -- a truthy
                # string from a query parameter must not count as consent.
                for not_consent in ["true", 1, "yes", {"confirm": True}]:
                    with self.assertRaises(ValueError, msg=f"{action} accepted {not_consent!r}"):
                        dispatcher.dispatch(action, {"confirm": not_consent})

    def test_every_allowed_action_is_reachable(self):
        # Guards against an action being advertised in ALLOWED_ACTIONS but
        # falling through the if-chain in dispatch() to the end.
        missing = []
        source = pathlib.Path(dispatcher.__file__).read_text(encoding="utf-8")
        for action in sorted(core.ALLOWED_ACTIONS):
            if f"'{action}'" not in source:
                missing.append(action)
        self.assertEqual(missing, [], f"dispatch() never handles: {missing}")


class TotpActions(unittest.TestCase):
    """The four admin.totp.* actions: whitelisting, dispatch and 2FA policy."""

    NEW_ACTIONS = (
        "admin.totp.begin",
        "admin.totp.enable",
        "admin.totp.disable",
        "admin.totp.consume_recovery",
    )

    def test_new_actions_are_whitelisted_but_not_destructive(self):
        for action in self.NEW_ACTIONS:
            self.assertIn(action, core.ALLOWED_ACTIONS, f"{action} missing from ALLOWED_ACTIONS")
            self.assertNotIn(action, core.DESTRUCTIVE_ACTIONS,
                             f"{action} must not be treated as destructive")

    def test_unregistered_totp_action_is_rejected(self):
        with sandbox():
            seed_admin()
            with self.assertRaises(ValueError):
                dispatcher.dispatch("admin.totp.destroy", {})

    def test_begin_returns_a_fresh_unenabled_enrollment(self):
        with sandbox():
            seed_admin()
            result = dispatcher.dispatch("admin.totp.begin", {})
            self.assertFalse(result["enabled"])
            self.assertTrue(result["secret"])
            self.assertIn("otpauth://totp/MailStack:admin", result["uri"])
            public = dispatcher.dispatch("admin.get", {})
            self.assertFalse(public["twoFactorEnabled"])

    def test_begin_requires_a_configured_administrator(self):
        with sandbox():
            # No admin.json seeded: enrollment must not create state out of thin air.
            with self.assertRaises(ValueError):
                dispatcher.dispatch("admin.totp.begin", {})

    def test_enable_requires_a_valid_live_code(self):
        with sandbox():
            seed_admin()
            dispatcher.dispatch("admin.totp.begin", {})
            for bad in ["000000", "", "abcdef", "12345678"]:
                with self.assertRaises(ValueError, msg=f"code {bad!r} must be rejected"):
                    dispatcher.dispatch("admin.totp.enable", {"code": bad})

    def test_enable_without_a_pending_enrollment_is_rejected(self):
        with sandbox():
            seed_admin()
            with self.assertRaises(ValueError):
                dispatcher.dispatch("admin.totp.enable", {"code": "123456"})

    def test_enable_with_a_live_code_returns_recovery_codes_and_public_state(self):
        with sandbox():
            seed_admin()
            begin = dispatcher.dispatch("admin.totp.begin", {})
            enabled = dispatcher.dispatch(
                "admin.totp.enable", {"code": live_totp_code(begin["secret"])}
            )
            self.assertTrue(enabled["enabled"])
            self.assertEqual(len(enabled["recoveryCodes"]), totp.RECOVERY_CODE_COUNT)
            public = dispatcher.dispatch("admin.get", {})
            self.assertTrue(public["twoFactorEnabled"])
            self.assertEqual(public["recoveryCodesRemaining"], totp.RECOVERY_CODE_COUNT)
            # The secret must never leak through the public admin surface.
            self.assertNotIn("secret", json.dumps(public))
            self.assertNotIn(begin["secret"], json.dumps(public))

    def test_recovery_code_is_single_use(self):
        with sandbox():
            seed_admin()
            codes = enroll_totp()
            first = dispatcher.dispatch("admin.totp.consume_recovery", {"code": codes[0]})
            self.assertTrue(first["consumed"])
            self.assertEqual(first["remaining"], totp.RECOVERY_CODE_COUNT - 1)
            # The same code a second time is now unknown.
            with self.assertRaises(ValueError):
                dispatcher.dispatch("admin.totp.consume_recovery", {"code": codes[0]})
            self.assertEqual(
                dispatcher.dispatch("admin.get", {})["recoveryCodesRemaining"],
                totp.RECOVERY_CODE_COUNT - 1,
            )

    def test_consume_recovery_requires_enabled_2fa(self):
        with sandbox():
            seed_admin()
            with self.assertRaises(ValueError):
                dispatcher.dispatch("admin.totp.consume_recovery", {"code": "deadbeef-cafe0123"})

    def test_disable_requires_a_valid_credential(self):
        with sandbox():
            seed_admin()
            enroll_totp()
            for bad in ["", "nope", "123456", "already-spent"]:
                with self.assertRaises(ValueError, msg=f"disable accepted {bad!r}"):
                    dispatcher.dispatch("admin.totp.disable", {"code": bad})
            self.assertTrue(dispatcher.dispatch("admin.get", {})["twoFactorEnabled"])

    def test_disable_with_a_recovery_code_consumes_it_and_clears_state(self):
        with sandbox():
            seed_admin()
            codes = enroll_totp()
            result = dispatcher.dispatch("admin.totp.disable", {"code": codes[0]})
            self.assertFalse(result["enabled"])
            public = dispatcher.dispatch("admin.get", {})
            self.assertFalse(public["twoFactorEnabled"])
            self.assertEqual(public["recoveryCodesRemaining"], 0)

    def test_concurrent_recovery_consumption_succeeds_exactly_once(self):
        # The double-spend regression: two requests racing on the same recovery
        # code must not both succeed. The fix wraps the whole load-modify-save
        # in one locked() section; without it each thread writes back a file
        # where the code hash still exists.
        with sandbox():
            seed_admin()
            codes = enroll_totp()
            code = codes[0]
            results = []
            barrier = threading.Barrier(2)

            def attempt():
                barrier.wait()
                try:
                    dispatcher.dispatch("admin.totp.consume_recovery", {"code": code})
                    results.append("consumed")
                except ValueError:
                    results.append("rejected")

            threads = [threading.Thread(target=attempt) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(30)
            self.assertEqual(results.count("consumed"), 1,
                             f"double-spend detected: {results}")
            cfg = json.loads(core.ADMIN_CONFIG.read_text(encoding="utf-8"))
            self.assertEqual(len(cfg["totp"]["recovery"]), totp.RECOVERY_CODE_COUNT - 1)


class TotpEnvelope(unittest.TestCase):
    """A3/T-TOTP-1 + T-TOTP-2: the TOTP secret is stored as an AES-256-GCM
    envelope in admin.json (never plaintext), verification happens inside the
    helper via admin.totp.verify, and the master key file is 0600 root:root.

    Skipped when python3-cryptography is unavailable: begin/enable/verify are
    fail-closed by design (no self-made encryption), so there is nothing to
    exercise without the crypto backend.
    """

    @unittest.skipIf(totp.AESGCM is None, "python3-cryptography is not installed")
    def test_begin_stores_envelope_and_no_plaintext_secret(self):
        with sandbox():
            seed_admin()
            dispatcher.dispatch("admin.totp.begin", {})
            text = core.ADMIN_CONFIG.read_text(encoding="utf-8")
            self.assertNotIn('"secret":', text,
                             "admin.json must not carry a plaintext TOTP secret")
            cfg = json.loads(text)
            totp_cfg = cfg["totp"]
            for field in ("enc", "nonce", "tag"):
                self.assertIn(field, totp_cfg, f"envelope is missing {field!r}")
            self.assertFalse(totp_cfg["enabled"])

    @unittest.skipIf(totp.AESGCM is None, "python3-cryptography is not installed")
    def test_verify_accepts_live_code_and_rejects_wrong_code(self):
        with sandbox():
            seed_admin()
            begin = dispatcher.dispatch("admin.totp.begin", {})
            dispatcher.dispatch("admin.totp.enable", {"code": live_totp_code(begin["secret"])})
            good = dispatcher.dispatch("admin.totp.verify", {"code": live_totp_code(begin["secret"])})
            self.assertIs(good["ok"], True)
            # A deterministic wrong code: bump the live code by one step value.
            live = live_totp_code(begin["secret"])
            wrong = str((int(live) + 1) % 1000000).zfill(6)
            bad = dispatcher.dispatch("admin.totp.verify", {"code": wrong})
            self.assertIs(bad["ok"], False)

    @unittest.skipIf(totp.AESGCM is None, "python3-cryptography is not installed")
    def test_verify_never_returns_the_secret(self):
        with sandbox():
            seed_admin()
            begin = dispatcher.dispatch("admin.totp.begin", {})
            dispatcher.dispatch("admin.totp.enable", {"code": live_totp_code(begin["secret"])})
            result = dispatcher.dispatch("admin.totp.verify", {"code": live_totp_code(begin["secret"])})
            self.assertEqual(set(result.keys()), {"ok"})
            self.assertNotIn(begin["secret"], json.dumps(result))

    @unittest.skipIf(totp.AESGCM is None, "python3-cryptography is not installed")
    def test_legacy_plaintext_secret_is_resealed_on_verify(self):
        # Migration: an admin.json written by a pre-A3 build still holds the
        # plaintext secret. The first verify must atomically re-seal it so the
        # on-disk file no longer leaks the secret, without breaking the login.
        with sandbox():
            secret = totp._b32encode(os.urandom(20))
            core.atomic(core.ADMIN_CONFIG, json.dumps({
                "username": "admin", "hash": "ab" * 32,
                "totp": {"secret": secret, "enabled": True, "recovery": []},
            }) + "\n", 0o640)
            good = dispatcher.dispatch("admin.totp.verify", {"code": live_totp_code(secret)})
            self.assertIs(good["ok"], True)
            text = core.ADMIN_CONFIG.read_text(encoding="utf-8")
            self.assertNotIn('"secret":', text)
            self.assertIn('"enc":', text)

    @unittest.skipIf(totp.AESGCM is None, "python3-cryptography is not installed")
    @unittest.skipUnless(hasattr(os, "geteuid"), "POSIX file permissions only (Windows chmod is not reflected in st_mode)")
    def test_master_key_file_is_0600_and_root_owned(self):
        # T-TOTP-2 (stat half): the master key must be 0600; when the suite runs
        # as root (WSL) it must also be owned by root:root so the web service
        # account mailstack-admin cannot read it (`sudo -u mailstack-admin cat`
        # returns EACCES on the live host).
        with sandbox():
            seed_admin()
            dispatcher.dispatch("admin.totp.begin", {})
            key_path = totp.TOTP_KEY_PATH
            self.assertTrue(key_path.exists(), "totp.key was not generated")
            st = key_path.stat()
            self.assertEqual(st.st_mode & 0o777, 0o600)
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                self.assertEqual(st.st_uid, 0)
                self.assertEqual(st.st_gid, 0)


class PeerCred(unittest.TestCase):
    """A2/T-PEER-1: the helper socket rejects peers whose uid is neither root
    nor the mailstack-admin service account, and records a peer_denied audit.

    SO_PEERCRED is Linux-only; on development hosts without it the gate is
    skipped by design, so the behaviour tests are skipped there too.
    """

    class _FakePeerSocket:
        """Minimal stand-in for an accepted unix-socket connection."""

        def __init__(self, uid, pid=4321, gid=0):
            self._uid = uid
            self._pid = pid
            self._gid = gid

        def getsockopt(self, level, optname, buflen):
            return struct.pack("3i", self._pid, self._uid, self._gid)

        def settimeout(self, timeout):
            pass

        def recv(self, count):
            return b""  # empty -> _recvn returns None -> clean early return

        def sendall(self, data):
            pass

    def _serve_with_uid(self, uid):
        """Run _Handler._serve against a fake peer; return captured audit calls."""
        captured = []
        real_audit = daemon.audit
        real_pwd = daemon.pwd
        daemon.audit = lambda action, ok, *a, **k: captured.append((action, ok))
        # Deterministic whitelist: with pwd unavailable the only allowed uid is 0.
        daemon.pwd = None
        try:
            handler = object.__new__(daemon._Handler)
            handler.request = self._FakePeerSocket(uid)
            handler.server = types.SimpleNamespace()
            handler.client_address = ("test",)
            handler._serve()
        finally:
            daemon.audit = real_audit
            daemon.pwd = real_pwd
        return captured

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED is Linux-only")
    def test_foreign_uid_is_denied_and_audited(self):
        captured = self._serve_with_uid(424242)
        self.assertIn(("peer_denied", False), captured,
                      "a non-whitelisted uid must be denied and audited")

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED is Linux-only")
    def test_root_uid_passes_the_gate(self):
        captured = self._serve_with_uid(0)
        self.assertNotIn("peer_denied", [action for action, _ in captured],
                         "uid 0 (root) must not be denied")


class DualSocket(unittest.TestCase):
    """B1/T-SOCK-1 + T-SOCK-2: the helper daemon binds a read-only surface
    (helper-ro.sock, 0660 root:mailstack-admin) and a root-only change surface
    (helper.sock, 0600 root:root); the channel -- not the peer uid -- decides
    the action subset.

    T-SOCK-1 is covered in halves: the filesystem half (server_bind chmod/chown
    wiring -- 0600 root:root means connect(2) itself fails with EACCES for the
    admin service account) plus the peercred half (the admin uid is not on the
    rw whitelist and is refused when it does get a connection). T-SOCK-2 is the
    ro_channel_violation refusal. The static grep half of both gates lives in
    tests/security-static.test.mjs (B1/T-SOCK).
    """

    class _FakePeerSocket:
        """Stand-in for an accepted connection carrying a canned request."""

        def __init__(self, uid, pid=4321, gid=0, payload=b""):
            self._uid = uid
            self._pid = pid
            self._gid = gid
            self._payload = payload
            self.sent = b""

        def getsockopt(self, level, optname, buflen):
            return struct.pack("3i", self._pid, self._uid, self._gid)

        def settimeout(self, timeout):
            pass

        def recv(self, count):
            data, self._payload = self._payload[:count], self._payload[count:]
            return data

        def sendall(self, data):
            self.sent += data

    @staticmethod
    def _request(action):
        payload = json.dumps({"action": action, "data": {}}).encode("utf-8")
        return struct.pack(">I", len(payload)) + payload

    def _serve(self, channel, allowed_actions, uid=0, action="domains.add",
               keep_pwd=False):
        """Run _Handler._serve on a fake `channel` server; return (audit, reply)."""
        captured = []
        real_audit = daemon.audit
        real_pwd = daemon.pwd
        daemon.audit = lambda act, ok, *a, **k: captured.append((act, ok))
        if not keep_pwd:
            # Deterministic whitelist: with pwd unavailable the only allowed
            # uid is 0 on both channels.
            daemon.pwd = None
        try:
            handler = object.__new__(daemon._Handler)
            handler.request = self._FakePeerSocket(uid, payload=self._request(action))
            handler.server = types.SimpleNamespace(
                channel=channel, allowed_actions=allowed_actions,
                semaphore=threading.Semaphore(1))
            handler.client_address = ("test",)
            handler._serve()
        finally:
            daemon.audit = real_audit
            daemon.pwd = real_pwd
        return captured, handler.request.sent

    # ---- channel bookkeeping (runs everywhere, incl. Windows dev hosts) ----

    def test_ro_and_rw_partition_the_allowlist(self):
        self.assertTrue(core.ALLOWED_ACTIONS_RO)
        self.assertTrue(core.ALLOWED_ACTIONS_RW)
        self.assertEqual(core.ALLOWED_ACTIONS_RO & core.ALLOWED_ACTIONS_RW, set(),
                         "an action may live on only one channel")
        self.assertEqual(core.ALLOWED_ACTIONS_RO | core.ALLOWED_ACTIONS_RW,
                         core.ALLOWED_ACTIONS,
                         "the union must equal the legacy allowlist exactly")

    def test_channel_membership_examples(self):
        # Pin the classification of representative actions: mutating ones on
        # the change surface, read-only ones on the read-only surface.
        for action in ("domains.add", "domains.delete", "users.password",
                       "backup.restore", "settings.set", "admin.totp.verify",
                       "services.action", "security.ban"):
            self.assertIn(action, core.ALLOWED_ACTIONS_RW)
            self.assertNotIn(action, core.ALLOWED_ACTIONS_RO)
        for action in ("snapshot", "system.doctor", "setup.status", "logs.list",
                       "metrics.realtime", "domains.list", "certs.list",
                       "settings.get", "security.scan", "backup.list",
                       "admin.get", "ai.config.get", "ai.models.list",
                       "network.check_port"):
            self.assertIn(action, core.ALLOWED_ACTIONS_RO)
            self.assertNotIn(action, core.ALLOWED_ACTIONS_RW)

    def test_rw_channel_peer_whitelist_is_root_only(self):
        # T-SOCK-1 (uid half): the change surface accepts uid==0 only -- even
        # the mailstack-admin service account is not on the rw whitelist.
        self.assertEqual(daemon._allowed_uids("rw"), {0})

    def test_ro_channel_peer_whitelist_includes_admin(self):
        # The read-only surface additionally accepts the mailstack-admin
        # service account; that is the whole point of the ro socket.
        uids = daemon._allowed_uids("ro")
        self.assertIn(0, uids)
        if daemon.pwd is not None:
            try:
                admin_uid = daemon.pwd.getpwnam("mailstack-admin").pw_uid
            except KeyError:
                pass  # account absent on this dev host; production always has it
            else:
                self.assertIn(admin_uid, uids)

    # ---- behaviour (Linux hosts only) ----

    @unittest.skipIf(daemon._Server is None, "unix stream server is Linux-only")
    def test_server_bind_applies_channel_permissions(self):
        # T-SOCK-1 (filesystem half): server_bind must chmod/chown the socket
        # node per channel -- rw: 0600 root:root, so connect(2) fails with
        # EACCES for the admin service account; ro: 0660 root:mailstack-admin,
        # so the admin group reaches the read-only surface.
        import socketserver
        calls = []
        real_bind = socketserver.UnixStreamServer.server_bind
        real_chmod, real_chown = os.chmod, os.chown
        real_grp = daemon.grp
        socketserver.UnixStreamServer.server_bind = lambda self: None
        os.chmod = lambda path, mode: calls.append(("chmod", str(path), mode))
        os.chown = lambda path, uid, gid: calls.append(("chown", str(path), uid, gid))
        daemon.grp = types.SimpleNamespace(
            getgrnam=lambda name: types.SimpleNamespace(gr_gid=4321))
        try:
            for channel, mode, group in (("rw", 0o600, None),
                                         ("ro", 0o660, "mailstack-admin")):
                server = object.__new__(daemon._Server)
                server.channel = channel
                server._socket_path = f"/run/mailstack/probe-{channel}.sock"
                server._mode = mode
                server._group = group
                server.server_bind()
        finally:
            socketserver.UnixStreamServer.server_bind = real_bind
            os.chmod = real_chmod
            os.chown = real_chown
            daemon.grp = real_grp
        self.assertEqual(
            [c for c in calls if "probe-rw" in c[1]],
            [("chmod", "/run/mailstack/probe-rw.sock", 0o600),
             ("chown", "/run/mailstack/probe-rw.sock", 0, 0)],
            "the rw socket must end up 0600 root:root")
        self.assertEqual(
            [c for c in calls if "probe-ro" in c[1]],
            [("chmod", "/run/mailstack/probe-ro.sock", 0o660),
             ("chown", "/run/mailstack/probe-ro.sock", 0, 4321)],
            "the ro socket must end up 0660 root:mailstack-admin")

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED is Linux-only")
    def test_t_sock_1_admin_uid_is_denied_on_the_rw_channel(self):
        # T-SOCK-1 (peercred half): the service account talks to the change
        # surface without sudo -> peer_denied, no reply.
        captured, sent = self._serve("rw", core.ALLOWED_ACTIONS, uid=1234,
                                     action="domains.add")
        self.assertIn(("peer_denied", False), captured,
                      "a non-root uid on the rw socket must be denied and audited")
        self.assertEqual(sent, b"", "a denied peer must not receive a reply")

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED is Linux-only")
    def test_t_sock_2_ro_channel_refuses_mutating_action(self):
        # T-SOCK-2: domains.add on the read-only surface is refused and audited
        # as ro_channel_violation -- the channel, not the uid, decides. Even
        # root is refused here (uid=0 passes the peer gate first).
        captured, sent = self._serve("ro", core.ALLOWED_ACTIONS_RO, uid=0,
                                     action="domains.add")
        self.assertIn(("ro_channel_violation", False), captured,
                      "a mutating action on the ro socket must be audited as ro_channel_violation")
        self.assertNotIn(("domains.add", True), captured,
                         "the mutating action must NOT reach dispatch")
        self.assertTrue(sent, "the daemon must answer the violating request")
        reply = json.loads(sent[4:].decode("utf-8"))
        self.assertFalse(reply.get("ok"), "the ro channel must refuse the mutating action")

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED is Linux-only")
    def test_ro_channel_serves_read_only_actions(self):
        # Sanity: a read-only action passes the channel gate and reaches
        # dispatch, audited under its own name -- never as a channel violation.
        seen = []
        real_dispatch = daemon.dispatch
        daemon.dispatch = lambda action, data: (seen.append(action), {})[1]
        try:
            captured, _ = self._serve("ro", core.ALLOWED_ACTIONS_RO, uid=0,
                                      action="snapshot")
        finally:
            daemon.dispatch = real_dispatch
        self.assertEqual(seen, ["snapshot"])
        self.assertIn(("snapshot", True), captured)
        self.assertNotIn("ro_channel_violation", [a for a, _ in captured])

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED is Linux-only")
    def test_admin_uid_passes_the_ro_peer_gate(self):
        # The ro surface admits the mailstack-admin service account (that is
        # how Node reaches it); combined with test_t_sock_1 the same uid is
        # refused on rw and served on ro.
        if daemon.pwd is None:
            self.skipTest("pwd module unavailable")
        try:
            admin_uid = daemon.pwd.getpwnam("mailstack-admin").pw_uid
        except KeyError:
            self.skipTest("mailstack-admin account absent on this host")
        seen = []
        real_dispatch = daemon.dispatch
        daemon.dispatch = lambda action, data: (seen.append(action), {})[1]
        try:
            captured, _ = self._serve("ro", core.ALLOWED_ACTIONS_RO, uid=admin_uid,
                                      action="snapshot", keep_pwd=True)
        finally:
            daemon.dispatch = real_dispatch
        self.assertEqual(seen, ["snapshot"],
                         "the admin uid must be served on the ro channel")
        self.assertNotIn("peer_denied", [a for a, _ in captured])


class DkimKeyPermissions(unittest.TestCase):
    """DKIM private keys must end up root:opendkim 0640 on every write path."""

    def test_helper_applies_0640_and_root_opendkim(self):
        with sandbox():
            key = LAYOUT.etc / "dkim-perm-probe.private"
            key.write_text("PRIVATE KEY MATERIAL", encoding="utf-8")
            chowns = []

            class FakeGrp:
                @staticmethod
                def getgrnam(name):
                    assert name == "opendkim", f"unexpected group lookup: {name}"
                    return types.SimpleNamespace(gr_gid=4321)

            saved_grp = core.grp
            saved_chown = getattr(os, "chown", None)
            core.grp = FakeGrp
            os.chown = lambda path, uid, gid: chowns.append((pathlib.Path(path), uid, gid))
            try:
                core.set_dkim_key_permissions(key)
            finally:
                core.grp = saved_grp
                if saved_chown is None:
                    del os.chown
                else:
                    os.chown = saved_chown
            self.assertEqual(chowns, [(key, 0, 4321)], "chown target must be root:opendkim")
            if os.name != "nt":
                mode = key.stat().st_mode & 0o777
                self.assertEqual(mode, 0o640, f"key mode must be 0640, got {oct(mode)}")

    def test_helper_survives_a_missing_opendkim_group(self):
        with sandbox():
            key = LAYOUT.etc / "dkim-perm-probe2.private"
            key.write_text("PRIVATE KEY MATERIAL", encoding="utf-8")

            class MissingGrp:
                @staticmethod
                def getgrnam(name):
                    raise KeyError(name)

            saved_grp = core.grp
            core.grp = MissingGrp
            try:
                # Dev-host degradation: no crash, the chmod still happened.
                core.set_dkim_key_permissions(key)
            finally:
                core.grp = saved_grp
            if os.name != "nt":
                self.assertEqual(key.stat().st_mode & 0o777, 0o640)

    def test_dkim_rotate_hardens_the_generated_private_key(self):
        with sandbox() as box:
            calls = []
            real = core.set_dkim_key_permissions

            def spy(path):
                calls.append(pathlib.Path(path))
                real(path)

            def fake_run(args, input=None, timeout=45, check=True):
                box.commands.append(list(args))
                out_dir = None
                for i, arg in enumerate(args):
                    if arg == "-D" and i + 1 < len(args):
                        out_dir = pathlib.Path(args[i + 1])
                if out_dir is not None:
                    out_dir.mkdir(parents=True, exist_ok=True)
                    (out_dir / "mailstack.private").write_text("KEY", encoding="utf-8")
                    (out_dir / "mailstack.txt").write_text('"v=DKIM1; k=rsa; p=AAAA"', encoding="utf-8")
                return subprocess.CompletedProcess(args, 0, "", "")

            saved = {"ETC": certs.ETC, "run": certs.run, "shutil": certs.shutil,
                     "helper": certs.set_dkim_key_permissions}
            certs.ETC = LAYOUT.etc
            certs.run = fake_run
            certs.shutil = FakeShutil()
            certs.set_dkim_key_permissions = spy
            try:
                result = dispatcher.dispatch("dkim.rotate", {"domain": "example.com"})
            finally:
                for attr, value in saved.items():
                    setattr(certs, attr, value)
            self.assertEqual(result["status"], "ok")
            expected_key = LAYOUT.etc / "dkim" / "example.com" / "mailstack.private"
            self.assertEqual(calls, [expected_key],
                             "dkim_rotate must harden exactly the generated private key")

    def test_setup_identity_hardens_the_generated_private_key(self):
        with sandbox() as box:
            opendkim_root = LAYOUT.root / "opendkim"
            calls = []
            writes = []
            real = core.set_dkim_key_permissions

            def spy(path):
                calls.append(pathlib.Path(path))
                real(path)

            def fake_run(args, input=None, timeout=45, check=True):
                box.commands.append(list(args))
                if "opendkim-genkey" in str(args[0]):
                    out_dir = None
                    for i, arg in enumerate(args):
                        if arg == "-D" and i + 1 < len(args):
                            out_dir = pathlib.Path(args[i + 1])
                    if out_dir is not None:
                        out_dir.mkdir(parents=True, exist_ok=True)
                        (out_dir / "mail.private").write_text("KEY", encoding="utf-8")
                        (out_dir / "mail.txt").write_text("v=DKIM1; k=rsa; p=ABCD1234", encoding="utf-8")
                return subprocess.CompletedProcess(args, 0, "", "")

            saved = {
                "run": network.run, "shutil": network.shutil,
                "service_ctl": network.service_ctl, "atomic": network.atomic,
                "OPENDKIM_ROOT": network.OPENDKIM_ROOT,
                "SETUP_CONFIG": network.SETUP_CONFIG,
                "helper": network.set_dkim_key_permissions,
            }
            network.run = fake_run
            network.shutil = FakeShutil()
            network.service_ctl = lambda unit, verb: None
            network.atomic = lambda path, data, mode=0o640: writes.append((pathlib.Path(path), mode))
            network.OPENDKIM_ROOT = opendkim_root
            network.SETUP_CONFIG = LAYOUT.etc / "setup.json"
            network.set_dkim_key_permissions = spy
            try:
                result = network.setup_identity({
                    "domain": "example.com",
                    "mailHost": "mail.example.com",
                    "serverIp": "203.0.113.9",
                })
            finally:
                for attr, value in saved.items():
                    setattr(network, attr, value)
            self.assertTrue(result["applied"])
            self.assertEqual(result["dkimPublicKey"], "ABCD1234")
            expected_key = opendkim_root / "keys" / "example.com" / "mail.private"
            self.assertEqual(calls, [expected_key],
                             "setup_identity must harden exactly the generated private key")


class EscapeHatchScan(unittest.TestCase):
    """A5/T-ESC-1: doctor's escape-hatch scan flags production switches.

    telemetry.escape_hatch_scan() is a pure function over pre-parsed unit
    ``Environment=`` lines and a ``/proc/<pid>/environ`` blob, so it can be driven
    with fabricated data. In public mode any of COOKIE_SECURE=0 / HOST=0.0.0.0 /
    ADMIN_HOST=0.0.0.0 / MAILSTACK_ALLOW_UNSAFE_GIT=1 / MAILSTACK_AUDIT_FAILOPEN=1
    is a FAIL; the scan also asserts the admin panel binds a loopback address.
    The core T-ESC-1 assertion is: public + MAILSTACK_ALLOW_UNSAFE_GIT=1 -> FAIL.
    """

    @staticmethod
    def _status(checks, name):
        for chk in checks:
            if chk['name'] == name:
                return chk['status']
        return None

    def test_public_unsafe_git_is_fail(self):
        checks = telemetry.escape_hatch_scan(
            True, unit_env=['Environment=MAILSTACK_ALLOW_UNSAFE_GIT=1'])
        self.assertEqual(self._status(checks, 'Escape hatches'), 'FAIL',
                         "public mode with MAILSTACK_ALLOW_UNSAFE_GIT=1 must be a doctor FAIL")

    def test_public_cookie_secure_off_is_fail(self):
        checks = telemetry.escape_hatch_scan(
            True, unit_env=['Environment=COOKIE_SECURE=0'])
        self.assertEqual(self._status(checks, 'Escape hatches'), 'FAIL')

    def test_public_nonloopback_bind_is_fail(self):
        checks = telemetry.escape_hatch_scan(
            True, unit_env=['Environment=HOST=0.0.0.0'])
        self.assertEqual(self._status(checks, 'Escape hatches'), 'FAIL')
        self.assertEqual(self._status(checks, 'Admin bind address'), 'FAIL',
                         "a public admin panel bound to 0.0.0.0 must be a FAIL")

    def test_public_audit_failopen_from_proc_environ_is_fail(self):
        # The scan also reads the live process environment (/proc/<pid>/environ,
        # NUL-separated), not just the unit file.
        blob = 'PATH=/usr/bin\x00MAILSTACK_AUDIT_FAILOPEN=1\x00HOME=/root\x00'
        checks = telemetry.escape_hatch_scan(True, proc_environ=blob)
        self.assertEqual(self._status(checks, 'Escape hatches'), 'FAIL')

    def test_public_clean_config_passes(self):
        checks = telemetry.escape_hatch_scan(
            True, unit_env=['Environment=HOST=127.0.0.1', 'Environment=COOKIE_SECURE=1'])
        self.assertEqual(self._status(checks, 'Escape hatches'), 'PASS')
        self.assertEqual(self._status(checks, 'Admin bind address'), 'PASS')

    def test_local_cookie_secure_off_is_not_fail(self):
        # Over loopback/SSH, COOKIE_SECURE=0 in local mode is the correct config.
        checks = telemetry.escape_hatch_scan(
            False, unit_env=['Environment=COOKIE_SECURE=0', 'Environment=HOST=127.0.0.1'])
        self.assertNotEqual(self._status(checks, 'Escape hatches'), 'FAIL')

    def test_local_unsafe_git_is_warn(self):
        # An absolute-prohibition switch still earns a WARN even in local mode.
        checks = telemetry.escape_hatch_scan(
            False, unit_env=['Environment=MAILSTACK_ALLOW_UNSAFE_GIT=1'])
        self.assertEqual(self._status(checks, 'Escape hatches'), 'WARN')


class PublicBackupEncryption(unittest.TestCase):
    """B2/T-BKP-1: public mode refuses passphrase-less backup.create.

    The access mode is injected through the sandboxed install-args.conf --
    the real read_access_mode() plumbing, not a monkeypatched
    is_public_mode -- so the gate is exercised exactly as production
    reads it.
    """

    def setUp(self):
        # The tmp root is shared across the whole suite; audit and backup
        # sidecars left by earlier cases must not leak into "nothing was
        # written" claims.
        for name in ('audit.log', 'audit.log.head'):
            leftover = LAYOUT.root / name
            if leftover.exists():
                leftover.unlink()
        backups = LAYOUT.root / 'backups'
        if backups.is_dir():
            for stale in backups.iterdir():
                if stale.is_file():
                    stale.unlink()

    @staticmethod
    def _fake_backup_run(commands):
        # tar is asked to create the archive, so the fake writes it; gpg
        # stages its ciphertext next to the target (see _encrypt_archive).
        def fake_run(args, input=None, timeout=45, check=True):
            commands.append(list(args))
            if args and str(args[0]) == 'tar':
                pathlib.Path(args[2]).write_bytes(b'unit-test-archive')
            if args and str(args[0]) == 'gpg':
                for i, arg in enumerate(args[:-1]):
                    if str(arg) == '-o':
                        pathlib.Path(args[i + 1]).write_bytes(b'gpg-ciphertext')
                        break
            return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
        return fake_run

    def test_public_backup_without_passphrase_is_refused_before_tar(self):
        with sandbox() as box:
            core.INSTALL_ARGS_CONF.write_text('ACCESS_MODE=caddy\n', encoding='utf-8')
            with self.assertRaises(ValueError) as ctx:
                dispatcher.dispatch('backup.create', {})
            self.assertIn('passphrase', str(ctx.exception))
            # Fail-closed before any side effect: no binary ever ran and no
            # archive landed anywhere in the sandboxed backup directory.
            self.assertEqual(box.commands, [])
            self.assertEqual(list((LAYOUT.root / 'backups').glob('mailstack-backup-*')), [])

    def test_public_backup_with_passphrase_creates_encrypted_archive(self):
        commands = []
        with mock.patch.object(backup, 'run', self._fake_backup_run(commands)), \
                mock.patch.object(backup, '_backup_sources', return_value=[str(LAYOUT.etc)]), \
                mock.patch.object(backup, 'shutil', FakeShutil()):
            with sandbox():
                core.INSTALL_ARGS_CONF.write_text('ACCESS_MODE=caddy\n', encoding='utf-8')
                result = dispatcher.dispatch('backup.create', {'passphrase': 'unit-passphrase'})
        self.assertTrue(result['created'])
        self.assertTrue(result['backup']['encrypted'])
        # Exactly one archive; its .json metadata sidecar is not an archive.
        archives = list((LAYOUT.root / 'backups').glob('mailstack-backup-*.tar.gz'))
        self.assertEqual(len(archives), 1)
        gpg_calls = [c for c in commands if c and c[0] == 'gpg']
        self.assertEqual(len(gpg_calls), 1)
        # The passphrase travels via stdin (--passphrase-fd 0), never argv.
        self.assertNotIn('unit-passphrase', ' '.join(gpg_calls[0]))

    def test_local_backup_without_passphrase_stays_allowed(self):
        commands = []
        with mock.patch.object(backup, 'run', self._fake_backup_run(commands)), \
                mock.patch.object(backup, '_backup_sources', return_value=[str(LAYOUT.etc)]):
            with sandbox():
                # No install-args.conf -> local mode: plaintext is legitimate.
                result = dispatcher.dispatch('backup.create', {})
        self.assertTrue(result['created'])
        self.assertFalse(result['backup']['encrypted'])
        self.assertEqual([c[0] for c in commands], ['tar'])

    def test_plaintext_scan_flags_only_unencrypted_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            plain = directory / 'mailstack-backup-20240101-010101.tar.gz'
            plain.write_bytes(b'plaintext')
            encrypted = directory / 'mailstack-backup-20240102-020202.tar.gz'
            encrypted.write_bytes(b'ciphertext')
            (directory / 'mailstack-backup-20240102-020202.json').write_text(
                json.dumps({'encrypted': True}), encoding='utf-8')
            # A missing/damaged metadata file counts as plaintext (fail-closed).
            scan = backup.plaintext_backup_scan(directory, public_mode=True)
            self.assertEqual(scan, {'publicMode': True, 'plaintext': [plain.name]})
            # Local mode never reports plaintext archives: they are legal.
            self.assertEqual(backup.plaintext_backup_scan(directory, public_mode=False),
                             {'publicMode': False, 'plaintext': []})


class AuditChain(unittest.TestCase):
    """B3/T-AUD-1: the audit prev_hash chain detects tamper and truncation."""

    def setUp(self):
        # Hosts without syslog (Windows/CI) flip the forwarder into its
        # degraded no-op state so audit() does not retry-and-warn per case.
        core._syslog_state['failed'] = True
        self.addCleanup(core._syslog_state.update, ready=False, failed=False)

    def _fresh_log(self):
        for name in ('audit.log', 'audit.log.head'):
            leftover = LAYOUT.root / name
            if leftover.exists():
                leftover.unlink()

    def _append_entries(self, count):
        for i in range(count):
            core.audit(f'unit.chain.{i}', True)

    def test_three_entry_chain_verifies_ok(self):
        with sandbox():
            self._fresh_log()
            self._append_entries(3)
            result = core.audit_verify()
            self.assertTrue(result['ok'], result['error'])
            self.assertEqual(result['entries'], 3)
            self.assertTrue(result['anchor'])

    def test_truncated_tail_fails_verification(self):
        # T-AUD-1: drop the last record; the .head anchor still points at the
        # removed record's hash, so verification must fail.
        with sandbox():
            self._fresh_log()
            self._append_entries(3)
            lines = core.AUDIT_LOG.read_text(encoding='utf-8').splitlines(keepends=True)
            core.AUDIT_LOG.write_text(''.join(lines[:-1]), encoding='utf-8')
            result = core.audit_verify()
            self.assertFalse(result['ok'])
            self.assertEqual(result['entries'], 2)
            self.assertIn('anchor mismatch', result['error'])

    def test_tampered_middle_record_fails_verification(self):
        with sandbox():
            self._fresh_log()
            self._append_entries(3)
            lines = core.AUDIT_LOG.read_text(encoding='utf-8').splitlines()
            record = json.loads(lines[1])
            record['action'] = 'innocent.action'  # silently rewriting history
            lines[1] = json.dumps(record, ensure_ascii=False)
            core.AUDIT_LOG.write_text('\n'.join(lines) + '\n', encoding='utf-8')
            result = core.audit_verify()
            self.assertFalse(result['ok'])
            self.assertIn('hash mismatch', result['error'])

    def test_verify_cli_exits_nonzero_for_a_truncated_chain(self):
        # `ms audit-verify` drives monitoring from its exit code: a broken
        # chain must exit non-zero and say so on stderr.
        with sandbox():
            self._fresh_log()
            self._append_entries(3)
            lines = core.AUDIT_LOG.read_text(encoding='utf-8').splitlines(keepends=True)
            core.AUDIT_LOG.write_text(''.join(lines[:-1]), encoding='utf-8')
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = core.audit_verify_cli()
            self.assertNotEqual(exit_code, 0)
            self.assertIn('FAILED', stderr.getvalue())

    def test_verify_cli_exits_zero_for_an_intact_chain(self):
        with sandbox():
            self._fresh_log()
            self._append_entries(2)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = core.audit_verify_cli()
            self.assertEqual(exit_code, 0)
            self.assertIn('audit chain OK: 2 chained entries', stdout.getvalue())


class AiOutboundGate(unittest.TestCase):
    """B5: ai.* outbound actions are off by default in public mode."""

    def setUp(self):
        # The gate reads the environment; the suite must not inherit whatever
        # the developer's shell happens to export.
        for var in ('MAILSTACK_SECURITY_PROFILE', 'MAILSTACK_AI_OUTBOUND'):
            os.environ.pop(var, None)
            self.addCleanup(os.environ.pop, var, None)

    def test_public_mode_blocks_ai_chat_without_optin(self):
        with sandbox():
            core.INSTALL_ARGS_CONF.write_text('ACCESS_MODE=caddy\n', encoding='utf-8')
            with self.assertRaises(ValueError) as ctx:
                dispatcher.dispatch('ai.chat', {})
            self.assertIn('AI outbound actions are disabled', str(ctx.exception))

    def test_every_ai_outbound_action_is_gated_in_public_mode(self):
        with sandbox():
            core.INSTALL_ARGS_CONF.write_text('ACCESS_MODE=direct\n', encoding='utf-8')
            for action in sorted(dispatcher.AI_OUTBOUND_ACTIONS):
                with self.assertRaises(ValueError, msg=f'{action} must be gated') as ctx:
                    dispatcher.dispatch(action, {})
                self.assertIn('AI outbound actions are disabled', str(ctx.exception))

    def test_security_profile_high_is_treated_as_public(self):
        with sandbox():
            os.environ['MAILSTACK_SECURITY_PROFILE'] = 'high'
            with self.assertRaises(ValueError) as ctx:
                dispatcher.dispatch('ai.chat', {})
            self.assertIn('AI outbound actions are disabled', str(ctx.exception))

    def test_ai_conf_optin_unlocks_the_gate(self):
        with sandbox():
            core.INSTALL_ARGS_CONF.write_text('ACCESS_MODE=caddy\n', encoding='utf-8')
            core.AI_OUTBOUND_CONF.write_text('enabled=true\n', encoding='utf-8')
            # Past the gate the payload validator fires next (empty messages):
            # the request is rejected before any outbound HTTP could happen.
            with self.assertRaises(ValueError) as ctx:
                dispatcher.dispatch('ai.chat', {})
            self.assertNotIn('AI outbound actions are disabled', str(ctx.exception))

    def test_env_optin_unlocks_the_gate(self):
        with sandbox():
            core.INSTALL_ARGS_CONF.write_text('ACCESS_MODE=direct\n', encoding='utf-8')
            os.environ['MAILSTACK_AI_OUTBOUND'] = '1'
            with self.assertRaises(ValueError) as ctx:
                dispatcher.dispatch('ai.chat', {})
            self.assertNotIn('AI outbound actions are disabled', str(ctx.exception))

    def test_local_mode_stays_open(self):
        with sandbox():
            # No install-args.conf and no profile -> local mode: the historic
            # behaviour (outbound allowed) is preserved.
            with self.assertRaises(ValueError) as ctx:
                dispatcher.dispatch('ai.chat', {})
            self.assertNotIn('AI outbound actions are disabled', str(ctx.exception))

    def test_gate_covers_exactly_the_registered_outbound_ai_actions(self):
        registered_ai = {a for a in core.ALLOWED_ACTIONS if a.startswith('ai.')}
        self.assertEqual(
            dispatcher.AI_OUTBOUND_ACTIONS,
            registered_ai - {'ai.config.get', 'ai.config.set'},
            'AI_OUTBOUND_ACTIONS must track every registered ai.* action that can go outbound',
        )


class RemoteSyslogScan(unittest.TestCase):
    """B3: doctor's remote-syslog probe (pure function over config text)."""

    @staticmethod
    def _status(checks, name):
        for chk in checks:
            if chk['name'] == name:
                return chk['status']
        return None

    def _scan(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            conf = pathlib.Path(tmp) / '90-audit.conf'
            conf.write_text(text, encoding='utf-8')
            return telemetry.remote_syslog_scan(True, config_paths=[conf])

    def test_public_mode_without_forwarding_is_warn(self):
        checks = self._scan('# local file logging only\nmail.* -/var/log/mail.log\n')
        self.assertEqual(self._status(checks, 'Remote syslog'), 'WARN')

    def test_public_mode_with_tcp_forwarding_is_pass(self):
        checks = self._scan('authpriv.* @@loghost.example:6514\n')
        self.assertEqual(self._status(checks, 'Remote syslog'), 'PASS')

    def test_public_mode_with_udp_forwarding_is_pass(self):
        checks = self._scan('authpriv.* @loghost.example\n')
        self.assertEqual(self._status(checks, 'Remote syslog'), 'PASS')

    def test_commented_out_forwarding_is_not_detected(self):
        checks = self._scan('# authpriv.* @@loghost.example:6514\n')
        self.assertEqual(self._status(checks, 'Remote syslog'), 'WARN')

    def test_email_address_in_a_template_is_not_a_forwarding_target(self):
        checks = self._scan('$template mailtpl,"%FROM% <abuse@example.com>\\n"\n')
        self.assertEqual(self._status(checks, 'Remote syslog'), 'WARN')

    def test_omfwd_action_is_detected(self):
        checks = self._scan('action(type="omfwd" target="loghost.example" port="6514" protocol="tcp")\n')
        self.assertEqual(self._status(checks, 'Remote syslog'), 'PASS')

    def test_local_mode_produces_no_check(self):
        self.assertEqual(telemetry.remote_syslog_scan(False, config_paths=[]), [])


class KeyPermissionScan(unittest.TestCase):
    """B5: key-material permission verdicts are FAIL-level doctor checks.

    The scan is a pure function over paths, but the verdicts come from
    stat(), and Windows chmod cannot express 0600-vs-0644, so the matrix is
    driven by patching Path.stat with crafted os.stat_result values.
    """

    @staticmethod
    def _status(checks, name):
        for chk in checks:
            if chk['name'] == name:
                return chk['status']
        return None

    @staticmethod
    def _stat(mode, gid=0):
        return os.stat_result((0o100000 | mode, 0, 0, 1, 0, gid, 1, 0.0, 0.0, 0.0))

    @staticmethod
    def _local_opendkim_gid():
        """gid a correctly-permissioned DKIM key carries on THIS machine.

        The scanner treats root:opendkim as the owner contract; machines that
        already have the group (mail-stack dev boxes, WSL test rigs) must see
        it in the faked stat, or the 0640-is-pass matrix goes red for reasons
        that have nothing to do with the code under test.
        """
        try:
            import grp
        except ImportError:
            return 0
        try:
            return grp.getgrnam('opendkim').gr_gid
        except (KeyError, OSError):
            return 0

    @contextlib.contextmanager
    def _patch_stat(self, paths, mode, gid=0):
        """Fake stat() only for the given paths; everything else stays real.

        A blanket ``return_value`` mock on Path.stat breaks Path.glob/rglob on
        Python <= 3.12 (its directory iteration consults Path.stat), so the
        scanner silently finds zero files and the assertions see None -- red
        on CI (3.11), green on 3.14 dev machines whose glob no longer calls
        Path.stat. Faking only the target paths keeps glob fully functional.
        """
        wanted = {os.fspath(p) for p in paths}
        fake = self._stat(mode, gid)
        real = pathlib.Path.stat

        def selective(path, *args, **kwargs):
            if os.fspath(path) in wanted:
                return fake
            return real(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, 'stat', autospec=True,
                               side_effect=selective):
            yield

    def test_sasl_passwd_mode_0644_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            sasl = pathlib.Path(tmp) / 'sasl_passwd'
            sasl.write_text('smtp.example user:pass\n', encoding='utf-8')
            with self._patch_stat([sasl], 0o644):
                checks = telemetry.key_permission_scan(
                    sasl_passwd=sasl,
                    dkim_key_dir=pathlib.Path(tmp) / 'no-keys',
                    backup_dir=pathlib.Path(tmp) / 'no-backups')
            self.assertEqual(self._status(checks, 'sasl_passwd'), 'FAIL')

    def test_sasl_passwd_mode_0600_is_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            sasl = pathlib.Path(tmp) / 'sasl_passwd'
            sasl.write_text('smtp.example user:pass\n', encoding='utf-8')
            with self._patch_stat([sasl], 0o600):
                checks = telemetry.key_permission_scan(
                    sasl_passwd=sasl,
                    dkim_key_dir=pathlib.Path(tmp) / 'no-keys',
                    backup_dir=pathlib.Path(tmp) / 'no-backups')
            self.assertEqual(self._status(checks, 'sasl_passwd'), 'PASS')

    def test_dkim_private_key_mode_0640_is_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = pathlib.Path(tmp)
            key = keys / 'mail.private'
            key.write_text('KEY', encoding='utf-8')
            with self._patch_stat([key], 0o640, gid=self._local_opendkim_gid()):
                checks = telemetry.key_permission_scan(dkim_key_dir=keys)
            self.assertEqual(self._status(checks, 'DKIM key mail.private'), 'PASS')

    def test_dkim_private_key_mode_0644_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = pathlib.Path(tmp)
            key = keys / 'mail.private'
            key.write_text('KEY', encoding='utf-8')
            with self._patch_stat([key], 0o644):
                checks = telemetry.key_permission_scan(dkim_key_dir=keys)
            self.assertEqual(self._status(checks, 'DKIM key mail.private'), 'FAIL')

    def test_backup_archive_mode_0644_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = pathlib.Path(tmp) / 'mailstack-backup-20240101-010101.tar.gz.gpg'
            archive.write_bytes(b'ciphertext')
            with self._patch_stat([archive], 0o644):
                checks = telemetry.key_permission_scan(backup_dir=pathlib.Path(tmp))
            self.assertEqual(self._status(checks, f'backup {archive.name}'), 'FAIL')

    def test_backup_archive_mode_0600_is_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = pathlib.Path(tmp) / 'mailstack-backup-20240101-010101.tar.gz.gpg'
            archive.write_bytes(b'ciphertext')
            with self._patch_stat([archive], 0o600):
                checks = telemetry.key_permission_scan(backup_dir=pathlib.Path(tmp))
            self.assertEqual(self._status(checks, f'backup {archive.name}'), 'PASS')


if __name__ == "__main__":
    unittest.main(verbosity=2)

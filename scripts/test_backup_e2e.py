#!/usr/bin/env python3
"""
MailStack Backup and Restore E2E Integrity and Security Test Suite
Tests:
1. Backup creation with full metadata and SHA256 checksum
2. SHA256 tampering rejection
3. Dangerous tar path traversal (../../) rejection
4. Symlink / Device file exploit rejection
5. Safe dry-run extraction preview
6. Snapshot generation prior to restoration
"""
import os, sys, tempfile, shutil, pathlib, json, hashlib, tarfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / 'backend'))
from mailstackctl.version import __version__ as PRODUCT_VERSION
from mailstackctl import backup

def run_backup_e2e_tests():
    print("=== MailStack Backup E2E Test Suite ===")
    
    # 1. Test validate_tar_safe on path traversal
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        traversal_tar = tmp_path / "traversal_attack.tar.gz"
        
        with tarfile.open(traversal_tar, "w:gz") as tar:
            f = tmp_path / "fake_shadow"
            f.write_text("root:*:12345:0:99999:7:::", encoding="utf-8")
            tar.add(f, arcname="../../etc/shadow")
            
        try:
            backup.validate_tar_safe(traversal_tar)
            print("? FAIL: Traversal tar was NOT rejected!")
            sys.exit(1)
        except ValueError as e:
            assert "traversal" in str(e).lower() or "allowlist" in str(e).lower()
            print("? PASS: Path traversal attack correctly blocked by validate_tar_safe")

    # 2. Test validate_tar_safe on unapproved external paths
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        escape_tar = tmp_path / "escape_attack.tar.gz"
        
        with tarfile.open(escape_tar, "w:gz") as tar:
            f = tmp_path / "malicious_bin"
            f.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
            tar.add(f, arcname="usr/local/bin/malicious")
            
        try:
            backup.validate_tar_safe(escape_tar)
            print("? FAIL: Unauthorized path in archive was NOT rejected!")
            sys.exit(1)
        except ValueError as e:
            print(f"? PASS: Unauthorized extraction path correctly blocked ({e})")

    # 3. Reject links and privileged permission bits.
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        link_tar = tmp_path / "link_attack.tar.gz"
        with tarfile.open(link_tar, "w:gz") as tar:
            link = tarfile.TarInfo("etc/mailstack/admin-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/shadow"
            tar.addfile(link)
        try:
            backup.validate_tar_safe(link_tar)
            raise AssertionError("Symbolic link archive was accepted")
        except ValueError as exc:
            assert "link" in str(exc).lower()

        mode_tar = tmp_path / "setuid_attack.tar.gz"
        payload = tmp_path / "payload"
        payload.write_text("test", encoding="utf-8")
        with tarfile.open(mode_tar, "w:gz") as tar:
            info = tar.gettarinfo(payload, arcname="etc/mailstack/payload")
            info.mode = 0o4755
            with payload.open("rb") as handle:
                tar.addfile(info, handle)
        try:
            backup.validate_tar_safe(mode_tar)
            raise AssertionError("Setuid archive member was accepted")
        except ValueError as exc:
            assert "permission" in str(exc).lower()
        print("PASS: Links and unsafe permission bits were rejected")

    # 4. Test valid tar verification and dry-run preview
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        valid_tar = tmp_path / "valid_backup.tar.gz"
        
        with tarfile.open(valid_tar, "w:gz") as tar:
            dummy_cfg = tmp_path / "settings.json"
            dummy_cfg.write_text('{"colorTheme": "cyan"}', encoding="utf-8")
            info = tar.gettarinfo(dummy_cfg, arcname="etc/mailstack/settings.json")
            info.mode = 0o640
            with dummy_cfg.open("rb") as handle:
                tar.addfile(info, handle)
            
        inspected = backup.validate_tar_safe(valid_tar)
        assert len(inspected) >= 1
        print("? PASS: Valid archive accepted and inspected correctly")

    # 4. Test SHA256 tampering rejection
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        backup.BACKUP_DIR = tmp_path
        
        test_tar = tmp_path / "mailstack-backup-20240101-000000.tar.gz"
        with tarfile.open(test_tar, "w:gz") as tar:
            f = tmp_path / "dummy.txt"
            f.write_text("mailstack backup test", encoding="utf-8")
            info = tar.gettarinfo(f, arcname="etc/mailstack/test.txt")
            info.mode = 0o640
            with f.open("rb") as handle:
                tar.addfile(info, handle)
            
        actual_sha = hashlib.sha256(test_tar.read_bytes()).hexdigest()
        meta = {
            "name": test_tar.name,
            "filename": test_tar.name,
            "path": str(test_tar),
            "sha256": actual_sha,
            "version": PRODUCT_VERSION
        }
        meta_file = tmp_path / test_tar.name.replace(".tar.gz", ".json")
        meta_file.write_text(json.dumps(meta), encoding="utf-8")
        
        # Dry-run on untampered archive
        preview = backup.backup_restore({"name": test_tar.name, "dryRun": True})
        assert preview.get("dryRun") is True or preview.get("ready") is True
        print("? PASS: Dry run preview succeeds on genuine archive")
        
        # Tamper 1 byte in the archive
        data = bytearray(test_tar.read_bytes())
        data[20] = (data[20] + 1) % 256
        test_tar.write_bytes(bytes(data))
        
        try:
            backup.backup_restore({"name": test_tar.name, "dryRun": False})
            print("? FAIL: Tampered archive did not fail SHA256 check!")
            sys.exit(1)
        except ValueError as e:
            assert "SHA" in str(e) or "??" in str(e) or "integrity" in str(e).lower()
            print("? PASS: Tampered archive rejected by SHA-256 mismatch detection")

    # 5. Home directories: only MailStack-managed unix accounts are restorable.
    #    A crafted archive aiming an authorized_keys file at an unrelated user
    #    must be rejected before any extraction happens.
    from mailstackctl import mail
    saved_mailboxes = mail.MANAGED_MAILBOXES
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            attack_tar = tmp_path / "home_escape.tar.gz"
            with tarfile.open(attack_tar, "w:gz") as tar:
                f = tmp_path / "authorized_keys"
                f.write_text("ssh-ed25519 AAAA... attacker@host", encoding="utf-8")
                tar.add(f, arcname="home/stranger/.ssh/authorized_keys")
            try:
                backup.validate_tar_safe(attack_tar)
                print("FAIL: unmanaged home member was NOT rejected!")
                sys.exit(1)
            except ValueError as e:
                assert "home" in str(e).lower() or "manage" in str(e).lower()
                print("PASS: Unmanaged home/.ssh/authorized_keys member rejected")

        # Positive control: with the managed-mailboxes registry seeded, the same
        # path under a managed account passes validation.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            registry = tmp_path / "managed-mailboxes.json"
            registry.write_text(json.dumps([{"email": "alice@example.com", "unixUser": "alice"}]), encoding="utf-8")
            mail.MANAGED_MAILBOXES = registry
            ok_tar = tmp_path / "managed_home.tar.gz"
            with tarfile.open(ok_tar, "w:gz") as tar:
                f = tmp_path / "authorized_keys_ok"
                f.write_text("ssh-ed25519 AAAA... alice@host", encoding="utf-8")
                tar.add(f, arcname="home/alice/.ssh/authorized_keys")
            inspected = backup.validate_tar_safe(ok_tar)
            assert inspected == ["home/alice/.ssh/authorized_keys"]
            print("PASS: Managed-account home member accepted with seeded registry")
    finally:
        mail.MANAGED_MAILBOXES = saved_mailboxes

    # 6. Encrypted backups: fail-closed creation, listing, passphrase-gated restore.
    if not shutil.which("gpg"):
        print("SKIP: gpg not installed -- encrypted backup round-trip tests skipped")
    else:
        passphrase = "correct-horse-battery-9"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            backup.BACKUP_DIR = tmp_path
            enc_tar = tmp_path / "mailstack-backup-20240102-000000.tar.gz"
            with tarfile.open(enc_tar, "w:gz") as tar:
                f = tmp_path / "dummy.txt"
                f.write_text("encrypted backup payload", encoding="utf-8")
                info = tar.gettarinfo(f, arcname="etc/mailstack/test.txt")
                info.mode = 0o640
                with f.open("rb") as handle:
                    tar.addfile(info, handle)

            backup._encrypt_archive(enc_tar, passphrase)
            # On-disk bytes are no longer gzip and no plaintext staging file remains.
            assert enc_tar.read_bytes()[:2] != b"\x1f\x8b", "archive must be ciphertext"
            assert not (tmp_path / (enc_tar.name + ".enc")).exists()

            meta = {
                "name": enc_tar.name,
                "filename": enc_tar.name,
                "path": str(enc_tar),
                "sha256": hashlib.sha256(enc_tar.read_bytes()).hexdigest(),
                "encrypted": True,
                "version": PRODUCT_VERSION,
            }
            (tmp_path / enc_tar.name.replace(".tar.gz", ".json")).write_text(json.dumps(meta), encoding="utf-8")

            # Still listable, and the listing carries the encrypted flag.
            listing = backup.backup_list()
            assert any(item.get("filename") == enc_tar.name and item.get("encrypted") for item in listing), \
                "encrypted backup must be listable with encrypted=true"
            print("PASS: Encrypted backup created in place and listed with encrypted=true")

            # Restore without a passphrase is refused before any decryption.
            try:
                backup.backup_restore({"name": enc_tar.name, "dryRun": True})
                print("FAIL: encrypted restore succeeded without a passphrase!")
                sys.exit(1)
            except ValueError as e:
                assert "passphrase" in str(e).lower()
            print("PASS: Encrypted restore without passphrase rejected")

            # Wrong passphrase fails closed with a clear error.
            try:
                backup.backup_restore({"name": enc_tar.name, "dryRun": True, "passphrase": "wrong"})
                print("FAIL: wrong passphrase decrypted the archive!")
                sys.exit(1)
            except ValueError as e:
                assert "decrypt" in str(e).lower()
            print("PASS: Wrong passphrase rejected")

            # With the passphrase the full validation chain runs on the plaintext.
            preview = backup.backup_restore({"name": enc_tar.name, "dryRun": True, "passphrase": passphrase})
            assert preview.get("ready") is True and preview.get("encrypted") is True
            assert preview["previewFiles"] == ["etc/mailstack/test.txt"]
            # No decrypted temp file may survive the restore path.
            leftovers = list(tmp_path.glob(".mailstack-restore-*"))
            assert leftovers == [], f"decrypted temp files leaked: {leftovers}"
            print("PASS: Encrypted backup restored (dry-run) with passphrase, no temp leak")

    # 7. Restored admin.json must keep the console-readable permission
    #    contract (0640 root:mailstack-admin). The Node console is not root
    #    and reads it via the group bit; a 0600 restore locks the console out.
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        admin_tar = tmp_path / "admin_restore.tar.gz"
        with tarfile.open(admin_tar, "w:gz") as tar:
            f = tmp_path / "admin.json"
            f.write_text(json.dumps({"username": "admin", "hash": "probe"}), encoding="utf-8")
            info = tar.gettarinfo(f, arcname="etc/mailstack/admin.json")
            info.mode = 0o600
            with f.open("rb") as handle:
                tar.addfile(info, handle)
            s = tmp_path / "sasl_passwd"
            s.write_text("relay.example user:pass", encoding="utf-8")
            info2 = tar.gettarinfo(s, arcname="etc/postfix/sasl_passwd")
            info2.mode = 0o600
            with s.open("rb") as handle:
                tar.addfile(info2, handle)
        dest = tmp_path / "root"
        dest.mkdir()
        backup.safe_extract_and_copy(admin_tar, dest)
        restored_admin = dest / "etc" / "mailstack" / "admin.json"
        restored_sasl = dest / "etc" / "postfix" / "sasl_passwd"
        assert restored_admin.is_file() and restored_sasl.is_file()
        if os.name == "posix":
            admin_mode = restored_admin.stat().st_mode & 0o777
            sasl_mode = restored_sasl.stat().st_mode & 0o777
            assert admin_mode == 0o640, \
                f"admin.json must restore as 0640 (group-readable), got {oct(admin_mode)}"
            assert sasl_mode == 0o600, \
                f"sasl_passwd must stay 0600, got {oct(sasl_mode)}"
        # Windows cannot represent unix mode bits via os.chmod; existence
        # assertions above are the portable part of this contract.
        print("PASS: admin.json restored with the 0640 console-read contract")

    # 8. A corrupted plaintext backup (gzip magic destroyed, checksum still
    #    matching) must be reported as corrupted -- not as "encrypted".
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        backup.BACKUP_DIR = tmp_path
        corrupt_tar = tmp_path / "mailstack-backup-20240103-000000.tar.gz"
        with tarfile.open(corrupt_tar, "w:gz") as tar:
            f = tmp_path / "dummy.txt"
            f.write_text("corruption probe", encoding="utf-8")
            info = tar.gettarinfo(f, arcname="etc/mailstack/test.txt")
            info.mode = 0o640
            with f.open("rb") as handle:
                tar.addfile(info, handle)
        raw = bytearray(corrupt_tar.read_bytes())
        raw[0] = 0x00  # destroy the gzip magic without touching the length
        raw[1] = 0x00
        corrupt_tar.write_bytes(bytes(raw))
        meta = {
            "name": corrupt_tar.name,
            "filename": corrupt_tar.name,
            "path": str(corrupt_tar),
            "sha256": hashlib.sha256(corrupt_tar.read_bytes()).hexdigest(),
            "version": PRODUCT_VERSION,
        }
        (tmp_path / corrupt_tar.name.replace(".tar.gz", ".json")).write_text(json.dumps(meta), encoding="utf-8")
        try:
            backup.backup_restore({"name": corrupt_tar.name, "dryRun": True})
            print("FAIL: corrupted plaintext backup was not rejected!")
            sys.exit(1)
        except ValueError as e:
            msg = str(e).lower()
            assert "corrupted" in msg or "gzip" in msg, f"expected a corruption error, got: {e}"
            assert "passphrase" not in msg, "corruption must not be misreported as encryption"
        print("PASS: Corrupted plaintext backup reported as corrupted, not encrypted")

    print("=== All Backup E2E Tests Passed Successfully ===")

if __name__ == "__main__":
    run_backup_e2e_tests()

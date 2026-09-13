# MailStack admin-console two-factor authentication (TOTP, RFC 6238).
#
# A3: The TOTP secret is stored as an AES-256-GCM envelope in admin.json.
# The master key lives at /etc/mailstack/totp.key (0600 root:root) and is
# readable ONLY by the privileged helper. The Node process can read
# admin.json but sees only {enc, nonce, tag} -- never the plaintext secret.
#
# Verification of a login-time TOTP happens inside the helper via the
# `admin.totp.verify` action; the secret never leaves this module.
# Consumption of a recovery code is a mutation and must come here (it is
# one-time by construction: the hash is removed from the list).
#
# When the `cryptography` package is unavailable, all 2FA operations
# fail-closed with an explicit error. Self-made encryption is FORBIDDEN.
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time

from .core import ADMIN_CONFIG, ETC, atomic, locked, warn

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
RECOVERY_CODE_COUNT = 10
TOTP_KEY_PATH = ETC / 'totp.key'

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

try:
    import grp
except ImportError:  # pragma: no cover - development hosts only
    grp = None


def _require_aesgcm():
    """Fail-closed guard: every envelope operation requires cryptography."""
    if AESGCM is None:
        raise ValueError(
            'python3-cryptography is not installed; 2FA operations are unavailable. '
            'Install the distribution package (apt/dnf/pacman/apk). '
            'Self-made encryption is forbidden.'
        )


def _b32encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode('ascii').rstrip('=')


def _b32decode(value: str) -> bytes:
    cleaned = ''.join(str(value).split()).upper()
    if not cleaned or len(cleaned) > 64:
        raise ValueError('invalid base32 secret')
    return base64.b32decode(cleaned + '=' * ((-len(cleaned)) % 8))


def _hotp(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (
        (digest[offset] & 0x7F) << 24
        | digest[offset + 1] << 16
        | digest[offset + 2] << 8
        | digest[offset + 3]
    ) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def totp_match(secret_b32: str, code: str, window: int = 1) -> bool:
    """Constant-time TOTP check over the previous/current/next 30s step."""
    try:
        secret = _b32decode(secret_b32)
    except Exception:
        return False
    digits = ''.join(ch for ch in str(code) if ch.isdigit())
    if len(digits) != TOTP_DIGITS:
        return False
    counter = int(time.time()) // TOTP_STEP_SECONDS
    return any(
        hmac.compare_digest(_hotp(secret, counter + drift), digits)
        for drift in (-window, 0, window)
    )


# --- AES-256-GCM envelope helpers ---

def _load_master_key() -> bytes:
    """Load (or generate) the 32-byte master key at /etc/mailstack/totp.key.

    Generation requires root: the file is created 0600 root:root immediately.
    Only the privileged helper process (running as root) can read it.
    """
    _require_aesgcm()
    if TOTP_KEY_PATH.exists():
        try:
            key = TOTP_KEY_PATH.read_bytes()
            if len(key) == 32:
                return key
            warn(f'totp.key has unexpected length {len(key)}, regenerating')
        except OSError as exc:
            raise ValueError(f'cannot read {TOTP_KEY_PATH}: {exc}') from exc
    # Generate a fresh key. This path is only reachable as root (the helper).
    key = secrets.token_bytes(32)
    TOTP_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically: tmp file then rename, so a crash never leaves a
    # half-written key that would make existing envelopes undecryptable.
    tmp = TOTP_KEY_PATH.with_suffix('.tmp')
    tmp.write_bytes(key)
    os.chmod(tmp, 0o600)
    try:
        os.chown(tmp, 0, 0)
    except (OSError, AttributeError):
        pass
    os.replace(tmp, TOTP_KEY_PATH)
    return key


def _seal_secret(plaintext_b32: str) -> dict:
    """Encrypt a base32 TOTP secret into {enc, nonce, tag} (all base64)."""
    _require_aesgcm()
    key = _load_master_key()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext_b32.encode('utf-8'), None)
    # AESGCM.encrypt returns ciphertext || tag (last 16 bytes).
    tag = ciphertext[-16:]
    enc = ciphertext[:-16]
    return {
        'enc': base64.b64encode(enc).decode('ascii'),
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'tag': base64.b64encode(tag).decode('ascii'),
    }


def _open_envelope(envelope: dict) -> str:
    """Decrypt {enc, nonce, tag} back to the plaintext base32 secret."""
    _require_aesgcm()
    key = _load_master_key()
    aesgcm = AESGCM(key)
    enc = base64.b64decode(envelope['enc'])
    nonce = base64.b64decode(envelope['nonce'])
    tag = base64.b64decode(envelope['tag'])
    plaintext = aesgcm.decrypt(nonce, enc + tag, None)
    return plaintext.decode('utf-8')


def _migrate_plaintext_secret(cfg: dict) -> bool:
    """If admin.json still holds a plaintext `secret` field, re-seal it.

    Returns True if a migration was performed (caller must persist).
    Called inside locked(ADMIN_CONFIG) so the read-modify-write is atomic.
    """
    totp_cfg = cfg.get('totp')
    if not isinstance(totp_cfg, dict):
        return False
    if 'secret' not in totp_cfg:
        return False
    plaintext = totp_cfg.pop('secret')
    if not plaintext:
        return True  # empty secret, just remove the field
    envelope = _seal_secret(str(plaintext))
    totp_cfg.update(envelope)
    cfg['totp'] = totp_cfg
    return True


def _load_admin() -> dict:
    try:
        cfg = json.loads(ADMIN_CONFIG.read_text(encoding='utf-8'))
    except FileNotFoundError:
        raise ValueError('administrator account is not configured')
    if not isinstance(cfg, dict):
        raise ValueError('administrator configuration is invalid')
    return cfg


def _save_admin(cfg: dict) -> None:
    atomic(ADMIN_CONFIG, json.dumps(cfg, indent=2) + '\n', 0o640)
    if grp is not None:
        try:
            os.chown(ADMIN_CONFIG, 0, grp.getgrnam('mailstack-admin').gr_gid)
        except Exception as exc:
            warn('chown admin config to mailstack-admin', exc)


def _normalize_recovery_code(code: str) -> str:
    return ''.join(str(code).split()).lower()


def _consume_recovery(cfg: dict, code: str) -> bool:
    """Remove one recovery-code hash from *cfg* in memory; the caller persists
    the result. Every caller holds locked(ADMIN_CONFIG) across the whole
    load-modify-save, so a consumed hash can never be resurrected by a racing
    writer (the old split let two concurrent requests double-spend a code)."""
    totp_cfg = cfg.get('totp') or {}
    digest = hashlib.sha256(_normalize_recovery_code(code).encode('utf-8')).hexdigest()
    remaining = list(totp_cfg.get('recovery') or [])
    kept = [h for h in remaining if not hmac.compare_digest(str(h), digest)]
    if len(kept) == len(remaining):
        return False
    totp_cfg['recovery'] = kept
    cfg['totp'] = totp_cfg
    return True


def _get_secret_from_envelope(totp_cfg: dict) -> str:
    """Open the envelope and return the plaintext base32 secret."""
    if 'enc' in totp_cfg and 'nonce' in totp_cfg and 'tag' in totp_cfg:
        return _open_envelope(totp_cfg)
    # Legacy plaintext (should have been migrated, but handle gracefully).
    if 'secret' in totp_cfg:
        return str(totp_cfg['secret'])
    raise ValueError('no TOTP secret envelope found')


def totp_begin(data=None):
    """Start (or restart) an enrollment: fresh secret, not yet enabled.

    When 2FA is already enabled this call is a re-enrollment and would
    silently downgrade the account to single factor until confirmed, so it is
    gated exactly like disable: it must present a live TOTP or an unused
    recovery code. A hijacked session alone is no longer enough.

    A3: The secret is stored as an AES-256-GCM envelope; plaintext never
    touches admin.json.
    """
    _require_aesgcm()
    with locked(ADMIN_CONFIG):
        cfg = _load_admin()
        # Migrate any legacy plaintext secret before proceeding.
        if _migrate_plaintext_secret(cfg):
            _save_admin(cfg)
        existing = cfg.get('totp') or {}
        if existing.get('enabled'):
            code = str((data or {}).get('code', ''))
            secret_b32 = _get_secret_from_envelope(existing)
            if not totp_match(secret_b32, code) and not _consume_recovery(cfg, code):
                raise ValueError('two-factor is enabled; a valid code is required to re-enroll')
        secret = _b32encode(secrets.token_bytes(20))
        envelope = _seal_secret(secret)
        cfg['totp'] = {**envelope, 'enabled': False, 'recovery': []}
        _save_admin(cfg)
        username = str(cfg.get('username') or 'admin')
        issuer = 'MailStack'
        uri = (
            f'otpauth://totp/{issuer}:{username}'
            f'?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}'
        )
    return {'secret': secret, 'uri': uri, 'enabled': False}


def totp_enable(data):
    """Confirm enrollment with a live code; returns one-time recovery codes."""
    _require_aesgcm()
    with locked(ADMIN_CONFIG):
        cfg = _load_admin()
        # Migrate any legacy plaintext secret.
        if _migrate_plaintext_secret(cfg):
            _save_admin(cfg)
        totp_cfg = cfg.get('totp') or {}
        if 'enc' not in totp_cfg:
            raise ValueError('no pending two-factor enrollment')
        secret_b32 = _get_secret_from_envelope(totp_cfg)
        if not totp_match(secret_b32, str((data or {}).get('code', ''))):
            raise ValueError('invalid TOTP code')
        codes = [f'{secrets.token_hex(4)}-{secrets.token_hex(4)}' for _ in range(RECOVERY_CODE_COUNT)]
        totp_cfg['enabled'] = True
        totp_cfg['recovery'] = sorted(hashlib.sha256(c.encode('utf-8')).hexdigest() for c in codes)
        cfg['totp'] = totp_cfg
        _save_admin(cfg)
    return {'enabled': True, 'recoveryCodes': codes}


def totp_disable(data):
    """Turn 2FA off. Requires a valid TOTP or an unused recovery code."""
    _require_aesgcm()
    with locked(ADMIN_CONFIG):
        cfg = _load_admin()
        totp_cfg = cfg.get('totp') or {}
        if not totp_cfg.get('enabled'):
            return {'enabled': False}
        code = str((data or {}).get('code', ''))
        secret_b32 = _get_secret_from_envelope(totp_cfg)
        if not totp_match(secret_b32, code) and not _consume_recovery(cfg, code):
            raise ValueError('invalid TOTP or recovery code')
        cfg.pop('totp', None)
        _save_admin(cfg)
    return {'enabled': False}


def totp_consume_recovery(data):
    """Login path: spend a recovery code. One-time by construction."""
    with locked(ADMIN_CONFIG):
        cfg = _load_admin()
        totp_cfg = cfg.get('totp') or {}
        if not totp_cfg.get('enabled'):
            raise ValueError('two-factor authentication is not enabled')
        if not _consume_recovery(cfg, str((data or {}).get('code', ''))):
            raise ValueError('invalid recovery code')
        _save_admin(cfg)
        remaining = len((cfg.get('totp') or {}).get('recovery') or [])
    return {'consumed': True, 'remaining': remaining}


def totp_verify(data):
    """A3: Verify a TOTP code inside the helper. The secret never leaves.

    Called by Node during login: {code} → {ok: bool}.
    The replay guard (per-user 30s step counter) stays in Node.
    """
    _require_aesgcm()
    code = str((data or {}).get('code', ''))
    with locked(ADMIN_CONFIG):
        cfg = _load_admin()
        # Migrate any legacy plaintext secret on first verify after upgrade.
        if _migrate_plaintext_secret(cfg):
            _save_admin(cfg)
        totp_cfg = cfg.get('totp') or {}
        if not totp_cfg.get('enabled'):
            return {'ok': False}
        try:
            secret_b32 = _get_secret_from_envelope(totp_cfg)
        except Exception:
            return {'ok': False}
    # totp_match is constant-time; no lock needed for the comparison itself.
    return {'ok': totp_match(secret_b32, code)}

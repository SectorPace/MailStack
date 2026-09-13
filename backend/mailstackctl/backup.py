# MailStack backup and restore engine.
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import tarfile
import tempfile

try:
    import pwd
except ImportError:  # pragma: no cover - Linux production dependency
    pwd = None

try:
    import grp
except ImportError:  # pragma: no cover - development hosts only
    grp = None

from .version import __version__
from .core import atomic, run, service_ctl, warn, is_public_mode
from .mail import managed_mailboxes

BACKUP_DIR = pathlib.Path('/var/backups/mailstack')
BACKUP_FILENAME_RE = re.compile(r'^mailstack-backup-\d{8}-\d{6}(?:-[a-z0-9_-]+)?\.tar\.gz$')
HOME_ROOTS = ('home/',)
ALLOWED_PREFIXES = (
    'etc/mailstack/',
    'etc/postfix/',
    'etc/dovecot/',
    'etc/opendkim/',
    'var/vmail/',
    'var/lib/mailstack/',
    'root/Maildir/',
) + HOME_ROOTS
ALLOWED_EXACT = tuple(prefix.rstrip('/') for prefix in ALLOWED_PREFIXES)
ALLOWED_RESTORE_PREFIXES = tuple('/' + prefix.rstrip('/') for prefix in ALLOWED_PREFIXES)
allowed_prefixes = ALLOWED_RESTORE_PREFIXES
MAX_BACKUP_ARCHIVE_BYTES = 5 * 1024 * 1024 * 1024
MAX_BACKUP_MEMBERS = 100_000
MAX_BACKUP_EXPANDED_BYTES = 50 * 1024 * 1024 * 1024


def file_sha256(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _require_gpg():
    # Fail-closed: an encryption request must never silently degrade into a
    # plaintext backup, so a missing gpg binary is a hard error.
    if not shutil.which('gpg'):
        raise RuntimeError('gpg is not installed; encrypted backups are unavailable (refusing to fall back to plaintext)')


def _encrypt_archive(target, passphrase):
    """Encrypt *target* in place with gpg symmetric AES256.

    The passphrase travels only via stdin (--passphrase-fd 0), never through
    argv or logs. On any failure the plaintext archive is removed as well: if
    the operator asked for encryption, leaving the plaintext behind would be a
    silent downgrade.
    """
    target = pathlib.Path(target)
    _require_gpg()
    staged = target.with_name(target.name + '.enc')
    try:
        run(['gpg', '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase-fd', '0',
             '--symmetric', '--cipher-algo', 'AES256', '-o', str(staged), str(target)],
            input=passphrase, timeout=600)
        os.chmod(staged, 0o600)
        os.replace(staged, target)
    except BaseException:
        staged.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        raise


def _is_gzip_file(path):
    try:
        with pathlib.Path(path).open('rb') as handle:
            return handle.read(2) == b'\x1f\x8b'
    except OSError:
        return False


def _restore_home_users():
    """Accounts whose home directory a restore is allowed to write into.

    Limited to the unix accounts MailStack actually manages, so a crafted archive
    cannot overwrite an unrelated user's shell profile or authorized_keys.
    """
    users = set()
    for mailbox in managed_mailboxes():
        user = str(mailbox.get('unixUser', ''))
        if re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user):
            users.add(user)
    return users


def _normalized_member(member):
    name = member.name.strip().replace('\\', '/').lstrip('/')
    parts = pathlib.PurePosixPath(name).parts
    if not name or any(part in ('', '.', '..') for part in parts):
        raise ValueError(f'Archive path traversal rejected: {member.name}')
    normalized = '/'.join(parts)
    if normalized not in ALLOWED_EXACT and not any(normalized.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        raise ValueError(f'Archive member is outside the restore allowlist: {member.name}')
    if normalized.startswith('home/'):
        owner = normalized.split('/', 2)[1] if len(normalized.split('/')) > 1 else ''
        if not owner or owner not in _restore_home_users():
            raise ValueError(f'Archive member targets a home directory MailStack does not manage: {member.name}')
    if member.isdev() or member.isfifo() or (hasattr(member, 'issocket') and member.issocket()):
        raise ValueError(f'Archive contains a device or special file: {member.name}')
    if member.issym() or member.islnk():
        raise ValueError(f'Archive contains a symbolic or hard link: {member.name}')
    if not (member.isdir() or member.isfile()):
        raise ValueError(f'Archive contains an unsupported member: {member.name}')
    if member.mode & 0o7000:
        raise ValueError(f'Archive contains unsafe permission bits: {member.name}')
    return normalized


def validate_tar_safe(tar_path):
    archive = pathlib.Path(tar_path)
    if not archive.is_file() or archive.is_symlink():
        raise ValueError('Backup archive must be a regular file')
    if archive.stat().st_size > MAX_BACKUP_ARCHIVE_BYTES:
        raise ValueError('Backup archive exceeds the size limit')
    inspected = []
    expanded_bytes = 0
    with tarfile.open(archive, 'r:*') as tar:
        members = tar.getmembers()
        if len(members) > MAX_BACKUP_MEMBERS:
            raise ValueError('Backup archive contains too many entries')
        for member in members:
            normalized = _normalized_member(member)
            expanded_bytes += max(0, member.size)
            if expanded_bytes > MAX_BACKUP_EXPANDED_BYTES:
                raise ValueError('Backup archive expands beyond the size limit')
            inspected.append(normalized)
    return inspected


def _make_safe_parent(destination_root, parts):
    parent = destination_root
    for part in parts:
        candidate = parent / part
        if candidate.is_symlink():
            raise ValueError(f'Restore destination contains a symbolic link: {candidate}')
        if not candidate.exists():
            owner = parent.stat()
            candidate.mkdir(mode=0o750)
            if hasattr(os, 'chown'):
                os.chown(candidate, owner.st_uid, owner.st_gid)
        elif not candidate.is_dir():
            raise ValueError(f'Restore destination parent is not a directory: {candidate}')
        parent = candidate
    return parent


def _mailstack_admin_gid():
    """GID of the mailstack-admin group, or None when it cannot be resolved.

    The admin Node process is not root and reads /etc/mailstack/admin.json
    through the 0640 root:mailstack-admin group permission, so a restored
    admin.json must land with exactly that ownership -- a 0600 root:root file
    locks the console out of its own credentials.
    """
    if grp is None:
        return None
    try:
        return grp.getgrnam('mailstack-admin').gr_gid
    except (KeyError, OSError):
        return None


def safe_extract_and_copy(tar_path, dest_root=pathlib.Path('/')):
    inspected = validate_tar_safe(tar_path)
    destination_root = pathlib.Path(dest_root).resolve()
    restored = []
    with tempfile.TemporaryDirectory(prefix='ms_backup_extract_') as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        with tarfile.open(tar_path, 'r:*') as tar:
            for member, normalized in zip(tar.getmembers(), inspected):
                temp_target = tmp_path.joinpath(*pathlib.PurePosixPath(normalized).parts)
                if member.isdir():
                    temp_target.mkdir(parents=True, exist_ok=True)
                    os.chmod(temp_target, 0o700)
                    continue
                temp_target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError(f'Cannot read archive member: {member.name}')
                with source, temp_target.open('xb') as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                os.chmod(temp_target, 0o600)

        for normalized in inspected:
            source = tmp_path.joinpath(*pathlib.PurePosixPath(normalized).parts)
            if source.is_dir():
                continue
            parts = pathlib.PurePosixPath(normalized).parts
            parent = _make_safe_parent(destination_root, parts[:-1])
            target = parent / parts[-1]
            if target.is_symlink():
                raise ValueError(f'Restore target is a symbolic link: {target}')
            existed = target.exists()
            if existed and target.stat().st_nlink > 1:
                raise ValueError(f'Restore target has multiple hard links: {target}')
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            secret_names = {'admin.json', 'sasl_passwd', 'ai.json', 'ai-provider.json'}
            if target.name == 'admin.json':
                # admin.json is read by the non-root Node process via the
                # mailstack-admin group: restoring it 0600 (the generic secret
                # treatment) locks the console out. Keep it 0640 root:group.
                mode = 0o640
            elif target.name in secret_names:
                mode = 0o600
            else:
                mode = 0o640
            descriptor = os.open(target, flags, mode)
            try:
                with os.fdopen(descriptor, 'wb', closefd=False) as output, source.open('rb') as input_file:
                    shutil.copyfileobj(input_file, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                os.fchmod(descriptor, mode)
                if target.name == 'admin.json':
                    admin_gid = _mailstack_admin_gid()
                    if admin_gid is not None and hasattr(os, 'fchown'):
                        try:
                            os.fchown(descriptor, 0, admin_gid)
                        except OSError as exc:
                            warn(f'chown restored admin.json to group mailstack-admin', exc)
                    elif grp is None:
                        warn('chown restored admin.json to group mailstack-admin',
                             RuntimeError('grp module unavailable; keeping 0640 with current ownership'))
                elif not existed and hasattr(os, 'fchown'):
                    owner = parent.stat()
                    os.fchown(descriptor, owner.st_uid, owner.st_gid)
            finally:
                os.close(descriptor)
            restored.append(str(target))
    return restored


safe_extract_tar = safe_extract_and_copy


def _metadata_path(archive):
    return archive.parent / archive.name.replace('.tar.gz', '.json')


def _backup_sources(include_mails):
    sources = [
        item for item in ('/etc/mailstack', '/etc/postfix', '/etc/dovecot', '/etc/opendkim', '/var/lib/mailstack')
        if pathlib.Path(item).exists()
    ]
    if include_mails:
        if pathlib.Path('/var/vmail').is_dir():
            sources.append('/var/vmail')
        if pwd is not None:
            for mailbox in managed_mailboxes():
                user = str(mailbox.get('unixUser', ''))
                if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user):
                    continue
                try:
                    maildir = pathlib.Path(pwd.getpwnam(user).pw_dir) / 'Maildir'
                except (KeyError, OSError):
                    continue
                if maildir.is_dir():
                    sources.append(str(maildir))
    return list(dict.fromkeys(sources))


def backup_list():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    output = []
    archives = sorted(BACKUP_DIR.glob('mailstack-backup-*.tar.gz'), key=lambda item: item.stat().st_mtime, reverse=True)
    for archive in archives[:50]:
        if archive.is_symlink() or not BACKUP_FILENAME_RE.fullmatch(archive.name):
            continue
        metadata = None
        metadata_path = _metadata_path(archive)
        if metadata_path.is_file() and not metadata_path.is_symlink():
            try:
                metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
            except (OSError, ValueError, TypeError):
                metadata = None
        if not isinstance(metadata, dict):
            metadata = {
                'name': archive.name,
                'filename': archive.name,
                'path': str(archive),
                'size': archive.stat().st_size,
                'createdAt': datetime.datetime.fromtimestamp(archive.stat().st_mtime, datetime.timezone.utc).isoformat(),
                'includeMails': False,
                'version': __version__,
                'metadataMissing': True,
            }
        output.append(metadata)
    return output


def backup_create(data=None):
    data = data or {}
    # B2 备份默认加密：公网模式（caddy/direct/high）无 passphrase 直接拒绝，
    # 在打 tar 之前 fail-closed——明文归档只允许 local 模式。门放在函数
    # 开头而非 dispatcher，保证任何调用路径（CLI/daemon/直调）都被覆盖。
    passphrase = str(data.get('passphrase') or '')
    if is_public_mode() and not passphrase:
        raise ValueError('backup.create requires a passphrase in public mode; plaintext backups are local-mode only')
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    target = BACKUP_DIR / f'mailstack-backup-{timestamp}.tar.gz'
    # Two creates inside the same second used to race onto the same name and
    # the second silently overwrote the first; a random suffix disambiguates
    # (BACKUP_FILENAME_RE already accepts the optional -<suffix> part).
    if target.exists():
        target = BACKUP_DIR / f'mailstack-backup-{timestamp}-{secrets.token_hex(2)}.tar.gz'
    metadata_path = _metadata_path(target)
    include_mails = bool(data.get('includeMails', False))
    include_secrets = bool(data.get('includeSecrets', False))
    allow_partial = bool(data.get('allowPartial', False))
    sources = _backup_sources(include_mails)
    if not sources:
        raise RuntimeError('No configuration sources were found for backup')
    command = ['tar', '-czf', str(target)]
    if not include_secrets:
        command.extend([
            '--exclude=/etc/mailstack/admin.json',
            '--exclude=/etc/mailstack/ai.json',
            '--exclude=/etc/mailstack/ai-provider.json',
            '--exclude=/etc/postfix/sasl_passwd',
            '--exclude=/etc/postfix/sasl_passwd.db',
        ])
    if allow_partial:
        command.append('--ignore-failed-read')
    command.extend(['--'] + sources)
    result = run(command, timeout=180, check=False)
    partial = result.returncode != 0
    if partial and not allow_partial:
        target.unlink(missing_ok=True)
        raise RuntimeError(f'tar backup failed with exit code {result.returncode}')
    if not target.is_file():
        raise RuntimeError('Backup archive was not created')
    os.chmod(target, 0o600)
    # Optional at-rest encryption (mandatory in public mode, enforced above).
    # The archive keeps its .tar.gz name so listing/resolution/restore stay on
    # the existing path; the on-disk bytes become a gpg symmetric ciphertext
    # and the metadata carries the flag.
    encrypted = False
    if passphrase:
        _encrypt_archive(target, passphrase)
        encrypted = True
    metadata = {
        'name': target.name,
        'filename': target.name,
        'path': str(target),
        'size': target.stat().st_size,
        'sha256': file_sha256(target),
        'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'includeMails': include_mails,
        'includeSecrets': include_secrets,
        'partial': partial,
        'encrypted': encrypted,
        'version': __version__,
    }
    atomic(metadata_path, json.dumps(metadata, indent=2) + '\n', 0o600)
    return {'created': True, 'backup': metadata}


def _resolve_archive(name):
    if pathlib.Path(name).name != name or not BACKUP_FILENAME_RE.fullmatch(name):
        raise ValueError('Backup filename must identify a local MailStack backup')
    base = BACKUP_DIR.resolve()
    target = base / name
    if target.is_symlink() or target.resolve().parent != base or not target.is_file():
        raise ValueError('Backup archive was not found in the system backup directory')
    if target.stat().st_size > MAX_BACKUP_ARCHIVE_BYTES:
        raise ValueError('Backup archive exceeds the size limit')
    return base, target


def backup_restore(data):
    name = str(data.get('filename') or data.get('name') or '').strip()
    if not name:
        raise ValueError('Backup filename is required')
    base, target = _resolve_archive(name)
    metadata_path = _metadata_path(target)
    if metadata_path.is_symlink() or metadata_path.resolve().parent != base or not metadata_path.is_file():
        raise ValueError('Matching backup metadata was not found')
    try:
        metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError('Backup metadata is invalid') from exc
    if str(metadata.get('name') or metadata.get('filename') or '') != name:
        raise ValueError('Backup metadata filename does not match the archive')
    if metadata.get('partial') and not data.get('allowPartialRestore'):
        raise ValueError('Partial backups require allowPartialRestore=true')
    expected_sha = str(metadata.get('sha256') or '').lower()
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha):
        raise ValueError('Backup metadata does not contain a valid SHA256 checksum')
    actual_sha = file_sha256(target)
    if actual_sha != expected_sha:
        raise ValueError('Backup archive SHA256 integrity verification failed')
    # Encrypted archives are detected by the metadata flag alone. A missing
    # gzip magic number on an unmarked archive means corruption, not
    # encryption: demanding a passphrase there sends operators chasing a key
    # for a file that simply lost its header.
    archive = target
    decrypted = None
    try:
        if metadata.get('encrypted'):
            passphrase = str(data.get('passphrase') or '')
            if not passphrase:
                raise ValueError('This backup is encrypted; the passphrase is required to restore it')
            _require_gpg()
            fd, tmp_name = tempfile.mkstemp(prefix='.mailstack-restore-', suffix='.tar', dir=str(base))
            os.close(fd)
            decrypted = pathlib.Path(tmp_name)
            os.chmod(decrypted, 0o600)
            try:
                run(['gpg', '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase-fd', '0',
                     '--decrypt', '-o', str(decrypted), str(target)], input=passphrase, timeout=600)
            except BaseException:
                raise ValueError('Backup decryption failed; check the passphrase and gpg installation')
            archive = decrypted
        else:
            # Not marked encrypted: a non-gzip file here is a damaged archive,
            # reported as such instead of prompting for a passphrase.
            if not _is_gzip_file(target):
                raise ValueError('Backup archive is corrupted (not a gzip archive) and cannot be restored')
        members = validate_tar_safe(archive)
        if data.get('dryRun'):
            return {
                'dryRun': True,
                'target': str(target),
                'filesCount': len(members),
                'previewFiles': members[:20],
                'ready': True,
                'sha256': actual_sha,
                'encrypted': bool(metadata.get('encrypted')),
            }
        if data.get('confirm') is not True:
            raise ValueError('Explicit confirmation is required')
        # B2: 公网模式下恢复操作必须带 passphrase——预恢复快照用它加密。
        # 明文快照留在 /var/backups 正是 doctor 的 FAIL 项，宁可拒绝恢复。
        # （加密包无口令的 fail-closed 已在上面 encrypted 分支先行拦截。）
        restore_passphrase = str(data.get('passphrase') or '')
        if is_public_mode() and not restore_passphrase:
            raise ValueError('backup.restore requires a passphrase in public mode: the pre-restore snapshot is encrypted with it')
        # Snapshot name must match BACKUP_FILENAME_RE and carry its own metadata so the
        # same strict restore path can roll back to it later. The previous
        # pre-restore-snapshot-* name was rejected by _resolve_archive, which made the
        # `ms rollback` CLI command fail unconditionally.
        snapshot = base / f"mailstack-backup-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}-pre-restore.tar.gz"
        sources = _backup_sources(False)
        snapshot_warning = None
        if sources:
            # A truncated/failed snapshot must never be registered as a
            # rollback point: check the exit code and smoke-test that the
            # archive is actually readable before writing its metadata.
            snap_result = run(['tar', '-czf', str(snapshot), '--ignore-failed-read', '--'] + sources, timeout=60, check=False)
            if snap_result.returncode != 0:
                snapshot_warning = f'pre-restore snapshot tar exited with code {snap_result.returncode}'
            elif snapshot.exists():
                try:
                    with tarfile.open(snapshot, 'r:gz') as probe:
                        probe.getmembers()
                except (OSError, tarfile.TarError, EOFError) as exc:
                    snapshot_warning = f'pre-restore snapshot failed the readability check: {exc}'
            else:
                snapshot_warning = 'pre-restore snapshot was not created'
            if snapshot_warning:
                warn('pre-restore snapshot', RuntimeError(snapshot_warning))
                snapshot.unlink(missing_ok=True)
            else:
                os.chmod(snapshot, 0o600)
                # B2: 公网模式下预恢复快照同样加密（口令沿用本次恢复的
                # passphrase）。_encrypt_archive 失败会删除明文快照并中止
                # 整个恢复——带着明文回滚点继续是 doctor 的 FAIL 状态。
                snapshot_encrypted = False
                if is_public_mode():
                    _encrypt_archive(snapshot, restore_passphrase)
                    snapshot_encrypted = True
                snapshot_meta = {
                    'name': snapshot.name,
                    'filename': snapshot.name,
                    'path': str(snapshot),
                    'size': snapshot.stat().st_size,
                    'sha256': file_sha256(snapshot),
                    'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'includeMails': False,
                    'includeSecrets': True,
                    'partial': False,
                    'encrypted': snapshot_encrypted,
                    'version': __version__,
                }
                atomic(_metadata_path(snapshot), json.dumps(snapshot_meta, indent=2) + '\n', 0o600)
        restored = safe_extract_and_copy(archive, pathlib.Path('/'))
        service_ctl('postfix', 'reload')
        service_ctl('dovecot', 'reload')
        service_ctl('opendkim', 'restart')
        return {
            'restored': True,
            'filename': name,
            'filesCount': len(restored),
            'restoredFiles': restored[:20],
            'preRestoreSnapshot': str(snapshot) if snapshot.exists() else None,
            # Snapshot failure degrades the restore (no rollback point) but
            # does not abort it; the caller must be told explicitly.
            'preRestoreSnapshotWarning': snapshot_warning,
            'sha256': actual_sha,
        }
    finally:
        if decrypted is not None:
            decrypted.unlink(missing_ok=True)


def backup_delete(data):
    if data.get('confirm') is not True:
        raise ValueError('Explicit confirmation is required')
    name = str(data.get('filename') or data.get('name') or '').strip()
    _, target = _resolve_archive(name)
    metadata_path = _metadata_path(target)
    target.unlink()
    if metadata_path.is_file() and not metadata_path.is_symlink():
        metadata_path.unlink()
    return {'deleted': True, 'filename': name}


def plaintext_backup_scan(backup_dir=None, public_mode=None):
    """B2: 扫描备份目录里的未加密归档，供 doctor FAIL check 与测试复用。

    仅在公网模式下有意义（local 模式明文备份合法）。归档是否加密依据
    同目录 metadata 的 encrypted 标志；metadata 缺失或损坏一律按未加密
    处理（fail-closed）。返回 {'publicMode': bool, 'plaintext': [文件名]}。
    """
    directory = pathlib.Path(backup_dir if backup_dir is not None else BACKUP_DIR)
    if public_mode is None:
        public_mode = is_public_mode()
    plaintext = []
    if not public_mode:
        return {'publicMode': False, 'plaintext': plaintext}
    try:
        candidates = sorted(directory.glob('mailstack-backup-*.tar.gz'))
    except OSError:
        candidates = []
    for archive in candidates:
        if archive.is_symlink() or not BACKUP_FILENAME_RE.fullmatch(archive.name):
            continue
        encrypted = False
        try:
            metadata = json.loads(_metadata_path(archive).read_text(encoding='utf-8'))
            encrypted = bool(metadata.get('encrypted'))
        except (OSError, ValueError, TypeError):
            encrypted = False
        if not encrypted:
            plaintext.append(archive.name)
    return {'publicMode': True, 'plaintext': plaintext}

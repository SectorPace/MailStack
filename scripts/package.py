import gzip
import hashlib
import os
import pathlib
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
# .workbuddy 是本地 agent 工作目录（scratch 脚本 + memory 笔记），.dockerignore 第 8 行
# 已声明其不进入分发物；此处一并排除，避免签名发布包夹带内部临时产物。
EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", ".workbuddy"}
EXCLUDED_FILES = {".DS_Store", "SHA256SUMS", "Thumbs.db", "desktop.ini"}
EXCLUDED_TOP_LEVEL_DIRS = {"release"}
SOURCE_DATE_EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "1704067200"))


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_version():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not version or any(ch.isspace() for ch in version):
        raise SystemExit("VERSION must contain one non-empty version token")
    return version


def is_build_litter(rel: pathlib.PurePosixPath) -> bool:
    """Refuse to ship the output of a mistyped shell variable.

    A command written as `... > %SystemDrive%/ProgramData/...` on a machine that
    does not expand that syntax creates a literal directory called
    `%SystemDrive%`, and rglob happily packs it. Anything with an unexpanded
    `%...%` in its name is a mistake by construction; there is no legitimate
    source file called that.
    """
    return any("%" in part for part in rel.parts)


def source_files():
    files = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if path.is_dir() or any(part in EXCLUDED_DIRS or part in EXCLUDED_TOP_LEVEL_DIRS for part in rel.parts):
            continue
        if path.name in EXCLUDED_FILES or path.suffix in {".pyc", ".map"}:
            continue
        if is_build_litter(rel):
            print(f"warning: skipping unexpanded-variable artefact {rel.as_posix()}")
            continue
        files.append((rel.as_posix(), path))
    return sorted(files)


def normalized_mode(path):
    return 0o755 if path.suffix == ".sh" or os.access(path, os.X_OK) else 0o644


def create_tar(output, archive_root, files):
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=SOURCE_DATE_EPOCH) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for rel, path in files:
                    info = tarfile.TarInfo(f"{archive_root}/{rel}")
                    info.size = path.stat().st_size
                    info.type = tarfile.REGTYPE
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = SOURCE_DATE_EPOCH
                    info.mode = normalized_mode(path)
                    with path.open("rb") as handle:
                        tar.addfile(info, handle)


def create_zip(output, archive_root, files):
    timestamp = (2024, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for rel, path in files:
            info = zipfile.ZipInfo(f"{archive_root}/{rel}", timestamp)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | normalized_mode(path)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def sign_checksum_manifest(output_dir, sums_path):
    """Opt-in ssh-keygen signature of the checksum manifest.

    Only runs when MAILSTACK_SIGNING_KEY points at a readable private key;
    otherwise the build stays in reproducible CI mode and every output file
    is byte-identical to an unsigned run. The verify invocation mirrors
    `ms upgrade` in mailstack.sh (identity `mailstack-release`, namespace
    `file`) so a signature that passes here passes on upgrading servers.
    """
    key_env = os.environ.get("MAILSTACK_SIGNING_KEY", "").strip()
    if not key_env:
        print("未配置签名私钥，跳过签名（CI 复现模式）")
        return

    key_path = pathlib.Path(key_env).expanduser()
    if not key_path.is_file() or not os.access(key_path, os.R_OK):
        raise SystemExit(
            f"MAILSTACK_SIGNING_KEY 已设置，但私钥文件不存在或不可读: {key_path}"
        )
    if shutil.which("ssh-keygen") is None:
        raise SystemExit(
            "MAILSTACK_SIGNING_KEY 已设置，但找不到 ssh-keygen（需要 OpenSSH >= 8.0），拒绝产出未签名资产"
        )
    signers = ROOT / "deploy" / "mailstack-release.allowed_signers"
    if not signers.is_file():
        raise SystemExit(f"签名自验所需的信任锚缺失: {signers}")

    sig_path = output_dir / f"{sums_path.name}.sig"
    sig_path.unlink(missing_ok=True)
    # ssh-keygen -Y sign 默认把签名写入 <输入文件>.sig（OpenSSH 默认行为）。
    # 注意：-Y sign 不接受 -I（签名体不嵌入 principal；验签端的 -I 只用于在
    # allowed_signers 中选择身份），与 RELEASE_CHECKLIST 的签名蓝本一致。
    sign_cmd = [
        "ssh-keygen", "-Y", "sign",
        "-f", str(key_path),
        "-n", "file",
        str(sums_path),
    ]
    result = subprocess.run(sign_cmd, capture_output=True, text=True)
    if result.returncode != 0 or not sig_path.is_file():
        # 只回显 stderr 文本；私钥内容永远不会进入 ssh-keygen 的错误输出。
        raise SystemExit(f"ssh-keygen 签名失败 (退出码 {result.returncode}): {result.stderr.strip()}")

    # 签名后立即自验，与 mailstack.sh 的验证命令逐字对齐；失败即非零退出。
    verify_cmd = [
        "ssh-keygen", "-Y", "verify",
        "-f", str(signers),
        "-I", "mailstack-release",
        "-n", "file",
        "-s", str(sig_path),
    ]
    with sums_path.open("rb") as manifest:
        result = subprocess.run(verify_cmd, stdin=manifest, capture_output=True, text=True)
    if result.returncode != 0 or "Good" not in result.stdout:
        raise SystemExit(
            f"签名自验失败，绝不发布 (退出码 {result.returncode}): "
            f"{(result.stderr or result.stdout).strip()}"
        )
    print(f"Created {sig_path}")
    print("签名自验通过 (identity: mailstack-release, namespace: file)")


def main():
    version = release_version()
    archive_root = os.environ.get("ARCHIVE_ROOT", f"MailStack-v{version}").strip()
    output_basename = os.environ.get("RELEASE_BASENAME", f"MailStack-v{version}").strip()
    for label, value in (("ARCHIVE_ROOT", archive_root), ("RELEASE_BASENAME", output_basename)):
        if not value or any(char in value for char in '\\/:*?"<>|'):
            raise SystemExit(f"{label} must be a valid archive basename")
    output_dir = pathlib.Path(os.environ.get("RELEASE_OUT_DIR", ROOT / "release")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    files = source_files()
    if not files:
        raise SystemExit("No source files selected for release")
    forbidden = [rel for rel, _ in files if pathlib.PurePosixPath(rel).name == "SHA256SUMS" or rel.startswith("release/")]
    if forbidden:
        raise SystemExit(f"Release inputs contain self-referential checksum/output files: {forbidden}")

    tar_output = output_dir / f"{output_basename}.tar.gz"
    zip_output = output_dir / f"{output_basename}.zip"
    with tempfile.TemporaryDirectory(dir=output_dir) as temp_dir:
        temp = pathlib.Path(temp_dir)
        temp_tar = temp / tar_output.name
        temp_zip = temp / zip_output.name
        create_tar(temp_tar, archive_root, files)
        create_zip(temp_zip, archive_root, files)
        os.replace(temp_tar, tar_output)
        os.replace(temp_zip, zip_output)

    sums = "".join(f"{sha256(path)}  {path.name}\n" for path in (tar_output, zip_output))
    (output_dir / "SHA256SUMS").write_text(sums, encoding="ascii", newline="\n")
    print(f"Created {tar_output}")
    print(f"Created {zip_output}")
    print(f"Created {output_dir / 'SHA256SUMS'}")
    sign_checksum_manifest(output_dir, output_dir / "SHA256SUMS")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
MailStack Release Version & Manifest Consistency Verifier

package.json is the single source of truth. Everything else either imports it at
build time or is checked here.

The previous version of this script compared four files while the version was
actually written out in eight places, so a release could ship with /api/health
reporting one version and the build manifest another. Two things changed:

  1. The Python modules, the admin server, the webmail server and the frontend
     defaults now derive the version instead of repeating it.
  2. This script sweeps every shipped source file for a leftover version literal,
     so adding a new hard-coded copy fails the build instead of shipping.
"""
import sys, json, re, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Files that must state the version and must agree with package.json exactly.
DECLARATION_SITES = [
    ("VERSION", lambda text: text.strip()),
    ("package-lock.json", lambda text: json.loads(text).get("version", "").strip()),
    ("backend/mailstackctl/version.py", lambda text: _py_dunder(text)),
]

# Directories swept for stray hard-coded versions. Docs are excluded on purpose:
# release notes and checklists legitimately quote older versions.
SCAN_DIRS = ["backend", "scripts", "src", "tests", "webmail", "deploy", "lib"]
SCAN_SUFFIXES = {".py", ".ts", ".tsx", ".mjs", ".js", ".sh", ".json"}
SCAN_SKIP_PARTS = {"node_modules", "dist", "release", "__pycache__", ".git"}

# Matches this product's version family. Built from fragments so that this file,
# which has to talk about stale versions, does not match its own sweep.
VERSION_RE = re.compile(r"\b0\.5\." + r"\d+(?:-[0-9A-Za-z.\-]+)?\b")

# Files allowed to mention old versions because their job is to talk about them.
SCAN_SKIP_FILES = {"verify_release_consistency.py"}


def _py_dunder(text):
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', text)
    return m.group(1).strip() if m else ""


def _canonical_version():
    pkg = ROOT / "package.json"
    if not pkg.exists():
        return None, ["package.json not found"]
    try:
        return json.loads(pkg.read_text(encoding="utf-8")).get("version", "").strip(), []
    except json.JSONDecodeError as exc:
        return None, [f"package.json is not valid JSON: {exc}"]


def _check_manifest(canonical, errors):
    manifest_file = ROOT / "dist" / "build-manifest.json"
    if not manifest_file.exists():
        print("  - dist/build-manifest.json not found (generated during build)")
        return
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"dist/build-manifest.json is not valid JSON: {exc}")
        return
    found = str(manifest.get("version", "")).strip()
    if found != canonical:
        errors.append(f"dist/build-manifest.json version ({found}) does not match package.json ({canonical})")
    else:
        print(f"  - dist/build-manifest.json matches: {found}")


def _check_changelog(canonical, errors):
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        errors.append("CHANGELOG.md not found")
        return
    if canonical in changelog.read_text(encoding="utf-8"):
        print(f"  - CHANGELOG.md contains an entry for: {canonical}")
    else:
        errors.append(f"CHANGELOG.md has no entry for {canonical}")


def _sweep(canonical, errors):
    """Flag any stale version literal left behind in shipped source."""
    offenders = []
    for directory in SCAN_DIRS:
        base = ROOT / directory
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
                continue
            if SCAN_SKIP_PARTS & set(path.parts) or path.name in SCAN_SKIP_FILES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                for match in VERSION_RE.finditer(line):
                    if match.group(0) != canonical:
                        rel = path.relative_to(ROOT).as_posix()
                        offenders.append(f"{rel}:{lineno}: found {match.group(0)}, expected {canonical}")
    if offenders:
        errors.append(
            "stale version literal(s) in shipped source -- derive the version from "
            "package.json instead of repeating it:"
        )
        errors.extend(f"    {item}" for item in offenders)
    else:
        print(f"  - no stale version literals in {', '.join(SCAN_DIRS)}")


def verify_release_consistency():
    canonical, errors = _canonical_version()
    if canonical is None:
        return False
    print(f"Canonical Project Version (package.json): v{canonical}")

    for rel, extract in DECLARATION_SITES:
        path = ROOT / rel
        if not path.exists():
            errors.append(f"{rel} not found")
            continue
        found = extract(path.read_text(encoding="utf-8")).strip()
        if found != canonical:
            errors.append(f"{rel} version ({found}) does not match package.json ({canonical})")
        else:
            print(f"  - {rel} matches: {found}")

    _check_manifest(canonical, errors)
    _check_changelog(canonical, errors)
    _sweep(canonical, errors)

    if errors:
        print("\nVersion Consistency Verification Failed:")
        for item in errors:
            print(f"  - {item}")
        return False

    print("\nAll Release Version References Are 100% Consistent!")
    return True


if __name__ == "__main__":
    sys.exit(0 if verify_release_consistency() else 1)

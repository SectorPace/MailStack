# MailStack Support Matrix

| Distribution | Versions | Tier | Installer path | Verification |
|---|---|---|---|---|
| Ubuntu | 22.04 / 24.04 LTS | Tier 1 | APT, systemd, standalone bundles | `docs/verification/real_machine_ubuntu_24_04.md` |
| Debian | 12 Bookworm | Tier 1 | APT, systemd, standalone bundles | `docs/verification/real_machine_debian_12.md` |
| RHEL / Rocky / AlmaLinux | 9.x | Tier 2 | DNF, systemd, standalone bundles | `scripts/test_distro_matrix.py` |
| openSUSE Leap / Tumbleweed | 15.x / rolling | Tier 2 | Zypper, systemd, standalone bundles | `scripts/test_distro_matrix.py` |
| Alpine Linux | 3.19+ | Experimental | APK, OpenRC | Verify manually before production use |

## Platform capability notes

- **Alpine / musl**: Node.js is normally installed from the Alpine repository (Alpine 3.20+ ships Node >= 20). The pinned-tarball fallback detects musl libc and downloads the `linux-x64-musl` variant from the Node.js official unofficial-builds channel (`unofficial-builds.nodejs.org`) with a pinned SHA256; the glibc tarballs from nodejs.org do not run on musl. No musl arm64 build is published by that channel, so musl + arm64 relies entirely on the distro package.
- **OpenDKIM is optional on dnf distributions**: the installer tries `epel-release`, then `oracle-epel-release-el<N>` (Oracle Linux uses the latter package name). If OpenDKIM cannot be installed — e.g. the openEuler 25.09 OS/everything repositories do not ship an `opendkim` package — the install degrades: DKIM signing is unavailable, mail sending/receiving still works, and the DKIM configuration/service steps are skipped. Install `opendkim` manually later and run `dkim.rotate` to enable signing.
- **Arch Linux (including older snapshots)**: the installer refreshes `archlinux-keyring` and re-populates the pacman keyring before installing packages; if signature errors persist, run `pacman -Syu archlinux-keyring` first. Older snapshots can also sit in a partially upgraded state (e.g. pacman itself links against a stale `libicuuc.so` after icu moved on); the installer detects the missing SONAMEs and restores just those library files from the local package cache or `archive.archlinux.org`, then re-registers the gcc-libs split packages, without touching the newer libraries.
- **EL9 Python ≥3.10 guarantee**: the backend uses PEP 604 union syntax, so Python ≥3.10 is a hard gate. On dnf distributions the installer tries its best to upgrade python3 first; if the interpreter still reports below 3.10 the install fails early instead of producing a stack whose privileged helper crashes on import (observed on Oracle Linux 9 defaulting to python3=3.9).
- **Alpine OpenRC bootstrap**: on containers/images without a booted init, the installer touches `/run/openrc/softlevel` (rc-service refuses to start anything without it), writes the loopback stanza into `/etc/network/interfaces` (init scripts depend on `net`), and pre-creates the service-account log files under `/var/log`.
- **fail2ban pip fallback**: when no repository package exists (e.g. openEuler 25.09 OS/everything), fail2ban is installed from the pinned GitHub 1.1.0 tarball via pip across all five package-manager branches, with the full `/etc/fail2ban` configuration tree unpacked manually because pip `data_files` deployment is unreliable there.
- **Orphan listener cleanup and init.d session detachment**: before starting services the installer kills only the processes actually listening on 8787/18788 (`fuser -k`, scoped fallback otherwise), preventing EADDRINUSE restart loops when an interrupted install is re-run; on the init.d branch the admin/webmail processes are started under `setsid` so they survive the installing session (falls back to bare start when `setsid` is unavailable).

## Tier definitions

- **Tier 1**: the release team runs the installer, health checks, mail-path tests and uninstall checks on a clean machine for every release candidate.
- **Tier 2**: the source and standalone build are tested automatically; a clean-machine installation is recommended before production deployment.
- **Experimental**: the platform is not a release blocker for the primary systemd support matrix.

A support claim is valid only for the exact release artifact and Node.js range listed in `package.json`.

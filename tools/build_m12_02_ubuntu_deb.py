#!/usr/bin/env python3
"""Build and validate the quarantined Russian-only Good Bear Ubuntu package.

This is deliberately a repackager, not a Firefox build entry point.  It accepts
only the M12-01 promoted Ubuntu input snapshot and an already produced non-LTO
Russian archive.  A failed run remains under ``quarantine`` and never replaces
a previously promoted candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
IDENTITY = json.loads((ROOT / "config/product-identity.json").read_text(encoding="utf-8"))
PACKAGE_VERSION = IDENTITY["version_pair"]["package_version"]
DEFAULT_SNAPSHOT = ROOT / "artifacts" / "m12-01-input-snapshot-ubuntu2604"
DEFAULT_ARCHIVE = (
    ROOT / "artifacts" / "development" / "m15-02-ubuntu-obj" / "dist"
    / f"goodbear-{PACKAGE_VERSION}.ru.linux-x86_64.tar.xz"
)
# Older pre-M12 Docker candidates are intentionally preserved in a root-owned
# directory.  M12 candidates use their own project-owned quarantine root so
# they cannot mutate those historical inputs.
DEFAULT_DESTINATION = ROOT / "artifacts" / "m12-02-ubuntu-candidates"
PACKAGE = "goodbear-browser"
DESKTOP_ID = "com.ledovskoy.goodbear"
VERSION = PACKAGE_VERSION + "-1"
EPOCH = "0"
REQUIRED_BROWSER_RUSSIAN_RESOURCES = (
    "localization/ru/browser/appmenu.ftl",
    "localization/ru/browser/browser.ftl",
    "localization/ru/browser/protectionsPanel.ftl",
    "localization/ru/browser/sitePermissions.ftl",
)


class PackageError(RuntimeError):
    """A package input or acceptance gate failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_snapshot(snapshot: Path) -> dict:
    """Verify the exact M12-01 promoted snapshot before reading a candidate."""
    sys.path.insert(0, str(ROOT / "tools"))
    import prepare_m12_release_build_inputs as inputs  # pylint: disable=import-outside-toplevel

    lock = inputs.load_lock(ROOT / "config" / "m12-release-build-inputs-lock.json")
    promoted = snapshot / "ubuntu-amd64"
    inputs.verify_snapshot(lock, promoted)
    manifest = json.loads((promoted / "manifest.json").read_text(encoding="utf-8"))
    require(manifest["release_locale"] == "ru", "M12 input snapshot is not Russian-only")
    require(manifest["candidate_mode"] == "non-lto" and manifest["lto"] == "forbidden",
            "M12 input snapshot does not forbid LTO")
    require(manifest["network_after_fetch"] == "network forbidden",
            "M12 input snapshot permits networking")
    return manifest


def archive_member(archive: Path, name: str) -> bytes:
    with tarfile.open(archive, "r:xz") as bundle:
        member = bundle.extractfile(name)
        require(member is not None, f"candidate archive lacks {name}")
        return member.read()


def verify_russian_archive(archive: Path) -> None:
    """Enforce the same Russian-only contract on the package input itself."""
    require(archive.is_file(), f"candidate archive does not exist: {archive}")
    with tarfile.open(archive, "r:xz") as bundle:
        names = set(bundle.getnames())
        require("goodbear/goodbear" in names and "goodbear/goodbear-bin" in names,
                "candidate archive has no Good Bear launcher")
        require("goodbear/libmozsandbox.so" in names,
                "candidate archive lacks the Mozilla sandbox helper")
        for member_name in ("goodbear/omni.ja", "goodbear/browser/omni.ja"):
            member = bundle.extractfile(member_name)
            require(member is not None, f"candidate archive lacks {member_name}")
            with zipfile.ZipFile(io.BytesIO(member.read())) as omni:
                entries = omni.namelist()
                require(not any("/localization/en-US/" in f"/{entry}" for entry in entries),
                        f"en-US localization leaked into {member_name}")
                require(any("/localization/ru/" in f"/{entry}" for entry in entries),
                        f"Russian localization missing from {member_name}")
                if member_name == "goodbear/browser/omni.ja":
                    for resource in REQUIRED_BROWSER_RUSSIAN_RESOURCES:
                        require(resource in entries and omni.read(resource),
                                f"candidate archive has missing or empty Russian Fluent resource: {resource}")
                if member_name == "goodbear/omni.ja":
                    require(omni.read("res/multilocale.txt") == b"ru\n",
                            "candidate archive has a non-Russian multilocale list")


def write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def control(depends: str) -> str:
    return f"""Package: {PACKAGE}
Version: {VERSION}
Architecture: amd64
Maintainer: Valery Ledovskoy <valery@ledovskoy.com>
Depends: {depends}
Section: web
Priority: optional
Homepage: https://github.com/Goudron/good-bear
Description: Good Bear — русскоязычный независимый браузер
 Good Bear создан Валерием Ледовским на основе открытого исходного кода Mozilla Firefox.
 Проект не является продуктом Mozilla и не связан с Mozilla.
"""


LAUNCHER = """#!/bin/sh
# Russian-only Good Bear launcher installed by the goodbear-browser package.
set -eu
export LANG=ru_RU.UTF-8
export LANGUAGE=ru:ru_RU
exec /opt/goodbear/goodbear --lang=ru "$@"
"""


DESKTOP = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=Good Bear
Name[ru]=Good Bear
Comment=Независимый русскоязычный браузер Good Bear
Exec=good-bear %u
Icon={DESKTOP_ID}
Terminal=false
StartupNotify=true
StartupWMClass=goodbear
Categories=Network;WebBrowser;
MimeType=text/html;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;
Actions=new-window;new-private-window;

[Desktop Action new-window]
Name=Новое окно
Exec=good-bear --new-window

[Desktop Action new-private-window]
Name=Новое приватное окно
Exec=good-bear --private-window
"""


MIME_XML = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">
  <mime-type type=\"text/html\"><comment xml:lang=\"ru\">документ HTML</comment></mime-type>
  <mime-type type=\"application/xhtml+xml\"><comment xml:lang=\"ru\">документ XHTML</comment></mime-type>
</mime-info>
"""


COPYRIGHT = """Good Bear
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>

Good Bear is an independent browser based on Mozilla Firefox open-source code.
Good Bear is not affiliated with, sponsored by, or endorsed by Mozilla.
Mozilla and Firefox are trademarks of the Mozilla Foundation.

Firefox-derived source files retain their applicable Mozilla and third-party
copyright notices and licenses, including MPL-2.0 where applicable.  The
corresponding Good Bear source form, ordered patches, pinned upstream revision,
and reproducible-build entry point are available at:
https://github.com/Goudron/good-bear

Original Good Bear artwork remains copyrighted by Valery Ledovskoy; all rights
reserved unless otherwise stated.  Russian PKI support does not imply any
affiliation with or endorsement by Минцифры России or other government body.
"""


POSTINST = f"""#!/bin/sh
set -eu
case "${{1:-}}" in
  configure|abort-upgrade|abort-deconfigure|abort-remove) ;;
  *) exit 0 ;;
esac
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v update-mime-database >/dev/null 2>&1 && update-mime-database /usr/share/mime || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
exit 0
"""


POSTRM = """#!/bin/sh
set -eu
case "${1:-}" in
  remove|purge|abort-install|disappear) ;;
  *) exit 0 ;;
esac
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v update-mime-database >/dev/null 2>&1 && update-mime-database /usr/share/mime || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
exit 0
"""


def extract_payload(archive: Path, stage: Path) -> None:
    """Extract the single product directory without accepting path traversal."""
    destination = stage / "opt"
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r:xz") as bundle:
        members = [member for member in bundle.getmembers() if member.name == "goodbear" or member.name.startswith("goodbear/")]
        require(members, "candidate archive has no Good Bear payload")
        for member in members:
            target = (destination / member.name).resolve()
            require(target.is_relative_to(destination.resolve()), "archive member escapes package payload")
        bundle.extractall(destination, members=members, filter="data")
    payload = destination / "goodbear"
    require(payload.is_dir(), "candidate payload extraction failed")
    for path in payload.rglob("*"):
        if path.is_file():
            path.chmod(0o755 if os.access(path, os.X_OK) else 0o644)
        elif path.is_dir():
            path.chmod(0o755)


def install_desktop_integration(stage: Path) -> None:
    write(stage / "usr" / "bin" / "good-bear", LAUNCHER, 0o755)
    write(stage / "usr" / "share" / "applications" / f"{DESKTOP_ID}.desktop", DESKTOP)
    write(stage / "usr" / "share" / "mime" / "packages" / f"{DESKTOP_ID}.xml", MIME_XML)
    write(stage / "usr" / "share" / "doc" / PACKAGE / "copyright", COPYRIGHT)
    for size in (16, 32, 48, 64, 128):
        icon = archive_member_path = stage / "opt" / "goodbear" / "browser" / "chrome" / "icons" / "default" / f"default{size}.png"
        require(icon.is_file(), f"candidate archive lacks {icon.name}")
        target = stage / "usr" / "share" / "icons" / "hicolor" / f"{size}x{size}" / "apps" / f"{DESKTOP_ID}.png"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(icon, target)
        target.chmod(0o644)
    write(stage / "DEBIAN" / "postinst", POSTINST, 0o755)
    write(stage / "DEBIAN" / "postrm", POSTRM, 0o755)


def normalize_package_modes(stage: Path) -> None:
    """Make archive permissions independent of the builder's umask."""
    stage.chmod(0o755)
    for path in stage.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file() and not os.access(path, os.X_OK):
            path.chmod(0o644)


def elf_files(stage: Path) -> list[Path]:
    files: list[Path] = []
    for path in (stage / "opt" / "goodbear").rglob("*"):
        if not path.is_file():
            continue
        with path.open("rb") as candidate:
            if candidate.read(4) == b"\x7fELF":
                files.append(path)
    require(files, "package payload has no ELF executables or libraries")
    return files


def generated_dependencies(stage: Path) -> str:
    # dpkg-shlibdeps consults debian/control even with -O.  Keep its temporary
    # input outside DEBIAN so it can never be included in the delivered .deb.
    stage = stage.resolve()
    metadata = stage / "debian"
    write(metadata / "control", "Source: goodbear-browser\n\n" + control("libc6"))
    try:
        command = ["dpkg-shlibdeps", "-O", f"-l{stage / 'opt' / 'goodbear'}",
                   *[str(path.resolve()) for path in elf_files(stage)]]
        result = subprocess.run(command, cwd=stage, text=True, capture_output=True, check=False)
        require(result.returncode == 0, f"dpkg-shlibdeps failed: {result.stderr.strip()}")
        line = next((value for value in result.stdout.splitlines() if value.startswith("shlibs:Depends=")), "")
        require(line, "dpkg-shlibdeps did not produce binary dependencies")
        depends = line.partition("=")[2]
        require(depends and "${" not in depends, "package has unresolved binary dependencies")
        return depends
    finally:
        shutil.rmtree(metadata, ignore_errors=True)


def build_deb(stage: Path, output: Path) -> None:
    depends = generated_dependencies(stage)
    write(stage / "DEBIAN" / "control", control(depends))
    environment = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH)
    result = subprocess.run(["dpkg-deb", "--root-owner-group", "--threads-max=2", "--build", str(stage), str(output)],
                            text=True, capture_output=True, env=environment, check=False)
    require(result.returncode == 0, f"dpkg-deb failed: {result.stderr.strip()}")


def control_field(deb: Path, field: str) -> str:
    return subprocess.check_output(["dpkg-deb", "-f", str(deb), field], text=True).strip()


def data_entries(deb: Path) -> list[tuple[str, int, str]]:
    output = subprocess.check_output(["dpkg-deb", "-c", str(deb)], text=True)
    entries: list[tuple[str, int, str]] = []
    for line in output.splitlines():
        match = re.match(r"^(?P<mode>\S+)\s+\S+/\S+\s+\d+\s+\S+\s+\S+\s+(?P<path>.+)$", line)
        if not match:
            continue
        mode_text = match.group("mode")
        permissions = mode_text[-9:]
        mode = 0
        bits = (0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001)
        for index, marker in enumerate(permissions):
            if marker in "rwx":
                mode |= bits[index]
            elif marker in "sS":
                mode |= 0o4000 if index == 2 else 0o2000
                if marker == "s":
                    mode |= bits[index]
            elif marker in "tT":
                mode |= 0o1000
                if marker == "t":
                    mode |= bits[index]
        entries.append((match.group("path"), mode, mode_text[0]))
    return entries


def validate_deb(deb: Path, *, temporary_root: Path | None = None) -> None:
    """Lintian-equivalent, deterministic acceptance checks with no network use."""
    require(deb.is_file(), f"package does not exist: {deb}")
    require(control_field(deb, "Package") == PACKAGE, "wrong Debian package identity")
    require(control_field(deb, "Architecture") == "amd64", "package is not amd64")
    require("official Firefox" not in control_field(deb, "Description"),
            "public package description presents the package as official Firefox")
    dependencies = control_field(deb, "Depends")
    require(dependencies, "package has no runtime dependencies")
    require("libc6 (>= 2.43)" in dependencies,
            "package does not pin the declared Ubuntu 26.04/glibc 2.43 runtime baseline")
    entries = data_entries(deb)
    names = {name.rstrip("/") for name, _, _ in entries}
    required = {
        "./opt/goodbear/goodbear", "./opt/goodbear/goodbear-bin", "./opt/goodbear/libmozsandbox.so",
        "./usr/bin/good-bear", f"./usr/share/applications/{DESKTOP_ID}.desktop",
        f"./usr/share/mime/packages/{DESKTOP_ID}.xml", f"./usr/share/doc/{PACKAGE}/copyright",
    }
    require(required <= names, f"package misses required entries: {sorted(required - names)}")
    for path, mode, kind in entries:
        require(not (mode & 0o002), f"world-writable package path: {path}")
        require(not (mode & 0o6000), f"setuid/setgid package path: {path}")
        if kind == "d":
            require(mode == 0o755, f"directory has nonstandard mode {mode:o}: {path}")
    # Package inspection must not spill into a machine-global temporary area.
    # Callers that already own a task quarantine can supply it explicitly.
    temporary_root = temporary_root or (ROOT / "artifacts" / "m12-02-ubuntu-candidates" / "quarantine")
    temporary_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="verify-", dir=temporary_root) as raw:
        root = Path(raw)
        subprocess.run(["dpkg-deb", "-x", str(deb), str(root)], check=True)
        subprocess.run(["dpkg-deb", "-e", str(deb), str(root / "DEBIAN")], check=True)
        desktop = root / "usr" / "share" / "applications" / f"{DESKTOP_ID}.desktop"
        checked = subprocess.run(["desktop-file-validate", str(desktop)], text=True, capture_output=True, check=False)
        diagnostic = (checked.stderr + checked.stdout).strip()
        require(checked.returncode == 0, f"desktop file validation failed: {diagnostic}")
        launcher = (root / "usr" / "bin" / "good-bear").read_text(encoding="utf-8")
        require("--lang=ru" in launcher and "LANGUAGE=ru:ru_RU" in launcher,
                "launcher does not force the Russian packaged locale")
        require("exec /opt/goodbear/goodbear --lang=ru \"$@\"" in launcher,
                "launcher does not target the packaged Good Bear executable")
        for omni in (root / "opt" / "goodbear" / "omni.ja", root / "opt" / "goodbear" / "browser" / "omni.ja"):
            with zipfile.ZipFile(omni) as bundle:
                files = bundle.namelist()
                require(not any("/localization/en-US/" in f"/{item}" for item in files),
                        f"English localization leaked into package {omni}")
                require(any("/localization/ru/" in f"/{item}" for item in files),
                        f"Russian localization missing from package {omni}")
        copyright_text = (root / "usr" / "share" / "doc" / PACKAGE / "copyright").read_text(encoding="utf-8")
        require("not affiliated" in copyright_text and "Минцифры" in copyright_text,
                "required non-affiliation notices are missing")


def assemble(snapshot: Path, archive: Path, destination: Path) -> Path:
    manifest = checked_snapshot(snapshot)
    verify_russian_archive(archive)
    destination.mkdir(parents=True, exist_ok=True)
    final = destination / f"{PACKAGE}_{VERSION}_amd64.deb"
    require(not final.exists(), f"refusing to replace promoted candidate: {final}")
    quarantine = destination / "quarantine"
    quarantine.mkdir(exist_ok=True)
    staging = quarantine / uuid.uuid4().hex
    stage = staging / "root"
    output = staging / final.name
    try:
        staging.mkdir()
        print("[M12-02 1/5] Validating M12-01 non-LTO Russian input snapshot", flush=True)
        print(f"  snapshot: {snapshot / 'ubuntu-amd64'}; archive sha256: {sha256(archive)}", flush=True)
        print("[M12-02 2/5] Extracting validated Russian Good Bear payload", flush=True)
        extract_payload(archive, stage)
        print("[M12-02 3/5] Adding launcher, desktop/MIME integration, icons, notices, and scripts", flush=True)
        install_desktop_integration(stage)
        normalize_package_modes(stage)
        print("[M12-02 4/5] Computing runtime dependencies and building Debian archive", flush=True)
        build_deb(stage, output)
        print("[M12-02 5/5] Running package ownership, locale, identity, and desktop lint gates", flush=True)
        validate_deb(output)
        evidence = {
            "schema_version": 1,
            "task": "GB100-M12-02",
            "input_snapshot": str((snapshot / "ubuntu-amd64").relative_to(ROOT)),
            "input_manifest": manifest,
            "archive": str(archive.relative_to(ROOT)),
            "archive_sha256": sha256(archive),
            "package": output.name,
            "package_sha256": sha256(output),
            "locale": "ru",
            "lto": "forbidden",
            "network_after_fetch": "forbidden",
        }
        write(staging / "evidence.json", json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        os.replace(output, final)
        os.replace(staging / "evidence.json", destination / f"{final.name}.evidence.json")
        shutil.rmtree(staging / "root")
        staging.rmdir()
        print(f"M12-02 candidate promoted: {final}", flush=True)
        return final
    except BaseException:
        print(f"M12-02 candidate retained in quarantine: {staging}", flush=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("package", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        if args.action == "build":
            assemble(args.snapshot, args.archive, args.destination)
        else:
            require(args.package is not None, "verify requires a .deb path")
            validate_deb(args.package)
            print(f"M12-02 Ubuntu package verified: {args.package}", flush=True)
    except (PackageError, OSError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Package the frozen GB100-M13-06 Russian LTO archive as an Ubuntu 24.04 .deb.

This deliberately packages an already-built archive.  It never invokes mach,
does not compile a replacement browser, and records the exact source manifest
that produced the archive.  The older M12 packager is intentionally unsuitable:
it describes a Firefox 154 non-LTO / Ubuntu 26.04 historical candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid
import zipfile


ROOT = Path(os.environ.get("GOODBEAR_ROOT", Path(__file__).resolve().parents[1])).resolve()
IDENTITY = json.loads((ROOT / "config/product-identity.json").read_text(encoding="utf-8"))
PACKAGE = "goodbear-browser"
VERSION = IDENTITY["version_pair"]["package_version"] + "-1"
EXPECTED_ARCHIVE = (
    f"goodbear-{IDENTITY['version_pair']['package_version']}.ru.linux-x86_64.tar.xz"
)


class PackageError(RuntimeError):
    """The M13 LTO package cannot be promoted."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageError(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def load_m12() -> object:
    spec = importlib.util.spec_from_file_location("goodbear_m12_deb", ROOT / "tools/build_m12_02_ubuntu_deb.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_manifest(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "source manifest must be a JSON object")
    require(value.get("schema_version") == 1, "unsupported source manifest schema")
    require(value.get("task") == "GB100-M15-01", "source manifest is not an M15 source snapshot")
    baseline = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
    version = baseline.get("version")
    require(IDENTITY["version_pair"]["firefox_base_version"] == version and
            IDENTITY["version_pair"]["package_version"] == f"1.0+firefox{version}",
            "package identity does not match the pinned Firefox baseline")
    require(value.get("upstream") == {
        "product": baseline.get("product"), "version": version,
        "revision": baseline.get("vcs", {}).get("revision"),
        "archive": baseline.get("source", {}).get("archive_path"),
        "archive_sha256": baseline.get("source", {}).get("sha256"),
    }, "source manifest does not match the pinned Firefox baseline")
    return value


def validate_archive(module: object, archive: Path) -> None:
    require(archive.is_file() and archive.name == EXPECTED_ARCHIVE,
            f"expected frozen Russian LTO archive {EXPECTED_ARCHIVE}")
    module.verify_russian_archive(archive)


def validate_deb(module: object, deb: Path) -> None:
    require(module.control_field(deb, "Package") == PACKAGE, "wrong Debian package identity")
    require(module.control_field(deb, "Version") == VERSION, "wrong Debian package version")
    require(module.control_field(deb, "Architecture") == "amd64", "package is not amd64")
    require(module.control_field(deb, "Depends"), "package has no runtime dependencies")
    entries = {path.rstrip("/") for path, _, _ in module.data_entries(deb)}
    required = {
        "./opt/goodbear/goodbear", "./opt/goodbear/goodbear-bin",
        "./opt/goodbear/libmozsandbox.so", "./usr/bin/good-bear",
        "./usr/share/applications/com.ledovskoy.goodbear.desktop",
        "./usr/share/doc/goodbear-browser/copyright",
    }
    require(required <= entries, f"package misses required entries: {sorted(required - entries)}")
    with tempfile.TemporaryDirectory(prefix="m13-06-verify-") as raw:
        unpacked = Path(raw)
        subprocess.run(["dpkg-deb", "-x", str(deb), str(unpacked)], check=True)
        launcher = (unpacked / "usr/bin/good-bear").read_text(encoding="utf-8")
        require("--lang=ru" in launcher, "launcher does not force Russian locale")
        for name in ("omni.ja", "browser/omni.ja"):
            with zipfile.ZipFile(unpacked / "opt/goodbear" / name) as bundle:
                entries = bundle.namelist()
                require(any("/localization/ru/" in f"/{entry}" for entry in entries),
                        f"Russian localization missing from {name}")
                require(not any("/localization/en-US/" in f"/{entry}" for entry in entries),
                        f"en-US localization leaked into {name}")
                if name == "browser/omni.ja":
                    for resource in module.REQUIRED_BROWSER_RUSSIAN_RESOURCES:
                        require(resource in entries and bundle.read(resource),
                                f"Debian package has missing or empty Russian Fluent resource: {resource}")


def assemble(archive: Path, source_manifest: Path, destination: Path) -> Path:
    module = load_m12()
    validate_archive(module, archive)
    manifest = load_manifest(source_manifest)
    destination.mkdir(parents=True, exist_ok=True)
    final = destination / f"{PACKAGE}_{VERSION}_amd64.deb"
    require(not final.exists(), f"refusing to replace candidate: {final}")
    quarantine = destination / "quarantine"
    quarantine.mkdir(exist_ok=True)
    staging = quarantine / uuid.uuid4().hex
    stage = staging / "root"
    output = staging / final.name
    try:
        staging.mkdir()
        module.extract_payload(archive, stage)
        module.install_desktop_integration(stage)
        module.normalize_package_modes(stage)
        module.build_deb(stage, output)
        validate_deb(module, output)
        evidence = {
            "schema_version": 1,
            "task": "GB100-M13-06",
            "candidate_status": "unsigned candidate; public release not implied",
            "platform": "ubuntu-amd64",
            "ubuntu_target": "24.04.4 LTS",
            "lto": "full",
            "locale": "ru",
            "version_pair": IDENTITY["version_pair"],
            "archive": archive.name,
            "archive_sha256": digest(archive),
            "source_manifest": source_manifest.name,
            "source_manifest_sha256": digest(source_manifest),
            "source_manifest_schema": manifest["schema_version"],
            "package": output.name,
            "package_sha256": digest(output),
        }
        (staging / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(output, final)
        os.replace(staging / "evidence.json", destination / f"{final.name}.evidence.json")
        shutil.rmtree(stage)
        staging.rmdir()
        return final
    except BaseException:
        print(f"M13-06 package retained in quarantine: {staging}", file=sys.stderr)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("source_manifest", type=Path)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        package = assemble(args.archive.resolve(), args.source_manifest.resolve(), args.destination.resolve())
        print(f"M13-06 Ubuntu LTO package promoted: {package}")
    except (PackageError, OSError, subprocess.CalledProcessError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

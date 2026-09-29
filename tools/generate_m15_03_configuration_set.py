#!/usr/bin/env python3
"""Assemble the fail-closed GB100-M15-03 Windows configuration-set ISO.

The Microsoft installation ISO is never remastered.  This tool creates one
separate, immutable configuration-set ISO containing only ``Autounattend.xml``
and ``$OEM$`` payloads.  Initial KVM installation uses a SATA disk.  VirtIO
media is intentionally not copied to this ISO and no driver is loaded by
Windows Setup: the post-boot Windows signature/membership gate controls it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

import generate_m15_03_autounattend as AUTO


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "config" / "m15-03-windows-autounattend-lock.json"
ISO_NAME = "goodbear-m15-03-configuration-set.iso"
VOLUME_LABEL = "GB_M15_03_CFG"


class ConfigurationSetError(ValueError):
    """The configuration medium cannot be safely generated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigurationSetError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_regular_pinned(path: Path, expected_sha256: str, name: str) -> None:
    require(path.is_file() and not path.is_symlink(), f"{name} is absent or not a regular file")
    require(sha256_file(path) == expected_sha256, f"{name} SHA-256 mismatch")


def require_iso_builder() -> str:
    executable = shutil.which("xorriso")
    require(executable is not None, "xorriso is required to create a configuration-set ISO")
    return executable


def validate_output(destination: Path) -> Path:
    target = destination.resolve()
    build = (ROOT / "build").resolve()
    try:
        target.relative_to(build)
    except ValueError as exc:
        raise ConfigurationSetError("output directory must be under build/") from exc
    require(target.name.startswith("m15-03-configuration-set-") and not target.exists(),
            "output must be a new build/m15-03-configuration-set-* directory")
    return target


def setup_complete_command() -> str:
    """Return SetupComplete.cmd, which only starts the staged SYSTEM bootstrap."""
    return r'''@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "GB_BOOTSTRAP=C:\GoodBear\first-boot.ps1"
if not exist "%GB_BOOTSTRAP%" exit /b 70
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%GB_BOOTSTRAP%"
set "GB_EXIT=%ERRORLEVEL%"
exit /b %GB_EXIT%
'''


def manifest_for(root: Path, paths: list[Path]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for path in sorted(paths, key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        records.append({"path": "/" + relative, "sha256": sha256_file(path), "size": path.stat().st_size})
    return {
        "schema_version": 1,
        "task": "GB100-M15-03",
        "format": "windows-configuration-set",
        "volume_label": VOLUME_LABEL,
        "files": records,
        "virtio": {
            "included": False,
            "reason": "post_boot_windows_signtool_kp_gate_required_before_dism_or_sysprep",
        },
        "sensitive_material_absent": True,
    }


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def stage_payload(lock: dict[str, Any], payload: Path) -> tuple[dict[str, Any], list[Path]]:
    """Stage only validated, declared configuration-set payloads."""
    xml, bootstrap, provenance, signature_gate = AUTO.render(lock)
    cloudbase = lock["inputs"]["cloudbase_init"]
    source = Path(cloudbase["path"])
    require_regular_pinned(source, cloudbase["sha256"], "Cloudbase-Init input")

    answer = payload / "Autounattend.xml"
    goodbear = payload / "$OEM$" / "$1" / "GoodBear"
    setup_complete = payload / "$OEM$" / "$$" / "Setup" / "Scripts" / "SetupComplete.cmd"
    write_text(answer, xml)
    write_text(goodbear / "first-boot.ps1", bootstrap)
    write_text(goodbear / "verify-virtio-signatures.ps1", signature_gate)
    write_text(goodbear / "provenance.json", json.dumps(provenance, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    input_cache = goodbear / "input-cache"
    input_cache.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, input_cache / source.name)
    write_text(setup_complete, setup_complete_command())

    payload_files = [path for path in payload.rglob("*") if path.is_file() and not path.is_symlink()]
    manifest = manifest_for(payload, payload_files)
    manifest_path = goodbear / "config-set-manifest.json"
    write_text(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return manifest, payload_files + [manifest_path]


def verify_iso_tree(xorriso: str, iso: Path) -> None:
    result = subprocess.run(
        [xorriso, "-indev", str(iso), "-find", "/", "-type", "f", "-exec", "lsdl"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    require(result.returncode == 0, "xorriso could not inspect the generated configuration-set ISO")
    required = (
        "/Autounattend.xml",
        "/$OEM$/$1/GoodBear/first-boot.ps1",
        "/$OEM$/$1/GoodBear/verify-virtio-signatures.ps1",
        "/$OEM$/$1/GoodBear/input-cache/",
        "/$OEM$/$$/Setup/Scripts/SetupComplete.cmd",
    )
    rendered = result.stdout + result.stderr
    for expected in required:
        require(expected in rendered, f"generated configuration-set ISO is missing {expected}")


def assemble(lock: dict[str, Any], destination: Path) -> Path:
    """Build and atomically publish a new configuration-set directory."""
    target = validate_output(destination)
    xorriso = require_iso_builder()
    # stage_payload validates exact ISO and Cloudbase bytes, but deliberately
    # does not allow an unverified VirtIO download to become an answer-file input.
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".m15-03-configuration-set-", dir=target.parent))
    try:
        payload = staging / "payload"
        manifest, _ = stage_payload(lock, payload)
        iso = staging / ISO_NAME
        result = subprocess.run(
            [xorriso, "-as", "mkisofs", "-iso-level", "3", "-J", "-joliet-long", "-r",
             "-V", VOLUME_LABEL, "-o", str(iso), str(payload)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        require(result.returncode == 0 and iso.is_file() and not iso.is_symlink(),
                "xorriso failed to create the configuration-set ISO")
        verify_iso_tree(xorriso, iso)
        assembly = {
            "schema_version": 1,
            "task": "GB100-M15-03",
            "format": "windows-configuration-set",
            "iso": {"path": ISO_NAME, "sha256": sha256_file(iso), "size": iso.stat().st_size},
            "payload_manifest_sha256": sha256_file(payload / "$OEM$" / "$1" / "GoodBear" / "config-set-manifest.json"),
            "payload_file_count": len(manifest["files"]),
            "windows_iso_remastered": False,
            "virtio_promoted": False,
            "sensitive_material_absent": True,
        }
        (staging / "assembly.json").write_text(
            json.dumps(assembly, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        shutil.rmtree(payload)
        os.replace(staging, target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed M15-03 Windows configuration-set ISO assembler")
    parser.add_argument("action", choices=("validate", "assemble"))
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        lock = AUTO.load_lock(args.lock)
        if args.action == "validate":
            require_iso_builder()
            AUTO.validate_lock(lock)
            print("M15-03 configuration-set inputs validated; no artifact generated", flush=True)
        else:
            require(args.output is not None, "assemble requires --output")
            print(f"M15-03 configuration-set assembled: {assemble(lock, args.output)}", flush=True)
        return 0
    except (AUTO.AutounattendError, ConfigurationSetError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

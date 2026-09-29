#!/usr/bin/env python3
"""Fail-closed, secret-free M15-03 Server Core autounattend generator.

No VM, ISO mount, download, Cloud call, password, credential or private key is
involved.  A new output directory is atomically created only after every
non-secret external input path and SHA-256 pin validates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Any
from xml.sax.saxutils import escape

import generate_m15_03_windows_signature_gate as SIGNATURE_GATE
import generate_m15_03_windows_bootstrap as WINDOWS_BOOTSTRAP


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "config" / "m15-03-windows-autounattend-lock.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SECRET_KEY = re.compile(r"(?:password|secret|credential|token|private.?key|key_id)", re.IGNORECASE)
SECRET_VALUE = re.compile(r"-----BEGIN(?: [A-Z0-9 ]+)? PRIVATE KEY-----|authorization\s*:\s*bearer|gh[pousr]_[A-Za-z0-9]{20,}", re.IGNORECASE)


class AutounattendError(ValueError):
    """Inputs are not safe enough to produce a Windows answer-file artifact."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AutounattendError(message)


def load_lock(path: Path = DEFAULT_LOCK) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AutounattendError("cannot read M15-03 autounattend lock") from exc
    require(isinstance(value, dict), "autounattend lock must be a JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def reject_secrets(value: object, trail: str = "lock") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str) and SECRET_KEY.search(key) is None,
                    f"secret-like field is forbidden: {trail}")
            reject_secrets(item, f"{trail}.{key}")
    elif isinstance(value, list):
        for number, item in enumerate(value):
            reject_secrets(item, f"{trail}[{number}]")
    elif isinstance(value, str):
        require(SECRET_VALUE.search(value) is None, f"secret-like value is forbidden: {trail}")


def validate_lock(lock: dict[str, Any], verify_files: bool = True) -> None:
    reject_secrets(lock)
    require(lock.get("schema_version") == 1 and lock.get("task") == "GB100-M15-03", "wrong M15-03 lock")
    require(isinstance(lock.get("output_version"), str) and lock["output_version"], "missing output version")
    windows = lock.get("windows")
    require(isinstance(windows, dict) and windows == {
        "architecture": "x64", "edition": "Server Core", "gui": False, "locale": "ru-RU",
        "image_name": "Windows Server 2025 Standard Evaluation",
    }, "answer file must pin Russian Windows Server 2025 Evaluation Server Core without GUI")
    headless = lock.get("headless")
    require(headless == {"transport": "openssh", "cloudbase_init_first_boot": True,
                         "windows_update_before_sysprep": True},
            "headless OpenSSH/Cloudbase/Windows Update sequencing drifted")
    privacy = lock.get("privacy")
    require(privacy == {"ceip_enabled": 0, "diagnostic_data": "required_only"},
            "answer file must pin required-only diagnostic data and opt out of CEIP")
    virtio = lock.get("virtio")
    require(virtio == {"architecture_path": "amd64", "scsi_driver": "vioscsi",
                       "network_driver": "NetKVM"}, "VirtIO SCSI/network driver contract drifted")
    require(lock.get("sysprep", {}).get("arguments") == ["/oobe", "/generalize", "/shutdown"],
            "sysprep must remain OOBE/generalize/shutdown")
    inputs = lock.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) == {"windows_server_2025_eval_iso", "virtio_win", "cloudbase_init"},
            "input lock must contain ISO, VirtIO and Cloudbase-Init only")
    for name, key, verified in (("windows_server_2025_eval_iso", "sha256", None),
                                ("cloudbase_init", "sha256", "authenticode_verified")):
        entry = inputs[name]
        require(isinstance(entry, dict) and isinstance(entry.get("path"), str) and entry["path"],
                f"{name} requires an existing pinned path")
        require(isinstance(entry.get(key), str) and SHA256.fullmatch(entry[key]) is not None,
                f"{name} requires a SHA-256 pin")
        if verified:
            require(entry.get(verified) is True, f"{name} signature verification is required")
        if verify_files:
            source = Path(entry["path"])
            require(source.is_file() and not source.is_symlink(), f"{name} input path is absent or not a regular file")
            require(sha256_file(source) == entry[key], f"{name} input SHA-256 mismatch")
    # VirtIO is deliberately *not* an installation input.  The initial local
    # disk is SATA.  Driver media is mounted read-only only after Windows
    # starts, and its exact Server 2025 bundles must pass signtool /kp catalog
    # membership before DISM or Sysprep.  Do not let a transport download be
    # promoted merely because an answer file was generated.
    virtio_input = inputs["virtio_win"]
    require(virtio_input == {
        "path": None,
        "sha256": None,
        "signature_verified": False,
        "media_volume_label": "virtio-win-0.1.302",
    }, "VirtIO must remain an untrusted post-boot, signature-gated input")
    cloudbase = inputs["cloudbase_init"]
    require(isinstance(cloudbase.get("publisher"), str) and cloudbase["publisher"],
            "Cloudbase-Init Authenticode publisher is required")


def render(lock: dict[str, Any]) -> tuple[str, str, dict[str, Any], str]:
    validate_lock(lock)
    windows = lock["windows"]
    virtio = lock["virtio"]
    virtio_input = lock["inputs"]["virtio_win"]
    cloudbase = lock["inputs"]["cloudbase_init"]
    signature_gate = SIGNATURE_GATE.render_gate()
    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>{escape(windows["locale"])}</UILanguage></SetupUILanguage>
      <InputLocale>{escape(windows["locale"])}</InputLocale><SystemLocale>{escape(windows["locale"])}</SystemLocale><UILanguage>{escape(windows["locale"])}</UILanguage><UserLocale>{escape(windows["locale"])}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UseConfigurationSet>true</UseConfigurationSet>
      <DiskConfiguration><WillShowUI>OnError</WillShowUI><Disk wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk><CreatePartitions><CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition><CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition><CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition></CreatePartitions><ModifyPartitions><ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition><ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition></ModifyPartitions></Disk></DiskConfiguration>
      <ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Key>/IMAGE/NAME</Key><Value>{escape(windows["image_name"])}</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI></OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <!-- This is deliberately explicit: Server Core must not pause the
         reproducible image flow to ask an interactive telemetry question. -->
    <component name="Microsoft-Windows-SQMAPI" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <CEIPEnabled>{lock["privacy"]["ceip_enabled"]}</CEIPEnabled>
    </component>
  </settings>
</unattend>
'''
    bootstrap = WINDOWS_BOOTSTRAP.render_bootstrap(
        virtio_input["media_volume_label"], Path(cloudbase["path"]).name,
        cloudbase["sha256"], cloudbase["publisher"]
    )
    provenance = {
        "schema_version": 1, "task": "GB100-M15-03", "output_version": lock["output_version"],
        "inputs": {name: {"path": value["path"], "sha256": value["sha256"]}
                   for name, value in lock["inputs"].items()},
        "windows": windows, "headless": lock["headless"], "virtio": virtio,
        "windows_signature_gate": {
            "required_before_sysprep": True,
            "evidence_fields": ["path", "sha256", "result"],
            "host_catalog_check_not_accepted": True,
            "explicit_signtool_path_required": True,
            "resumable_system_state_machine_required": True,
            "windows_update_before_signing_tools": True,
            "windows_sdk_auto_removal": "forbidden_pending_build-toolchain-dependency-decision",
            "virtio_media_discovery": {
                "required_volume_label": virtio_input["media_volume_label"],
                "fixed_drive_letter_forbidden": True,
                "post_boot_only": True,
            },
        },
        "sensitive_material_absent": True,
    }
    reject_secrets(xml); reject_secrets(bootstrap); reject_secrets(signature_gate); reject_secrets(provenance)
    return xml, bootstrap, provenance, signature_gate


def validate_output(path: Path) -> Path:
    target = path.resolve()
    build = (ROOT / "build").resolve()
    try:
        target.relative_to(build)
    except ValueError as exc:
        raise AutounattendError("output directory must be under build/") from exc
    require(target.name.startswith("m15-03-autounattend-") and not target.exists(),
            "output must be a new build/m15-03-autounattend-* directory")
    return target


def generate(lock: dict[str, Any], destination: Path) -> Path:
    destination = validate_output(destination)
    xml, bootstrap, provenance, signature_gate = render(lock)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".m15-03-autounattend-", dir=destination.parent))
    try:
        (staging / "autounattend.xml").write_text(xml, encoding="utf-8")
        (staging / "first-boot.ps1").write_text(bootstrap, encoding="utf-8")
        (staging / "verify-virtio-signatures.ps1").write_text(signature_gate, encoding="utf-8")
        (staging / "provenance.json").write_text(json.dumps(provenance, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(staging, destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed M15-03 Server Core autounattend generator")
    parser.add_argument("action", choices=("validate", "generate"))
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        lock = load_lock(args.lock)
        if args.action == "validate":
            validate_lock(lock)
            print("M15-03 autounattend inputs validated; no artifact generated", flush=True)
        else:
            require(args.output is not None, "generate requires --output")
            print(f"M15-03 autounattend generated: {generate(lock, args.output)}", flush=True)
        return 0
    except AutounattendError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

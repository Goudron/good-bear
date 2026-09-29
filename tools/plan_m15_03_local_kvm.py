#!/usr/bin/env python3
"""Validate and render, but never create, the M15-03 local KVM VM plan.

This is deliberately a *preflight-only* tool.  It never invokes ``virsh
define``, ``virt-install``, QEMU, ``qemu-img``, a network service, or sudo.  A
successful result is reviewable domain XML plus a storage budget; it is not a
VM, disk, NVRAM copy, or permission change.  A future, separately approved
creation step must consume the rendered plan and repeat every input check.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any
from xml.sax.saxutils import escape

import generate_m15_03_autounattend as AUTO
import generate_m15_03_configuration_set as CONFIG_SET


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "config" / "m15-03-windows-autounattend-lock.json"
DEFAULT_CONTRACT = ROOT / "config" / "m15-03-local-kvm-contract.json"
GIB = 1024 ** 3
PLAN_NAME = "m15-03-local-kvm-plan.json"
DOMAIN_NAME = "m15-03-local-kvm-domain.xml"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class KvmPlanError(ValueError):
    """The local KVM preflight cannot safely render a plan."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KvmPlanError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_regular(path: Path, name: str) -> Path:
    require(path.is_file() and not path.is_symlink(), f"{name} must be an existing regular non-symlink file")
    return path.resolve()


def load_json(path: Path, name: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KvmPlanError(f"cannot read {name}") from exc
    require(isinstance(value, dict), f"{name} must be a JSON object")
    return value


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    contract = load_json(path, "local KVM contract")
    AUTO.reject_secrets(contract, "local_kvm_contract")
    expected = {
        "schema_version": 1,
        "task": "GB100-M15-03",
        "purpose": "local-headless-windows-image-preparation-preflight-only",
        "vm": {
            "name": "goodbear-m15-03-windows-server-2025-prep",
            "vcpus": 2,
            "memory_mib": 2560,
            "graphics": False,
            "serial_console": True,
        },
        "firmware": {
            "uefi": True,
            "secure_boot": True,
            "code_candidates": ["/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"],
            "vars_template_candidates": ["/usr/share/OVMF/OVMF_VARS_4M.ms.fd"],
        },
        "disk": {
            "format": "raw",
            "bus": "sata",
            "logical_size_gib": 250,
            "initial_allocation_reservation_gib": 64,
            "minimum_free_headroom_gib": 16,
        },
        "media": {
            "windows_installation_bus": "sata",
            "configuration_set_bus": "sata",
            "virtio_bus": "sata",
            "virtio_read_only": True,
            "virtio_windowspe_load": False,
        },
        "network": {
            "type": "network",
            "source": "default",
            "model": "e1000e",
            "virtio_network_before_signature_gate": False,
        },
        "lifecycle": {
            "libvirt_define": False,
            "libvirt_start": False,
            "disk_create": False,
            "nvram_copy": False,
            "vm_create": False,
        },
    }
    require(contract == expected, "local KVM contract drifted; review and explicitly update the preflight implementation")
    return contract


def select_regular_candidate(candidates: list[str], name: str) -> Path:
    for value in candidates:
        candidate = Path(value)
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.resolve()
    raise KvmPlanError(f"no regular {name} candidate is available")


def validate_output_directory(path: Path) -> Path:
    require(path.is_absolute(), "--vm-output-dir must be an explicit absolute directory")
    require(path.is_dir() and not path.is_symlink(), "--vm-output-dir must be an existing non-symlink directory")
    return path.resolve()


def validate_windows_iso(lock: dict[str, Any]) -> Path:
    AUTO.validate_lock(lock, verify_files=False)
    entry = lock["inputs"]["windows_server_2025_eval_iso"]
    source = require_regular(Path(entry["path"]), "pinned Windows installation ISO")
    require(sha256_file(source) == entry["sha256"], "pinned Windows installation ISO SHA-256 mismatch")
    return source


def validate_configuration_set(iso_path: Path) -> tuple[Path, dict[str, Any]]:
    iso = require_regular(iso_path, "configuration-set ISO")
    require(iso.name == CONFIG_SET.ISO_NAME, "configuration-set ISO must retain its declared filename")
    assembly_path = iso.parent / "assembly.json"
    require(assembly_path.is_file() and not assembly_path.is_symlink(), "configuration-set assembly.json is required beside the ISO")
    assembly = load_json(assembly_path, "configuration-set assembly record")
    record = assembly.get("iso")
    require(isinstance(record, dict), "configuration-set assembly record lacks ISO data")
    require(record.get("path") == CONFIG_SET.ISO_NAME and isinstance(record.get("sha256"), str)
            and SHA256.fullmatch(record["sha256"]) is not None, "configuration-set assembly ISO record drifted")
    require(record.get("sha256") == sha256_file(iso), "configuration-set ISO SHA-256 mismatch")
    require(assembly.get("windows_iso_remastered") is False, "remastered Windows installation media is forbidden")
    require(assembly.get("virtio_promoted") is False, "VirtIO must not be promoted into the configuration-set")
    require(assembly.get("sensitive_material_absent") is True, "configuration-set must declare sensitive material absent")
    return iso, assembly


def validate_untrusted_virtio(iso_path: Path) -> Path:
    """Only ensure a read-only attachment target exists; do not promote it."""
    iso = require_regular(iso_path, "untrusted VirtIO ISO")
    require(iso.stat().st_size > 0, "untrusted VirtIO ISO must not be empty")
    return iso


def storage_budget(output_dir: Path, contract: dict[str, Any]) -> dict[str, int | bool]:
    disk = contract["disk"]
    logical = disk["logical_size_gib"] * GIB
    reservation = disk["initial_allocation_reservation_gib"] * GIB
    headroom = disk["minimum_free_headroom_gib"] * GIB
    stat = os.statvfs(output_dir)
    available = stat.f_bavail * stat.f_frsize
    required = reservation + headroom
    require(available >= required,
            "output filesystem has insufficient free space for the initial sparse-disk allocation reservation plus headroom")
    return {
        "logical_raw_disk_bytes": logical,
        "planned_initial_allocated_bytes": 0,
        "initial_allocation_reservation_bytes": reservation,
        "minimum_free_headroom_bytes": headroom,
        "available_bytes_before_creation": available,
        "available_bytes_after_reservation": available - reservation,
        "safe_without_full_preallocation": True,
    }


def disk_paths(output_dir: Path, contract: dict[str, Any]) -> tuple[Path, Path]:
    stem = contract["vm"]["name"]
    raw = output_dir / f"{stem}.raw"
    nvram = output_dir / f"{stem}.nvram.fd"
    require(not raw.exists() and not raw.is_symlink(), "refusing a plan that could reuse or overwrite an existing raw disk")
    require(not nvram.exists() and not nvram.is_symlink(), "refusing a plan that could reuse or overwrite existing NVRAM")
    return raw, nvram


def render_domain_xml(contract: dict[str, Any], *, windows_iso: Path, configuration_set: Path,
                      virtio_iso: Path, raw_disk: Path, nvram: Path, firmware_code: Path,
                      firmware_vars: Path) -> str:
    """Render a domain definition for review only; callers must not define it."""
    vm = contract["vm"]
    return f'''<domain type="kvm">
  <name>{escape(vm["name"])}</name>
  <memory unit="MiB">{vm["memory_mib"]}</memory>
  <currentMemory unit="MiB">{vm["memory_mib"]}</currentMemory>
  <vcpu placement="static">{vm["vcpus"]}</vcpu>
  <os>
    <type arch="x86_64" machine="q35">hvm</type>
    <loader readonly="yes" secure="yes" type="pflash">{escape(str(firmware_code))}</loader>
    <nvram template="{escape(str(firmware_vars))}">{escape(str(nvram))}</nvram>
    <boot dev="cdrom"/>
    <boot dev="hd"/>
  </os>
  <features><acpi/><apic/></features>
  <cpu mode="host-passthrough" check="none"/>
  <devices>
    <emulator>{escape(shutil.which("qemu-system-x86_64") or "/usr/bin/qemu-system-x86_64")}</emulator>
    <controller type="sata" index="0"/>
    <disk type="file" device="disk"><driver name="qemu" type="raw" cache="none" io="native"/><source file="{escape(str(raw_disk))}"/><target dev="sda" bus="sata"/></disk>
    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{escape(str(windows_iso))}"/><target dev="sdb" bus="sata"/><readonly/></disk>
    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{escape(str(configuration_set))}"/><target dev="sdc" bus="sata"/><readonly/></disk>
    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{escape(str(virtio_iso))}"/><target dev="sdd" bus="sata"/><readonly/></disk>
    <interface type="network"><source network="default"/><model type="e1000e"/></interface>
    <serial type="pty"><target port="0"/></serial>
    <console type="pty"><target type="serial" port="0"/></console>
    <!-- Deliberately no graphical device: libvirt's supported headless form. -->
  </devices>
</domain>
'''


def make_plan(lock: dict[str, Any], contract: dict[str, Any], *, vm_output_dir: Path,
              configuration_set: Path, virtio_iso: Path) -> tuple[dict[str, Any], str]:
    output = validate_output_directory(vm_output_dir)
    windows = validate_windows_iso(lock)
    config_iso, assembly = validate_configuration_set(configuration_set)
    virtio = validate_untrusted_virtio(virtio_iso)
    firmware_code = select_regular_candidate(contract["firmware"]["code_candidates"], "UEFI code")
    firmware_vars = select_regular_candidate(contract["firmware"]["vars_template_candidates"], "UEFI variable template")
    raw, nvram = disk_paths(output, contract)
    budget = storage_budget(output, contract)
    xml = render_domain_xml(contract, windows_iso=windows, configuration_set=config_iso, virtio_iso=virtio,
                            raw_disk=raw, nvram=nvram, firmware_code=firmware_code, firmware_vars=firmware_vars)
    plan: dict[str, Any] = {
        "schema_version": 1,
        "task": "GB100-M15-03",
        "kind": "local-kvm-preflight-only",
        "domain_name": contract["vm"]["name"],
        "vm": contract["vm"],
        "firmware": {"uefi": True, "secure_boot": True, "code": str(firmware_code), "vars_template": str(firmware_vars),
                     "planned_nvram_path": str(nvram), "nvram_created": False},
        "disk": {"path": str(raw), "format": "raw", "bus": "sata", "created": False, **budget},
        "media": {
            "windows_installation_iso": {"path": str(windows), "sha256": lock["inputs"]["windows_server_2025_eval_iso"]["sha256"], "read_only": True},
            "configuration_set_iso": {"path": str(config_iso), "sha256": assembly["iso"]["sha256"], "read_only": True,
                                        "windows_iso_remastered": False},
            "virtio_iso": {"path": str(virtio), "read_only": True, "trusted": False,
                            "post_boot_signtool_kp_gate_required": True, "loaded_in_windowspe": False},
        },
        "network": contract["network"],
        "lifecycle": {**contract["lifecycle"], "qemu_invoked": False, "virt_install_invoked": False},
        "libvirt_permission_diagnosis": {
            "read_only_command": ["sg", "libvirt", "-c", "virsh -c qemu:///system uri"],
            "mutating_commands_forbidden": ["virsh define", "virsh start", "virt-install", "qemu-img create"],
        },
        "sensitive_material_absent": True,
    }
    AUTO.reject_secrets(plan, "local_kvm_plan")
    return plan, xml


def validate_plan_output(path: Path) -> Path:
    target = path.resolve()
    build = (ROOT / "build").resolve()
    try:
        target.relative_to(build)
    except ValueError as exc:
        raise KvmPlanError("--plan-output must be under build/") from exc
    require(target.name.startswith("m15-03-local-kvm-plan-") and not target.exists(),
            "--plan-output must be a new build/m15-03-local-kvm-plan-* directory")
    return target


def write_plan(destination: Path, plan: dict[str, Any], xml: str) -> Path:
    target = validate_plan_output(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".m15-03-local-kvm-plan-", dir=target.parent))
    try:
        (staging / PLAN_NAME).write_text(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (staging / DOMAIN_NAME).write_text(xml, encoding="utf-8")
        os.replace(staging, target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


def diagnose_libvirt() -> dict[str, Any]:
    """Perform only a fixed, read-only libvirt connectivity diagnosis."""
    import grp
    import pwd
    # getgrouplist includes the configured supplementary groups even when this
    # long-lived shell predates a usermod.  The actual process groups decide
    # whether plain virsh works right now; the fixed ``sg`` call below is the
    # no-login recovery path.
    user = pwd.getpwuid(os.getuid()).pw_name
    configured_gids = set(os.getgrouplist(user, os.getgid()))
    libvirt_group = grp.getgrnam("libvirt")
    in_current_process = libvirt_group.gr_gid in os.getgroups() or os.getgid() == libvirt_group.gr_gid
    configured_for_user = libvirt_group.gr_gid in configured_gids
    sg = shutil.which("sg")
    virsh = shutil.which("virsh")
    require(sg is not None and virsh is not None, "sg and virsh are required for libvirt permission diagnosis")
    command = [sg, "libvirt", "-c", "virsh -c qemu:///system uri"]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return {
        "configured_for_libvirt_group": configured_for_user,
        "current_process_has_libvirt_group": in_current_process,
        "read_only_command": command,
        "returncode": result.returncode,
        "uri": result.stdout.strip() if result.returncode == 0 else None,
        "diagnostic": ("current process needs a new login or the fixed sg command" if configured_for_user and not in_current_process
                       else "read-only libvirt connectivity checked"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "render", "diagnose-libvirt"))
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--vm-output-dir", type=Path)
    parser.add_argument("--configuration-set", type=Path)
    parser.add_argument("--virtio-iso", type=Path)
    parser.add_argument("--plan-output", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "diagnose-libvirt":
            print(json.dumps(diagnose_libvirt(), ensure_ascii=False, sort_keys=True), flush=True)
            return 0
        require(args.vm_output_dir is not None and args.configuration_set is not None and args.virtio_iso is not None,
                "--vm-output-dir, --configuration-set, and --virtio-iso are required")
        lock = AUTO.load_lock(args.lock)
        contract = load_contract(args.contract)
        plan, xml = make_plan(lock, contract, vm_output_dir=args.vm_output_dir,
                              configuration_set=args.configuration_set, virtio_iso=args.virtio_iso)
        if args.action == "render":
            require(args.plan_output is not None, "render requires --plan-output")
            print(f"M15-03 local KVM plan rendered: {write_plan(args.plan_output, plan, xml)}", flush=True)
        else:
            print("M15-03 local KVM preflight passed; no VM, disk, NVRAM, domain, or network was created", flush=True)
        return 0
    except (AUTO.AutounattendError, KvmPlanError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

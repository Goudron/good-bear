#!/usr/bin/env python3
"""Fail-closed executor for one reviewed GB100-M15-03 local KVM plan.

The companion planner deliberately never changes libvirt.  This separate tool
accepts only that planner's reviewed build artifact, derives the expected plan
again from the pinned inputs, and then exposes three deliberately narrow
actions:

* ``validate`` -- revalidate only, with no filesystem or libvirt mutation;
* ``dry-run`` -- additionally show the fixed command sequence, still without
  mutation; and
* ``create`` -- create exactly the pinned sparse raw disk and NVRAM copy,
  grant only ``libvirt-qemu`` the ACLs needed for these exact files, and define
  then start the one pinned domain through ``sg libvirt``.

There is no generic domain, disk, network, path, or command interface here.
In particular this tool never starts a libvirt network, changes Cloud
resources, invokes sudo, or accepts a shell fragment from its caller.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable

import plan_m15_03_local_kvm as KVM
import generate_m15_03_autounattend as AUTO


ROOT = Path(__file__).resolve().parents[1]
PLAN_NAME = KVM.PLAN_NAME
DOMAIN_NAME = KVM.DOMAIN_NAME
QEMU_USER = "libvirt-qemu"
OUTPUT_DIRECTORY_NAME = "m15-03-local-vm"
EXPECTED_DOMAIN = "goodbear-m15-03-windows-server-2025-prep"
ALLOWED_ACTIONS = ("validate", "dry-run", "render-boot-automation", "create", "create-boot-automation")
BOOT_AUTOMATION_XML_NAME = "m15-03-local-kvm-boot-automation.xml"


class KvmExecutionError(ValueError):
    """The reviewed plan cannot be executed safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KvmExecutionError(message)


def require_regular(path: Path, label: str) -> Path:
    require(path.is_file() and not path.is_symlink(), f"{label} must be an existing regular non-symlink file")
    return path.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KvmExecutionError(f"cannot read {label}") from exc
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def relative_to_build(path: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to((ROOT / "build").resolve())
    except ValueError as exc:
        raise KvmExecutionError(f"{label} must be under this project's build/ directory") from exc
    return resolved


def validate_plan_directory(path: Path) -> tuple[Path, Path, Path]:
    require(path.is_absolute(), "--plan-dir must be an explicit absolute directory")
    root = relative_to_build(path, "--plan-dir")
    require(root.is_dir() and not root.is_symlink(), "--plan-dir must be an existing regular build directory")
    require(root.name.startswith("m15-03-local-kvm-plan-"),
            "--plan-dir must be a newly rendered build/m15-03-local-kvm-plan-* directory")
    plan_path = root / PLAN_NAME
    xml_path = root / DOMAIN_NAME
    require_regular(plan_path, "reviewed plan JSON")
    require_regular(xml_path, "reviewed domain XML")
    return root, plan_path, xml_path


def normalize_dynamic_storage(plan: dict[str, Any]) -> dict[str, Any]:
    """Remove live-capacity observations while retaining capacity invariants."""
    result = copy.deepcopy(plan)
    disk = result.get("disk")
    require(isinstance(disk, dict), "reviewed plan lacks disk data")
    disk.pop("available_bytes_before_creation", None)
    disk.pop("available_bytes_after_reservation", None)
    return result


def validate_recorded_storage(plan: dict[str, Any]) -> None:
    disk = plan.get("disk")
    require(isinstance(disk, dict), "reviewed plan lacks disk data")
    before = disk.get("available_bytes_before_creation")
    after = disk.get("available_bytes_after_reservation")
    reserve = disk.get("initial_allocation_reservation_bytes")
    headroom = disk.get("minimum_free_headroom_bytes")
    require(all(isinstance(value, int) and value >= 0 for value in (before, after, reserve, headroom)),
            "reviewed plan storage observations are malformed")
    require(before - reserve == after, "reviewed plan storage reservation arithmetic drifted")
    require(before >= reserve + headroom, "reviewed plan did not satisfy its storage headroom invariant")


def canonical_expected_plan(plan: dict[str, Any]) -> tuple[dict[str, Any], str, Path, Path]:
    """Recompute all trusted plan content from current pinned inputs.

    The VirtIO image remains an explicitly untrusted *read-only transport*
    attachment.  It is not hashed/promoted here; the guest's later signtool
    gate is the mandatory trust boundary before Sysprep.
    """
    require(plan.get("schema_version") == 1 and plan.get("task") == "GB100-M15-03",
            "reviewed plan has an unexpected schema or task")
    require(plan.get("kind") == "local-kvm-preflight-only", "reviewed plan kind is not preflight-only")
    require(plan.get("domain_name") == EXPECTED_DOMAIN, "reviewed plan domain name is not pinned")
    require(plan.get("sensitive_material_absent") is True, "reviewed plan does not declare sensitive material absent")
    AUTO.reject_secrets(plan, "reviewed_local_kvm_plan")
    vm = plan.get("vm")
    require(isinstance(vm, dict) and vm.get("name") == EXPECTED_DOMAIN, "reviewed plan VM identity drifted")
    disk = plan.get("disk")
    firmware = plan.get("firmware")
    media = plan.get("media")
    require(isinstance(disk, dict) and isinstance(firmware, dict) and isinstance(media, dict),
            "reviewed plan omits required disk, firmware, or media data")
    raw = Path(str(disk.get("path", "")))
    nvram = Path(str(firmware.get("planned_nvram_path", "")))
    require(raw.is_absolute() and nvram.is_absolute(), "reviewed storage paths must be absolute")
    output = raw.parent.resolve()
    require(output == nvram.parent.resolve(), "raw disk and NVRAM must share their one preflighted output directory")
    relative_to_build(output, "reviewed VM output directory")
    require(output.name == OUTPUT_DIRECTORY_NAME and output.is_dir() and not output.is_symlink(),
            "reviewed VM output directory is not the pinned existing build/m15-03-local-vm directory")
    require(raw.name == f"{EXPECTED_DOMAIN}.raw" and nvram.name == f"{EXPECTED_DOMAIN}.nvram.fd",
            "reviewed storage filenames are not pinned")
    require(not raw.exists() and not raw.is_symlink(), "refusing to reuse, overwrite, or follow an existing raw disk")
    require(not nvram.exists() and not nvram.is_symlink(), "refusing to reuse, overwrite, or follow existing NVRAM")
    validate_recorded_storage(plan)

    try:
        lock = AUTO.load_lock(KVM.DEFAULT_LOCK)
        contract = KVM.load_contract(KVM.DEFAULT_CONTRACT)
        config_entry = media["configuration_set_iso"]
        virtio_entry = media["virtio_iso"]
    except (AUTO.AutounattendError, KVM.KvmPlanError, KeyError, TypeError) as exc:
        raise KvmExecutionError("current local KVM inputs cannot be loaded") from exc
    require(isinstance(config_entry, dict) and isinstance(virtio_entry, dict), "reviewed media entries are malformed")
    configuration_set = Path(str(config_entry.get("path", "")))
    virtio_iso = Path(str(virtio_entry.get("path", "")))
    try:
        expected, expected_xml = KVM.make_plan(
            lock, contract, vm_output_dir=output, configuration_set=configuration_set, virtio_iso=virtio_iso,
        )
    except (AUTO.AutounattendError, KVM.KvmPlanError) as exc:
        raise KvmExecutionError(f"current pinned inputs no longer validate: {exc}") from exc
    require(normalize_dynamic_storage(plan) == normalize_dynamic_storage(expected),
            "reviewed plan differs from a freshly derived pinned plan")
    validate_recorded_storage(expected)
    return expected, expected_xml, raw, nvram


def validate_plan(plan_dir: Path) -> dict[str, Any]:
    root, plan_path, xml_path = validate_plan_directory(plan_dir)
    plan = load_json(plan_path, "reviewed plan JSON")
    expected, expected_xml, raw, nvram = canonical_expected_plan(plan)
    supplied_xml = xml_path.read_text(encoding="utf-8")
    require(supplied_xml == expected_xml, "reviewed domain XML differs from freshly derived secure XML")
    require("<graphics" not in supplied_xml and "secure=\"yes\"" in supplied_xml,
            "reviewed domain XML lacks required headless Secure Boot settings")
    require('source network="default"' in supplied_xml and '<model type="e1000e"/>' in supplied_xml,
            "reviewed domain XML lacks the pinned existing default/e1000e network attachment")
    return {
        "plan_dir": str(root),
        "plan_sha256": sha256_file(plan_path),
        "domain_xml_sha256": sha256_file(xml_path),
        "domain_name": expected["domain_name"],
        "raw_disk": str(raw),
        "nvram": str(nvram),
        "logical_raw_disk_bytes": expected["disk"]["logical_raw_disk_bytes"],
        "available_bytes_before_create": KVM.storage_budget(raw.parent, KVM.load_contract())["available_bytes_before_creation"],
        "minimum_free_headroom_bytes": expected["disk"]["minimum_free_headroom_bytes"],
        "virtio_untrusted_until_guest_signtool_kp_gate": True,
    }


def render_loopback_boot_automation_xml(headless_xml: str) -> str:
    """Derive the only permitted temporary graphical variant of a reviewed XML."""
    marker = "    <!-- Deliberately no graphical device: libvirt's supported headless form. -->"
    require(headless_xml.count(marker) == 1, "reviewed headless XML has no unique graphical-device marker")
    require("<graphics" not in headless_xml, "reviewed normal XML must be headless before VNC derivation")
    temporary = (
        "    <!-- Temporary pre-OS transport: local loopback only; never expose this VNC server. -->\n"
        "    <graphics type=\"vnc\" port=\"-1\" autoport=\"yes\" listen=\"127.0.0.1\">\n"
        "      <listen type=\"address\" address=\"127.0.0.1\"/>\n"
        "    </graphics>\n"
        "    <video><model type=\"virtio\" heads=\"1\" primary=\"yes\"/></video>\n"
        "    <!-- Required only to deliver the one automated pre-OS boot key. -->\n"
        "    <input type=\"keyboard\" bus=\"usb\"/>"
    )
    result = headless_xml.replace(marker, temporary)
    require(result.count('listen="127.0.0.1"') == 1 and result.count('address="127.0.0.1"') == 1,
            "temporary VNC XML must be loopback-only")
    return result


def validate_boot_automation_xml(evidence: dict[str, Any], path: Path) -> Path:
    """Accept exactly the generated local-only pre-OS XML, never arbitrary XML."""
    require(path.is_absolute(), "--boot-automation-xml must be an explicit absolute file")
    target = relative_to_build(path, "--boot-automation-xml")
    require(target.name == BOOT_AUTOMATION_XML_NAME, "boot-automation XML filename is not pinned")
    require_regular(target, "boot-automation XML")
    normal = Path(str(evidence["plan_dir"])) / DOMAIN_NAME
    expected = render_loopback_boot_automation_xml(normal.read_text(encoding="utf-8"))
    require(target.read_text(encoding="utf-8") == expected,
            "boot-automation XML differs from the only reviewed local-loopback derivation")
    return target


def write_boot_automation_xml(evidence: dict[str, Any]) -> Path:
    """Atomically publish the sole permitted local-only pre-OS VNC variant."""
    plan_dir = Path(str(evidence["plan_dir"]))
    normal = plan_dir / DOMAIN_NAME
    target = plan_dir / BOOT_AUTOMATION_XML_NAME
    require(not target.exists() and not target.is_symlink(),
            "refusing to overwrite an existing boot-automation XML")
    rendered = render_loopback_boot_automation_xml(normal.read_text(encoding="utf-8"))
    temporary = target.with_name("." + target.name + ".tmp")
    try:
        temporary.write_text(rendered, encoding="utf-8", newline="\n")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return validate_boot_automation_xml(evidence, target)


def _sg_command(argv: list[str]) -> list[str]:
    """Return one fixed ``sg`` invocation; only internally-derived argv enters it."""
    require(argv and argv[0] == "virsh", "only virsh may run through sg libvirt")
    return ["sg", "libvirt", "-c", shlex.join(argv)]


def command_sequence(evidence: dict[str, Any], domain_xml: Path | None = None) -> list[list[str]]:
    name = str(evidence["domain_name"])
    return [
        _sg_command(["virsh", "-c", "qemu:///system", "net-info", "default"]),
        _sg_command(["virsh", "-c", "qemu:///system", "list", "--all", "--name"]),
        _sg_command(["virsh", "-c", "qemu:///system", "define", str(domain_xml or Path(evidence["plan_dir"]) / DOMAIN_NAME)]),
        _sg_command(["virsh", "-c", "qemu:///system", "start", name]),
        _sg_command(["virsh", "-c", "qemu:///system", "domstate", name]),
        _sg_command(["virsh", "-c", "qemu:///system", "ttyconsole", name]),
    ]


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def run_checked(command: list[str], runner: Runner, label: str) -> subprocess.CompletedProcess[str]:
    result = runner(command)
    if result.returncode != 0:
        raise KvmExecutionError(f"{label} failed (exit {result.returncode}): {result.stderr.strip() or result.stdout.strip()}")
    return result


def system_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def validate_libvirt_preconditions(evidence: dict[str, Any], runner: Runner) -> None:
    commands = command_sequence(evidence)
    network = run_checked(commands[0], runner, "required existing libvirt default network check")
    normalized_network = network.stdout.lower()
    require("active:" in normalized_network and "yes" in normalized_network,
            "existing libvirt default network is not active; this executor will not start or alter networks")
    domains = run_checked(commands[1], runner, "libvirt domain inventory check")
    name = str(evidence["domain_name"])
    require(name not in {line.strip() for line in domains.stdout.splitlines() if line.strip()},
            "refusing to define or alter an existing domain with the pinned name")


def qemu_acl_targets(evidence: dict[str, Any]) -> list[tuple[Path, str]]:
    """Return exact owner-controlled paths only; never recursively change modes."""
    raw = Path(str(evidence["raw_disk"]))
    nvram = Path(str(evidence["nvram"]))
    plan_dir = Path(str(evidence["plan_dir"]))
    plan = load_json(plan_dir / PLAN_NAME, "reviewed plan JSON")
    media = plan["media"]
    files = [
        (raw, "rw"), (nvram, "rw"),
        (Path(str(media["windows_installation_iso"]["path"])), "r"),
        (Path(str(media["configuration_set_iso"]["path"])), "r"),
        (Path(str(media["virtio_iso"]["path"])), "r"),
    ]
    targets: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for file_path, permissions in files:
        resolved = require_regular(file_path, "QEMU attachment")
        if resolved not in seen:
            targets.append((resolved, permissions))
            seen.add(resolved)
        current = resolved.parent
        # Grant traversal only through exact existing ancestors that the user owns;
        # do not touch /, /home, or a system-owned directory.
        while current != Path("/"):
            if current == Path("/home"):
                break
            try:
                owner = current.stat().st_uid
            except OSError as exc:
                raise KvmExecutionError("cannot inspect a required QEMU attachment parent") from exc
            if owner == os.getuid() and current not in seen:
                targets.append((current, "x"))
                seen.add(current)
            current = current.parent
    return targets


def apply_minimal_qemu_acls(evidence: dict[str, Any], runner: Runner) -> list[list[str]]:
    """Grant only user ACLs to the exact media/output paths after creation.

    POSIX ACL entries are used rather than broad chmod/chown.  If ACL support
    is unavailable the operation fails before libvirt definition; callers can
    inspect the retained sparse files and resolve host policy explicitly.
    """
    setfacl = shutil.which("setfacl")
    require(setfacl is not None, "setfacl is required for minimal libvirt-qemu ACLs")
    commands: list[list[str]] = []
    for path, permissions in qemu_acl_targets(evidence):
        command = [setfacl, "-m", f"u:{QEMU_USER}:{permissions}", "--", str(path)]
        run_checked(command, runner, f"minimal {QEMU_USER} ACL")
        commands.append(command)
    return commands


def create_sparse_raw(path: Path, logical_size: int) -> None:
    """Create one exact sparse regular raw file without qemu-img or overwrite."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise KvmExecutionError("cannot atomically create the pinned raw disk") from exc
    try:
        os.ftruncate(descriptor, logical_size)
        os.fsync(descriptor)
    except OSError as exc:
        raise KvmExecutionError("cannot size/fsync the pinned sparse raw disk") from exc
    finally:
        os.close(descriptor)
    require_regular(path, "new sparse raw disk")
    require(path.stat().st_size == logical_size, "new sparse raw disk has the wrong logical size")


def copy_nvram(template: Path, destination: Path) -> None:
    source = require_regular(template, "UEFI NVRAM template")
    try:
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise KvmExecutionError("cannot atomically create the pinned NVRAM copy") from exc
    try:
        with source.open("rb") as input_file, os.fdopen(destination_fd, "wb", closefd=False) as output_file:
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
    except OSError as exc:
        raise KvmExecutionError("cannot copy/fsync the pinned NVRAM template") from exc
    finally:
        os.close(destination_fd)
    require_regular(destination, "new NVRAM copy")
    require(sha256_file(source) == sha256_file(destination), "new NVRAM copy differs from its pinned template")


def create(evidence: dict[str, Any], runner: Runner = system_runner, *, domain_xml: Path | None = None,
           boot_automation: bool = False) -> dict[str, Any]:
    """Perform the irreducible local action after all checks; no rollback/overwrite."""
    validate_libvirt_preconditions(evidence, runner)
    raw = Path(str(evidence["raw_disk"]))
    nvram = Path(str(evidence["nvram"]))
    plan = load_json(Path(str(evidence["plan_dir"])) / PLAN_NAME, "reviewed plan JSON")
    template = Path(str(plan["firmware"]["vars_template"]))
    create_sparse_raw(raw, int(evidence["logical_raw_disk_bytes"]))
    copy_nvram(template, nvram)
    acl_commands = apply_minimal_qemu_acls(evidence, runner)
    commands = command_sequence(evidence, domain_xml)
    run_checked(commands[2], runner, "pinned domain definition")
    run_checked(commands[3], runner, "pinned domain start")
    state = run_checked(commands[4], runner, "pinned domain state query").stdout.strip()
    require(state == "running", "pinned domain did not report running after start")
    console = run_checked(commands[5], runner, "pinned serial console discovery").stdout.strip()
    require(console.startswith("/dev/pts/"), "pinned domain did not expose the required serial PTY console")
    return {
        **evidence,
        "action": "create",
        "raw_disk_created": True,
        "nvram_created": True,
        "qemu_acl_commands": acl_commands,
        "domain_state": state,
        "serial_console": console,
        "virtio_untrusted_until_guest_signtool_kp_gate": True,
        "temporary_local_loopback_vnc_for_pre_os_boot_automation": boot_automation,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=ALLOWED_ACTIONS)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--boot-automation-xml", type=Path)
    args = parser.parse_args()
    try:
        evidence = validate_plan(args.plan_dir)
        if args.action == "validate":
            result: dict[str, Any] = {**evidence, "action": "validate", "mutation": False}
        elif args.action == "dry-run":
            result = {**evidence, "action": "dry-run", "mutation": False,
                      "exact_future_commands": command_sequence(evidence),
                      "note": "No file, ACL, libvirt, or network action was performed."}
        elif args.action == "render-boot-automation":
            require(args.boot_automation_xml is None,
                    "render-boot-automation derives its one pinned output path")
            boot_xml = write_boot_automation_xml(evidence)
            result = {**evidence, "action": "render-boot-automation", "mutation": "local-build-xml-only",
                      "boot_automation_xml": str(boot_xml), "loopback_only": True}
        elif args.action == "create":
            require(args.boot_automation_xml is None,
                    "--boot-automation-xml is only valid with create-boot-automation")
            result = create(evidence)
        else:
            require(args.boot_automation_xml is not None,
                    "create-boot-automation requires --boot-automation-xml")
            temporary_xml = validate_boot_automation_xml(evidence, args.boot_automation_xml)
            result = create(evidence, domain_xml=temporary_xml, boot_automation=True)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
        return 0
    except (AUTO.AutounattendError, KVM.KvmPlanError, KvmExecutionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

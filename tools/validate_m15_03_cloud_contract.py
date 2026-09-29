#!/usr/bin/env python3
"""Offline, fail-closed planning validator for GB100-M15-03.

It never opens the credential reference, contacts Cloud.ru, creates a VM, or
starts a local guest.  It validates the non-secret control-plane shape and
reports the concrete pins/identifiers that must exist before a separately
authorized lifecycle implementation can be considered.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "config" / "m15-03-cloud-api-contract.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PROJECT_ID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")


class ContractError(ValueError):
    """The requested Cloud control-plane action must remain blocked."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read M15-03 contract: {exc}") from exc
    require(isinstance(data, dict), "M15-03 contract must be a JSON object")
    return data


def validate_shape(contract: dict[str, Any], root: Path = ROOT) -> None:
    require(contract.get("schema_version") == 1, "unsupported M15-03 contract schema")
    require(contract.get("task") == "GB100-M15-03", "wrong M15-03 task identifier")
    require(contract.get("mode") == "offline-planning-only", "M15-03 contract must remain offline-only")
    require(contract.get("mutation_authorized") is False, "Cloud mutation requires separate explicit authorization")

    credentials = contract.get("credential_reference")
    require(isinstance(credentials, dict), "missing credential reference")
    credential_path = credentials.get("path")
    require(isinstance(credential_path, str) and Path(credential_path).is_absolute(),
            "credential reference must be an absolute external path")
    require(credentials.get("outside_repository") is True and credentials.get("read_by_offline_validator") is False,
            "offline validation must neither store nor read credentials")
    try:
        Path(credential_path).resolve().relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise ContractError("credential reference must remain outside the repository")

    api = contract.get("api")
    require(api == {
        "iam_token_endpoint": "https://iam.api.cloud.ru/api/v1/auth/token",
        "compute_endpoint": "https://compute.api.cloud.ru",
    }, "Cloud.ru endpoints drifted from the reviewed official API endpoints")
    require(isinstance(contract.get("project_id"), str) and PROJECT_ID.fullmatch(contract["project_id"]) is not None,
            "project_id must be a non-secret UUID")

    tags = contract.get("identity", {}).get("tags")
    require(tags == {"managed_by": "good-bear", "role": "windows-builder", "task": "GB100-M15-03"},
            "only uniquely tagged Good Bear Windows builder resources are in scope")
    kvm = contract.get("local_kvm")
    require(isinstance(kvm, dict) and kvm.get("disk_format") == "raw" and kvm.get("requires_kvm") is True,
            "local image must use a RAW VirtIO KVM disk")
    require(kvm.get("required_commands") == ["qemu-img", "qemu-system-x86_64", "virt-install", "virsh"],
            "KVM command prerequisite set drifted")

    builder = contract.get("builder")
    require(isinstance(builder, dict), "missing builder shape")
    require((builder.get("vcpu"), builder.get("memory_gib"), builder.get("ssd_workspace_gib")) == (4, 16, 250),
            "builder must remain 4 vCPU / 16 GiB / 250 GiB SSD")

    access = contract.get("remote_access")
    require(isinstance(access, dict) and access.get("permitted_tcp_ports") == [22, 5985, 5986],
            "remote access must be restricted to SSH/WinRM ports")
    require(access.get("recovery_console") == "audited-exception-only", "recovery console must remain exceptional")
    cidrs = access.get("allowed_source_cidrs")
    require(isinstance(cidrs, list), "allowed_source_cidrs must be a list")
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError as exc:
            raise ContractError(f"invalid maintainer source CIDR: {cidr}") from exc
        require(network.prefixlen != 0, "broad public ingress is forbidden")

    lifecycle = contract.get("lifecycle")
    require(isinstance(lifecycle, dict), "missing lifecycle guard")
    require(lifecycle.get("inspect_before_mutation") is True
            and lifecycle.get("stop_after_completed_or_unsuccessful_run") is True
            and lifecycle.get("delete_after_verified_return") is True
            and lifecycle.get("retention_exception_recorded") is False,
            "cost/lifecycle guard must remain fail-closed")


def readiness_blockers(contract: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    windows = contract["image_inputs"]["windows_server_2025_evaluation"]
    virtio = contract["image_inputs"]["virtio_win"]
    bootstrap = contract["image_inputs"]["bootstrap"]
    for label, value in (("Windows Server 2025 Evaluation ISO path", windows.get("path")),
                         ("Windows Server 2025 Evaluation ISO SHA-256", windows.get("sha256")),
                         ("VirtIO media path", virtio.get("path")),
                         ("VirtIO media SHA-256", virtio.get("sha256")),
                         ("VirtIO signature path", virtio.get("signature_path")),
                         ("VirtIO signature SHA-256", virtio.get("signature_sha256")),
                         ("Cloudbase-Init bootstrap path", bootstrap.get("cloudbase_init_path")),
                         ("Cloudbase-Init bootstrap SHA-256", bootstrap.get("cloudbase_init_sha256"))):
        if not isinstance(value, str) or not value:
            blockers.append(label)
    for label, value in (("Cloudbase-Init SHA-256", bootstrap.get("cloudbase_init_sha256")),
                         ("Windows Server 2025 Evaluation ISO SHA-256", windows.get("sha256")),
                         ("VirtIO media SHA-256", virtio.get("sha256")),
                         ("VirtIO signature SHA-256", virtio.get("signature_sha256"))):
        if isinstance(value, str) and value and SHA256.fullmatch(value) is None:
            blockers.append(f"valid {label}")
    if bootstrap.get("openssh_or_winrm") not in {"openssh", "winrm", "openssh-and-winrm"}:
        blockers.append("headless OpenSSH or WinRM bootstrap choice")
    if virtio.get("signature_verified") is not True:
        blockers.append("verified VirtIO signature")
    if bootstrap.get("cloudbase_init_authenticode_verified") is not True:
        blockers.append("verified Cloudbase-Init Authenticode")
    if not isinstance(bootstrap.get("cloudbase_init_publisher"), str) or not bootstrap["cloudbase_init_publisher"]:
        blockers.append("Cloudbase-Init Authenticode publisher")
    for key in ("flavor_id", "availability_zone_id", "subnet_id", "security_group_id", "public_ip_id", "user_image_id"):
        if not isinstance(contract["builder"].get(key), str) or not contract["builder"][key]:
            blockers.append(f"Cloud.ru builder.{key}")
    if not contract["remote_access"]["allowed_source_cidrs"]:
        blockers.append("approved maintainer source CIDR")
    return blockers


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline fail-closed GB100-M15-03 contract validator")
    parser.add_argument("action", choices=("plan", "preflight"))
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    args = parser.parse_args()
    try:
        contract = load_contract(args.contract)
        validate_shape(contract)
        blockers = readiness_blockers(contract)
        if args.action == "plan":
            print("GB100-M15-03 offline plan: no credential read, API call, VM, image upload, or mutation", flush=True)
            for blocker in blockers:
                print(f"BLOCKED: {blocker}", flush=True)
            return 0
        require(not blockers, "M15-03 preflight blocked: " + "; ".join(blockers))
        print("M15-03 preflight shape passed; separate authorization is still required for mutation", flush=True)
        return 0
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

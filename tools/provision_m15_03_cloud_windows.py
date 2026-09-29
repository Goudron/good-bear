#!/usr/bin/env python3
"""Fail-closed lifecycle control for the direct Cloud.ru Windows builder.

The only secrets read or created by this tool live outside the repository.  Its
default action is a read-only inspection.  Every mutation is explicit and is
allowed only after the exact existing VM identity, shape, network and egress
policy have been inspected.  Output and the optional inventory contain no
password, bearer token, or access-key material.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "config" / "m15-03-direct-cloud-windows-2022.json"

WINDOWS_RDP_CLOUD_INIT = """#cloud-config
users:
  - name: {{ builder_username }}
    lock_passwd: false
    passwd: {{ builder_password }}
    groups: Administrators
    shell: powershell.exe
runcmd:
  - powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference = 'Stop'; Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0; Set-Service -Name 'TermService' -StartupType Automatic; Start-Service -Name 'TermService'; & netsh advfirewall firewall delete rule name='Good Bear RDP' | Out-Null; & netsh advfirewall firewall add rule name='Good Bear RDP' dir=in action=allow protocol=TCP localport=3389 profile=any | Out-Null; Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null; Set-Service -Name 'sshd' -StartupType Automatic; Start-Service -Name 'sshd'; & netsh advfirewall firewall delete rule name='Good Bear OpenSSH' | Out-Null; & netsh advfirewall firewall add rule name='Good Bear OpenSSH' dir=in action=allow protocol=TCP localport=22 profile=any | Out-Null; Set-Service -Name 'WinRM' -StartupType Automatic; Start-Service -Name 'WinRM'; Set-Item -Path 'WSMan:\\localhost\\Service\\Auth\\Basic' -Value $true; Set-Item -Path 'WSMan:\\localhost\\Service\\AllowUnencrypted' -Value $false; $https = Get-ChildItem -Path 'WSMan:\\localhost\\Listener' | Where-Object { $_.Keys -match 'Transport=HTTPS' }; if (-not $https) { $cert = New-SelfSignedCertificate -DnsName 'goodbear-m15-03-win-2022-builder' -CertStoreLocation 'Cert:\\LocalMachine\\My'; New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{Address='*';Transport='HTTPS'} -ValueSet @{Hostname='goodbear-m15-03-win-2022-builder';CertificateThumbprint=$cert.Thumbprint} }; & netsh advfirewall firewall delete rule name='Good Bear WinRM HTTPS' | Out-Null; & netsh advfirewall firewall add rule name='Good Bear WinRM HTTPS' dir=in action=allow protocol=TCP localport=5986 profile=any | Out-Null\"
"""


class CloudProvisionError(ValueError):
    """A direct-cloud precondition has not been proved."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CloudProvisionError(message)


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CloudProvisionError(f"cannot read JSON: {path}") from exc
    require(isinstance(value, dict), f"JSON object required: {path}")
    return value


def require_external_secret_path(path: Path) -> None:
    require(path.is_absolute(), "secret path must be absolute")
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return
    raise CloudProvisionError("secret path must remain outside the repository")


def load_cloud_credentials(path: Path, project_id: str) -> dict[str, str]:
    require_external_secret_path(path)
    require(path.is_file() and not path.is_symlink(), "Cloud.ru credentials must be a regular file")
    require(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0,
            "Cloud.ru credentials must not be group/world accessible")
    value = load_json(path)
    require(set(value) == {"key_id", "secret", "project_id"}, "unexpected Cloud.ru credential fields")
    require(value["project_id"] == project_id, "credential project differs from contract")
    require(all(isinstance(value[key], str) and value[key] for key in value), "empty Cloud.ru credential")
    return value


def validate_contract(contract: dict[str, Any]) -> None:
    require(contract.get("schema_version") == 1, "unsupported direct builder contract schema")
    require(contract.get("task") == "GB100-M15-03", "wrong task")
    require(contract.get("mode") == "direct-cloud-marketplace", "unexpected builder mode")
    require(contract.get("maintainer_authorization", {}).get("date") == "2026-09-14",
            "missing recorded maintainer authorization")
    api = contract.get("api")
    require(api == {"iam_token_endpoint": "https://iam.api.cloud.ru/api/v1/auth/token",
                    "compute_endpoint": "https://compute.api.cloud.ru"}, "unreviewed Cloud.ru endpoints")
    builder = contract.get("builder")
    require(isinstance(builder, dict), "missing builder")
    require((builder.get("vcpu"), builder.get("memory_gib"), builder.get("boot_disk_gib")) == (4, 16, 250),
            "builder must remain 4 vCPU / 16 GiB / 250 GiB")
    require(builder.get("marketplace_image_name") == "wind-2022-dc-evo-prod",
            "only the approved Windows Server 2022 marketplace image is allowed")
    require(isinstance(builder.get("tags"), list) and builder["tags"] == ["goodbear", "windows-builder", "gb100-m15-03"],
            "builder identity tags drifted")
    access = contract.get("remote_access")
    require(isinstance(access, dict), "missing remote-access policy")
    source = access.get("allowed_source_cidr")
    try:
        network = ipaddress.ip_network(source, strict=True)
    except ValueError as exc:
        raise CloudProvisionError("invalid maintainer source CIDR") from exc
    global_exposure = access.get("inbound_exposure") == "global-at-maintainer-request"
    require(network.prefixlen == network.max_prefixlen or (network == ipaddress.ip_network("0.0.0.0/0") and global_exposure),
            "remote access must be a single maintainer address or recorded global maintainer authorization")
    require(access.get("inbound_exposure") in (None, "global-at-maintainer-request"),
            "unreviewed remote-access exposure")
    require(access.get("inbound_tcp_ports") == [22, 3389, 5986],
            "only the approved SSH, RDP, and WinRM HTTPS ingress ports are permitted")
    require(access.get("recovery_console") == "audited-exception-only", "console must remain exceptional")
    bootstrap = contract.get("windows_bootstrap")
    require(bootstrap == {"method": "cloud-init", "rdp_enabled_on_first_boot": True,
                          "rdp_service": "TermService", "rdp_firewall_rule_name": "Good Bear RDP",
                          "openssh_enabled_on_first_boot": True,
                          "openssh_firewall_rule_name": "Good Bear OpenSSH",
                          "winrm_https_enabled_on_first_boot": True,
                          "winrm_firewall_rule_name": "Good Bear WinRM HTTPS"},
            "Windows first-boot RDP bootstrap differs from the approved exact set")
    lifecycle = contract.get("lifecycle")
    require(isinstance(lifecycle, dict) and all(lifecycle.get(key) is True for key in
            ("inspect_before_mutation", "stop_after_completed_or_unsuccessful_run", "delete_after_verified_return")),
            "lifecycle guard drifted")
    references = contract.get("credential_reference")
    require(isinstance(references, dict) and references.get("outside_repository") is True,
            "credential references must stay external")


def call_json(method: str, url: str, headers: dict[str, str], body: dict[str, Any] | list[Any] | None = None) -> Any:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=45) as response:  # nosec B310: endpoints are fixed by contract
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise CloudProvisionError(f"Cloud.ru {method} {urlsplit_path(url)} returned HTTP {exc.code}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise CloudProvisionError(f"Cloud.ru {method} {urlsplit_path(url)} failed") from exc
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudProvisionError(f"Cloud.ru {method} {urlsplit_path(url)} returned non-JSON") from exc


def urlsplit_path(url: str) -> str:
    return url.split(".ru", 1)[-1].split("?", 1)[0]


def bearer_token(contract: dict[str, Any], credentials: dict[str, str]) -> str:
    result = call_json("POST", contract["api"]["iam_token_endpoint"], {"Content-Type": "application/json"},
                       {"keyId": credentials["key_id"], "secret": credentials["secret"]})
    token = result.get("access_token") if isinstance(result, dict) else None
    require(isinstance(token, str) and token, "Cloud.ru IAM response has no access token")
    return token


def compute_url(contract: dict[str, Any], path: str, **query: str) -> str:
    require(path.startswith("/api/"), "invalid API path")
    return contract["api"]["compute_endpoint"].rstrip("/") + path + ("?" + urlencode(query) if query else "")


def response_items(value: Any, label: str) -> list[dict[str, Any]]:
    items = value.get("items") if isinstance(value, dict) else value
    if isinstance(value, dict) and label == "tags":
        items = value.get("tags")
    require(isinstance(items, list) and all(isinstance(item, dict) for item in items),
            f"Cloud.ru {label} response has no item list")
    return items


def ensure_builder_access(path: Path, username: str) -> dict[str, str]:
    require_external_secret_path(path)
    if path.exists():
        require(path.is_file() and not path.is_symlink(), "builder access file must be a regular file")
        require(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0,
                "builder access file must not be group/world accessible")
        value = load_json(path)
        require(set(value) == {"username", "password"} and value.get("username") == username
                and isinstance(value.get("password"), str) and len(value["password"]) >= 24,
                "builder access material is malformed")
        return value
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    password = "Gb!" + secrets.token_urlsafe(36)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"username": username, "password": password}, stream)
        stream.write("\n")
    return {"username": username, "password": password}


def expected_rules(contract: dict[str, Any]) -> set[tuple[str, str, str, str, str]]:
    source = contract["remote_access"]["allowed_source_cidr"]
    inbound = {
        ("ingress", "IPv4", "tcp", f"{port}:{port}", source)
        for port in contract["remote_access"]["inbound_tcp_ports"]
    }
    return inbound | {
        ("egress", "IPv4", "tcp", "1:65535", "0.0.0.0/0"),
        ("egress", "IPv4", "udp", "1:65535", "0.0.0.0/0"),
    }


def group_rules_payload(contract: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"direction": "ingress", "ether_type": "IPv4", "ip_protocol": "tcp", "port_range": "22",
         "remote_ip_prefix": contract["remote_access"]["allowed_source_cidr"],
         "description": "Maintainer-authorized global SSH automation"},
        {"direction": "ingress", "ether_type": "IPv4", "ip_protocol": "tcp", "port_range": "3389",
         "remote_ip_prefix": contract["remote_access"]["allowed_source_cidr"],
         "description": "Maintainer-only RDP recovery"},
        {"direction": "ingress", "ether_type": "IPv4", "ip_protocol": "tcp", "port_range": "5986",
         "remote_ip_prefix": contract["remote_access"]["allowed_source_cidr"],
         "description": "Maintainer-authorized WinRM HTTPS provisioning"},
        {"direction": "egress", "ether_type": "IPv4", "ip_protocol": "tcp", "port_range": "1-65535",
         "remote_ip_prefix": "0.0.0.0/0", "description": "Windows updates and declared build inputs TCP"},
        {"direction": "egress", "ether_type": "IPv4", "ip_protocol": "udp", "port_range": "1-65535",
         "remote_ip_prefix": "0.0.0.0/0", "description": "DNS and declared build inputs UDP"},
    ]


def yaml_single_quoted(value: str) -> str:
    """Render one trusted scalar without giving cloud-init YAML syntax control."""
    return "'" + value.replace("'", "''") + "'"


def windows_rdp_cloud_init(builder_access: dict[str, str]) -> str:
    """Materialize the one first-boot Windows bootstrap only in request memory."""
    username = builder_access.get("username")
    password = builder_access.get("password")
    require(isinstance(username, str) and username, "builder bootstrap username is missing")
    require(isinstance(password, str) and password, "builder bootstrap password is missing")
    return (WINDOWS_RDP_CLOUD_INIT
            .replace("{{ builder_username }}", yaml_single_quoted(username))
            .replace("{{ builder_password }}", yaml_single_quoted(password)))


def select_one(items: list[dict[str, Any]], *, key: str, expected: str, label: str) -> dict[str, Any]:
    matches = [item for item in items if item.get(key) == expected]
    require(len(matches) == 1, f"expected exactly one {label}")
    return matches[0]


def vm_tag_ids(vm: dict[str, Any]) -> set[str]:
    """Return tag identifiers from either supported Cloud.ru VM response shape."""
    direct = vm.get("tag_ids")
    if isinstance(direct, list) and all(isinstance(item, str) for item in direct):
        return set(direct)
    tags = vm.get("tags")
    require(isinstance(tags, list) and all(isinstance(item, dict) for item in tags),
            "existing builder does not expose tags")
    identifiers = {item.get("id") for item in tags}
    require(all(isinstance(item, str) and item for item in identifiers),
            "existing builder has malformed tags")
    return identifiers


def vm_has_public_ip(vm: dict[str, Any], public_ip_id: str) -> bool:
    interfaces = vm.get("interfaces")
    if not isinstance(interfaces, list):
        return False
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        floating = interface.get("floating_ip")
        if isinstance(floating, dict) and floating.get("id") == public_ip_id:
            return True
    return False


def reference_id(value: object, fallback: object = None) -> str | None:
    if isinstance(value, dict) and isinstance(value.get("id"), str):
        return value["id"]
    if isinstance(value, str):
        return value
    return fallback if isinstance(fallback, str) else None


def validate_existing_vm(summary: dict[str, Any], detail: dict[str, Any], builder: dict[str, Any],
                         project_id: str, tag_ids: list[str]) -> None:
    """Prove that both Cloud.ru response shapes describe the one approved VM."""
    require(isinstance(summary.get("id"), str) and summary["id"], "existing builder lacks ID")
    require(detail.get("id") == summary["id"] and detail.get("name") == builder["name"],
            "existing builder detail differs from the exact named VM")
    summary_project = summary.get("project_id")
    detail_project = reference_id(detail.get("project"), detail.get("project_id"))
    require(summary_project in (None, project_id) and detail_project in (None, project_id),
            "existing builder belongs to another project")
    summary_zone = reference_id(summary.get("availability_zone"), summary.get("availability_zone_id"))
    detail_zone = reference_id(detail.get("availability_zone"), detail.get("availability_zone_id"))
    require(summary_zone == builder["availability_zone_id"] and detail_zone == builder["availability_zone_id"],
            "existing builder availability zone differs from the contract")
    summary_flavor = summary.get("flavor")
    detail_flavor = detail.get("flavor")
    require(isinstance(summary_flavor, dict) and isinstance(detail_flavor, dict),
            "existing builder does not expose its flavor")
    require(summary_flavor.get("id") == builder["flavor_id"]
            and summary_flavor.get("name") == builder["flavor_name"]
            and summary_flavor.get("cpu") == builder["vcpu"]
            and summary_flavor.get("ram") == builder["memory_gib"],
            "existing builder flavor differs from the pinned 4-vCPU/16-GiB shape")
    require(detail_flavor.get("id") == builder["flavor_id"]
            and detail_flavor.get("name") == builder["flavor_name"],
            "existing builder detail flavor differs from the contract")
    require(vm_tag_ids(summary) == set(tag_ids) and vm_tag_ids(detail) == set(tag_ids),
            "existing builder tags differ from approved exact set")
    require(vm_has_public_ip(summary, builder["public_ip_id"])
            and vm_has_public_ip(detail, builder["public_ip_id"]),
            "existing builder does not have the approved public IP")

    disks = detail.get("disks")
    require(isinstance(disks, list), "existing builder detail does not expose disks")
    boot_disks = [disk for disk in disks if isinstance(disk, dict) and disk.get("primary") is True]
    require(len(boot_disks) == 1, "existing builder must expose exactly one boot disk")
    boot = boot_disks[0]
    disk_type_id = reference_id(boot.get("disk_type"), boot.get("disk_type_id"))
    require(boot.get("name") == builder["boot_disk_name"]
            and boot.get("size") == builder["boot_disk_gib"]
            and disk_type_id == builder["ssd_disk_type_id"],
            "existing builder boot disk differs from the pinned 250-GiB SSD")

    interfaces = detail.get("interfaces")
    require(isinstance(interfaces, list), "existing builder detail does not expose interfaces")
    primary = [interface for interface in interfaces
               if isinstance(interface, dict) and interface.get("primary") is True]
    require(len(primary) == 1, "existing builder must expose exactly one primary interface")
    interface = primary[0]
    security_groups = interface.get("security_groups")
    require(interface.get("type") == "regular"
            and interface.get("interface_security_enabled") is True
            and reference_id(interface.get("subnet"), interface.get("subnet_id")) == builder["subnet_id"]
            and isinstance(security_groups, list)
            and {reference_id(group) for group in security_groups} == {builder["security_group_id"]},
            "existing builder primary interface differs from the approved network boundary")


def validate_create_catalog(contract: dict[str, Any], headers: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate inputs needed only when a new VM will actually be created."""
    builder = contract["builder"]
    project = contract["project_id"]
    image = call_json("GET", compute_url(contract, f"/api/v1/images/{builder['marketplace_image_id']}",
                                          project_id=project), headers)
    require(isinstance(image, dict) and image.get("name") == builder["marketplace_image_name"]
            and image.get("type") == "marketplace", "marketplace image changed")
    zones = image.get("availability_zones")
    require(isinstance(zones, list) and any(zone.get("availability_zone_id") == builder["availability_zone_id"]
            and zone.get("enabled") is True for zone in zones if isinstance(zone, dict)),
            "image is unavailable in selected AZ")
    flavors = response_items(call_json("GET", compute_url(contract, "/api/v1/flavors", project_id=project,
                                                       availability_zone_id=builder["availability_zone_id"]), headers), "flavors")
    flavor = select_one(flavors, key="id", expected=builder["flavor_id"], label="selected flavor")
    require(flavor.get("name") == builder["flavor_name"]
            and flavor.get("cpu") == builder["vcpu"] and flavor.get("ram") == builder["memory_gib"],
            "selected flavor does not satisfy 4 vCPU / 16 GiB")
    return image, flavor


def preflight(contract: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    builder = contract["builder"]
    project = contract["project_id"]
    subnets = response_items(call_json("GET", compute_url(contract, "/api/v1/subnets", project_id=project,
                                                       availability_zone_ids=builder["availability_zone_id"]), headers), "subnets")
    select_one(subnets, key="id", expected=builder["subnet_id"], label="selected subnet")
    tags = response_items(call_json("GET", compute_url(contract, "/api/tags/v1/tags", project_id=project), headers), "tags")
    tag_ids = []
    for name in builder["tags"]:
        tag_ids.append(select_one(tags, key="name", expected=name, label=f"tag {name}")["id"])
    groups = response_items(call_json("GET", compute_url(contract, "/api/v1/security-groups", project_id=project,
                                                      name=builder["security_group_name"]), headers), "security groups")
    group = select_one(groups, key="id", expected=builder["security_group_id"], label="security group")
    rules = response_items(call_json("GET", compute_url(contract, f"/api/v1/security-groups/{group['id']}/rules"), headers), "security group rules")
    actual_rules = {(rule.get("direction"), rule.get("ether_type"), rule.get("ip_protocol"),
                     rule.get("port_range"), rule.get("remote_ip_prefix")) for rule in rules}
    require(actual_rules == expected_rules(contract), "security group rules differ from approved exact set")
    vms = response_items(call_json("GET", compute_url(contract, "/api/v1/vms", project_id=project), headers), "VMs")
    matching = [item for item in vms if item.get("name") == builder["name"]]
    require(len(matching) <= 1, "more than one identically named builder exists")
    existing = matching[0] if matching else None
    if existing is not None:
        detail = call_json("GET", compute_url(contract, f"/api/v1/vms/{existing.get('id')}",
                                               project_id=project), headers)
        require(isinstance(detail, dict), "existing builder detail is not an object")
        validate_existing_vm(existing, detail, builder, project, tag_ids)
        existing = detail
    fips = response_items(call_json("GET", compute_url(contract, "/api/v1/floating-ips", project_id=project,
                                                    availability_zone_id=builder["availability_zone_id"]), headers), "floating IPs")
    floating = select_one(fips, key="id", expected=builder["public_ip_id"], label="selected public IP")
    public_state = str(floating.get("status", floating.get("state", ""))).lower()
    attached_to_expected = existing is not None and vm_has_public_ip(existing, builder["public_ip_id"])
    require(public_state in {"available", "created"} or attached_to_expected,
            "selected public IP is neither available nor attached to the exact tagged builder")
    if existing is None:
        image, flavor = validate_create_catalog(contract, headers)
        catalog_validation = "create-inputs-current"
    else:
        # A retired catalog flavor must not make an already-created, exactly
        # pinned VM uninspectable.  Its immutable embedded shape was checked
        # above against both the list and detail responses.
        image = {"type": "existing-instance-pinned"}
        flavor = existing["flavor"]
        catalog_validation = "existing-instance-pinned"
    return {"image": image, "flavor": flavor, "group": group, "tag_ids": tag_ids,
            "existing_vm": existing, "existing_vm_verified": existing is not None,
            "public_ip_state": public_state, "catalog_validation": catalog_validation}


def create_vm(contract: dict[str, Any], headers: dict[str, str], evidence: dict[str, Any], builder_access: dict[str, str]) -> dict[str, Any]:
    builder = contract["builder"]
    payload = [{
        "project_id": contract["project_id"],
        "availability_zone_id": builder["availability_zone_id"],
        "name": builder["name"],
        "description": "Good Bear GB100-M15-03 disposable Windows Server 2022 builder",
        "flavor_id": builder["flavor_id"],
        "image_id": builder["marketplace_image_id"],
        "disks": [{"name": builder["boot_disk_name"], "size": builder["boot_disk_gib"],
                   "disk_type_id": builder["ssd_disk_type_id"]}],
        "interfaces": [{"type": "regular", "subnet_id": builder["subnet_id"],
                        "interface_security_enabled": True, "security_groups": [builder["security_group_id"]],
                        "attach_external_ip_id": builder["public_ip_id"]}],
        "cloud_init": base64.b64encode(windows_rdp_cloud_init(builder_access).encode("utf-8")).decode("ascii"),
        "tag_ids": evidence["tag_ids"],
    }]
    result = call_json("POST", compute_url(contract, "/api/v1.1/vms"), headers, payload)
    items = response_items(result, "VM creation")
    require(len(items) == 1 and isinstance(items[0].get("id"), str), "VM creation returned no unique VM")
    return items[0]


def set_builder_password(contract: dict[str, Any], headers: dict[str, str], vm: dict[str, Any],
                         builder_access: dict[str, str]) -> None:
    """Reassert access only after exact-name, exact-tag and exact-IP preflight."""
    call_json("POST", compute_url(contract, f"/api/v1/vms/{vm['id']}/set-password"), headers,
              {"login": builder_access["username"], "password": builder_access["password"]})


def execute_lifecycle(contract: dict[str, Any], headers: dict[str, str], evidence: dict[str, Any],
                      action: str, *, lifecycle_reason: str | None = None,
                      verified_return: bool = False, confirm_delete: str | None = None,
                      caller=call_json) -> tuple[dict[str, Any], bool, str]:
    """Execute one idempotent action after the exact-instance preflight.

    The mutable endpoint receives only the VM identifier returned by the
    verified preflight.  Delete additionally requires proof that artifacts
    were returned and an exact-name confirmation.
    """
    require(action in {"start", "stop", "delete"}, "unsupported lifecycle action")
    require(evidence.get("existing_vm_verified") is True, "lifecycle action requires an exact verified existing builder")
    vm = evidence.get("existing_vm")
    require(isinstance(vm, dict) and isinstance(vm.get("id"), str) and vm["id"],
            "lifecycle action requires an exact existing builder ID")
    require(vm.get("name") == contract["builder"]["name"], "lifecycle target name differs from the contract")
    state = vm.get("state", vm.get("status"))
    require(isinstance(state, str), "lifecycle target does not expose a state")
    state = state.lower()
    endpoint = compute_url(contract, f"/api/v1/vms/{vm['id']}")

    if action == "start":
        require(lifecycle_reason is None and not verified_return and confirm_delete is None,
                "start does not accept stop/delete confirmations")
        require(state in {"stopped", "running"}, "builder can only start from stopped state")
        if state == "running":
            return vm, False, "already-running"
        caller("POST", endpoint + "/set-power", headers, {"state": "power_on"})
        updated = dict(vm)
        updated["state"] = "starting"
        return updated, True, "start-requested"

    if action == "stop":
        require(contract["lifecycle"].get("stop_after_completed_or_unsuccessful_run") is True,
                "contract does not authorize lifecycle stop")
        require(lifecycle_reason in {"completed", "unsuccessful"},
                "stop requires --lifecycle-reason completed|unsuccessful")
        require(not verified_return and confirm_delete is None, "stop does not accept delete confirmations")
        require(state in {"running", "stopped"}, "builder can only stop from running state")
        if state == "stopped":
            return vm, False, "already-stopped"
        caller("POST", endpoint + "/set-power", headers, {"state": "power_off"})
        updated = dict(vm)
        updated["state"] = "stopping"
        return updated, True, "stop-requested"

    require(contract["lifecycle"].get("delete_after_verified_return") is True,
            "contract does not authorize lifecycle delete")
    require(lifecycle_reason is None, "delete does not accept a stop reason")
    require(verified_return, "delete requires --verified-return")
    require(confirm_delete == contract["builder"]["name"],
            "delete requires the exact builder name in --confirm-delete")
    require(state == "stopped", "builder must be stopped before delete")
    caller("DELETE", endpoint, headers, {})
    updated = dict(vm)
    updated["state"] = "deleting"
    return updated, True, "delete-requested"


def safe_inventory(contract: dict[str, Any], evidence: dict[str, Any], vm: dict[str, Any], applied: bool,
                   actions: list[str]) -> dict[str, Any]:
    builder = contract["builder"]
    return {
        "schema_version": 1,
        "task": contract["task"],
        "recorded_at": datetime.now(UTC).isoformat(),
        "mode": contract["mode"],
        "applied": applied,
        "actions": actions,
        "builder": {"name": builder["name"], "availability_zone_id": builder["availability_zone_id"],
                    "marketplace_image_id": builder["marketplace_image_id"], "marketplace_image_name": builder["marketplace_image_name"],
                    "flavor_id": builder["flavor_id"], "flavor_name": builder["flavor_name"],
                    "security_group_id": builder["security_group_id"], "subnet_id": builder["subnet_id"],
                    "public_ip_id": builder["public_ip_id"], "tags": builder["tags"],
                    "vcpu": builder["vcpu"], "memory_gib": builder["memory_gib"], "boot_disk_gib": builder["boot_disk_gib"]},
        "preflight": {"catalog_validation": evidence["catalog_validation"],
                      "existing_vm_verified": evidence["existing_vm_verified"],
                      "image_type": evidence["image"].get("type"),
                      "security_group_state": evidence["group"].get("state"), "tag_ids": evidence["tag_ids"]},
        "vm": {key: vm.get(key) for key in ("id", "name", "state", "status")},
        "secrets_redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    mutation = parser.add_mutually_exclusive_group()
    mutation.add_argument("--apply", action="store_true", help="create the VM after an exact preflight")
    mutation.add_argument("--start", action="store_true", help="start the exact stopped builder")
    mutation.add_argument("--stop", action="store_true", help="stop the exact running builder")
    mutation.add_argument("--delete", action="store_true", help="delete the exact stopped builder after verified return")
    mutation.add_argument("--reassert-builder-password", action="store_true",
                          help="set the external builder password on the exact existing tagged VM")
    parser.add_argument("--lifecycle-reason", choices=("completed", "unsuccessful"),
                        help="mandatory reason for --stop")
    parser.add_argument("--verified-return", action="store_true",
                        help="confirm that returned artifacts were independently verified before --delete")
    parser.add_argument("--confirm-delete", help="exact builder name; mandatory with --delete")
    parser.add_argument("--inventory-out", type=Path, default=None)
    args = parser.parse_args()
    try:
        contract = load_json(args.contract)
        validate_contract(contract)
        credentials = load_cloud_credentials(Path(contract["credential_reference"]["cloudru_access_path"]), contract["project_id"])
        token = bearer_token(contract, credentials)
        headers = {"Accept": "application/json", "Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        evidence = preflight(contract, headers)
        existing = evidence["existing_vm"]
        actions: list[str] = []
        if existing is not None:
            vm = existing
            applied = False
            require(existing.get("id"), "existing builder lacks ID")
        elif args.apply:
            access = ensure_builder_access(Path(contract["credential_reference"]["builder_access_path"]), contract["remote_access"]["username"])
            vm = create_vm(contract, headers, evidence, access)
            applied = True
            actions.append("created")
        else:
            vm = {"id": None, "name": contract["builder"]["name"], "state": "not-created"}
            applied = False
        lifecycle_action = "start" if args.start else "stop" if args.stop else "delete" if args.delete else None
        if lifecycle_action is not None:
            vm, applied, recorded_action = execute_lifecycle(
                contract, headers, evidence, lifecycle_action,
                lifecycle_reason=args.lifecycle_reason, verified_return=args.verified_return,
                confirm_delete=args.confirm_delete,
            )
            actions.append(recorded_action)
        else:
            require(args.lifecycle_reason is None, "--lifecycle-reason requires --stop")
            require(not args.verified_return and args.confirm_delete is None,
                    "--verified-return and --confirm-delete require --delete")
        if args.reassert_builder_password:
            require(existing is not None, "password can only be set on the exact existing tagged builder")
            access = ensure_builder_access(Path(contract["credential_reference"]["builder_access_path"]),
                                           contract["remote_access"]["username"])
            set_builder_password(contract, headers, vm, access)
            actions.append("builder-password-reasserted")
            applied = True
        inventory = safe_inventory(contract, evidence, vm, applied, actions)
        if args.inventory_out is not None:
            require(args.inventory_out.is_absolute(), "inventory output must be an absolute path")
            args.inventory_out.parent.mkdir(parents=True, exist_ok=True)
            temporary = args.inventory_out.with_suffix(args.inventory_out.suffix + ".tmp")
            temporary.write_text(canonical_json(inventory), encoding="utf-8")
            temporary.replace(args.inventory_out)
        print(canonical_json(inventory), end="")
        return 0
    except CloudProvisionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Read-only Cloud.ru M15-03 availability-zone and flavor inventory.

The only compute calls this tool can issue are GET requests for the paths
declared in the M15-03 contract.  Credentials are read only from an explicitly
passed external path, the bearer token stays in process memory, and persisted
output is a deliberately redacted selection record rather than a raw API dump.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

from validate_m15_03_cloud_contract import (  # noqa: E402
    DEFAULT_CONTRACT,
    ROOT,
    ContractError,
    load_contract,
    require,
    validate_shape,
)


class InventoryError(ContractError):
    """The read-only inventory must stop without exposing authentication data."""


JsonResponse = dict[str, Any] | list[dict[str, Any]]
HttpSender = Callable[[str, str, dict[str, str], bytes | None], JsonResponse]
APPROVED_PATHS = (
    "/api/v1/availability-zones", "/api/v1/flavors", "/api/v1/vms",
    "/api/v1/subnets", "/api/v1/security-groups", "/api/v1/floating-ips", "/api/v1/images",
)
RESOURCE_PATHS = ("/api/v1/subnets", "/api/v1/security-groups", "/api/v1/floating-ips", "/api/v1/images")
RESOURCE_QUERY_POLICIES = {
    "/api/v1/subnets": {"availability_zone_query_parameter": "availability_zone_ids", "project_id_required": True},
    "/api/v1/security-groups": {"availability_zone_query_parameter": "availability_zone_id", "project_id_required": True},
    "/api/v1/floating-ips": {"availability_zone_query_parameter": "availability_zone_id", "project_id_required": True},
    "/api/v1/images": {"availability_zone_query_parameter": "availability_zone_id", "project_id_required": True},
}
SENSITIVE_TEXT = re.compile(r"(?:access.?token|authorization|bearer|credential|password|private.?key|secret)", re.IGNORECASE)


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def validate_inventory_contract(contract: dict[str, Any]) -> None:
    validate_shape(contract)
    inventory = contract.get("read_only_inventory")
    require(isinstance(inventory, dict), "missing read-only inventory contract")
    require(inventory.get("official_api_reference") == "https://cloud.ru/docs/virtual-machines/ug/topics/api-ref",
            "official Cloud.ru API reference drifted")
    require(tuple(inventory.get("compute_get_paths", ())) == APPROVED_PATHS,
            "compute inventory allowlist drifted")
    require(inventory.get("query_parameter") == "project_id", "inventory must use project_id")
    require(inventory.get("flavor_availability_zone_query_parameter") == "availability_zone_id",
            "flavor availability-zone query parameter drifted")
    require(inventory.get("resource_query_policies") == RESOURCE_QUERY_POLICIES,
            "official resource query policy drifted")
    require(inventory.get("not_in_this_compute_openapi") == ["vpcs", "ssh_keys"],
            "unsupported Compute OpenAPI targets drifted")
    require(inventory.get("required_flavor") == {"vcpu": 4, "memory_gib": 16},
            "required builder flavor must remain exactly 4 vCPU / 16 GiB")


def load_external_credentials(path: Path, contract: dict[str, Any]) -> dict[str, str]:
    require(path.is_absolute(), "credentials path must be explicitly passed as an absolute external path")
    expected = Path(contract["credential_reference"]["path"])
    require(path.resolve() == expected.resolve(), "credentials path differs from the declared external reference")
    require(not path.is_symlink() and path.is_file(), "external credentials must be a regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    require(mode & 0o077 == 0, "external credentials must not be group/world accessible")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError("cannot read external Cloud.ru credential JSON") from exc
    require(isinstance(value, dict) and set(value) == {"key_id", "secret", "project_id"},
            "external credentials must contain only key_id, secret, project_id")
    require(all(isinstance(value[key], str) and value[key] for key in value),
            "external credentials contain an empty field")
    require(value["project_id"] == contract["project_id"], "credential project_id differs from contract")
    return {key: value[key] for key in ("key_id", "secret", "project_id")}


def approved_compute_url(contract: dict[str, Any], path: str, availability_zone_id: str | None = None) -> str:
    require(path in APPROVED_PATHS, "unapproved read-only inventory path")
    require(availability_zone_id is None or path == "/api/v1/flavors",
            "availability-zone scoping is allowed only for flavors")
    require(availability_zone_id is None or (isinstance(availability_zone_id, str) and availability_zone_id),
            "availability-zone identifier must be non-empty")
    endpoint = contract["api"]["compute_endpoint"].rstrip("/")
    query = {"project_id": contract["project_id"]}
    if availability_zone_id is not None:
        query[contract["read_only_inventory"]["flavor_availability_zone_query_parameter"]] = availability_zone_id
    url = endpoint + path + "?" + urlencode(query)
    validate_compute_request("GET", url, contract)
    return url


def validate_compute_request(method: str, url: str, contract: dict[str, Any]) -> None:
    require(method == "GET", "compute inventory permits GET only")
    actual = urlsplit(url)
    expected = urlsplit(contract["api"]["compute_endpoint"])
    require((actual.scheme, actual.netloc) == (expected.scheme, expected.netloc),
            "compute inventory host is not the official endpoint")
    require(actual.path in APPROVED_PATHS, "compute inventory path is not allowlisted")
    query = parse_qs(actual.query, keep_blank_values=True)
    expected = {"project_id": [contract["project_id"]]}
    zone_parameter = contract["read_only_inventory"]["flavor_availability_zone_query_parameter"]
    if actual.path == "/api/v1/flavors" and zone_parameter in query:
        require(len(query[zone_parameter]) == 1 and bool(query[zone_parameter][0]),
                "availability-zone query needs one non-empty declared identifier")
        expected[zone_parameter] = query[zone_parameter]
    require(query == expected, "compute inventory query must contain only declared project and availability-zone identifiers")


def urllib_sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> JsonResponse:
    try:
        request = Request(url, data=body, headers=headers, method=method)
        with urlopen(request, timeout=30) as response:  # nosec B310: endpoints are allowlisted before use
            payload = response.read()
    except HTTPError as exc:
        raise InventoryError(f"approved Cloud.ru request returned HTTP {exc.code}") from exc
    except (URLError, OSError) as exc:
        raise InventoryError("approved Cloud.ru request failed") from exc
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("approved Cloud.ru response is not JSON") from exc
    require(isinstance(value, dict) or (isinstance(value, list) and all(isinstance(item, dict) for item in value)),
            "approved Cloud.ru response must be a JSON object or object list")
    return value


def retrieve_bearer(contract: dict[str, Any], credentials: dict[str, str], sender: HttpSender) -> str:
    endpoint = contract["api"]["iam_token_endpoint"]
    require(endpoint == "https://iam.api.cloud.ru/api/v1/auth/token", "IAM endpoint drifted")
    body = json.dumps({"keyId": credentials["key_id"], "secret": credentials["secret"]}, separators=(",", ":")).encode()
    response = sender("POST", endpoint, {"Content-Type": "application/json"}, body)
    require(isinstance(response, dict), "IAM response must be a JSON object")
    token = response.get("access_token")
    require(isinstance(token, str) and token, "IAM response lacks access_token")
    return token


def response_items(response: JsonResponse, keys: tuple[str, ...], label: str) -> list[dict[str, Any]]:
    if isinstance(response, list):
        return response
    for key in keys:
        value = response.get(key)
        if isinstance(value, list):
            require(all(isinstance(item, dict) for item in value), f"{label} response contains a non-object item")
            return value
    raise InventoryError(f"{label} response lacks an item list")


def first_integer(value: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool):
            return item
    return None


def flavor_memory_gib(value: dict[str, Any]) -> int | None:
    # Cloud.ru's VM flavor reference describes RAM in GiB.  The live list uses
    # ``ram``; byte/MiB fields are handled only under their explicit names.
    direct = first_integer(value, ("memory_gib", "ram_gib", "memory", "ram"))
    if direct is not None:
        return direct
    mib = first_integer(value, ("ram_mb", "memory_mb"))
    if mib is not None and mib % 1024 == 0:
        return mib // 1024
    return None


def redact_zone(value: dict[str, Any]) -> dict[str, str]:
    identifier = value.get("id")
    name = value.get("name")
    require(isinstance(identifier, str) and identifier and isinstance(name, str) and name,
            "availability-zone response lacks non-secret id/name")
    return {"id": identifier, "name": name}


def redact_flavor(value: dict[str, Any]) -> dict[str, Any] | None:
    identifier = value.get("id")
    name = value.get("name")
    vcpu = first_integer(value, ("vcpu", "vcpus", "cpu"))
    memory_gib = flavor_memory_gib(value)
    if not (isinstance(identifier, str) and identifier and isinstance(name, str) and name
            and isinstance(vcpu, int) and isinstance(memory_gib, int)):
        return None
    return {"id": identifier, "memory_gib": memory_gib, "name": name, "vcpu": vcpu}


def redact_tags(value: object) -> list[str]:
    raw = value if isinstance(value, list) else list(value.items()) if isinstance(value, dict) else []
    tags: list[str] = []
    for item in raw:
        rendered = item if isinstance(item, str) else "=".join(item) if isinstance(item, tuple) and len(item) == 2 and all(isinstance(part, str) for part in item) else ""
        if rendered and SENSITIVE_TEXT.search(rendered) is None:
            tags.append(rendered)
    return sorted(set(tags))


def named_reference(value: object, fallback_id: object) -> dict[str, str] | None:
    if isinstance(value, dict):
        identifier = value.get("id")
        name = value.get("name")
        if isinstance(identifier, str) and identifier:
            result = {"id": identifier}
            if isinstance(name, str) and name:
                result["name"] = name
            return result
    if isinstance(value, str) and value:
        return {"id": value}
    if isinstance(fallback_id, str) and fallback_id:
        return {"id": fallback_id}
    return None


def redact_vm(value: dict[str, Any]) -> dict[str, Any] | None:
    identifier = value.get("id")
    name = value.get("name")
    status = value.get("status", value.get("state"))
    if not (isinstance(identifier, str) and identifier and isinstance(name, str) and name and isinstance(status, str) and status):
        return None
    availability_zone = named_reference(value.get("availability_zone"), value.get("availability_zone_id"))
    flavor = redact_flavor(value["flavor"]) if isinstance(value.get("flavor"), dict) else None
    if flavor is None:
        flavor = named_reference(value.get("flavor"), value.get("flavor_id"))
    return {"availability_zone": availability_zone, "flavor": flavor, "id": identifier,
            "name": name, "status": status, "tags": redact_tags(value.get("tags"))}


def redact_named_resource(value: dict[str, Any], label: str) -> dict[str, Any] | None:
    """Keep only identifiers, names, status and AZ; never network/address details."""
    identifier = value.get("id")
    name = value.get("name")
    if not (isinstance(identifier, str) and identifier and isinstance(name, str) and name):
        return None
    status = value.get("status", value.get("state"))
    result: dict[str, Any] = {"id": identifier, "name": name}
    if isinstance(status, str) and status:
        result["status"] = status
    availability_zone = named_reference(value.get("availability_zone"), value.get("availability_zone_id"))
    if availability_zone is not None:
        result["availability_zone"] = availability_zone
    return result


def redact_network_resources(responses: dict[str, JsonResponse]) -> dict[str, list[dict[str, Any]]]:
    labels = {
        "/api/v1/subnets": ("subnets", "subnet"),
        "/api/v1/security-groups": ("security_groups", "security-groups"),
        "/api/v1/floating-ips": ("floating_ips", "floating-ips"),
        "/api/v1/images": ("images", "images"),
    }
    result: dict[str, list[dict[str, Any]]] = {}
    for path, (response_key, label) in labels.items():
        items = response_items(responses[path], ("items", response_key), label)
        result[response_key] = sorted(
            (item for item in (redact_named_resource(value, label) for value in items) if item is not None),
            key=lambda item: (item["name"], item["id"]),
        )
    return result


def is_stopped_ubuntu(vm: dict[str, Any]) -> bool:
    identity = " ".join([vm["name"], *vm["tags"]]).lower()
    stopped = vm["status"].lower() in {"stopped", "shutoff", "powered_off", "off"}
    return stopped and "ubuntu" in identity


def has_good_bear_tag(vm: dict[str, Any]) -> bool:
    identity = " ".join(vm["tags"]).lower().replace("-", " ").replace("_", " ")
    return "goodbear" in identity or "good bear" in identity


def flavor_selection_evidence(flavors: list[dict[str, Any]], requirement: dict[str, int]) -> dict[str, Any]:
    normalized = sorted((item for item in (redact_flavor(value) for value in flavors) if item is not None),
                        key=lambda item: (item["name"], item["id"]))
    matches = [item for item in normalized if item["vcpu"] == requirement["vcpu"]
               and item["memory_gib"] == requirement["memory_gib"]]
    nearby = [item for item in normalized if item["vcpu"] == requirement["vcpu"]
              and item["memory_gib"] != requirement["memory_gib"]]
    selection = "unique-match" if len(matches) == 1 else "no-match" if not matches else "ambiguous-match"
    return {"candidates": matches, "nearby_4vcpu": nearby, "required": requirement, "status": selection}


def collect_inventory(contract: dict[str, Any], credentials: dict[str, str], sender: HttpSender) -> dict[str, Any]:
    validate_inventory_contract(contract)
    bearer = retrieve_bearer(contract, credentials, sender)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {bearer}"}
    zones_url = approved_compute_url(contract, APPROVED_PATHS[0])
    zones = response_items(sender("GET", zones_url, headers, None), ("items", "availability_zones"), "availability-zone")
    redacted_zones = sorted((redact_zone(item) for item in zones), key=lambda item: (item["name"], item["id"]))
    requirement = contract["read_only_inventory"]["required_flavor"]
    global_flavors = response_items(sender("GET", approved_compute_url(contract, APPROVED_PATHS[1]), headers, None),
                                    ("items", "flavors"), "global flavor")
    by_zone = []
    for zone in redacted_zones:
        flavors = response_items(sender("GET", approved_compute_url(contract, APPROVED_PATHS[1], zone["id"]), headers, None),
                                 ("items", "flavors"), f"flavor for {zone['id']}")
        by_zone.append({"availability_zone": zone, "selection": flavor_selection_evidence(flavors, requirement)})
    raw_vms = response_items(sender("GET", approved_compute_url(contract, APPROVED_PATHS[2]), headers, None),
                             ("items", "vms"), "virtual-machine")
    redacted_vms = [item for item in (redact_vm(value) for value in raw_vms) if item is not None]
    candidates = sorted((item for item in redacted_vms if is_stopped_ubuntu(item)),
                        key=lambda item: (item["name"], item["id"]))
    vm_status = "unique-match" if len(candidates) == 1 else "no-match" if not candidates else "ambiguous-match"
    tag_status = "not-applicable" if not candidates else "tagged" if all(has_good_bear_tag(item) for item in candidates) else "untagged"
    resource_responses = {
        path: sender("GET", approved_compute_url(contract, path), headers, None)
        for path in RESOURCE_PATHS
    }
    return {
        "api": {
            "compute_endpoint": contract["api"]["compute_endpoint"],
            "get_paths": list(APPROVED_PATHS),
            "flavor_availability_zone_query_parameter": contract["read_only_inventory"]["flavor_availability_zone_query_parameter"],
        },
        "availability_zones": redacted_zones,
        "flavor_selection": flavor_selection_evidence(global_flavors, requirement),
        "flavor_selection_by_availability_zone": by_zone,
        "network_and_image_inventory": redact_network_resources(resource_responses),
        "not_in_this_compute_openapi": contract["read_only_inventory"]["not_in_this_compute_openapi"],
        "stopped_ubuntu_builder_parity": {
            "candidates": candidates,
            "mutation_eligibility": "tagged-only; untagged candidates are inventory evidence only",
            "status": vm_status,
            "tag_status": tag_status,
        },
        "project_id": contract["project_id"],
        "redaction": "Sensitive values and raw responses are excluded from this record.",
        "schema_version": 1,
        "task": "GB100-M15-03",
    }


def validate_output_path(path: Path) -> Path:
    resolved = path.resolve()
    allowed = (ROOT / "build").resolve()
    try:
        resolved.relative_to(allowed)
    except ValueError as exc:
        raise InventoryError("inventory output must remain under project build/") from exc
    require(resolved.name.startswith("m15-03-") and resolved.suffix == ".json",
            "inventory output needs a new m15-03-*.json filename")
    require(not resolved.exists(), "refusing to overwrite an inventory record")
    return resolved


def persist_inventory(path: Path, inventory: dict[str, Any]) -> Path:
    target = validate_output_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name("." + target.name + ".tmp")
    try:
        temporary.write_text(canonical_json(inventory), encoding="utf-8")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description="GET-only, redacted Cloud.ru M15-03 inventory")
    parser.add_argument("--credentials", type=Path, required=True,
                        help="explicit absolute external Cloud.ru credential JSON path")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path,
                        help="new project build/m15-03-*.json path; otherwise print redacted JSON")
    args = parser.parse_args()
    try:
        contract = load_contract(args.contract)
        validate_inventory_contract(contract)
        credentials = load_external_credentials(args.credentials, contract)
        inventory = collect_inventory(contract, credentials, urllib_sender)
        if args.output:
            print(f"redacted M15-03 inventory persisted: {persist_inventory(args.output, inventory)}", flush=True)
        else:
            print(canonical_json(inventory), end="", flush=True)
        return 0
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

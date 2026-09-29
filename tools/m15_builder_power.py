#!/usr/bin/env python3
"""Narrow power control for the one recorded M15 Ubuntu build VM.

This tool deliberately has no generic VM, project, endpoint, credential-path,
or desired-state arguments.  It authenticates with Cloud.ru IAM, reads the VM
before a mutation, and polls the same VM afterwards.  Every identity check is
fail-closed and errors intentionally omit response bodies and credentials.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import sys
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen


CONFIG_PATH = Path("/home/valery/.config/goodbear/cloudru-access.json")
IAM_TOKEN_ENDPOINT = "https://iam.api.cloud.ru/api/v1/auth/token"
COMPUTE_ENDPOINT = "https://compute.api.cloud.ru"
VM_ID = "4695a2dd-0e51-4c4b-bdaf-5c1bd03be181"
VM_NAME = "Ubuntu-4cpu-32ram"
PROJECT_ID = "ed75ec2f-6b92-4687-aabf-e0e41655b03b"
PUBLIC_IP = "176.108.241.13"
MAX_POLLS = 12
POLL_SECONDS = 2.0

STOPPED_STATES = frozenset({"stopped", "shutoff", "powered_off", "off"})
RUNNING_STATES = frozenset({"running", "active", "powered_on", "on"})
STATUS_STATES = STOPPED_STATES | RUNNING_STATES | frozenset({"starting", "stopping", "paused", "suspended", "rebooting", "error"})
HttpSender = Callable[[str, str, dict[str, str], bytes | None], dict[str, Any]]


class PowerControlError(RuntimeError):
    """A safe failure that contains no Cloud.ru response or credential data."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PowerControlError(message)


def load_credentials() -> dict[str, str]:
    """Read only the pinned external IAM credential file, with strict permissions."""
    path = CONFIG_PATH
    require(path.is_absolute() and not path.is_symlink() and path.is_file(),
            "Cloud.ru credential file must be the pinned regular file")
    require(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0,
            "Cloud.ru credential file must not be group/world accessible")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PowerControlError("cannot read Cloud.ru credential JSON") from exc
    require(isinstance(value, dict) and set(value) == {"key_id", "secret", "project_id"},
            "Cloud.ru credential JSON must contain only key_id, secret, project_id")
    require(all(isinstance(value[key], str) and value[key] for key in value),
            "Cloud.ru credential JSON contains an empty field")
    require(value["project_id"] == PROJECT_ID, "credential project does not match the pinned builder project")
    return {key: value[key] for key in ("key_id", "secret", "project_id")}


def vm_url(*, action: bool = False) -> str:
    path = f"/api/v1/vms/{VM_ID}" + ("/set-power" if action else "")
    return COMPUTE_ENDPOINT + path + "?" + urlencode({"project_id": PROJECT_ID})


def validate_request(method: str, url: str, body: bytes | None) -> None:
    actual = urlsplit(url)
    expected = urlsplit(COMPUTE_ENDPOINT)
    require((actual.scheme, actual.netloc) == (expected.scheme, expected.netloc),
            "Cloud.ru compute host is not the pinned official endpoint")
    query = parse_qs(actual.query, keep_blank_values=True)
    require(query == {"project_id": [PROJECT_ID]}, "Cloud.ru request must use only the pinned project")
    get_path = f"/api/v1/vms/{VM_ID}"
    power_path = get_path + "/set-power"
    if method == "GET":
        require(actual.path == get_path and body is None, "only the pinned VM GET is permitted")
        return
    require(method == "POST" and actual.path == power_path, "only pinned VM set-power POST is permitted")
    try:
        payload = json.loads((body or b"").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PowerControlError("power request has an invalid body") from exc
    require(payload in ({"state": "power_on"}, {"state": "power_off"}),
            "power request must contain one approved state")


def urllib_sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict[str, Any]:
    """Send one already-validated request without ever rendering its contents."""
    try:
        request = Request(url, data=body, headers=headers, method=method)
        with urlopen(request, timeout=30) as response:  # nosec B310: caller validates the endpoint
            status = response.status
            content_type = response.headers.get("Content-Type")
            payload = response.read()
    except HTTPError as exc:
        metadata = safe_response_metadata(exc.code, exc.headers.get("Content-Type") if exc.headers else None)
        raise PowerControlError(f"approved Cloud.ru request returned {metadata}") from None
    except (URLError, OSError):
        raise PowerControlError("approved Cloud.ru request failed") from None
    # Cloud.ru's successful power mutation is HTTP 204 No Content.  Keep the
    # sender's stable object-shaped contract for callers, but do not attempt
    # to decode an empty response as JSON.  A non-empty 204 is rejected so a
    # malformed or unexpected response cannot be silently accepted.
    if status == 204:
        require(not payload, "approved Cloud.ru 204 response must be empty")
        return {}
    try:
        response = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PowerControlError(f"approved Cloud.ru response is not JSON ({safe_response_metadata(status, content_type)})") from None
    require(isinstance(response, dict), "approved Cloud.ru response must be a JSON object")
    return response


def safe_response_metadata(status: object, content_type: object) -> str:
    """Show only numeric status and a known media type, never arbitrary header text."""
    status_label = str(status) if type(status) is int and 100 <= status <= 599 else "unknown"
    media_type = content_type.split(";", 1)[0].strip().lower() if isinstance(content_type, str) else ""
    if media_type not in {"application/json", "application/problem+json", "text/html", "text/plain"}:
        media_type = "unknown"
    return f"HTTP {status_label}; Content-Type: {media_type}"


def retrieve_bearer(credentials: dict[str, str], sender: HttpSender) -> str:
    """Use the same keyId/secret Cloud.ru IAM exchange as the inventory tool."""
    body = json.dumps({"keyId": credentials["key_id"], "secret": credentials["secret"]},
                      separators=(",", ":")).encode("utf-8")
    response = sender("POST", IAM_TOKEN_ENDPOINT, {"Content-Type": "application/json"}, body)
    token = response.get("access_token")
    require(isinstance(token, str) and token, "IAM response lacks access_token")
    return token


def vm_from_response(response: dict[str, Any]) -> dict[str, Any]:
    vm = response.get("vm", response)
    require(isinstance(vm, dict), "VM response lacks a VM object")
    return vm


def project_from_vm(vm: dict[str, Any]) -> str | None:
    direct = vm.get("project_id")
    if isinstance(direct, str) and direct:
        return direct
    project = vm.get("project")
    if isinstance(project, dict) and isinstance(project.get("id"), str) and project["id"]:
        return project["id"]
    return None


def status_from_vm(vm: dict[str, Any]) -> str:
    status = vm.get("status", vm.get("state"))
    require(isinstance(status, str) and status, "VM response lacks a status")
    return status.lower()


def public_ips_from_vm(vm: dict[str, Any]) -> set[str]:
    """Extract only explicit network-address fields needed for the pinned identity check."""
    possible: set[str] = set()

    def add(value: object) -> None:
        if isinstance(value, str) and value:
            possible.add(value)
        elif isinstance(value, dict):
            for key in ("ip", "ip_address", "address", "public_ip", "floating_ip", "external_ip"):
                add(value.get(key))
            for key in ("ips", "addresses", "fixed_ips"):
                add(value.get(key))
        elif isinstance(value, list):
            for item in value:
                add(item)

    for key in ("public_ip", "public_ips", "floating_ip", "floating_ips", "external_ip", "external_ips",
                "interfaces", "addresses", "networks"):
        add(vm.get(key))
    return possible


def validate_vm_identity(vm: dict[str, Any], allowed_states: frozenset[str]) -> str:
    require(vm.get("id") == VM_ID, "VM identity does not match the pinned Ubuntu builder")
    require(project_from_vm(vm) == PROJECT_ID, "VM project does not match the pinned builder project")
    require(vm.get("name") == VM_NAME, "VM name does not match the pinned Ubuntu builder")
    require(PUBLIC_IP in public_ips_from_vm(vm), "VM public IP does not match the pinned Ubuntu builder")
    status = status_from_vm(vm)
    require(status in allowed_states, "VM status conflicts with the requested power transition")
    return status


def fetch_vm(headers: dict[str, str], sender: HttpSender) -> dict[str, Any]:
    url = vm_url()
    validate_request("GET", url, None)
    return vm_from_response(sender("GET", url, headers, None))


def execute(action: str, credentials: dict[str, str], sender: HttpSender,
            sleep: Callable[[float], None] = time.sleep) -> str:
    """Read, mutate once, then bounded-poll until the requested terminal state."""
    require(action in {"power_on", "power_off"}, "requested action is not approved")
    token = retrieve_bearer(credentials, sender)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    initial_states = STOPPED_STATES if action == "power_on" else RUNNING_STATES
    desired_states = RUNNING_STATES if action == "power_on" else STOPPED_STATES
    transitional_states = frozenset({"starting"}) if action == "power_on" else frozenset({"stopping"})
    validate_vm_identity(fetch_vm(headers, sender), initial_states)

    body = json.dumps({"state": action}, separators=(",", ":")).encode("utf-8")
    url = vm_url(action=True)
    validate_request("POST", url, body)
    response = sender("POST", url, {**headers, "Content-Type": "application/json"}, body)
    require(isinstance(response, dict), "power response must be a JSON object")

    for attempt in range(MAX_POLLS):
        if attempt:
            sleep(POLL_SECONDS)
        vm = fetch_vm(headers, sender)
        status = validate_vm_identity(vm, desired_states | transitional_states)
        if status in desired_states:
            return status
    raise PowerControlError("VM did not reach the requested power state within the bounded polling window")


def status_ubuntu(credentials: dict[str, str], sender: HttpSender) -> str:
    """Read and verify the pinned builder without making a compute mutation."""
    token = retrieve_bearer(credentials, sender)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    return validate_vm_identity(fetch_vm(headers, sender), STATUS_STATES)


def parse_action(argv: list[str] | None = None) -> str:
    parser = argparse.ArgumentParser(description="Power-control only the pinned M15 Ubuntu builder")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--start-ubuntu", action="store_true", help="start the pinned stopped Ubuntu builder")
    actions.add_argument("--stop-ubuntu", action="store_true", help="stop the pinned running Ubuntu builder")
    actions.add_argument("--status-ubuntu", action="store_true", help="read and verify the pinned Ubuntu builder status")
    args = parser.parse_args(argv)
    if args.start_ubuntu:
        return "power_on"
    if args.stop_ubuntu:
        return "power_off"
    return "status"


def main(argv: list[str] | None = None) -> int:
    try:
        action = parse_action(argv)
        credentials = load_credentials()
        if action == "status":
            status = status_ubuntu(credentials, urllib_sender)
            print("Pinned M15 Ubuntu builder verified; "
                  f"name match: yes; status: {status}; project match: yes; public-IP match: yes.",
                  flush=True)
            return 0
        final_status = execute(action, credentials, urllib_sender)
        verb = "started" if action == "power_on" else "stopped"
        print(f"Pinned M15 Ubuntu builder {verb}; verified status: {final_status}.", flush=True)
        return 0
    except PowerControlError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

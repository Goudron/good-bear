#!/usr/bin/env python3
"""Resize only the verified primary disk of the pinned M15 Ubuntu builder.

The Cloud.ru disk API and request shape are specified at:
https://cloud.ru/docs/virtual-machines/ug/topics/api-ref
No VM/disk ID, project, endpoint, credential path, or size is user-selectable.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Callable
from urllib.parse import urlsplit

import m15_builder_power as power


TARGET_GB = 250
MAX_POLLS = 30
POLL_SECONDS = 5.0
READY_STATES = frozenset({"in_use"})
PROGRESS_STATES = READY_STATES | frozenset({"updating"})
ALLOWED_VM_STATES = power.RUNNING_STATES | power.STOPPED_STATES
HttpSender = power.HttpSender
ResizeError = power.PowerControlError


def require(condition: bool, message: str) -> None:
    power.require(condition, message)


def disk_url(disk_id: str) -> str:
    require(isinstance(disk_id, str) and len(disk_id) == 36 and
            all(char in "0123456789abcdef-" for char in disk_id.lower()) and
            [index for index, char in enumerate(disk_id) if char == "-"] == [8, 13, 18, 23],
            "primary disk ID is not a UUID")
    return f"{power.COMPUTE_ENDPOINT}/api/v1/disks/{disk_id}"


def validate_disk_request(method: str, url: str, body: bytes | None, disk_id: str) -> None:
    actual = urlsplit(url)
    expected = urlsplit(power.COMPUTE_ENDPOINT)
    require((actual.scheme, actual.netloc) == (expected.scheme, expected.netloc) and
            actual.path == f"/api/v1/disks/{disk_id}" and
            not actual.query and not actual.fragment and not actual.username and not actual.password,
            "disk request must use only the pinned official endpoint and discovered disk")
    if method == "GET":
        require(body is None, "disk GET cannot contain a body")
        return
    require(method == "PUT" and body == b'{"size":250}',
            "disk mutation must be exactly PUT with size 250 GB")


def primary_disk_from_vm(vm: dict[str, Any]) -> dict[str, Any]:
    power.validate_vm_identity(vm, ALLOWED_VM_STATES)
    disks = vm.get("disks")
    require(isinstance(disks, list) and disks, "VM response lacks a disk list")
    primaries = [item for item in disks if isinstance(item, dict) and item.get("primary") is True]
    require(len(primaries) == 1, "VM must have exactly one primary disk")
    primary = primaries[0]
    require(isinstance(primary.get("id"), str), "primary disk lacks an ID")
    disk_url(primary["id"])
    require(type(primary.get("size")) is int and 0 < primary["size"] <= TARGET_GB,
            "VM primary disk size is missing or exceeds target")
    return primary


def validated_disk(disk: dict[str, Any], vm_primary: dict[str, Any], *,
                   allowed_states: frozenset[str], allow_target: bool) -> tuple[int, str]:
    disk_id = vm_primary["id"]
    require(disk.get("id") == disk_id, "disk response does not match VM primary disk")
    project = disk.get("project")
    require(isinstance(project, dict) and project.get("id") == power.PROJECT_ID,
            "disk project does not match the pinned builder project")
    require(disk.get("name") == vm_primary.get("name"), "disk name does not match VM primary disk")
    require(disk.get("bootable") is True, "discovered disk is not bootable")
    require(disk.get("readonly") is False, "discovered disk is read-only")
    require(disk.get("shared") is False, "discovered disk is shared")
    attachments = disk.get("vms")
    require(isinstance(attachments, list) and len(attachments) == 1 and
            isinstance(attachments[0], dict) and
            attachments[0].get("id") == power.VM_ID and
            attachments[0].get("name") == power.VM_NAME and
            attachments[0].get("primary") is True,
            "disk attachment is not exclusively the pinned primary VM")
    state = disk.get("state")
    require(isinstance(state, str) and state.lower() in allowed_states,
            "disk state does not permit this resize stage")
    size = disk.get("size")
    require(type(size) is int and 0 < size <= TARGET_GB,
            "disk size is missing or exceeds target")
    require(allow_target or size < TARGET_GB, "primary disk is already at the target size")
    return size, state.lower()


def fetch_disk(headers: dict[str, str], sender: HttpSender, disk_id: str) -> dict[str, Any]:
    url = disk_url(disk_id)
    validate_disk_request("GET", url, None, disk_id)
    response = sender("GET", url, headers, None)
    require(isinstance(response, dict), "disk response must be a JSON object")
    return response


def inspect(credentials: dict[str, str], sender: HttpSender) -> tuple[str, int, str]:
    """Read-only identity and disk checks for a reviewable resize decision."""
    token = power.retrieve_bearer(credentials, sender)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    vm = power.fetch_vm(headers, sender)
    primary = primary_disk_from_vm(vm)
    size, state = validated_disk(fetch_disk(headers, sender, primary["id"]), primary,
                                 allowed_states=READY_STATES, allow_target=True)
    require(primary["size"] == size, "VM and disk API disagree on primary disk size")
    return primary["id"], size, state


def resize(credentials: dict[str, str], sender: HttpSender,
           sleep: Callable[[float], None] = time.sleep,
           progress: Callable[[str], None] = lambda _message: None) -> tuple[str, int]:
    """Read VM and disk, mutate only that disk once, then bounded-poll both."""
    token = power.retrieve_bearer(credentials, sender)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    vm = power.fetch_vm(headers, sender)
    primary = primary_disk_from_vm(vm)
    disk_id = primary["id"]
    initial_size, _ = validated_disk(fetch_disk(headers, sender, disk_id), primary,
                                     allowed_states=READY_STATES, allow_target=False)
    require(primary["size"] == initial_size, "VM and disk API disagree on primary disk size")
    progress(f"Verified primary disk {disk_id}: {initial_size} GB; requesting 250 GB.")

    body = json.dumps({"size": TARGET_GB}, separators=(",", ":")).encode("ascii")
    url = disk_url(disk_id)
    validate_disk_request("PUT", url, body, disk_id)
    result = sender("PUT", url, {**headers, "Content-Type": "application/json"}, body)
    require(isinstance(result, dict) and result.get("id") == disk_id,
            "disk update response does not match the pinned disk")
    progress("Disk resize accepted; polling the pinned VM and disk.")

    for attempt in range(MAX_POLLS):
        if attempt:
            sleep(POLL_SECONDS)
        current_vm = power.fetch_vm(headers, sender)
        current_primary = primary_disk_from_vm(current_vm)
        require(current_primary["id"] == disk_id, "VM primary disk changed during resize")
        current_size, state = validated_disk(fetch_disk(headers, sender, disk_id), current_primary,
                                             allowed_states=PROGRESS_STATES, allow_target=True)
        require(initial_size <= current_size <= TARGET_GB,
                "disk size regressed during resize")
        require(current_primary["size"] in {initial_size, current_size, TARGET_GB},
                "VM and disk API disagree during resize")
        progress(f"Resize poll {attempt + 1}/{MAX_POLLS}: disk {current_size} GB, state {state}; "
                 f"VM reports {current_primary['size']} GB.")
        if current_size == TARGET_GB and state in READY_STATES and current_primary["size"] == TARGET_GB:
            return disk_id, TARGET_GB
    raise ResizeError("primary disk did not reach 250 GB within bounded polling")


def parse_action(argv: list[str] | None = None) -> str:
    parser = argparse.ArgumentParser(description="Inspect or resize only the pinned M15 Ubuntu primary disk")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--inspect-ubuntu-disk", action="store_true", help="verify VM and disk without mutation")
    actions.add_argument("--resize-ubuntu-disk-to", type=int, choices=[TARGET_GB], metavar="250",
                         help="resize verified primary disk to exactly 250 GB")
    args = parser.parse_args(argv)
    return "inspect" if args.inspect_ubuntu_disk else "resize"


def main(argv: list[str] | None = None) -> int:
    try:
        action = parse_action(argv)
        credentials = power.load_credentials()
        if action == "inspect":
            disk_id, size, state = inspect(credentials, power.urllib_sender)
            print(f"Pinned Ubuntu primary disk verified: {disk_id}; size: {size} GB; state: {state}.", flush=True)
        else:
            disk_id, size = resize(credentials, power.urllib_sender,
                                   progress=lambda message: print(message, flush=True))
            print(f"Pinned Ubuntu primary disk {disk_id} resized and verified: {size} GB.", flush=True)
        return 0
    except ResizeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

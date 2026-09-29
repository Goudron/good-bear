#!/usr/bin/env python3
"""Resize the pinned M15 Ubuntu builder to the sole approved 64-GiB flavor."""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Callable
from urllib.parse import urlsplit

import m15_builder_power as power


TARGET_FLAVOR_ID = "1e332e48-ddbd-402b-aff5-66c87e411f06"
TARGET_FLAVOR_NAME = "gen-4-64"
TARGET_CPU = 4
TARGET_RAM_GIB = 64
MAX_POLLS = 30
POLL_SECONDS = 5.0
PROGRESS_STATES = power.STATUS_STATES | frozenset({"updating"})
HttpSender = power.HttpSender
ResizeError = power.PowerControlError


def require(condition: bool, message: str) -> None:
    power.require(condition, message)


def validate_request(method: str, url: str, body: bytes | None) -> None:
    actual = urlsplit(url)
    expected = urlsplit(power.COMPUTE_ENDPOINT)
    require((actual.scheme, actual.netloc) == (expected.scheme, expected.netloc) and
            actual.path == f"/api/v1/vms/{power.VM_ID}" and
            actual.query == urlsplit(power.vm_url()).query and not actual.fragment and
            not actual.username and not actual.password,
            "flavor request must use only the pinned VM endpoint")
    if method == "GET":
        require(body is None, "flavor GET cannot contain a body")
        return
    require(method == "PUT" and body ==
            b'{"flavor_id":"1e332e48-ddbd-402b-aff5-66c87e411f06"}',
            "flavor mutation must be exactly the approved 4-vCPU/64-GiB flavor")


def fetch_vm(headers: dict[str, str], sender: HttpSender) -> dict[str, Any]:
    url = power.vm_url()
    validate_request("GET", url, None)
    return power.vm_from_response(sender("GET", url, headers, None))


def flavor_from_vm(vm: dict[str, Any], states: frozenset[str], *, allow_target: bool) -> str:
    status = power.validate_vm_identity(vm, states)
    flavor = vm.get("flavor")
    require(isinstance(flavor, dict), "VM response lacks a flavor")
    flavor_id = flavor.get("id")
    name = flavor.get("name")
    cpu = flavor.get("cpu")
    ram = flavor.get("ram")
    require(isinstance(flavor_id, str) and isinstance(name, str) and type(cpu) is int and type(ram) is int,
            "VM flavor has malformed fields")
    if flavor_id == TARGET_FLAVOR_ID:
        require(allow_target and (name, cpu, ram) == (TARGET_FLAVOR_NAME, TARGET_CPU, TARGET_RAM_GIB),
                "target flavor attributes do not match the approved builder shape")
    else:
        require(not allow_target and flavor_id == "800df814-9478-49ad-99f5-086c3d85a19e" and
                (name, cpu, ram) == ("gen-4-32", 4, 32),
                "builder does not have the expected source flavor")
    return status


def inspect(credentials: dict[str, str], sender: HttpSender) -> str:
    token = power.retrieve_bearer(credentials, sender)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    return flavor_from_vm(fetch_vm(headers, sender), power.STOPPED_STATES, allow_target=True)


def resize(credentials: dict[str, str], sender: HttpSender,
           sleep: Callable[[float], None] = time.sleep,
           progress: Callable[[str], None] = lambda _message: None) -> None:
    token = power.retrieve_bearer(credentials, sender)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    initial = fetch_vm(headers, sender)
    flavor_from_vm(initial, power.STOPPED_STATES, allow_target=False)
    progress("Verified the stopped pinned builder at gen-4-32; requesting gen-4-64.")
    body = json.dumps({"flavor_id": TARGET_FLAVOR_ID}, separators=(",", ":")).encode("ascii")
    url = power.vm_url()
    validate_request("PUT", url, body)
    reply = power.vm_from_response(sender("PUT", url, {**headers, "Content-Type": "application/json"}, body))
    power.validate_vm_identity(reply, PROGRESS_STATES)
    progress("Flavor change accepted; polling the pinned builder.")
    for attempt in range(MAX_POLLS):
        if attempt:
            sleep(POLL_SECONDS)
        vm = fetch_vm(headers, sender)
        status = flavor_from_vm(vm, PROGRESS_STATES, allow_target=True)
        progress(f"Flavor poll {attempt + 1}/{MAX_POLLS}: VM status {status}.")
        if status in power.STOPPED_STATES:
            return
    raise ResizeError("builder did not return to stopped with the approved flavor within bounded polling")


def parse_action(argv: list[str] | None = None) -> str:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--inspect-ubuntu-flavor", action="store_true")
    actions.add_argument("--resize-ubuntu-to-64gib", action="store_true")
    args = parser.parse_args(argv)
    return "inspect" if args.inspect_ubuntu_flavor else "resize"


def main(argv: list[str] | None = None) -> int:
    try:
        action = parse_action(argv)
        credentials = power.load_credentials()
        if action == "inspect":
            status = inspect(credentials, power.urllib_sender)
            print(f"Pinned Ubuntu builder flavor verified: {TARGET_FLAVOR_NAME}; status: {status}.", flush=True)
        else:
            resize(credentials, power.urllib_sender, progress=lambda message: print(message, flush=True))
            print(f"Pinned Ubuntu builder resized and verified: {TARGET_FLAVOR_NAME}.", flush=True)
        return 0
    except ResizeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

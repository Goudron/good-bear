#!/usr/bin/env python3
"""Stage deterministic, non-LTO Good Bear M12 release-build inputs.

The tool has no downloader by design.  Fetching is a separately controlled
operation; this stage only reads already-declared local inputs, checks their
hashes, and atomically promotes a complete input snapshot.  Consequently a
candidate build may run with networking disabled after this command succeeds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "config" / "m12-release-build-inputs-lock.json"
DEFAULT_DESTINATION = ROOT / "artifacts" / "release-build-inputs"
PLATFORM = "ubuntu-amd64"


class BuildInputError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildInputError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_lock(path: Path) -> dict:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildInputError(f"cannot read M12 release-build input lock: {exc}") from exc
    require(lock.get("schema_version") == 1, "unsupported M12 release-build input lock schema")
    require(lock.get("release_locale") == "ru", "M12 inputs must remain Russian-only")
    policy = lock.get("network_policy", {})
    require(policy.get("build_after_fetch") == "network forbidden", "build network must be forbidden after fetch")
    candidate = lock.get("intermediate_candidate", {})
    require(candidate.get("mode") == "non-lto" and candidate.get("lto") == "forbidden",
            "intermediate candidates must explicitly forbid LTO")
    platforms = lock.get("platforms")
    require(isinstance(platforms, dict) and set(platforms) == {"ubuntu-amd64", "windows-x64"},
            "lock must pin exactly Ubuntu amd64 and Windows x64")
    ubuntu = platforms["ubuntu-amd64"]
    require(ubuntu.get("target") == "Ubuntu 26.04 amd64", "Ubuntu target drift")
    require(ubuntu.get("libc6_minimum") == "2.43", "Ubuntu glibc baseline drift")
    require(ubuntu.get("target_rationale") ==
            "Maintainer-selected host-only release baseline. The candidate is linked on Ubuntu 26.04.1 LTS and must not claim Ubuntu 24.04 compatibility.",
            "Ubuntu host-only target rationale drift")
    inputs = ubuntu.get("inputs")
    require(isinstance(inputs, list) and inputs, "Ubuntu release inputs are missing")
    for item in inputs:
        require(isinstance(item, dict) and isinstance(item.get("path"), str), "malformed Ubuntu input")
        require(len(str(item.get("sha256", ""))) == 64 and all(c in "0123456789abcdef" for c in item["sha256"]),
                f"Ubuntu input {item.get('path')} lacks a SHA-256 pin")
    windows = platforms["windows-x64"]
    toolchain = windows.get("toolchain", {})
    require(windows.get("target") == "Windows x64", "Windows target drift")
    require(len(str(toolchain.get("sha256", ""))) == 64, "Windows toolchain lacks a SHA-256 pin")
    manual = windows.get("manual_vm_validation", {})
    require(manual.get("status") == "deferred-until-maintainer-provides-a-windows-environment" and
            manual.get("automation_prohibited") is True and manual.get("release_blocker") is True,
            "Windows manual-validation boundary drift")
    return lock


def platform_inputs(lock: dict, platform: str) -> list[dict]:
    require(platform == PLATFORM, "Windows input staging is deferred: no pinned Windows VM/SDK/MSVC cache exists")
    return lock["platforms"][platform]["inputs"]


def checked_source(relative: str, expected_hash: str) -> Path:
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise BuildInputError(f"input escapes project root: {relative}") from exc
    require(path.is_file(), f"declared input is missing: {relative}")
    actual = sha256_file(path)
    require(actual == expected_hash, f"input hash mismatch for {relative}: expected {expected_hash}, got {actual}")
    return path


def manifest(lock: dict, inputs: list[dict]) -> dict:
    ubuntu = lock["platforms"][PLATFORM]
    return {
        "schema_version": 1,
        "platform": PLATFORM,
        "release_locale": lock["release_locale"],
        "network_after_fetch": lock["network_policy"]["build_after_fetch"],
        "candidate_mode": lock["intermediate_candidate"]["mode"],
        "lto": lock["intermediate_candidate"]["lto"],
        "target": ubuntu["target"],
        "libc6_minimum": ubuntu["libc6_minimum"],
        "target_rationale": ubuntu["target_rationale"],
        "inputs": [{"path": item["path"], "sha256": item["sha256"]} for item in inputs],
    }


def stage(lock: dict, destination: Path) -> Path:
    inputs = platform_inputs(lock, PLATFORM)
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    final = destination / PLATFORM
    require(not final.exists(), f"refusing to replace existing promoted input snapshot: {final}")
    quarantine = destination / "quarantine"
    quarantine.mkdir(exist_ok=True)
    staging = quarantine / f"{PLATFORM}-{uuid.uuid4().hex}"
    try:
        staging.mkdir()
        print("[M12-01 1/3] Validating pinned local inputs (network disabled by this tool)", flush=True)
        for item in inputs:
            source = checked_source(item["path"], item["sha256"])
            target = staging / "inputs" / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            print(f"  verified {item['path']}", flush=True)
        print("[M12-01 2/3] Writing non-LTO candidate manifest", flush=True)
        content = manifest(lock, inputs)
        (staging / "manifest.json").write_text(json.dumps(content, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        verify_snapshot(lock, staging)
        print("[M12-01 3/3] Atomically promoting verified input snapshot", flush=True)
        os.replace(staging, final)
        return final
    except BaseException:
        if staging.exists():
            print(f"M12 input stage retained in quarantine: {staging}", flush=True)
        raise


def verify_snapshot(lock: dict, snapshot: Path) -> None:
    inputs = platform_inputs(lock, PLATFORM)
    try:
        saved = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildInputError(f"cannot read staged input manifest: {exc}") from exc
    require(saved == manifest(lock, inputs), "staged input manifest differs from the declared lock")
    for item in inputs:
        copied = snapshot / "inputs" / item["path"]
        require(copied.is_file(), f"staged input is missing: {item['path']}")
        require(sha256_file(copied) == item["sha256"], f"staged input hash mismatch: {item['path']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("stage", "verify"))
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    try:
        lock = load_lock(args.lock)
        snapshot = args.destination / PLATFORM
        if args.action == "stage":
            promoted = stage(lock, args.destination)
            print(f"M12 non-LTO Ubuntu input snapshot promoted: {promoted}", flush=True)
        else:
            print("[M12-01 1/1] Verifying promoted non-networked input snapshot", flush=True)
            verify_snapshot(lock, snapshot)
            print(f"M12 Ubuntu input snapshot verified: {snapshot}", flush=True)
    except BuildInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

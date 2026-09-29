#!/usr/bin/env python3
"""Fail-closed GB100-M15-09 delivery-contract validation; never downloads assets."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*\Z")
TAG_RE = re.compile(
    r"goodbear-(?P<product>[0-9]+(?:\.[0-9]+)*)-firefox"
    r"(?P<firefox>[0-9]+(?:\.[0-9]+)*)\Z"
)
FILENAME_RE = re.compile(
    r"goodbear-browser_(?P<product>[0-9]+(?:\.[0-9]+)*)\+firefox"
    r"(?P<firefox>[0-9]+(?:\.[0-9]+)*)-(?P<revision>[1-9][0-9]*)_amd64\.deb\Z"
)
GITHUB_COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PRIVILEGE_ESCALATION_RE = re.compile(r"(?:^|[\s;&|()])(sudo|doas|pkexec|su)(?:\s|$)")


class DeliveryContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DeliveryContractError(message)


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.name} must be an object")
    return value


def validate_windows(windows: object) -> None:
    require(isinstance(windows, dict), "Windows delivery contract missing")
    require(set(windows).issubset({"delivery", "status", "failure_mode", "signing_evidence"}),
            "Windows delivery contract has unexpected fields")
    require(windows.get("delivery") == "Firefox Application Update complete MAR",
            "Windows delivery must use complete MARs")
    require(windows.get("failure_mode") == "non-fatal fail closed",
            "Windows failure mode must fail closed")
    status = windows.get("status")
    blocked = "blocked_pending_approved_signing_authority_and_signed_artifact"
    if status == blocked:
        require(set(windows) == {"delivery", "status", "failure_mode"},
                "blocked Windows delivery must not claim signing evidence")
        return

    # Do not allow a status change to be used as a substitute for a separately
    # approved metadata/MAR signing chain.  The structural check gives a clear
    # failure for the particularly dangerous no-evidence case, then remains
    # fail-closed because this repository has no approved authority.
    evidence = windows.get("signing_evidence")
    required_evidence = {
        "approved_authority", "metadata_signature", "complete_mar_signature", "key_rotation_record"
    }
    require(status == "ready" and isinstance(evidence, dict) and
            set(evidence) == required_evidence and
            all(isinstance(evidence[field], str) and evidence[field].strip() and
                evidence[field] != "not supplied" for field in required_evidence),
            "Windows delivery marked ready without signing evidence")
    raise DeliveryContractError(
        "Windows native delivery remains blocked pending an explicitly approved signing authority"
    )


def validate_ubuntu_contract(ubuntu: object) -> None:
    require(isinstance(ubuntu, dict), "Ubuntu delivery contract missing")
    require(set(ubuntu) == {"delivery", "status", "required_release_manifest_fields", "forbidden",
                            "command_shape"}, "Ubuntu delivery contract has missing or unexpected fields")
    require(ubuntu.get("delivery") == "user-initiated terminal command",
            "Ubuntu delivery must remain user initiated")
    require(ubuntu.get("status") == "blocked_pending_version_pinned_github_release_asset",
            "Ubuntu delivery must remain blocked pending a pinned release asset")
    require(ubuntu.get("required_release_manifest_fields") ==
            ["tag", "version", "deb_url", "deb_filename", "deb_sha256"],
            "Ubuntu release manifest fields changed")
    require(set(ubuntu.get("forbidden", [])) ==
            {"latest URL", "floating branch URL", "sudo before SHA-256 verification",
             "dpkg ownership override"},
            "Ubuntu delivery prohibitions changed")
    require(ubuntu.get("command_shape") ==
            "curl -fL --output <deb> <version-pinned-url> && printf '<sha>  <deb>\\n' | "
            "sha256sum -c - && sudo apt install ./<deb>",
            "Ubuntu command shape changed")


def validate_contract(contract: dict) -> None:
    require(set(contract) == {"schema_version", "task", "windows", "ubuntu"},
            "M15-09 contract has missing or unexpected fields")
    require(contract.get("schema_version") == 1 and contract.get("task") == "GB100-M15-09",
            "invalid M15-09 contract")
    validate_windows(contract.get("windows"))
    validate_ubuntu_contract(contract.get("ubuntu"))


def validate_ubuntu_release_manifest(manifest: object) -> None:
    """Validate a candidate release declaration without contacting GitHub."""
    require(isinstance(manifest, dict) and set(manifest) ==
            {"tag", "version", "deb_url", "deb_filename", "deb_sha256"},
            "Ubuntu release manifest has missing or unexpected fields")
    tag = manifest["tag"]
    version = manifest["version"]
    filename = manifest["deb_filename"]
    digest = manifest["deb_sha256"]
    require(isinstance(version, str) and VERSION_RE.fullmatch(version) is not None,
            "Ubuntu release version has an invalid shape")
    require(isinstance(tag, str) and (tag_match := TAG_RE.fullmatch(tag)) is not None and
            tag_match["product"] == version,
            "Ubuntu release tag must pin the declared product version and Firefox base")
    require(isinstance(filename, str) and
            (filename_match := FILENAME_RE.fullmatch(filename)) is not None and
            filename_match["product"] == version and
            filename_match["firefox"] == tag_match["firefox"],
            "Ubuntu .deb filename must pin the declared product and Firefox versions")
    require(isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            "Ubuntu .deb SHA-256 must be 64 lowercase hexadecimal characters")
    validate_github_release_url(manifest["deb_url"], tag, filename)


def validate_github_release_url(url: object, tag: str, filename: str) -> None:
    """Accept only a canonical, parameter-free GitHub Releases asset URL."""
    require(isinstance(url, str), "Ubuntu release URL missing")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise DeliveryContractError(
            "Ubuntu release URL must be a parameter-free, version-pinned GitHub Releases asset URL"
        ) from exc
    parts = parsed.path.strip("/").split("/")
    require(parsed.scheme == "https" and parsed.netloc == "github.com" and
            parsed.username is None and parsed.password is None and port is None and
            not parsed.query and not parsed.fragment and len(parts) == 6 and
            all(GITHUB_COMPONENT_RE.fullmatch(part) is not None for part in parts[:2]) and
            parts[2:4] == ["releases", "download"] and parts[4] == tag and
            parts[5] == filename,
            "Ubuntu release URL must be a parameter-free, version-pinned GitHub Releases asset URL")


def render_ubuntu_command(manifest: dict) -> str:
    """Render the sole allowed command: download, verify, then escalate for install."""
    validate_ubuntu_release_manifest(manifest)
    return (
        f"curl -fL --output {manifest['deb_filename']} {manifest['deb_url']} && "
        f"printf '{manifest['deb_sha256']}  {manifest['deb_filename']}\\n' | sha256sum -c - && "
        f"sudo apt install ./{manifest['deb_filename']}"
    )


def validate_ubuntu_command(command: object, manifest: dict) -> None:
    """Reject any variation, especially privilege escalation before checksum verification."""
    require(isinstance(command, str), "Ubuntu update command missing")
    checksum_index = command.find("sha256sum -c -")
    before_checksum = command if checksum_index < 0 else command[:checksum_index]
    require(PRIVILEGE_ESCALATION_RE.search(before_checksum) is None,
            "Ubuntu command escalates privileges before SHA-256 verification")
    require(command == render_ubuntu_command(manifest),
            "Ubuntu command must exactly download, verify SHA-256, then install the verified local .deb")


def verify(root: Path = ROOT) -> None:
    validate_contract(load(root / "config/m15-09-update-delivery-contract.json"))


def main() -> int:
    try:
        verify()
    except (DeliveryContractError, OSError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("M15-09 update delivery contract verified; Windows and Ubuntu delivery remain BLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

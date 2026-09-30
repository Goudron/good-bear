#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Fail closed on material that cannot enter the public corresponding source.

The checked tree is the Git index, rather than the local working directory:
materialising Firefox, compiling it, or checking a candidate must remain
possible locally without making that derived state publishable by accident.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "config/m10-07-source-release-inventory.json"
SOURCE_OFFER = ROOT / "SOURCE_OFFER.md"
RELEASE_DIRECTORY = Path("release/good-bear-1.0")
RELEASE_ASSETS = {
    "goodbear-browser_1.0+firefox156.0-1_amd64.deb":
        "a738b9b556c90da7a1ccb601cab5a5c2e6b6dbd050046a0dbcf7dba50c02d7d0",
    "GoodBear.Setup.1.0+firefox156.0.x64.ru.exe":
        "d9f67c12680758f8d39143ef2acbd6a602b193d2d2418fa183c5c334107d77c2",
}


class PublicSourceOfferError(RuntimeError):
    """The indexed public tree or its offer contract is unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicSourceOfferError(message)


def load_inventory(root: Path) -> dict:
    try:
        value = json.loads((root / "config/m10-07-source-release-inventory.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PublicSourceOfferError(f"cannot read source-offer inventory: {exc}") from exc
    require(isinstance(value, dict), "source-offer inventory must be a JSON object")
    return value


def indexed_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=False, capture_output=True
    )
    require(result.returncode == 0, "cannot list the Git index for the public-source check")
    paths = [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]
    require(paths == sorted(paths), "Git index paths are unexpectedly unordered")
    return paths


def forbidden_reason(path: str) -> str | None:
    pure = Path(path)
    parts = pure.parts
    require(not pure.is_absolute() and ".." not in parts, f"unsafe indexed path: {path}")
    if path.startswith("source/") and path != "source/.gitkeep":
        return "materialized Firefox source or archive"
    if path.startswith("artifacts/") and path != "artifacts/.gitkeep":
        return "local candidate or build artifact"
    if any(part.startswith("obj-") or part in {"dist", ".cache", "cache", "profiles", "profile"}
           for part in parts):
        return "object output, cache, or browser profile"
    lowered = path.casefold()
    if lowered.endswith((".key", ".p12", ".pfx", ".pem")) or "/.env" in lowered or lowered.startswith(".env"):
        return "credential, private key, or environment secret"
    if lowered.endswith((".tar", ".tar.xz", ".tar.zst", ".zip", ".7z", ".deb", ".exe", ".msi", ".dmg")):
        return "archive or binary distribution artifact"
    return None


def matches_allowlist(path: str, allowlist: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in allowlist)


def validate_paths(paths: Iterable[str], allowlist: Iterable[str]) -> None:
    allowed = list(allowlist)
    for path in paths:
        reason = forbidden_reason(path)
        require(reason is None, f"public source must reject {reason}: {path}")
        require(matches_allowlist(path, allowed), f"undeclared public-source path: {path}")


def validate_contract(root: Path, inventory: dict) -> dict:
    source = inventory.get("corresponding_source", {})
    offer = source.get("source_offer", {})
    public = offer.get("public_repository", {})
    require(offer.get("location") == "https://github.com/Goudron/good-bear",
            "public source-offer location drift")
    require(offer.get("document") == "SOURCE_OFFER.md" and
            offer.get("machine_verifier") == "tools/verify_public_source_offer.py",
            "public source-offer entry points drift")
    require(offer.get("release_metadata") == [
        "config/m10-07-source-release-inventory.json",
        "config/product-identity.json",
        "config/firefox-baseline.json",
        "release/good-bear-1.0/SHA256SUMS",
        "release/good-bear-1.0/notices.json",
        "release/good-bear-1.0/provenance.intoto.json",
        "release/good-bear-1.0/sbom.cdx.json",
        "release/good-bear-1.0/source-offer.json",
    ], "public source release metadata inventory drift")
    require(offer.get("terms_must_not_restrict_mpl_source_code_form") is True,
            "source offer must preserve MPL Source Code Form rights")
    require(public.get("full_firefox_source_mirror") == "forbidden",
            "full Firefox source mirror must remain forbidden")
    allowlist = public.get("tracked_path_allowlist")
    require(isinstance(allowlist, list) and all(isinstance(path, str) and path for path in allowlist),
            "public source path allowlist is missing")
    require("artifacts/.gitkeep" in allowlist and "source/.gitkeep" in allowlist,
            "public source must retain only safe source/artifact directory markers")
    require("artwork/final/m10-03/**" in allowlist and "artwork/candidates/**" not in allowlist,
            "only reviewed final artwork may enter the public source")

    paths = offer.get("native_build_paths", {})
    windows = paths.get("windows_x64", {})
    require(windows.get("preflight") == [
        "tools/verify_nsis_branding_assets.py",
        "mozmake -n -C browser/installer/windows instgen/helper.exe",
        "tools/preflight_m15_cloud_windows.py",
    ], "Windows source preflight contract drift")
    require(windows.get("installer_only_recovery") == "./mach build installers-ru" and
            windows.get("recovery_forbidden_commands") == ["./mach configure", "./mach build"],
            "Windows installer-only recovery must not configure or rebuild Firefox")
    ubuntu = paths.get("ubuntu_amd64", {})
    require(ubuntu.get("preflight") == [
        "tools/verify_ubuntu_environment.py",
        "build/ubuntu/install-packages.sh",
        "tools/host_build_context.py",
    ], "Ubuntu source preflight contract drift")
    require(ubuntu.get("package_only_recovery") == "tools/build_m13_06_ubuntu_deb.py" and
            ubuntu.get("recovery_forbidden_commands") == ["mach configure", "mach build"],
            "Ubuntu package-only recovery must not configure or rebuild Firefox")

    required = offer.get("required_inputs", [])
    require(isinstance(required, list) and required, "declared source inputs are missing")
    for relative in required:
        if "*" not in relative:
            require((root / relative).exists(), f"declared source input is missing: {relative}")
    return {"allowlist": allowlist, "windows_preflight": windows["preflight"],
            "ubuntu_preflight": ubuntu["preflight"]}


def validate_document(root: Path) -> None:
    try:
        document = (root / "SOURCE_OFFER.md").read_text(encoding="utf-8")
    except OSError as exc:
        raise PublicSourceOfferError(f"cannot read SOURCE_OFFER.md: {exc}") from exc
    for required in (
        "Mozilla Public License 2.0",
        "mozmake -n -C browser/installer/windows instgen/helper.exe",
        "./mach build installers-ru",
        "tools/build_m13_06_ubuntu_deb.py",
        "не запускать `mach configure`",
        "полный исходный код Firefox",
    ):
        require(required.casefold() in document.casefold(),
                f"SOURCE_OFFER.md lacks required public-source guidance: {required}")


def load_release_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PublicSourceOfferError(f"cannot read release metadata {path.name}: {exc}") from exc
    require(isinstance(value, dict), f"release metadata {path.name} must be a JSON object")
    return value


def validate_release_metadata(root: Path, inventory: dict) -> None:
    directory = root / RELEASE_DIRECTORY
    sums = directory / "SHA256SUMS"
    try:
        sum_lines = sums.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PublicSourceOfferError(f"cannot read release checksums: {exc}") from exc
    actual_sums = {}
    for line in sum_lines:
        if line and not line.startswith("#"):
            digest, separator, name = line.partition("  ")
            require(separator == "  " and len(digest) == 64 and name,
                    "release checksum line is malformed")
            actual_sums[name] = digest
    require(actual_sums == RELEASE_ASSETS, "release checksums differ from the accepted unsigned candidates")
    require(any("unsigned" in line.casefold() for line in sum_lines),
            "release checksums must disclose unsigned artifacts")

    source_offer = load_release_json(directory / "source-offer.json")
    upstream = inventory["corresponding_source"]["upstream"]
    require(source_offer.get("kind") == "MPL corresponding-source offer" and
            source_offer.get("location") == "https://github.com/Goudron/good-bear" and
            source_offer.get("upstream") == {
                "version": upstream["version"], "revision": upstream["revision"],
                "source_url": upstream["source_url"], "archive_sha256": upstream["archive_sha256"],
            }, "release source offer does not bind the reviewed Firefox input")
    require(source_offer.get("patch_set_manifest_sha256") ==
            inventory["corresponding_source"]["patch_set"]["manifest_sha256"],
            "release source offer patch-set digest drift")
    require(source_offer.get("candidate_source_revision") == "4affb9064494b129a272ff21307af169c6e3b0e8" and
            source_offer.get("publication_tag") == "v1.0.0",
            "release source offer must bind the candidate source to the immutable publication tag")

    sbom = load_release_json(directory / "sbom.cdx.json")
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.5",
            "release SBOM is not CycloneDX 1.5")
    component_hashes = {
        item.get("name"): item.get("hashes", [{}])[0].get("content")
        for item in sbom.get("components", []) if isinstance(item, dict)
    }
    require(component_hashes.get("Good Bear Ubuntu amd64 package") ==
            RELEASE_ASSETS["goodbear-browser_1.0+firefox156.0-1_amd64.deb"] and
            component_hashes.get("Good Bear Windows x64 installer") ==
            RELEASE_ASSETS["GoodBear.Setup.1.0+firefox156.0.x64.ru.exe"],
            "release SBOM does not bind both accepted artifacts")

    provenance = load_release_json(directory / "provenance.intoto.json")
    subjects = {item.get("name"): item.get("digest", {}).get("sha256")
                for item in provenance.get("subject", []) if isinstance(item, dict)}
    require(provenance.get("_type") == "https://in-toto.io/Statement/v1" and
            subjects == RELEASE_ASSETS, "release provenance does not bind both accepted artifacts")
    notices = load_release_json(directory / "notices.json")
    require(notices.get("bundled_notice_entrypoint") == "about:license" and
            notices.get("source_inventory") == "config/m10-07-source-release-inventory.json" and
            notices.get("installed_notices_authoritative") is True,
            "release notices index is incomplete")


def validate(root: Path = ROOT, *, paths: Iterable[str] | None = None) -> dict:
    inventory = load_inventory(root)
    contract = validate_contract(root, inventory)
    validate_document(root)
    validate_release_metadata(root, inventory)
    checked_paths = list(paths) if paths is not None else indexed_paths(root)
    validate_paths(checked_paths, contract["allowlist"])
    return {
        "task": "GB100-M14-01",
        "checked_indexed_paths": len(checked_paths),
        "windows_preflight": contract["windows_preflight"],
        "ubuntu_preflight": contract["ubuntu_preflight"],
        "full_firefox_source_mirror": "forbidden",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        report = validate()
    except PublicSourceOfferError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("PASS: public corresponding-source boundary verified "
          f"({report['checked_indexed_paths']} indexed paths; Firefox mirror forbidden)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

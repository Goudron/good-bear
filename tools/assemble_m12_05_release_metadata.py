#!/usr/bin/env python3
"""Assemble and verify fail-closed GB100-M12-05 release metadata.

The generated directory is a local candidate record, not a release.  It maps
each available binary to its immutable upstream baseline, exact Good Bear
patch set, build evidence and SHA-256.  A Windows artefact or a signing key is
never fabricated merely to make the record look complete.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "config" / "m12-05-release-metadata.json"
DEFAULT_DESTINATION = ROOT / "artifacts" / "m12-05-release-metadata"
SHA256_LENGTH = 64


class ReleaseMetadataError(RuntimeError):
    """A release-candidate evidence or safety boundary is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseMetadataError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseMetadataError(f"cannot load {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path}: expected a JSON object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative_file(root: Path, relative: str, label: str) -> Path:
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(),
            f"{label} must be a non-empty project-relative path")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ReleaseMetadataError(f"{label} escapes the project root") from exc
    require(path.is_file(), f"{label} is missing: {relative}")
    return path


def require_digest(value: object, label: str) -> str:
    require(isinstance(value, str) and len(value) == SHA256_LENGTH and
            all(character in "0123456789abcdef" for character in value),
            f"{label} must be a lowercase SHA-256")
    return value


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    contract = load_json(path)
    require(contract.get("schema_version") == 1 and contract.get("task") == "GB100-M12-05",
            "unsupported M12-05 release metadata contract")
    require(contract.get("product") == "Good Bear" and contract.get("release_locale") == "ru",
            "M12-05 contract must be a Russian Good Bear release candidate")
    offer = contract.get("source_offer", {})
    require(offer.get("location") == "https://github.com/Goudron/good-bear" and
            offer.get("terms_must_not_restrict_mpl_source_code_form") is True and
            offer.get("full_firefox_source_mirror") == "forbidden",
            "source-offer boundary is incomplete")
    ubuntu = contract.get("ubuntu", {})
    require_digest(ubuntu.get("sha256"), "Ubuntu artifact digest")
    require_digest(
        ubuntu.get("patch_set_manifest_sha256"),
        "Ubuntu candidate patch-set manifest digest",
    )
    require_digest(ubuntu.get("package_evidence_sha256"), "Ubuntu package evidence digest")
    require(ubuntu.get("candidate_status") == "unsigned local candidate only",
            "Ubuntu candidate must remain unsigned and local")
    check_signing(ubuntu.get("signing"), "Ubuntu")
    windows = contract.get("windows", {})
    require(windows.get("artifact") is None and
            windows.get("candidate_status") == "not built; no local candidate exists" and
            windows.get("filename") == "GoodBear Setup 1.0+firefox156.0 x64 ru.exe",
            "Windows metadata must not invent a local installer")
    check_signing(windows.get("signing"), "Windows")
    public = contract.get("public_release", {})
    expected = {
        "good_bear_revision_unavailable",
        "ubuntu_signing_authority_unavailable",
        "windows_artifact_unavailable",
        "windows_manual_validation_pending",
        "windows_signing_authority_unavailable",
    }
    require(public.get("allowed") is False and set(public.get("required_blockers", [])) == expected,
            "M12-05 public-release blockers are incomplete")
    return contract


def check_signing(signing: object, platform: str) -> None:
    require(isinstance(signing, dict), f"{platform} signing metadata is missing")
    require(signing.get("approved_authority") == "not supplied" and
            signing.get("signature") == "not produced" and
            signing.get("public_release") ==
            "blocked until a separately approved signing authority is supplied" and
            signing.get("self_signed_or_invented_trust") == "forbidden",
            f"{platform} signing metadata must fail closed without an approved authority")


def source_inventory(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(root / "tools"))
    import verify_m10_07_source_release_inventory as inventory  # pylint: disable=import-outside-toplevel

    source_path = relative_file(root, contract["source_inventory"], "source inventory")
    require(source_path == (root / "config/m10-07-source-release-inventory.json").resolve(),
            "M12-05 must use the reviewed M10-07 source inventory")
    report = inventory.validate(root)
    require(report["public_release_blockers"] == ["good_bear_revision_unavailable"],
            "source inventory must expose the unresolved Good Bear revision honestly")
    return report


def ubuntu_evidence(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    ubuntu = contract["ubuntu"]
    artifact = relative_file(root, ubuntu["artifact"], "Ubuntu artifact")
    evidence_path = relative_file(root, ubuntu["package_evidence"], "Ubuntu package evidence")
    lifecycle_path = relative_file(root, ubuntu["lifecycle_evidence"], "Ubuntu lifecycle evidence")
    actual_artifact = sha256(artifact)
    actual_evidence = sha256(evidence_path)
    require(actual_artifact == ubuntu["sha256"], "Ubuntu artifact SHA-256 mismatch")
    require(actual_evidence == ubuntu["package_evidence_sha256"], "Ubuntu package evidence SHA-256 mismatch")
    package = load_json(evidence_path)
    require(package.get("task") == "GB100-M12-02" and package.get("locale") == "ru" and
            package.get("lto") == "forbidden" and package.get("network_after_fetch") == "forbidden" and
            package.get("package_sha256") == actual_artifact,
            "Ubuntu package evidence does not describe this Russian non-LTO artifact")
    lifecycle = load_json(lifecycle_path)
    require(lifecycle.get("task") == "GB100-M12-04" and
            lifecycle.get("package", {}).get("sha256") == actual_artifact and
            lifecycle.get("windows_manual_validation", {}).get("status") ==
            "deferred-until-maintainer-provides-a-windows-environment",
            "Ubuntu lifecycle evidence does not map to this package or masks Windows validation")
    return {
        "artifact": ubuntu["artifact"],
        "sha256": actual_artifact,
        "patch_set_manifest_sha256": ubuntu["patch_set_manifest_sha256"],
        "package_evidence": ubuntu["package_evidence"],
        "package_evidence_sha256": actual_evidence,
        "lifecycle_evidence": ubuntu["lifecycle_evidence"],
        "package_evidence_task": package["task"],
        "lifecycle_evidence_task": lifecycle["task"],
        "candidate_mode": package["lto"],
        "network_after_fetch": package["network_after_fetch"],
    }


def source_offer(contract: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "MPL corresponding-source offer",
        "location": contract["source_offer"]["location"],
        "terms_must_not_restrict_mpl_source_code_form": True,
        "full_firefox_source_mirror": "forbidden",
        "upstream": {
            "version": source["upstream_version"],
            "revision": source["upstream_revision"],
            "source_url": source["upstream_source_url"],
            "archive_sha256": source["upstream_archive_sha256"],
        },
        "version_pair": source["version_pair"],
        "good_bear_revision": {
            "value": source["good_bear_revision"],
            "status": "unavailable; blocks public release" if source["good_bear_revision"] is None else "recorded",
        },
        "patch_set": source["patch_set"],
        "overlay": source["overlay"],
        "russian_localization": source["russian_localization"],
        "artwork": source["artwork"],
        "components": source["components"],
        "legal_notice_entrypoint": source["legal_notice_entrypoint"],
    }


def sbom(source: dict[str, Any], ubuntu: dict[str, Any]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:good-bear-m12-05-local-candidate",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "Good Bear",
                "version": source["version_pair"]["package_version"] + "-1",
                "properties": [
                    {"name": "goodbear:product-version", "value": source["version_pair"]["good_bear_version"]},
                    {"name": "goodbear:firefox-base-version", "value": source["version_pair"]["firefox_base_version"]},
                    {"name": "goodbear:locale", "value": "ru"},
                    {"name": "goodbear:candidate-status", "value": "unsigned local candidate only"},
                    {"name": "goodbear:artifact-sha256", "value": ubuntu["sha256"]},
                ],
            }
        },
        "components": [
            {
                "type": "application",
                "name": "Good Bear Ubuntu amd64 package",
                "version": source["version_pair"]["package_version"] + "-1",
                "hashes": [{"alg": "SHA-256", "content": ubuntu["sha256"]}],
                "properties": [
                    {"name": "goodbear:artifact", "value": ubuntu["artifact"]},
                    {"name": "goodbear:source-patch-manifest", "value": source["patch_set"]["manifest_sha256"]},
                    {"name": "goodbear:upstream-revision", "value": source["upstream_revision"]},
                ],
            },
            {
                "type": "application",
                "name": "Mozilla Firefox upstream source",
                "version": source["upstream_version"],
                "hashes": [{"alg": "SHA-256", "content": source["upstream_archive_sha256"]}],
                "externalReferences": [{"type": "distribution", "url": source["upstream_source_url"]}],
            },
            *[
                {
                    "type": "library",
                    "name": component["id"],
                    "licenses": [{"license": {"name": component["license"]}}],
                    "properties": [
                        {"name": "goodbear:owner", "value": component["owner"]},
                        {"name": "goodbear:source", "value": component["source"]},
                        {"name": "goodbear:redistribution-status", "value": component["redistribution_status"]},
                    ],
                }
                for component in source["components"]
            ],
        ],
    }


def provenance(source: dict[str, Any], ubuntu: dict[str, Any]) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": ubuntu["artifact"], "digest": {"sha256": ubuntu["sha256"]}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://good-bear.local/build/m12-02-ubuntu-deb",
                "externalParameters": {
                    "version_pair": {
                        "good_bear": source["version_pair"]["good_bear_version"],
                        "firefox": source["version_pair"]["firefox_base_version"],
                    },
                    "locale": "ru",
                    "candidate_mode": ubuntu["candidate_mode"],
                    "network_after_fetch": ubuntu["network_after_fetch"],
                },
                "resolvedDependencies": [
                    {"uri": source["upstream_source_url"], "digest": {"sha256": source["upstream_archive_sha256"]}},
                    {"uri": "goodbear:patch-set", "digest": {"sha256": source["patch_set"]["manifest_sha256"]}},
                    {"uri": "goodbear:package-evidence", "digest": {"sha256": ubuntu["package_evidence_sha256"]}},
                ],
            },
            "runDetails": {
                "builder": {"id": "Good Bear local M12 candidate assembler; no signing authority"},
                "metadata": {"invocationId": "GB100-M12-05-local-candidate", "completeness": {"parameters": True, "environment": True, "materials": True}, "reproducible": False},
                "byproducts": [{"name": "Ubuntu lifecycle evidence", "value": ubuntu["lifecycle_evidence"]}],
            },
        },
    }


def notices(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "bundled_notice_entrypoint": source["legal_notice_entrypoint"],
        "components": source["components"],
        "policy": "Preserve applicable Mozilla and third-party notices; this index is not a replacement for the installed notices.",
    }


def signing_metadata(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "no approved signing authority supplied; no signatures produced",
        "ubuntu": copy.deepcopy(contract["ubuntu"]["signing"]),
        "windows": copy.deepcopy(contract["windows"]["signing"]),
        "prohibited": ["self-signed release certificate", "invented trust", "unsigned public release"],
    }


def release_manifest(contract: dict[str, Any], source: dict[str, Any], ubuntu: dict[str, Any]) -> dict[str, Any]:
    blockers = contract["public_release"]["required_blockers"]
    return {
        "schema_version": 1,
        "task": "GB100-M12-05",
        "product": "Good Bear",
        "version_pair": {
            "good_bear": source["version_pair"]["good_bear_version"],
            "firefox": source["version_pair"]["firefox_base_version"],
        },
        "release_locale": "ru",
        "candidate_status": "local only; public release blocked",
        "public_release_allowed": False,
        "public_release_blockers": blockers,
        "binary_source_mapping": {
            "ubuntu-amd64": {
                "artifact": ubuntu["artifact"],
                "artifact_sha256": ubuntu["sha256"],
                "upstream_revision": source["upstream_revision"],
                "upstream_archive_sha256": source["upstream_archive_sha256"],
                "good_bear_revision": source["good_bear_revision"],
                "good_bear_patch_set_manifest_sha256": source["patch_set"]["manifest_sha256"],
                "source_offer": "source-offer.json",
                "package_evidence": ubuntu["package_evidence"],
                "lifecycle_evidence": ubuntu["lifecycle_evidence"],
            },
            "windows-x64": {
                "artifact": None,
                "expected_filename": contract["windows"]["filename"],
                "status": "not built; no local candidate exists",
                "source_mapping": "declared but not release-eligible until a real verified artifact exists",
            },
        },
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def assemble(root: Path = ROOT, contract_path: Path = DEFAULT_CONTRACT,
             destination: Path = DEFAULT_DESTINATION) -> dict[str, Any]:
    contract = load_contract(contract_path)
    source = source_inventory(root, contract)
    ubuntu = ubuntu_evidence(root, contract)
    require(
        source["patch_set"]["manifest_sha256"]
        == ubuntu["patch_set_manifest_sha256"],
        "Ubuntu candidate predates the current Good Bear patch set; "
        "refusing to remap stale binary evidence",
    )
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".m12-05-", dir=destination.parent))
    try:
        write_json(staging / "source-offer.json", source_offer(contract, source))
        write_json(staging / "sbom.cdx.json", sbom(source, ubuntu))
        write_json(staging / "provenance.intoto.json", provenance(source, ubuntu))
        write_json(staging / "notices.json", notices(source))
        write_json(staging / "signing-metadata.json", signing_metadata(contract))
        manifest = release_manifest(contract, source, ubuntu)
        write_json(staging / "release-manifest.json", manifest)
        (staging / "SHA256SUMS").write_text(
            f"{ubuntu['sha256']}  {ubuntu['artifact']}\n"
            f"# Windows artifact unavailable: {contract['windows']['filename']}\n",
            encoding="utf-8",
        )
        previous = destination.with_name(destination.name + ".previous")
        if previous.exists():
            shutil.rmtree(previous)
        if destination.exists():
            os.replace(destination, previous)
        os.replace(staging, destination)
        if previous.exists():
            shutil.rmtree(previous)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


def verify(root: Path = ROOT, contract_path: Path = DEFAULT_CONTRACT,
           destination: Path = DEFAULT_DESTINATION) -> dict[str, Any]:
    expected = assemble(root, contract_path, destination)
    actual = load_json(destination / "release-manifest.json")
    require(actual == expected, "promoted M12-05 release manifest differs from generated evidence")
    sums = (destination / "SHA256SUMS").read_text(encoding="utf-8")
    ubuntu = expected["binary_source_mapping"]["ubuntu-amd64"]
    require(f"{ubuntu['artifact_sha256']}  {ubuntu['artifact']}" in sums,
            "SHA256SUMS does not contain the Ubuntu candidate")
    require("Windows artifact unavailable" in sums,
            "SHA256SUMS must not imply a Windows installer exists")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("assemble", "verify"))
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    try:
        print("[M12-05 1/4] Validating exact source inventory and MPL source-offer boundary", flush=True)
        print("[M12-05 2/4] Validating r3 Ubuntu candidate hash and clean-target lifecycle evidence", flush=True)
        if args.action == "assemble":
            result = assemble(ROOT, args.contract, args.destination)
        else:
            result = verify(ROOT, args.contract, args.destination)
        print("[M12-05 3/4] Writing SBOM, provenance, notices, checksums, and signing metadata", flush=True)
        print("[M12-05 4/4] Local candidate recorded; public release blocked: " +
              ", ".join(result["public_release_blockers"]), flush=True)
    except (OSError, ReleaseMetadataError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

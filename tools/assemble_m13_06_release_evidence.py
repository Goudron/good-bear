#!/usr/bin/env python3
"""Create verifiable metadata for the frozen M13-06 Ubuntu LTO candidate.

This tool consumes an already-built archive and Debian package.  It never
invokes ``mach``, edits the payload, signs it, or changes the frozen source
manifest.  Its output is evidence for a local unsigned candidate, not a public
release declaration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any


ROOT = Path(os.environ.get("GOODBEAR_ROOT", Path(__file__).resolve().parents[1])).resolve()
IDENTITY_PATH = ROOT / "config/product-identity.json"
BASELINE_PATH = ROOT / "config/firefox-baseline.json"
INVENTORY_PATH = ROOT / "config/m10-07-source-release-inventory.json"
SHA256_LENGTH = 64


class EvidenceError(RuntimeError):
    """Raised when a candidate cannot be described honestly."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path}: expected JSON object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def valid_sha256(value: object, label: str) -> str:
    require(isinstance(value, str) and len(value) == SHA256_LENGTH and
            all(character in "0123456789abcdef" for character in value),
            f"{label} is not a lowercase SHA-256")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def verify_source_bundle(source_bundle: Path, source_manifest: Path) -> None:
    """Verify the returned bundle bytes, not merely a freshly computed hash."""
    spec = importlib.util.spec_from_file_location(
        "goodbear_m13_source_transport", ROOT / "tools/m15_remote_transport.py")
    require(spec is not None and spec.loader is not None, "source transport verifier is unavailable")
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    try:
        transport.verify_bundle(ROOT, source_manifest, source_bundle)
    except transport.TransportError as exc:
        raise EvidenceError(f"source bundle verification failed: {exc}") from exc


def load_inputs(archive: Path, source_bundle: Path, source_manifest: Path,
                package: Path, package_evidence: Path) -> dict[str, Any]:
    for path, label in ((archive, "archive"), (source_bundle, "source bundle"),
                        (source_manifest, "source manifest"), (package, "package"),
                        (package_evidence, "package evidence")):
        require(path.is_file(), f"{label} is missing: {path}")
    identity = load_json(IDENTITY_PATH)
    baseline = load_json(BASELINE_PATH)
    inventory = load_json(INVENTORY_PATH)
    manifest = load_json(source_manifest)
    package_record = load_json(package_evidence)
    firefox_version = baseline.get("version")
    require(isinstance(firefox_version, str) and firefox_version,
            "pinned Firefox version is missing")
    baseline_sha256 = valid_sha256(baseline.get("source", {}).get("sha256"), "baseline archive hash")
    revision = baseline.get("vcs", {}).get("revision")
    require(isinstance(revision, str) and len(revision) == 40 and
            all(character in "0123456789abcdef" for character in revision),
            "pinned Firefox revision is invalid")
    version_pair = identity.get("version_pair")
    require(version_pair == {
        "schema_version": 1,
        "ordering": "good_bear_then_firefox_base",
        "good_bear_version": "1.0",
        "firefox_base_version": firefox_version,
        "canonical_about_ru": f"Good Bear 1.0 (Firefox {firefox_version})",
        "package_version": f"1.0+firefox{firefox_version}",
    }, "unexpected Good Bear / Firefox version pair")
    require(manifest.get("schema_version") == 1 and manifest.get("task") == "GB100-M15-01",
            "source manifest is not the frozen M15 transport manifest")
    require(package_record.get("task") == "GB100-M13-06" and
            package_record.get("candidate_status") == "unsigned candidate; public release not implied" and
            package_record.get("platform") == "ubuntu-amd64" and
            package_record.get("ubuntu_target") == "24.04.4 LTS" and
            package_record.get("lto") == "full" and package_record.get("locale") == "ru",
            "package evidence is not the Russian Ubuntu full-LTO candidate")
    require(package_record.get("version_pair") == version_pair,
            "package evidence version pair differs from identity")
    require(package_record.get("archive") == archive.name and
            package_record.get("archive_sha256") == sha256(archive),
            "package evidence does not bind the frozen archive")
    require(package_record.get("source_manifest") == source_manifest.name and
            package_record.get("source_manifest_sha256") == sha256(source_manifest),
            "package evidence does not bind the frozen source manifest")
    require(package_record.get("package") == package.name and
            package_record.get("package_sha256") == sha256(package),
            "package evidence does not bind the Debian artifact")
    require(manifest.get("upstream") == {
                "product": baseline.get("product"),
                "version": firefox_version,
                "revision": revision,
                "archive": baseline.get("source", {}).get("archive_path"),
                "archive_sha256": baseline_sha256,
            },
            "frozen source manifest does not bind the pinned Firefox baseline")
    verify_source_bundle(source_bundle, source_manifest)
    require(inventory.get("schema_version") == 1 and inventory.get("milestone") == "GB100-M10-07" and
            isinstance(inventory.get("components"), list) and inventory["components"],
            "reviewed source/third-party inventory is unavailable")
    return {
        "identity": identity,
        "baseline": baseline,
        "inventory": inventory,
        "manifest": manifest,
        "package_record": package_record,
        "archive": archive,
        "source_bundle": source_bundle,
        "source_manifest": source_manifest,
        "package": package,
        "package_evidence": package_evidence,
    }


def version_pair(data: dict[str, Any]) -> dict[str, str]:
    value = data["identity"]["version_pair"]
    return {"good_bear": value["good_bear_version"], "firefox": value["firefox_base_version"]}


def release_manifest(data: dict[str, Any], helper_digest: str) -> dict[str, Any]:
    record = data["package_record"]
    return {
        "schema_version": 1,
        "task": "GB100-M13-06",
        "candidate_status": "unsigned candidate; public release not implied",
        "public_release_allowed": False,
        "public_release_blockers": [
            "windows-x64 full-LTO candidate and mandatory validation are absent",
            "remaining M13 release gates are not represented by this Ubuntu-only evidence",
            "no approved signing authority has been supplied",
        ],
        "product": "Good Bear",
        "version_pair": version_pair(data),
        "platform": record["platform"],
        "ubuntu_target": record["ubuntu_target"],
        "locale": record["locale"],
        "lto": record["lto"],
        "application_updater": "disabled pending signed integration",
        "artifact": {"name": data["package"].name, "sha256": sha256(data["package"])},
        "frozen_build_archive": {"name": data["archive"].name, "sha256": sha256(data["archive"])},
        "source": {
            "manifest": {"name": data["source_manifest"].name, "sha256": sha256(data["source_manifest"])},
            "bundle": {"name": data["source_bundle"].name, "sha256": sha256(data["source_bundle"])},
            "upstream": data["manifest"]["upstream"],
        },
        "operational_metadata_assembler": {
            "name": Path(__file__).name,
            "sha256": helper_digest,
            "does_not_compile_or_modify_payload": True,
        },
    }


def sbom(data: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    record = data["package_record"]
    baseline = data["baseline"]
    components: list[dict[str, Any]] = [
        {
            "type": "application",
            "name": "Good Bear Ubuntu amd64 package",
            "version": data["identity"]["version_pair"]["package_version"] + "-1",
            "hashes": [{"alg": "SHA-256", "content": sha256(data["package"])}],
            "properties": [
                {"name": "goodbear:artifact", "value": data["package"].name},
                {"name": "goodbear:lto", "value": "full"},
                {"name": "goodbear:locale", "value": "ru"},
                {"name": "goodbear:candidate-status", "value": record["candidate_status"]},
            ],
        },
        {
            "type": "application",
            "name": "Mozilla Firefox upstream source",
            "version": baseline["version"],
            "hashes": [{"alg": "SHA-256", "content": baseline["source"]["sha256"]}],
            "externalReferences": [{"type": "distribution", "url": baseline["source"]["archive_url"]}],
            "properties": [{"name": "goodbear:upstream-revision", "value": baseline["vcs"]["revision"]}],
        },
    ]
    for component in data["inventory"]["components"]:
        components.append({
            "type": "library",
            "name": component["id"],
            "licenses": [{"license": {"name": component["license"]}}],
            "properties": [
                {"name": "goodbear:owner", "value": component["owner"]},
                {"name": "goodbear:source", "value": component["source"]},
                {"name": "goodbear:redistribution-status", "value": component["redistribution_status"]},
            ],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:good-bear-m13-06-ubuntu-lto-candidate",
        "version": 1,
        "metadata": {"component": {
            "type": "application", "name": "Good Bear", "version": "1.0",
            "properties": [
                {"name": "goodbear:firefox-base-version", "value": baseline["version"]},
                {"name": "goodbear:source-manifest-sha256", "value": sha256(data["source_manifest"])},
                {"name": "goodbear:source-bundle-sha256", "value": sha256(data["source_bundle"])},
                {"name": "goodbear:frozen-archive-sha256", "value": sha256(data["archive"])},
            ],
        }},
        "components": components,
    }


def provenance(data: dict[str, Any], helper_digest: str) -> dict[str, Any]:
    baseline = data["baseline"]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": data["package"].name, "digest": {"sha256": sha256(data["package"])}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://good-bear.local/build/m13-06-ubuntu-full-lto-deb",
                "externalParameters": {
                    "version_pair": version_pair(data), "locale": "ru", "lto": "full",
                    "ubuntu_target": "24.04.4 LTS", "candidate_status": "unsigned",
                },
                "resolvedDependencies": [
                    {"uri": baseline["source"]["archive_url"], "digest": {"sha256": baseline["source"]["sha256"]}},
                    {"uri": "goodbear:source-manifest", "digest": {"sha256": sha256(data["source_manifest"])}},
                    {"uri": "goodbear:source-bundle", "digest": {"sha256": sha256(data["source_bundle"])}},
                    {"uri": "goodbear:frozen-russian-lto-archive", "digest": {"sha256": sha256(data["archive"])}},
                    {"uri": "goodbear:package-evidence", "digest": {"sha256": sha256(data["package_evidence"])}},
                    {"uri": f"goodbear:{Path(__file__).name}", "digest": {"sha256": helper_digest}},
                ],
            },
            "runDetails": {
                "builder": {"id": "Cloud.ru Ubuntu remote builder; returned artifact reviewed locally"},
                "metadata": {"invocationId": "GB100-M13-06-ubuntu-full-lto", "reproducible": False,
                             "completeness": {"parameters": True, "environment": True, "materials": True}},
                "byproducts": [{"name": "package evidence", "value": data["package_evidence"].name}],
            },
        },
    }


def verify_output(destination: Path, expected: dict[str, Any]) -> None:
    actual = load_json(destination / "release-manifest.json")
    require(actual == expected, "release manifest differs from generated evidence")
    provenance_record = load_json(destination / "provenance.intoto.json")
    require(provenance_record.get("subject") == [{"name": expected["artifact"]["name"],
             "digest": {"sha256": expected["artifact"]["sha256"]}}], "provenance subject mismatch")
    bom = load_json(destination / "sbom.cdx.json")
    require(bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5",
            "invalid CycloneDX output")
    sums = (destination / "SHA256SUMS").read_text(encoding="utf-8")
    require(f"{expected['artifact']['sha256']}  {expected['artifact']['name']}" in sums,
            "artifact hash absent from SHA256SUMS")
    require("unsigned candidate; public release not implied" in sums,
            "unsigned candidate disclosure absent from SHA256SUMS")


def assemble(archive: Path, source_bundle: Path, source_manifest: Path, package: Path,
             package_evidence: Path, destination: Path) -> dict[str, Any]:
    data = load_inputs(archive, source_bundle, source_manifest, package, package_evidence)
    helper_digest = sha256(Path(__file__).resolve())
    manifest = release_manifest(data, helper_digest)
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".m13-06-evidence-", dir=destination.parent))
    try:
        write_json(staging / "release-manifest.json", manifest)
        write_json(staging / "sbom.cdx.json", sbom(data, manifest))
        write_json(staging / "provenance.intoto.json", provenance(data, helper_digest))
        write_json(staging / "notices.json", {"schema_version": 1,
                   "policy": "Installed notices remain authoritative; this is a provenance index.",
                   "components": data["inventory"]["components"]})
        entries = [(sha256(package), package.name), (sha256(archive), archive.name),
                   (sha256(source_manifest), source_manifest.name), (sha256(source_bundle), source_bundle.name),
                   (sha256(package_evidence), package_evidence.name)]
        (staging / "SHA256SUMS").write_text(
            f"# Good Bear 1.0 / Firefox {data['baseline']['version']} — unsigned candidate; public release not implied\n" +
            "".join(f"{digest}  {name}\n" for digest, name in entries), encoding="utf-8")
        if destination.exists():
            raise EvidenceError(f"refusing to replace existing evidence directory: {destination}")
        verify_output(staging, manifest)
        os.replace(staging, destination)
        return manifest
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--source-bundle", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-evidence", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        print("[M13-06 evidence 1/3] Binding package to frozen source and full-LTO archive", flush=True)
        result = assemble(args.archive.resolve(), args.source_bundle.resolve(), args.source_manifest.resolve(),
                          args.package.resolve(), args.package_evidence.resolve(), args.destination.resolve())
        print("[M13-06 evidence 2/3] Writing CycloneDX SBOM, in-toto provenance, notices and SHA256SUMS", flush=True)
        print("[M13-06 evidence 3/3] Evidence promoted for unsigned local candidate: " +
              result["artifact"]["name"], flush=True)
    except (EvidenceError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

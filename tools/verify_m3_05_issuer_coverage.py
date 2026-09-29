#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Verify the bounded, review-only GB100-M3-05 issuer-coverage snapshot."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COVERAGE_PATH = ROOT / "config/m3-05-issuer-coverage.json"
PROVENANCE_PATH = ROOT / "config/m3-01-certificate-provenance.json"
MANIFEST_PATH = ROOT / "config/russian-pki-manifest.json"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
ENTRY_ID = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
ENDPOINT = re.compile(r"^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):443$")


class CoverageError(RuntimeError):
    pass


def load_tool_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CoverageError(f"cannot load required verifier {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M301 = load_tool_module(
    "good_bear_m3_05_m3_01", ROOT / "tools/verify_m3_01_certificate_provenance.py"
)
M302 = load_tool_module(
    "good_bear_m3_05_m3_02", ROOT / "tools/verify_m3_02_russian_pki_manifest.py"
)


def require_mapping(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CoverageError(f"{description} must be an object")
    return value


def require_exact_fields(
    value: dict[str, Any], fields: set[str], description: str
) -> None:
    if set(value) != fields:
        raise CoverageError(f"{description} has missing or unknown fields")


def require_sha256(value: Any, description: str) -> str:
    if not isinstance(value, str) or not HEX_SHA256.fullmatch(value):
        raise CoverageError(f"{description} must be a lowercase SHA-256 digest")
    return value


def require_timestamp(value: Any, description: str) -> datetime:
    if not isinstance(value, str):
        raise CoverageError(f"{description} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise CoverageError(f"{description} must be an RFC 3339 UTC timestamp") from exc
    return parsed


def require_url(value: Any, description: str, *, https_only: bool) -> str:
    if not isinstance(value, str):
        raise CoverageError(f"{description} must be a URL")
    parsed = urllib.parse.urlparse(value)
    schemes = {"https"} if https_only else {"http", "https"}
    if (
        parsed.scheme not in schemes
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise CoverageError(f"{description} is not an approved absolute URL")
    return value


def identity(value: Any, description: str) -> tuple[str, str]:
    item = require_mapping(value, f"{description} identity")
    require_exact_fields(
        item,
        {"certificate_der_sha256", "spki_der_sha256"},
        f"{description} identity",
    )
    return (
        require_sha256(
            item["certificate_der_sha256"], f"{description} certificate pin"
        ),
        require_sha256(item["spki_der_sha256"], f"{description} SPKI pin"),
    )


def validate_policy(value: Any) -> None:
    policy = require_mapping(value, "coverage policy")
    expected = {
        "discovery_authorizes_trust": False,
        "new_trust_anchors": False,
        "global_trust": False,
        "runtime_certificate_download": False,
        "string_based_recognition": False,
        "require_existing_exact_root": True,
        "coverage_claim": "bounded_snapshot_not_exhaustive",
    }
    require_exact_fields(policy, set(expected), "coverage policy")
    if policy != expected:
        raise CoverageError("issuer coverage policy weakens a fail-closed invariant")


def validate_coverage(
    coverage: Any, provenance: dict[str, Any], manifest: dict[str, Any]
) -> None:
    try:
        M301.validate_manifest(provenance)
        M302.validate_manifest(manifest)
    except (M301.ProvenanceError, M302.ManifestError) as exc:
        raise CoverageError(
            f"underlying reviewed M3 contract is invalid: {exc}"
        ) from exc

    document = require_mapping(coverage, "issuer coverage")
    require_exact_fields(
        document,
        {
            "schema_version",
            "task",
            "observed_at",
            "policy",
            "discovery_sources",
            "accepted_issuers",
            "live_chain_observations",
            "bounded_conclusion",
        },
        "issuer coverage",
    )
    if document["schema_version"] != 1 or document["task"] != "GB100-M3-05":
        raise CoverageError("unexpected issuer-coverage schema or task")
    snapshot_time = require_timestamp(document["observed_at"], "coverage observed_at")
    validate_policy(document["policy"])

    sources = document["discovery_sources"]
    if not isinstance(sources, list) or not sources:
        raise CoverageError("at least one candidate-only discovery source is required")
    source_ids: set[str] = set()
    for index, source in enumerate(sources):
        item = require_mapping(source, f"discovery source {index}")
        require_exact_fields(
            item, {"id", "kind", "url", "trust_authority"}, f"discovery source {index}"
        )
        source_id = item["id"]
        if not isinstance(source_id, str) or not ENTRY_ID.fullmatch(
            source_id.replace("-", "_")
        ):
            raise CoverageError("discovery source has a malformed id")
        if source_id in source_ids:
            raise CoverageError("duplicate discovery source id")
        if item["kind"] not in {
            "certificate_transparency",
            "current_issuer_statistics",
        }:
            raise CoverageError("unsupported discovery source kind")
        require_url(item["url"], f"discovery source {source_id}", https_only=True)
        if item["trust_authority"] is not False:
            raise CoverageError("discovery evidence must never authorize trust")
        source_ids.add(source_id)

    provenance_records = {record["id"]: record for record in provenance["certificates"]}
    manifest_anchors = {entry["id"]: entry for entry in manifest["trust_anchors"]}
    anchor_identities = {
        identity(entry["identity"], f"anchor {entry['id']}")
        for entry in manifest_anchors.values()
    }
    manifest_intermediates = {entry["id"]: entry for entry in manifest["intermediates"]}

    issuers = document["accepted_issuers"]
    if not isinstance(issuers, list) or not issuers:
        raise CoverageError("at least one reviewed issuer is required")
    accepted: dict[str, tuple[str, str]] = {}
    for index, issuer in enumerate(issuers):
        item = require_mapping(issuer, f"accepted issuer {index}")
        require_exact_fields(
            item,
            {
                "id",
                "role",
                "status",
                "provenance_id",
                "official_source_url",
                "identity",
                "chains_to_anchor_identity",
                "discovery_references",
                "artifact_observations",
            },
            f"accepted issuer {index}",
        )
        issuer_id = item["id"]
        if not isinstance(issuer_id, str) or not ENTRY_ID.fullmatch(issuer_id):
            raise CoverageError("accepted issuer has a malformed id")
        if issuer_id in accepted:
            raise CoverageError("duplicate accepted issuer")
        if item["role"] != "intermediate" or item["status"] != "accepted_reviewed":
            raise CoverageError("issuer role confusion or unreviewed status")
        entry = manifest_intermediates.get(issuer_id)
        record = provenance_records.get(item["provenance_id"])
        if (
            entry is None
            or record is None
            or entry["provenance_id"] != item["provenance_id"]
        ):
            raise CoverageError(f"unreviewed or inactive accepted issuer: {issuer_id}")
        if record["id"] != issuer_id or record["role"] != "intermediate":
            raise CoverageError(
                f"issuer provenance role or identity mismatch: {issuer_id}"
            )
        require_url(
            item["official_source_url"],
            f"official source for {issuer_id}",
            https_only=False,
        )
        if item["official_source_url"] != record["source_url"]:
            raise CoverageError(f"official source drift for {issuer_id}")
        issuer_identity = identity(item["identity"], f"accepted issuer {issuer_id}")
        if issuer_identity != identity(
            entry["identity"], f"manifest issuer {issuer_id}"
        ):
            raise CoverageError(f"manifest identity drift for {issuer_id}")
        if issuer_identity != (
            record["certificate_der_sha256"],
            record["spki_der_sha256"],
        ):
            raise CoverageError(f"provenance identity drift for {issuer_id}")
        parent_identity = identity(
            item["chains_to_anchor_identity"], f"accepted issuer {issuer_id} parent"
        )
        if parent_identity not in anchor_identities:
            raise CoverageError(
                f"issuer does not end at an existing exact root: {issuer_id}"
            )
        if parent_identity != identity(
            entry["chains_to_anchor_identity"], f"manifest issuer {issuer_id} parent"
        ):
            raise CoverageError(f"issuer parent identity drift: {issuer_id}")
        if record.get("chains_to") not in manifest_anchors:
            raise CoverageError(
                f"issuer has no reviewed exact root parent: {issuer_id}"
            )

        references = item["discovery_references"]
        if not isinstance(references, list) or not references:
            raise CoverageError(f"issuer lacks discovery references: {issuer_id}")
        for reference in references:
            evidence = require_mapping(
                reference, f"discovery reference for {issuer_id}"
            )
            require_exact_fields(
                evidence,
                {"source_id", "reference"},
                f"discovery reference for {issuer_id}",
            )
            if evidence["source_id"] not in source_ids:
                raise CoverageError(
                    f"issuer references an unknown discovery source: {issuer_id}"
                )
            if (
                not isinstance(evidence["reference"], str)
                or not evidence["reference"].strip()
            ):
                raise CoverageError(
                    f"issuer has an empty discovery reference: {issuer_id}"
                )

        observations = item["artifact_observations"]
        if not isinstance(observations, list) or not observations:
            raise CoverageError(
                f"issuer lacks an exact artifact observation: {issuer_id}"
            )
        for observation in observations:
            artifact = require_mapping(
                observation, f"artifact observation for {issuer_id}"
            )
            require_exact_fields(
                artifact,
                {"retrieval_url", "certificate_der_sha256"},
                f"artifact observation for {issuer_id}",
            )
            require_url(
                artifact["retrieval_url"],
                f"artifact observation for {issuer_id}",
                https_only=False,
            )
            if (
                require_sha256(
                    artifact["certificate_der_sha256"],
                    f"artifact observation for {issuer_id}",
                )
                != issuer_identity[0]
            ):
                raise CoverageError(
                    f"observed artifact is not the reviewed issuer: {issuer_id}"
                )
        accepted[issuer_id] = issuer_identity

    if set(accepted) != set(manifest_intermediates):
        raise CoverageError(
            "coverage and active manifest intermediate identities differ"
        )

    live_observations = document["live_chain_observations"]
    if not isinstance(live_observations, list) or not live_observations:
        raise CoverageError("at least one exact live-chain observation is required")
    endpoints: set[str] = set()
    leaves: set[str] = set()
    anchor_der_hashes = {anchor_identity[0] for anchor_identity in anchor_identities}
    for index, observation in enumerate(live_observations):
        item = require_mapping(observation, f"live-chain observation {index}")
        require_exact_fields(
            item,
            {
                "endpoint",
                "observed_at",
                "hostname_verified",
                "leaf_der_sha256",
                "issuer_id",
                "issuer_der_sha256",
                "anchor_der_sha256",
            },
            f"live-chain observation {index}",
        )
        endpoint = item["endpoint"]
        if not isinstance(endpoint, str) or not ENDPOINT.fullmatch(endpoint):
            raise CoverageError(
                "live-chain endpoint must be an explicit DNS host on port 443"
            )
        if endpoint in endpoints:
            raise CoverageError("duplicate live-chain endpoint")
        endpoints.add(endpoint)
        if (
            require_timestamp(item["observed_at"], f"live-chain observation {endpoint}")
            > snapshot_time
        ):
            raise CoverageError(
                "live-chain observation occurs after the coverage snapshot"
            )
        if item["hostname_verified"] is not True:
            raise CoverageError("live-chain observation did not verify the hostname")
        leaf_hash = require_sha256(item["leaf_der_sha256"], f"live leaf for {endpoint}")
        if leaf_hash in leaves:
            raise CoverageError("duplicate live leaf observation")
        leaves.add(leaf_hash)
        issuer_id = item["issuer_id"]
        if issuer_id not in accepted:
            raise CoverageError("live chain uses an unreviewed issuer")
        if (
            require_sha256(item["issuer_der_sha256"], f"live issuer for {endpoint}")
            != accepted[issuer_id][0]
        ):
            raise CoverageError("live chain issuer identity drift")
        if (
            require_sha256(item["anchor_der_sha256"], f"live anchor for {endpoint}")
            not in anchor_der_hashes
        ):
            raise CoverageError("live chain does not end at an existing exact root")

    conclusion = require_mapping(document["bounded_conclusion"], "bounded conclusion")
    require_exact_fields(
        conclusion,
        {"status", "accepted_issuer_ids", "new_issuer_ids_added", "internet_coverage"},
        "bounded conclusion",
    )
    if conclusion["status"] not in {
        "reviewed_issuers_added",
        "no_additional_exact_issuer_discovered",
    }:
        raise CoverageError("unsupported bounded conclusion status")
    accepted_ids = conclusion["accepted_issuer_ids"]
    new_ids = conclusion["new_issuer_ids_added"]
    if (
        not isinstance(accepted_ids, list)
        or set(accepted_ids) != set(accepted)
        or len(accepted_ids) != len(set(accepted_ids))
    ):
        raise CoverageError("bounded conclusion accepted issuer set drift")
    if (
        not isinstance(new_ids, list)
        or not set(new_ids) <= set(accepted)
        or len(new_ids) != len(set(new_ids))
    ):
        raise CoverageError("bounded conclusion names an invalid new issuer set")
    if conclusion["status"] == "no_additional_exact_issuer_discovered" and new_ids:
        raise CoverageError("no-additional-issuer conclusion cannot name new issuers")
    if conclusion["internet_coverage"] != "bounded_snapshot_not_exhaustive":
        raise CoverageError(
            "issuer discovery must not claim exhaustive Internet coverage"
        )


def load_json(path: Path, description: str) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageError(f"cannot read {description}: {exc}") from exc


def run(
    coverage_path: Path = COVERAGE_PATH,
    provenance_path: Path = PROVENANCE_PATH,
    manifest_path: Path = MANIFEST_PATH,
) -> None:
    print(
        "[M3-05 1/3] Loading bounded discovery, provenance, and manifest inputs",
        flush=True,
    )
    coverage = load_json(coverage_path, "issuer coverage")
    provenance = load_json(provenance_path, "certificate provenance")
    manifest = load_json(manifest_path, "Russian PKI manifest")
    print(
        "[M3-05 2/3] Binding every observed issuer to exact reviewed identities and roots",
        flush=True,
    )
    validate_coverage(coverage, provenance, manifest)
    print(
        "[M3-05 3/3] Issuer coverage gate passed: "
        f"{len(coverage['accepted_issuers'])} reviewed issuer(s), "
        f"{len(coverage['live_chain_observations'])} exact live observation(s); "
        "discovery remains non-authoritative and non-exhaustive",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage", type=Path, default=COVERAGE_PATH)
    parser.add_argument("--provenance", type=Path, default=PROVENANCE_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args()
    try:
        run(args.coverage.resolve(), args.provenance.resolve(), args.manifest.resolve())
    except CoverageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

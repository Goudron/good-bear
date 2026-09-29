#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Validate the versioned, hash-pinned GB100-M3-02 Russian PKI manifest."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config/russian-pki-manifest.json"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
ENTRY_ID = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ManifestError(RuntimeError):
    pass


def require_mapping(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{description} must be an object")
    return value


def require_exact_fields(value: dict[str, Any], fields: set[str], description: str) -> None:
    if set(value) != fields:
        raise ManifestError(f"{description} has missing or unknown fields")


def parse_timestamp(value: Any, description: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ManifestError(f"{description} must be an RFC 3339 UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ManifestError(f"{description} is invalid") from exc


def validate_identity(value: Any, description: str) -> tuple[str, str]:
    identity = require_mapping(value, f"{description} identity")
    require_exact_fields(
        identity,
        {"certificate_der_sha256", "spki_der_sha256"},
        f"{description} identity",
    )
    certificate_hash = identity["certificate_der_sha256"]
    spki_hash = identity["spki_der_sha256"]
    for field, digest in (("certificate_der_sha256", certificate_hash), ("spki_der_sha256", spki_hash)):
        if not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest):
            raise ManifestError(f"{description} has malformed {field}")
    return certificate_hash, spki_hash


def validate_entry(entry: Any, *, expected_role: str, description: str) -> tuple[str, tuple[str, str]]:
    item = require_mapping(entry, description)
    expected_fields = {"id", "role", "identity", "provenance_id"}
    if expected_role == "intermediate":
        expected_fields.add("chains_to_anchor_identity")
    require_exact_fields(item, expected_fields, description)
    entry_id = item["id"]
    if not isinstance(entry_id, str) or not ENTRY_ID.fullmatch(entry_id):
        raise ManifestError(f"{description} has missing or malformed identity id")
    if item["role"] != expected_role:
        raise ManifestError(f"{description} role confusion: expected {expected_role}")
    if not isinstance(item["provenance_id"], str) or not ENTRY_ID.fullmatch(item["provenance_id"]):
        raise ManifestError(f"{description} has missing or malformed provenance_id")
    identity = validate_identity(item["identity"], description)
    return entry_id, identity


def validate_manifest(manifest: Any, *, now: datetime | None = None) -> None:
    document = require_mapping(manifest, "manifest")
    require_exact_fields(
        document,
        {"schema_version", "task", "manifest_id", "policy", "trust_anchors", "intermediates"},
        "manifest",
    )
    if document["schema_version"] != 1 or document["task"] != "GB100-M3-02":
        raise ManifestError("unexpected manifest schema or task")
    if document["manifest_id"] != "good-bear-russian-pki":
        raise ManifestError("unexpected manifest identity")

    policy = require_mapping(document["policy"], "policy")
    require_exact_fields(
        policy,
        {"issued_at", "expires_at", "remote_updates", "runtime_certificate_download", "trust_scope"},
        "policy",
    )
    issued_at = parse_timestamp(policy["issued_at"], "policy issued_at")
    expires_at = parse_timestamp(policy["expires_at"], "policy expires_at")
    if issued_at >= expires_at:
        raise ManifestError("policy expiry must follow issuance")
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        raise ManifestError("validation time must be timezone-aware")
    current_time = current_time.astimezone(timezone.utc)
    if current_time < issued_at or current_time >= expires_at:
        raise ManifestError("policy metadata is expired or not yet active")
    if policy["remote_updates"] is not False or policy["runtime_certificate_download"] is not False:
        raise ManifestError("manifest policy must forbid dynamic certificate updates")
    if policy["trust_scope"] != "dedicated_russian_pki_container_only":
        raise ManifestError("manifest policy has an unsafe trust scope")

    anchors = document["trust_anchors"]
    intermediates = document["intermediates"]
    if not isinstance(anchors, list) or not anchors:
        raise ManifestError("manifest must contain at least one explicit trust anchor")
    if not isinstance(intermediates, list):
        raise ManifestError("intermediates must be a list separate from trust anchors")

    ids: set[str] = set()
    certificate_hashes: set[str] = set()
    anchor_identities: set[tuple[str, str]] = set()
    for index, anchor in enumerate(anchors):
        entry_id, identity = validate_entry(
            anchor, expected_role="trust_anchor", description=f"trust anchor {index}"
        )
        if entry_id in ids or identity[0] in certificate_hashes:
            raise ManifestError("duplicate trust identity")
        ids.add(entry_id)
        certificate_hashes.add(identity[0])
        anchor_identities.add(identity)

    for index, intermediate in enumerate(intermediates):
        entry_id, identity = validate_entry(
            intermediate, expected_role="intermediate", description=f"intermediate {index}"
        )
        if entry_id in ids or identity[0] in certificate_hashes:
            raise ManifestError("duplicate trust identity")
        parent_identity = validate_identity(
            require_mapping(intermediate, f"intermediate {index}")["chains_to_anchor_identity"],
            f"intermediate {index} parent anchor",
        )
        if parent_identity not in anchor_identities:
            raise ManifestError("intermediate does not name an explicit anchor identity")
        ids.add(entry_id)
        certificate_hashes.add(identity[0])


def load_manifest(path: Path = MANIFEST_PATH, *, now: datetime | None = None) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read Russian PKI manifest: {exc}") from exc
    validate_manifest(manifest, now=now)
    return manifest


def run(path: Path = MANIFEST_PATH) -> None:
    print("[M3-02 1/2] Validating versioned Russian PKI manifest contract", flush=True)
    manifest = load_manifest(path)
    print(
        "[M3-02 2/2] Manifest contract passed: "
        f"{len(manifest['trust_anchors'])} explicit anchor(s), "
        f"{len(manifest['intermediates'])} separate intermediate(s)",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args()
    try:
        run(args.manifest.resolve())
    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

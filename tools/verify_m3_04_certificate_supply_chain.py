#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fail closed on tampered or unreviewed Russian PKI build certificate inputs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

from project_temp import temporary_directory


ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = ROOT / "config/m3-01-certificate-provenance.json"
MANIFEST_PATH = ROOT / "config/russian-pki-manifest.json"
BUILD_INPUT_SCHEMA_VERSION = 1
BUILD_INPUT_TASK = "GB100-M3-03"


class SupplyChainError(RuntimeError):
    pass


def load_tool_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SupplyChainError(f"cannot load required verifier {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M301 = load_tool_module("good_bear_m3_04_m3_01", ROOT / "tools/verify_m3_01_certificate_provenance.py")
M302 = load_tool_module("good_bear_m3_04_m3_02", ROOT / "tools/verify_m3_02_russian_pki_manifest.py")


def canonical_digest(*documents: Any) -> str:
    encoded = b"\n".join(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        for document in documents
    )
    return hashlib.sha256(encoded).hexdigest()


def openssl(*args: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["openssl", *args], input=input_bytes, capture_output=True, check=False
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise SupplyChainError(f"certificate parsing failed: {detail}")
    return result.stdout


def certificate_identity(der: bytes) -> tuple[str, str]:
    """Parse DER and return the certificate and SubjectPublicKeyInfo pins."""
    openssl("x509", "-inform", "DER", "-noout", input_bytes=der)
    public_key = openssl("x509", "-inform", "DER", "-pubkey", "-noout", input_bytes=der)
    spki = openssl("pkey", "-pubin", "-outform", "DER", input_bytes=public_key)
    return hashlib.sha256(der).hexdigest(), hashlib.sha256(spki).hexdigest()


def certificate_text(der: bytes) -> str:
    return openssl("x509", "-inform", "DER", "-noout", "-text", input_bytes=der).decode(
        "utf-8", "replace"
    )


def certificate_name(der: bytes, option: str, prefix: str) -> str:
    output = openssl(
        "x509", "-inform", "DER", "-noout", option, "-nameopt", "RFC2253", input_bytes=der
    ).decode("utf-8", "replace").strip()
    if not output.startswith(prefix):
        raise SupplyChainError(f"unexpected OpenSSL output for {option}")
    return output.removeprefix(prefix)


def require_ca_constraints(der: bytes, certificate_id: str) -> None:
    text = certificate_text(der)
    if "X509v3 Basic Constraints: critical" not in text or "CA:TRUE" not in text:
        raise SupplyChainError(f"CA basic constraints rejected for {certificate_id}")
    if "X509v3 Key Usage: critical" not in text or "Certificate Sign" not in text:
        raise SupplyChainError(f"CA key usage rejected for {certificate_id}")


def verify_self_signed_root(der: bytes, certificate_id: str) -> None:
    if certificate_name(der, "-subject", "subject=") != certificate_name(der, "-issuer", "issuer="):
        raise SupplyChainError(f"trust anchor is not self-issued: {certificate_id}")
    with temporary_directory(prefix="good-bear-m3-04-root-") as temporary:
        certificate_path = Path(temporary) / "anchor.der"
        certificate_pem_path = Path(temporary) / "anchor.pem"
        certificate_path.write_bytes(der)
        certificate_pem_path.write_bytes(openssl("x509", "-inform", "DER", "-outform", "PEM", input_bytes=der))
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", str(certificate_pem_path), str(certificate_pem_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode:
        raise SupplyChainError(f"trust anchor self-signature rejected for {certificate_id}")


def verify_intermediate_chain(intermediate_der: bytes, anchor_der: bytes, certificate_id: str) -> None:
    if certificate_name(intermediate_der, "-subject", "subject=") == certificate_name(
        intermediate_der, "-issuer", "issuer="
    ):
        raise SupplyChainError(f"intermediate must not be self-issued: {certificate_id}")
    with temporary_directory(prefix="good-bear-m3-04-chain-") as temporary:
        directory = Path(temporary)
        anchor_path = directory / "anchor.pem"
        intermediate_path = directory / "intermediate.pem"
        anchor_path.write_bytes(openssl("x509", "-inform", "DER", "-outform", "PEM", input_bytes=anchor_der))
        intermediate_path.write_bytes(
            openssl("x509", "-inform", "DER", "-outform", "PEM", input_bytes=intermediate_der)
        )
        result = subprocess.run(
            [
                "openssl", "verify", "-CAfile", str(anchor_path),
                "-untrusted", str(intermediate_path), str(intermediate_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode:
        raise SupplyChainError(f"intermediate chain rejected for {certificate_id}")


def expected_entries(manifest: dict[str, Any]) -> list[tuple[dict[str, Any], str]]:
    return [
        *((entry, "trust_anchor") for entry in manifest["trust_anchors"]),
        *((entry, "intermediate") for entry in manifest["intermediates"]),
    ]


def reviewed_records(provenance: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {record["id"]: record for record in provenance["certificates"]}


def validate_reviewed_rotation(manifest: dict[str, Any], records: dict[str, dict[str, Any]]) -> None:
    """Require every active anchor and intermediate to have an explicit reviewed record.

    ``records`` may contain retired certificates, so removing an active anchor is
    permitted. Adding an anchor is not: it must first receive an exact reviewed
    provenance record, including both certificate and SPKI pins.
    """
    seen_ids: set[str] = set()
    for entry, expected_role in expected_entries(manifest):
        certificate_id = entry["id"]
        if certificate_id in seen_ids:
            raise SupplyChainError(f"duplicate active certificate id: {certificate_id}")
        seen_ids.add(certificate_id)
        record = records.get(entry["provenance_id"])
        if record is None or record.get("id") != certificate_id:
            raise SupplyChainError(f"unreviewed active certificate: {certificate_id}")
        if record.get("role") != expected_role:
            raise SupplyChainError(f"reviewed role mismatch for {certificate_id}")
        if (
            record.get("certificate_der_sha256") != entry["identity"]["certificate_der_sha256"]
            or record.get("spki_der_sha256") != entry["identity"]["spki_der_sha256"]
        ):
            raise SupplyChainError(f"reviewed certificate identity drift for {certificate_id}")


def load_build_index(build_inputs_dir: Path) -> dict[str, Any]:
    try:
        index = json.loads((build_inputs_dir / "build-inputs.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SupplyChainError(f"cannot read promoted build-inputs index: {exc}") from exc
    required = {
        "schema_version", "task", "source_contract_sha256", "runtime_certificate_download", "certificates"
    }
    if set(index) != required:
        raise SupplyChainError("build-inputs index has missing or unknown fields")
    if index["schema_version"] != BUILD_INPUT_SCHEMA_VERSION or index["task"] != BUILD_INPUT_TASK:
        raise SupplyChainError("unexpected promoted build-inputs schema or task")
    if index["runtime_certificate_download"] is not False:
        raise SupplyChainError("promoted build inputs permit runtime certificate download")
    if not isinstance(index["certificates"], list):
        raise SupplyChainError("promoted build-inputs certificates must be a list")
    return index


def validate_build_inputs(
    build_inputs_dir: Path,
    manifest: dict[str, Any],
    records: dict[str, dict[str, Any]],
    *,
    source_contract_sha256: str | None = None,
) -> None:
    """Validate one promoted M3-03 build-input tree without accepting test inputs."""
    if shutil.which("openssl") is None:
        raise SupplyChainError("OpenSSL is required for the M3-04 certificate supply-chain gate")
    M302.validate_manifest(manifest)
    validate_reviewed_rotation(manifest, records)
    index = load_build_index(build_inputs_dir)
    if source_contract_sha256 is not None and index["source_contract_sha256"] != source_contract_sha256:
        raise SupplyChainError("promoted build-inputs source contract drift")

    expected: dict[str, tuple[dict[str, Any], str, Path]] = {}
    for entry, role in expected_entries(manifest):
        certificate_id = entry["id"]
        expected[certificate_id] = (entry, role, Path(role) / f"{certificate_id}.der")

    indexed: dict[str, dict[str, Any]] = {}
    required_entry = {
        "id", "role", "path", "source_payload_sha256", "certificate_der_sha256", "spki_der_sha256"
    }
    for item in index["certificates"]:
        if not isinstance(item, dict) or set(item) != required_entry:
            raise SupplyChainError("build-inputs certificate index has missing or unknown fields")
        certificate_id = item.get("id")
        if not isinstance(certificate_id, str) or certificate_id in indexed:
            raise SupplyChainError("duplicate or malformed build-input certificate id")
        indexed[certificate_id] = item
    if set(indexed) != set(expected):
        raise SupplyChainError("promoted build-inputs include missing, unreviewed, or test certificates")

    expected_files = {Path("build-inputs.json")}
    der_by_id: dict[str, bytes] = {}
    for certificate_id, (entry, role, relative_path) in expected.items():
        item = indexed[certificate_id]
        identity = entry["identity"]
        record = records[entry["provenance_id"]]
        if (
            item["role"] != role
            or item["path"] != relative_path.as_posix()
            or item["certificate_der_sha256"] != identity["certificate_der_sha256"]
            or item["spki_der_sha256"] != identity["spki_der_sha256"]
            or item["source_payload_sha256"] != record.get("source_payload_sha256")
        ):
            raise SupplyChainError(f"build-inputs manifest drift for {certificate_id}")
        expected_files.add(relative_path)
        try:
            der = (build_inputs_dir / relative_path).read_bytes()
        except OSError as exc:
            raise SupplyChainError(f"missing promoted certificate input: {relative_path}") from exc
        actual_identity = certificate_identity(der)
        if actual_identity != (identity["certificate_der_sha256"], identity["spki_der_sha256"]):
            raise SupplyChainError(f"DER-to-manifest identity mismatch for {certificate_id}")
        require_ca_constraints(der, certificate_id)
        der_by_id[certificate_id] = der

    actual_files: set[Path] = set()
    for path in build_inputs_dir.rglob("*"):
        if path.is_symlink() or (path.exists() and not path.is_file() and not path.is_dir()):
            raise SupplyChainError("promoted build-inputs contain a non-regular path")
        if path.is_file():
            actual_files.add(path.relative_to(build_inputs_dir))
    if actual_files != expected_files:
        raise SupplyChainError("promoted build-inputs contain unexpected files or test-anchor leakage")

    for certificate_id, (entry, role, _) in expected.items():
        if role == "trust_anchor":
            verify_self_signed_root(der_by_id[certificate_id], certificate_id)
        else:
            parent = entry["chains_to_anchor_identity"]
            parent_id = next(
                (
                    anchor_id
                    for anchor_id, (anchor, anchor_role, _) in expected.items()
                    if anchor_role == "trust_anchor" and anchor["identity"] == parent
                ),
                None,
            )
            if parent_id is None:
                raise SupplyChainError(f"intermediate parent anchor is unavailable for {certificate_id}")
            verify_intermediate_chain(der_by_id[certificate_id], der_by_id[parent_id], certificate_id)


def load_production_contract(
    provenance_path: Path = PROVENANCE_PATH, manifest_path: Path = MANIFEST_PATH
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], str]:
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SupplyChainError(f"cannot read production M3 inputs: {exc}") from exc
    try:
        M301.validate_manifest(provenance)
        M302.validate_manifest(manifest)
    except (M301.ProvenanceError, M302.ManifestError) as exc:
        raise SupplyChainError(f"production M3 contract rejected: {exc}") from exc
    return manifest, reviewed_records(provenance), canonical_digest(provenance, manifest)


def run(build_inputs_dir: Path) -> None:
    print("[M3-04 1/3] Loading approved production provenance and manifest", flush=True)
    manifest, records, digest = load_production_contract()
    print("[M3-04 2/3] Checking promoted DER files against reviewed identities", flush=True)
    validate_build_inputs(build_inputs_dir, manifest, records, source_contract_sha256=digest)
    print("[M3-04 3/3] Supply-chain tamper, role, rotation, and test-separation gate passed", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-input-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.build_input_dir.resolve())
    except SupplyChainError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Verify current official GB100-M3-01 certificate provenance without bundling bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

from project_temp import temporary_directory


ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = ROOT / "config/m3-01-certificate-provenance.json"
MAX_CERTIFICATE_BYTES = 64 * 1024
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
LEGACY_CDP_INTERMEDIATE_ID = "russian_trusted_sub_ca_rsa_2024"
LEGACY_CDP_INTERMEDIATE_URL = (
    "http://nuc-cdp.digital.gov.ru/cdp/subca_ssl_rsa2024.crt"
)


class ProvenanceError(RuntimeError):
    pass


def load_manifest(path: Path = PROVENANCE_PATH) -> dict:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"cannot read provenance manifest: {exc}") from exc
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: dict) -> None:
    if manifest.get("schema_version") != 1 or manifest.get("task") != "GB100-M3-01":
        raise ProvenanceError("unexpected provenance schema or task")
    evidence = manifest.get("official_source_evidence", {})
    if evidence.get("distribution_page") != "https://www.gosuslugi.ru/crt":
        raise ProvenanceError("official Gosuslugi distribution page is not pinned")
    if evidence.get("retrieval_transport") is None or "bypasses are forbidden" not in evidence["retrieval_transport"]:
        raise ProvenanceError("TLS verification bypass must be forbidden")

    certificates = manifest.get("certificates")
    if not isinstance(certificates, list) or not certificates:
        raise ProvenanceError("at least one explicit trust anchor is required")
    ids = {certificate.get("id") for certificate in certificates}
    if len(ids) != len(certificates) or not all(isinstance(certificate_id, str) and certificate_id for certificate_id in ids):
        raise ProvenanceError("certificate identities are incomplete")
    roles = {certificate.get("role") for certificate in certificates}
    if not roles <= {"trust_anchor", "intermediate"} or "trust_anchor" not in roles:
        raise ProvenanceError("certificate roles are incomplete")
    anchor_ids = {certificate["id"] for certificate in certificates if certificate["role"] == "trust_anchor"}
    for certificate in certificates:
        source_url = certificate.get("source_url", "")
        parsed = urllib.parse.urlparse(source_url)
        https_asset = parsed.scheme == "https" and parsed.hostname == "gu-st.ru"
        # The Ministry's currently published RSA-2024 issuing certificate is
        # exposed by its CDP only over HTTP. This tightly scoped import
        # exception is not a general HTTP download rule: the URL is exact,
        # redirects are forbidden, and the source bytes, DER, SPKI, CA role,
        # and chain to the exact root are all pinned and verified before use.
        legacy_cdp_asset = (
            certificate.get("id") == LEGACY_CDP_INTERMEDIATE_ID
            and source_url == LEGACY_CDP_INTERMEDIATE_URL
        )
        if not https_asset and not legacy_cdp_asset:
            raise ProvenanceError("certificate source is not an approved official endpoint")
        for field in ("source_payload_sha256", "certificate_der_sha256", "spki_der_sha256"):
            if not HEX_SHA256.fullmatch(certificate.get(field, "")):
                raise ProvenanceError(f"malformed {field} for {certificate.get('id')}")
        if certificate.get("basic_constraints", {}).get("ca") is not True:
            raise ProvenanceError("both recorded certificates must be CA certificates")
        if certificate["role"] == "intermediate":
            if certificate.get("chains_to") not in anchor_ids:
                raise ProvenanceError(f"wrong role or chain parent for {certificate['id']}")
        elif "chains_to" in certificate:
            raise ProvenanceError(f"wrong role or chain parent for {certificate['id']}")

    redistribution = manifest.get("redistribution", {})
    disposition = manifest.get("disposition", {})
    if redistribution.get("status") != "approved_for_binary_redistribution":
        raise ProvenanceError("binary redistribution approval is missing")
    if redistribution.get("explicit_third_party_redistribution_grant_found") is not True:
        raise ProvenanceError("redistribution approval must be explicitly recorded")
    required_fail_safe = {
        "mode": "controlled_official_source_import_with_binary_bundle",
        "bundle_certificate_bytes": True,
        "commit_certificate_bytes": False,
        "runtime_download": False,
        "official_source_only": True,
        "require_source_payload_sha256": True,
        "require_certificate_der_sha256": True,
        "require_spki_der_sha256": True,
        "require_role_and_chain_validation": True,
    }
    for field, expected in required_fail_safe.items():
        if disposition.get(field) != expected:
            raise ProvenanceError(f"unsafe disposition field {field}")


def fetch_certificate(certificate: dict) -> bytes:
    request = urllib.request.Request(
        certificate["source_url"],
        headers={"User-Agent": "Good-Bear-Provenance-Gate/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.geturl() != certificate["source_url"]:
                raise ProvenanceError(f"redirect forbidden for {certificate['id']}")
            payload = response.read(MAX_CERTIFICATE_BYTES + 1)
    except ProvenanceError:
        raise
    except Exception as exc:
        raise ProvenanceError(f"official retrieval failed for {certificate['id']}: {exc}") from exc
    if not payload or len(payload) > MAX_CERTIFICATE_BYTES:
        raise ProvenanceError(f"invalid payload size for {certificate['id']}")
    return payload


def assert_payload_pin(certificate: dict, payload: bytes) -> None:
    actual = hashlib.sha256(payload).hexdigest()
    if actual != certificate["source_payload_sha256"]:
        raise ProvenanceError(
            f"source byte hash mismatch for {certificate['id']}: {actual}"
        )


def openssl(*args: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["openssl", *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise ProvenanceError(f"openssl {' '.join(args)} failed: {detail}")
    return result.stdout


def certificate_der(payload: bytes) -> bytes:
    return openssl("x509", "-inform", "PEM", "-outform", "DER", input_bytes=payload)


def certificate_field(payload: bytes, option: str, prefix: str) -> str:
    output = openssl(
        "x509", "-inform", "PEM", "-noout", option, "-nameopt", "RFC2253",
        input_bytes=payload,
    ).decode("utf-8").strip()
    if not output.startswith(prefix):
        raise ProvenanceError(f"unexpected OpenSSL output for {option}: {output}")
    return output.removeprefix(prefix)


def validate_certificate(certificate: dict, payload: bytes) -> bytes:
    assert_payload_pin(certificate, payload)
    der = certificate_der(payload)
    if hashlib.sha256(der).hexdigest() != certificate["certificate_der_sha256"]:
        raise ProvenanceError(f"DER certificate hash mismatch for {certificate['id']}")

    public_key = openssl("x509", "-inform", "PEM", "-pubkey", "-noout", input_bytes=payload)
    spki = openssl("pkey", "-pubin", "-outform", "DER", input_bytes=public_key)
    if hashlib.sha256(spki).hexdigest() != certificate["spki_der_sha256"]:
        raise ProvenanceError(f"SPKI hash mismatch for {certificate['id']}")

    expected_fields = {
        ("-subject", "subject="): certificate["subject_rfc2253"],
        ("-issuer", "issuer="): certificate["issuer_rfc2253"],
        ("-serial", "serial="): certificate["serial_number_hex"],
    }
    for (option, prefix), expected in expected_fields.items():
        if certificate_field(payload, option, prefix) != expected:
            raise ProvenanceError(f"{option[1:]} mismatch for {certificate['id']}")

    dates = openssl(
        "x509", "-inform", "PEM", "-noout", "-startdate", "-enddate", "-dateopt", "iso_8601",
        input_bytes=payload,
    ).decode("ascii").splitlines()
    actual_dates = dict(line.split("=", 1) for line in dates)
    expected_dates = {
        "notBefore": certificate["not_before"].replace("T", " "),
        "notAfter": certificate["not_after"].replace("T", " "),
    }
    if actual_dates != expected_dates:
        raise ProvenanceError(f"validity mismatch for {certificate['id']}: {actual_dates}")
    openssl("x509", "-inform", "PEM", "-noout", "-checkend", "0", input_bytes=payload)

    text = openssl("x509", "-inform", "PEM", "-noout", "-text", input_bytes=payload).decode("utf-8")
    path_length = certificate["basic_constraints"]["path_length"]
    required_fragments = (
        "Signature Algorithm: sha256WithRSAEncryption",
        "Public Key Algorithm: rsaEncryption",
        "X509v3 Basic Constraints: critical",
        f"CA:TRUE, pathlen:{path_length}",
        "X509v3 Key Usage: critical",
        "Digital Signature, Certificate Sign, CRL Sign",
    )
    if any(fragment not in text for fragment in required_fragments):
        raise ProvenanceError(f"algorithm, constraints, or key usage mismatch for {certificate['id']}")
    return der


def validate_chain(root_payload: bytes, intermediate_payload: bytes) -> None:
    with temporary_directory(prefix="good-bear-m3-01-") as temporary:
        directory = Path(temporary)
        root_path = directory / "root.pem"
        intermediate_path = directory / "intermediate.pem"
        root_path.write_bytes(root_payload)
        intermediate_path.write_bytes(intermediate_payload)
        for target in (root_path, intermediate_path):
            result = subprocess.run(
                ["openssl", "verify", "-CAfile", str(root_path), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode:
                raise ProvenanceError(
                    f"chain validation failed for {target.name}: {result.stderr.strip()}"
                )


def assert_adversarial_rejections(certificates: list[dict], payloads: dict[str, bytes]) -> None:
    root = next(item for item in certificates if item["role"] == "trust_anchor")
    intermediate = next(item for item in certificates if item["role"] == "intermediate")
    mutated = payloads[root["id"]] + b"\n"
    try:
        assert_payload_pin(root, mutated)
    except ProvenanceError:
        pass
    else:
        raise ProvenanceError("tampered source payload unexpectedly passed its exact byte pin")

    try:
        validate_certificate(root, payloads[intermediate["id"]])
    except ProvenanceError:
        pass
    else:
        raise ProvenanceError("intermediate unexpectedly passed as the trust anchor")


def run(path: Path = PROVENANCE_PATH) -> None:
    if shutil.which("openssl") is None:
        raise ProvenanceError("OpenSSL is required for the M3-01 provenance gate")
    print("[M3-01 1/4] Validating provenance and controlled bundle disposition", flush=True)
    manifest = load_manifest(path)
    certificates = manifest["certificates"]
    print("[M3-01 2/4] Retrieving pinned bytes from approved official sources", flush=True)
    payloads = {certificate["id"]: fetch_certificate(certificate) for certificate in certificates}
    print("[M3-01 3/4] Checking exact certificate/SPKI identities, roles, validity, and chain", flush=True)
    for certificate in certificates:
        validate_certificate(certificate, payloads[certificate["id"]])
    roots = {item["id"]: item for item in certificates if item["role"] == "trust_anchor"}
    for intermediate in (item for item in certificates if item["role"] == "intermediate"):
        validate_chain(payloads[roots[intermediate["chains_to"]]["id"]], payloads[intermediate["id"]])
    assert_adversarial_rejections(certificates, payloads)
    print("[M3-01 4/4] Official provenance gate passed; only verified bytes may enter binary bundles", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=PROVENANCE_PATH)
    args = parser.parse_args()
    try:
        run(args.manifest.resolve())
    except ProvenanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

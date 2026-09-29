#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Prepare verified, non-bundled Russian PKI certificate build inputs.

This is a controlled build/preparation tool.  It deliberately has no runtime
consumer: the browser receives only the promoted, verified build inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import sys
import urllib.request
import uuid
from typing import Any, Callable, NamedTuple


ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = ROOT / "config/m3-01-certificate-provenance.json"
MANIFEST_PATH = ROOT / "config/russian-pki-manifest.json"
MAX_CERTIFICATE_BYTES = 64 * 1024
TASK = "GB100-M3-03"
CACHE_SCHEMA_VERSION = 1
# Changing a source URL is an explicit source-code review event, not a remote
# update.  The bytes remain separately pinned in the M3-01 and M3-02 inputs.
OFFICIAL_SOURCE_URLS = {
    "russian_trusted_root_ca_rsa_2022": "https://gu-st.ru/content/Other/doc/russian_trusted_root_ca.cer",
    "russian_trusted_sub_ca_rsa_2022": "https://gu-st.ru/content/Other/doc/russian_trusted_sub_ca.cer",
    "russian_trusted_sub_ca_rsa_2024": "http://nuc-cdp.digital.gov.ru/cdp/subca_ssl_rsa2024.crt",
}


class ImportError(RuntimeError):
    pass


def load_tool_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load required verifier {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M301 = load_tool_module("good_bear_m3_01", ROOT / "tools/verify_m3_01_certificate_provenance.py")
M302 = load_tool_module("good_bear_m3_02", ROOT / "tools/verify_m3_02_russian_pki_manifest.py")


class CertificateInput(NamedTuple):
    id: str
    role: str
    provenance: dict[str, Any]
    identity: dict[str, str]


class InputContract(NamedTuple):
    certificates: tuple[CertificateInput, ...]
    digest: str


def canonical_digest(*documents: Any) -> str:
    encoded = b"\n".join(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        for document in documents
    )
    return hashlib.sha256(encoded).hexdigest()


def load_input_contract(
    provenance_path: Path = PROVENANCE_PATH, manifest_path: Path = MANIFEST_PATH
) -> InputContract:
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ImportError(f"cannot load M3 certificate inputs: {exc}") from exc
    try:
        M301.validate_manifest(provenance)
        M302.validate_manifest(manifest)
    except (M301.ProvenanceError, M302.ManifestError) as exc:
        raise ImportError(f"M3 certificate input contract rejected: {exc}") from exc

    disposition = provenance["disposition"]
    policy = manifest["policy"]
    required_disposition = {
        "mode": "controlled_official_source_import_with_binary_bundle",
        "bundle_certificate_bytes": True,
        "commit_certificate_bytes": False,
    }
    if any(disposition.get(key) != value for key, value in required_disposition.items()):
        raise ImportError(
            "M3-03 requires controlled official-source import with approved binary bundling"
        )
    if disposition["runtime_download"] or policy["runtime_certificate_download"]:
        raise ImportError("runtime certificate download is forbidden")

    records = {record["id"]: record for record in provenance["certificates"]}
    entries = [
        *( (entry, "trust_anchor") for entry in manifest["trust_anchors"] ),
        *( (entry, "intermediate") for entry in manifest["intermediates"] ),
    ]
    if set(records) != {entry["provenance_id"] for entry, _ in entries}:
        raise ImportError("provenance and Russian PKI manifest identities differ")

    anchors_by_identity = {
        (entry["identity"]["certificate_der_sha256"], entry["identity"]["spki_der_sha256"]): entry
        for entry in manifest["trust_anchors"]
    }
    certificates: list[CertificateInput] = []
    for entry, role in entries:
        record = records.get(entry["provenance_id"])
        if record is None or record["id"] != entry["id"]:
            raise ImportError(f"missing provenance for {entry['id']}")
        if record["role"] != role or entry["role"] != role:
            raise ImportError(f"wrong role for {entry['id']}")
        if record["source_url"] != OFFICIAL_SOURCE_URLS.get(entry["id"]):
            raise ImportError(f"official source drift for {entry['id']}")
        identity = entry["identity"]
        if (
            record["certificate_der_sha256"] != identity["certificate_der_sha256"]
            or record["spki_der_sha256"] != identity["spki_der_sha256"]
        ):
            raise ImportError(f"certificate identity drift for {entry['id']}")
        if role == "intermediate":
            parent = anchors_by_identity.get(
                (
                    entry["chains_to_anchor_identity"]["certificate_der_sha256"],
                    entry["chains_to_anchor_identity"]["spki_der_sha256"],
                )
            )
            if parent is None or record.get("chains_to") != parent["id"]:
                raise ImportError(f"intermediate chain parent drift for {entry['id']}")
        certificates.append(CertificateInput(entry["id"], role, record, identity))
    return InputContract(tuple(certificates), canonical_digest(provenance, manifest))


def fetch_official_certificate(certificate: CertificateInput) -> bytes:
    record = certificate.provenance
    request = urllib.request.Request(
        record["source_url"], headers={"User-Agent": "Good-Bear-M3-03-Import/1.0"}
    )
    try:
        # HTTPS sources use ordinary platform TLS validation. The sole HTTP
        # source is the reviewed legacy-CDP exception enforced by M3-01: its
        # exact source-byte, DER, SPKI, role, and root-chain pins still reject
        # every changed response before cache or build-input promotion.
        with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
            if response.geturl() != record["source_url"]:
                raise ImportError(f"redirect or source drift for {certificate.id}")
            content_type = response.headers.get_content_type()
            if content_type != record["source_media_type"]:
                raise ImportError(f"unexpected media type for {certificate.id}: {content_type}")
            declared_length = response.headers.get("Content-Length")
            payload = response.read(MAX_CERTIFICATE_BYTES + 1)
    except ImportError:
        raise
    except Exception as exc:
        raise ImportError(f"official retrieval failed for {certificate.id}: {exc}") from exc
    if not payload or len(payload) > MAX_CERTIFICATE_BYTES:
        raise ImportError(f"invalid payload size for {certificate.id}")
    if declared_length is not None:
        try:
            if int(declared_length) != len(payload):
                raise ImportError(f"partial download for {certificate.id}")
        except ValueError as exc:
            raise ImportError(f"invalid Content-Length for {certificate.id}") from exc
    return payload


def validate_payloads(contract: InputContract, payloads: dict[str, bytes]) -> dict[str, bytes]:
    expected_ids = {certificate.id for certificate in contract.certificates}
    if set(payloads) != expected_ids:
        raise ImportError("certificate payload set is incomplete or unexpected")
    der_by_id: dict[str, bytes] = {}
    for certificate in contract.certificates:
        try:
            # M3-01 validates the source-byte pin before parsing, then validates
            # DER and SPKI pins plus certificate identity and CA constraints.
            der_by_id[certificate.id] = M301.validate_certificate(
                certificate.provenance, payloads[certificate.id]
            )
        except M301.ProvenanceError as exc:
            raise ImportError(f"certificate validation failed for {certificate.id}: {exc}") from exc
    anchors = {item.id: item for item in contract.certificates if item.role == "trust_anchor"}
    if not anchors:
        raise ImportError("Russian PKI topology has no explicit trust anchor")
    try:
        for intermediate in (item for item in contract.certificates if item.role == "intermediate"):
            parent_id = intermediate.provenance.get("chains_to")
            parent = anchors.get(parent_id)
            if parent is None:
                raise ImportError(f"unreviewed chain parent for {intermediate.id}")
            M301.validate_chain(payloads[parent.id], payloads[intermediate.id])
    except M301.ProvenanceError as exc:
        raise ImportError(f"certificate chain validation failed: {exc}") from exc
    return der_by_id


def metadata_for(contract: InputContract, payloads: dict[str, bytes]) -> dict[str, Any]:
    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "task": TASK,
        "source_contract_sha256": contract.digest,
        "certificates": [
            {
                "id": certificate.id,
                "role": certificate.role,
                "source_payload_sha256": hashlib.sha256(payloads[certificate.id]).hexdigest(),
            }
            for certificate in contract.certificates
        ],
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def new_quarantine_stage(root: Path, label: str) -> Path:
    stage = root / "quarantine" / f"{label}-{uuid.uuid4().hex}"
    stage.mkdir(parents=True, exist_ok=False)
    return stage


def promote_release(root: Path, stage: Path) -> Path:
    releases = root / "releases"
    releases.mkdir(parents=True, exist_ok=True)
    release = releases / stage.name
    os.replace(stage, release)
    pending = root / f".current-{uuid.uuid4().hex}"
    pending.symlink_to(os.path.relpath(release, root), target_is_directory=True)
    os.replace(pending, root / "current")
    return release


def retrieve_to_quarantine(
    cache_dir: Path,
    contract: InputContract,
    fetcher: Callable[[CertificateInput], bytes],
) -> tuple[Path, dict[str, bytes]]:
    """Keep every network candidate quarantined until the whole set validates."""
    stage = new_quarantine_stage(cache_dir, "download")
    payloads: dict[str, bytes] = {}
    for certificate in contract.certificates:
        payload = fetcher(certificate)
        (stage / f"{certificate.id}.cer").write_bytes(payload)
        payloads[certificate.id] = payload
    return stage, payloads


def promote_verified_cache(stage: Path, contract: InputContract, payloads: dict[str, bytes]) -> None:
    write_json(stage / "metadata.json", metadata_for(contract, payloads))
    promote_release(stage.parents[1], stage)


def read_verified_cache(cache_dir: Path, contract: InputContract) -> dict[str, bytes]:
    current = cache_dir / "current"
    if not current.is_dir():
        raise ImportError("no verified certificate cache is available for offline rebuild")
    try:
        metadata = json.loads((current / "metadata.json").read_text(encoding="utf-8"))
        payloads = {
            certificate.id: (current / f"{certificate.id}.cer").read_bytes()
            for certificate in contract.certificates
        }
    except (OSError, json.JSONDecodeError) as exc:
        raise ImportError(f"cannot read verified certificate cache: {exc}") from exc
    if metadata != metadata_for(contract, payloads):
        raise ImportError("verified certificate cache metadata drift")
    return payloads


def write_build_inputs(
    output_dir: Path, contract: InputContract, payloads: dict[str, bytes], der_by_id: dict[str, bytes]
) -> None:
    stage = new_quarantine_stage(output_dir, "build-inputs")
    index: list[dict[str, str]] = []
    for certificate in contract.certificates:
        relative_path = Path(certificate.role) / f"{certificate.id}.der"
        target = stage / relative_path
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(der_by_id[certificate.id])
        index.append(
            {
                "id": certificate.id,
                "role": certificate.role,
                "path": relative_path.as_posix(),
                "source_payload_sha256": hashlib.sha256(payloads[certificate.id]).hexdigest(),
                "certificate_der_sha256": certificate.identity["certificate_der_sha256"],
                "spki_der_sha256": certificate.identity["spki_der_sha256"],
            }
        )
    write_json(
        stage / "build-inputs.json",
        {
            "schema_version": CACHE_SCHEMA_VERSION,
            "task": TASK,
            "source_contract_sha256": contract.digest,
            "runtime_certificate_download": False,
            "certificates": index,
        },
    )
    promote_release(output_dir, stage)


def run_import(
    *,
    cache_dir: Path,
    output_dir: Path,
    offline: bool,
    provenance_path: Path = PROVENANCE_PATH,
    manifest_path: Path = MANIFEST_PATH,
    fetcher: Callable[[CertificateInput], bytes] = fetch_official_certificate,
) -> None:
    if shutil.which("openssl") is None:
        raise ImportError("OpenSSL is required for the M3-03 certificate import gate")
    contract = load_input_contract(provenance_path, manifest_path)
    cache_stage: Path | None = None
    if offline:
        print("[M3-03 1/4] Loading only the verified offline certificate cache", flush=True)
        payloads = read_verified_cache(cache_dir, contract)
    else:
        print("[M3-03 1/4] Retrieving pinned official certificate bytes", flush=True)
        cache_stage, payloads = retrieve_to_quarantine(cache_dir, contract, fetcher)
    print("[M3-03 2/4] Checking exact byte, DER, SPKI, role, and chain pins", flush=True)
    der_by_id = validate_payloads(contract, payloads)
    if not offline:
        print("[M3-03 3/4] Promoting the fully verified certificate cache atomically", flush=True)
        assert cache_stage is not None
        promote_verified_cache(cache_stage, contract, payloads)
    else:
        print("[M3-03 3/4] Reusing the verified cache after complete revalidation", flush=True)
    print("[M3-03 4/4] Promoting verified build inputs atomically; runtime download remains disabled", flush=True)
    write_build_inputs(output_dir, contract, payloads, der_by_id)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--provenance", type=Path, default=PROVENANCE_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args()
    try:
        run_import(
            cache_dir=args.cache_dir.resolve(),
            output_dir=args.output_dir.resolve(),
            offline=args.offline,
            provenance_path=args.provenance.resolve(),
            manifest_path=args.manifest.resolve(),
        )
    except ImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

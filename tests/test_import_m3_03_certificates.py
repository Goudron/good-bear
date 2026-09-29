#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m3_03_import", ROOT / "tools/import_m3_03_certificates.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M303CertificateImportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="good-bear-m3-03-test-")
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.output = self.root / "output"
        self.payloads = {"test_root": b"root source bytes", "test_intermediate": b"intermediate source bytes"}
        self.contract = PROBE.InputContract(
            (
                self.certificate("test_root", "trust_anchor"),
                self.certificate("test_intermediate", "intermediate"),
            ),
            "c" * 64,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def certificate(self, certificate_id: str, role: str) -> object:
        payload = self.payloads[certificate_id]
        return PROBE.CertificateInput(
            certificate_id,
            role,
            {
                "id": certificate_id,
                "source_url": f"https://official.invalid/{certificate_id}.cer",
                "source_media_type": "application/octet-stream",
                "source_payload_sha256": hashlib.sha256(payload).hexdigest(),
            },
            {"certificate_der_sha256": "a" * 64, "spki_der_sha256": "b" * 64},
        )

    def run_synthetic(self, *, offline: bool, output: Path | None = None, fetcher=None) -> None:
        der = {certificate_id: b"DER-" + payload for certificate_id, payload in self.payloads.items()}
        with (
            mock.patch.object(PROBE, "load_input_contract", return_value=self.contract),
            mock.patch.object(PROBE, "validate_payloads", return_value=der),
        ):
            PROBE.run_import(
                cache_dir=self.cache,
                output_dir=output or self.output,
                offline=offline,
                fetcher=fetcher or (lambda certificate: self.payloads[certificate.id]),
            )

    def test_online_promotion_and_offline_rebuild_revalidate_verified_cache(self) -> None:
        self.run_synthetic(offline=False)
        self.assertTrue((self.cache / "current").is_dir())
        self.assertTrue((self.output / "current" / "trust_anchor" / "test_root.der").is_file())
        output = self.root / "offline-output"
        fetcher = mock.Mock(side_effect=AssertionError("offline rebuild attempted network retrieval"))
        self.run_synthetic(offline=True, output=output, fetcher=fetcher)
        fetcher.assert_not_called()
        index = json.loads((output / "current" / "build-inputs.json").read_text(encoding="utf-8"))
        self.assertFalse(index["runtime_certificate_download"])
        self.assertEqual({item["role"] for item in index["certificates"]}, {"trust_anchor", "intermediate"})

    def test_hash_mismatch_fails_before_cache_or_build_promotion(self) -> None:
        contract = PROBE.load_input_contract()
        bad = {certificate.id: b"not the exact official bytes" for certificate in contract.certificates}
        with self.assertRaisesRegex(PROBE.ImportError, "source byte hash mismatch"):
            PROBE.validate_payloads(contract, bad)
        self.assertFalse((self.cache / "current").exists())
        self.assertFalse((self.output / "current").exists())

    def test_partial_download_remains_quarantined_and_never_promotes(self) -> None:
        def partial_fetch(certificate):
            if certificate.id == "test_root":
                return self.payloads[certificate.id]
            raise PROBE.ImportError("partial download for test_intermediate")

        with (
            mock.patch.object(PROBE, "load_input_contract", return_value=self.contract),
            mock.patch.object(PROBE, "validate_payloads") as validation,
            self.assertRaisesRegex(PROBE.ImportError, "partial download"),
        ):
            PROBE.run_import(
                cache_dir=self.cache,
                output_dir=self.output,
                offline=False,
                fetcher=partial_fetch,
            )
        validation.assert_not_called()
        self.assertFalse((self.cache / "current").exists())
        quarantined = list((self.cache / "quarantine").iterdir())
        self.assertEqual(len(quarantined), 1)
        self.assertTrue((quarantined[0] / "test_root.cer").is_file())
        self.assertFalse((self.output / "current").exists())

    def test_unavailable_network_fails_before_certificate_validation_or_compilation_inputs(self) -> None:
        with (
            mock.patch.object(PROBE, "load_input_contract", return_value=self.contract),
            mock.patch.object(PROBE, "validate_payloads") as validation,
            self.assertRaisesRegex(PROBE.ImportError, "network unavailable"),
        ):
            PROBE.run_import(
                cache_dir=self.cache,
                output_dir=self.output,
                offline=False,
                fetcher=lambda _: (_ for _ in ()).throw(PROBE.ImportError("network unavailable")),
            )
        validation.assert_not_called()
        self.assertFalse((self.output / "current").exists())

    def test_tampered_cache_is_rejected_before_offline_build_promotion(self) -> None:
        self.run_synthetic(offline=False)
        (self.cache / "current" / "test_root.cer").write_bytes(b"tampered")
        output = self.root / "tampered-output"
        with (
            mock.patch.object(PROBE, "load_input_contract", return_value=self.contract),
            mock.patch.object(PROBE, "validate_payloads") as validation,
            self.assertRaisesRegex(PROBE.ImportError, "cache metadata drift"),
        ):
            PROBE.run_import(cache_dir=self.cache, output_dir=output, offline=True)
        validation.assert_not_called()
        self.assertFalse((output / "current").exists())

    def test_source_drift_and_wrong_role_are_rejected_before_retrieval(self) -> None:
        provenance = json.loads(PROBE.PROVENANCE_PATH.read_text(encoding="utf-8"))
        manifest = json.loads(PROBE.MANIFEST_PATH.read_text(encoding="utf-8"))
        provenance["certificates"][0]["source_url"] = "https://gu-st.ru/content/Other/doc/other.cer"
        provenance_path = self.root / "source-drift.json"
        manifest_path = self.root / "manifest.json"
        provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(PROBE.ImportError, "official source drift"):
            PROBE.load_input_contract(provenance_path, manifest_path)

        provenance = json.loads(PROBE.PROVENANCE_PATH.read_text(encoding="utf-8"))
        provenance["certificates"][0]["role"] = "intermediate"
        provenance["certificates"][1]["role"] = "trust_anchor"
        provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
        with self.assertRaisesRegex(PROBE.ImportError, "wrong role"):
            PROBE.load_input_contract(provenance_path, manifest_path)

    def test_binary_bundle_disposition_is_exact_and_never_permits_source_commit(self) -> None:
        provenance = json.loads(PROBE.PROVENANCE_PATH.read_text(encoding="utf-8"))
        manifest = json.loads(PROBE.MANIFEST_PATH.read_text(encoding="utf-8"))
        provenance_path = self.root / "unsafe-disposition.json"
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        for key, value in (
            ("mode", "controlled_official_source_import"),
            ("bundle_certificate_bytes", False),
            ("commit_certificate_bytes", True),
        ):
            unsafe = copy.deepcopy(provenance)
            unsafe["disposition"][key] = value
            provenance_path.write_text(json.dumps(unsafe), encoding="utf-8")
            # Exercise the importer's own disposition guard independently of
            # the provenance verifier, which enforces the same policy first.
            with mock.patch.object(PROBE.M301, "validate_manifest"):
                with self.assertRaisesRegex(PROBE.ImportError, "approved binary bundling"):
                    PROBE.load_input_contract(provenance_path, manifest_path)

    def test_source_response_redirect_and_truncation_are_rejected(self) -> None:
        certificate = self.contract.certificates[0]

        class Headers(dict):
            def get_content_type(self):
                return "application/octet-stream"

        class Response:
            def __init__(self, url, content_length, payload):
                self.url = url
                self.headers = Headers({"Content-Length": content_length})
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def geturl(self):
                return self.url

            def read(self, _):
                return self.payload

        with mock.patch.object(
            PROBE.urllib.request, "urlopen", return_value=Response("https://redirect.invalid/root", "1", b"x")
        ):
            with self.assertRaisesRegex(PROBE.ImportError, "redirect or source drift"):
                PROBE.fetch_official_certificate(certificate)
        with mock.patch.object(
            PROBE.urllib.request, "urlopen", return_value=Response(certificate.provenance["source_url"], "2", b"x")
        ):
            with self.assertRaisesRegex(PROBE.ImportError, "partial download"):
                PROBE.fetch_official_certificate(certificate)

    def test_multiple_reviewed_anchors_and_intermediates_are_checked_per_parent(self) -> None:
        self.payloads.update(
            {
                "test_root_next": b"next root source bytes",
                "test_intermediate_next": b"next intermediate source bytes",
            }
        )
        root = self.certificate("test_root", "trust_anchor")
        intermediate = self.certificate("test_intermediate", "intermediate")._replace(
            provenance={**self.certificate("test_intermediate", "intermediate").provenance, "chains_to": "test_root"}
        )
        next_root = self.certificate("test_root_next", "trust_anchor")
        next_intermediate = self.certificate("test_intermediate_next", "intermediate")._replace(
            provenance={
                **self.certificate("test_intermediate_next", "intermediate").provenance,
                "chains_to": "test_root_next",
            }
        )
        contract = PROBE.InputContract((root, intermediate, next_root, next_intermediate), "c" * 64)
        payloads = dict(self.payloads)
        der = {certificate_id: b"DER-" + payload for certificate_id, payload in payloads.items()}
        with (
            mock.patch.object(PROBE.M301, "validate_certificate", side_effect=lambda certificate, payload: der[certificate["id"]]),
            mock.patch.object(PROBE.M301, "validate_chain") as validate_chain,
        ):
            self.assertEqual(PROBE.validate_payloads(contract, payloads), der)
        self.assertEqual(
            validate_chain.call_args_list,
            [
                mock.call(payloads["test_root"], payloads["test_intermediate"]),
                mock.call(payloads["test_root_next"], payloads["test_intermediate_next"]),
            ],
        )


if __name__ == "__main__":
    unittest.main()

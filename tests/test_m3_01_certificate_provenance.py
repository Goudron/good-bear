#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config/m3-01-certificate-provenance.json"
SPEC = importlib.util.spec_from_file_location(
    "m3_01_provenance", ROOT / "tools/verify_m3_01_certificate_provenance.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M301CertificateProvenanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_acceptance_metadata_is_complete_and_exactly_role_separated(self) -> None:
        PROBE.validate_manifest(self.manifest)
        self.assertEqual(self.manifest["retrieved_at"], "2026-09-01T10:15:37Z")
        certificates = self.manifest["certificates"]
        self.assertEqual(
            {certificate["role"] for certificate in certificates},
            {"trust_anchor", "intermediate"},
        )
        for certificate in certificates:
            for field in (
                "source_url", "source_payload_sha256", "certificate_der_sha256",
                "spki_der_sha256", "serial_number_hex", "subject_rfc2253",
                "issuer_rfc2253", "not_before", "not_after", "role",
            ):
                self.assertTrue(certificate[field], f"{certificate['id']}: {field}")
        root = next(item for item in certificates if item["role"] == "trust_anchor")
        intermediates = [item for item in certificates if item["role"] == "intermediate"]
        self.assertEqual(root["subject_rfc2253"], root["issuer_rfc2253"])
        self.assertTrue(intermediates)
        for intermediate in intermediates:
            self.assertEqual(intermediate["issuer_rfc2253"], root["subject_rfc2253"])
            self.assertEqual(intermediate["chains_to"], root["id"])
        self.assertEqual(root["basic_constraints"]["path_length"], 4)
        self.assertTrue(all(item["basic_constraints"]["path_length"] == 0 for item in intermediates))

    def test_owner_approved_rights_allow_only_verified_binary_bundling(self) -> None:
        redistribution = self.manifest["redistribution"]
        disposition = self.manifest["disposition"]
        self.assertEqual(redistribution["status"], "approved_for_binary_redistribution")
        self.assertTrue(redistribution["explicit_third_party_redistribution_grant_found"])
        self.assertEqual(disposition["mode"], "controlled_official_source_import_with_binary_bundle")
        self.assertTrue(disposition["bundle_certificate_bytes"])
        self.assertFalse(disposition["commit_certificate_bytes"])
        self.assertFalse(disposition["runtime_download"])
        self.assertTrue(disposition["require_role_and_chain_validation"])

    def test_adversarial_unapproved_bundling_is_rejected(self) -> None:
        unsafe = copy.deepcopy(self.manifest)
        unsafe["redistribution"]["explicit_third_party_redistribution_grant_found"] = False
        with self.assertRaisesRegex(PROBE.ProvenanceError, "approval"):
            PROBE.validate_manifest(unsafe)

    def test_adversarial_nonofficial_or_malformed_pin_is_rejected(self) -> None:
        nonofficial = copy.deepcopy(self.manifest)
        nonofficial["certificates"][0]["source_url"] = "https://example.invalid/root.cer"
        with self.assertRaisesRegex(PROBE.ProvenanceError, "approved official endpoint"):
            PROBE.validate_manifest(nonofficial)
        malformed = copy.deepcopy(self.manifest)
        malformed["certificates"][1]["spki_der_sha256"] = "00"
        with self.assertRaisesRegex(PROBE.ProvenanceError, "malformed spki"):
            PROBE.validate_manifest(malformed)

    def test_adversarial_payload_drift_is_rejected_before_parsing(self) -> None:
        certificate = self.manifest["certificates"][0]
        with self.assertRaisesRegex(PROBE.ProvenanceError, "source byte hash mismatch"):
            PROBE.assert_payload_pin(certificate, b"not the official certificate")

    def test_accepts_reviewed_rotation_and_rejects_an_unpinned_parent(self) -> None:
        rotated = copy.deepcopy(self.manifest)
        root = copy.deepcopy(rotated["certificates"][0])
        intermediate = copy.deepcopy(rotated["certificates"][1])
        root["id"] = "russian_trusted_root_ca_rsa_2027"
        root["source_url"] = "https://gu-st.ru/content/Other/doc/russian_trusted_root_ca_2027.cer"
        root["source_payload_sha256"] = "a" * 64
        root["certificate_der_sha256"] = "b" * 64
        root["spki_der_sha256"] = "c" * 64
        intermediate["id"] = "russian_trusted_sub_ca_rsa_2027"
        intermediate["source_url"] = "https://gu-st.ru/content/Other/doc/russian_trusted_sub_ca_2027.cer"
        intermediate["source_payload_sha256"] = "d" * 64
        intermediate["certificate_der_sha256"] = "e" * 64
        intermediate["spki_der_sha256"] = "f" * 64
        intermediate["chains_to"] = root["id"]
        rotated["certificates"].extend((root, intermediate))
        PROBE.validate_manifest(rotated)

        intermediate["chains_to"] = "unreviewed_root"
        with self.assertRaisesRegex(PROBE.ProvenanceError, "wrong role or chain parent"):
            PROBE.validate_manifest(rotated)


if __name__ == "__main__":
    unittest.main()

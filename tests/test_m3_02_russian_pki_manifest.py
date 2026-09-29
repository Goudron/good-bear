#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config/russian-pki-manifest.json"
SPEC = importlib.util.spec_from_file_location(
    "m3_02_manifest", ROOT / "tools/verify_m3_02_russian_pki_manifest.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M302RussianPkiManifestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.now = datetime(2026, 8, 26, tzinfo=timezone.utc)

    def validate(self, manifest: dict) -> None:
        PROBE.validate_manifest(manifest, now=self.now)

    def test_accepts_hash_pinned_anchor_and_separate_intermediate(self) -> None:
        self.validate(self.manifest)
        anchor = self.manifest["trust_anchors"][0]
        intermediate = self.manifest["intermediates"][0]
        self.assertEqual(anchor["role"], "trust_anchor")
        self.assertEqual(intermediate["role"], "intermediate")
        self.assertEqual(intermediate["chains_to_anchor_identity"], anchor["identity"])

    def test_accepts_multiple_explicit_anchors(self) -> None:
        rotated = copy.deepcopy(self.manifest)
        additional_anchor = copy.deepcopy(rotated["trust_anchors"][0])
        additional_anchor["id"] = "russian_trusted_root_ca_rsa_2027"
        additional_anchor["provenance_id"] = "russian_trusted_root_ca_rsa_2027"
        additional_anchor["identity"]["certificate_der_sha256"] = "a" * 64
        additional_anchor["identity"]["spki_der_sha256"] = "b" * 64
        rotated["trust_anchors"].append(additional_anchor)
        self.validate(rotated)

    def test_rejects_missing_or_duplicate_identity(self) -> None:
        missing = copy.deepcopy(self.manifest)
        del missing["trust_anchors"][0]["identity"]
        with self.assertRaisesRegex(PROBE.ManifestError, "missing or unknown fields"):
            self.validate(missing)

        duplicate = copy.deepcopy(self.manifest)
        duplicate["intermediates"][0]["id"] = duplicate["trust_anchors"][0]["id"]
        with self.assertRaisesRegex(PROBE.ManifestError, "duplicate trust identity"):
            self.validate(duplicate)

        duplicate_hash = copy.deepcopy(self.manifest)
        duplicate_hash["intermediates"][0]["identity"]["certificate_der_sha256"] = (
            duplicate_hash["trust_anchors"][0]["identity"]["certificate_der_sha256"]
        )
        with self.assertRaisesRegex(PROBE.ManifestError, "duplicate trust identity"):
            self.validate(duplicate_hash)

    def test_rejects_role_confusion_and_intermediate_as_root(self) -> None:
        confused_anchor = copy.deepcopy(self.manifest)
        confused_anchor["trust_anchors"][0]["role"] = "intermediate"
        with self.assertRaisesRegex(PROBE.ManifestError, "role confusion"):
            self.validate(confused_anchor)

        intermediate_as_root = copy.deepcopy(self.manifest)
        intermediate_as_root["intermediates"][0]["role"] = "trust_anchor"
        with self.assertRaisesRegex(PROBE.ManifestError, "role confusion"):
            self.validate(intermediate_as_root)

    def test_rejects_malformed_hash_and_unpinned_parent(self) -> None:
        malformed = copy.deepcopy(self.manifest)
        malformed["trust_anchors"][0]["identity"]["spki_der_sha256"] = "not-a-hash"
        with self.assertRaisesRegex(PROBE.ManifestError, "malformed spki_der_sha256"):
            self.validate(malformed)

        unpinned_parent = copy.deepcopy(self.manifest)
        unpinned_parent["intermediates"][0]["chains_to_anchor_identity"]["certificate_der_sha256"] = "c" * 64
        with self.assertRaisesRegex(PROBE.ManifestError, "does not name an explicit anchor identity"):
            self.validate(unpinned_parent)

    def test_rejects_expired_or_dynamic_policy_metadata(self) -> None:
        expired = copy.deepcopy(self.manifest)
        expired["policy"]["issued_at"] = "2026-08-24T00:00:00Z"
        expired["policy"]["expires_at"] = "2026-08-25T23:59:59Z"
        with self.assertRaisesRegex(PROBE.ManifestError, "policy metadata is expired"):
            self.validate(expired)

        dynamic = copy.deepcopy(self.manifest)
        dynamic["policy"]["runtime_certificate_download"] = True
        with self.assertRaisesRegex(PROBE.ManifestError, "forbid dynamic certificate updates"):
            self.validate(dynamic)


if __name__ == "__main__":
    unittest.main()

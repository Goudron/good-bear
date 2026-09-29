#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/verify_m3_05_issuer_coverage.py"
SPEC = importlib.util.spec_from_file_location("good_bear_m3_05", TOOL_PATH)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M305IssuerCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.coverage = json.loads(PROBE.COVERAGE_PATH.read_text(encoding="utf-8"))
        cls.provenance = json.loads(PROBE.PROVENANCE_PATH.read_text(encoding="utf-8"))
        cls.manifest = json.loads(PROBE.MANIFEST_PATH.read_text(encoding="utf-8"))

    def validate(self, coverage: dict, *, manifest: dict | None = None) -> None:
        PROBE.validate_coverage(
            coverage,
            self.provenance,
            manifest if manifest is not None else self.manifest,
        )

    def test_production_snapshot_binds_every_active_intermediate_to_exact_reviewed_inputs(
        self,
    ) -> None:
        self.validate(self.coverage)
        self.assertEqual(
            {item["id"] for item in self.coverage["accepted_issuers"]},
            {item["id"] for item in self.manifest["intermediates"]},
        )
        self.assertFalse(self.coverage["bounded_conclusion"]["new_issuer_ids_added"])

    def test_discovery_source_cannot_authorize_trust(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["discovery_sources"][0]["trust_authority"] = True
        with self.assertRaisesRegex(PROBE.CoverageError, "must never authorize trust"):
            self.validate(coverage)

    def test_rejects_unreviewed_or_missing_active_issuer(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["accepted_issuers"] = coverage["accepted_issuers"][1:]
        coverage["bounded_conclusion"]["accepted_issuer_ids"] = [
            coverage["accepted_issuers"][0]["id"]
        ]
        with self.assertRaisesRegex(
            PROBE.CoverageError, "coverage and active manifest"
        ):
            self.validate(coverage)

        coverage = copy.deepcopy(self.coverage)
        fake = copy.deepcopy(coverage["accepted_issuers"][0])
        fake["id"] = "unreviewed_candidate"
        fake["provenance_id"] = "unreviewed_candidate"
        coverage["accepted_issuers"].append(fake)
        coverage["bounded_conclusion"]["accepted_issuer_ids"].append(fake["id"])
        with self.assertRaisesRegex(PROBE.CoverageError, "unreviewed or inactive"):
            self.validate(coverage)

    def test_rejects_identity_and_root_parent_drift(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["accepted_issuers"][0]["identity"]["certificate_der_sha256"] = "a" * 64
        with self.assertRaisesRegex(PROBE.CoverageError, "manifest identity drift"):
            self.validate(coverage)

        coverage = copy.deepcopy(self.coverage)
        coverage["accepted_issuers"][0]["chains_to_anchor_identity"][
            "certificate_der_sha256"
        ] = "b" * 64
        with self.assertRaisesRegex(PROBE.CoverageError, "existing exact root"):
            self.validate(coverage)

    def test_rejects_role_confusion_and_artifact_hash_drift(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["accepted_issuers"][0]["role"] = "trust_anchor"
        with self.assertRaisesRegex(PROBE.CoverageError, "role confusion"):
            self.validate(coverage)

        coverage = copy.deepcopy(self.coverage)
        coverage["accepted_issuers"][0]["artifact_observations"][0][
            "certificate_der_sha256"
        ] = "c" * 64
        with self.assertRaisesRegex(PROBE.CoverageError, "not the reviewed issuer"):
            self.validate(coverage)

    def test_rejects_official_source_drift(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["accepted_issuers"][0]["official_source_url"] = (
            "https://example.invalid/unreviewed.cer"
        )
        with self.assertRaisesRegex(PROBE.CoverageError, "official source drift"):
            self.validate(coverage)

    def test_rejects_unreviewed_live_issuer_or_unverified_hostname(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["live_chain_observations"][0]["issuer_id"] = "unknown_issuer"
        with self.assertRaisesRegex(PROBE.CoverageError, "unreviewed issuer"):
            self.validate(coverage)

        coverage = copy.deepcopy(self.coverage)
        coverage["live_chain_observations"][0]["hostname_verified"] = False
        with self.assertRaisesRegex(PROBE.CoverageError, "did not verify the hostname"):
            self.validate(coverage)

    def test_rejects_exhaustive_claim_or_runtime_update(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["bounded_conclusion"]["internet_coverage"] = "all_internet_sites"
        with self.assertRaisesRegex(PROBE.CoverageError, "must not claim exhaustive"):
            self.validate(coverage)

        coverage = copy.deepcopy(self.coverage)
        coverage["policy"]["runtime_certificate_download"] = True
        with self.assertRaisesRegex(
            PROBE.CoverageError, "weakens a fail-closed invariant"
        ):
            self.validate(coverage)


if __name__ == "__main__":
    unittest.main()

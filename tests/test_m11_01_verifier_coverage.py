#!/usr/bin/env python3
"""Static acceptance guard for the production-equivalent M11-01 gtest contour."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
CONTRACT = json.loads(
    (ROOT / "config/m11-01-verifier-coverage-contract.json").read_text(encoding="utf-8")
)
MATRIX = json.loads((ROOT / "config/m2-05-pki-fixture-matrix.json").read_text(encoding="utf-8"))


class M1101VerifierCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gtest = (FIREFOX / CONTRACT["test_owner"]).read_text(encoding="utf-8")
        cls.build = (FIREFOX / CONTRACT["test_build_owner"]).read_text(encoding="utf-8")
        cls.scenarios = {scenario["id"]: scenario for scenario in MATRIX["scenarios"]}

    def test_contract_is_pinned_to_the_fixture_and_production_gates(self) -> None:
        self.assertEqual(CONTRACT["schema_version"], 1)
        self.assertEqual(CONTRACT["task"], "GB100-M11-01")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        self.assertEqual(CONTRACT["fixture_matrix"], "config/m2-05-pki-fixture-matrix.json")
        self.assertEqual(
            CONTRACT["supply_chain_gate"], "tools/verify_m3_04_certificate_supply_chain.py"
        )
        self.assertIn("must not be added to the ordinary NSS store", CONTRACT["test_only_root_boundary"])
        self.assertIn("production manifest", CONTRACT["test_only_root_boundary"])

    def test_required_matrix_scenarios_are_owned_by_the_production_gtest(self) -> None:
        for scenario_id, test_name in CONTRACT["required_scenarios"].items():
            scenario = self.scenarios[scenario_id]
            self.assertEqual(scenario["owner"], CONTRACT["test_owner"], scenario_id)
            self.assertEqual(scenario["harness"], "gtest", scenario_id)
            self.assertIn(test_name, self.gtest, scenario_id)

    def test_every_declared_x509_negative_preserves_the_standard_error(self) -> None:
        for test_name in CONTRACT["required_scenarios"].values():
            if test_name.endswith("RetainsOriginalTLSError"):
                self.assertIn(test_name, self.gtest)
        for test_name in CONTRACT["required_algorithm_negatives"]:
            self.assertIn(test_name, self.gtest)
        for required in (
            "PKIXResult::ERROR_UNKNOWN_ISSUER, result.mResult",
            "ASSERT_FALSE(result.ChannelUsable())",
            "NonEligibleFailureNeverUsesAlternateTrustEvenInDedicatedContainer",
        ):
            self.assertIn(required, self.gtest)

    def test_exact_anchor_chain_and_role_boundaries_use_the_real_verifier_path(self) -> None:
        for test_name in CONTRACT["required_role_separation"]:
            self.assertIn(test_name, self.gtest)
        for required in (
            "VerifyGoodBearRussianPKISSLServerCert(",
            "GetGoodBearRussianPKIExactTrustAnchors(roots)",
            "GetGoodBearRussianPKIApprovedIntermediates(intermediates)",
            "VerifyStandardRussianPKI()",
            "ASSERT_NE(Success, VerifyStandardRussianPKI())",
        ):
            self.assertIn(required, self.gtest)

    def test_test_material_is_staged_only_for_gtest_and_cannot_be_a_release_input(self) -> None:
        self.assertIn("TEST_HARNESS_FILES.gtest", self.build)
        for fixture in (
            "russian-root.pem",
            "russian-intermediate.pem",
            "russian-leaf.pem",
            "same-name-fake-leaf.pem",
            "bad-signature-leaf.pem",
        ):
            self.assertIn(f'"goodbear-russian-pki/{fixture}"', self.build)

        supply_gate = (ROOT / CONTRACT["supply_chain_gate"]).read_text(encoding="utf-8")
        for required in (
            "promoted build-inputs include missing, unreviewed, or test certificates",
            "promoted build-inputs contain unexpected files or test-anchor leakage",
            "validate_reviewed_rotation",
        ):
            self.assertIn(required, supply_gate)


if __name__ == "__main__":
    unittest.main()

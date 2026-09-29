#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "config/m2-05-pki-fixture-matrix.json"


class M205PKIFixtureMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
        cls.fixtures = {fixture["id"]: fixture for fixture in cls.matrix["fixtures"]}

    def test_matrix_is_pinned_offline_and_separates_test_trust(self) -> None:
        self.assertEqual(self.matrix["schema_version"], 1)
        self.assertEqual(self.matrix["task"], "GB100-M2-05")
        baseline = json.loads(
            (ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8")
        )
        self.assertEqual(self.matrix["firefox_version"], baseline["version"])
        self.assertTrue(self.matrix["offline_only"])
        self.assertEqual(self.matrix["materializer"], "tools/run_m2_05_pki_fixture_probe.py")
        separation = self.matrix["trust_separation"]
        self.assertEqual(separation["production_inputs"], "forbidden")
        self.assertIn("DER SHA-256 fingerprint", separation["anchor_match"])
        self.assertIn("never be added to the ordinary NSS trust store", separation["test_anchor_policy"])

    def test_local_pki_covers_valid_chain_and_every_required_negative(self) -> None:
        required = {
            "standard_root", "standard_intermediate", "standard_leaf",
            "russian_root", "russian_intermediate", "russian_leaf",
            "same_name_fake_root", "same_name_fake_leaf", "wrong_hostname_leaf",
            "expired_leaf", "bad_signature_leaf", "wrong_eku_leaf",
            "not_ca_intermediate", "not_ca_leaf", "pathlen_intermediate",
            "pathlen_subintermediate", "pathlen_leaf", "missing_intermediate_chain",
            "ordinary_and_russian_state_jars", "local_tls_endpoints", "early_data_capture",
        }
        self.assertTrue(required.issubset(self.fixtures))
        self.assertEqual(
            self.fixtures["same_name_fake_root"]["same_subject_as"], "russian_root"
        )
        self.assertEqual(self.fixtures["russian_leaf"]["dns_name"], "test-russian.example")
        self.assertEqual(self.fixtures["wrong_eku_leaf"]["eku"], "clientAuth")
        self.assertEqual(self.fixtures["not_ca_intermediate"]["basic_constraints"], "CA:FALSE")
        self.assertEqual(self.fixtures["missing_intermediate_chain"]["omits"], ["russian_intermediate"])
        self.assertEqual(self.fixtures["early_data_capture"]["network"], "loopback-only")

    def test_t01_through_t25_have_one_concrete_offline_owner(self) -> None:
        scenarios = self.matrix["scenarios"]
        self.assertEqual([scenario["id"] for scenario in scenarios], [f"T{i:02}" for i in range(1, 26)])
        for scenario in scenarios:
            self.assertTrue(scenario["fixture_ids"], scenario["id"])
            self.assertTrue(scenario["expected"], scenario["id"])
            self.assertRegex(scenario["owner_task"], r"^GB100-M[4-8]-\d{2}$")
            self.assertTrue(scenario["owner"].endswith((".cpp", ".js")))
            self.assertIn(scenario["harness"], {"gtest", "xpcshell", "browser-chrome"})
            for fixture_id in scenario["fixture_ids"]:
                self.assertIn(fixture_id, self.fixtures, f"{scenario['id']}: {fixture_id}")

    def test_security_boundary_cases_are_mapped_to_their_future_test_owners(self) -> None:
        scenarios = {scenario["id"]: scenario for scenario in self.matrix["scenarios"]}
        for scenario_id in ("T04", "T05", "T06", "T07", "T21", "T22"):
            self.assertEqual(
                scenarios[scenario_id]["owner"],
                "security/manager/ssl/tests/gtest/GoodBearRussianPKIVerifierTest.cpp",
            )
        expected_owner_fragments = {
            "T11": "storage",
            "T12": "storage",
            "T13": "storage",
            "T14": "service_worker",
            "T15": "credentials",
        }
        for scenario_id, owner_fragment in expected_owner_fragments.items():
            self.assertIn(owner_fragment, scenarios[scenario_id]["owner"])
        self.assertEqual(scenarios["T25"]["owner"], "netwerk/test/unit/test_goodbear_russian_pki_0rtt.js")


if __name__ == "__main__":
    unittest.main()

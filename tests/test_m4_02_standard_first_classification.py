#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads(
    (ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8")
)
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
CONTRACT = json.loads(
    (ROOT / "config/m4-02-standard-first-classification-contract.json").read_text(
        encoding="utf-8"
    )
)


def read(relative: str) -> str:
    return (FIREFOX / relative).read_text(encoding="utf-8")


class M402StandardFirstClassificationTest(unittest.TestCase):
    def test_contract_is_narrow_and_pinned(self) -> None:
        self.assertEqual(CONTRACT["task"], "GB100-M4-02")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        self.assertEqual(CONTRACT["eligible_standard_results"], ["ERROR_UNKNOWN_ISSUER"])
        self.assertEqual(
            CONTRACT["classifications"],
            ["Standard", "RussianPKIRequired", "Invalid"],
        )

    def test_patch_is_ordered_and_contains_both_security_owners(self) -> None:
        series = [
            line
            for line in (ROOT / "patches" / "series").read_text(
                encoding="utf-8"
            ).splitlines()
            if line and not line.startswith("#")
        ]
        patch_path = ROOT / CONTRACT["patch"]
        self.assertEqual(series.count(patch_path.name), 1)
        patch = patch_path.read_text(encoding="utf-8")
        for relative in (CONTRACT["owner"], CONTRACT["test_owner"]):
            self.assertIn(f"b/{relative}", patch)

    def test_standard_success_short_circuits_secondary_verification(self) -> None:
        owner = read(CONTRACT["owner"])
        success = """if (aStandardResult == mozilla::pkix::Success) {
    return {GoodBearOrdinaryTrustClassification::Standard, aStandardResult};
  }

  if (!IsGoodBearRussianPKISecondaryVerificationEligible"""
        self.assertIn(success, owner)
        self.assertLess(owner.index(success), owner.index("aVerifyRussianPKI()"))

    def test_only_unknown_issuer_is_eligible(self) -> None:
        owner = read(CONTRACT["owner"])
        eligible_function = owner.split(
            "inline bool IsGoodBearRussianPKISecondaryVerificationEligible", 1
        )[1].split("inline GoodBearOrdinaryVerificationResult", 1)[0]
        self.assertIn("Result::ERROR_UNKNOWN_ISSUER", eligible_function)
        for forbidden in (
            "ERROR_BAD_CERT_DOMAIN",
            "ERROR_EXPIRED_CERTIFICATE",
            "ERROR_BAD_SIGNATURE",
            "ERROR_INADEQUATE_KEY_USAGE",
            "ERROR_UNTRUSTED_ISSUER",
        ):
            self.assertNotIn(forbidden, eligible_function)

    def test_alternate_success_cannot_make_the_ordinary_channel_usable(self) -> None:
        owner = read(CONTRACT["owner"])
        self.assertIn("GoodBearOrdinaryTrustClassification::RussianPKIRequired", owner)
        self.assertIn(
            "? nsITransportSecurityInfo::GoodBearTrustDomain::Standard\n"
            "               : nsITransportSecurityInfo::GoodBearTrustDomain::Invalid",
            owner,
        )
        self.assertNotIn("GoodBearTrustDomain::RussianPKI", owner)

    def test_gtest_covers_positive_and_adversarial_control_flow(self) -> None:
        test = read(CONTRACT["test_owner"])
        for case in (
            "StandardSuccessReturnsImmediately",
            "EligibleAlternateSuccessRequiresAnotherChannel",
            "EligibleAlternateFailurePreservesOriginalError",
            "NonEligibleFailuresNeverRunSecondaryVerification",
        ):
            self.assertIn(case, test)
        self.assertIn("ASSERT_FALSE(result.OrdinaryChannelUsable())", test)
        self.assertIn("GoodBearTrustDomain::Invalid", test)


if __name__ == "__main__":
    unittest.main()

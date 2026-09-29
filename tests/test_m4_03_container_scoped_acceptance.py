#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads(
    (ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8")
)
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
CONTRACT = json.loads(
    (ROOT / "config/m4-03-container-scoped-acceptance-contract.json").read_text(
        encoding="utf-8"
    )
)


def read_firefox(relative: str) -> str:
    return (FIREFOX / relative).read_text(encoding="utf-8")


class M403ContainerScopedAcceptanceTest(unittest.TestCase):
    def test_contract_is_pinned_to_real_origin_attributes_and_local_fixtures(self) -> None:
        self.assertEqual(CONTRACT["task"], "GB100-M4-03")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        self.assertEqual(
            CONTRACT["channel_origin_attributes_owner"],
            "security/manager/ssl/SSLServerCertVerification.h",
        )
        matrix = json.loads((ROOT / CONTRACT["fixture_matrix"]).read_text(encoding="utf-8"))
        self.assertEqual(matrix["task"], "GB100-M2-05")
        self.assertEqual(matrix["trust_separation"]["production_inputs"], "forbidden")
        self.assertIn(
            "der sha-256 fingerprint",
            matrix["trust_separation"]["anchor_match"].lower(),
        )

    def test_patch_is_ordered_and_contains_only_the_focused_psm_surface(self) -> None:
        series = [
            line
            for line in (ROOT / "patches/series").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        patch_path = ROOT / CONTRACT["patch"]
        self.assertEqual(series.count(patch_path.name), 1)
        patch_index = series.index(patch_path.name)
        self.assertGreater(patch_index, 0)
        self.assertEqual(
            series[patch_index - 1],
            "0004-good-bear-standard-first-classification.patch",
        )
        patch = patch_path.read_text(encoding="utf-8")
        for relative in (CONTRACT["owner"], CONTRACT["test_owner"]):
            self.assertIn(f"b/{relative}", patch)
        self.assertIn("b/security/manager/ssl/tests/gtest/moz.build", patch)
        self.assertNotIn("BEGIN CERTIFICATE", patch)
        self.assertNotIn("russian_trusted_root_ca_rsa_2022.der", patch)

    def test_scope_uses_real_channel_user_context_and_fails_closed(self) -> None:
        owner = read_firefox(CONTRACT["owner"])
        self.assertIn("const mozilla::OriginAttributes& aOriginAttributes", owner)
        self.assertIn("aOriginAttributes.mUserContextId", owner)
        self.assertIn("mDedicatedUserContextId.isSome()", owner)
        self.assertIn("DEFAULT_USER_CONTEXT_ID", owner)
        self.assertIn("GoodBearTrustDomain::Invalid", owner)
        self.assertIn("FATAL_ERROR_INVALID_STATE", owner)
        for forbidden in ("commonName", "issuerName", "subjectName", "Russian Trusted Root CA"):
            self.assertNotIn(forbidden, owner)

        verification_flow = read_firefox(CONTRACT["channel_origin_attributes_owner"])
        self.assertIn("const OriginAttributes& aOriginAttributes", verification_flow)
        self.assertIn("mOriginAttributes(aOriginAttributes)", verification_flow)
        self.assertIn("OriginAttributes mOriginAttributes;", verification_flow)

    def test_standard_first_and_live_scope_recheck_are_ordered(self) -> None:
        owner = read_firefox(CONTRACT["owner"])
        standard = owner.index("if (aStandardResult == mozilla::pkix::Success)")
        eligible = owner.index("IsGoodBearRussianPKISecondaryVerificationEligible")
        first_scope = owner.index("aScopeAllows(aOriginAttributes)", eligible)
        alternate = owner.index("aVerifyAgainstExactRussianPKIAnchors()", first_scope)
        second_scope = owner.index("aScopeAllows(aOriginAttributes)", alternate)
        self.assertLess(standard, eligible)
        self.assertLess(eligible, first_scope)
        self.assertLess(first_scope, alternate)
        self.assertLess(alternate, second_scope)

    def test_gtest_covers_positive_and_adversarial_scope_transitions(self) -> None:
        test = read_firefox(CONTRACT["test_owner"])
        for case in (
            "DefaultResultIsFailClosed",
            "StandardSuccessDoesNotConsultScopeOrAlternateTrust",
            "SameValidRussianChainIsAcceptedOnlyInDedicatedContainer",
            "DisabledOrMissingContainerNeverRunsAlternateVerification",
            "DisablementDuringVerificationFailsClosed",
            "RecreatedContainerInvalidatesOldAndInFlightChannels",
            "NonEligibleFailureNeverUsesAlternateTrustEvenInDedicatedContainer",
        ):
            self.assertIn(case, test)
        self.assertIn("ChannelAttributes(kDedicatedUserContextId)", test)
        self.assertIn("ChannelAttributes(userContextId)", test)
        self.assertIn("GoodBearTrustDomain::RussianPKI", test)
        self.assertIn("GoodBearTrustDomain::Invalid", test)

    def test_local_chain_is_valid_only_under_the_exact_test_anchor(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("OpenSSL is required for the local PKI fixture check")
        chain = {
            key: ROOT / relative
            for key, relative in CONTRACT["test_chain"].items()
            if key != "exact_anchor_der_sha256"
        }
        for path in chain.values():
            self.assertTrue(path.is_file(), path)

        der = subprocess.run(
            ["openssl", "x509", "-in", str(chain["root"]), "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        digest = hashlib.sha256(der).hexdigest()
        fixture_index = json.loads(
            (ROOT / CONTRACT["fixture_index"]).read_text(encoding="utf-8")
        )
        self.assertEqual(digest, CONTRACT["test_chain"]["exact_anchor_der_sha256"])
        self.assertEqual(digest, fixture_index["exact_anchor_sha256"])

        exact = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(chain["root"]),
                "-untrusted",
                str(chain["intermediate"]),
                str(chain["leaf"]),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(exact.returncode, 0, exact.stderr or exact.stdout)

        ordinary = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(chain["ordinary_root"]),
                "-untrusted",
                str(chain["intermediate"]),
                str(chain["leaf"]),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(ordinary.returncode, 0)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads(
    (ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8")
)
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
CONTRACT = json.loads(
    (ROOT / "config/m4-01-normalized-trust-type-contract.json").read_text(
        encoding="utf-8"
    )
)


def read(relative: str) -> str:
    return (FIREFOX / relative).read_text(encoding="utf-8")


class M401NormalizedTrustTypeTest(unittest.TestCase):
    def test_contract_matches_the_pinned_typed_domain(self) -> None:
        self.assertEqual(CONTRACT["task"], "GB100-M4-01")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        self.assertEqual(
            CONTRACT["states"], {"Invalid": 0, "Standard": 1, "RussianPKI": 2}
        )
        self.assertEqual(CONTRACT["default"], "Invalid")

    def test_verifier_is_the_only_non_invalid_assignment_owner(self) -> None:
        verifier = read(CONTRACT["verifier_owner"])
        self.assertIn("GoodBearTrustDomain::Standard", verifier)
        self.assertRegex(
            verifier,
            r"GoodBearTrustDomain::Invalid,\s+goodBearRussianPKIRequired,\s+0,\s+finalError",
        )
        self.assertIn("if (mSucceeded != trustDomainIsValid)", verifier)
        self.assertIn("mFinalError = SEC_ERROR_LIBRARY_FAILURE;", verifier)

        # Transport may compare a typed value, revoke it to Invalid, or restore
        # explicitly typed cache metadata. Those operations cannot classify a
        # certificate by assigning a literal successful trust domain.
        for relative in (
            "security/manager/ssl/CommonSocketControl.h",
            "security/manager/ssl/CommonSocketControl.cpp",
            "security/manager/ssl/VerifySSLServerCertParent.cpp",
            "security/manager/ssl/VerifySSLServerCertChild.cpp",
        ):
            text = read(relative)
            self.assertNotRegex(text, r"\bClassifyGoodBearRussianPKI\w*\s*\(")
            self.assertNotRegex(
                text,
                r"(?:SetGoodBearTrustDomain\s*\(\s*|mGoodBearTrustDomain\s*=(?!=)\s*)"
                r"(?:nsITransportSecurityInfo::)?GoodBearTrustDomain::(?:Standard|RussianPKI)",
            )

    def test_transport_preserves_or_fails_closed_without_reclassification(self) -> None:
        socket = read(CONTRACT["transport_owners"][0])
        info = read(CONTRACT["transport_owners"][1])
        ipc = read(CONTRACT["transport_owners"][2])
        fuzzy = read(CONTRACT["transport_owners"][3])

        self.assertIn("mPeerId, mGoodBearTrustDomain", socket)
        self.assertIn(
            "const GoodBearTrustDomain mGoodBearTrustDomain;",
            read("security/manager/ssl/TransportSecurityInfo.h"),
        )
        self.assertIn("Write32(static_cast<uint32_t>(mGoodBearTrustDomain))", info)
        self.assertIn("if (parsedTrustDomain.isNothing())", info)
        self.assertIn("return NS_ERROR_UNEXPECTED;", info)
        self.assertIn("ReadParam(aReader, &aGoodBearTrustDomain)", info)
        self.assertIn("ContiguousEnumSerializerInclusive", ipc)
        self.assertIn("*aGoodBearTrustDomain = GoodBearTrustDomain::Invalid;", fuzzy)

    def test_browser_consumes_typed_result_without_parallel_classifier(self) -> None:
        ui_test = read(CONTRACT["ui_evidence"])
        self.assertIn("securityInfo.goodBearTrustDomain", ui_test)
        self.assertIn("Ci.nsITransportSecurityInfo.Standard", ui_test)

        guarded_owners = [
            CONTRACT["verifier_owner"],
            CONTRACT["routing_owner"],
            CONTRACT["ui_evidence"],
        ]
        forbidden = (
            "isRussianCA",
            "isRussianPKI",
            "isMincifry",
            "isRuCert",
            "specialRoot",
            "russianIssuer",
            "russianSubject",
        )
        combined = "\n".join(read(relative) for relative in guarded_owners)
        for identifier in forbidden:
            self.assertNotIn(identifier, combined, identifier)


if __name__ == "__main__":
    unittest.main()

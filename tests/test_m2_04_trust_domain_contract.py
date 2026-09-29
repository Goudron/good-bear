#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
VERSION = BASELINE["version"]
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{VERSION}"
CONTRACT_PATH = ROOT / "config/m2-04-trust-domain-contract.json"
PATCH_PATH = ROOT / "patches" / "0003-good-bear-typed-trust-domain.patch"


def read(relative: str) -> str:
    return (FIREFOX / relative).read_text(encoding="utf-8")


class M204TrustDomainContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def test_contract_is_pinned_complete_and_owned(self) -> None:
        self.assertEqual(self.contract["task"], "GB100-M2-04")
        self.assertEqual(self.contract["firefox_version"], VERSION)
        source = self.contract["source_of_truth"]
        self.assertEqual(
            source["states"], {"Invalid": 0, "Standard": 1, "RussianPKI": 2}
        )
        self.assertEqual(source["default"], "Invalid")
        self.assertEqual(len(self.contract["serialization_boundaries"]), 3)
        for relative in self.contract["rebase_guards"]:
            self.assertTrue((FIREFOX / relative).is_file(), relative)

    def test_xpidl_is_the_only_enum_definition_and_exposes_typed_state(self) -> None:
        owner = self.contract["source_of_truth"]["owner"]
        idl = read(owner)
        enum = re.search(
            r"cenum GoodBearTrustDomain\s*:\s*8\s*\{(?P<body>.*?)\};",
            idl,
            re.DOTALL,
        )
        self.assertIsNotNone(enum)
        body = enum.group("body")
        self.assertRegex(body, r"\bInvalid\s*=\s*0\s*,")
        self.assertRegex(body, r"\bStandard\s*=\s*1\s*,")
        self.assertRegex(body, r"\bRussianPKI\s*=\s*2\s*,")
        self.assertEqual(body.count("="), 3)
        self.assertIn(
            "readonly attribute nsITransportSecurityInfo_GoodBearTrustDomain goodBearTrustDomain;",
            idl,
        )

        declarations = []
        for relative in self.contract["rebase_guards"]:
            text = read(relative)
            if "cenum GoodBearTrustDomain" in text or "enum class GoodBearTrustDomain" in text:
                declarations.append(relative)
        self.assertEqual(declarations, [owner])

    def test_verifier_is_the_only_classifier_and_result_is_fail_closed(self) -> None:
        verifier = read("security/manager/ssl/SSLServerCertVerification.cpp")
        self.assertRegex(
            verifier,
            r"GoodBearTrustDomain::Standard,\s+false,\s+"
            r"usedGoodBearRussianPKIAlternateTrust\s*\?\s*goodBearScopeLease\s*:\s*0,\s*0,",
        )
        self.assertRegex(
            verifier,
            r"GoodBearTrustDomain::Invalid,\s+goodBearRussianPKIRequired,\s+0,\s+finalError,",
        )
        self.assertRegex(
            verifier,
            r"SetGoodBearTrustDomain\(\s+nsITransportSecurityInfo::GoodBearTrustDomain::Invalid\)",
        )
        self.assertIn("if (mSucceeded != trustDomainIsValid)", verifier)
        self.assertIn("mFinalError = SEC_ERROR_LIBRARY_FAILURE;", verifier)

        setter_calls = []
        for relative in self.contract["rebase_guards"]:
            text = read(relative)
            if "SetGoodBearTrustDomain(" in text:
                setter_calls.append(relative)
        self.assertEqual(
            setter_calls,
            [
                "security/manager/ssl/SSLServerCertVerification.cpp",
                "security/manager/ssl/CommonSocketControl.h",
            ],
        )

    def test_typed_result_crosses_all_verification_and_socket_process_owners(self) -> None:
        for relative in (
            "security/manager/ssl/SSLServerCertVerification.h",
            "security/manager/ssl/VerifySSLServerCertParent.h",
            "security/manager/ssl/VerifySSLServerCertParent.cpp",
            "security/manager/ssl/VerifySSLServerCertChild.h",
            "security/manager/ssl/VerifySSLServerCertChild.cpp",
            "security/manager/ssl/PVerifySSLServerCert.ipdl",
        ):
            self.assertIn("GoodBearTrustDomain", read(relative), relative)
        ipdl = read("security/manager/ssl/PVerifySSLServerCert.ipdl")
        self.assertIn("GoodBearTrustDomain aGoodBearTrustDomain", ipdl)

    def test_connection_default_and_snapshot_are_fail_closed_and_immutable(self) -> None:
        control_h = read("security/manager/ssl/CommonSocketControl.h")
        control_cpp = read("security/manager/ssl/CommonSocketControl.cpp")
        info_h = read("security/manager/ssl/TransportSecurityInfo.h")
        fuzzy = read("netwerk/base/FuzzySecurityInfo.cpp")
        self.assertIn("GoodBearTrustDomain mGoodBearTrustDomain;", control_h)
        self.assertIn("GoodBearTrustDomain::Invalid", control_cpp)
        self.assertIn("const GoodBearTrustDomain mGoodBearTrustDomain;", info_h)
        self.assertIn("mPeerId, mGoodBearTrustDomain", control_cpp)
        self.assertIn("*aGoodBearTrustDomain = GoodBearTrustDomain::Invalid;", fuzzy)

    def test_ipc_and_persistent_serializers_reject_unknown_values(self) -> None:
        ipc = read("ipc/glue/TransportSecurityInfoUtils.h")
        self.assertIn("ParamTraits<nsITransportSecurityInfo::GoodBearTrustDomain>", ipc)
        self.assertIn("GoodBearTrustDomain::Invalid", ipc)
        self.assertIn("GoodBearTrustDomain::RussianPKI", ipc)

        info = read("security/manager/ssl/TransportSecurityInfo.cpp")
        self.assertIn('NS_ConvertUTF8toUTF16("11")', info)
        self.assertIn("Write32(static_cast<uint32_t>(mGoodBearTrustDomain))", info)
        self.assertIn("WriteBoolean(mGoodBearRussianPKIRequired)", info)
        self.assertIn("GoodBearTrustDomain::Invalid;", info)
        self.assertIn("if (serVersionParsedToInt >= 10)", info)
        self.assertIn("if (serVersionParsedToInt >= 11)", info)
        self.assertIn("if (parsedTrustDomain.isNothing())", info)
        self.assertIn("return NS_ERROR_UNEXPECTED;", info)
        self.assertIn("WriteParam(aWriter, mGoodBearTrustDomain);", info)
        self.assertIn("WriteParam(aWriter, mGoodBearRussianPKIRequired);", info)
        self.assertIn("ReadParam(aReader, &aGoodBearTrustDomain)", info)
        self.assertIn("ReadParam(aReader, &aGoodBearRussianPKIRequired)", info)

    def test_compile_and_roundtrip_tests_cover_every_state_and_legacy_default(self) -> None:
        gtest = read("security/manager/ssl/tests/gtest/GoodBearTrustDomainTest.cpp")
        for state, value in self.contract["source_of_truth"]["states"].items():
            self.assertIn(f"GoodBearTrustDomain::{state}) == {value}", gtest)
        self.assertIn("TypedValuesSurviveImmutableSecurityInfo", gtest)
        self.assertIn("TypedValuesSurvivePersistentSerialization", gtest)
        legacy = read("security/manager/ssl/tests/gtest/DeserializeCertTest.cpp")
        self.assertIn("GoodBearTrustDomain::Invalid", legacy)

    def test_ui_uses_typed_transport_result_without_parallel_classifier(self) -> None:
        test = read(self.contract["ui_contract"]["typed_test_owner"])
        self.assertIn("securityInfo.goodBearTrustDomain", test)
        self.assertIn("Ci.nsITransportSecurityInfo.Standard", test)

        ui = read(self.contract["ui_contract"]["owner"])
        combined = ui + "\n" + test
        for forbidden in (
            "isRussianCA",
            "isRussianPKI",
            "isMincifry",
            "isRuCert",
            "specialRoot",
            "russianIssuer",
            "russianSubject",
        ):
            self.assertNotIn(forbidden, combined)

    def test_ordered_patch_preserves_every_rebase_guard(self) -> None:
        series = [
            line
            for line in (ROOT / "patches" / "series").read_text(
                encoding="utf-8"
            ).splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(series.count(PATCH_PATH.name), 1)

        patch = PATCH_PATH.read_text(encoding="utf-8")
        self.assertIn("cenum GoodBearTrustDomain : 8", patch)
        for relative in self.contract["rebase_guards"]:
            self.assertIn(f"b/{relative}", patch, relative)


if __name__ == "__main__":
    unittest.main()

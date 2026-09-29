#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches" / "0013-good-bear-privacy-safe-diagnostics.patch"


class M906PrivacyDiagnosticsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.source = PATCH.read_text(encoding="utf-8")
        self.added_source = "\n".join(
            line[1:]
            for line in self.source.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )

    def test_patch_emits_only_fixed_native_verification_identifiers(self) -> None:
        self.assertIn('LazyLogModule gGoodBearTrustLog("GoodBearTrust")', self.source)
        self.assertEqual(
            re.findall(r"result=(standard-failed|secondary-succeeded|secondary-failed)", self.source),
            ["standard-failed", "secondary-succeeded", "secondary-failed"],
        )
        self.assertNotIn("GoodBearDiagnostics", self.source)
        self.assertNotIn("result=routing", self.source)
        self.assertNotIn("result=transition", self.source)

    def test_secondary_identifiers_follow_native_verifier_outcomes(self) -> None:
        self.assertRegex(
            self.source,
            re.compile(
                r"if \(russianPKIResult\.ChannelUsable\(\)\) \{\n"
                r"\+      MOZ_LOG\(gGoodBearTrustLog, LogLevel::Debug,\n"
                r'\+              \("phase=verification result=secondary-succeeded"\)\);'
            ),
        )
        self.assertRegex(
            self.source,
            re.compile(
                r"else if \(IsGoodBearRussianPKISecondaryVerificationEligible\(result\)\) \{\n"
                r"\+      MOZ_LOG\(gGoodBearTrustLog, LogLevel::Debug,\n"
                r'\+              \("phase=verification result=secondary-failed"\)\);'
            ),
        )

    def test_patch_contains_no_sensitive_diagnostic_payload_surface(self) -> None:
        self.assertEqual(
            [line for line in self.source.splitlines() if "MOZ_LOG" in line],
            [
                "+    MOZ_LOG(gGoodBearTrustLog, LogLevel::Debug,",
                "+      MOZ_LOG(gGoodBearTrustLog, LogLevel::Debug,",
                "+      MOZ_LOG(gGoodBearTrustLog, LogLevel::Debug,",
            ],
        )
        self.assertNotRegex(
            self.added_source.lower(),
            re.compile(
                r"\b(?:hostname|uri|url|chain|cookie|authorization|password|private key|request body|formdata)\b"
            ),
        )


if __name__ == "__main__":
    unittest.main()

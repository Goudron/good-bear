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
PRISTINE = ROOT / "source" / "pristine" / f"firefox-{BASELINE['version']}"
CONTRACT = json.loads(
    (ROOT / "config/m4-04-complete-x509-tls-validation-contract.json").read_text(
        encoding="utf-8"
    )
)


def read_firefox(relative: str) -> str:
    return (FIREFOX / relative).read_text(encoding="utf-8")


class M404CompleteX509TLSValidationTest(unittest.TestCase):
    def test_contract_is_pinned_to_m3_exact_anchor_gate(self) -> None:
        self.assertEqual(CONTRACT["task"], "GB100-M4-04")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        manifest = json.loads(
            (ROOT / CONTRACT["production_manifest"]).read_text(encoding="utf-8")
        )
        self.assertFalse(manifest["policy"]["runtime_certificate_download"])
        self.assertEqual(
            manifest["policy"]["trust_scope"],
            "dedicated_russian_pki_container_only",
        )
        gate = (ROOT / CONTRACT["production_supply_chain_gate"]).read_text(
            encoding="utf-8"
        )
        for required in (
            "certificate_der_sha256",
            "spki_der_sha256",
            "require_ca_constraints",
            "verify_self_signed_root",
        ):
            self.assertIn(required, gate)

    def test_upstream_cert_verifier_is_byte_identical_to_pristine(self) -> None:
        for relative in (
            CONTRACT["upstream_verifier"],
            CONTRACT["upstream_verifier_header"],
        ):
            self.assertEqual(
                (FIREFOX / relative).read_bytes(),
                (PRISTINE / relative).read_bytes(),
                relative,
            )

    def test_local_helper_uses_exact_roots_and_unchanged_upstream_validation(self) -> None:
        owner = read_firefox(CONTRACT["owner"])
        for required in (
            "aVerifiedExactTrustAnchors.IsEmpty()",
            "anchorDER.IsEmpty()",
            "EnterpriseCert",
            "VerifySSLServerCert",
            "mOCSPDownloadConfig",
            "mOCSPStrict",
            "mOCSPTimeoutSoft",
            "mOCSPTimeoutHard",
            "mCertShortLifetimeInDays",
            "mCTConfig.mMode",
            "mCTConfig.mSkipForHosts",
            "mCTConfig.mSkipForSPKIHashes",
            "mCRLiteMode",
            "aStapledOCSPResponse",
            "aSctsFromTLS",
            "aDCInfo",
            "aOriginAttributes",
            "aBuiltChain.LastElement() == anchorDER",
            "aBuiltChain.Clear()",
        ):
            self.assertIn(required, owner)
        for forbidden in (
            "CERT_ChangeCertTrust",
            "ImportCert",
            "commonName",
            "issuerName",
            "subjectName",
            "Russian Trusted Root CA",
        ):
            self.assertNotIn(forbidden, owner)

    def test_gtest_covers_complete_positive_and_negative_flow(self) -> None:
        test = read_firefox(CONTRACT["test_owner"])
        for case in (
            "CompleteUpstreamValidationAcceptsExactAnchorOnlyInScopedFlow",
            "AlternateVerifierDoesNotMutateOrdinaryOrGlobalTrust",
            "EmptyAnchorSetFailsClosed",
            "SameNameFakeRootDoesNotMatchExactAnchor",
            "HostnameMismatchRetainsOriginalTLSError",
            "ExpiredChainRetainsOriginalTLSError",
            "InvalidSignatureRetainsOriginalTLSError",
            "WrongEKURetainsOriginalTLSError",
            "NonCAIntermediateRetainsOriginalTLSError",
            "PathLengthRetainsOriginalTLSError",
            "MissingIntermediateRetainsOriginalTLSError",
        ):
            self.assertIn(case, test)
        self.assertIn("PKIXResult::ERROR_UNKNOWN_ISSUER, result.mResult", test)
        self.assertIn("ASSERT_FALSE(result.ChannelUsable())", test)

    def test_installed_public_fixtures_exactly_match_m2_matrix_outputs(self) -> None:
        fixture_dir = (
            FIREFOX
            / "security/manager/ssl/tests/gtest/goodbear-russian-pki"
        )
        sources = {
            "russian-root.pem": "pki/russian-root.pem",
            "russian-intermediate.pem": "pki/russian-intermediate.pem",
            "russian-leaf.pem": "pki/russian-leaf.pem",
            "same-name-fake-leaf.pem": "negative/same-name-fake-leaf.pem",
            "wrong-hostname-leaf.pem": "negative/wrong-hostname-leaf.pem",
            "expired-leaf.pem": "negative/expired-leaf.pem",
            "bad-signature-leaf.pem": "negative/bad-signature-leaf.pem",
            "wrong-eku-leaf.pem": "negative/wrong-eku-leaf.pem",
            "not-ca-intermediate.pem": "negative/not-ca-intermediate.pem",
            "not-ca-leaf.pem": "negative/not-ca-leaf.pem",
            "pathlen-intermediate.pem": "negative/pathlen-intermediate.pem",
            "pathlen-subintermediate.pem": "negative/pathlen-subintermediate.pem",
            "pathlen-leaf.pem": "negative/pathlen-leaf.pem",
        }
        source_root = ROOT / "artifacts/m2-05-pki-fixtures"
        for installed_name, source_name in sources.items():
            installed = fixture_dir / installed_name
            source = source_root / source_name
            self.assertEqual(installed.read_bytes(), source.read_bytes(), installed_name)
            self.assertNotIn(b"PRIVATE KEY", installed.read_bytes())

    def test_patch_precedes_later_milestones_and_contains_no_production_root(self) -> None:
        series = [
            line
            for line in (ROOT / "patches/series").read_text(
                encoding="utf-8"
            ).splitlines()
            if line and not line.startswith("#")
        ]
        patch_path = ROOT / CONTRACT["patch"]
        self.assertEqual(series.count(patch_path.name), 1)
        patch_index = series.index(patch_path.name)
        self.assertEqual(
            series[patch_index + 1], "0007-good-bear-trust-results-performance.patch"
        )
        patch = patch_path.read_text(encoding="utf-8")
        for relative in (CONTRACT["owner"], CONTRACT["test_owner"]):
            self.assertIn(f"b/{relative}", patch)
        self.assertNotIn("russian_trusted_root_ca_rsa_2022.der", patch)
        self.assertNotIn(
            "d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31",
            patch,
        )


if __name__ == "__main__":
    unittest.main()

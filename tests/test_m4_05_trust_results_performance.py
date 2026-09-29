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
    (ROOT / "config/m4-05-trust-results-performance-contract.json").read_text(
        encoding="utf-8"
    )
)


def read_firefox(relative: str) -> str:
    return (FIREFOX / relative).read_text(encoding="utf-8")


class M405TrustResultsPerformanceTest(unittest.TestCase):
    def test_contract_is_pinned_and_orders_the_patch_after_m4_04(self) -> None:
        self.assertEqual(CONTRACT["task"], "GB100-M4-05")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        series = [
            line
            for line in (ROOT / "patches/series").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        patch = Path(CONTRACT["patch"])
        patch_index = series.index(patch.name)
        self.assertEqual(
            series[patch_index - 1], "0006-good-bear-complete-x509-tls-validation.patch"
        )
        self.assertEqual(series.count(patch.name), 1)
        patch_text = (ROOT / patch).read_text(encoding="utf-8")
        for required in (
            "GoodBearRussianPKIAlternateVerifierCache",
            "GoodBearRussianPKIVerificationCounters",
            "browser-siteIdentity.js",
            "identity-goodbear-russian-pki-description",
        ):
            self.assertIn(required, patch_text)

    def test_cache_reuses_only_upstream_work_not_a_tls_decision(self) -> None:
        owner = read_firefox(CONTRACT["cache_owner"])
        for required in (
            "GoodBearRussianPKIAlternateVerifierCache",
            "aVerifiedExactTrustAnchors.IsEmpty()",
            "anchorDER.IsEmpty()",
            "mAlternateVerifier.VerifySSLServerCert(",
            "aPeerCert, aTime, aPinArg, aHostname, aBuiltChain, aFlags",
            "aExtraCertificates, aStapledOCSPResponse, aSctsFromTLS, aDCInfo",
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
            "russian_trusted_root_ca_rsa_2022.der",
        ):
            self.assertNotIn(forbidden, owner)

    def test_counters_are_aggregate_only_and_standard_short_circuits(self) -> None:
        scope = read_firefox(CONTRACT["scope_owner"])
        for required in (
            "mStandardResults",
            "mSecondaryChecks",
            "mSecondarySuccesses",
            "RecordStandardResult",
            "RecordSecondaryCheck",
            "GoodBearRussianPKIVerificationCounters* aCounters",
        ):
            self.assertIn(required, scope)
        standard = scope.index("if (aStandardResult == mozilla::pkix::Success)")
        first_secondary = scope.index("aVerifyAgainstExactRussianPKIAnchors()")
        self.assertLess(standard, first_secondary)
        counter_definition = scope.split("struct GoodBearRussianPKIVerificationCounters", 1)[1].split(
            "// aScopeAllows", 1
        )[0]
        for forbidden in ("Hostname", "Certificate", "OriginAttributes"):
            self.assertNotIn(forbidden, counter_definition)

    def test_gtest_covers_cache_context_recheck_and_frequency(self) -> None:
        test = read_firefox(CONTRACT["test_owner"])
        for case in (
            "SecondaryCheckCountersDoNotGrantOrReuseTrust",
            "ReusableAlternateVerifierRechecksHostnameAndKeepsExactAnchor",
        ):
            self.assertIn(case, test)
        for assertion in (
            "ASSERT_EQ(0U, counters.mSecondaryChecks)",
            "ASSERT_EQ(PKIXResult::ERROR_BAD_CERT_DOMAIN",
            "GoodBearRussianPKIAlternateVerifierCache::Create",
        ):
            self.assertIn(assertion, test)

    def test_ui_uses_only_the_transport_owned_typed_result(self) -> None:
        ui = read_firefox(CONTRACT["ui_owner"])
        for required in (
            "this._secInfo?.goodBearTrustDomain",
            "Ci.nsITransportSecurityInfo.RussianPKI",
            "Ci.nsITransportSecurityInfo.Standard",
            "Ci.nsITransportSecurityInfo.Invalid",
            "this._isSecureConnection",
            '"goodbear-trust-domain"',
            '"russian-pki"',
        ):
            self.assertIn(required, ui)
        for forbidden in ("commonName", "issuerName", "subjectName", "Russian Trusted Root CA"):
            self.assertNotIn(ui.split("get _goodBearTrustDomain()", 1)[1].split("_refreshIdentityIcons", 1)[0], forbidden)

        for markup_path in CONTRACT["ui_markup"]:
            markup = read_firefox(markup_path)
            self.assertIn('when-goodbear-trust-domain="russian-pki"', markup)
            self.assertIn("identity-goodbear-russian-pki-description", markup)

        russian = (ROOT / CONTRACT["russian_locale"]).read_text(encoding="utf-8")
        self.assertIn("identity-goodbear-russian-pki-label", russian)
        self.assertIn("Российскую PKI", russian)
        self.assertIn(
            "Good Bear распознал в качестве издателя сертификата этого веб-сайта Минцифры РФ.",
            russian,
        )

        panel_css = read_firefox("browser/themes/shared/controlcenter/panel.css")
        self.assertIn(
            '.site-information-popup[goodbear-trust-domain="russian-pki"] [when-customroot]',
            panel_css,
        )

        trust_panel = read_firefox("browser/base/content/browser-trustPanel.js")
        for required in (
            "get #usesGoodBearRussianPKI()",
            "this.#secInfo?.goodBearTrustDomain",
            "Ci.nsITransportSecurityInfo.RussianPKI",
            '"goodbear-trust-domain"',
        ):
            self.assertIn(required, trust_panel)


if __name__ == "__main__":
    unittest.main()

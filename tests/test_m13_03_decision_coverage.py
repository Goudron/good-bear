#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m13_03_decision_coverage", ROOT / "tools/verify_m13_03_decision_coverage.py"
)
assert SPEC and SPEC.loader
COVERAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COVERAGE)


class M1303DecisionCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = COVERAGE.load_contract()

    def test_declared_good_bear_surface_has_a_positive_and_negative_test_for_every_decision(self) -> None:
        matrix = COVERAGE.validate_contract(self.contract)
        self.assertEqual(self.contract["firefox_version"], "156.0")
        self.assertEqual(matrix["declared_decision_count"], 52)
        self.assertEqual(matrix["positive_covered"], 52)
        self.assertEqual(matrix["negative_covered"], 52)
        self.assertEqual(matrix["declaration_coverage_percent"], 100)
        self.assertEqual(matrix["explicit_nondecision_exclusion_count"], 2)
        self.assertEqual(len(COVERAGE.load_series()), 54)
        self.assertEqual(len(self.contract["native_test_owner_sha256"]), 18)
        self.assertEqual(matrix["evidence_scope"], COVERAGE.EVIDENCE_SCOPE)
        self.assertIsNone(matrix["runtime_coverage_percent"])

    def test_existing_upstream_test_owner_is_resolved_in_the_active_pinned_worktree(self) -> None:
        matrix = COVERAGE.validate_contract(self.contract)
        d020 = matrix["decisions"][19]
        expected_owner = (
            "source/worktrees/firefox-156.0/"
            "browser/components/asrouter/tests/xpcshell/test_PreonboardingSplash.js"
        )
        self.assertEqual(d020["id"], "GB100-D020")
        self.assertIn(expected_owner, d020["positive"]["locations"])
        self.assertIn(expected_owner, d020["negative"]["locations"])

    def test_mar_public_certificate_binding_has_both_executable_selectors(self) -> None:
        matrix = COVERAGE.validate_contract(self.contract)
        decision = next(
            row for row in matrix["decisions"]
            if row["patch"] == "0035-good-bear-mar-public-cert-binding.patch"
        )
        self.assertEqual(decision["id"], "GB100-D034")
        self.assertEqual(decision["patch"], "0035-good-bear-mar-public-cert-binding.patch")
        self.assertIn("tests/test_m15_08_native_update.py", decision["positive"]["locations"])
        self.assertIn("tests/test_m15_08_native_update.py", decision["negative"]["locations"])

    def test_missing_negative_evidence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.contract)
        del changed["decision_surface"]["decisions"][0]["negative"]
        with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "missing or unknown"):
            COVERAGE.validate_contract(changed)

    def test_settings_prompts_and_scope_override_keep_their_complete_native_test_surface(self) -> None:
        matrix = COVERAGE.validate_contract(self.contract)
        rows = {row["id"]: row for row in matrix["decisions"]}
        expected = {
            "GB100-D041": (
                "0042-good-bear-russian-pki-settings.patch",
                "browser/components/preferences/tests/browser_goodbear_russian_pki.js",
                (
                    "test_goodbear_settings_live_enable_and_locked_pref",
                    "test_goodbear_settings_single_reset_confirm_and_cancel",
                    "test_goodbear_settings_clear_all_confirm_and_cancel",
                    "test_goodbear_settings_reset_failure_keeps_isolation",
                    "test_goodbear_settings_origin_validation_and_no_credentials",
                ),
            ),
            "GB100-D042": (
                "0043-good-bear-localized-russian-pki-prompts.patch",
                "browser/components/contextualidentity/test/browser/browser_goodbear_russian_pki_trust_change.js",
                (
                    "test_localized_address_only_prompt_choices",
                    "test_prompt_localization_failure_never_opens_destination",
                ),
            ),
            "GB100-D043": (
                "0044-good-bear-russian-pki-scope-override-containment.patch",
                "security/manager/ssl/tests/gtest/GoodBearRussianPKIVerifierTest.cpp",
                (
                    "ScopeRevocationCannotResumeThroughExistingCertificateOverride",
                    "ScopeRevocationBeforeAlternateCheckCannotUseCertificateOverride",
                    "OrdinaryInvalidCertificatesRetainUpstreamOverridePolicy",
                    "StandardSuccessAndRussianRoutingNeverConsultCertificateOverrides",
                    "NonEligibleStandardFailuresRetainUpstreamOverridePolicy",
                ),
            ),
        }
        for decision_id, (patch_name, owner, selectors) in expected.items():
            with self.subTest(decision=decision_id):
                self.assertEqual(rows[decision_id]["patch"], patch_name)
                self.assertEqual(rows[decision_id]["positive"]["owner"], owner)
                self.assertEqual(rows[decision_id]["negative"]["owner"], owner)
                for selector in selectors:
                    self.assertTrue(COVERAGE.selector_locations(ROOT, owner, selector, "156.0"))

    def test_removing_a_new_native_surface_cannot_reuse_its_reviewed_hashes(self) -> None:
        changed = copy.deepcopy(self.contract)
        del changed["native_test_owner_sha256"][
            "browser/components/preferences/tests/browser_goodbear_russian_pki.js"
        ]
        with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "every declared native test owner"):
            COVERAGE.validate_contract(changed)

    def test_scope_leases_details_interstitial_and_typed_cache_keep_native_regressions(self) -> None:
        matrix = COVERAGE.validate_contract(self.contract)
        rows = {row["id"]: row for row in matrix["decisions"]}
        expected = {
            "GB100-D045": (
                "0046-good-bear-russian-pki-live-scope-leases.patch",
                "security/manager/ssl/tests/gtest/GoodBearRussianPKIScopeAuthorityTest.cpp",
                (
                    "DisablementRevokesOldLeaseAndReenableRequiresNewPublication",
                    "UninitializedAndWrongScopesFailClosed",
                    "RecreatedIdentityCannotReviveOldLease",
                    "GenerationExhaustionNeverWraps",
                    "ReadOnlyLeaseMappingObservesParentRevocationAndRecreation",
                    "ReaderCannotReplaceTheParentAuthority",
                    "QueuedRussianResultCannotCompleteAfterScopeRevocation",
                    "ActiveRussianSocketCannotUseRevokedOrRecreatedLease",
                    "LegacyAlternateRootTokensRequireFreshVerification",
                    "MalformedPeerAttributesCannotRestoreToken",
                ),
            ),
            "GB100-D046": (
                "0047-good-bear-russian-pki-security-details.patch",
                "browser/components/contextualidentity/test/browser/browser_goodbear_russian_pki_security_ui.js",
                (
                    "test_goodbear_marker_is_independent_of_standard_trust",
                    "test_goodbear_verified_details_and_stale_viewer",
                ),
            ),
            "GB100-D047": (
                "0048-good-bear-maintained-javascript-quality.patch",
                "netwerk/test/unit/test_goodbear_russian_pki_0rtt.js",
                ("test_goodbear_never_sends_ordinary_request_data_as_0rtt",),
            ),
            "GB100-D048": (
                "0049-good-bear-blocking-russian-pki-interstitial.patch",
                "browser/components/contextualidentity/test/browser/browser_goodbear_russian_pki_trust_change.js",
                (
                    "test_localized_address_only_prompt_choices",
                    "test_prompt_localization_failure_never_opens_destination",
                    "test_interstitial_certificate_view_selects_native_viewer_without_consent",
                    "test_interstitial_navigation_and_scope_changes_revoke_consent",
                ),
            ),
            "GB100-D049": (
                "0050-good-bear-typed-tls-session-cache.patch",
                "netwerk/test/gtest/TestSSLTokensCache.cpp",
                (
                    "StandardTrustDomainSurvivesPersistenceAndRebuild",
                    "CertificateExceptionNeverBecomesStandardOnResume",
                    "LegacyUnknownAndRussianMetadataCannotResume",
                    "RebuildRejectsUntypedOrRussianMetadata",
                    "RussianSessionNeverEntersTokenCache",
                ),
            ),
            "GB100-D050": (
                "0051-good-bear-safe-browsing-v5-attributes.patch",
                "toolkit/components/url-classifier/tests/gtest/TestGoodBearV5Response.cpp",
                ("AttributeFreeThreatIsPreserved", "UnknownAttributeDiscardsEntireDetail"),
            ),
            "GB100-D051": (
                "0052-good-bear-safe-browsing-supplier-notice.patch",
                "browser/components/tests/browser/browser_goodbear_safebrowsing_notice.js",
                ("test_supplier_notice_new_and_existing_profiles", "test_supplier_notice_close_does_not_enable_service"),
            ),
            "GB100-D052": (
                "0053-good-bear-google-verdict-freshness.patch",
                "toolkit/components/url-classifier/tests/gtest/TestGoodBearGoogleFreshness.cpp",
                ("FreshPositiveAndStalePositivePreserveServerCache", "UnknownOldMetadataAndFullLengthPrefixNeedResponse"),
            ),
        }
        for decision_id, (patch_name, owner, selectors) in expected.items():
            with self.subTest(decision=decision_id):
                self.assertEqual(rows[decision_id]["patch"], patch_name)
                self.assertEqual(rows[decision_id]["positive"]["owner"], owner)
                self.assertEqual(rows[decision_id]["negative"]["owner"], owner)
                self.assertIn(owner, self.contract["native_test_owner_sha256"])
                for selector in selectors:
                    self.assertTrue(COVERAGE.selector_locations(ROOT, owner, selector, "156.0"))
        for selector in (
            "test_native_upload_presence_blocks_get_head_auto_replay",
            "test_assigned_policy_candidate_uses_native_stopped_channel_only",
        ):
            self.assertTrue(COVERAGE.selector_locations(
                ROOT,
                "browser/components/contextualidentity/test/browser/browser_goodbear_russian_pki_first_visit.js",
                selector, "156.0",
            ))

    def test_google_freshness_header_is_exported_for_cross_component_consumers(self) -> None:
        patch = (ROOT / "patches/0053-good-bear-google-verdict-freshness.patch").read_text(encoding="utf-8")
        self.assertIn("diff --git a/toolkit/components/url-classifier/moz.build", patch)
        exports = (ROOT / "source/worktrees/firefox-156.0/toolkit/components/url-classifier/moz.build").read_text(
            encoding="utf-8"
        )
        self.assertIn('"GoodBearGoogleVerdictFreshness.h",', exports)

    def test_security_gtest_local_includes_remain_mozbuild_sorted(self) -> None:
        path = ROOT / "source/worktrees/firefox-156.0/security/manager/ssl/tests/gtest/moz.build"
        source = path.read_text(encoding="utf-8")
        block = source.split("LOCAL_INCLUDES += [", 1)[1].split("]", 1)[0]
        includes = [line.strip().rstrip(",").strip('"') for line in block.splitlines() if '"' in line]
        self.assertEqual(includes, sorted(includes))
        self.assertEqual(includes, [
            "!/security/manager/ssl",
            "/netwerk/base",
            "/security/certverifier",
            "/security/manager/ssl",
            "/third_party/rust/cose-c/include",
        ])

    def test_missing_typed_cache_native_owner_cannot_claim_complete_declaration(self) -> None:
        changed = copy.deepcopy(self.contract)
        del changed["native_test_owner_sha256"]["netwerk/test/gtest/TestSSLTokensCache.cpp"]
        with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "every declared native test owner"):
            COVERAGE.validate_contract(changed)

    def test_user_agent_decision_binds_real_http_and_navigator_test_owners(self) -> None:
        matrix = COVERAGE.validate_contract(self.contract)
        decision = next(row for row in matrix["decisions"] if row["id"] == "GB100-D044")
        self.assertEqual(decision["patch"], "0045-good-bear-firefox-user-agent-compatibility.patch")
        browser_owner = "browser/components/contextualidentity/test/browser/browser_goodbear_user_agent.js"
        http_owner = "netwerk/test/unit/test_goodbear_user_agent.js"
        self.assertEqual(decision["positive"]["owner"], browser_owner)
        self.assertEqual(decision["negative"]["owner"], http_owner)
        self.assertIn(browser_owner, self.contract["native_test_owner_sha256"])
        self.assertIn(http_owner, self.contract["native_test_owner_sha256"])
        self.assertTrue(COVERAGE.selector_locations(
            ROOT, http_owner, "test_native_http_user_agent_preserves_firefox_compatibility", "156.0"
        ))

    def test_assertion_text_is_not_accepted_as_an_executable_selector(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["decision_surface"]["decisions"][0]["negative"]["selector"] = "fails closed"
        with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "executable identifier"):
            COVERAGE.validate_contract(changed)

    def test_selector_must_exist_in_its_declared_owner(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["decision_surface"]["decisions"][0]["positive"]["selector"] = "test_not_a_real_owner_selector"
        with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "absent from declared owner"):
            COVERAGE.validate_contract(changed)

    def test_every_patch_requires_a_decision_or_explicit_nondecision_exclusion(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["explicit_nondecision_exclusions"] = []
        with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "every Good Bear patch"):
            COVERAGE.validate_contract(changed)

    def test_stale_firefox_version_or_revision_cannot_reuse_the_declaration(self) -> None:
        for field, stale in (("firefox_version", "155.0.1"),
                             ("firefox_revision", "fb95137a04eb8fe1196cb12f26b100c1e060295c")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.contract)
                changed[field] = stale
                with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "pinned Firefox 156"):
                    COVERAGE.validate_contract(changed)

    def test_declaration_cannot_claim_runtime_coverage(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["evidence_scope"] = "runtime_100_percent"
        with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "cannot claim runtime"):
            COVERAGE.validate_contract(changed)

    def test_missing_materialized_test_cannot_fall_back_to_patch_text(self) -> None:
        owner = COVERAGE.SOURCE / self.contract["decision_surface"]["decisions"][2]["positive"]["owner"]
        real_is_file = Path.is_file
        with patch.object(Path, "is_file", lambda path: False if path == owner else real_is_file(path)):
            with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "absent from declared owner"):
                COVERAGE.validate_contract(self.contract)

    def test_stale_materialization_cannot_validate_current_selectors(self) -> None:
        real_load = COVERAGE.load_contract

        def stale_marker(path: Path) -> dict:
            value = real_load(path)
            if path.name == ".good-bear-materialization.json":
                value["version"] = "155.0.1"
            return value

        with patch.object(COVERAGE, "load_contract", side_effect=stale_marker):
            with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "materialization differs"):
                COVERAGE.validate_contract(self.contract)

    def test_native_owner_drift_requires_a_new_declaration_review(self) -> None:
        changed = copy.deepcopy(self.contract)
        owner = next(iter(changed["native_test_owner_sha256"]))
        changed["native_test_owner_sha256"][owner] = "0" * 64
        with self.assertRaisesRegex(COVERAGE.DecisionCoverageError, "changed after declaration review"):
            COVERAGE.validate_contract(changed)

    def test_bare_comment_is_not_an_executable_selector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root / "tests/test_comment.py"
            owner.parent.mkdir()
            owner.write_text("# test_comment_only is mentioned here but never defined\n", encoding="utf-8")
            self.assertEqual(COVERAGE.selector_locations(
                root, "tests/test_comment.py", "test_comment_only", "156.0"), [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_m15_12", ROOT / "tools" / "verify_m15_12_hosted_service_boundary.py")
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)


class HostedServiceBoundaryTest(unittest.TestCase):
    def load_contract(self) -> dict:
        return json.loads(VERIFY.CONTRACT.read_text(encoding="utf-8"))

    def verify_mutation(self, mutate) -> str:
        contract = copy.deepcopy(self.load_contract())
        mutate(contract)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaises(VERIFY.BoundaryError) as raised:
                VERIFY.verify(contract_path=path)
        return str(raised.exception)

    def test_repository_contract_passes(self) -> None:
        VERIFY.verify()

    def test_security_collection_names_match_the_native_signed_clients(self) -> None:
        source = (VERIFY.SOURCE / "security/manager/ssl/RemoteSecuritySettings.sys.mjs").read_text()
        VERIFY.verify_native_security_collections(source)
        for old, new in (("cert-revocations", "crlite-filters"),
                         ("onecrl.content-signature.mozilla.org", "unreviewed.example")):
            with self.subTest(changed=old), self.assertRaises(VERIFY.BoundaryError):
                VERIFY.verify_native_security_collections(source.replace(old, new))

    def test_stale_crlite_collection_cannot_replace_the_active_revocation_feed(self) -> None:
        def mutate(contract: dict) -> None:
            service = next(row for row in contract["security_services"]
                           if row["id"] == "remote_settings_security_collections")
            service["remote_collections_retained"] = [
                "security-state/onecrl", "security-state/intermediates", "security-state/crlite-filters"]
        self.assertIn("certificate security collections must remain protected", self.verify_mutation(mutate))

    def test_old_firefox_audit_cannot_be_reused(self) -> None:
        def mutate(contract: dict) -> None:
            contract["firefox_base"] = {
                "version": "155.0.1",
                "revision": "fb95137a04eb8fe1196cb12f26b100c1e060295c",
            }
        self.assertIn("not pinned to Firefox 156.0", self.verify_mutation(mutate))

    def test_changed_revision_does_not_reuse_the_source_review(self) -> None:
        def mutate(contract: dict) -> None:
            contract["rebase_audit"]["to_revision"] = "0" * 40
        self.assertIn("reviewed 155-to-156 delta", self.verify_mutation(mutate))

    def test_every_named_upstream_owner_needs_a_disposition(self) -> None:
        def mutate(contract: dict) -> None:
            del contract["rebase_audit"]["owner_dispositions"]["services/settings/RemoteSettingsClient.sys.mjs"]
        self.assertIn("needs a rebase disposition", self.verify_mutation(mutate))

    def test_upstream_signature_guards_cannot_be_discarded(self) -> None:
        def mutate(contract: dict) -> None:
            contract["rebase_audit"]["owner_dispositions"]["services/settings/RemoteSettingsClient.sys.mjs"][
                "disposition"] = "disable_signature_verification"
        self.assertIn("unsafe hosted-service owner disposition", self.verify_mutation(mutate))

    def test_new_relay_promo_and_account_ping_require_explicit_disables(self) -> None:
        for service_id, pref in (
            ("firefox_relay", "browser.promo.relay.enabled"),
            ("firefox_account_and_sync", "identity.fxaccounts.telemetry.clientInfoPing.enabled"),
        ):
            for value in (True, None):
                with self.subTest(service=service_id, value=value):
                    def mutate(contract: dict) -> None:
                        service = next(row for row in contract["disabled_services"] if row["id"] == service_id)
                        if value is None:
                            del service["prefs"][pref]
                        else:
                            service["prefs"][pref] = value
                    self.assertIn("explicitly disabled", self.verify_mutation(mutate))

    def test_ml_autofill_cannot_download_a_model_or_disable_local_autofill(self) -> None:
        for prefs in (
            {"extensions.formautofill.useml": True},
            {"extensions.formautofill.useml": False,
             "extensions.formautofill.addresses.enabled": False},
        ):
            with self.subTest(prefs=prefs):
                def mutate(contract: dict) -> None:
                    entry = next(row for row in contract["security_services"]
                                 if row["id"] == "form_autofill_model_download")
                    entry["prefs"] = prefs
                self.assertIn("unpinned model or disable local autofill", self.verify_mutation(mutate))

    def test_security_suppliers_cannot_be_disabled_or_promoted_without_review(self) -> None:
        for service_id in VERIFY.PRESERVED_SECURITY_PREFS:
            for changed_field, value in (("default", "disabled_pending_supplier"),
                                         ("supplier_status", "ready"),
                                         ("endpoint_prefs_cleared", ["services.settings.server"])):
                with self.subTest(service=service_id, field=changed_field):
                    def mutate(contract: dict) -> None:
                        service = next(row for row in contract["security_services"] if row["id"] == service_id)
                        service[changed_field] = value
                    self.assertIn("must retain security protection", self.verify_mutation(mutate))

    def test_truncated_patch_counts_cannot_hide_unapplied_security_defaults(self) -> None:
        patch_text = (ROOT / "patches/0037-good-bear-hosted-service-boundary.patch").read_text()
        VERIFY.verify_patch_hunk_counts(patch_text)
        shortened = patch_text.replace("+3723,120", "+3723,103")
        self.assertNotEqual(shortened, patch_text)
        with self.assertRaisesRegex(VERIFY.BoundaryError, "unapplied or missing lines"):
            VERIFY.verify_patch_hunk_counts(shortened)

    def test_patch_cannot_clear_security_endpoints_or_disable_protection(self) -> None:
        for name in VERIFY.PRESERVED_SECURITY_ENDPOINTS:
            with self.subTest(name=name):
                with self.assertRaisesRegex(VERIFY.BoundaryError, "preserve its upstream default"):
                    VERIFY.verify_preserved_security_defaults(VERIFY.pref_literal(name, ""))
        for prefs in VERIFY.PRESERVED_SECURITY_PREFS.values():
            for name in prefs:
                with self.subTest(name=name):
                    with self.assertRaisesRegex(VERIFY.BoundaryError, "preserve its upstream default"):
                        VERIFY.verify_preserved_security_defaults(VERIFY.pref_literal(name, False))

    def test_full_patch_applies_product_disables_and_preserves_security_and_local_autofill(self) -> None:
        """Apply the real patch to synthetic owners, then inspect actual output bytes."""
        protected = {name: value for prefs in VERIFY.PRESERVED_SECURITY_PREFS.values()
                     for name, value in prefs.items()}
        protected.update({name: "https://security.example.test/" for name in VERIFY.PRESERVED_SECURITY_ENDPOINTS})
        protected.update({"extensions.formautofill.addresses.enabled": True,
                          "extensions.formautofill.creditCards.enabled": True})
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            configure = stage / "browser/moz.configure"
            configure.parent.mkdir(parents=True)
            configure.write_text(
                '# file, You can obtain one at http://mozilla.org/MPL/2.0/.\n\n'
                'imply_option("MOZ_PLACES", True)\n'
                'imply_option("MOZ_SERVICES_HEALTHREPORT", True)\n'
                'imply_option("MOZ_SERVICES_SYNC", True)\n'
                'imply_option("MOZ_DEDICATED_PROFILES", True)\n'
                'imply_option("MOZ_BLOCK_PROFILE_DOWNGRADE", True)\n'
                'imply_option("MOZ_NORMANDY", True)\n'
                'imply_option("MOZ_PROFILE_MIGRATOR", True)\n\n\n', encoding="utf-8")
            defaults = stage / "browser/app/profile/firefox.js"
            defaults.parent.mkdir(parents=True)
            defaults.write_text(
                "\n".join(VERIFY.pref_literal(name, value)[1:] for name, value in protected.items()) +
                '\npref("breakpad.reportURL", "");\n'
                '#ifdef XP_MACOSX\n  pref("browser.macAppMenu.setAsDefaultShown", false);\n#endif\n',
                encoding="utf-8")
            result = subprocess.run(
                ["git", "apply", "--no-index", "--whitespace=error-all",
                 str(ROOT / "patches/0037-good-bear-hosted-service-boundary.patch")],
                cwd=stage, env={**os.environ, "GIT_CEILING_DIRECTORIES": str(stage.parent)},
                capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = {name: json.loads(value) for name, value in re.findall(
                r'^\s*pref\("([^"]+)",\s*(.*?)\);', defaults.read_text(), re.MULTILINE)}
            contract = self.load_contract()
            for entry in contract["disabled_services"] + contract["security_services"]:
                for name, expected in entry["prefs"].items():
                    self.assertEqual(actual[name], expected, name)
                for name in entry["endpoint_prefs_cleared"]:
                    self.assertEqual(actual[name], "", name)
            for name, expected in protected.items():
                self.assertEqual(actual[name], expected, name)

    def test_unknown_hosted_service_fails_closed(self) -> None:
        message = self.verify_mutation(lambda contract: contract["disabled_services"].append({
            "id": "new_upstream_service",
            "ui": "absent",
            "background_network": "denied",
            "prefs": {"new.service.enabled": False},
            "endpoint_prefs_cleared": ["new.service.url"],
        }))
        self.assertIn("inventory drift", message)

    def test_security_supplier_cannot_be_silently_enabled(self) -> None:
        def mutate(contract: dict) -> None:
            contract["security_services"][4]["default"] = "mozilla_default"
        self.assertIn("silently inherits", self.verify_mutation(mutate))

    def test_unknown_remote_collection_policy_cannot_be_relaxed(self) -> None:
        def mutate(contract: dict) -> None:
            contract["defaults"]["unknown_remote_config_collection"] = "allow"
        self.assertIn("must fail closed", self.verify_mutation(mutate))

    def test_content_navigation_is_not_confused_with_privileged_service_requests(self) -> None:
        def mutate(contract: dict) -> None:
            contract["content_navigation_policy"] = "deny"
        self.assertIn("web content navigation", self.verify_mutation(mutate))

    def test_static_contract_cannot_claim_release_runtime_evidence(self) -> None:
        def mutate(contract: dict) -> None:
            contract["release_status"] = "complete"
        self.assertIn("must not promote", self.verify_mutation(mutate))

    def test_good_bear_telemetry_cannot_reuse_mozilla_glean(self) -> None:
        def mutate(contract: dict) -> None:
            contract["good_bear_usage_telemetry"]["implementation"] = "mozilla_glean"
        self.assertIn("must not reactivate", self.verify_mutation(mutate))

    def test_enabled_user_default_does_not_open_unconfigured_transport(self) -> None:
        def mutate(contract: dict) -> None:
            contract["good_bear_usage_telemetry"]["transport_gate_default"] = True
        self.assertIn("fail closed", self.verify_mutation(mutate))

    def test_firefox_account_ui_enforcement_patch_is_required(self) -> None:
        self.assertIn("UI enforcement patch", self.verify_mutation(
            lambda contract: contract.__setitem__("ui_enforcement_patch", "missing.patch")))

    def test_user_opt_out_must_stop_every_submission_stage(self) -> None:
        def mutate(contract: dict) -> None:
            contract["good_bear_usage_telemetry"]["disable_actions"].remove(
                "retain_zero_network_requests")
        self.assertIn("opt-out semantics", self.verify_mutation(mutate))


if __name__ == "__main__":
    unittest.main()

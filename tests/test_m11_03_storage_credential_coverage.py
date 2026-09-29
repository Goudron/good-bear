#!/usr/bin/env python3
"""Ownership guard for executable GB100-M11-03 isolation evidence.

The assertions here only prevent accidental removal of the live probe and its
fail-closed guards.  They are intentionally not acceptance evidence by
themselves; run the probe against a freshly repacked candidate.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE

BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
FIREFOX = SOURCE
CONTRACT = json.loads(
    (ROOT / "config/m11-03-storage-credential-coverage-contract.json").read_text(
        encoding="utf-8"
    )
)


class M1103StorageCredentialCoverageTest(unittest.TestCase):
    def test_contract_owns_every_required_runtime_category(self) -> None:
        self.assertEqual(CONTRACT["schema_version"], 1)
        self.assertEqual(CONTRACT["task"], "GB100-M11-03")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        self.assertEqual(CONTRACT["required_profile_pref"], "privacy.userContext.enabled")
        self.assertEqual(
            CONTRACT["required_web_state"],
            ["cookies", "localStorage", "IndexedDB", "Cache API", "service workers"],
        )
        self.assertEqual(
            CONTRACT["required_credential_state"],
            [
                "saved logins",
                "autofill",
                "HTTP origin authentication",
                "HTTP proxy authentication",
                "TLS client-auth decisions",
            ],
        )

    def test_profile_global_credential_surfaces_fail_closed_in_the_native_context(self) -> None:
        password = (FIREFOX / CONTRACT["credential_guard_owners"]["password_manager"]).read_text(
            encoding="utf-8"
        )
        autofill = (FIREFOX / CONTRACT["credential_guard_owners"]["form_autofill"]).read_text(
            encoding="utf-8"
        )
        for source in (password, autofill):
            self.assertIn('Cc["@mozilla.org/psm;1"]', source)
            self.assertIn("isGoodBearRussianPKIContainer(\n        userContextId,", source)
            self.assertIn("principal.originAttributes.privateBrowsingId !== 0", source)
        for message in (
            "PasswordManager:findLogins",
            "PasswordManager:autoCompleteLogins",
            "PasswordManager:onPasswordEditedOrGenerated",
            "PasswordManager:ShowDoorhanger",
            "PasswordManager:removeLogin",
        ):
            self.assertIn(message, password)
        self.assertIn('return { records: [] };', autofill)
        self.assertIn("FormAutofill:SaveAddress", autofill)
        self.assertIn("FormAutofill:RemoveAddresses", autofill)

    def test_proxy_auth_uses_the_native_scope_authority_only_for_the_managed_context(self) -> None:
        source = (FIREFOX / CONTRACT["credential_guard_owners"]["http_proxy_auth"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("nsINSSComponent.h", source)
        self.assertIn("ShouldIsolateGoodBearRussianPKIProxyAuth", source)
        self.assertIn("GetAuthCacheOriginSuffix", source)
        self.assertIn("PSM_COMPONENT_CONTRACTID", source)
        self.assertIn("aProxyAuth", source)
        self.assertIn("nsHttp::Proxy_Authorization", source)
        self.assertNotIn("proxy credentials are not OA-isolated", source)

    def test_firefox_156_optional_autocomplete_stays_behind_native_guards(self) -> None:
        password = (FIREFOX / CONTRACT["credential_guard_owners"]["password_manager"]).read_text(
            encoding="utf-8"
        )
        dispatch_start = password.index("async receiveMessage(msg)")
        dispatch = password[dispatch_start : password.index("\n  #onUpdateDoorhangerSuggestions(", dispatch_start)]
        self.assertLess(
            dispatch.index("isGoodBearRussianPKIContainer(this.manager?.documentPrincipal)"),
            dispatch.index("return { logins: [] };"),
        )
        self.assertLess(
            dispatch.index("return { logins: [] };"),
            dispatch.index("this.doAutocompleteSearch(this.origin, data)"),
        )

        # Firefox 156 adds this optional provider to both native autocomplete
        # owners. Its default-off check must precede actor access; these source
        # assertions do not substitute for the separate runtime isolation probe.
        provider = (
            FIREFOX / "browser/components/aiwindow/ui/modules/SmartFormFillAutocomplete.sys.mjs"
        ).read_text(encoding="utf-8")
        start = provider.index("  async autocompleteItemsAsync({")
        autocomplete = provider[start : provider.index("  async createItemsAsync(", start)]
        guard = autocomplete.index(
            "if (!isSupportedInput || !lazy.SFF_ENABLED || !smartWindowActive)"
        )
        rejection = autocomplete.index("return [];", guard)
        actor = autocomplete.index('getActor("SmartFormFill")')
        self.assertLess(guard, rejection)
        self.assertLess(rejection, actor)
        self.assertIn("sffActor.searchAutoCompleteEntries(searchString,", autocomplete)
        defaults = (FIREFOX / "browser/app/profile/firefox.js").read_text(encoding="utf-8")
        self.assertIn('pref("browser.smartwindow.smartformfill.enabled", false);', defaults)
        self.assertIn('pref("browser.smartwindow.enabled", false);', defaults)

    def test_live_probe_exercises_runtime_and_not_a_ui_marker(self) -> None:
        source = (ROOT / CONTRACT["live_probe"]).read_text(encoding="utf-8")
        for required in (
            'user_pref("privacy.userContext.enabled", true);',
            "ThreadingHTTPServer",
            "open_state_tab",
            "serviceWorker",
            "LoginManager",
            "FormAutofill",
            "clientAuthRememberService",
            "Authorization",
            "proxy authentication",
            "restart",
        ):
            self.assertIn(required, source)
        self.assertNotIn("identity-icon-label", source)


if __name__ == "__main__":
    unittest.main()

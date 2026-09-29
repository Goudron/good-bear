#!/usr/bin/env python3
"""Structural guard for GB100-M11-04 executable UI/PB/0-RTT evidence.

The test deliberately does not substitute for the named live probe or the
packet/server xpcshell test. It prevents their safety-critical owners from
being silently disconnected from the release inputs.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
CONTRACT = json.loads(
    (ROOT / "config/m11-04-ui-private-early-coverage-contract.json").read_text(
        encoding="utf-8"
    )
)


class M1104UiPrivateEarlyCoverageTest(unittest.TestCase):
    def test_contract_is_pinned_to_the_approved_runtime_policy(self) -> None:
        self.assertEqual(CONTRACT["schema_version"], 1)
        self.assertEqual(CONTRACT["task"], "GB100-M11-04")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        self.assertEqual(CONTRACT["private_browsing_policy"], "blocked")
        self.assertEqual(CONTRACT["zero_rtt_policy"], "disabled_globally")

    def test_private_browsing_cannot_reuse_the_managed_context_id(self) -> None:
        authority = (FIREFOX / CONTRACT["private_scope_owners"][0]).read_text(encoding="utf-8")
        scope = (FIREFOX / CONTRACT["private_scope_owners"][1]).read_text(encoding="utf-8")
        gtest = (FIREFOX / CONTRACT["private_scope_owners"][2]).read_text(encoding="utf-8")
        self.assertIn("aOriginAttributes.mPrivateBrowsingId != 0", authority)
        self.assertIn("aOriginAttributes.mPrivateBrowsingId == 0", scope)
        self.assertIn("PrivateBrowsingNeverReceivesAlternateRussianPKITrust", gtest)
        self.assertIn("ASSERT_FALSE(authority.Allows(PrivateAttributesFor(17)))", gtest)

    def test_zero_rtt_packet_test_cannot_be_reenabled_by_pref(self) -> None:
        nss = (FIREFOX / "security/manager/ssl/nsNSSComponent.cpp").read_text(encoding="utf-8")
        packet_test = (FIREFOX / CONTRACT["zero_rtt_packet_test"]).read_text(encoding="utf-8")
        manifest = (FIREFOX / "netwerk/test/unit/xpcshell.toml").read_text(encoding="utf-8")
        self.assertGreaterEqual(nss.count("SSL_OptionSetDefault(SSL_ENABLE_0RTT_DATA, false);"), 2)
        self.assertIn('Services.prefs.setBoolPref("security.tls.enable_0rtt_data", true);', packet_test)
        self.assertIn('"Cookie", "ordinary=must-not-leak"', packet_test)
        self.assertIn('"X-Good-Bear-Ordinary", "must-not-leak"', packet_test)
        self.assertIn("TLS server observed no ordinary cookie or header in 0-RTT", packet_test)
        self.assertIn('["test_goodbear_russian_pki_0rtt.js"]', manifest)

    def test_russian_ui_uses_native_trust_domain_and_localized_noncolor_text(self) -> None:
        identity = (FIREFOX / CONTRACT["ui_owners"][0]).read_text(encoding="utf-8")
        trust_panel = (FIREFOX / CONTRACT["ui_owners"][1]).read_text(encoding="utf-8")
        css = (FIREFOX / CONTRACT["ui_owners"][2]).read_text(encoding="utf-8")
        russian = (ROOT / "source/l10n/firefox-l10n/ru/browser/browser/browser.ftl").read_text(
            encoding="utf-8"
        )
        self.assertIn("Ci.nsITransportSecurityInfo.RussianPKI", identity)
        self.assertIn("_usesGoodBearRussianPKI", identity)
        self.assertIn('"goodbear-trust-domain"', trust_panel)
        self.assertIn('[when-goodbear-trust-domain~="russian-pki"]', css)
        self.assertIn('[goodbear-trust-domain="russian-pki"] [when-customroot]', css)
        for message in CONTRACT["required_russian_messages"]:
            self.assertIn(f"{message} =", russian)
        self.assertIn("Good Bear распознал в качестве издателя сертификата", russian)

    def test_trust_panel_remains_local_when_mozilla_remote_settings_is_closed(self) -> None:
        trust_panel = (FIREFOX / CONTRACT["ui_owners"][1]).read_text(encoding="utf-8")
        guard = 'Services.prefs.getStringPref("services.settings.server", "")'
        remote_lookup = 'RemoteSettings(REMOTE_SETTINGS_COLLECTION).get()'
        self.assertIn(guard, trust_panel)
        self.assertIn(remote_lookup, trust_panel)
        self.assertLess(trust_panel.index(guard), trust_panel.index(remote_lookup))
        self.assertIn("return [];", trust_panel)

    def test_runtime_probe_is_kept_as_runtime_evidence(self) -> None:
        probe = ROOT / CONTRACT["runtime_probe"]
        self.assertTrue(probe.is_file())
        text = probe.read_text(encoding="utf-8")
        for required in (
            "Services.locale.appLocaleAsBCP47",
            "goodbear-trust-domain",
            "privateBrowsingId",
            "Marionette",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()

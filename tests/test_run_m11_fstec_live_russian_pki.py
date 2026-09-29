#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "fstec_live", ROOT / "tools" / "run_m11_fstec_live_russian_pki.py"
)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


class FSTECIntegrationRunnerTest(unittest.TestCase):
    def test_live_endpoint_and_success_invariants_are_explicit(self) -> None:
        self.assertEqual(LIVE.FSTEC_URL, "https://fstec.ru/")
        self.assertEqual(LIVE.RUSSIAN_PKI_TRUST_DOMAIN, 2)
        self.assertEqual(LIVE.RUSSIAN_PKI_LABEL, "RU")

    def test_success_requires_dedicated_container_and_native_domain(self) -> None:
        state = {
            "dedicatedUserContextId": 6,
            "tabs": [
                {
                    "url": "https://fstec.ru/",
                    "userContextId": 6,
                    "trustDomain": 2,
                }
            ],
        }
        self.assertIsNotNone(LIVE.successful_fstec_tab(state))
        state["tabs"][0]["trustDomain"] = 1
        self.assertIsNone(LIVE.successful_fstec_tab(state))

    def test_multiple_successes_require_the_same_dedicated_native_domain(self) -> None:
        state = {
            "dedicatedUserContextId": 6,
            "tabs": [
                {"url": LIVE.FSTEC_URL, "userContextId": 6, "trustDomain": 2},
                {"url": LIVE.FSTEC_URL, "userContextId": 0, "trustDomain": None},
            ],
        }
        self.assertEqual(len(LIVE.successful_fstec_tabs(state)), 1)
        state["tabs"][1] = {
            "url": LIVE.FSTEC_URL,
            "userContextId": 6,
            "trustDomain": 2,
        }
        self.assertEqual(len(LIVE.successful_fstec_tabs(state)), 2)

    def test_runner_uses_project_owned_temp_and_rejects_certificate_overrides(self) -> None:
        source = (ROOT / "tools/run_m11_fstec_live_russian_pki.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("temporary_directory(prefix=\"good-bear-fstec-live-\")", source)
        self.assertIn('profile / "cert_override.txt"', source)
        self.assertIn("verify_archive(archive)", source)
        self.assertIn("from marionette_driver.marionette import Marionette", source)
        self.assertIn('"--remote-allow-system-access"', source)
        self.assertIn('client.set_context("chrome")', source)
        self.assertIn('"Listening on port 2828"', source)
        self.assertIn("MarionetteActivePort", source)
        self.assertIn("runpy.run_path", source)
        self.assertIn("second ordinary tab", source)

    def test_runner_navigates_with_a_native_uri_not_a_string(self) -> None:
        source = (ROOT / "tools/run_m11_fstec_live_russian_pki.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('Services.io.newURI("https://fstec.ru/")', source)

    def test_runner_resolves_the_archive_before_entering_mach(self) -> None:
        source = (ROOT / "tools/run_m11_fstec_live_russian_pki.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("archive = args.archive.resolve()", source)
        self.assertIn("str(archive)", source)

    def test_runner_checks_the_visible_trust_panel_ru_badge(self) -> None:
        source = (ROOT / "tools/run_m11_fstec_live_russian_pki.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"trust-goodbear-russian-pki-label"', source)
        self.assertNotIn('const label = w.document.getElementById("identity-icon-label")', source)

    def test_runner_waits_for_the_first_visit_assignment_before_repeating(self) -> None:
        source = (ROOT / "tools/run_m11_fstec_live_russian_pki.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("def marionette_persisted_fstec_assignment", source)
        self.assertIn("container.assignmentStore.isAssigned", source)
        self.assertLess(
            source.index("Waiting for the exact FSTEC assignment"),
            source.index("Reopening FSTEC from a second ordinary tab"),
        )

    def test_production_badge_is_a_visible_trust_panel_control(self) -> None:
        markup = (
            LIVE.SOURCE / "browser/base/content/navigator-toolbox.inc.xhtml"
        ).read_text(encoding="utf-8")
        identity = (
            LIVE.SOURCE / "browser/base/content/browser-siteIdentity.js"
        ).read_text(encoding="utf-8")
        css = (
            LIVE.SOURCE / "browser/themes/shared/identity-block/identity-block.css"
        ).read_text(encoding="utf-8")
        self.assertIn('id="trust-goodbear-russian-pki-label"', markup)
        self.assertIn('"trust-goodbear-russian-pki-label"', identity)
        self.assertIn("this._goodBearRussianPKITrustLabel.hidden = false", identity)
        self.assertIn("this._goodBearRussianPKITrustLabel.hidden = true", identity)
        self.assertIn("#trust-goodbear-russian-pki-label", css)

    def test_production_route_uses_the_real_browser_window_in_all_three_paths(self) -> None:
        source = (
            LIVE.SOURCE / "browser/components/BrowserGlue.sys.mjs"
        ).read_text(encoding="utf-8")
        self.assertIn("function getBrowserWindow(browser)", source)
        self.assertGreaterEqual(source.count("getBrowserWindow(browser)"), 4)
        self.assertNotIn("if (!browser?.ownerGlobal || browser.ownerGlobal.closed)", source)
        patch = (
            ROOT / "patches/0023-good-bear-live-fstec-auto-route-window.patch"
        ).read_text(encoding="utf-8")
        self.assertIn("test_assigned_origin_uses_the_real_browser_window", patch)
        self.assertNotIn("test_real_browser_window_survives_deferred_auto_route", patch)


if __name__ == "__main__":
    unittest.main()

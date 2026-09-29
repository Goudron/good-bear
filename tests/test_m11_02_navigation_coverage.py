#!/usr/bin/env python3
"""Static ownership guard for the M11-02 browser-level navigation evidence."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
CONTRACT = json.loads(
    (ROOT / "config/m11-02-navigation-coverage-contract.json").read_text(encoding="utf-8")
)


class M1102NavigationCoverageTest(unittest.TestCase):
    def test_contract_pins_the_current_browser_coverage(self) -> None:
        self.assertEqual(CONTRACT["schema_version"], 1)
        self.assertEqual(CONTRACT["task"], "GB100-M11-02")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        for owner in CONTRACT["browser_tests"]:
            self.assertTrue((FIREFOX / owner).is_file(), owner)

    def test_network_probe_is_registered_and_checks_the_actual_request_boundary(self) -> None:
        evidence = CONTRACT["network_evidence"]
        test = (FIREFOX / evidence["test_owner"]).read_text(encoding="utf-8")
        server = (FIREFOX / evidence["server_probe"]).read_text(encoding="utf-8")
        manifest = (
            FIREFOX / "browser/components/contextualidentity/test/browser/browser.toml"
        ).read_text(encoding="utf-8")
        self.assertIn('["browser_goodbear_russian_pki_navigation_network.js"]', manifest)
        self.assertIn('"goodbear_russian_pki_navigation.sjs"', manifest)
        for required in evidence["required_assertions"]:
            self.assertIn(required, test)
        self.assertIn('aResponse.setStatusLine(aRequest.httpVersion, 302, "Found")', server)
        self.assertIn('document.body.dataset.opener', server)

    def test_each_required_navigation_dimension_has_a_browser_owner(self) -> None:
        owners = {Path(owner).name for owner in CONTRACT["browser_tests"]}
        for dimension, owner in CONTRACT["coverage"].items():
            self.assertIn(owner, owners, dimension)

    def test_runtime_probe_attacks_the_ordinary_subresource_boundary(self) -> None:
        probe = (ROOT / "tools/run_m11_02_navigation_network_probe.py").read_text(
            encoding="utf-8"
        )
        for marker in (
            "Ci.nsIContentPolicy.TYPE_SCRIPT",
            "Ci.nsIContentPolicy.TYPE_IMAGE",
            "Ci.nsIContentPolicy.TYPE_SUBDOCUMENT",
            "Ci.nsIContentPolicy.REJECT_POLICY",
            "subresource_rejections == [True, True, True]",
            "goodBearRussianPKIRequired: true",
            'errorCodeString: "SEC_ERROR_UNKNOWN_ISSUER"',
            '"stringOnlyRoutes": False',
            'requestMethod: "POST"',
            '"hasRequestBody": True',
            '"autoOpen": False',
        ):
            self.assertIn(marker, probe)


if __name__ == "__main__":
    unittest.main()

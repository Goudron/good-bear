# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "verify_m10_07_source_release_inventory",
    ROOT / "tools/verify_m10_07_source_release_inventory.py",
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class SourceReleaseInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = json.loads(
            (ROOT / "config/m10-07-source-release-inventory.json").read_text(encoding="utf-8")
        )

    def test_generates_exact_local_source_and_provenance_inventory(self) -> None:
        report = VERIFY.validate(ROOT)
        self.assertEqual(report["product"], "Good Bear")
        self.assertEqual(report["shipped_locales"], ["ru"])
        # The report includes patches/series itself plus every ordered patch.
        self.assertEqual(
            len(report["patch_set"]["files"]),
            len(VERIFY.series_entries(ROOT)) + 1,
        )
        self.assertTrue(report["overlay"]["files"])
        self.assertEqual(len(report["russian_localization"]), 4)
        self.assertTrue(report["artwork"])
        self.assertEqual(report["legal_notice_entrypoint"], "about:license")

    def test_public_release_remains_fail_closed_for_unresolved_inputs(self) -> None:
        report = VERIFY.validate(ROOT)
        self.assertFalse(report["public_release_allowed"])
        self.assertEqual(
            set(report["public_release_blockers"]), VERIFY.EXPECTED_PUBLIC_BLOCKERS
        )
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/verify_m10_07_source_release_inventory.py"),
             "--public-release"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("public release blocked", completed.stderr)

    def test_source_offer_location_and_certificate_binary_status_are_recorded(self) -> None:
        source = self.inventory["corresponding_source"]
        self.assertEqual(source["source_offer"]["location"], "https://github.com/Goudron/good-bear")
        certificates = next(
            component for component in self.inventory["components"]
            if component["id"] == "russian-pki-certificates"
        )
        self.assertIn("approved", certificates["redistribution_status"])

    def test_public_fstec_leaf_is_source_only_test_data(self) -> None:
        fixture = self.inventory["corresponding_source"]["test_certificate_fixtures"][0]
        self.assertFalse(fixture["trust_input"])
        self.assertFalse(fixture["binary_packaging"])
        report = VERIFY.validate(ROOT)
        component = next(
            item for item in report["components"]
            if item["id"] == "fstec-public-leaf-test-fixture"
        )
        self.assertIn("source-only", component["redistribution_status"])

    def test_rejects_fstec_leaf_as_a_trust_input(self) -> None:
        altered = copy.deepcopy(self.inventory)
        altered["corresponding_source"]["test_certificate_fixtures"][0]["trust_input"] = True
        with self.assertRaisesRegex(VERIFY.SourceInventoryError, "never trust or binary input"):
            VERIFY.validate(ROOT, inventory=altered)

    def test_rejects_wrong_corresponding_firefox_source(self) -> None:
        altered = copy.deepcopy(self.inventory)
        altered["corresponding_source"]["upstream"]["revision"] = "0" * 40
        with self.assertRaisesRegex(VERIFY.SourceInventoryError, "wrong Firefox revision"):
            VERIFY.validate(ROOT, inventory=altered)

    def test_rejects_legal_notice_checks_against_a_stale_worktree(self) -> None:
        altered = copy.deepcopy(self.inventory)
        altered["legal_surfaces"]["bundled_notice_owner"] = (
            "source/worktrees/firefox-155.0.1/toolkit/content/license.html")
        with self.assertRaisesRegex(VERIFY.SourceInventoryError, "current canonical Firefox source"):
            VERIFY.validate(ROOT, inventory=altered)

    def test_rejects_fixture_checks_against_a_stale_worktree(self) -> None:
        altered = copy.deepcopy(self.inventory)
        altered["corresponding_source"]["test_certificate_fixtures"][0]["path"] = (
            "source/worktrees/firefox-155.0.1/security/manager/ssl/tests/gtest/goodbear-russian-pki/fstec-rsa2024-leaf.pem")
        with self.assertRaisesRegex(VERIFY.SourceInventoryError, "current canonical Firefox source"):
            VERIFY.validate(ROOT, inventory=altered)

    def test_rejects_an_incomplete_component_rights_record(self) -> None:
        altered = copy.deepcopy(self.inventory)
        del altered["components"][0]["redistribution_status"]
        with self.assertRaisesRegex(VERIFY.SourceInventoryError, "fields are required"):
            VERIFY.validate(ROOT, inventory=altered)

    def test_rejects_a_patch_missing_from_the_source_offer(self) -> None:
        altered = copy.deepcopy(self.inventory)
        altered["corresponding_source"]["patch_set"]["entries"].pop()
        with self.assertRaisesRegex(VERIFY.SourceInventoryError, "differs from patches/series"):
            VERIFY.validate(ROOT, inventory=altered)

    def test_rejects_public_release_gate_bypass(self) -> None:
        altered = copy.deepcopy(self.inventory)
        altered["public_release_gate"]["allowed"] = True
        with self.assertRaisesRegex(VERIFY.SourceInventoryError, "must block public artifacts"):
            VERIFY.validate(ROOT, inventory=altered)

    def test_rejects_missing_mozilla_non_affiliation(self) -> None:
        altered = copy.deepcopy(self.inventory)
        altered["legal_surfaces"]["mozilla_non_affiliation"] = "неверное уведомление"
        with self.assertRaisesRegex(VERIFY.SourceInventoryError, "non-affiliation"):
            VERIFY.validate(ROOT, inventory=altered)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "verify_branding_inventory.py"
SPEC = importlib.util.spec_from_file_location("branding_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


class BrandingInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = json.loads(
            (ROOT / "config" / "branding-provenance-inventory.json").read_text(encoding="utf-8")
        )

    def test_reviewed_inventory_covers_every_required_surface_and_form(self) -> None:
        INVENTORY.validate(self.inventory)
        self.assertEqual(set(self.inventory["coverage"]), INVENTORY.REQUIRED_SURFACES)
        for forms in self.inventory["coverage"].values():
            self.assertTrue(forms["strings"])
            self.assertTrue(forms["assets"])

    def test_release_identity_inventory_passes_after_m10_03_asset_replacement(self) -> None:
        INVENTORY.validate(self.inventory, release=True)

    def test_original_m10_03_onboarding_identity_is_allowed_only_after_replacement(self) -> None:
        altered = copy.deepcopy(self.inventory)
        entry = next(item for item in altered["entries"]
                     if item["id"] == "onboarding-firefox-mascot-assets")
        entry["public_identity"] = "prohibited"
        with self.assertRaisesRegex(INVENTORY.InventoryError, "prohibited public identity"):
            INVENTORY.validate(altered)

    def test_connection_and_certificate_error_fox_art_is_explicitly_release_blocked(self) -> None:
        entry = next(item for item in self.inventory["entries"]
                     if item["id"] == "network-and-certificate-error-firefox-art")
        self.assertEqual(entry["surface"], "error")
        self.assertEqual(entry["classification"], "product_mark")
        self.assertEqual(entry["public_identity"], "allowed")
        self.assertEqual(entry["release_status"], "allowed")
        self.assertEqual(entry["paths"], [
            "overlay/toolkit/themes/shared/illustrations/goodbear-no-connection.png",
            "overlay/toolkit/themes/shared/illustrations/goodbear-security-error.png",
        ])

    def test_legal_attribution_remains_distinct_from_product_identity(self) -> None:
        entry = next(item for item in self.inventory["entries"]
                     if item["id"] == "about-upstream-attribution")
        self.assertEqual(entry["classification"], "legal_attribution")
        self.assertEqual(entry["public_identity"], "preserve_attribution")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m10_03_artwork", ROOT / "tools" / "verify_m10_03_artwork_system.py")
assert SPEC and SPEC.loader
ARTWORK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTWORK)


class ArtworkSystemTest(unittest.TestCase):
    def setUp(self) -> None:
        self.record = json.loads((ROOT / "config" / "m10-03-artwork-system.json").read_text(encoding="utf-8"))

    def test_selected_original_artwork_system_is_complete(self) -> None:
        ARTWORK.validate(self.record)

    def test_circle_or_security_state_claim_cannot_enter_the_mascot_contract(self) -> None:
        altered = copy.deepcopy(self.record)
        altered["identity_invariants"]["monochrome_or_small_icon_has_no_enclosing_circle"] = False
        with self.assertRaisesRegex(ARTWORK.ArtworkError, "identity invariant"):
            ARTWORK.validate(altered)

    def test_error_artwork_cannot_leave_its_transparent_safe_zone(self) -> None:
        altered = copy.deepcopy(self.record)
        altered["error_illustration_contract"]["assets"][
            "overlay/toolkit/themes/shared/illustrations/goodbear-no-connection.png"
        ]["minimum_transparent_margin_px"] = 400
        with self.assertRaisesRegex(ARTWORK.ArtworkError, "transparent safe zone"):
            ARTWORK.validate(altered)

    def test_error_artwork_cannot_drop_the_reserved_layout_contract(self) -> None:
        altered = copy.deepcopy(self.record)
        altered["error_illustration_contract"]["layout"]["functional_ui_preserved"] = ["title"]
        with self.assertRaisesRegex(ARTWORK.ArtworkError, "functional error UI contract drift"):
            ARTWORK.validate(altered)

    def test_every_audited_upstream_mascot_surface_has_an_independent_asset(self) -> None:
        self.assertEqual(len(self.record["surface_replacements"]), 24)
        self.assertTrue(all("fox" not in item["replacement"] for item in self.record["surface_replacements"]))


if __name__ == "__main__":
    unittest.main()

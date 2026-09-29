from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_m10_05_asset_injection", ROOT / "tools" / "verify_m10_05_asset_injection.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class AssetInjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = json.loads((ROOT / "config" / "m10-05-asset-injection.json").read_text(encoding="utf-8"))
        self.identity = json.loads((ROOT / "config" / "product-identity.json").read_text(encoding="utf-8"))
        self.patch_text = (ROOT / "patches" / VERIFY.PATCH_NAME).read_text(encoding="utf-8")

    def test_approved_artwork_is_injected_for_the_public_release(self) -> None:
        VERIFY.validate(ROOT)

    def test_patch_applies_to_the_pinned_pristine_build_owner(self) -> None:
        VERIFY.check_patch_application(ROOT)

    def test_active_source_accepts_the_complete_injection_contract(self) -> None:
        texts = {
            relative: "\n".join(required)
            for relative, required in VERIFY.ACTIVE_SOURCE_REQUIREMENTS.items()
        }
        VERIFY.check_active_source(ROOT, texts=texts,
                                   asset_digests=VERIFY.expected_active_asset_digests(ROOT))

    def test_active_source_rejects_a_missing_branding_content_slot(self) -> None:
        texts = {
            relative: "\n".join(required)
            for relative, required in VERIFY.ACTIVE_SOURCE_REQUIREMENTS.items()
        }
        texts["browser/branding/goodbear/content/jar.mn"] = ""
        with self.assertRaisesRegex(VERIFY.AssetInjectionError, "active source is missing M10-05"):
            VERIFY.check_active_source(ROOT, texts=texts,
                                       asset_digests=VERIFY.expected_active_asset_digests(ROOT))

    def test_active_source_rejects_an_altered_injected_asset(self) -> None:
        texts = {
            relative: "\n".join(required)
            for relative, required in VERIFY.ACTIVE_SOURCE_REQUIREMENTS.items()
        }
        digests = VERIFY.expected_active_asset_digests(ROOT)
        digests["browser/components/aboutwelcome/assets/goodbear-success.png"] = "0" * 64
        with self.assertRaisesRegex(VERIFY.AssetInjectionError, "active injected asset differs"):
            VERIFY.check_active_source(ROOT, texts=texts, asset_digests=digests)

    def test_allows_later_milestone_patches_after_m10_05(self) -> None:
        VERIFY.validate_patch_order([
            "0016-good-bear-public-product-rebranding.patch",
            VERIFY.PATCH_NAME,
            "0018-good-bear-about-author-links.patch",
        ])

    def test_rejects_an_injection_patch_not_immediately_after_m10_04(self) -> None:
        with self.assertRaisesRegex(VERIFY.AssetInjectionError, "immediately follow M10-04"):
            VERIFY.validate_patch_order([
                "0016-good-bear-public-product-rebranding.patch",
                "0018-good-bear-about-author-links.patch",
                VERIFY.PATCH_NAME,
            ])

    def test_rejects_a_public_release_placeholder_exception(self) -> None:
        altered = copy.deepcopy(self.gate)
        altered["release_gate"]["public_release_placeholders_allowed"] = True
        with self.assertRaisesRegex(VERIFY.AssetInjectionError, "fail-closed"):
            VERIFY.validate(ROOT, gate=altered, identity=self.identity, patch_text=self.patch_text)

    def test_rejects_an_unapproved_mascot_asset_digest(self) -> None:
        altered = copy.deepcopy(self.gate)
        altered["injected_surface_assets"][
            "overlay/browser/components/aboutwelcome/assets/goodbear-success.png"
        ] = "0" * 64
        with self.assertRaisesRegex(VERIFY.AssetInjectionError, "differs from approved artwork"):
            VERIFY.validate(ROOT, gate=altered, identity=self.identity, patch_text=self.patch_text)

    def test_rejects_non_russian_public_packaging(self) -> None:
        altered = copy.deepcopy(self.identity)
        altered["release"]["shipped_locales"] = ["ru", "en-US"]
        with self.assertRaisesRegex(VERIFY.AssetInjectionError, "Russian resources only"):
            VERIFY.validate(ROOT, gate=self.gate, identity=altered, patch_text=self.patch_text)

    def test_rejects_a_missing_icon_size_in_the_build_patch(self) -> None:
        altered = self.patch_text.replace('+            "default64.png",\n', "")
        with self.assertRaisesRegex(VERIFY.AssetInjectionError, "every Ubuntu icon size"):
            VERIFY.validate(ROOT, gate=self.gate, identity=self.identity, patch_text=altered)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "verify_public_rebranding.py"
SPEC = importlib.util.spec_from_file_location("verify_public_rebranding", MODULE_PATH)
assert SPEC and SPEC.loader
REBRANDING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REBRANDING)


class PublicRebrandingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = REBRANDING.load_json(ROOT / "config" / "product-identity.json")
        self.patch_text = (ROOT / "patches" / REBRANDING.PATCH_NAME).read_text(
            encoding="utf-8"
        )

    def test_repository_public_identity_contract_is_complete(self) -> None:
        REBRANDING.validate(ROOT)

    def test_patch_applies_to_the_pinned_pristine_firefox_owner_files(self) -> None:
        REBRANDING.check_patch_application(ROOT)

    def test_active_source_contains_applied_public_rebranding(self) -> None:
        REBRANDING.check_active_source(ROOT)

    def test_active_source_rejects_restored_mozilla_distribution_identity(self) -> None:
        texts = REBRANDING.active_source_texts(ROOT)
        relative = "browser/installer/linux/app/debian/distribution.ini"
        texts[relative] = texts[relative].replace("id=goodbear-ubuntu", "id=mozilla-deb")
        with self.assertRaisesRegex(REBRANDING.RebrandingError, "prohibited public identity"):
            REBRANDING.check_active_source(ROOT, texts=texts)

    def test_package_executable_and_desktop_ids_are_independent(self) -> None:
        release = self.identity["release"]
        self.assertEqual(release["package_name"], "goodbear-browser")
        self.assertEqual(release["executable_name"], "goodbear")
        self.assertEqual(release["desktop_file_id"], "com.ledovskoy.goodbear.desktop")
        additions = REBRANDING.added_lines(self.patch_text)
        self.assertIn('pkg_name = f"goodbear-browser{package_name_suffix}"', additions)
        self.assertIn('public_executable_name = "goodbear"', additions)
        self.assertIn('desktop_file_id = "com.ledovskoy.goodbear.desktop"', additions)

    def test_rejects_a_firefox_public_executable_name(self) -> None:
        altered = copy.deepcopy(self.identity)
        altered["release"]["executable_name"] = "firefox"
        with self.assertRaisesRegex(REBRANDING.RebrandingError, "release.executable_name"):
            REBRANDING.validate(ROOT, identity=altered, patch_text=self.patch_text)

    def test_rejects_erased_upstream_attribution(self) -> None:
        altered = self.patch_text.replace(
            "+Good Bear is an independent browser based on Mozilla Firefox open-source code.\n",
            "",
        )
        with self.assertRaisesRegex(REBRANDING.RebrandingError, "missing additions"):
            REBRANDING.validate(ROOT, identity=self.identity, patch_text=altered)

    def test_rejects_mozilla_as_public_package_maintainer(self) -> None:
        altered = self.patch_text.replace(
            "+Maintainer: Good Bear Project <valery@ledovskoy.com>",
            "+Maintainer: Mozilla <release@mozilla.com>",
        )
        with self.assertRaisesRegex(REBRANDING.RebrandingError, "upstream product identity"):
            REBRANDING.validate(ROOT, identity=self.identity, patch_text=altered)

    def test_compatibility_identifiers_are_preserved(self) -> None:
        compatibility = self.identity["upstream_compatibility"]
        self.assertEqual(compatibility["application_id"]["disposition"], "preserve")
        self.assertEqual(compatibility["user_agent_product"], {
            "value": "Firefox",
            "disposition": "preserve",
            "reason": "Web compatibility requires the Firefox UA product token; it must not be reused as a Good Bear product label.",
        })


if __name__ == "__main__":
    unittest.main()

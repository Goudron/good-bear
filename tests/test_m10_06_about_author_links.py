from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_m10_06_about_author_links", ROOT / "tools" / "verify_m10_06_about_author_links.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class AboutAuthorLinksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.patch_text = (ROOT / "patches" / VERIFY.PATCH_NAME).read_text(encoding="utf-8")

    def test_about_author_link_contract(self) -> None:
        VERIFY.validate(ROOT)

    def test_patch_applies_to_the_pinned_about_owner(self) -> None:
        VERIFY.check_patch_application(ROOT)

    def test_rejects_an_inexact_author_target(self) -> None:
        altered = self.patch_text.replace("https://boosty.to/goodbear", "https://boosty.to/other")
        with self.assertRaisesRegex(VERIFY.AboutAuthorLinksError, "exact target"):
            VERIFY.validate(ROOT, patch_text=altered)

    def test_rejects_an_inexact_russian_label(self) -> None:
        branding = ROOT / "overlay" / "browser" / "branding" / "goodbear" / "locales" / "en-US" / "brand.ftl"
        original = branding.read_text(encoding="utf-8")
        altered = original.replace("Поддержать автора", "Поддержать Good Bear")
        with self.assertRaisesRegex(VERIFY.AboutAuthorLinksError, "exact prescribed Russian label"):
            VERIFY.validate(ROOT, ftl_text=altered)


if __name__ == "__main__":
    unittest.main()

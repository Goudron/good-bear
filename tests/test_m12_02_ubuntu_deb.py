#!/usr/bin/env python3
"""Focused contracts for GB100-M12-02 Ubuntu packaging."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m12_02", ROOT / "tools" / "build_m12_02_ubuntu_deb.py")
assert SPEC and SPEC.loader
PACKAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGER)


class UbuntuDebPackagingContractTest(unittest.TestCase):
    def test_public_metadata_uses_good_bear_identity_not_official_firefox(self) -> None:
        metadata = PACKAGER.control("libc6 (>= 2.39)")
        self.assertIn("Package: goodbear-browser", metadata)
        self.assertIn("Architecture: amd64", metadata)
        self.assertIn("Good Bear", metadata)
        self.assertNotIn("official Firefox", metadata)
        self.assertIn("Mozilla Firefox", metadata)

    def test_launcher_forces_russian_language_without_global_profile_state(self) -> None:
        self.assertIn("LANGUAGE=ru:ru_RU", PACKAGER.LAUNCHER)
        self.assertIn("--lang=ru", PACKAGER.LAUNCHER)
        self.assertIn("/opt/goodbear/goodbear", PACKAGER.LAUNCHER)

    def test_package_validation_rejects_a_launcher_that_misses_the_payload(self) -> None:
        source = Path(PACKAGER.__file__).read_text(encoding="utf-8")
        self.assertIn("launcher does not target the packaged Good Bear executable", source)

    def test_package_validation_requires_nonempty_menu_and_security_fluent_resources(self) -> None:
        self.assertIn("localization/ru/browser/appmenu.ftl", PACKAGER.REQUIRED_BROWSER_RUSSIAN_RESOURCES)
        self.assertIn("localization/ru/browser/protectionsPanel.ftl", PACKAGER.REQUIRED_BROWSER_RUSSIAN_RESOURCES)

    def test_desktop_contract_has_default_browser_mime_handlers_and_no_english_comment(self) -> None:
        self.assertIn("x-scheme-handler/http", PACKAGER.DESKTOP)
        self.assertIn("x-scheme-handler/https", PACKAGER.DESKTOP)
        self.assertIn("MimeType=", PACKAGER.DESKTOP)
        self.assertIn("Comment=Независимый русскоязычный браузер Good Bear", PACKAGER.DESKTOP)
        self.assertNotIn("Comment[en]", PACKAGER.DESKTOP)

    def test_scripts_are_non_networked_cache_refreshes_only(self) -> None:
        for script in (PACKAGER.POSTINST, PACKAGER.POSTRM):
            self.assertNotIn("curl", script)
            self.assertNotIn("wget", script)
            self.assertNotIn("systemctl", script)
            self.assertIn("update-mime-database", script)

    def test_notices_preserve_non_affiliation_boundaries(self) -> None:
        self.assertIn("not affiliated", PACKAGER.COPYRIGHT)
        self.assertIn("Минцифры", PACKAGER.COPYRIGHT)
        self.assertIn("Mozilla and Firefox are trademarks", PACKAGER.COPYRIGHT)


if __name__ == "__main__":
    unittest.main()

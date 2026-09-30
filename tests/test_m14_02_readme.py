#!/usr/bin/env python3
"""Focused contracts for the GB100-M14-02 Russian release README."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


class M1402ReadmeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = README.read_text(encoding="utf-8")

    def test_first_section_navigates_to_versioned_release_assets(self) -> None:
        first_section = self.text.split("## Что такое Good Bear", 1)[0]
        self.assertNotIn("<RELEASE_TAG>", first_section)
        self.assertEqual(first_section.count("/releases/download/v1.0.0/"), 7)
        self.assertIn("/blob/v1.0.0/SOURCE_OFFER.md", first_section)
        self.assertNotIn("/releases/download/latest/", first_section)
        for name in (
            "goodbear-browser_1.0%2Bfirefox156.0-1_amd64.deb",
            "GoodBear.Setup.1.0%2Bfirefox156.0.x64.ru.exe",
            "SHA256SUMS",
            "sbom.cdx.json",
            "provenance.intoto.json",
            "notices.json",
            "source-offer.json",
        ):
            self.assertIn(name, first_section)

    def test_required_hashes_and_release_identity_are_present(self) -> None:
        for value in (
            "a738b9b556c90da7a1ccb601cab5a5c2e6b6dbd050046a0dbcf7dba50c02d7d0",
            "d9f67c12680758f8d39143ef2acbd6a602b193d2d2418fa183c5c334107d77c2",
            "Good Bear 1.0 (Firefox 156.0)",
            "MPL 2.0",
            "https://boosty.to/goodbear",
            "https://github.com/Goudron/ru-spelling-dictionary",
            "RusSpell Lab",
            "Валерий Ледовской",
            "Андрей Ковалёв",
            "valery@ledovskoy.com",
            "[GB]",
        ):
            self.assertIn(value, self.text)

    def test_download_counts_are_not_telemetry_or_unique_users(self) -> None:
        self.assertRegex(self.text, r"агрегированн\w+ сч[её]тчик\w+ распространения")
        for forbidden_claim in ("уникальных пользователей", "телеметрией браузера"):
            self.assertIn(forbidden_claim, self.text)

    def test_unsigned_and_non_affiliation_boundaries_are_explicit(self) -> None:
        for value in (
            "unsigned",
            "не аффилирован",
            "не подменяет обычную",
            "не даёт дополнительных функций",
            "автоматическое обновление не заявляются",
        ):
            self.assertIn(value, self.text)
        self.assertNotRegex(self.text, r"(?i)сертифицирован|одобрено Mozilla|официальн\w+ продукт Mozilla")

    def test_contact_section_is_final_visible_section(self) -> None:
        self.assertTrue(self.text.rstrip().endswith("Принимаются только письма, в теме которых указан маркер **[GB]**."))


if __name__ == "__main__":
    unittest.main()

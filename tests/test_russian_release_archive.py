from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_russian_release_archive", ROOT / "tools" / "verify_russian_release_archive.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class RussianReleaseArchiveTest(unittest.TestCase):
    def test_rejects_missing_archive(self) -> None:
        with self.assertRaisesRegex(VERIFY.ArchiveError, "does not exist"):
            VERIFY.verify(ROOT / "artifacts" / "missing.tar.xz")

    def test_release_verifier_requires_ru_and_rejects_en_us(self) -> None:
        source = (ROOT / "tools" / "verify_russian_release_archive.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('multilocale != "ru\\n"', source)
        self.assertIn('"/localization/en-US/"', source)
        self.assertIn('"/localization/ru/"', source)
        self.assertIn("REQUIRED_BROWSER_RUSSIAN_RESOURCES", source)
        self.assertIn("required Russian Fluent resource is empty", source)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "m15_07_spellcheck_defaults", ROOT / "tools/verify_m15_07_spellcheck_defaults.py"
)
assert SPEC and SPEC.loader
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)


class SpellcheckDefaultsTest(unittest.TestCase):
    def test_repository_contract_is_complete(self) -> None:
        CONTRACT.verify(ROOT)

    def test_stale_firefox_source_is_rejected(self) -> None:
        version = ROOT / CONTRACT.FIREFOX_SOURCE_PATH / "browser/config/version.txt"
        read_text = Path.read_text

        def stale_version(path: Path, *args: object, **kwargs: object) -> str:
            if path == version:
                return "155.0.1\n"
            return read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", stale_version):
            with self.assertRaisesRegex(CONTRACT.ContractError, "source version differs"):
                CONTRACT.verify(ROOT)

    def test_ruspell_extension_id_mismatch_fails_closed(self) -> None:
        path = ROOT / CONTRACT.CONTRACT_PATH
        original = CONTRACT.load(path)
        original["languages"]["ru"]["extension_id"] = "different@example.invalid"
        real_load = CONTRACT.load

        def load_with_wrong_extension_id(candidate: Path) -> dict:
            if candidate == path:
                return original
            return real_load(candidate)

        with patch.object(CONTRACT, "load", side_effect=load_with_wrong_extension_id):
            with self.assertRaisesRegex(CONTRACT.ContractError, "exact fresh-profile set"):
                CONTRACT.verify(ROOT)

    def test_missing_or_locked_fresh_profile_default_fails_closed(self) -> None:
        profile = ROOT / CONTRACT.FIREFOX_PROFILE_PATH
        original_read_text = Path.read_text

        def read_without_default(path: Path, *args: object, **kwargs: object) -> str:
            value = original_read_text(path, *args, **kwargs)
            if path == profile:
                return value.replace('pref("layout.spellcheckDefault", 1);\n', "")
            return value

        with patch.object(Path, "read_text", read_without_default):
            with self.assertRaisesRegex(CONTRACT.ContractError, "enable spellcheck exactly once"):
                CONTRACT.verify(ROOT)

        def read_with_locked_language(path: Path, *args: object, **kwargs: object) -> str:
            value = original_read_text(path, *args, **kwargs)
            if path == profile:
                return value + '\nlockPref("layout.spellcheckDefault", 1);\n'
            return value

        with patch.object(Path, "read_text", read_with_locked_language):
            with self.assertRaisesRegex(CONTRACT.ContractError, "language selection"):
                CONTRACT.verify(ROOT)


if __name__ == "__main__":
    unittest.main()

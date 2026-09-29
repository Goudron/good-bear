#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m15_06_ruspell", ROOT / "tools" / "verify_m15_06_ruspell.py"
)
assert SPEC and SPEC.loader
RUSPELL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUSPELL)


class RusSpellPackagingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock_path = ROOT / "config/m15-06-ruspell-lock.json"
        self.lock = json.loads(self.lock_path.read_text(encoding="utf-8"))

    def verify_with_lock(self, lock: dict) -> None:
        original = Path.read_text

        def read_substituted(path: Path, *args: object, **kwargs: object) -> str:
            if path == RUSPELL.LOCK:
                return json.dumps(lock)
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", read_substituted):
            with self.assertRaises(AssertionError):
                RUSPELL.main()

    def test_pinned_ruspell_package_is_verified(self) -> None:
        RUSPELL.main()

    def test_missing_aff_unknown_release_and_competing_dictionary_fail_closed(self) -> None:
        missing_aff = copy.deepcopy(self.lock)
        del missing_aff["dictionary"]["files"]["dictionaries/ru.aff"]
        self.verify_with_lock(missing_aff)

        unknown_release = copy.deepcopy(self.lock)
        unknown_release["source"]["commit"] = "not-an-immutable-release"
        self.verify_with_lock(unknown_release)

        competing = copy.deepcopy(self.lock)
        competing["dictionary"]["files"]["dictionaries/ru-legacy.dic"] = "0" * 64
        self.verify_with_lock(competing)


if __name__ == "__main__":
    unittest.main()

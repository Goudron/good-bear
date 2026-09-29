#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import copy
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m15_04_contract", ROOT / "tools/verify_m15_04_firefox_155_contract.py"
)
assert SPEC and SPEC.loader
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)


class Firefox156MigrationContractTest(unittest.TestCase):
    def test_repository_contract_is_complete(self) -> None:
        CONTRACT.verify(ROOT)

    def test_missing_patch_disposition_fails_closed(self) -> None:
        path = ROOT / "config/m15-04-firefox-155-migration-contract.json"
        original = CONTRACT.load(path)
        original["patch_dispositions"].pop()
        real_load = CONTRACT.load

        def load_with_incomplete_contract(candidate: Path) -> dict:
            if candidate == path:
                return original
            return real_load(candidate)

        with patch.object(CONTRACT, "load", side_effect=load_with_incomplete_contract):
            with self.assertRaisesRegex(CONTRACT.ContractError, "every ordered"):
                CONTRACT.verify(ROOT)

    def test_stale_target_or_changed_historical_source_fails_closed(self) -> None:
        path = ROOT / "config/m15-04-firefox-155-migration-contract.json"
        original = CONTRACT.load(path)
        real_load = CONTRACT.load
        mutations = (
            ("from", "version", "155.0.1", "historical Firefox 154"),
            ("from", "revision", "0" * 40, "historical Firefox 154"),
            ("to", "version", "155.0.1", "must pin Firefox 156"),
            ("to", "revision", "fb95137a04eb8fe1196cb12f26b100c1e060295c", "revision differs"),
            ("to", "sha256", "0" * 64, "sha256 differs"),
            ("version_pair", "firefox", "155.0.1", "Firefox version pair"),
            ("migration_rules", "security_contracts", "reuse_previous_results", "fail closed"),
        )
        for section, key, value, message in mutations:
            with self.subTest(section=section, key=key):
                altered = copy.deepcopy(original)
                altered[section][key] = value
                with patch.object(CONTRACT, "load", side_effect=lambda candidate:
                                  altered if candidate == path else real_load(candidate)):
                    with self.assertRaisesRegex(CONTRACT.ContractError, message):
                        CONTRACT.verify(ROOT)

    def test_matching_missing_source_hashes_do_not_count_as_provenance(self) -> None:
        contract_path = ROOT / "config/m15-04-firefox-155-migration-contract.json"
        baseline_path = ROOT / "config/firefox-baseline.json"
        real_load = CONTRACT.load
        altered = {path: real_load(path) for path in (contract_path, baseline_path)}
        del altered[contract_path]["to"]["sha256"]
        del altered[baseline_path]["source"]["sha256"]
        with patch.object(CONTRACT, "load", side_effect=lambda candidate:
                          altered[candidate] if candidate in altered else real_load(candidate)):
            with self.assertRaisesRegex(CONTRACT.ContractError, "sha256 is missing"):
                CONTRACT.verify(ROOT)


if __name__ == "__main__":
    unittest.main()

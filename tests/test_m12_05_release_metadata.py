#!/usr/bin/env python3
"""Focused contracts for the fail-closed GB100-M12-05 metadata assembly."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m12_05", ROOT / "tools" / "assemble_m12_05_release_metadata.py")
assert SPEC and SPEC.loader
M12_05 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M12_05
SPEC.loader.exec_module(M12_05)


class ReleaseMetadataContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = M12_05.load_contract()

    def test_rejects_removed_historical_ubuntu_candidate_before_rewriting_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "release-metadata"
            with self.assertRaisesRegex(M12_05.ReleaseMetadataError, "artifact is missing"):
                M12_05.assemble(ROOT, M12_05.DEFAULT_CONTRACT, destination)
            self.assertFalse(destination.exists())

    def test_rejects_signing_authority_drift(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["ubuntu"]["signing"]["approved_authority"] = "invented local key"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(M12_05.ReleaseMetadataError, "fail closed"):
                M12_05.load_contract(path)

    def test_source_offer_excludes_full_firefox_mirror_and_preserves_mpl_boundary(self) -> None:
        source = M12_05.source_inventory(ROOT, self.contract)
        offer = M12_05.source_offer(self.contract, source)
        self.assertTrue(offer["terms_must_not_restrict_mpl_source_code_form"])
        self.assertEqual(offer["full_firefox_source_mirror"], "forbidden")
        self.assertEqual(offer["good_bear_revision"]["status"], "recorded")


if __name__ == "__main__":
    unittest.main()

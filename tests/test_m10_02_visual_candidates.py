#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0
# Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "verify_m10_02_visual_candidates.py"
SPEC = importlib.util.spec_from_file_location("m10_02_candidates", MODULE_PATH)
assert SPEC and SPEC.loader
CANDIDATES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANDIDATES)


class M1002VisualCandidateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.record = json.loads(
            (ROOT / "config" / "m10-02-visual-candidates.json").read_text(encoding="utf-8")
        )

    def test_exactly_three_original_preview_candidates_are_complete_and_intact(self) -> None:
        CANDIDATES.validate(self.record)
        self.assertEqual(len(self.record["candidates"]), 3)
        for candidate in self.record["candidates"]:
            self.assertEqual(candidate["artifact_status"], "preview_only")
            self.assertEqual(candidate["dimensions_px"], [1254, 1254])

    def test_no_photo_or_unrecorded_reference_input_is_allowed(self) -> None:
        generation = self.record["generation"]
        self.assertEqual(generation["input_images"], [])
        self.assertEqual(generation["public_photograph_references"], [])
        self.assertFalse(generation["exact_confirmed_valery_reference_images"])

    def test_selected_direction_stays_preview_only_and_release_blocked(self) -> None:
        gate = self.record["selection_gate"]
        self.assertEqual(gate["selected_candidate_id"], "workshop-beacon")
        self.assertTrue(gate["selection_recorded"])
        self.assertIn("Valery Ledovskoy", gate["maintainer_selection"])
        self.assertIn("circular enclosing device", gate["required_m10_03_refinement"])
        with self.assertRaisesRegex(CANDIDATES.CandidateError, "release blocked"):
            CANDIDATES.validate(self.record, release=True)
        altered = copy.deepcopy(self.record)
        altered["selection_gate"]["selected_candidate_id"] = "editorial-guide"
        with self.assertRaisesRegex(CANDIDATES.CandidateError, "Workshop Beacon selection"):
            CANDIDATES.validate(altered)


if __name__ == "__main__":
    unittest.main()

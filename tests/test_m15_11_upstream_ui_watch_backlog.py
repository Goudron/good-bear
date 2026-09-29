#!/usr/bin/env python3
"""Focused planning contract for the deferred GB100-M15-11 UI rebase gate."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BACKLOG = ROOT / "backlogs" / "good_bear_1_0_russian_pki_container_backlog_2026-08-22.md"


def m15_11_row() -> str:
    for line in BACKLOG.read_text(encoding="utf-8").splitlines():
        if line.startswith("| `GB100-M15-11` "):
            return line
    raise AssertionError("GB100-M15-11 backlog row is missing")


class UpstreamUiWatchBacklogContractTest(unittest.TestCase):
    def test_exact_upstream_provenance_and_owner_diffs_are_required(self) -> None:
        row = m15_11_row()
        for requirement in (
            "Firefox 155 -> 156 -> 157",
            "exact Firefox 155/156/157 source revision",
            "signature/hash",
            "Mozilla release/security provenance",
            "browser UI, Good Bear branding, Fluent/l10n, and security UI",
            "owner-attributed diff disposition",
            "Project Nova",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, row)

    def test_russian_fluent_and_visual_regressions_cover_good_bear_surfaces(self) -> None:
        row = m15_11_row()
        for requirement in (
            "Fluent message IDs, attributes, selectors, access keys, Russian translations, and fallback exposure",
            "visual screenshot/regression checks",
            "container marker, Russian PKI trust indicator, security popup, trust-change/body interstitials, settings, assignment management, About, updater/error UX",
            "locale `ru`",
            "accessibility states",
            "unexplained visual or string drift fails closed",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, row)

    def test_unattended_ui_promotion_is_forbidden_and_manual_evidence_is_mandatory(self) -> None:
        row = m15_11_row()
        self.assertIn("No upstream UI patch, Project Nova adaptation, generated screenshot-baseline update, or localization change is promoted unattended", row)
        self.assertIn("named maintainer records manual Russian UI verification", row)
        self.assertIn("exact candidate/build hashes, browser/platform matrix, observed evidence references, and an explicit promotion decision", row)
        self.assertIn("Missing, ambiguous, or unverified evidence blocks the rebase and M13/M14 promotion", row)


if __name__ == "__main__":
    unittest.main()

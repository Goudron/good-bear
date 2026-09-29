#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ui_watch_fixture import reviewed_fixture, write_record


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_m15_11", ROOT / "tools" / "verify_m15_11_upstream_ui_watch.py")
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)


class UpstreamUiWatchTest(unittest.TestCase):
    def mutation_error(self, mutate) -> str:
        contract = json.loads(VERIFY.CONTRACT.read_text(encoding="utf-8"))
        mutate(contract)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            path = Path(directory) / "watch.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaises(VERIFY.WatchError) as raised:
                VERIFY.verify(contract_path=path)
        return str(raised.exception)

    def test_current_pending_watch_passes(self) -> None:
        VERIFY.verify()

    def test_pending_transition_cannot_promote(self) -> None:
        def mutate(contract: dict) -> None:
            contract["transitions"][0]["promotion_allowed"] = True
        self.assertIn("may not promote", self.mutation_error(mutate))

    def test_project_nova_owner_cannot_disappear(self) -> None:
        def mutate(contract: dict) -> None:
            contract["owner_scopes"].remove("project_nova_or_equivalent_ui_architecture")
        self.assertIn("owner inventory", self.mutation_error(mutate))

    def test_russian_visual_matrix_cannot_fall_back_to_english(self) -> None:
        def mutate(contract: dict) -> None:
            contract["visual_matrix"]["locale"] = "en-US"
        self.assertIn("Russian UI", self.mutation_error(mutate))

    def test_exact_156_pin_cannot_be_replaced_or_dropped(self) -> None:
        def mutate(contract: dict) -> None:
            contract["transitions"][0]["target_pin"]["sha256"] = "0" * 64
        self.assertIn("target pin differs", self.mutation_error(mutate))
        self.assertIn("pinned review transition", self.mutation_error(
            lambda contract: contract["transitions"][0].__setitem__(
                "status", "pending_exact_upstream_release")))

    def test_source_check_cannot_claim_visual_acceptance(self) -> None:
        def mutate(contract: dict) -> None:
            contract["transitions"][0]["ru_shield_source_audit"]["visual_parity_proven"] = True
        self.assertIn("cannot claim rendered visual parity", self.mutation_error(mutate))

    def test_badge_changes_invalidate_recorded_source_audit(self) -> None:
        def mutate(contract: dict) -> None:
            contract["transitions"][0]["ru_shield_source_audit"]["badge_patch_sha256"] = "0" * 64
        self.assertIn("badge patch changed", self.mutation_error(mutate))

    def test_warning_and_keyboard_matrix_cannot_be_dropped(self) -> None:
        self.assertIn("shield state matrix", self.mutation_error(
            lambda contract: contract["visual_matrix"]["trust_panel_states"].remove("warning")))
        self.assertIn("accessibility matrix", self.mutation_error(
            lambda contract: contract["visual_matrix"]["accessibility_states"].remove("keyboard_focus")))

    def test_pending_review_cannot_have_a_manual_promotion(self) -> None:
        self.assertIn("cannot record promotion", self.mutation_error(
            lambda contract: contract["transitions"][0].__setitem__(
                "manual_promotion", {"decision": "promote"})))

    def test_reviewed_evidence_requires_existing_successful_bound_artifacts(self) -> None:
        contract = VERIFY.load(VERIFY.CONTRACT)
        with reviewed_fixture(ROOT, contract) as (watch, report), patch.object(
            VERIFY, "current_fluent_audit", return_value=report,
        ):
            transition = watch["transitions"][0]
            VERIFY.verify_reviewed_evidence(ROOT, watch, transition)
            for field, value, expected in (
                ("fluent_audit", {"arbitrary": True}, "project artifact"),
                ("visual_evidence", [], "every platform"),
                ("manual_promotion", {}, "named maintainer"),
            ):
                changed = copy.deepcopy(transition)
                changed[field] = value
                with self.subTest(field=field), self.assertRaisesRegex(VERIFY.WatchError, expected):
                    VERIFY.verify_reviewed_evidence(ROOT, watch, changed)
            transition["manual_promotion"]["candidate_hash"] = {"other": "0" * 64}
            with self.assertRaisesRegex(VERIFY.WatchError, "not bound"):
                VERIFY.verify_reviewed_evidence(ROOT, watch, transition)

    def test_source_only_or_stale_fluent_cannot_be_declared_passed(self) -> None:
        with reviewed_fixture(ROOT, VERIFY.load(VERIFY.CONTRACT)) as (watch, report):
            for actual, expected in (
                (report | {"status": "blocked", "binding_findings": [{"id": "missing"}]}, "unresolved findings"),
                (report | {"source_manifest_sha256": "c" * 64}, "canonical source"),
            ):
                with self.subTest(expected=expected), patch.object(
                    VERIFY, "current_fluent_audit", return_value=actual,
                ), self.assertRaisesRegex(VERIFY.WatchError, expected):
                    VERIFY.verify_reviewed_evidence(ROOT, watch, watch["transitions"][0])

    def test_runtime_baseline_errors_and_missing_matrix_cells_fail_even_with_new_hash(self) -> None:
        with reviewed_fixture(ROOT, VERIFY.load(VERIFY.CONTRACT)) as (watch, report), patch.object(
            VERIFY, "current_fluent_audit", return_value=report,
        ):
            transition = watch["transitions"][0]
            entry = transition["visual_evidence"][0]
            path = ROOT / entry["runtime_report"]["path"]
            runtime = VERIFY.load(path)
            for changed, expected in (
                (runtime | {"firefox_baseline": {"version": "155.0.1"}}, "different baseline"),
                (runtime | {"errors": ["failed keyboard focus"]}, "incomplete"),
                (runtime | {"captures": runtime["captures"][1:]}, "coverage is incomplete"),
            ):
                entry["runtime_report"] = write_record(ROOT, path, changed)
                with self.subTest(expected=expected), self.assertRaisesRegex(VERIFY.WatchError, expected):
                    VERIFY.verify_reviewed_evidence(ROOT, watch, transition)

    def test_artifact_hash_escape_and_truncated_png_are_rejected(self) -> None:
        with reviewed_fixture(ROOT, VERIFY.load(VERIFY.CONTRACT)) as (watch, report), patch.object(
            VERIFY, "current_fluent_audit", return_value=report,
        ):
            transition = watch["transitions"][0]
            entry = transition["visual_evidence"][0]
            original = entry["candidate"]
            for record, expected in ((original | {"sha256": "0" * 64}, "hash mismatch"),
                                     (original | {"path": "artifacts/../../outside"}, "missing or escapes")):
                entry["candidate"] = record
                with self.subTest(expected=expected), self.assertRaisesRegex(VERIFY.WatchError, expected):
                    VERIFY.verify_reviewed_evidence(ROOT, watch, transition)
            entry["candidate"] = original
            runtime_path = ROOT / entry["runtime_report"]["path"]
            runtime = VERIFY.load(runtime_path)
            image = runtime["captures"][0]["png"]
            image_path = ROOT / image["path"]
            runtime["captures"][0]["png"] = write_record(ROOT, image_path, image_path.read_bytes()[:24])
            entry["runtime_report"] = write_record(ROOT, runtime_path, runtime)
            with self.assertRaisesRegex(VERIFY.WatchError, "truncated or corrupt"):
                VERIFY.verify_reviewed_evidence(ROOT, watch, transition)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Narrow fail-closed tests; synthetic reports are not runtime acceptance evidence."""

from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ui_watch_fixture import reviewed_fixture


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_m15_10_release_gate as GATE


def write_json(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class M15ReleaseGateTests(unittest.TestCase):
    def test_unreviewed_security_suppliers_block_release_without_disabling_protection(self) -> None:
        problems = GATE.hosted_service_release_blockers()
        self.assertIn("M15-12 security supplier review remains pending: safe_browsing", problems)
        self.assertIn("M15-12 security supplier review remains pending: remote_settings_security_collections", problems)

    def test_supplier_review_cannot_be_claimed_by_changing_one_status(self) -> None:
        actual_load = GATE.hosted_service_boundary.load
        contract_path = ROOT / "config/m15-12-hosted-service-boundary.json"

        def fake_approval(path: Path) -> dict:
            data = copy.deepcopy(actual_load(path))
            if path == contract_path:
                for service in data["security_services"]:
                    if service["id"] == "safe_browsing":
                        service["supplier_status"] = "approved"
            return data

        with patch.object(GATE.hosted_service_boundary, "load", side_effect=fake_approval):
            problems = GATE.hosted_service_release_blockers()
        self.assertTrue(any("M15-12 hosted-service boundary blocks release" in item for item in problems))

    def approved_ui_watch_fixture(self) -> dict:
        """Synthetic verifier input only; never written as release evidence."""
        watch = GATE.upstream_ui_watch.load(ROOT / "config/m15-11-upstream-ui-watch.json")
        current = watch["transitions"][0]
        current.update({
            "status": "reviewed",
            "promotion_allowed": True,
            "fluent_audit": {"synthetic_test": True},
            "visual_evidence": [{"synthetic_test": True}],
            "manual_promotion": {
                "maintainer": "synthetic-unit-test-reviewer",
                "candidate_hash": "a" * 64,
                "build_hash": "b" * 64,
                "observed_evidence": "synthetic-unit-test-only",
                "decision": "promote",
            },
        })
        current["ru_shield_source_audit"].update({
            "status": "source_and_visual_reviewed", "visual_parity_proven": True,
        })
        return watch

    def ui_watch_blockers(self, watch: dict | Exception) -> list[str]:
        actual_load = GATE.upstream_ui_watch.load
        contract_path = ROOT / "config/m15-11-upstream-ui-watch.json"

        def load_ui_fixture(path: Path) -> dict:
            if path == contract_path:
                if isinstance(watch, Exception):
                    raise watch
                return copy.deepcopy(watch)
            return actual_load(path)

        with self.synthetic_materialization(), patch.object(
            GATE.upstream_ui_watch, "load", side_effect=load_ui_fixture,
        ):
            return [message for message in GATE.blockers()
                    if message.startswith("M15-11 upstream UI watch")]

    @contextmanager
    def synthetic_materialization(self, marker_overrides: dict | None = None,
                                  matrix_overrides: dict | None = None):
        """Exercise source binding without claiming a real Firefox 156 materialization."""
        actual_read = GATE.read_json
        baseline = actual_read(ROOT / "config/firefox-baseline.json")
        matrix_path = ROOT / "config/m15-10-verification-matrix.json"
        matrix = actual_read(matrix_path)
        marker_path = ROOT / matrix["materialization_marker"]
        series = [line.strip() for line in (ROOT / "patches/series").read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
        marker = {
            "version": baseline["version"],
            "source_sha256": baseline["source"]["sha256"],
            "source_sha512": baseline["source"]["sha512"],
            "baseline_config_sha256": GATE.sha256_file(ROOT / "config/firefox-baseline.json"),
            "patches": [{"path": name, "sha256": GATE.sha256_file(ROOT / "patches" / name)}
                        for name in series],
        }
        marker.update(marker_overrides or {})
        matrix.update(matrix_overrides or {})

        def synthetic_read(path: Path) -> dict:
            if path == marker_path:
                return marker
            if path == matrix_path:
                return matrix
            return actual_read(path)

        with patch.object(GATE, "read_json", side_effect=synthetic_read):
            yield

    def test_matrix_targets_firefox_156_but_synthetic_materialization_cannot_release(self) -> None:
        with self.synthetic_materialization():
            self.assertEqual(GATE.matrix_contract()["firefox_version"], "156.0")
            problems = GATE.blockers()
        self.assertNotIn("decision coverage contract is not rebased to Firefox 156", problems)
        self.assertTrue(any("decision_branches_156" in message for message in problems))
        self.assertFalse(any("Windows transport does not declare" in message for message in problems))
        self.assertTrue(any("windows_unsigned_distribution" in message for message in problems))
        self.assertTrue(any("ubuntu_unsigned_distribution" in message for message in problems))
        self.assertTrue(any("ubuntu_package_ownership" in message for message in problems))
        self.assertTrue(any("spellcheck_ui_ru_en" in message for message in problems))
        self.assertTrue(any("profile_migration_154_to_156" in message for message in problems))
        self.assertTrue(any("M15-11 upstream UI watch blocks release" in message and
                            "manual promotion remain pending" in message for message in problems))

    def test_existing_verified_manual_ui_approval_removes_only_the_ui_blocker(self) -> None:
        contract = GATE.upstream_ui_watch.load(ROOT / "config/m15-11-upstream-ui-watch.json")
        with reviewed_fixture(ROOT, contract) as (watch, report), patch.object(
            GATE.upstream_ui_watch, "current_fluent_audit", return_value=report,
        ):
            self.assertEqual(self.ui_watch_blockers(watch), [])

    def test_arbitrary_fluent_visual_and_manual_dicts_are_not_approval(self) -> None:
        self.assertIn("project artifact", self.ui_watch_blockers(self.approved_ui_watch_fixture())[0])

    def test_source_only_ui_watch_cannot_promote_by_changing_one_flag(self) -> None:
        watch = GATE.upstream_ui_watch.load(ROOT / "config/m15-11-upstream-ui-watch.json")
        watch["transitions"][0]["promotion_allowed"] = True
        self.assertIn("may not promote while pending review", self.ui_watch_blockers(watch)[0])

    def test_ui_approval_requires_existing_pin_audit_and_manual_conditions(self) -> None:
        mutations = (
            (lambda item: item["target_pin"].__setitem__("sha256", "0" * 64), "target pin differs"),
            (lambda item: item["ru_shield_source_audit"].__setitem__("badge_patch_sha256", "0" * 64),
             "badge patch changed"),
        )
        for mutate, expected in mutations:
            watch = self.approved_ui_watch_fixture()
            mutate(watch["transitions"][0])
            with self.subTest(expected=expected):
                self.assertIn(expected, self.ui_watch_blockers(watch)[0])

    def test_missing_or_malformed_ui_watch_is_an_explicit_release_blocker(self) -> None:
        for fixture in (
            FileNotFoundError("missing M15-11 watch contract"),
            {"schema_version": 1, "task": "GB100-M15-11", "current_baseline": None},
        ):
            with self.subTest(fixture=fixture):
                problems = self.ui_watch_blockers(fixture)
                self.assertEqual(len(problems), 1)
                self.assertIn("M15-11 upstream UI watch blocks release", problems[0])

    def test_old_or_tampered_materialization_is_rejected(self) -> None:
        for field, value, message in (
            ("version", "155.0.1", "differs from baseline"),
            ("source_sha256", "0" * 64, "differs from baseline"),
            ("source_sha512", "0" * 128, "differs from baseline"),
            ("baseline_config_sha256", "0" * 64, "differs from baseline"),
            ("patches", [], "ordered patch inputs"),
        ):
            with self.subTest(field=field), self.synthetic_materialization({field: value}):
                with self.assertRaisesRegex(GATE.GateError, message):
                    GATE.matrix_contract()

    def test_old_runtime_ids_and_changed_prior_profile_are_rejected(self) -> None:
        matrix = GATE.read_json(ROOT / "config/m15-10-verification-matrix.json")
        runtime = copy.deepcopy(matrix["runtime_evidence"])
        runtime["targeted_tests_155"] = runtime.pop("targeted_tests_156")
        for change, message in (
            ({"runtime_evidence": runtime}, "runtime evidence matrix"),
            ({"prior_profile_version": "155.0.1"}, "migration/version pair"),
            ({"materialization_marker": "source/worktrees/firefox-155.0.1/.good-bear-materialization.json"},
             "source and coverage bindings"),
        ):
            with self.subTest(change=change), self.synthetic_materialization(matrix_overrides=change):
                with self.assertRaisesRegex(GATE.GateError, message):
                    GATE.matrix_contract()

    def test_nonapproved_windows_workspace_is_a_release_blocker(self) -> None:
        actual = GATE.load_contract

        def stale_contract(path: Path) -> dict:
            contract = copy.deepcopy(actual(path))
            contract["remote_workspaces"]["windows-x64"]["kind"] = (
                "disposable Windows Server 2025 workspace"
            )
            return contract

        with self.synthetic_materialization(), patch.object(GATE, "load_contract", side_effect=stale_contract):
            self.assertIn(
                "M15-01 Windows transport does not declare the approved Server 2022 workspace",
                GATE.blockers(),
            )

    def report_fixture(self, directory: Path,
                       item_id: str = "spellcheck_ui_ru_en") -> tuple[Path, dict, dict]:
        log_path = directory / "logs" / "spell.log"
        log_path.parent.mkdir(parents=True)
        log_path.write_text("synthetic test run\n", encoding="utf-8")
        report = {
            "task": "GB100-M15-10", "id": item_id, "status": "passed",
            "source_manifest_sha256": "a" * 64,
            "version_pair": {"good_bear": "1.0", "firefox": "156.0"},
            "platform": "ubuntu-amd64", "artifact_sha256": "b" * 64,
            "runner": "synthetic-test", "executed_at": "2026-09-15T00:00:00Z",
            "command": ["synthetic-spellcheck-test"],
            "checks": {name: True for name in GATE.REQUIRED_RUNTIME[item_id]},
            "log": {"path": "logs/spell.log", "sha256": GATE.sha256_file(log_path)},
        }
        report_path = directory / "reports" / "spell.json"
        digest = write_json(report_path, report)
        index = {"runtime": {item_id: {
            "report": "reports/spell.json", "sha256": digest}}}
        write_json(directory / "evidence.json", index)
        return directory, report, index

    def verify_spell(self, directory: Path) -> None:
        GATE.verify_report(ROOT, directory, "spellcheck_ui_ru_en",
                           GATE.REQUIRED_RUNTIME["spellcheck_ui_ru_en"], "a" * 64,
                           {"ubuntu-amd64": "b" * 64}, set())

    def test_hashed_report_requires_all_positive_and_negative_ui_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory, report, index = self.report_fixture(Path(temporary))
            self.verify_spell(directory)
            report["checks"]["ru_misspelling_marked"] = False
            index["runtime"]["spellcheck_ui_ru_en"]["sha256"] = write_json(
                directory / "reports/spell.json", report)
            write_json(directory / "evidence.json", index)
            with self.assertRaisesRegex(GATE.GateError, "incomplete checks"):
                self.verify_spell(directory)

    def test_hash_valid_old_version_report_cannot_be_reused_for_firefox_156(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory, report, index = self.report_fixture(Path(temporary))
            report["version_pair"]["firefox"] = "155.0.1"
            index["runtime"]["spellcheck_ui_ru_en"]["sha256"] = write_json(
                directory / "reports/spell.json", report)
            write_json(directory / "evidence.json", index)
            with self.assertRaisesRegex(GATE.GateError, "wrong identity/status/source manifest"):
                self.verify_spell(directory)

    def test_profile_migration_requires_the_historical_154_candidate(self) -> None:
        item_id = "profile_migration_154_to_156"
        with tempfile.TemporaryDirectory() as temporary:
            directory, report, index = self.report_fixture(Path(temporary), item_id)
            report["prior_candidate_sha256"] = "c" * 64
            for version in ("154.0", "155.0.1", None):
                report["prior_profile_version"] = version
                index["runtime"][item_id]["sha256"] = write_json(directory / "reports/spell.json", report)
                write_json(directory / "evidence.json", index)
                args = (ROOT, directory, item_id, GATE.REQUIRED_RUNTIME[item_id],
                        "a" * 64, {"ubuntu-amd64": "b" * 64}, set())
                with self.subTest(version=version):
                    if version == "154.0":
                        GATE.verify_report(*args)
                    else:
                        with self.assertRaisesRegex(GATE.GateError, "real Firefox-154-derived candidate"):
                            GATE.verify_report(*args)

    def test_tampered_report_log_or_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory, report, index = self.report_fixture(Path(temporary))
            (directory / "reports/spell.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(GATE.GateError, "report hash mismatch"):
                self.verify_spell(directory)
            write_json(directory / "reports/spell.json", report)
            (directory / "logs/spell.log").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(GATE.GateError, "run log hash mismatch"):
                self.verify_spell(directory)
            index = copy.deepcopy(index)
            index["runtime"]["spellcheck_ui_ru_en"]["report"] = "../outside.json"
            write_json(directory / "evidence.json", index)
            with self.assertRaisesRegex(GATE.GateError, "unsafe evidence path"):
                self.verify_spell(directory)

    def test_missing_remote_result_cannot_be_promoted_by_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory, _, _ = self.report_fixture(Path(temporary))
            with self.synthetic_materialization():
                with self.assertRaisesRegex((GATE.GateError, RuntimeError), "cannot read|не удалось"):
                    GATE.verify_remote(ROOT, directory)


if __name__ == "__main__":
    unittest.main()

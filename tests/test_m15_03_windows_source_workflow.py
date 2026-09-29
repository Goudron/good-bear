#!/usr/bin/env python3
"""Exercise the actual embedded Windows source gate without a remote runner."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/m15-03-windows-encrypted-source-materialize.yml"
SPEC = importlib.util.spec_from_file_location(
    "m15_03_workflow_materializer", ROOT / "tools/materialize_firefox_source.py"
)
assert SPEC and SPEC.loader
MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)


def workflow_gate():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(r"          \$materializationGate = @'\n(.*?)\n          '@", workflow, re.S)
    if match is None:
        raise AssertionError("Windows workflow embedded materialization gate is absent")
    namespace = {"__name__": "windows_source_workflow_gate"}
    exec(compile(textwrap.dedent(match[1]), str(WORKFLOW), "exec"), namespace)
    expected = {}
    for name in ("VERSION", "REVISION", "SHA256"):
        value = re.search(rf"^      GOODBEAR_EXPECTED_FIREFOX_{name}: ([^\n]+)$", workflow, re.M)
        if value is None:
            raise AssertionError(f"Missing workflow Firefox {name} pin")
        expected[name] = value[1].strip("'")
    return namespace["checked_materialization"], expected


class WindowsSourceWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.baseline_path = self.root / "config/firefox-baseline.json"
        self.baseline_path.parent.mkdir()
        self.baseline = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
        self.baseline_path.write_text(json.dumps(self.baseline), encoding="utf-8")
        (self.root / "patches").mkdir()
        (self.root / "patches/series").write_text("", encoding="utf-8")
        self.gate, self.expected = workflow_gate()
        _, archive, _ = MATERIALIZER.baseline_values(self.baseline, self.baseline_path)
        self.worktree = archive.parent / "worktrees" / MATERIALIZER.archive_root_name(self.baseline["version"])

    def materialized(self, marker_change=None, actual_version=None, baseline_change=None):
        def result(config, archive, verifier, *, baseline_offline):
            self.assertEqual(config, self.baseline_path)
            self.assertTrue(baseline_offline)
            version_file = self.worktree / "browser/config/version.txt"
            version_file.parent.mkdir(parents=True, exist_ok=True)
            version_file.write_text(actual_version or self.baseline["version"], encoding="utf-8")
            marker = {
                "baseline_config_sha256": MATERIALIZER.hash_file(self.baseline_path, "sha256"),
                "version": self.baseline["version"],
                "source_sha256": self.baseline["source"]["sha256"],
                "source_sha512": self.baseline["source"]["sha512"],
                "patches": [],
                "overlay_files": [],
            }
            if marker_change:
                marker_change(marker)
            (self.worktree / ".good-bear-materialization.json").write_text(json.dumps(marker), encoding="utf-8")
            if baseline_change:
                self.baseline_path.write_text(json.dumps(baseline_change), encoding="utf-8")
            return self.worktree
        return result

    def run_gate(self):
        return self.gate(self.root, self.expected["VERSION"], self.expected["REVISION"],
                         self.expected["SHA256"], MATERIALIZER)

    def test_current_baseline_and_materialized_marker_are_accepted(self) -> None:
        with patch.object(MATERIALIZER, "materialize", side_effect=self.materialized()) as invoked:
            evidence = self.run_gate()
        invoked.assert_called_once()
        self.assertEqual(evidence["version"], "156.0")
        self.assertEqual(evidence["revision"], self.baseline["vcs"]["revision"])
        self.assertEqual(evidence["baseline_config_sha256"], MATERIALIZER.hash_file(self.baseline_path, "sha256"))
        self.assertEqual(len(evidence["materialization_marker_sha256"]), 64)

    def test_all_materialization_python_invocations_isolate_startup(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        commands = [line.strip() for line in workflow.splitlines() if line.strip().startswith("& $env:GOODBEAR_PYTHON")]
        self.assertEqual(len(commands), 3)
        for command in commands:
            self.assertIn(" -I -S -B -u -X ('pycache_prefix=' + $pythonCache) -c ", command)
        self.assertEqual(sum("-c $trustedWrapper $verifier" in command for command in commands), 2)
        self.assertEqual(sum("-c $materializationGate" in command for command in commands), 1)

    def test_actual_workflow_bootstrap_loads_dynamic_m3_without_source_bytecode(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        match = re.search(r"          \$trustedWrapper = @'\n(.*?)\n          '@", workflow, re.S)
        self.assertIsNotNone(match)
        bootstrap = textwrap.dedent(match[1])
        tools = self.root / "tools"
        tools.mkdir()
        (tools / "project_temp.py").write_text("VALUE = 'checked-local-import'\n")
        (tools / "verify_m3_04_certificate_supply_chain.py").write_text(
            "from project_temp import VALUE\n"
            "def run(path):\n    assert VALUE == 'checked-local-import'\n"
        )
        # Execute the production transport loader under the workflow's actual
        # bootstrap, with a tiny M3 fixture. No real PKI staging or native claim.
        (tools / "m15_remote_transport.py").write_bytes((ROOT / "tools/m15_remote_transport.py").read_bytes())
        entry = tools / "entry.py"
        entry.write_text(
            "from pathlib import Path\nimport sys\nimport m15_remote_transport as transport\n"
            "assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode\n"
            "transport.verify_m3_build_inputs(Path(__file__).parent.parent, Path('fixture'))\n"
            "print('DYNAMIC_M3_ISOLATED')\n"
        )
        cache = self.root / "fresh-cache"
        cache.mkdir()
        environment = {**os.environ, "PYTHONHOME": str(self.root / "untrusted-home"), "PYTHONPATH": str(tools)}
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-u", "-X", f"pycache_prefix={cache}",
             "-c", bootstrap, str(entry)], env=environment, capture_output=True, text=True, check=True)
        self.assertEqual(completed.stdout.strip(), "DYNAMIC_M3_ISOLATED")
        self.assertFalse((tools / "__pycache__").exists())
        self.assertEqual(list(cache.iterdir()), [])

    def test_previous_encrypted_payload_is_rejected_before_materialization(self) -> None:
        self.baseline["version"] = "155.0.1"
        self.baseline["source"]["archive_path"] = "source/firefox-155.0.1.source.tar.xz"
        self.baseline_path.write_text(json.dumps(self.baseline), encoding="utf-8")
        with patch.object(MATERIALIZER, "materialize") as invoked:
            with self.assertRaisesRegex(ValueError, "not the approved Firefox 156.0"):
                self.run_gate()
        invoked.assert_not_called()

    def test_wrong_revision_or_archive_pin_is_rejected_before_materialization(self) -> None:
        for block, field, value, message in (
            ("vcs", "revision", "0" * 40, "source revision differs"),
            ("source", "sha256", "0" * 64, "source archive pin differs"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.baseline)
                changed[block][field] = value
                self.baseline_path.write_text(json.dumps(changed), encoding="utf-8")
                with patch.object(MATERIALIZER, "materialize") as invoked:
                    with self.assertRaisesRegex(ValueError, message):
                        self.run_gate()
                invoked.assert_not_called()

    def test_baseline_archive_cannot_escape_the_project(self) -> None:
        self.baseline["source"]["archive_path"] = "../untrusted.tar.xz"
        self.baseline_path.write_text(json.dumps(self.baseline), encoding="utf-8")
        with patch.object(MATERIALIZER, "materialize") as invoked:
            with self.assertRaisesRegex(MATERIALIZER.MaterializationError, "escapes"):
                self.run_gate()
        invoked.assert_not_called()

    def test_stale_or_tampered_marker_cannot_pass(self) -> None:
        for field, value in (("version", "155.0.1"), ("baseline_config_sha256", "0" * 64),
                             ("source_sha256", "0" * 64), ("source_sha512", "0" * 128)):
            with self.subTest(field=field):
                def change(marker):
                    marker[field] = value
                with patch.object(MATERIALIZER, "materialize", side_effect=self.materialized(change)):
                    with self.assertRaisesRegex(ValueError, "marker differs"):
                        self.run_gate()

    def test_stale_patch_marker_is_rejected(self) -> None:
        def change(marker):
            marker["patches"] = [{"path": "old.patch", "sha256": "0" * 64}]
        with patch.object(MATERIALIZER, "materialize", side_effect=self.materialized(change)):
            with self.assertRaisesRegex(ValueError, "patch manifest differs"):
                self.run_gate()

    def test_actual_source_version_must_match_marker_and_baseline(self) -> None:
        with patch.object(MATERIALIZER, "materialize", side_effect=self.materialized(actual_version="155.0.1")):
            with self.assertRaisesRegex(ValueError, "Materialized source version differs"):
                self.run_gate()

    def test_baseline_cannot_change_during_materialization(self) -> None:
        changed = copy.deepcopy(self.baseline)
        changed["selected_at"] = "unreviewed"
        with patch.object(MATERIALIZER, "materialize", side_effect=self.materialized(baseline_change=changed)):
            with self.assertRaisesRegex(ValueError, "Baseline changed"):
                self.run_gate()

    def test_materializer_cannot_return_another_worktree(self) -> None:
        with patch.object(MATERIALIZER, "materialize", return_value=self.root / "other"):
            with self.assertRaisesRegex(ValueError, "canonical baseline layout"):
                self.run_gate()

    def test_missing_marker_is_not_materialization_evidence(self) -> None:
        with patch.object(MATERIALIZER, "materialize", return_value=self.worktree):
            with self.assertRaises(FileNotFoundError):
                self.run_gate()


if __name__ == "__main__":
    unittest.main()

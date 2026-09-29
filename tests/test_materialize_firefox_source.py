#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "materialize_firefox_source.py"
SPEC = importlib.util.spec_from_file_location("materialize_firefox_source", MODULE_PATH)
assert SPEC and SPEC.loader
MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)


def digest(path: Path, algorithm: str) -> str:
    value = hashlib.new(algorithm)
    value.update(path.read_bytes())
    return value.hexdigest()


class MaterializeFirefoxSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        (self.root / "patches").mkdir()
        (self.root / "overlay").mkdir()
        (self.root / "source").mkdir()
        self.version = "1.2"
        source_root = self.root / "fixture-source" / f"firefox-{self.version}"
        source_root.mkdir(parents=True)
        (source_root / "browser.txt").write_text("upstream\n", encoding="utf-8")
        self.archive = self.root / "source" / "firefox-1.2.source.tar.xz"
        with tarfile.open(self.archive, "w:xz") as archive:
            archive.add(source_root, arcname=source_root.name)
        self.config = self.root / "config" / "firefox-baseline.json"
        self.config.write_text(json.dumps({
            "version": self.version,
            "source": {
                "archive_path": "source/firefox-1.2.source.tar.xz",
                "sha256": digest(self.archive, "sha256"),
                "sha512": digest(self.archive, "sha512"),
            },
        }), encoding="utf-8")
        (self.root / "patches" / "series").write_text("add-good-bear.patch\n", encoding="utf-8")
        (self.root / "patches" / "add-good-bear.patch").write_text(
            "diff --git a/feature.txt b/feature.txt\n"
            "new file mode 100644\n"
            "index 0000000..89d2d08\n"
            "--- /dev/null\n"
            "+++ b/feature.txt\n"
            "@@ -0,0 +1 @@\n"
            "+patched\n",
            encoding="utf-8",
        )
        (self.root / "overlay" / "good-bear.txt").write_text("overlay\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_materializes_pinned_archive_with_overlay_and_ordered_patch(self) -> None:
        verifier = self.root / "verify.py"
        verifier.write_text("", encoding="utf-8")
        with patch.object(MATERIALIZER, "run_baseline_verifier") as verify:
            worktree = MATERIALIZER.materialize(self.config, self.archive, verifier)
        verify.assert_called_once_with(verifier, self.config.resolve(), self.archive.resolve(), offline=False)
        self.assertEqual((worktree / "browser.txt").read_text(encoding="utf-8"), "upstream\n")
        self.assertEqual((worktree / "feature.txt").read_text(encoding="utf-8"), "patched\n")
        self.assertEqual((worktree / "good-bear.txt").read_text(encoding="utf-8"), "overlay\n")
        pristine = self.root / "source" / "pristine" / f"firefox-{self.version}"
        self.assertFalse((pristine / "feature.txt").exists())
        self.assertFalse((pristine / "browser.txt").stat().st_mode & stat.S_IWUSR)
        self.assertTrue((worktree / "browser.txt").stat().st_mode & stat.S_IWUSR)
        marker = json.loads((worktree / ".good-bear-materialization.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["patches"][0]["path"], "add-good-bear.patch")
        self.assertEqual(marker["overlay_files"], ["good-bear.txt"])

    def test_baseline_child_uses_isolated_startup_and_keeps_import_tree_cache_free(self) -> None:
        tools = self.root / "tools"
        tools.mkdir()
        verifier = tools / "verify.py"
        (tools / "project_temp.py").write_text("VALUE = 'reviewed-helper'\n")
        verifier.write_text(
            "import sys, project_temp\n"
            "assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode\n"
            "assert project_temp.VALUE == 'reviewed-helper'\n"
            "assert sys.argv[-1] == '--offline'\n"
            "print('ISOLATED_BASELINE_CHILD')\n"
        )
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "sitecustomize.py").write_text("raise RuntimeError('UNREVIEWED_STARTUP')\n")
        with patch.dict(os.environ, {"PYTHONPATH": str(foreign), "PYTHONHOME": str(foreign)}):
            MATERIALIZER.run_baseline_verifier(verifier, self.config, self.archive, offline=True)
        self.assertFalse((tools / "__pycache__").exists())
        caches = list((self.root / "artifacts/build-tmp/python-startup").glob("python-startup-*"))
        self.assertEqual(len(caches), 1)
        self.assertEqual(list(caches[0].iterdir()), [])

    def test_materialized_patch_changes_an_existing_upstream_file(self) -> None:
        (self.root / "patches" / "add-good-bear.patch").write_text(
            "diff --git a/browser.txt b/browser.txt\n"
            "index 1111111..2222222 100644\n"
            "--- a/browser.txt\n"
            "+++ b/browser.txt\n"
            "@@ -1 +1 @@\n"
            "-upstream\n"
            "+good-bear\n",
            encoding="utf-8",
        )
        verifier = self.root / "verify.py"
        verifier.write_text("", encoding="utf-8")
        with patch.object(MATERIALIZER, "run_baseline_verifier"):
            worktree = MATERIALIZER.materialize(self.config, self.archive, verifier)
        pristine = self.root / "source" / "pristine" / f"firefox-{self.version}"
        self.assertEqual((pristine / "browser.txt").read_text(encoding="utf-8"), "upstream\n")
        self.assertEqual((worktree / "browser.txt").read_text(encoding="utf-8"), "good-bear\n")

    def test_rejects_added_tail_that_git_check_silently_ignores_then_applies_corrected_hunk(self) -> None:
        patch_file = self.root / "patches/add-good-bear.patch"
        original = patch_file.read_text(encoding="utf-8")
        patch_file.write_text(original + "+must-not-be-ignored\n", encoding="utf-8")
        worktree = self.root / "hunk-target"
        worktree.mkdir()
        checked = subprocess.run(
            ["git", "apply", "--no-index", "--check", "--whitespace=error-all", str(patch_file)],
            cwd=worktree, capture_output=True, text=True,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        with patch.object(MATERIALIZER.subprocess, "run") as run:
            with self.assertRaisesRegex(MATERIALIZER.MaterializationError,
                                        "declared old/new 0/1, actual 0/2"):
                MATERIALIZER.apply_patches([patch_file], worktree, self.root / "patches")
        run.assert_not_called()
        self.assertFalse((worktree / "feature.txt").exists())

        patch_file.write_text(
            original.replace("@@ -0,0 +1 @@", "@@ -0,0 +1,2 @@") + "+must-not-be-ignored\n",
            encoding="utf-8",
        )
        MATERIALIZER.apply_patches([patch_file], worktree, self.root / "patches")
        self.assertEqual((worktree / "feature.txt").read_text(), "patched\nmust-not-be-ignored\n")

    def test_rejects_ignored_deletion_context_and_truncated_hunks(self) -> None:
        patch_file = self.root / "patches/add-good-bear.patch"
        for hunk in (
            "@@ -1 +0,0 @@\n-one\n-two\n",
            "@@ -1 +1 @@\n one\n two\n",
            "@@ -0,0 +1,2 @@\n+only-one\n",
            "@@ -0,0 +1 @@\n+one\n\n+ignored-after-separator\n",
        ):
            with self.subTest(hunk=hunk):
                patch_file.write_text("--- a/test\n+++ b/test\n" + hunk, encoding="utf-8")
                with self.assertRaisesRegex(MATERIALIZER.MaterializationError, "text hunk counts differ"):
                    MATERIALIZER.verify_patch_hunk_counts(patch_file)

    def test_audit_collects_later_independent_failure_without_quarantining(self) -> None:
        worktree = self.root / "audit-target"
        worktree.mkdir()
        (worktree / "browser.txt").write_text("upstream\n", encoding="utf-8")
        first = self.root / "patches" / "first.patch"
        second = self.root / "patches" / "second.patch"
        third = self.root / "patches" / "third.patch"
        first.write_text(
            "--- a/browser.txt\n+++ b/browser.txt\n@@ -1 +1 @@\n-upstream\n+first\n",
            encoding="utf-8",
        )
        second.write_text(
            "--- a/missing.txt\n+++ b/missing.txt\n@@ -1 +1 @@\n-missing\n+changed\n",
            encoding="utf-8",
        )
        third.write_text(
            "--- a/other.txt\n+++ b/other.txt\n@@ -1 +1 @@\n-missing\n+changed\n",
            encoding="utf-8",
        )
        failures = MATERIALIZER.audit_patches(
            [first, second, third], worktree, self.root / "patches"
        )
        self.assertEqual((worktree / "browser.txt").read_text(encoding="utf-8"), "first\n")
        self.assertEqual([failure["path"] for failure in failures], ["second.patch", "third.patch"])
        self.assertNotIn("may_depend_on", failures[0])
        self.assertEqual(failures[1]["may_depend_on"], "second.patch")

    def test_accepts_multiple_hunks_files_zero_counts_and_no_newline_markers(self) -> None:
        worktree = self.root / "hunk-target"
        worktree.mkdir()
        (worktree / "first.txt").write_text("one\ntwo\nthree\nfour\nlast", encoding="utf-8")
        (worktree / "deleted.txt").write_text("deleted\n", encoding="utf-8")
        patch_file = self.root / "patches/add-good-bear.patch"
        patch_file.write_text(
            "--- a/first.txt\n+++ b/first.txt\n"
            "@@ -1,2 +1,2 @@\n-one\n+ONE\n two\n"
            "@@ -4,2 +4,2 @@\n four\n-last\n\\ No newline at end of file\n"
            "+LAST\n\\ No newline at end of file\n"
            "--- /dev/null\n+++ b/created.txt\n@@ -0,0 +1 @@\n+created\n"
            "--- a/deleted.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-deleted\n",
            encoding="utf-8",
        )
        MATERIALIZER.apply_patches([patch_file], worktree, self.root / "patches")
        self.assertEqual((worktree / "first.txt").read_text(), "ONE\ntwo\nthree\nfour\nLAST")
        self.assertEqual((worktree / "created.txt").read_text(), "created\n")
        self.assertFalse((worktree / "deleted.txt").exists())

    def test_accepts_header_like_source_empty_context_and_mail_footer(self) -> None:
        patch_file = self.root / "patches/add-good-bear.patch"
        patch_file.write_bytes(
            b"--- a/test\n+++ b/test\n@@ -1,2 +1,2 @@\n"
            b"--- removed source text\n+++ added source text\n\n-- \n2.40.0\n"
        )
        MATERIALIZER.verify_patch_hunk_counts(patch_file)

    def test_binary_payload_is_left_to_git(self) -> None:
        patch_file = self.root / "patches/add-good-bear.patch"
        patch_file.write_bytes(
            b"diff --git a/image b/image\nGIT binary patch\nliteral 4\n"
            b"@@ -1 +2 @@\n\xff\x00\n\n"
            b"diff --git a/test b/test\n--- a/test\n+++ b/test\n@@ -1 +1 @@\n-old\n+new\n"
        )
        MATERIALIZER.verify_patch_hunk_counts(patch_file)

    def test_windows_copy_uses_robocopy_and_accepts_its_success_codes(self) -> None:
        source = self.root / "pristine"
        destination = self.root / "staging" / "firefox-1.2"
        source.mkdir()
        (source / "browser.txt").write_text("upstream\n", encoding="utf-8")
        completed = subprocess.CompletedProcess(args=["robocopy"], returncode=1,
                                                 stdout="copied", stderr="")
        with patch.object(MATERIALIZER.os, "name", "nt"), \
             patch.object(MATERIALIZER.subprocess, "run", return_value=completed) as run:
            MATERIALIZER.copy_pristine_to_staging(source, destination)
        command = run.call_args.args[0]
        self.assertEqual(command[0], "robocopy")
        self.assertIn("/SL", command)
        self.assertIn("/COPY:DAT", command)

    def test_applies_existing_file_patch_inside_an_ignored_source_tree(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / ".gitignore").write_text("source/*\n", encoding="utf-8")
        (self.root / "patches" / "add-good-bear.patch").write_text(
            "diff --git a/browser.txt b/browser.txt\n"
            "index 1111111..2222222 100644\n"
            "--- a/browser.txt\n"
            "+++ b/browser.txt\n"
            "@@ -1 +1 @@\n"
            "-upstream\n"
            "+good-bear\n",
            encoding="utf-8",
        )
        verifier = self.root / "verify.py"
        verifier.write_text("", encoding="utf-8")
        with patch.object(MATERIALIZER, "run_baseline_verifier"):
            worktree = MATERIALIZER.materialize(self.config, self.archive, verifier)
        self.assertEqual((worktree / "browser.txt").read_text(encoding="utf-8"), "good-bear\n")

    def test_accepts_a_tar_current_directory_entry(self) -> None:
        archive = self.root / "source" / "firefox-1.2-with-dot.source.tar.xz"
        fixture_root = self.root / "fixture-source" / f"firefox-{self.version}"
        with tarfile.open(archive, "w:xz") as output:
            dot = tarfile.TarInfo(".")
            dot.type = tarfile.DIRTYPE
            output.addfile(dot)
            output.add(fixture_root, arcname=fixture_root.name)
        MATERIALIZER.validate_archive(archive, self.version)

    def test_refuses_an_archive_outside_the_pinned_path_before_verification(self) -> None:
        other = self.root / "other.tar.xz"
        other.write_bytes(self.archive.read_bytes())
        verifier = self.root / "verify.py"
        verifier.write_text("", encoding="utf-8")
        with patch.object(MATERIALIZER, "run_baseline_verifier") as verify:
            with self.assertRaisesRegex(MATERIALIZER.MaterializationError, "pinned path"):
                MATERIALIZER.materialize(self.config, other, verifier)
        verify.assert_not_called()

    def test_quarantines_failed_patch_application_without_promoting_worktree(self) -> None:
        (self.root / "patches" / "add-good-bear.patch").write_text(
            "diff --git a/missing.txt b/missing.txt\n"
            "--- a/missing.txt\n"
            "+++ b/missing.txt\n"
            "@@ -1 +1 @@\n"
            "-missing\n"
            "+changed\n",
            encoding="utf-8",
        )
        verifier = self.root / "verify.py"
        verifier.write_text("", encoding="utf-8")
        with patch.object(MATERIALIZER, "run_baseline_verifier"):
            with self.assertRaisesRegex(MATERIALIZER.MaterializationError, "patch check failed"):
                MATERIALIZER.materialize(self.config, self.archive, verifier)
        worktree = self.root / "source" / "worktrees" / f"firefox-{self.version}"
        self.assertFalse(worktree.exists())
        self.assertTrue(any((self.root / "source" / "quarantine").iterdir()))



if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ubuntu_candidate", ROOT / "tools" / "run_ubuntu_candidate.py")
assert SPEC and SPEC.loader
CANDIDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANDIDATE)


class UbuntuCandidateTest(unittest.TestCase):
    def test_declares_only_supported_candidate_commands(self) -> None:
        build = CANDIDATE.command_for("build")
        self.assertIn(
            "gmake -C /workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/browser/locales merge-ru",
            build,
        )
        self.assertIn("IS_LANGUAGE_REPACK=1", build)
        self.assertIn("REAL_LOCALE_MERGEDIR=/workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/browser/locales/merge-dir/ru", build)
        self.assertIn("./mach build -j1 &&", build)
        self.assertIn(
            "gmake -C /workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/browser/locales chrome-ru &&",
            build,
        )
        self.assertIn(
            "gmake -C /workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/browser/locales multilocale.txt-ru &&",
            build,
        )
        self.assertIn(
            "/workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/dist/xpi-stage/res/multilocale.txt",
            build,
        )
        self.assertTrue(build.endswith(
            "/workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/dist/bin/res/multilocale.txt"
        ))
        self.assertEqual(
            CANDIDATE.command_for("repack-ru"),
            "./mach package-multi-locale --locales ru",
        )
        self.assertNotIn("--without-wasm-sandboxed-libraries", CANDIDATE.command_for("configure"))

    def test_mount_is_explicit_and_never_uses_the_host_root(self) -> None:
        rendered = CANDIDATE.mount(ROOT / "source", "/workspace/source", "ro")
        self.assertIn("type=bind,src=", rendered)
        self.assertIn("dst=/workspace/source,readonly", rendered)
        self.assertNotIn("src=/,", rendered)

    def test_candidate_runner_disables_pip_indexes(self) -> None:
        self.assertIn('"-e", "PIP_NO_INDEX=1"', (ROOT / "tools" / "run_ubuntu_candidate.py").read_text())

    def test_candidate_runner_uses_bash_for_source_based_mozconfig(self) -> None:
        text = (ROOT / "tools" / "run_ubuntu_candidate.py").read_text()
        self.assertIn('"bash", "-lc", command', text)
        self.assertNotIn('"sh", "-lc", command', text)


if __name__ == "__main__":
    unittest.main()

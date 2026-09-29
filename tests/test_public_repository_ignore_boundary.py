"""Prevent public source-freezes from staging local build evidence or inputs."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublicRepositoryIgnoreBoundaryTest(unittest.TestCase):
    def ignored(self, path: str) -> bool:
        return subprocess.run(
            ["git", "check-ignore", "--quiet", "--no-index", path],
            cwd=ROOT,
            check=False,
        ).returncode == 0

    def test_local_build_evidence_and_private_transport_are_ignored(self) -> None:
        for path in (
            "build/m13-06-source-freeze/source-bundle.tar",
            "build/m15-03-cloud-windows-status.json",
            "build/m15-03-local-vm/current-vm-screen.png",
            "build/m15-10-windows-encrypted/source-bundle.tar.enc",
            ".runnerprobe.txt",
            "Projectsbe=",
            "firefox-l-l10n=",
        ):
            self.assertTrue(self.ignored(path), path)

    def test_reproducible_build_recipes_remain_trackable(self) -> None:
        for path in (
            "build/ubuntu/Dockerfile",
            "build/ubuntu/install-packages.sh",
            "build/ubuntu/mozconfig.dev",
            "build/ubuntu/mozconfig.host",
            "build/ubuntu/mozconfig.release-lto",
            "build/windows/mozconfig.engine-test",
            "build/windows/mozconfig.release-lto",
        ):
            self.assertFalse(self.ignored(path), path)

    def test_russian_l10n_overlay_is_tracked_but_materialized_input_is_not(self) -> None:
        self.assertFalse(self.ignored(
            "overlay/l10n/firefox-l10n/ru/browser/browser/aboutDialog.ftl"))
        self.assertTrue(self.ignored(
            "source/l10n/firefox-l10n/ru/browser/browser/aboutDialog.ftl"))


if __name__ == "__main__":
    unittest.main()

"""Tests for the reproducible Russian locale materializer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.materialize_pinned_russian_l10n import (
    L10nError,
    apply_verified_overlay,
    load_lock,
    verify_materialized_checkout,
)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class PinnedRussianL10nTest(unittest.TestCase):
    def make_fixture(self) -> tuple[Path, Path, dict[str, object], dict[str, str]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        checkout = root / "source/l10n/firefox-l10n"
        overlay = root / "overlay/l10n/firefox-l10n"
        originals = {
            "ru/browser/browser/aboutDialog.ftl": "upstream-about\n",
            "ru/browser/browser/browser.ftl": "upstream-browser\n",
        }
        replacements = {
            "ru/browser/browser/aboutDialog.ftl": "good-bear-about\n",
            "ru/browser/browser/browser.ftl": "good-bear-browser\n",
            "ru/browser/browser/goodbearSafeBrowsing.ftl": "safe-browsing\n",
            "ru/browser/browser/preferences/goodBearRussianPKI.ftl": "russian-pki\n",
        }
        for name, content in originals.items():
            path = checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "config", "user.email", "tests@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(checkout), "config", "user.name", "Good Bear tests"], check=True)
        subprocess.run(["git", "-C", str(checkout), "add", "ru"], check=True)
        subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "upstream locale fixture"], check=True)
        revision = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"], check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        for name, content in replacements.items():
            path = overlay / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        lock: dict[str, object] = {
            "revision": revision,
            "checkout": "source/l10n/firefox-l10n",
            "overlay": "overlay/l10n/firefox-l10n",
            "assets": {
                name: {
                    "base_sha256": sha256(originals[name]) if name in originals else None,
                    "overlay_sha256": sha256(content),
                }
                for name, content in replacements.items()
            },
        }
        return root, checkout, lock, replacements

    def test_lock_is_well_formed(self) -> None:
        lock = load_lock()
        self.assertEqual(lock["locale"], "ru")
        self.assertEqual(len(lock["assets"]), 4)

    def test_verified_overlay_replaces_only_pinned_resources(self) -> None:
        root, checkout, lock, replacements = self.make_fixture()
        apply_verified_overlay(root, checkout, lock)
        for name, expected in replacements.items():
            self.assertEqual((checkout / name).read_text(encoding="utf-8"), expected)
        self.assertEqual(verify_materialized_checkout(root, lock), checkout)

    def test_verifier_rejects_an_extra_local_locale_change(self) -> None:
        root, checkout, lock, _ = self.make_fixture()
        apply_verified_overlay(root, checkout, lock)
        extra = checkout / "ru/browser/browser/unrelated.ftl"
        extra.write_text("unreviewed\n", encoding="utf-8")
        with self.assertRaisesRegex(L10nError, "untracked files differ"):
            verify_materialized_checkout(root, lock)

    def test_overlay_rejects_dirty_upstream_checkout(self) -> None:
        root, checkout, lock, _ = self.make_fixture()
        (checkout / "ru/browser/browser/aboutDialog.ftl").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(L10nError, "not clean"):
            apply_verified_overlay(root, checkout, lock)

    def test_overlay_rejects_base_hash_drift(self) -> None:
        root, checkout, lock, _ = self.make_fixture()
        assets = lock["assets"]
        assert isinstance(assets, dict)
        record = assets["ru/browser/browser/aboutDialog.ftl"]
        assert isinstance(record, dict)
        record["base_sha256"] = "0" * 64
        with self.assertRaisesRegex(L10nError, "base hash mismatch"):
            apply_verified_overlay(root, checkout, lock)

    def test_lock_rejects_unexpected_asset_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
            with self.assertRaisesRegex(L10nError, "repository drift"):
                load_lock(path)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Focused tests for the offline pinned-archive verification boundary."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "verify_firefox_baseline", ROOT / "tools" / "verify_firefox_baseline.py"
)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class OfflinePinnedArchiveTest(unittest.TestCase):
    def test_accepts_matching_hashes_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "firefox.source.tar.xz"
            archive.write_bytes(b"pinned-fixture")
            config = {"source": {
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "sha512": hashlib.sha512(archive.read_bytes()).hexdigest(),
            }}
            VERIFIER.verify_pinned_archive_offline(config, archive)

    def test_rejects_changed_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "firefox.source.tar.xz"
            archive.write_bytes(b"changed")
            config = {"source": {"sha256": "0" * 64, "sha512": "0" * 128}}
            with self.assertRaisesRegex(VERIFIER.VerificationError, "sha256 mismatch"):
                VERIFIER.verify_pinned_archive_offline(config, archive)


if __name__ == "__main__":
    unittest.main()

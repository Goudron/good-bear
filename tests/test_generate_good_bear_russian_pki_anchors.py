#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
SOURCE_GENERATOR = (
    ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
    / "security/manager/ssl/generate_good_bear_russian_pki_anchors.py"
)
SPEC = importlib.util.spec_from_file_location("good_bear_anchor_generator", SOURCE_GENERATOR)
assert SPEC and SPEC.loader
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class GoodBearRussianPKIAnchorGeneratorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="good-bear-anchor-generator-")
        self.input_dir = Path(self.temporary.name)
        self.root_path = self.input_dir / GENERATOR.ROOT_RELATIVE_PATH
        self.root_path.parent.mkdir(parents=True)
        self.root = b"exact locally verified root input"
        self.root_path.write_bytes(self.root)
        self.intermediates = (
            b"exact locally verified RSA 2022 intermediate input",
            b"exact locally verified RSA 2024 intermediate input",
        )
        for (_, relative_path, _), intermediate in zip(
            GENERATOR.APPROVED_INTERMEDIATES, self.intermediates, strict=True
        ):
            intermediate_path = self.input_dir / relative_path
            intermediate_path.parent.mkdir(parents=True, exist_ok=True)
            intermediate_path.write_bytes(intermediate)
        self.environment = {GENERATOR.ENVIRONMENT_NAME: str(self.input_dir)}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def generate(self) -> str:
        output = io.StringIO()
        GENERATOR.generate(output)
        return output.getvalue()

    def test_emits_hash_pinned_root_and_non_anchor_intermediate_arrays(self) -> None:
        with (
            mock.patch.object(GENERATOR, "ROOT_SHA256", hashlib.sha256(self.root).hexdigest()),
            mock.patch.object(
                GENERATOR,
                "APPROVED_INTERMEDIATES",
                tuple(
                    (name, path, hashlib.sha256(intermediate).hexdigest())
                    for (name, path, _), intermediate in zip(
                        GENERATOR.APPROVED_INTERMEDIATES, self.intermediates, strict=True
                    )
                ),
            ),
            mock.patch.dict(os.environ, self.environment, clear=True),
        ):
            generated = self.generate()
        self.assertIn("constexpr uint8_t kGoodBearRussianPKIExactRoot[]", generated)
        self.assertIn("constexpr uint8_t kGoodBearRussianPKIApprovedIntermediateRSA2022[]", generated)
        self.assertIn("constexpr uint8_t kGoodBearRussianPKIApprovedIntermediateRSA2024[]", generated)
        self.assertIn("0x65, 0x78, 0x61, 0x63, 0x74", generated)
        self.assertIn("0x30, 0x32, 0x34, 0x20, 0x69, 0x6e, 0x74", generated)

    def test_missing_or_tampered_input_fails_before_compilation(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "required"):
                self.generate()
        with mock.patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "root does not match"):
                self.generate()
        with (
            mock.patch.object(GENERATOR, "ROOT_SHA256", hashlib.sha256(self.root).hexdigest()),
            mock.patch.dict(os.environ, self.environment, clear=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "IntermediateRSA2022 does not match"):
                self.generate()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m2_05_probe", ROOT / "tools/run_m2_05_pki_fixture_probe.py"
)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class M205PKIFixtureProbeTest(unittest.TestCase):
    def test_local_materializer_builds_and_rejects_adversarial_chains(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixtures"
            PROBE.run(output)
            index = json.loads((output / "fixture-index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["task"], "GB100-M2-05")
            self.assertTrue(index["offline_only"])
            self.assertNotEqual(
                index["exact_anchor_sha256"], index["same_name_fake_root_sha256"]
            )
            for relative in (
                "pki/standard-root.pem", "pki/russian-root.pem",
                "negative/bad-signature-leaf.pem", "negative/missing-intermediate-chain.pem",
                "negative/pathlen-subintermediate.pem",
            ):
                self.assertTrue((output / relative).is_file(), relative)


if __name__ == "__main__":
    unittest.main()

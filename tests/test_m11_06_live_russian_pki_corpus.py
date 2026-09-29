#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "m11_06_corpus", ROOT / "tools" / "run_m11_live_russian_pki_corpus.py"
)
assert SPEC and SPEC.loader
CORPUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORPUS)


class M1106LiveCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(CORPUS.CORPUS_PATH.read_text(encoding="utf-8"))

    def test_corpus_is_a_deduplicated_test_only_candidate_set(self) -> None:
        candidates = CORPUS.validate_corpus(self.document)
        self.assertGreaterEqual(len(candidates), 2)
        self.assertEqual(len({candidate["url"] for candidate in candidates}), len(candidates))
        self.assertIn("https://check.russian-trusted.ru/", {candidate["url"] for candidate in candidates})
        self.assertFalse(self.document["policy"]["runtime_allowlist"])
        self.assertFalse(self.document["policy"]["production_trust_input"])
        self.assertFalse(self.document["policy"]["external_availability_required"])
        self.assertFalse(self.document["policy"]["government_endpoint_required"])

    def test_duplicate_or_non_https_candidate_is_rejected(self) -> None:
        duplicate = copy.deepcopy(self.document)
        duplicate["candidates"].append(copy.deepcopy(duplicate["candidates"][0]))
        duplicate["candidates"][-1]["id"] = "duplicate_check"
        with self.assertRaisesRegex(CORPUS.CorpusError, "deduplicated"):
            CORPUS.validate_corpus(duplicate)
        insecure = copy.deepcopy(self.document)
        insecure["candidates"][0]["url"] = "http://check.russian-trusted.ru/"
        with self.assertRaisesRegex(CORPUS.CorpusError, "safe HTTPS"):
            CORPUS.validate_corpus(insecure)

    def test_policy_cannot_become_a_runtime_or_production_input(self) -> None:
        weakened = copy.deepcopy(self.document)
        weakened["policy"]["runtime_allowlist"] = True
        with self.assertRaisesRegex(CORPUS.CorpusError, "test-only boundary"):
            CORPUS.validate_corpus(weakened)
        weakened = copy.deepcopy(self.document)
        weakened["policy"]["external_availability_required"] = True
        with self.assertRaisesRegex(CORPUS.CorpusError, "test-only boundary"):
            CORPUS.validate_corpus(weakened)

    def test_runner_uses_exact_existing_inputs_and_artifact_only_reports(self) -> None:
        source = (ROOT / "tools" / "run_m11_live_russian_pki_corpus.py").read_text(encoding="utf-8")
        self.assertIn("MANIFEST_PATH", source)
        self.assertIn("BUILD_INPUTS", source)
        self.assertIn("-verify_hostname", source)
        self.assertIn('"reviewed_build_input"', source)
        self.assertIn("ordinary context acquired Russian PKI trust", source)
        self.assertIn("redirected_to_isolated_native_russian_pki", source)
        self.assertIn("browser session unavailable before navigation", source)
        self.assertIn('"browser_session": {"status": "not_proven"}', source)
        self.assertIn("artifacts/live-russian-pki-corpus", source)
        self.assertNotIn("write_text(MANIFEST_PATH", source)
        self.assertIn('"runtime_allowlist": False', source)

    def test_supported_chain_inputs_are_existing_manifest_identities(self) -> None:
        inputs = CORPUS.load_supported_chain_inputs()
        self.assertIn(
            "d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31",
            inputs["anchors"],
        )
        self.assertIn(
            "2155785036c900dbb5f1bb2a1569c80c55595bd6bf94867a29bbddbc7d88a3f2",
            inputs["intermediates"],
        )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "verify_dependency_toolchain_audit.py"
SPEC = importlib.util.spec_from_file_location("dependency_toolchain_audit", MODULE_PATH)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class DependencyToolchainAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = json.loads(
            (ROOT / "config" / "dependency-toolchain-audit.json").read_text(encoding="utf-8")
        )
        self.baseline = json.loads(
            (ROOT / "config" / "firefox-baseline.json").read_text(encoding="utf-8")
        )

    def test_repository_audit_is_consistent(self) -> None:
        AUDIT.verify(self.audit, self.baseline)

    def test_rejects_a_stale_baseline_audit(self) -> None:
        self.audit["baseline"]["firefox_version"] = "155.0.1"
        with self.assertRaisesRegex(AUDIT.AuditError, "does not match the immutable baseline"):
            AUDIT.verify(self.audit, self.baseline)

    def test_rejects_a_non_russian_release_audit(self) -> None:
        self.audit["scope"]["release_locale"] = "en-US"
        with self.assertRaisesRegex(AUDIT.AuditError, "release locale"):
            AUDIT.verify(self.audit, self.baseline)

    def test_rejects_a_floating_firefox_owner_source(self) -> None:
        component = next(item for item in self.audit["components"] if item["id"] == "rust-and-cargo")
        component["current_pin_or_floor"]["source_url"] = (
            "https://raw.githubusercontent.com/mozilla-firefox/firefox/main/Cargo.toml"
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "immutable toolchain lock"):
            AUDIT.verify(self.audit, self.baseline)

    def test_rejects_treating_the_upstream_driver_as_a_direct_update(self) -> None:
        component = next(item for item in self.audit["components"] if item["id"] == "geckodriver")
        component["disposition"]["status"] = "adopt_candidate_after_compatibility_gate"
        with self.assertRaisesRegex(AUDIT.AuditError, "upstream-owned"):
            AUDIT.verify(self.audit, self.baseline)

    def test_rejects_a_latest_python_exception_without_a_compatible_candidate(self) -> None:
        component = next(item for item in self.audit["components"] if item["id"] == "python-mach")
        del component["compatible_stable_candidate"]
        with self.assertRaisesRegex(AUDIT.AuditError, "without a compatible candidate"):
            AUDIT.verify(self.audit, self.baseline)

    def test_rejects_an_llvm_exception_without_time_bounded_follow_up(self) -> None:
        component = next(item for item in self.audit["components"] if item["id"] == "clang-llvm-lld")
        del component["disposition"]["review_on_or_before"]
        with self.assertRaisesRegex(AUDIT.AuditError, "review_on_or_before"):
            AUDIT.verify(self.audit, self.baseline)


if __name__ == "__main__":
    unittest.main()

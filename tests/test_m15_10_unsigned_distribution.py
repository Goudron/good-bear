#!/usr/bin/env python3
"""Unsigned release guards; synthetic reports are never acceptance evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_m15_10_release_gate as GATE


class UnsignedDistributionTests(unittest.TestCase):
    def test_current_disabled_delivery_is_valid_without_accepting_signed_updates(self):
        self.assertEqual(GATE.unsigned_distribution_blockers(), [])
        matrix = GATE.read_json(GATE.MATRIX)
        self.assertEqual(matrix["distribution_policy"], GATE.DISTRIBUTION_POLICY)
        deferred = matrix["distribution_policy"]["deferred_signed_update"]
        self.assertEqual(deferred["status"], "not_accepted_for_this_release_mode")
        self.assertEqual(set(deferred["required_checks"]), GATE.SIGNED_UPDATE_CHECKS)
        self.assertIn("allowed_update_applied", deferred["required_checks"])
        self.assertIn("modified_mar_rejected", deferred["required_checks"])

    def test_enabled_updater_or_endpoint_cannot_use_unsigned_mode(self):
        actual = GATE.read_json
        for replacement in ({"enabled": True, "endpoints": []},
                            {"enabled": False, "endpoints": ["https://example.invalid/"]},
                            {"enabled": None, "endpoints": []}):
            def altered(path):
                data = copy.deepcopy(actual(path))
                if path.name == "product-identity.json":
                    data["services"]["application_updater"] = replacement
                return data
            with self.subTest(updater=replacement), patch.object(GATE, "read_json", side_effect=altered):
                self.assertTrue(any("disabled native updater" in item
                                    for item in GATE.unsigned_distribution_blockers()))

    def test_forged_ready_or_signing_state_is_rejected(self):
        actual = GATE.read_json
        for filename, key in (("m15-09-update-delivery-contract.json", "windows"),
                              ("m15-09-update-delivery-contract.json", "ubuntu"),
                              ("m15-08-signing-public-manifest.json", "updater_enabled")):
            def altered(path):
                data = copy.deepcopy(actual(path))
                if path.name == filename:
                    if key == "updater_enabled":
                        data[key] = True
                    else:
                        data[key]["status"] = "ready"
                return data
            with self.subTest(filename=filename, key=key), patch.object(GATE, "read_json", side_effect=altered):
                self.assertTrue(GATE.unsigned_distribution_blockers())

    def test_each_platform_requires_actual_bound_unsigned_evidence(self):
        for item_id, platform in (("windows_unsigned_distribution", "windows-x64"),
                                  ("ubuntu_unsigned_distribution", "ubuntu-amd64")):
            required = GATE.REQUIRED_RUNTIME[item_id]
            self.assertTrue(GATE.UNSIGNED_CHECKS <= required)
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                log = directory / "run.log"
                log.write_text("synthetic unit fixture only\n")
                report = {
                    "task": "GB100-M15-10", "id": item_id, "status": "passed",
                    "source_manifest_sha256": "a" * 64,
                    "version_pair": GATE.VERSION_PAIR, "platform": platform,
                    "artifact_sha256": "b" * 64, "runner": "synthetic-only",
                    "executed_at": "2026-09-19T00:00:00Z", "command": ["synthetic-only"],
                    "checks": dict.fromkeys(required, True),
                    "log": {"path": log.name, "sha256": GATE.sha256_file(log)},
                }
                path = directory / "report.json"

                def verify():
                    path.write_text(json.dumps(report))
                    (directory / "evidence.json").write_text(json.dumps({
                        "runtime": {item_id: {"report": path.name,
                                             "sha256": GATE.sha256_file(path)}}}))
                    GATE.verify_report(ROOT, directory, item_id, required, "a" * 64,
                                       {"windows-x64": "b" * 64, "ubuntu-amd64": "b" * 64}, set())

                verify()
                for check in sorted(required):
                    report["checks"][check] = False
                    with self.subTest(check=check), self.assertRaisesRegex(GATE.GateError, "incomplete checks"):
                        verify()
                    report["checks"][check] = True
                report["platform"] = "ubuntu-amd64" if platform == "windows-x64" else "windows-x64"
                with self.assertRaisesRegex(GATE.GateError, "wrong execution platform"):
                    verify()


if __name__ == "__main__":
    unittest.main()

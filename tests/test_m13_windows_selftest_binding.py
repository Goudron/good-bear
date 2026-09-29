#!/usr/bin/env python3
"""Exercise receipt decisions with modeled native operations, not Windows proof."""

import argparse
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import test_m13_cloud_windows as fixtures

ROUTE = fixtures.ROUTE
inventory = fixtures.inventory


class RecoveredSelftestBindingTest(unittest.TestCase):
    setUp = fixtures.NativeCloudRouteTest.setUp
    fixture = fixtures.NativeCloudRouteTest.fixture

    def recovered(self):
        job, state, path = self.fixture()
        state.update(status="finished", exit_code=0, network_transition_started=True,
                     worker_started=True, worker_sid="S-1-5-21-test")
        result = {"phase": "isolation-selftest", "job_id": job["id"],
                  "job_sha256": ROUTE.preflight.sha256(path), "internal_engine_only": True,
                  "product_artifacts": [], "public_release_allowed": False,
                  "completed_utc": "2026-09-20T00:00:00+00:00",
                  "native_network_probe": {"ipv4": 10013, "ipv6": 10051, "loopback": "passed"}}
        ROUTE.atomic_json(Path(job["workspace"]) / "worker-result.json", result)
        self.backend.current = inventory(offline=True, boot="boot-b")
        ROUTE.recover(job, state, path, self.backend)
        reference = {"job_id": job["id"], "job_sha256": ROUTE.preflight.sha256(path),
                     "receipt_sha256": ROUTE.preflight.sha256(path.parent / "recovered-selftest.json")}
        args = argparse.Namespace(**{**vars(self.args), "phase": "configure"})
        target = ROUTE.make_job(args, inventory(boot="boot-b"), job["preflight"], "2" * 32)
        return job, state, path, reference, target

    def rewrite_receipt(self, path, reference, **changes):
        receipt = ROUTE.load_bounded_record(path.parent / "recovered-selftest.json")
        receipt.update(changes)
        ROUTE.atomic_json(path.parent / "recovered-selftest.json", receipt)
        reference["receipt_sha256"] = ROUTE.preflight.sha256(path.parent / "recovered-selftest.json")

    def test_recovery_creates_exact_binding_only_after_removing_tasks(self):
        _, _, path, reference, target = self.recovered()
        authorization = ROUTE.verified_selftest(reference, target, self.backend)
        target["isolation_authorization"] = authorization
        for phase in ("configure", "engine-test"):
            ROUTE.validate_job_authorization({**target, "phase": phase})
        ROUTE.validate_job_authorization({**target, "phase": "full-lto", "internal_engine_only": False})
        self.assertEqual(authorization["binding"], ROUTE.selftest_binding(target))
        self.assertTrue((path.parent / "selftest-result.json").is_file())
        self.assertLess(self.backend.events.index("remove-tasks"), self.backend.events.index("verify-acl"))

    def test_arbitrary_standalone_pass_boolean_is_not_authorization(self):
        with self.assertRaisesRegex(ROUTE.RouteError, "exact recovered selftest"):
            ROUTE.verified_selftest({"passed": True, "network_restored": True}, {}, self.backend)
        self.assertEqual(self.backend.events, [])

    def test_source_bundle_toolchain_and_vm_drift_invalidate_receipt(self):
        _, _, _, reference, target = self.recovered()
        mutations = [lambda j: j.update(expected_manifest_sha256="e" * 64),
                     lambda j: j.update(expected_bundle_sha256="e" * 64),
                     lambda j: j.update(executor_sha256="e" * 64),
                     lambda j: j.update(helper_sha256="e" * 64),
                     lambda j: j["original_network"].update(vm_identity_sha256="e" * 64),
                     lambda j: j["preflight"]["frozen_source"].update(firefox_version="155.0.1"),
                     lambda j: j["preflight"]["installed_tools"].update(executable="e" * 64),
                     lambda j: j["preflight"].update(toolchain_lock_sha256="e" * 64)]
        for mutate in mutations:
            changed = copy.deepcopy(target)
            mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaisesRegex(ROUTE.RouteError, "binding differs"):
                ROUTE.verified_selftest(reference, changed, self.backend)

    def test_acl_and_caller_hash_are_checked_before_accepting_old_evidence(self):
        _, _, _, reference, target = self.recovered()
        self.backend.trusted = False
        with self.assertRaisesRegex(ROUTE.RouteError, "protected native evidence"):
            ROUTE.verified_selftest(reference, target, self.backend)
        self.backend.trusted = True
        for field in ("job_sha256", "receipt_sha256"):
            with self.subTest(field=field), self.assertRaisesRegex(ROUTE.RouteError, "hash differs"):
                ROUTE.verified_selftest({**reference, field: "0" * 64}, target, self.backend)

    def test_failed_or_incomplete_state_is_rejected_even_with_updated_hash(self):
        _, state, path, reference, target = self.recovered()
        for changes in ({"exit_code": 1}, {"exit_code": False}, {"network_restored": False},
                        {"worker_started": False}, {"worker_sid": None}, {"cleanup_error": "failed"},
                        {"recovery_checks": {"quiescent": True, "account_removed": True}}):
            ROUTE.atomic_json(path.parent / "state.json", {**state, **changes})
            self.rewrite_receipt(path, reference, state_sha256=ROUTE.preflight.sha256(path.parent / "state.json"))
            with self.subTest(changes=changes), self.assertRaisesRegex(ROUTE.RouteError, "finish and recover"):
                ROUTE.verified_selftest(reference, target, self.backend)

    def test_same_boot_and_result_substitution_fail_closed(self):
        _, state, path, reference, target = self.recovered()
        ROUTE.atomic_json(path.parent / "state.json", {**state, "recovered_boot": "boot-a"})
        self.rewrite_receipt(path, reference, recovered_boot="boot-a",
                             state_sha256=ROUTE.preflight.sha256(path.parent / "state.json"))
        with self.assertRaisesRegex(ROUTE.RouteError, "different-boot"):
            ROUTE.verified_selftest(reference, target, self.backend)
        ROUTE.atomic_json(path.parent / "state.json", state)
        self.rewrite_receipt(path, reference, recovered_boot="boot-b",
                             state_sha256=ROUTE.preflight.sha256(path.parent / "state.json"))
        result_path = path.parent / "selftest-result.json"
        result = ROUTE.load_bounded_record(result_path)
        for changes in ({"job_id": "2" * 32}, {"job_sha256": "f" * 64},
                        {"phase": "engine-test"}, {"error": "failed"},
                        {"native_network_probe": None},
                        {"native_network_probe": {"ipv4": 0, "ipv6": 10051, "loopback": "passed"}},
                        {"native_network_probe": {"ipv4": 10013, "ipv6": 10051, "loopback": "failed"}}):
            ROUTE.atomic_json(result_path, {**result, **changes})
            self.rewrite_receipt(path, reference, result_sha256=ROUTE.preflight.sha256(result_path))
            with self.subTest(changes=changes), self.assertRaises(ROUTE.RouteError):
                ROUTE.verified_selftest(reference, target, self.backend)

    def test_receipt_writer_rejects_incomplete_recovery_even_after_successful_exit(self):
        job, state, path = self.fixture()
        state.update(status="finished", exit_code=0)
        with self.assertRaisesRegex(ROUTE.RouteError, "incomplete recovery"):
            ROUTE.publish_selftest_receipt(job, state, path, self.backend)
        self.assertFalse((path.parent / "recovered-selftest.json").exists())

    def test_tampered_hashed_state_or_result_is_not_accepted(self):
        _, _, path, reference, target = self.recovered()
        for name in ("state.json", "selftest-result.json"):
            artifact = path.parent / name
            original = artifact.read_bytes()
            artifact.write_bytes(original + b"\n")
            with self.subTest(name=name), self.assertRaisesRegex(ROUTE.RouteError, "bind its native evidence"):
                ROUTE.verified_selftest(reference, target, self.backend)
            artifact.write_bytes(original)

    def test_uncertain_task_removal_never_publishes_receipt(self):
        job, state, path = self.fixture()
        state.update(status="finished", exit_code=0, network_transition_started=True,
                     worker_started=True, worker_sid="S-1-5-21-test")
        self.backend.current = inventory(offline=True, boot="boot-b")
        self.backend.fail = "remove-tasks"
        with self.assertRaisesRegex(ROUTE.NativeError, "remove-tasks"):
            ROUTE.recover(job, state, path, self.backend)
        self.assertFalse(state["network_restored"])
        self.assertFalse((path.parent / "recovered-selftest.json").exists())

    def test_disabled_but_remaining_firewall_rule_does_not_prove_restoration(self):
        job, state, path = self.fixture()
        state.update(network_transition_started=True, worker_started=True, worker_sid="S-1-5-21-test")
        self.backend.current = inventory(offline=True, boot="boot-b")
        with patch.object(self.backend, "owned_rule_absent", return_value=False), \
                self.assertRaisesRegex(ROUTE.RouteError, "restoration is unproven"):
            ROUTE.recover(job, state, path, self.backend)
        self.assertNotIn("remove-tasks", self.backend.events)
        self.assertFalse(state["network_restored"])

    def test_coordinator_rechecks_receipt_before_disconnect(self):
        _, _, _, reference, target = self.recovered()
        target["isolation_authorization"] = ROUTE.verified_selftest(reference, target, self.backend)
        self.backend.trusted = False
        self.backend.events.clear()
        stage = self.jobs / target["id"]
        stage.mkdir()
        path = stage / "job.json"
        ROUTE.atomic_json(path, target)
        state = {"network_transition_started": False}
        ROUTE.execute_offline(target, state, path, self.backend)
        self.assertNotIn("block", self.backend.events)
        self.assertNotIn("create-account", self.backend.events)
        self.assertEqual(state["status"], "failed")
        self.assertIn("protected native evidence", state["error"])

    def test_recovery_does_not_require_build_receipt_or_private_key(self):
        job, state, path = self.fixture("engine-test")
        self.backend.current = inventory(offline=True, boot="boot-b")
        with patch.object(ROUTE, "verified_selftest", side_effect=AssertionError("receipt read")), \
                patch.object(ROUTE, "private_context", side_effect=AssertionError("key read")):
            ROUTE.recover(job, state, path, self.backend)
        self.assertTrue(state["network_restored"])
        self.assertFalse((path.parent / "recovered-selftest.json").exists())

    def test_bounded_records_reject_symlinks_hardlinks_and_oversized_data(self):
        original = self.base / "record.json"
        original.write_text('{}')
        self.assertEqual(ROUTE.load_bounded_record(original), {})
        linked = self.base / "linked.json"
        linked.symlink_to(original)
        with self.assertRaisesRegex(ROUTE.RouteError, "non-linked"):
            ROUTE.load_bounded_record(linked)
        linked.unlink()
        linked.hardlink_to(original)
        with self.assertRaisesRegex(ROUTE.RouteError, "non-linked"):
            ROUTE.load_bounded_record(original)
        linked.unlink()
        original.write_bytes(b" " * 65537)
        with self.assertRaisesRegex(ROUTE.RouteError, "size bound"):
            ROUTE.load_bounded_record(original)


if __name__ == "__main__":
    unittest.main()

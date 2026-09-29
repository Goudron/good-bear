#!/usr/bin/env python3
"""Parser/state/order regressions only; these are NOT Windows isolation proof."""

from __future__ import annotations

import argparse
import copy
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m13_cloud_windows", ROOT / "tools/run_m13_cloud_windows.py")
assert SPEC and SPEC.loader
ROUTE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROUTE)
NATIVE = sys.modules["windows_offline_worker"]
HOST = sys.modules["host_build_context"]


def inventory(*, offline=False, boot="boot-a"):
    return {"boot": boot, "cpus": 4, "memory_bytes": 16 * 1024**3, "system": True,
            "vm_identity_sha256": "c" * 64,
            "adapters": [{"guid": "physical-a", "index": 7, "enabled": not offline, "status": "Up"},
                         {"guid": "hidden-b", "index": 12, "enabled": False, "status": "Disabled"}],
            "loopback": [1], "connected": [] if offline else [7],
            "routes": [{"index": 1, "prefix": "127.0.0.0/8"}, {"index": 7, "prefix": "0.0.0.0/0"}],
            "firewall_profiles": [{"name": name, "enabled": True} for name in ("Domain", "Private", "Public")]}


class FakeBackend:
    def __init__(self):
        self.events = []
        self.current = inventory()
        self.rule = True
        self.quiescent = True
        self.trusted = True
        self.protected = []
        self.acl_checks = []
        self.fail = None
        self.worker_io_password = None
        self.worker_io_result_phase = None

    def event(self, name):
        self.events.append(name)
        if self.fail == name:
            raise ROUTE.NativeError("injected " + name + " failure")

    def arm_lock(self):
        self.event("lock")
        return nullcontext()

    def inventory(self):
        self.event("inventory")
        return copy.deepcopy(self.current)

    def protect_job(self, directory):
        self.protected.append(directory)
        self.event("protect")

    def seal_new_job(self, directory):
        self.event("seal-new-job")

    def verify_private_acl(self, path, purpose, worker_sid=None, trusted_root=None):
        self.acl_checks.append((path, purpose, worker_sid, trusted_root))
        self.event("verify-acl")
        return self.trusted

    def verify_provisioning_boundaries(self, *args):
        self.event("verify-provisioning-boundaries")
        return self.trusted

    def verify_worker_io(self, *args):
        self.worker_io_password = args[2]
        self.event("worker-io")
        if self.fail == "worker-io":
            raise NATIVE.NativeError("worker I/O probe failed")
        if self.worker_io_result_phase:
            Path(args[4][-1]).write_text(json.dumps({"phase": self.worker_io_result_phase}), encoding="ascii")
            return False
        return True

    def current_user_sid(self):
        return "S-1-5-21-test"

    def grant_private_inputs(self, directory, sid):
        self.event("grant-private-read")

    def register_tasks(self, *args):
        self.event("register")

    def launch(self, job):
        self.event("launch")

    def remove_tasks(self, job):
        self.event("remove-tasks")

    def block_network(self, job):
        self.event("block")
        self.current = inventory(offline=True)

    def rule_active(self, job):
        self.event("rule")
        return self.rule

    def owned_rule_absent(self, job):
        self.event("rule-absent")
        return not self.rule

    def create_account(self, *args, **kwargs):
        self.event("create-account")
        return "S-1-5-21-test"

    def provision_worker_workspace_acl(self, *args):
        self.event("workspace-acl")

    def provision_worker_stage_acl(self, *args):
        self.event("stage-acl")

    def grant_worker_descriptor_read(self, *args):
        self.event("descriptor-acl")

    def grant_worker_probe_read(self, *args):
        self.event("worker-probe-acl")

    def disable_account(self, *args):
        self.event("disable-account")

    def enable_account(self, *args):
        self.event("enable-account")

    def quiescent_after_boot(self, *args):
        self.event("quiescence")
        return self.quiescent

    def remove_account(self, *args):
        self.event("remove-account")

    def restore_network(self, job):
        self.event("restore")
        self.current = inventory(boot=self.current["boot"])
        self.rule = False

    def reboot(self):
        self.event("reboot")


class FakeJob:
    def __init__(self, backend, *, fail=None, code=0):
        self.backend, self.fail, self.code = backend, fail, code

    def event(self, name):
        self.backend.events.append(name)
        if self.fail == name:
            raise ROUTE.NativeError("injected " + name + " failure")

    def start(self, username, password, command, cwd, environment):
        self.event("start-child")
        assert command[-1] == "_build"
        assert command[1:6] == ["-I", "-S", "-B", "-u", "-X"]
        assert command[6].startswith("pycache_prefix=")
        assert password
        assert "GH_TOKEN" not in environment

    def allow_worker_query(self, sid):
        self.event("allow-query")

    def wait(self, deadline, heartbeat):
        self.event("wait-child")
        heartbeat()
        return self.code

    def close(self):
        self.event("close-child")


class NativeCloudRouteTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.artifacts = self.base / "artifacts"
        self.jobs = self.base / "native-offline-jobs"
        for module, name, value in ((ROUTE, "ARTIFACTS", self.artifacts),
                                    (HOST, "ARTIFACTS", self.artifacts),
                                    (ROUTE, "JOBS_ROOT", self.jobs),
                                    (ROUTE, "ACL_PROVISIONING_RECEIPT", self.base / "acl-preflight.json")):
            patcher = patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.args = argparse.Namespace(phase="isolation-selftest", timeout_minutes=5,
                                      manifest=self.base / "manifest.json", bundle=self.base / "bundle.tar",
                                      expected_manifest_sha256="a" * 64, expected_bundle_sha256="b" * 64)
        self.backend = FakeBackend()
        ROUTE.atomic_json(ROUTE.ACL_PROVISIONING_RECEIPT, {
            "schema_version": 1, "kind": "windows-acl-provisioning-preflight",
            "manifest_sha256": self.args.expected_manifest_sha256,
            "bundle_sha256": self.args.expected_bundle_sha256,
            "executor_sha256": ROUTE.preflight.sha256(ROOT / "tools/run_m13_cloud_windows.py"),
            "worker_helper_sha256": ROUTE.preflight.sha256(ROOT / "tools/windows_offline_worker.py"),
            "vm_identity_sha256": "c" * 64, "boundaries": list(ROUTE.ACL_BOUNDARIES), "passed": True})

    def fixture(self, phase="isolation-selftest"):
        self.args.phase = phase
        identifier = "1" * 32
        job = ROUTE.make_job(self.args, inventory(), {
            "preflight_passed": True, "m3_04": "passed", "toolchain_lock_sha256": "d" * 64,
            "installed_tools": {"pinned": True}, "toolchain_cache": {"pinned": True},
            "frozen_source": {"manifest_sha256": "a" * 64, "firefox_version": "156.0"}}, identifier)
        stage = self.jobs / identifier
        stage.mkdir(parents=True)
        ROUTE.workspace_for(identifier).mkdir(parents=True)
        path = stage / "job.json"
        ROUTE.atomic_json(path, job)
        state = {"launch_requested": True, "network_transition_started": False,
                 "worker_started": False, "network_restored": False, "worker_sid": None}
        ROUTE.atomic_json(stage / "state.json", state)
        return job, state, path

    def execute(self, *, fail=None, code=0):
        job, state, path = self.fixture()
        worker = FakeJob(self.backend, fail=fail, code=code)
        ROUTE.execute_offline(job, state, path, self.backend, job_factory=lambda _: worker)
        return job, state, path

    def recovered_fixture(self):
        job, state, path = self.fixture()
        state.update(network_transition_started=True, worker_started=True, worker_sid="S-1-5-21-test")
        self.backend.current = inventory(offline=True, boot="boot-b")
        return job, state, path

    def test_full_lto_cannot_skip_the_recovered_native_selftest_gate(self):
        self.args.phase = "full-lto"
        with patch.object(ROUTE, "require_native"), self.assertRaisesRegex(ROUTE.RouteError, "successful reboot recovery"):
            ROUTE.arm(self.args, self.backend)
        self.assertEqual(self.backend.events, [])

    def test_configure_and_engine_cannot_skip_recovered_native_selftest_gate(self):
        for phase in ("configure", "engine-test"):
            self.args.phase = phase
            with self.subTest(phase=phase), patch.object(ROUTE, "require_native"), \
                    self.assertRaisesRegex(ROUTE.RouteError, "successful reboot recovery"):
                ROUTE.arm(self.args, self.backend)
        self.assertEqual(self.backend.events, [])

    def test_direct_engine_execution_cannot_skip_recovered_native_selftest_gate(self):
        job, _, path = self.fixture("engine-test")
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "assert_worker") as worker, \
                self.assertRaisesRegex(ROUTE.RouteError, "successful reboot recovery"):
            ROUTE.run_build(job, path)
        worker.assert_not_called()

    def test_cloud_context_requires_matching_frozen_native_preflight_evidence(self):
        job, _, _ = self.fixture()
        frozen = {"manifest_sha256": "a" * 64, "firefox_version": "156.0"}
        job["preflight"].update(frozen_source=frozen, installed_tools={"pinned": True},
                                toolchain_cache={"pinned": True}, m3_04="passed")
        context = ROUTE.object_context(job["id"])
        with patch.object(Path, "is_file", return_value=True), patch.object(Path, "is_dir", return_value=True), \
                patch.object(Path, "is_symlink", return_value=False):
            context.validate(job=job, frozen=frozen)
            with self.assertRaisesRegex(ROUTE.RouteError, "matching frozen/preflight"):
                context.validate(job=job, frozen={**frozen, "manifest_sha256": "b" * 64})
            with patch.object(Path, "is_file", return_value=False), \
                    self.assertRaisesRegex(ROUTE.RouteError, "source/mach"):
                context.validate(job=job, frozen=frozen)

    def test_linux_cannot_arm_native_administrative_actions(self):
        with patch.object(NATIVE.sys, "platform", "linux"), self.assertRaisesRegex(NATIVE.NativeError, "native Windows"):
            ROUTE.arm(self.args, self.backend)
        self.assertEqual(self.backend.events, [])

    def test_timeout_and_job_identity_are_bounded(self):
        for timeout in (0, 361):
            self.args.timeout_minutes = timeout
            with self.assertRaisesRegex(ROUTE.RouteError, "timeout"):
                ROUTE.make_job(self.args, inventory(), {}, "1" * 32)
        with self.assertRaisesRegex(ROUTE.RouteError, "identity"):
            ROUTE.make_job(self.args, inventory(), {}, "../escape")

    def test_pinned_cloud_resources_accept_positive_and_reject_vbox(self):
        ROUTE.check_cloud_inventory(inventory())
        for name, value in (("cpus", 3), ("memory_bytes", 3 * 1024**3), ("loopback", [])):
            changed = inventory()
            changed[name] = value
            with self.subTest(name=name), self.assertRaises(ROUTE.RouteError):
                ROUTE.check_cloud_inventory(changed)

    def test_disabled_firewall_profile_rejects_arm(self):
        changed = inventory()
        changed["firewall_profiles"][1]["enabled"] = False
        with self.assertRaisesRegex(ROUTE.RouteError, "firewall"):
            ROUTE.check_cloud_inventory(changed)

    def test_offline_accepts_loopback_and_stale_routes_on_disabled_adapters(self):
        ROUTE.assert_offline(inventory(offline=True), inventory(), True)

    def test_offline_rejects_interface_route_boot_and_firewall_gaps(self):
        changes = [lambda x: x.update(connected=[7]),
                   lambda x: x["adapters"][0].update(enabled=True),
                   lambda x: x["adapters"].append({"guid": "new", "index": 22, "enabled": False}),
                   lambda x: x["routes"].append({"index": 99, "prefix": "::/0"}),
                   lambda x: x.update(boot="another"), lambda x: x.update(loopback=[])]
        for change in changes:
            observed = inventory(offline=True)
            change(observed)
            with self.subTest(change=change), self.assertRaises(ROUTE.RouteError):
                ROUTE.assert_offline(observed, inventory(), True)
        with self.assertRaisesRegex(ROUTE.RouteError, "outbound deny"):
            ROUTE.assert_offline(inventory(offline=True), inventory(), False)

    def test_snapshot_must_include_all_new_route_owners(self):
        self.args.manifest.write_text(json.dumps({"declared_inputs": [{"path": value} for value in ROUTE.REQUIRED_FROZEN]}))
        with patch.object(ROUTE.preflight, "run", return_value={"passed": True}):
            self.assertEqual(ROUTE.verify_inputs(self.args), {"passed": True})
            self.args.manifest.write_text(json.dumps({"declared_inputs": [{"path": "tools/run_m13_cloud_windows.py"}]}))
            with self.assertRaisesRegex(ROUTE.RouteError, "snapshot lacks"):
                ROUTE.verify_inputs(self.args)

    def test_arm_persists_descriptor_before_explicit_launch(self):
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "verify_inputs", return_value={}):
            path = ROUTE.arm(self.args, self.backend)
        self.assertLess(self.backend.events.index("protect"), self.backend.events.index("seal-new-job"))
        self.assertLess(self.backend.events.index("seal-new-job"), self.backend.events.index("register"))
        self.assertLess(self.backend.events.index("register"), self.backend.events.index("launch"))
        state = ROUTE.preflight.load(path.parent / "state.json")
        self.assertTrue(state["launch_requested"])
        self.assertFalse(state["network_transition_started"])
        job, _ = ROUTE.load_job(path, ROUTE.preflight.sha256(path))
        self.assertEqual(Path(job["objdir"]).parent, ROUTE.workspace_for(job["id"]))
        self.assertFalse(job["public_release_allowed"])
        self.assertEqual(self.backend.protected[0], self.jobs)

    def test_recovered_selftest_acl_stops_at_the_hardened_jobs_root(self):
        job, state, path = self.recovered_fixture()
        digest = ROUTE.preflight.sha256(path)
        ROUTE.atomic_json(Path(job["workspace"]) / "worker-result.json", {
            "phase": "isolation-selftest", "job_id": job["id"], "job_sha256": digest,
            "internal_engine_only": True, "product_artifacts": [], "public_release_allowed": False,
            "completed_utc": "2026-09-26T15:00:00+00:00",
            "native_network_probe": {"ipv4": 10051, "ipv6": 10051, "loopback": "passed"},
        })
        state.update(status="finished", exit_code=0)
        ROUTE.protect_jobs_root(self.backend)
        ROUTE.recover(job, state, path, self.backend)
        self.assertTrue(self.backend.acl_checks)
        self.assertTrue(all(check[3] == self.jobs for check in self.backend.acl_checks))

    def test_acl_provisioning_preflight_exercises_all_boundaries_without_network_mutation(self):
        self.args.output = self.base / "acl-preflight-output"
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "verify_inputs", return_value={"passed": True}):
            receipt = ROUTE.acl_provisioning_preflight(self.args, self.backend)
        self.assertTrue(receipt["passed"])
        self.assertEqual(receipt["boundaries"], list(ROUTE.ACL_BOUNDARIES))
        self.assertTrue(self.backend.worker_io_password)
        for event in ("protect", "seal-new-job", "create-account", "disable-account",
                      "workspace-acl", "stage-acl", "descriptor-acl", "grant-private-read", "worker-probe-acl",
                      "verify-provisioning-boundaries", "worker-io", "remove-account"):
            self.assertIn(event, self.backend.events)
        self.assertNotIn("block", self.backend.events)
        self.assertNotIn("launch", self.backend.events)
        self.assertFalse(any(self.jobs.iterdir()))
        self.assertTrue((self.args.output / "acl-provisioning-preflight.json").is_file())

    def test_acl_provisioning_preflight_requires_effective_worker_io(self):
        self.args.output = self.base / "acl-preflight-worker-io-failure-output"
        self.backend.fail = "worker-io"
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "verify_inputs", return_value={"passed": True}):
            with self.assertRaisesRegex(ROUTE.RouteError, "worker-io"):
                ROUTE.acl_provisioning_preflight(self.args, self.backend)
        self.assertIn("worker-io", self.backend.events)
        self.assertIn("remove-account", self.backend.events)
        self.assertNotIn("block", self.backend.events)
        self.assertFalse((self.args.output / "acl-provisioning-preflight.json").exists())

    def test_acl_provisioning_preflight_reports_worker_io_phase(self):
        self.args.output = self.base / "acl-preflight-worker-io-phase-output"
        self.backend.worker_io_result_phase = "descriptor"
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "verify_inputs", return_value={"passed": True}):
            with self.assertRaisesRegex(ROUTE.RouteError, "worker-io:descriptor"):
                ROUTE.acl_provisioning_preflight(self.args, self.backend)
        self.assertIn("remove-account", self.backend.events)
        self.assertNotIn("block", self.backend.events)
        self.assertFalse((self.args.output / "acl-provisioning-preflight.json").exists())

    def test_acl_provisioning_preflight_collects_later_boundaries_after_one_failure(self):
        self.args.output = self.base / "acl-preflight-failure-output"
        self.backend.fail = "descriptor-acl"
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "verify_inputs", return_value={"passed": True}):
            with self.assertRaisesRegex(ROUTE.RouteError, "descriptor"):
                ROUTE.acl_provisioning_preflight(self.args, self.backend)
        self.assertIn("workspace-acl", self.backend.events)
        self.assertIn("stage-acl", self.backend.events)
        self.assertIn("descriptor-acl", self.backend.events)
        self.assertIn("grant-private-read", self.backend.events)
        self.assertIn("remove-account", self.backend.events)
        self.assertNotIn("block", self.backend.events)

    def test_arm_rejects_a_stale_acl_provisioning_receipt(self):
        record = ROUTE.preflight.load(ROUTE.ACL_PROVISIONING_RECEIPT)
        record["bundle_sha256"] = "d" * 64
        ROUTE.atomic_json(ROUTE.ACL_PROVISIONING_RECEIPT, record)
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "verify_inputs", return_value={}):
            with self.assertRaisesRegex(ROUTE.RouteError, "ACL provisioning preflight receipt"):
                ROUTE.arm(self.args, self.backend)
        self.assertNotIn("protect", self.backend.events)

    def test_scheduled_coordinator_and_recovery_use_separate_isolated_startups(self):
        job, _, path = self.fixture()
        with patch.object(NATIVE, "powershell") as administration:
            NATIVE.WindowsBackend().register_tasks(job, path, "a" * 64)
        values = administration.call_args.args[1]
        for name, action in (("worker_args", "_worker"), ("watchdog_args", "_recover")):
            self.assertTrue(values[name].startswith("-I -S -B -u -X pycache_prefix="))
            self.assertTrue(values[name].endswith(action))
            self.assertIn("--job-sha256 " + "a" * 64, values[name])
        caches = list(path.parent.glob("python-startup-*"))
        self.assertEqual(len(caches), 2)
        self.assertTrue(all(cache.is_dir() and not list(cache.iterdir()) for cache in caches))
        for cache in caches:
            self.assertEqual(sum(str(cache) in values[name] for name in ("worker_args", "watchdog_args")), 1)

    def test_workflow_commands_match_real_cli_and_keep_only_selftest_arm(self):
        # This validates argument boundaries, not PowerShell parsing/execution.
        workflow = (ROOT / ".github/workflows/m13-06-windows-offline-selftest.yml").read_text()
        commands = [line.strip() for line in workflow.splitlines() if "& 'C:\\GoodBear\\tools\\Python312\\python.exe'" in line]
        self.assertEqual(len(commands), 3)
        parsed = []
        replacements = {
            "(Join-Path $workspace 'source-manifest.json')": "manifest.json",
            "(Join-Path $workspace 'source-bundle.tar')": "bundle.tar",
            "$env:GOODBEAR_MANIFEST_SHA256": "a" * 64,
            "$env:GOODBEAR_BUNDLE_SHA256": "b" * 64,
            "$env:GOODBEAR_JOB_SHA256": "c" * 64,
            "$job": "job.json", "$output": "source-free-evidence",
        }
        for command in commands:
            self.assertIn(" -I -S -B -u -X ('pycache_prefix=' + $cache) $script ", command)
            tail = command.split("$script ", 1)[1]
            for original, value in replacements.items():
                tail = tail.replace(original, value)
            parsed.append(ROUTE.parser().parse_args(shlex.split(tail)))
        self.assertEqual([args.action for args in parsed], ["arm", "collect", "status"])
        self.assertEqual(parsed[0].phase, "isolation-selftest")
        self.assertEqual(parsed[0].timeout_minutes, 10)
        self.assertEqual(parsed[1].job_sha256, "c" * 64)
        self.assertEqual(parsed[1].output, Path("source-free-evidence"))
        self.assertEqual(parsed[2].job_sha256, "c" * 64)

    def test_workflow_static_import_guard_precedes_python_and_matches_closure(self):
        workflow = (ROOT / ".github/workflows/m13-06-windows-offline-selftest.yml").read_text()
        required = workflow.split("$requiredPython = @(", 1)[1].split("\n          )", 1)[0]
        self.assertEqual(set(re.findall(r"'(tools/[^']+\.py)'", required)),
                         ROUTE.preflight.REQUIRED_PYTHON_OWNERS)
        self.assertLess(workflow.index("Undeclared Python import file"),
                        workflow.index("& 'C:\\GoodBear\\tools\\Python312\\python.exe'"))
        self.assertIn("@('.pyc', '.pyo')", workflow)
        self.assertIn("@('.py', '.pyd')", workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        for script in re.findall(r"        run: \|\n((?:          [^\n]*\n|\n)+)", workflow):
            self.assertNotIn("${{", script)

    def test_uncertain_registration_failure_does_not_authorize_another_job(self):
        self.backend.fail = "register"
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "verify_inputs", return_value={}):
            with self.assertRaisesRegex(NATIVE.NativeError, "register"):
                ROUTE.arm(self.args, self.backend)
            self.backend.fail = None
            with self.assertRaisesRegex(ROUTE.RouteError, "not completed recovery"):
                ROUTE.arm(self.args, self.backend)
        self.assertNotIn("launch", self.backend.events)
        self.assertNotIn("restore", self.backend.events)

    def test_failed_launch_keeps_watchdog_and_pending_recovery(self):
        self.backend.fail = "launch"
        with patch.object(ROUTE, "require_native"), patch.object(ROUTE, "verify_inputs", return_value={}):
            with self.assertRaisesRegex(NATIVE.NativeError, "launch"):
                ROUTE.arm(self.args, self.backend)
        self.assertNotIn("remove-tasks", self.backend.events)
        self.assertNotIn("restore", self.backend.events)
        state = ROUTE.preflight.load(next(self.jobs.iterdir()) / "state.json")
        self.assertTrue(state["launch_requested"])

    def test_job_hash_rejects_modified_descriptor(self):
        job, _, path = self.fixture()
        digest = ROUTE.preflight.sha256(path)
        job["phase"] = "engine-test"
        ROUTE.atomic_json(path, job)
        with self.assertRaisesRegex(ROUTE.RouteError, "hash differs"):
            ROUTE.load_job(path, digest)

    def test_descriptor_rejects_escaping_paths_and_foreign_owned_names(self):
        job, _, path = self.fixture()
        for name, value in (("workspace", str(self.base)), ("objdir", str(self.base)),
                            ("worker_task", "Another-Task"), ("python", "py.exe"),
                            ("source", "firefox-155.0.1"), ("public_release_allowed", True)):
            changed = {**job, name: value}
            ROUTE.atomic_json(path, changed)
            with self.subTest(name=name), self.assertRaises(ROUTE.RouteError):
                ROUTE.load_job(path, ROUTE.preflight.sha256(path))

    def test_worker_can_read_descriptor_without_private_coordinator_state(self):
        _, _, path = self.fixture()
        (path.parent / "state.json").unlink()
        job, state = ROUTE.load_job(path, ROUTE.preflight.sha256(path), read_state=False)
        self.assertTrue(job["internal_engine_only"])
        self.assertEqual(state, {})

    def test_worker_environment_removes_credentials_and_admin_profile_case_variants(self):
        job, _, _ = self.fixture()
        inherited = {"SystemRoot": r"C:\Windows", "UserProfile": r"C:\Users\Administrator",
                     "PATH": "safe", "GH_TOKEN": "not-real", "PYTHONPATH": "foreign"}
        with patch.dict(ROUTE.os.environ, inherited, clear=True):
            environment = ROUTE.job_environment(job)
        self.assertNotIn("GH_TOKEN", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("UserProfile", environment)
        self.assertEqual(environment["USERPROFILE"], str(Path(job["workspace"]) / "profile"))
        self.assertEqual(environment["MOZ_OBJDIR"], job["objdir"])
        self.assertEqual(environment["MOZCONFIG"], str(ROOT / "build/windows/mozconfig.engine-test"))

    def test_source_freeze_and_full_lto_command_path_use_release_context(self):
        job, _, _ = self.fixture("engine-test")
        commands = ROUTE.build_commands(job)
        self.assertEqual([item[0] for item in commands], ["configure", "build"])
        self.assertEqual(commands[1][1], [job["python"], str(ROUTE.SOURCE / "mach"), "build", "-j4"])
        self.assertEqual(ROUTE.build_commands({**job, "phase": "isolation-selftest"}), [])
        full = {**job, "phase": "full-lto", "internal_engine_only": False}
        self.assertEqual(
            ROUTE.build_commands(full),
            [
                ("configure", [job["python"], str(ROUTE.SOURCE / "mach"), "configure"]),
                ("build", [job["python"], str(ROUTE.SOURCE / "mach"), "build", "-j4"]),
                ("repack", [job["python"], str(ROUTE.SOURCE / "mach"), "build", "installers-ru"]),
            ],
        )
        self.assertEqual(ROUTE.object_context(job["id"], "full-lto").base_mozconfig,
                         ROOT / "build/windows/mozconfig.release-lto")
        rendered = ROUTE.object_context(job["id"]).render("engine-test")
        self.assertIn("mozconfig.engine-test", rendered)
        self.assertIn("not Russian UI evidence", rendered)

    def test_full_lto_workflow_requires_recovered_binding_and_keeps_private_key_step_scoped(self):
        workflow = (ROOT / ".github/workflows/m13-06-windows-full-lto.yml").read_text()
        self.assertIn("runs-on: [self-hosted, Windows, X64, goodbear]", workflow)
        self.assertIn("--phase full-lto", workflow)
        self.assertIn("--selftest-receipt-sha256", workflow)
        self.assertIn("GOODBEAR_SAFE_BROWSING_API_KEY: ${{ secrets.GOODBEAR_SAFE_BROWSING_API_KEY }}", workflow)
        self.assertIn("C:\\GoodBear\\m15-03-operation-cache", workflow)
        self.assertNotIn("RUNNER_TEMP", workflow)
        self.assertIn("collect --output $output", workflow)
        self.assertIn("candidate and redacted native evidence", workflow)
        self.assertIn("[Text.Encoding]::ASCII", workflow)
        self.assertNotIn("[Text.ASCIIEncoding]::new($false)", workflow)
        self.assertIn("& icacls.exe $operation /setowner '*S-1-5-32-544' /Q", workflow)
        self.assertIn("/inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F'", workflow)
        self.assertLess(workflow.index("& icacls.exe $operation /setowner"),
                        workflow.index("WriteAllText($key"))

    def test_private_acl_callback_carries_its_explicit_trusted_root(self):
        target = self.jobs / "a" / "private-inputs" / "safebrowsing.key"
        verifier = ROUTE.bounded_private_acl_verifier(self.backend, self.jobs, "S-1-5-21-test")
        self.assertTrue(verifier(target, "private-key"))
        self.assertEqual(self.backend.acl_checks[-1],
                         (target, "private-key", "S-1-5-21-test", self.jobs))

    def test_r42_overlay_current_hashes_continue_from_r41_outputs(self):
        workflow = (ROOT / ".github/workflows/m13-06-windows-source-overlay-r42.yml").read_text()
        expected_current = {
            "tools/preflight_m15_cloud_windows.py": "3d835c586c606700a823c379a9113aae8d3febdfdf9d2804cb1d158b4f12300c",
            "tools/run_m13_cloud_windows.py": "b9d1b8915fd052a7d384b003bd2e7923535208adfff36becb5824be06eb86bf4",
            "tools/windows_offline_worker.py": "4b8c9790efb4cdb09a03939133534fa6d46f3c5d179fb2de412d9118594cb3d6",
        }
        for path, digest in expected_current.items():
            self.assertIn(f"'{path}' = '{digest}'", workflow)
        self.assertIn("PREVIOUS_RECORD: 6cab7c7b313af95b9db3c4b1c4f76c4e83b8dde169d98180252858d13d2302d5", workflow)
        self.assertIn("overlay current file differs: ", workflow)
        self.assertIn("actual=' + $currentHash", workflow)
        self.assertIn("$validated = @()", workflow)
        self.assertIn("$currentHash -ne $item.sha256", workflow)
        self.assertLess(workflow.index("$validated = @()"),
                        workflow.index("Copy-Item -LiteralPath $entry.Replacement"))

    def test_worker_uses_a_named_runtime_cache_instead_of_tmp(self):
        job, _, _ = self.fixture()
        environment = ROUTE.job_environment(job)
        self.assertTrue(environment["TEMP"].endswith("runtime-cache"))
        self.assertEqual(environment["TEMP"], environment["TMP"])

    def test_successful_engine_exit_requires_new_boot_before_any_restore(self):
        _, state, path = self.execute()
        events = self.backend.events
        self.assertLess(events.index("create-account"), events.index("disable-account"))
        self.assertLess(events.index("disable-account"), events.index("block"))
        self.assertLess(events.index("block"), events.index("enable-account"))
        self.assertLess(events.index("enable-account"), events.index("start-child"))
        self.assertLess(events.index("close-child"), events.index("disable-account", 3))
        self.assertLess(events.index("disable-account", 3), events.index("reboot"))
        self.assertNotIn("restore", events)
        self.assertEqual(state["exit_code"], 0)
        self.assertEqual(state["recovery_required"], "different-boot")
        self.assertFalse(ROUTE.preflight.load(path.parent / "state.json")["network_restored"])

    def test_failed_offline_check_never_starts_a_child(self):
        self.backend.rule = False
        _, state, _ = self.execute()
        self.assertIn("create-account", self.backend.events)
        self.assertIn("disable-account", self.backend.events)
        self.assertNotIn("start-child", self.backend.events)
        self.assertIn("reboot", self.backend.events)
        self.assertEqual(state["status"], "failed")

    def test_partial_disconnection_failure_uses_reboot_recovery(self):
        self.backend.fail = "block"
        _, state, _ = self.execute()
        self.assertTrue(state["network_transition_started"])
        self.assertIn("reboot", self.backend.events)
        self.assertNotIn("restore", self.backend.events)

    def test_timeout_and_uncertain_job_cleanup_never_restore_same_boot(self):
        for failure in ("wait-child", "close-child"):
            with self.subTest(failure=failure):
                # Separate fixtures keep the evidence files independent.
                job, state, path = self.fixture()
                worker = FakeJob(self.backend, fail=failure)
                ROUTE.execute_offline(job, state, path, self.backend, job_factory=lambda _: worker)
                self.assertIn("reboot", self.backend.events)
                self.assertNotIn("restore", self.backend.events)
                self.assertEqual(state["status"], "failed")
                import shutil
                shutil.rmtree(path.parent)
                shutil.rmtree(Path(job["workspace"]))
                self.backend.events.clear()

    def test_pre_disconnect_account_disable_failure_never_touches_network(self):
        self.backend.fail = "disable-account"
        _, state, _ = self.execute()
        self.assertIn("error", state)
        self.assertFalse(state["network_transition_started"])
        self.assertFalse(state["network_restored"])
        self.assertNotIn("block", self.backend.events)
        self.assertNotIn("reboot", self.backend.events)

    def test_same_boot_watchdog_only_requests_reboot(self):
        job, state, path = self.fixture()
        ROUTE.recover(job, state, path, self.backend)
        self.assertEqual(self.backend.events, ["inventory", "disable-account", "reboot"])
        self.assertFalse(state["network_restored"])

    def test_new_boot_restores_only_after_quiescence_and_account_removal(self):
        job, state, path = self.recovered_fixture()
        ROUTE.recover(job, state, path, self.backend)
        events = self.backend.events
        self.assertLess(events.index("quiescence"), events.index("remove-account"))
        self.assertLess(events.index("remove-account"), events.index("restore"))
        self.assertLess(events.index("restore"), events.index("remove-tasks"))
        self.assertTrue(state["network_restored"])
        self.assertEqual(state["recovered_boot"], "boot-b")

    def test_new_boot_unproven_process_quiescence_blocks_restore(self):
        job, state, path = self.recovered_fixture()
        self.backend.quiescent = False
        with self.assertRaisesRegex(ROUTE.RouteError, "quiescence"):
            ROUTE.recover(job, state, path, self.backend)
        self.assertNotIn("restore", self.backend.events)

    def test_new_boot_account_cleanup_failure_blocks_restore(self):
        job, state, path = self.recovered_fixture()
        self.backend.fail = "remove-account"
        with self.assertRaisesRegex(NATIVE.NativeError, "remove-account"):
            ROUTE.recover(job, state, path, self.backend)
        self.assertNotIn("restore", self.backend.events)

    def test_new_boot_adapter_identity_drift_blocks_restore(self):
        job, state, path = self.recovered_fixture()
        self.backend.current["adapters"][0]["guid"] = "replacement"
        with self.assertRaisesRegex(ROUTE.RouteError, "adapter identities"):
            ROUTE.recover(job, state, path, self.backend)
        self.assertNotIn("restore", self.backend.events)

    def test_new_boot_missing_firewall_evidence_blocks_restore(self):
        job, state, path = self.recovered_fixture()
        self.backend.rule = False
        with self.assertRaisesRegex(ROUTE.RouteError, "neither offline nor already restored"):
            ROUTE.recover(job, state, path, self.backend)
        self.assertNotIn("restore", self.backend.events)

    def test_new_boot_already_restored_network_allows_cleanup_without_receipt(self):
        job, state, path = self.recovered_fixture()
        self.backend.rule = False
        self.backend.current = inventory(boot="boot-b")
        ROUTE.recover(job, state, path, self.backend)
        self.assertIn("remove-account", self.backend.events)
        self.assertIn("remove-tasks", self.backend.events)
        self.assertNotIn("restore", self.backend.events)
        self.assertTrue(state["network_restored"])
        self.assertEqual(state["recovery_mode"], "already-restored-cleanup-only")

    def test_collect_requires_recovery_and_excludes_binaries_and_source(self):
        job, state, path = self.fixture()
        output = self.base / "returned-evidence"
        with self.assertRaisesRegex(ROUTE.RouteError, "reboot recovery"):
            ROUTE.collect(job, state, path, output)
        workspace = Path(job["workspace"])
        (workspace / "build.log").write_text("actual fixture build output\n")
        (workspace / "firefox.exe").write_bytes(b"not-a-real-binary")
        (workspace / "source.tar").write_bytes(b"not-a-real-source")
        state.update(status="finished", exit_code=0, network_restored=True)
        ROUTE.collect(job, state, path, output)
        self.assertTrue((output / "build.log").is_file())
        self.assertFalse((output / "firefox.exe").exists())
        self.assertFalse((output / "source.tar").exists())
        self.assertEqual(ROUTE.preflight.load(output / "sha256.json")["product_artifacts"], [])

    def test_full_lto_collect_returns_only_the_exact_recorded_nsis_candidate(self):
        job, state, path = self.fixture("full-lto")
        workspace = Path(job["workspace"])
        for name in ("configure.log", "build.log", "repack.log"):
            (workspace / name).write_text(name + "\n")
        dist = ROUTE.object_context(job["id"], "full-lto").objdir / "dist"
        dist.mkdir(parents=True)
        installer = dist / "goodbear-156.0.ru.win64.installer.exe"
        installer.write_bytes(b"verified native installer")
        record = ROUTE.product_record(installer)
        ROUTE.atomic_json(workspace / "worker-result.json", {
            "phase": "full-lto", "job_id": job["id"], "product_artifacts": [record],
        })
        state.update(status="finished", exit_code=0, network_restored=True)
        output = self.base / "returned-full-lto"
        ROUTE.collect(job, state, path, output)
        returned = output / "candidate" / ROUTE.WINDOWS_CANDIDATE_FILENAME
        self.assertEqual(returned.read_bytes(), installer.read_bytes())
        products = ROUTE.preflight.load(output / "sha256.json")["product_artifacts"]
        self.assertEqual(products, [{"path": "candidate/GoodBear Setup 1.0+firefox156.0 x64 ru.exe",
                                     "sha256": ROUTE.preflight.sha256(installer),
                                     "bytes": installer.stat().st_size,
                                     "kind": "windows-nsis-full-installer"}])
        installer.write_bytes(b"substituted")
        with self.assertRaisesRegex(ROUTE.RouteError, "product record differs"):
            ROUTE.collect(job, state, path, self.base / "tampered-full-lto")

    def test_parser_requires_exact_pins_and_explicit_timeout(self):
        good = ["arm", "--phase", "configure", "--manifest", "m", "--bundle", "b",
                "--expected-manifest-sha256", "a" * 64, "--expected-bundle-sha256", "b" * 64,
                "--timeout-minutes", "10"]
        args = ROUTE.parser().parse_args(good)
        self.assertEqual(args.timeout_minutes, 10)
        for option in ("--expected-manifest-sha256", "--expected-bundle-sha256", "--timeout-minutes"):
            missing = good.copy()
            index = missing.index(option)
            del missing[index:index + 2]
            with self.subTest(option=option), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                ROUTE.parser().parse_args(missing)

    def test_acl_provisioning_parser_requires_exact_pins_and_output(self):
        good = ["acl-provisioning-preflight", "--manifest", "m", "--bundle", "b",
                "--expected-manifest-sha256", "a" * 64, "--expected-bundle-sha256", "b" * 64,
                "--output", "receipt"]
        args = ROUTE.parser().parse_args(good)
        self.assertEqual(args.action, "acl-provisioning-preflight")
        self.assertEqual(args.output, Path("receipt"))
        for option in ("--expected-manifest-sha256", "--expected-bundle-sha256", "--output"):
            missing = good.copy()
            index = missing.index(option)
            del missing[index:index + 2]
            with self.subTest(option=option), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                ROUTE.parser().parse_args(missing)

    def test_native_wait_failure_cannot_be_interpreted_as_a_successful_exit(self):
        worker = NATIVE.NativeJob.__new__(NATIVE.NativeJob)
        worker.process = object()
        worker.kernel = argparse.Namespace(WaitForSingleObject=lambda *_: 0xFFFFFFFF)
        with self.assertRaisesRegex(NATIVE.NativeError, "wait failed"):
            worker.wait(0, lambda: None)

    def test_direct_build_call_cannot_skip_worker_identity_and_job_membership(self):
        job, _, path = self.fixture()
        with patch.object(ROUTE, "require_native"), \
                patch.object(ROUTE, "assert_worker", side_effect=NATIVE.NativeError("outside exact job")), \
                patch.object(ROUTE, "network_selftest") as network:
            with self.assertRaisesRegex(NATIVE.NativeError, "outside exact job"):
                ROUTE.run_build(job, path)
        network.assert_not_called()

    def test_private_acl_trusted_root_uses_one_windows_separator(self):
        backend = NATIVE.WindowsBackend()
        calls = []

        def record(script, values=None, **kwargs):
            calls.append((script, values, kwargs))
            return {"ok": True, "reason": None}

        with patch.object(NATIVE, "powershell", side_effect=record):
            self.assertTrue(backend.verify_private_acl(
                Path(r"C:\GoodBear\m15-03-private-source\native-offline-jobs\a" * 32),
                "selftest-receipt", trusted_root=Path(r"C:\GoodBear\m15-03-private-source\native-offline-jobs")))
        script = calls[0][0]
        one = "$target.StartsWith($stop+'" + "\\" + "',[StringComparison]"
        two = "$target.StartsWith($stop+'" + "\\\\" + "',[StringComparison]"
        self.assertIn(one, script)
        self.assertNotIn(two, script)

    def test_native_administration_error_does_not_expose_private_payload(self):
        process = unittest.mock.Mock(returncode=1)
        process.communicate.return_value = ("private account password", "private PowerShell error")
        with patch.object(NATIVE, "require_native"), patch.dict(NATIVE.os.environ, {"SystemRoot": "system"}), \
                patch.object(NATIVE.subprocess, "Popen", return_value=process):
            with self.assertRaises(NATIVE.NativeError) as failure:
                NATIVE.powershell("fixed-reviewed-script", {"password": "private account password"})
        self.assertNotIn("private account password", str(failure.exception))
        self.assertNotIn("private PowerShell error", str(failure.exception))

    def test_create_account_uses_native_account_interface_and_labels_each_acl_boundary(self):
        backend = NATIVE.WindowsBackend()
        calls = []

        def record(script, values=None, **kwargs):
            calls.append((script, values, kwargs))
            return "S-1-5-21-test" if len(calls) == 1 else None

        with patch.object(NATIVE, "powershell", side_effect=record):
            sid = backend.create_account("gb-test", "private-password", Path("root"),
                                         Path("workspace"), Path("a" * 32))

        self.assertEqual(sid, "S-1-5-21-test")
        self.assertIn("net.exe user $p.name $p.password /add", calls[0][0])
        self.assertIn("/comment:", calls[0][0])
        self.assertIn("NetUserGetInfo", calls[0][0])
        self.assertNotIn("/expires:", calls[0][0])
        self.assertNotIn("/passwordchg:", calls[0][0])
        self.assertNotIn("Get-CimInstance", calls[0][0])
        self.assertNotIn("New-LocalUser", calls[0][0])
        self.assertIn("net.exe localgroup $p.group $p.name /add", calls[0][0])
        self.assertIn("/remove:d", calls[1][0])
        self.assertIn("/grant:r", calls[1][0])
        self.assertEqual([call[2]["safe_label"] for call in calls], [
            "restricted worker account creation",
            "restricted worker workspace ACL isolation",
            "restricted worker job traversal ACL isolation",
            "restricted worker descriptor read ACL",
        ])
        self.assertEqual(calls[0][1]["password"], "private-password")

    def test_native_worker_password_is_short_and_has_required_character_classes(self):
        with patch.object(ROUTE.secrets, "token_hex", return_value="abcdef1234"):
            password = ROUTE.native_worker_password()
        self.assertEqual(password, "Gb1!abcdef1234")
        self.assertEqual(len(password), 14)
        self.assertRegex(password, r"[A-Z]")
        self.assertRegex(password, r"[a-z]")
        self.assertRegex(password, r"[0-9]")
        self.assertRegex(password, r"[^A-Za-z0-9]")

    def test_worker_owner_is_exact_and_fits_net_user_comment_limit(self):
        identifier = "a" * 32
        self.assertEqual(NATIVE.worker_owner(identifier), "GBN:" + identifier)
        self.assertLessEqual(len(NATIVE.worker_owner(identifier)), 48)
        with self.assertRaisesRegex(NATIVE.NativeError, "ownership identifier"):
            NATIVE.worker_owner("invalid")

    def test_timed_out_native_administration_is_not_successful_cleanup(self):
        process = unittest.mock.Mock(returncode=0)
        process.communicate.side_effect = [NATIVE.subprocess.TimeoutExpired("native", 15), ("", "")]
        output = io.StringIO()
        with patch.object(NATIVE, "require_native"), patch.dict(NATIVE.os.environ, {"SystemRoot": "system"}), \
                patch.object(NATIVE.subprocess, "Popen", return_value=process), \
                patch.object(NATIVE.time, "monotonic", side_effect=[0, 121]), redirect_stdout(output):
            with self.assertRaisesRegex(NATIVE.NativeError, "cleanup is unproven"):
                NATIVE.powershell("fixed-reviewed-script", {"password": "never-log-this"})
        process.kill.assert_called_once_with()
        self.assertNotIn("never-log-this", output.getvalue())
        self.assertIn("121s", output.getvalue())


if __name__ == "__main__":
    unittest.main()

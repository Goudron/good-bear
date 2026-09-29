#!/usr/bin/env python3
"""Arm a native Cloud Windows configure/engine job with whole-VM isolation.

The arm command is an explicit Windows mutation. It does not start a Cloud VM.
Configure/engine execution requires an exact protected native selftest receipt
from this VM after successful reboot recovery. A scheduled SYSTEM coordinator disconnects
every non-loopback adapter before starting an unprivileged child. Networking
returns only in a different boot after recovery; runner control is offline meanwhile.
Full LTO additionally requires current M13-01..05 evidence.
"""

from __future__ import annotations

import argparse
import ast
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import preflight_m15_cloud_windows as preflight
from host_build_context import (SOURCE, L10N_BASE, ARTIFACTS, HostBuildContext,
                               load_safebrowsing_contract)
from safebrowsing_build_input import (BuildInputError, EffectiveMozconfig,
                                     create_effective_mozconfig, verify_effective_mozconfig,
                                     verify_key_file)
from windows_offline_worker import (NativeError, NativeJob, WindowsBackend, assert_worker,
                                    require_native, trusted_python_command)

JOBS_ROOT = ROOT.parent / "native-offline-jobs"
PHASES = ("isolation-selftest", "configure", "engine-test", "full-lto")
REQUIRED_FROZEN = {*preflight.REQUIRED_PYTHON_OWNERS,
                   "build/windows/mozconfig.engine-test", "build/windows/mozconfig.release-lto",
                   "config/m13-03-decision-coverage-contract.json",
                   "config/m15-12-safebrowsing-build-input.json"}
EXPORTED_FILES = ("job.json", "state.json", "controller.log", "context.log", "configure.log", "build.log", "repack.log",
                  "worker-result.json", "selftest-result.json", "recovered-selftest.json")
# Keep the user-facing Windows candidate aligned with the canonical Good Bear /
# Firefox version pair used by the Linux package and product identity.
WINDOWS_CANDIDATE_FILENAME = "GoodBear Setup 1.0+firefox156.0 x64 ru.exe"


class RouteError(RuntimeError):
    pass


class CloudEngineContext(HostBuildContext):
    # The SYSTEM coordinator proves the worker SID's read-only ACL on both
    # private files before it cuts networking.  A contained ordinary worker
    # must not spawn an administrative PowerShell child merely to repeat that
    # proof: on Server Core that child can be denied despite the checked ACL.
    @property
    def base_mozconfig(self) -> Path:
        return ROOT / ("build/windows/mozconfig.release-lto"
                       if self.release_lto else "build/windows/mozconfig.engine-test")

    @property
    def private_input_dir(self) -> Path:
        return JOBS_ROOT / self.objdir.parent.name / "private-inputs"

    def validate_safebrowsing(self) -> None:
        require(self._safebrowsing is not None, "native configure requires a verified private supplier input")
        contract, digest = load_safebrowsing_contract()
        require(digest == self._supplier_contract_sha256 and
                contract["key_file_sha256"] == self._safebrowsing.key_sha256 and
                self._safebrowsing.base_path == self.base_mozconfig and
                self._safebrowsing.path.parent == self.private_input_dir,
                "private supplier input differs from the canonical native context")
        backend = WindowsBackend()
        verifier = (lambda _path, _purpose: True) if os.environ.get("GOODBEAR_WORKER_ACL_PREVERIFIED") == "1" else \
            bounded_private_acl_verifier(backend, JOBS_ROOT, backend.current_user_sid())
        verify_effective_mozconfig(
            self._safebrowsing,
            windows_acl_verifier=verifier)

    def validate(self, *, job: dict, frozen: dict) -> None:
        require(self.objdir == object_context(job["id"], job["phase"]).objdir and str(self.objdir) == job["objdir"],
                "native object directory differs from canonical context")
        require(job.get("source") == str(SOURCE) and SOURCE.is_dir() and (SOURCE / "mach").is_file(),
                "native canonical source/mach is absent")
        require(self.mozconfig.is_file() and not self.mozconfig.is_symlink() and
                L10N_BASE.is_dir() and (L10N_BASE / "ru").is_dir(),
                "native engine mozconfig or Russian locale input is absent")
        evidence = job.get("preflight", {})
        require(evidence.get("preflight_passed") is True and evidence.get("m3_04") == "passed" and
                evidence.get("installed_tools") and evidence.get("toolchain_cache") and
                evidence.get("frozen_source") == frozen, "native context lacks matching frozen/preflight/M3 evidence")
        if job["phase"] != "isolation-selftest":
            self.validate_safebrowsing()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RouteError(message)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("w", encoding="utf-8") as output:
        output.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def workspace_for(identifier: str) -> Path:
    return ARTIFACTS / "native-offline-jobs" / identifier


def bounded_private_acl_verifier(backend: WindowsBackend, trusted_root: Path,
                                 worker_sid: str | None = None):
    """Return an ACL verifier that cannot inspect beyond a sealed boundary."""
    boundary = Path(trusted_root)
    return lambda path, purpose: backend.verify_private_acl(
        Path(path), purpose, worker_sid, trusted_root=boundary)


def protect_jobs_root(backend: WindowsBackend) -> None:
    """Create a trusted ACL boundary for durable job evidence.

    SYSTEM recovery must not have to trust owners of the source workspace or
    other higher-level VM directories.  The root has disabled inheritance and
    is owned by Administrators before any child job is created; ACL validation
    may therefore stop there after checking that root itself.
    """
    JOBS_ROOT.mkdir(parents=True, exist_ok=True)
    backend.protect_job(JOBS_ROOT)


ACL_PROVISIONING_RECEIPT = ROOT.parent / "m13-06-acl-provisioning-preflight.json"
ACL_BOUNDARIES = ("source-group", "workspace", "stage", "descriptor", "private-input", "worker-probe", "worker-io")


def require_acl_provisioning_preflight(args: argparse.Namespace, inventory: dict) -> None:
    """Bind arming to a completed no-network ACL provisioning exercise."""
    require(ACL_PROVISIONING_RECEIPT.is_file() and not ACL_PROVISIONING_RECEIPT.is_symlink(),
            "exact-source ACL provisioning preflight receipt is absent")
    receipt = load_bounded_record(ACL_PROVISIONING_RECEIPT)
    expected = {"schema_version": 1, "kind": "windows-acl-provisioning-preflight",
                "manifest_sha256": args.expected_manifest_sha256,
                "bundle_sha256": args.expected_bundle_sha256,
                "executor_sha256": preflight.sha256(Path(__file__)),
                "worker_helper_sha256": preflight.sha256(ROOT / "tools/windows_offline_worker.py"),
                "vm_identity_sha256": inventory["vm_identity_sha256"],
                "boundaries": list(ACL_BOUNDARIES), "passed": True}
    require(receipt == expected, "ACL provisioning preflight receipt does not bind this exact source and VM")


def write_acl_provisioning_receipt(args: argparse.Namespace, inventory: dict, output: Path | None) -> dict:
    receipt = {"schema_version": 1, "kind": "windows-acl-provisioning-preflight",
               "manifest_sha256": args.expected_manifest_sha256,
               "bundle_sha256": args.expected_bundle_sha256,
               "executor_sha256": preflight.sha256(Path(__file__)),
               "worker_helper_sha256": preflight.sha256(ROOT / "tools/windows_offline_worker.py"),
               "vm_identity_sha256": inventory["vm_identity_sha256"],
               "boundaries": list(ACL_BOUNDARIES), "passed": True}
    atomic_json(ACL_PROVISIONING_RECEIPT, receipt)
    if output is not None:
        output.mkdir(parents=True, exist_ok=False)
        atomic_json(output / "acl-provisioning-preflight.json", receipt)
    return receipt


def acl_provisioning_preflight(args: argparse.Namespace, backend: WindowsBackend) -> dict:
    """Exercise all worker ACL transitions before any firewall/adapter mutation."""
    require_native()
    evidence = verify_inputs(args)
    inventory = backend.inventory()
    check_cloud_inventory(inventory)
    protect_jobs_root(backend)
    identifier = uuid.uuid4().hex
    stage = JOBS_ROOT / identifier
    workspace = workspace_for(identifier)
    private = stage / "private-inputs"
    descriptor = stage / "job.json"
    job = {"id": identifier, "worker_account": "gbpre" + identifier[:12]}
    sid: str | None = None
    cleanup_error: Exception | None = None
    try:
        stage.mkdir(parents=True, exist_ok=False)
        backend.protect_job(stage)
        workspace.mkdir(parents=True, exist_ok=False)
        atomic_json(descriptor, {"kind": "acl-provisioning-preflight", "id": identifier})
        private.mkdir(mode=0o700, exist_ok=False)
        backend.protect_job(private)
        probe = private / "probe.txt"
        probe.write_text("Good Bear ACL provisioning preflight\n", encoding="ascii")
        worker_probe = stage / "worker-acl-probe.py"
        worker_result = workspace / "worker-acl-probe-result.json"
        worker_probe.write_text(
            "from pathlib import Path\nimport json, sys\n"
            "marker, descriptor, private_probe, workspace, result = map(Path, sys.argv[1:])\n"
            "phase = 'launcher-or-script'\n"
            "try:\n"
            "    for phase, item in (('marker', marker), ('descriptor', descriptor), ('private-input', private_probe)):\n"
            "        with item.open('rb') as source: source.read(1)\n"
            "    phase = 'workspace'\n"
            "    target = workspace / 'worker-acl-probe.tmp'\n"
            "    target.write_bytes(b'GoodBear')\n"
            "    if target.read_bytes() != b'GoodBear': raise RuntimeError('workspace round-trip failed')\n"
            "    target.unlink()\n"
            "except Exception:\n"
            "    result.write_text(json.dumps({'phase': phase}), encoding='ascii')\n"
            "    raise\n"
            "result.write_text(json.dumps({'phase': 'passed'}), encoding='ascii')\n", encoding="ascii")
        backend.seal_new_job(stage)
        password = native_worker_password()
        sid = backend.create_account(job["worker_account"], password, ROOT, workspace, stage,
                                     provision_workspace=False, provision_stage=False,
                                     provision_descriptor=False)
        backend.disable_account(job, sid)
        failures: list[str] = []
        for boundary, operation in (
            ("workspace", lambda: backend.provision_worker_workspace_acl(workspace, sid)),
            ("stage", lambda: backend.provision_worker_stage_acl(stage, sid)),
            ("descriptor", lambda: backend.grant_worker_descriptor_read(stage, sid)),
            ("private-input", lambda: backend.grant_private_inputs(private, sid)),
            ("worker-probe", lambda: backend.grant_worker_probe_read(worker_probe, sid)),
        ):
            try:
                operation()
            except (NativeError, OSError, ValueError):
                failures.append(boundary)
        if not failures:
            try:
                require(backend.verify_provisioning_boundaries(ROOT, workspace, stage, descriptor, worker_probe, probe, sid),
                        "ACL provisioning boundary verification failed")
            except (NativeError, RouteError, OSError, ValueError):
                failures.append("effective-acl")
        if not failures:
            try:
                lock = preflight.load(ROOT / "config/m15-03-windows-toolchain-lock.json")
                worker_python = Path(lock["install_root"]) / "Python312/python.exe"
                backend.enable_account(job, sid)
                worker_io_ok = backend.verify_worker_io(
                    "Global\\GoodBear-ACL-Probe-" + identifier, job["worker_account"], password, sid,
                    [str(worker_python), "-I", "-S", "-B", "-u", str(worker_probe),
                     str(SOURCE / ".good-bear-materialization.json"), str(descriptor), str(probe), str(workspace),
                     str(worker_result)], ROOT, preflight.native_environment())
            except (NativeError, RouteError, OSError, ValueError):
                failures.append("worker-io:launcher-or-script")
            else:
                if not worker_io_ok:
                    phase = "launcher-or-script"
                    if worker_result.is_file():
                        record = json.loads(worker_result.read_text(encoding="ascii"))
                        if record.get("phase") in {"marker", "descriptor", "private-input", "workspace"}:
                            phase = record["phase"]
                    failures.append("worker-io:" + phase)
            finally:
                backend.disable_account(job, sid)
        # The password is needed only until the bounded worker-I/O probe has exited.
        password = ""
        backend.remove_account(job, sid, ROOT, stage)
        sid = None
        require(not failures, "ACL provisioning boundary failures: " + ",".join(failures))
    finally:
        if sid is not None:
            try:
                backend.disable_account(job, sid)
                backend.remove_account(job, sid, ROOT, stage)
                sid = None
            except Exception as exc:
                cleanup_error = exc
        for directory in (workspace, stage):
            if directory.exists():
                try:
                    shutil.rmtree(directory)
                except Exception as exc:
                    cleanup_error = cleanup_error or exc
    if cleanup_error is not None:
        raise RouteError("ACL provisioning preflight cleanup is unproven") from cleanup_error
    require(not stage.exists() and not workspace.exists(), "ACL provisioning preflight cleanup is incomplete")
    receipt = write_acl_provisioning_receipt(args, inventory, args.output)
    print(json.dumps({"acl_provisioning_preflight": "passed", "boundaries": receipt["boundaries"]}), flush=True)
    return {**receipt, "preflight": evidence}


def object_context(identifier: str, phase: str = "engine-test") -> CloudEngineContext:
    validate_phase(phase)
    return CloudEngineContext.create(workspace_for(identifier) / "obj-engine",
                                     release_lto=phase == "full-lto")


def validate_phase(phase: str) -> None:
    require(phase in PHASES, "unknown native build phase")


def validate_execution_phase(phase: str, authorization: dict | None = None) -> None:
    validate_phase(phase)
    if phase != "isolation-selftest":
        require(isinstance(authorization, dict) and authorization.get("kind") == "recovered-native-selftest",
                "configure/engine execution requires an exact selftest with successful reboot recovery")


def check_cloud_inventory(inventory: dict) -> None:
    require(bool(preflight.HEX256.fullmatch(inventory.get("vm_identity_sha256", ""))),
            "stable VM/OS identity is missing")
    require(inventory.get("cpus") == 4, "Cloud worker must retain the pinned four CPUs")
    require(15 * 1024**3 <= inventory.get("memory_bytes", 0) <= 16 * 1024**3,
            "Cloud worker memory differs from the pinned 16 GiB flavor")
    require(bool(inventory.get("boot")) and isinstance(inventory.get("adapters"), list)
            and inventory["adapters"] and isinstance(inventory.get("loopback"), list)
            and inventory["loopback"], "incomplete native boot/adapter inventory")
    profiles = inventory.get("firewall_profiles", [])
    require(len(profiles) == 3 and all(item.get("enabled") is True for item in profiles),
            "all native firewall profiles must already be enabled")


def assert_offline(inventory: dict, original: dict, rule_active: bool) -> None:
    require(rule_active, "owned whole-VM outbound deny is not active")
    require(inventory.get("boot") == original.get("boot"), "boot changed during offline build")
    require({item["guid"] for item in inventory.get("adapters", [])} ==
            {item["guid"] for item in original["adapters"]}, "adapter inventory changed during offline build")
    loopback = set(inventory.get("loopback", []))
    require(loopback and not inventory.get("connected"), "a non-loopback IP interface remains connected")
    adapters = {item["index"]: item for item in inventory["adapters"]}
    require(all(item["enabled"] is False for item in adapters.values() if item["index"] not in loopback),
            "a non-loopback adapter remains administratively enabled")
    require(all(route["index"] in loopback or
                (route["index"] in adapters and adapters[route["index"]]["enabled"] is False)
                for route in inventory.get("routes", [])),
            "a non-loopback route has no verified disabled adapter")


def verify_inputs(args: argparse.Namespace) -> dict:
    evidence = preflight.run(args)
    manifest = preflight.load(args.manifest)
    entries = {item["path"] for item in manifest["declared_inputs"]}
    require(REQUIRED_FROZEN.issubset(entries), "snapshot lacks the reviewed Cloud executor/helper/engine mozconfig")
    return evidence


def selftest_binding(job: dict) -> dict:
    return {"manifest_sha256": job["expected_manifest_sha256"],
            "bundle_sha256": job["expected_bundle_sha256"],
            "executor_sha256": job["executor_sha256"], "helper_sha256": job["helper_sha256"],
            "frozen_source": job["preflight"]["frozen_source"],
            "toolchain_sha256": preflight.toolchain_fingerprint(job["preflight"]),
            "vm_identity_sha256": job["original_network"]["vm_identity_sha256"]}


def load_bounded_record(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink() and not
            getattr(path, "is_junction", lambda: False)() and path.stat().st_nlink == 1,
            "evidence must be one regular non-linked file")
    with path.open("rb") as stream:
        content = stream.read(65537)
    require(len(content) <= 65536, "evidence exceeds its size bound")
    record = json.loads(content)
    require(isinstance(record, dict), "evidence must be an object")
    return record


def validate_selftest_result(result: dict, job: dict, digest: str) -> None:
    require(result.get("phase") == "isolation-selftest" and result.get("job_id") == job["id"]
            and result.get("job_sha256") == digest and result.get("internal_engine_only") is True
            and result.get("product_artifacts") == [] and result.get("public_release_allowed") is False
            and result.get("completed_utc") and "error" not in result,
            "selftest result does not bind the successful exact job")
    probes = result.get("native_network_probe", {})
    require(isinstance(probes, dict) and set(probes) == {"ipv4", "ipv6", "loopback"}
            and all(type(probes[name]) is int and probes[name] in {10013, 10050, 10051}
                    for name in ("ipv4", "ipv6")) and probes["loopback"] == "passed",
            "selftest lacks native denial and loopback positive controls")


def verified_selftest(reference: dict, target_job: dict, backend: WindowsBackend) -> dict:
    require(isinstance(reference, dict) and set(reference) == {"job_id", "job_sha256", "receipt_sha256"},
            "exact recovered selftest reference is required")
    require(bool(re.fullmatch(r"[0-9a-f]{32}", reference.get("job_id", ""))) and
            all(bool(preflight.HEX256.fullmatch(reference.get(name, "")))
                for name in ("job_sha256", "receipt_sha256")), "invalid recovered selftest hashes")
    stage = JOBS_ROOT / reference["job_id"]
    for name in ("job.json", "state.json", "selftest-result.json", "recovered-selftest.json"):
        require(backend.verify_private_acl(stage / name, "selftest-receipt", trusted_root=JOBS_ROOT),
                "recovered selftest is not protected native evidence")
    previous, state = load_job(stage / "job.json", reference["job_sha256"])
    receipt_path = stage / "recovered-selftest.json"
    require(preflight.sha256(receipt_path) == reference["receipt_sha256"], "selftest receipt hash differs")
    receipt = load_bounded_record(receipt_path)
    result_path = stage / "selftest-result.json"
    validate_selftest_result(load_bounded_record(result_path), previous, reference["job_sha256"])
    require(previous["phase"] == "isolation-selftest" and receipt.get("schema_version") == 1
            and receipt.get("kind") == "recovered-native-selftest"
            and receipt.get("job_sha256") == reference["job_sha256"]
            and receipt.get("state_sha256") == preflight.sha256(stage / "state.json")
            and receipt.get("result_sha256") == preflight.sha256(result_path),
            "selftest receipt does not bind its native evidence")
    require(state.get("status") == "finished" and type(state.get("exit_code")) is int
            and state["exit_code"] == 0 and state.get("worker_started") is True
            and state.get("network_transition_started") is True and state.get("worker_sid")
            and not any(name in state for name in ("error", "cleanup_error", "recovery_error"))
            and state.get("network_restored") is True
            and state.get("recovery_checks") == {"quiescent": True, "account_removed": True, "tasks_removed": True},
            "selftest did not finish and recover successfully")
    require(receipt.get("original_boot") == previous["original_network"]["boot"]
            and receipt.get("recovered_boot") == state.get("recovered_boot")
            and receipt["original_boot"] != receipt["recovered_boot"], "selftest lacks a different-boot recovery")
    require(receipt.get("binding") == selftest_binding(previous) == selftest_binding(target_job),
            "selftest source/toolchain/VM binding differs; rerun the selftest")
    return {"kind": "recovered-native-selftest", "reference": reference, "binding": receipt["binding"]}


def validate_job_authorization(job: dict) -> None:
    authorization = job.get("isolation_authorization")
    validate_execution_phase(job["phase"], authorization)
    if job["phase"] != "isolation-selftest":
        require(authorization.get("binding") == selftest_binding(job),
                "immutable job lacks matching selftest authorization")


def publish_selftest_receipt(job: dict, state: dict, path: Path, backend: WindowsBackend) -> None:
    if (job["phase"] != "isolation-selftest" or state.get("status") != "finished"
            or type(state.get("exit_code")) is not int or state["exit_code"] != 0):
        return
    require(not any(name in state for name in ("error", "cleanup_error", "recovery_error")),
            "failed cleanup cannot authorize another execution")
    require(state.get("network_restored") is True and state.get("worker_started") is True
            and state.get("network_transition_started") is True and state.get("worker_sid")
            and state.get("recovery_checks") == {"quiescent": True, "account_removed": True, "tasks_removed": True}
            and isinstance(state.get("recovered_boot"), str) and state["recovered_boot"]
            and state["recovered_boot"] != job["original_network"]["boot"],
            "incomplete recovery cannot publish a selftest receipt")
    require(backend.verify_private_acl(path.parent, "selftest-receipt", trusted_root=JOBS_ROOT),
            "selftest stage is not protected")
    digest = preflight.sha256(path)
    result = load_bounded_record(Path(job["workspace"]) / "worker-result.json")
    validate_selftest_result(result, job, digest)
    result_path = path.parent / "selftest-result.json"
    receipt_path = path.parent / "recovered-selftest.json"
    require(not result_path.exists() and not receipt_path.exists(), "selftest receipt cannot be replaced")
    atomic_json(result_path, result)
    receipt = {"schema_version": 1, "kind": "recovered-native-selftest", "job_sha256": digest,
               "binding": selftest_binding(job), "original_boot": job["original_network"]["boot"],
               "recovered_boot": state["recovered_boot"], "state_sha256": preflight.sha256(path.parent / "state.json"),
               "result_sha256": preflight.sha256(result_path)}
    atomic_json(receipt_path, receipt)
    require(backend.verify_private_acl(receipt_path, "selftest-receipt", trusted_root=JOBS_ROOT),
            "new selftest receipt is not protected")


def private_input_paths(job: dict) -> tuple[Path, Path]:
    directory = JOBS_ROOT / job["id"] / "private-inputs"
    return directory / "safebrowsing.key", directory / "effective-mozconfig"


def prepare_private_inputs(args: argparse.Namespace, job: dict, backend: WindowsBackend) -> dict:
    contract, contract_digest = load_safebrowsing_contract()
    require(args.safebrowsing_contract_sha256 == contract_digest, "explicit supplier contract hash differs")
    external_root = Path(args.safebrowsing_key_file).parent
    external_acl = bounded_private_acl_verifier(backend, external_root)
    checked = verify_key_file(args.safebrowsing_key_file, contract["key_file_sha256"],
                              forbidden_roots=(ROOT, SOURCE), windows_acl_verifier=external_acl)
    key_path, wrapper = private_input_paths(job)
    key_path.parent.mkdir(mode=0o700, exist_ok=False)
    backend.protect_job(key_path.parent)
    with checked.path.open("rb") as stream:
        data = stream.read(129)
    require(len(data) == checked.size and hashlib.sha256(data).hexdigest() == checked.sha256,
            "private input changed before native staging")
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    staged_acl = bounded_private_acl_verifier(backend, JOBS_ROOT)
    key = verify_key_file(key_path, checked.sha256, forbidden_roots=(ROOT, SOURCE),
                          windows_acl_verifier=staged_acl)
    base = object_context(job["id"], job["phase"]).base_mozconfig
    binding = create_effective_mozconfig(base_mozconfig=base, expected_base_sha256=preflight.sha256(base),
                                        key_input=key, wrapper_path=wrapper, source_root=SOURCE,
                                        windows_acl_verifier=staged_acl)
    return {**binding.evidence(), "supplier_contract_sha256": contract_digest,
            "key_file": str(key_path), "mozconfig": str(wrapper)}


def private_context(job: dict, backend: WindowsBackend, *, worker_acl_preverified: bool = False) -> CloudEngineContext:
    context = object_context(job["id"], job["phase"])
    if job["phase"] == "isolation-selftest":
        require(not job.get("private_build_inputs"), "selftest cannot consume private supplier inputs")
        return context
    record = job.get("private_build_inputs", {})
    key_path, wrapper = private_input_paths(job)
    contract, digest = load_safebrowsing_contract()
    require(record.get("key_file") == str(key_path) and record.get("mozconfig") == str(wrapper)
            and record.get("supplier_contract_sha256") == digest
            and record.get("safebrowsing_keyfile_sha256") == contract["key_file_sha256"],
            "native private input descriptor differs from the supplier contract")
    acl = (lambda _path, _purpose: True) if worker_acl_preverified else \
        bounded_private_acl_verifier(backend, JOBS_ROOT, backend.current_user_sid())
    key = verify_key_file(key_path, record["safebrowsing_keyfile_sha256"],
                          forbidden_roots=(ROOT, SOURCE), windows_acl_verifier=acl)
    binding = EffectiveMozconfig(context.base_mozconfig, record["base_mozconfig_sha256"],
                                wrapper, record["effective_mozconfig_sha256"], key.sha256, SOURCE, key)
    verify_effective_mozconfig(binding, windows_acl_verifier=acl)
    return replace(context, _safebrowsing=binding, _supplier_contract_sha256=digest)


def verify_configured_private_input(context: CloudEngineContext) -> None:
    context.validate_safebrowsing()
    path = context.objdir / "config.status"
    require(path.is_file() and not path.is_symlink(), "native config.status is unavailable")
    with path.open("rb") as stream:
        contents = stream.read(8 * 1024 * 1024 + 1)
    require(len(contents) <= 8 * 1024 * 1024, "native config.status exceeds its size bound")
    try:
        typed_substs = {"CC_TYPE": "CompilerType", "HOST_CC_TYPE": "CompilerType",
                        "WASM_CC_TYPE": "CompilerType", "CPU_ARCH": "RaiseErrorOnUse",
                        "HOST_CPU_ARCH": "CPU", "TARGET_CPU": "CPU", "HOST_OS_ARCH": "Kernel",
                        "TARGET_KERNEL": "Kernel", "TARGET_ENDIANNESS": "Endianness", "TARGET_OS": "OS"}
        def parse_substs(value):
            try:
                parsed = ast.literal_eval(value)
                if isinstance(parsed, dict):
                    return parsed
            except (ValueError, TypeError):
                pass
            require(isinstance(value, ast.Dict), "unsupported native config.status substs")
            result = {}
            for key, item in zip(value.keys, value.values):
                name = ast.literal_eval(key)
                require(isinstance(name, str) and name not in result, "unsupported native config.status substs key")
                if name == "MOZ_GOOGLE_SAFEBROWSING_API_KEY":
                    result[name] = ast.literal_eval(item)
                    continue
                try:
                    ast.literal_eval(item)
                    continue
                except (ValueError, TypeError):
                    expected = typed_substs.get(name)
                    require(expected and isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and
                            item.func.id == expected and not item.keywords and len(item.args) == 1 and
                            isinstance(item.args[0], ast.Constant) and isinstance(item.args[0].value, str),
                            "unsupported native config.status substs value")
        values = {}
        allowed = {"substs", "defines", "mozconfig", "topobjdir", "topsrcdir", "__all__"}
        generated_import = ast.dump(ast.parse("from mozbuild.configure.constants import *").body[0])
        generated_main = ast.dump(ast.parse(
            "if __name__ == '__main__':\n"
            "    from mozbuild.config_status import config_status\n"
            "    args = dict([(name, globals()[name]) for name in __all__])\n"
            "    config_status(**args)\n").body[0])
        import_count = main_count = 0
        for node in ast.parse(contents).body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name in allowed:
                    require(name not in values, "ambiguous native configure input")
                    values[name] = parse_substs(node.value) if name == "substs" else ast.literal_eval(node.value)
                    continue
            if ast.dump(node) == generated_import:
                import_count += 1
            elif ast.dump(node) == generated_main:
                main_count += 1
            else:
                raise RouteError("unsupported native config.status statement; configure again")
        require(set(values) == allowed and import_count == 1 and main_count <= 1
                and values.get("__all__") == ["topobjdir", "topsrcdir", "defines", "substs", "mozconfig"]
                and values.get("mozconfig") == str(context.mozconfig)
                and values.get("topobjdir") == str(context.objdir) and values.get("topsrcdir") == str(SOURCE)
                and isinstance(values.get("substs"), dict)
                and context.configured_safebrowsing_key_matches(values["substs"].get("MOZ_GOOGLE_SAFEBROWSING_API_KEY")),
                "native configure did not bind the verified private input")
    except (ValueError, TypeError, SyntaxError, UnicodeError, RecursionError, MemoryError):
        raise RouteError("unsupported native config.status; configure again with the private input") from None


def run_redacted_command(command: list[str], environment: dict, output: Path,
                         context: CloudEngineContext) -> int:
    redactor = context.safebrowsing_log_redactor()
    with output.open("wb") as stream:
        process = subprocess.Popen(command, cwd=SOURCE, env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        assert process.stdout is not None
        with process.stdout:
            for chunk in iter(lambda: process.stdout.read(65536), b""):
                stream.write(redactor.feed(chunk))
                stream.flush()
        stream.write(redactor.finish())
        return process.wait()


def make_job(args: argparse.Namespace, inventory: dict, evidence: dict, identifier: str) -> dict:
    validate_phase(args.phase)
    require(bool(re.fullmatch(r"[0-9a-f]{32}", identifier)), "invalid job identity")
    require(1 <= args.timeout_minutes <= 360, "native job timeout must be explicit and within 1..360 minutes")
    now = utc_now()
    return {"schema_version": 1, "kind": "native-cloud-engine-job", "id": identifier,
            "phase": args.phase, "created_utc": now.isoformat(),
            "not_before": (now + timedelta(seconds=60)).isoformat(),
            "deadline": (now + timedelta(minutes=args.timeout_minutes, seconds=60)).isoformat(),
            "timeout_seconds": args.timeout_minutes * 60, "source_root": str(ROOT),
            "source": str(SOURCE), "workspace": str(workspace_for(identifier)),
            "objdir": str(object_context(identifier, args.phase).objdir),
            "python": str(Path(preflight.load(ROOT / "config/m15-03-windows-toolchain-lock.json")["install_root"]) / "Python312/python.exe"),
            "executor": str(Path(__file__).resolve()), "executor_sha256": preflight.sha256(Path(__file__)),
            "helper_sha256": preflight.sha256(ROOT / "tools/windows_offline_worker.py"),
            "manifest": str(args.manifest.resolve()), "bundle": str(args.bundle.resolve()),
            "expected_manifest_sha256": args.expected_manifest_sha256,
            "expected_bundle_sha256": args.expected_bundle_sha256,
            "worker_task": "GoodBear-Offline-Worker-" + identifier,
            "watchdog_task": "GoodBear-Offline-Recovery-" + identifier,
            "firewall_rule": "GoodBear-Offline-Deny-" + identifier,
            "job_object": "Global\\GoodBear-Offline-" + identifier,
            "worker_account": "gbeng" + identifier[:12], "original_network": inventory,
            "preflight": evidence, "internal_engine_only": args.phase != "full-lto",
            "product_artifacts": [], "public_release_allowed": False}


def native_worker_password() -> str:
    """Generate a short, complex password compatible with Server Core net.exe.

    The native local-account API on the Windows builder rejects the long
    token_urlsafe values used elsewhere.  Four fixed character classes plus
    five random bytes rendered as hex give a 14-character password with 40
    bits of fresh entropy for the short, isolated worker lifetime.
    """
    return "Gb1!" + secrets.token_hex(5)


def arm(args: argparse.Namespace, backend: WindowsBackend) -> Path:
    require_native()
    validate_phase(args.phase)
    if args.phase != "isolation-selftest":
        require(all(getattr(args, name, None) for name in
                    ("selftest_job_id", "selftest_job_sha256", "selftest_receipt_sha256")),
                "configure/engine execution requires an exact selftest with successful reboot recovery")
        require(getattr(args, "safebrowsing_key_file", None) is not None and
                bool(preflight.HEX256.fullmatch(getattr(args, "safebrowsing_contract_sha256", "") or "")),
                "configure/engine requires an explicit private key file and supplier contract hash")
    else:
        require(not getattr(args, "safebrowsing_key_file", None) and not getattr(args, "safebrowsing_contract_sha256", None),
                "selftest must not consume a private key")
    with backend.arm_lock():
        if JOBS_ROOT.exists():
            for stage in JOBS_ROOT.iterdir():
                if not stage.is_dir() or stage.is_symlink():
                    raise RouteError("unexpected native job directory entry")
                state_path = stage / "state.json"
                require(state_path.is_file(), "incomplete prior job requires review before another arm")
                previous = preflight.load(state_path)
                require(previous.get("network_restored") is True or previous.get("status") == "registration-rolled-back",
                        "a previous native job has not completed recovery")
        return arm_locked(args, backend)


def arm_locked(args: argparse.Namespace, backend: WindowsBackend) -> Path:
    evidence = verify_inputs(args)
    inventory = backend.inventory()
    check_cloud_inventory(inventory)
    require_acl_provisioning_preflight(args, inventory)
    protect_jobs_root(backend)
    identifier = uuid.uuid4().hex
    job = make_job(args, inventory, evidence, identifier)
    if args.phase != "isolation-selftest":
        reference = {"job_id": args.selftest_job_id, "job_sha256": args.selftest_job_sha256,
                     "receipt_sha256": args.selftest_receipt_sha256}
        job["isolation_authorization"] = verified_selftest(reference, job, backend)
    stage = JOBS_ROOT / identifier
    stage.mkdir(parents=True, exist_ok=False)
    backend.protect_job(stage)
    workspace_for(identifier).mkdir(parents=True, exist_ok=False)
    if args.phase != "isolation-selftest":
        job["private_build_inputs"] = prepare_private_inputs(args, job, backend)
    path = stage / "job.json"
    atomic_json(path, job)
    digest = preflight.sha256(path)
    state = {"status": "prepared", "launch_requested": False, "network_transition_started": False,
             "network_restored": False, "worker_started": False, "worker_sid": None}
    atomic_json(stage / "state.json", state)
    backend.seal_new_job(stage)
    registered = False
    try:
        backend.register_tasks(job, path, digest)
        registered = True
        # From this durable point onward a failed Start-ScheduledTask is
        # ambiguous. Do not roll back tasks or restore networking by assumption.
        state.update(status="launch-requested", launch_requested=True)
        atomic_json(stage / "state.json", state)
        print(json.dumps({"job": str(path), "job_sha256": digest,
                          "network_disconnect_not_before": job["not_before"]}), flush=True)
        backend.launch(job)
    except Exception:
        if registered and not state["launch_requested"]:
            backend.remove_tasks(job)
        if not state["launch_requested"]:
            # register_tasks verifies rollback itself. On any uncertain native
            # failure leave the job pending; an operator must inspect it.
            state["status"] = "registration-failed-review-required"
            atomic_json(stage / "state.json", state)
        raise
    return path


def load_job(path: Path, digest: str, *, read_state: bool = True) -> tuple[dict, dict]:
    require(path.resolve().parent.parent == JOBS_ROOT.resolve() and path.name == "job.json"
            and not path.is_symlink(), "job must be an owned native-offline-jobs descriptor")
    require(bool(preflight.HEX256.fullmatch(digest)) and preflight.sha256(path) == digest,
            "immutable job descriptor hash differs")
    job = preflight.load(path)
    identifier = path.parent.name
    require(bool(re.fullmatch(r"[0-9a-f]{32}", identifier)) and job.get("id") == identifier,
            "job identity differs from its owned directory")
    require(job.get("schema_version") == 1 and job.get("kind") == "native-cloud-engine-job",
            "unknown native job descriptor")
    # Recovery/status must remain usable even if a build authorization receipt
    # has since become unavailable. Only execution entry points consume it.
    validate_phase(job.get("phase"))
    require(job.get("source_root") == str(ROOT) and job.get("source") == str(SOURCE)
            and job.get("executor") == str(Path(__file__).resolve()), "job source/executor path differs")
    require(job.get("executor_sha256") == preflight.sha256(Path(__file__)) and
            job.get("helper_sha256") == preflight.sha256(ROOT / "tools/windows_offline_worker.py"),
            "native executor implementation changed after arming")
    require(job.get("workspace") == str(workspace_for(identifier)) and
            job.get("objdir") == str(object_context(identifier, job["phase"]).objdir), "job workspace/objdir escaped canonical stage")
    for field, expected in {"worker_task": "GoodBear-Offline-Worker-" + identifier,
                            "watchdog_task": "GoodBear-Offline-Recovery-" + identifier,
                            "firewall_rule": "GoodBear-Offline-Deny-" + identifier,
                            "job_object": "Global\\GoodBear-Offline-" + identifier,
                            "worker_account": "gbeng" + identifier[:12]}.items():
        require(job.get(field) == expected, "native job owned identity differs: " + field)
    require(job.get("product_artifacts") == [] and job.get("public_release_allowed") is False,
            "native route cannot authorize a public product")
    require(job.get("internal_engine_only") is (job["phase"] != "full-lto"),
            "native job phase/product classification differs")
    expected_python = Path(preflight.load(ROOT / "config/m15-03-windows-toolchain-lock.json")["install_root"]) / "Python312/python.exe"
    require(job.get("python") == str(expected_python), "job does not use the pinned Python")
    require(isinstance(job.get("timeout_seconds"), int) and 60 <= job["timeout_seconds"] <= 21600,
            "job timeout is outside the approved bounds")
    return job, preflight.load(path.parent / "state.json") if read_state else {}


def job_environment(job: dict) -> dict[str, str]:
    # Windows names are case insensitive. Do not retain a second inherited
    # spelling of an administrator's profile or PATH next to its replacement.
    environment = {key.upper(): value for key, value in preflight.native_environment().items()}
    work = Path(job["workspace"])
    for name, relative in {"USERPROFILE": "profile", "APPDATA": "profile/AppData/Roaming",
                           "LOCALAPPDATA": "profile/AppData/Local", "TEMP": "runtime-cache", "TMP": "runtime-cache"}.items():
        destination = work / relative
        destination.mkdir(parents=True, exist_ok=True)
        environment[name] = str(destination)
    environment.update({"MOZ_OBJDIR": job["objdir"], "MOZCONFIG": job.get("private_build_inputs", {}).get(
                            "mozconfig", str(ROOT / "build/windows/mozconfig.engine-test")),
                        "GOODBEAR_L10N_BASE": str(L10N_BASE), "MOZBUILD_STATE_PATH": str(work / "mozbuild"),
                        "MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE": "system", "MOZILLABUILD": r"C:\mozilla-build",
                        "PYTHONDONTWRITEBYTECODE": "1", "PIP_NO_INDEX": "1", "CARGO_NET_OFFLINE": "true",
                        "GOODBEAR_WORKER_ACL_PREVERIFIED": "1"})
    return environment


def execute_offline(job: dict, state: dict, path: Path, backend: WindowsBackend,
                    job_factory=NativeJob) -> None:
    native_job = None
    try:
        inventory = backend.inventory()
        require(inventory.get("system") is True, "offline coordinator must be the scheduled SYSTEM task")
        require(inventory.get("boot") == job["original_network"]["boot"], "armed job belongs to another boot")
        require(inventory.get("vm_identity_sha256") == job["original_network"]["vm_identity_sha256"],
                "armed VM/OS identity changed")
        validate_job_authorization(job)
        if job["phase"] != "isolation-selftest":
            actual = verified_selftest(job["isolation_authorization"]["reference"], job, backend)
            require(actual == job["isolation_authorization"], "coordinator selftest authorization changed")
            private_context(job, backend).validate_safebrowsing()
        # Provision and disable the exact worker before the first network
        # mutation.  ACL or Job Object failures must therefore be reversible
        # while the administrative channel is still available.
        password = native_worker_password()
        workspace = Path(job["workspace"])
        environment = job_environment(job)
        state["worker_sid"] = backend.create_account(job["worker_account"], password, ROOT, workspace, path.parent)
        backend.disable_account(job, state["worker_sid"])
        if job.get("private_build_inputs"):
            key_path, wrapper = private_input_paths(job)
            backend.grant_private_inputs(key_path.parent, state["worker_sid"])
            for private_path, purpose in ((key_path, "worker-private-key"),
                                          (wrapper, "worker-effective-mozconfig")):
                require(backend.verify_private_acl(private_path, purpose, state["worker_sid"],
                                                   trusted_root=JOBS_ROOT),
                        "coordinator could not prove the worker private-input ACL")
        native_job = job_factory(job["job_object"])
        native_job.allow_worker_query(state["worker_sid"])
        # Persist before the first firewall/adapter mutation; any partial
        # disconnect must take the reboot recovery path.
        state.update(status="disconnecting", original_boot=inventory["boot"], network_transition_started=True)
        atomic_json(path.parent / "state.json", state)
        backend.block_network(job)
        assert_offline(backend.inventory(), job["original_network"], backend.rule_active(job))
        backend.enable_account(job, state["worker_sid"])
        state.update(status="worker-starting", worker_started=True)
        atomic_json(path.parent / "state.json", state)
        command = trusted_python_command(
            job["python"], Path(job["executor"]),
            ["--job", str(path), "--job-sha256", preflight.sha256(path),
             "--worker-acl-preverified", "_build"], path.parent)
        native_job.start(job["worker_account"], password, command, SOURCE, environment)
        password = ""
        last_heartbeat = [0.0]

        def heartbeat():
            if time.monotonic() - last_heartbeat[0] >= 15:
                assert_offline(backend.inventory(), job["original_network"], backend.rule_active(job))
                with (path.parent / "controller.log").open("a", encoding="utf-8") as output:
                    output.write(utc_now().isoformat() + " offline worker active\n")
                last_heartbeat[0] = time.monotonic()

        remaining = (datetime.fromisoformat(job["deadline"]) - utc_now()).total_seconds()
        require(remaining > 0, "offline deadline expired before the worker could complete")
        code = native_job.wait(time.monotonic() + min(remaining, job["timeout_seconds"]), heartbeat)
        state.update(status="finished" if code == 0 else "failed", exit_code=code)
    except Exception as exc:
        state.update(status="failed", error=type(exc).__name__ + ": " + str(exc))
    finally:
        if native_job is not None:
            try:
                native_job.close()
            except Exception as exc:
                state.update(status="failed", cleanup_error=type(exc).__name__ + ": " + str(exc))
        if state.get("network_transition_started"):
            try:
                backend.disable_account(job, state.get("worker_sid"))
                state["recovery_required"] = "different-boot"
                atomic_json(path.parent / "state.json", state)
                backend.reboot()
            except Exception as exc:
                state["recovery_error"] = type(exc).__name__ + ": " + str(exc)
                atomic_json(path.parent / "state.json", state)
        else:
            atomic_json(path.parent / "state.json", state)


def recover(job: dict, state: dict, path: Path, backend: WindowsBackend) -> None:
    inventory = backend.inventory()
    require(inventory.get("system") is True, "recovery must run as the registered SYSTEM task")
    require(inventory.get("vm_identity_sha256") == job["original_network"]["vm_identity_sha256"],
            "recovery VM/OS identity differs")
    backend.disable_account(job, state.get("worker_sid"))
    if inventory["boot"] == job["original_network"]["boot"]:
        # A deadline watchdog never attempts same-boot network restoration.
        state["recovery_required"] = "different-boot"
        atomic_json(path.parent / "state.json", state)
        backend.reboot()
        return
    require(backend.quiescent_after_boot(job, state.get("worker_sid")),
            "fresh-boot worker quiescence is unproven; networking remains disabled")
    require({item["guid"] for item in inventory["adapters"]} ==
            {item["guid"] for item in job["original_network"]["adapters"]},
            "adapter identities changed; manual recovery is required")
    expected_adapters = {item["guid"]: item["enabled"] for item in job["original_network"]["adapters"]}
    observed_adapters = {item["guid"]: item["enabled"] for item in inventory["adapters"]}
    offline = state.get("network_transition_started") and backend.rule_active(job)
    if offline:
        assert_offline(inventory, {**job["original_network"], "boot": inventory["boot"]}, True)
    elif state.get("network_transition_started"):
        # A human may have removed the owned deny rule to restore a stranded
        # machine.  This is cleanup-only: it never publishes a selftest
        # receipt, yet it permits removal of the exact disabled account/tasks.
        require(backend.owned_rule_absent(job) and observed_adapters == expected_adapters,
                "native network state is neither offline nor already restored")
    # Remove the disabled ephemeral identity and its exact ACL entries before
    # reopening any adapter. Failure leaves the machine offline for review.
    backend.remove_account(job, state.get("worker_sid"), ROOT, path.parent)
    if offline:
        backend.restore_network(job)
        restored = backend.inventory()
        require(restored.get("vm_identity_sha256") == inventory["vm_identity_sha256"]
                and restored.get("boot") == inventory["boot"] and backend.owned_rule_absent(job)
                and {item["guid"]: item["enabled"] for item in restored["adapters"]} == expected_adapters,
                "native network restoration is unproven")
    backend.remove_tasks(job)
    state.update(network_restored=True, recovered_boot=inventory["boot"], recovered_utc=utc_now().isoformat())
    state["recovery_checks"] = {"quiescent": True, "account_removed": True, "tasks_removed": True}
    state["recovery_mode"] = "automatic-offline" if offline else "already-restored-cleanup-only"
    atomic_json(path.parent / "state.json", state)
    if offline:
        publish_selftest_receipt(job, state, path, backend)


def network_selftest() -> dict:
    results = {}
    for name, family, address in (("ipv4", socket.AF_INET, ("192.0.2.1", 443)),
                                  ("ipv6", socket.AF_INET6, ("2001:db8::1", 443))):
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            code = connection.connect_ex(address)
            require(code in {10013, 10050, 10051}, "offline socket probe did not report a native access/network denial")
            results[name] = code
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=3) as client:
            accepted, _ = server.accept()
            with accepted:
                client.sendall(b"offline-local-probe")
                require(accepted.recv(32) == b"offline-local-probe", "loopback positive control failed")
    results["loopback"] = "passed"
    return results


def release_installer(context: CloudEngineContext) -> Path:
    """Return the one NSIS installer produced by this fresh full-LTO objdir."""
    dist = context.objdir / "dist"
    require(dist.is_dir() and not dist.is_symlink(), "native release dist directory is unavailable")
    candidates = sorted(
        item for item in dist.glob("*.installer.exe")
        if item.is_file() and not item.is_symlink() and item.stat().st_nlink == 1
    )
    require(len(candidates) == 1,
            "full-LTO Russian repack must produce exactly one regular NSIS installer in objdir/dist")
    return candidates[0]


def product_record(installer: Path) -> dict:
    return {"kind": "windows-nsis-full-installer", "source": str(installer),
            "sha256": preflight.sha256(installer), "bytes": installer.stat().st_size}


def build_commands(job: dict) -> list[tuple[str, list[str]]]:
    validate_phase(job["phase"])
    commands = []
    if job["phase"] != "isolation-selftest":
        commands.append(("configure", [job["python"], str(SOURCE / "mach"), "configure"]))
    if job["phase"] == "engine-test":
        commands.append(("build", [job["python"], str(SOURCE / "mach"), "build", "-j4"]))
    elif job["phase"] == "full-lto":
        commands.extend((
            ("build", [job["python"], str(SOURCE / "mach"), "build", "-j4"]),
            ("repack", [job["python"], str(SOURCE / "mach"), "build", "installers-ru"]),
        ))
    return commands


def run_build(job: dict, path: Path, *, worker_acl_preverified: bool = False) -> None:
    require_native()
    validate_job_authorization(job)
    assert_worker(job)
    # Administrative inventory/rule checks run in the SYSTEM coordinator
    # before resume and every 15 seconds, not under the non-admin build token.
    workspace = Path(job["workspace"])
    result = {"native_network_probe": network_selftest(), "phase": job["phase"],
              "job_id": job["id"], "job_sha256": preflight.sha256(path),
              "internal_engine_only": job["internal_engine_only"], "native_tests_executed": False,
              "product_artifacts": [], "public_release_allowed": False}
    # Recheck frozen source bytes inside the disconnected worker before configure.
    args = argparse.Namespace(**{key: job[key] for key in ("expected_manifest_sha256", "expected_bundle_sha256")})
    args.manifest, args.bundle = Path(job["manifest"]), Path(job["bundle"])
    frozen = preflight.verify_frozen_source(ROOT, SOURCE, args.manifest, args.bundle,
                                           args.expected_manifest_sha256, args.expected_bundle_sha256)
    require(worker_acl_preverified, "build worker lacks coordinator ACL proof")
    context = private_context(job, WindowsBackend(), worker_acl_preverified=True)
    context.validate(job=job, frozen=frozen)
    context_text = context.render("russian-repack" if job["phase"] == "full-lto" else "engine-test")
    (workspace / "context.log").write_text(context_text + "\n", encoding="utf-8")
    print(context_text, flush=True)
    commands = build_commands(job)
    if not commands:
        result["completed_utc"] = utc_now().isoformat()
        atomic_json(workspace / "worker-result.json", result)
        return
    result["private_input_digests"] = context.safebrowsing_evidence()
    environment = job_environment(job)
    lock = preflight.load(ROOT / "config/m15-03-windows-toolchain-lock.json")
    tools = Path(lock["install_root"])
    vsdev = tools.parent / "vs-buildtools/Common7/Tools/VsDevCmd.bat"
    require(not any(ch in str(vsdev) for ch in '&|<>^%!\r\n"'), "unsafe Visual Studio environment path")
    setup = subprocess.run([str(Path(environment["SYSTEMROOT"]) / "System32/cmd.exe"), "/d", "/s", "/c",
                            f'call "{vsdev}" -no_logo -arch=x64 -host_arch=x64 >nul && set'],
                           env=environment, text=True, capture_output=True, check=False)
    require(setup.returncode == 0, "pinned Visual Studio environment initialization failed")
    for line in setup.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key and not key.startswith("="):
                environment[key.upper()] = value
    components = preflight.components(lock)
    llvm = tools / f"clang+llvm-{components['llvm']['version']}-x86_64-pc-windows-msvc/bin"
    rust_version = components["rust"]["version"].removesuffix("-x86_64-pc-windows-msvc")
    environment.update(CC=str(llvm / "clang-cl.exe"), CXX=str(llvm / "clang-cl.exe"),
                       LINKER=str(llvm / "lld-link.exe"), RUSTC=str(tools / f"rust-{rust_version}/bin/rustc.exe"),
                       CARGO=str(tools / f"rust-{rust_version}/bin/cargo.exe"),
                       NODEJS=str(tools / f"node-v{components['node']['version']}-win-x64/node.exe"))
    pinned_bins = [llvm, Path(job["python"]).parent, tools / f"rust-{rust_version}/bin",
                   tools / f"node-v{components['node']['version']}-win-x64",
                   tools / f"nasm-{components['nasm']['version']}", Path(components["git-for-windows"]["executable"]).parent]
    environment["PATH"] = ";".join(map(str, pinned_bins)) + ";" + environment["PATH"]
    environment["MOZCONFIG"] = str(context.mozconfig)
    for name in ("MOZ_CONFIGURE_OPTIONS", "MOZ_GOOGLE_SAFEBROWSING_API_KEY", "GOODBEAR_SAFEBROWSING_KEY_FILE"):
        environment.pop(name, None)
    for phase, command in commands:
        context.validate(job=job, frozen=frozen)
        if phase != "configure":
            verify_configured_private_input(context)
        code = run_redacted_command(command, environment, workspace / (phase + ".log"), context)
        require(code == 0, f"native {phase} failed; inspect the redacted local log")
        verify_configured_private_input(context)
    if job["phase"] == "full-lto":
        result["product_artifacts"] = [product_record(release_installer(context))]
    result["completed_utc"] = utc_now().isoformat()
    atomic_json(workspace / "worker-result.json", result)


def collect(job: dict, state: dict, path: Path, output: Path) -> None:
    require(state.get("network_restored") is True, "evidence collection waits for verified reboot recovery")
    require(state.get("status") == "finished" and state.get("exit_code") == 0,
            "product collection requires a successful native job")
    output = output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "collection requires a new path outside frozen source")
    output.mkdir(parents=True)
    hashes = {}
    for name in EXPORTED_FILES:
        source = path.parent / name
        if name in {"context.log", "configure.log", "build.log", "repack.log", "worker-result.json"}:
            source = Path(job["workspace"]) / name
        if source.is_file() and not source.is_symlink():
            shutil.copyfile(source, output / name)
            hashes[name] = preflight.sha256(output / name)
    products = []
    if job["phase"] == "full-lto":
        result = load_bounded_record(Path(job["workspace"]) / "worker-result.json")
        installer = release_installer(object_context(job["id"], job["phase"]))
        expected = product_record(installer)
        require(result.get("phase") == "full-lto" and result.get("job_id") == job["id"]
                and result.get("product_artifacts") == [expected] and "error" not in result,
                "native full-LTO product record differs from the exact installer")
        relative = Path("candidate") / WINDOWS_CANDIDATE_FILENAME
        target = output / relative
        target.parent.mkdir()
        shutil.copyfile(installer, target)
        products = [{"path": relative.as_posix(), "sha256": preflight.sha256(target),
                     "bytes": target.stat().st_size, "kind": expected["kind"]}]
        require(products[0]["sha256"] == expected["sha256"] and products[0]["bytes"] == expected["bytes"],
                "returned Windows candidate differs from the native full-LTO installer")
        hashes[relative.as_posix()] = products[0]["sha256"]
    atomic_json(output / "sha256.json", {"files": hashes, "product_artifacts": products,
                                           "public_release_allowed": False})


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--job", type=Path)
    result.add_argument("--job-sha256")
    result.add_argument("--worker-acl-preverified", action="store_true")
    sub = result.add_subparsers(dest="action", required=True)
    arm_parser = sub.add_parser("arm")
    arm_parser.add_argument("--phase", choices=PHASES, required=True)
    arm_parser.add_argument("--manifest", type=Path, required=True)
    arm_parser.add_argument("--bundle", type=Path, required=True)
    arm_parser.add_argument("--expected-manifest-sha256", required=True)
    arm_parser.add_argument("--expected-bundle-sha256", required=True)
    arm_parser.add_argument("--timeout-minutes", type=int, required=True)
    arm_parser.add_argument("--selftest-job-id")
    arm_parser.add_argument("--selftest-job-sha256")
    arm_parser.add_argument("--selftest-receipt-sha256")
    arm_parser.add_argument("--safebrowsing-key-file", type=Path)
    arm_parser.add_argument("--safebrowsing-contract-sha256")
    acl_parser = sub.add_parser("acl-provisioning-preflight")
    acl_parser.add_argument("--manifest", type=Path, required=True)
    acl_parser.add_argument("--bundle", type=Path, required=True)
    acl_parser.add_argument("--expected-manifest-sha256", required=True)
    acl_parser.add_argument("--expected-bundle-sha256", required=True)
    acl_parser.add_argument("--output", type=Path, required=True)
    sub.add_parser("status")
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--output", type=Path, required=True)
    for name in ("_worker", "_recover", "_build"):
        sub.add_parser(name, help=argparse.SUPPRESS)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        require_native()
        backend = WindowsBackend()
        if args.action == "acl-provisioning-preflight":
            acl_provisioning_preflight(args, backend)
            return 0
        if args.action == "arm":
            arm(args, backend)
            return 0
        require(args.job is not None and args.job_sha256 is not None, "job path and exact descriptor SHA-256 are required")
        job, state = load_job(args.job, args.job_sha256, read_state=args.action != "_build")
        if args.action == "status":
            print(json.dumps(state, indent=2), flush=True)
        elif args.action == "collect":
            collect(job, state, args.job, args.output)
        elif args.action == "_worker":
            with (args.job.parent / "controller.log").open("a", encoding="utf-8", buffering=1) as output, \
                    redirect_stdout(output), redirect_stderr(output):
                remaining = (datetime.fromisoformat(job["not_before"]) - utc_now()).total_seconds()
                if remaining > 0:
                    time.sleep(min(remaining, 60))
                require(utc_now() < datetime.fromisoformat(job["deadline"]), "offline job deadline already expired")
                args_for_preflight = argparse.Namespace(**job)
                args_for_preflight.manifest = Path(job["manifest"])
                args_for_preflight.bundle = Path(job["bundle"])
                current_evidence = verify_inputs(args_for_preflight)
                require(current_evidence.get("frozen_source") == job["preflight"].get("frozen_source") and
                        preflight.toolchain_fingerprint(current_evidence) == preflight.toolchain_fingerprint(job["preflight"]),
                        "coordinator source/toolchain changed after arm")
                require(utc_now() < datetime.fromisoformat(job["deadline"]), "offline job deadline expired during preflight")
                execute_offline(job, state, args.job, backend)
        elif args.action == "_recover":
            with (args.job.parent / "controller.log").open("a", encoding="utf-8", buffering=1) as output, \
                    redirect_stdout(output), redirect_stderr(output):
                recover(job, state, args.job, backend)
        else:
            run_build(job, args.job, worker_acl_preverified=args.worker_acl_preverified)
    except (RouteError, NativeError, BuildInputError, preflight.PreflightError, OSError, ValueError, KeyError) as exc:
        if args.action == "_build" and "job" in locals():
            atomic_json(Path(job["workspace"]) / "worker-result.json",
                        {"phase": job["phase"], "error": str(exc), "product_artifacts": [],
                         "public_release_allowed": False})
        elif args.action in {"_worker", "_recover"} and "job" in locals():
            state.update(status="coordinator-failed", last_error=str(exc))
            atomic_json(args.job.parent / "state.json", state)
            with (args.job.parent / "controller.log").open("a", encoding="utf-8") as output:
                output.write(utc_now().isoformat() + " coordinator failed: " + str(exc) + "\n")
        print("Cloud native route failed: " + str(exc), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

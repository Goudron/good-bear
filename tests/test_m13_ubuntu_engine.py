"""Pure planning/frozen-file negative checks; no Docker, VM or socket execution."""
from argparse import Namespace
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import run_m13_ubuntu_engine as ENGINE


def sha(data):
    return hashlib.sha256(data).hexdigest()


class UbuntuEngineTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="goodbear-engine-test-")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.root = self.parent / "frozen"
        self.root.mkdir()
        self.source = self.root / "source/worktrees/firefox-156.0"
        self.source.mkdir(parents=True)
        self.artifacts = self.root / "artifacts"
        self.objdir = self.artifacts / "development/engine-test"
        self.objdir.mkdir(parents=True)
        self.context = SimpleNamespace(objdir=self.objdir)
        self.key = self.parent / "external.key"
        self.key.write_text("not a key; mount planning fixture only\n")
        self.manifest = self.parent / "source-manifest.json"
        self.bundle = self.parent / "source-bundle.tar"
        self.args = Namespace(phase="engine", objdir=self.objdir, image="sha256:" + "a" * 64,
                              uid=1000, gid=1000, manifest=self.manifest, bundle=self.bundle,
                              safebrowsing_key_file=self.key, expected_manifest_sha256="1" * 64,
                              expected_bundle_sha256="2" * 64, expected_source_marker_sha256="3" * 64,
                              host_netns="net:[123]", run_id="c" * 32, timeout_minutes=10, worker=False)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in {"ROOT": self.root, "SOURCE": self.source, "ARTIFACTS": self.artifacts}.items():
            self.stack.enter_context(mock.patch.object(ENGINE, name, value))
        for path in ENGINE.worker_paths(self.context).values():
            path.mkdir(parents=True)
        self.manifest.touch()
        self.bundle.touch()

    def document(self):
        return {"Image": self.args.image, "AppArmorProfile": "docker-default",
                "Config": {"User": "1000:1000", "Labels": {"goodbear.engine": "owned"}},
                "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                               "CapDrop": ["ALL"], "CapAdd": None,
                               "SecurityOpt": ["no-new-privileges", "apparmor=docker-default"],
                               "PidMode": "", "IpcMode": "private"},
                "Mounts": [{"Source": str(src), "Destination": str(dst), "RW": not readonly}
                           for src, dst, readonly in ENGINE.mounts(self.args, self.context)]}

    def test_plan_requires_immutable_local_image_and_nonroot_user(self):
        command = ENGINE.docker_create(self.args, self.context, self.artifacts / "control", "owned")
        for argument in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                         "--security-opt=no-new-privileges", "--security-opt=apparmor=docker-default",
                         "--cpus=4", "-I", "-S", "-B"):
            self.assertIn(argument, command)
        self.assertEqual(command[:7], ["/usr/bin/sudo", "-n", "--", "/usr/bin/docker",
                                       "--host", "unix:///var/run/docker.sock", "create"])
        for value in ("ubuntu:24.04", "sha256:bad", "docker.io/example@sha256:" + "b" * 64):
            self.args.image = value
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.docker_create(self.args, self.context, self.artifacts / "control", "owned")
        self.args.image = "sha256:" + "a" * 64
        for name in ("uid", "gid"):
            setattr(self.args, name, 0)
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.docker_create(self.args, self.context, self.artifacts / "control", "owned")
            setattr(self.args, name, 1000)

    def test_only_objdir_and_canonical_buildtmp_are_writable_mounts(self):
        plan = ENGINE.mounts(self.args, self.context)
        self.assertEqual({dst for _, dst, ro in plan if not ro},
                         {self.objdir, self.artifacts / "build-tmp"})
        self.assertIn((self.root, self.root, True), plan)
        self.assertIn((self.key, self.key, True), plan)
        self.assertNotIn(Path("/var/run/docker.sock"), {dst for _, dst, _ in plan})

    def test_container_metadata_rejects_every_isolation_weakening(self):
        valid = self.document()
        ENGINE.verify_container(valid, self.args, self.context, "owned")
        changed = copy.deepcopy(valid)
        changed["AppArmorProfile"] = ""
        with self.assertRaises(ENGINE.EngineError):
            ENGINE.verify_container(changed, self.args, self.context, "owned")
        for field, bad in (("NetworkMode", "host"), ("ReadonlyRootfs", False), ("Privileged", True),
                           ("CapDrop", []), ("CapAdd", ["SYS_ADMIN"]), ("SecurityOpt", []),
                           ("PidMode", "host"), ("IpcMode", "host")):
            changed = copy.deepcopy(valid)
            changed["HostConfig"][field] = bad
            with self.subTest(field=field), self.assertRaises(ENGINE.EngineError):
                ENGINE.verify_container(changed, self.args, self.context, "owned")
        for path in ("/var/run/docker.sock", "/home/user1", "/run/dbus"):
            changed = copy.deepcopy(valid)
            changed["Mounts"].append({"Source": path, "Destination": path, "RW": True})
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.verify_container(changed, self.args, self.context, "owned")

    def test_swapped_image_user_and_token_never_pass_container_check(self):
        for field in ("image", "user", "label"):
            document = self.document()
            if field == "image":
                document["Image"] = "sha256:" + "b" * 64
            elif field == "user":
                document["Config"]["User"] = "0:0"
            else:
                document["Config"]["Labels"]["goodbear.engine"] = "someone-else"
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.verify_container(document, self.args, self.context, "owned")

    def test_mount_parser_and_unsafe_paths_fail_closed(self):
        flags = ENGINE.mount_flags("10 1 0:1 / / ro,nosuid - overlay overlay ro\n"
                                   "11 10 0:2 / /work\\040space rw - ext4 /dev/x rw\n")
        self.assertIn("ro", flags["/"])
        self.assertEqual(flags["/work space"], {"rw"})
        for value in (Path("relative"), self.parent / "x,y", self.parent / "bad\npath"):
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.safe_path(value)
        alias = self.parent / "alias"
        alias.symlink_to(self.key)
        with self.assertRaises(ENGINE.EngineError):
            ENGINE.safe_path(alias)

    def test_environment_has_no_inherited_credentials_or_network_fallback(self):
        with mock.patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "secret", "SSH_AUTH_SOCK": "agent",
                                         "DOCKER_HOST": "tcp://external:2375", "PYTHONPATH": "foreign"}):
            environment = ENGINE.clean_environment(ENGINE.worker_paths(self.context))
        for name in ("AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "DOCKER_HOST", "PYTHONPATH"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["PIP_NO_INDEX"], "1")
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE"], "system")
        self.assertEqual(environment["TMPDIR"], str(self.artifacts / "build-tmp"))

    def test_worker_arguments_bind_a_fresh_attempt_and_no_key_value(self):
        arguments = ENGINE.worker_arguments(self.args)
        self.assertEqual(arguments[arguments.index("--run-id") + 1], self.args.run_id)
        self.assertEqual(arguments[arguments.index("--safebrowsing-key-file") + 1], str(self.key))
        self.assertNotIn(self.key.read_text(), " ".join(arguments))
        self.args.run_id = ""
        with self.assertRaisesRegex(ENGINE.EngineError, "attempt identity"):
            ENGINE.worker(self.args)

    def test_nonisolated_native_entry_rejects_before_project_imports(self):
        # This invokes only the entry guard on the local host; no engine/Docker
        # call or positive runtime receipt is produced.
        completed = ENGINE.subprocess.run([sys.executable, "-B", str(Path(ENGINE.__file__).resolve()), "--help"],
                                          text=True, capture_output=True, timeout=10,
                                          env=ENGINE.clean_environment())
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("requires python3 -I -S -B", completed.stderr)

    def test_cli_cannot_select_candidate_package_repack_or_lto(self):
        for action in ("build", "package", "repack", "installers-ru", "full-lto"):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                ENGINE.parser().parse_args([action])

    def test_developer_host_never_reaches_docker(self):
        with mock.patch.object(ENGINE.socket, "gethostname", return_value="local-developer"), \
                mock.patch.object(ENGINE.subprocess, "run") as run:
            with self.assertRaisesRegex(ENGINE.EngineError, "recorded native Ubuntu builder"):
                ENGINE.launch(self.args)
            run.assert_not_called()

    def frozen_fixture(self):
        for relative in ENGINE.REQUIRED:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# fixture\n")
        archive = self.root / "source/firefox-156.0.source.tar.xz"
        archive.write_bytes(b"synthetic archive fixture")
        baseline = {"product": "Firefox Desktop / Gecko", "version": "156.0", "vcs": {"revision": "b" * 40},
                    "source": {"archive_path": archive.relative_to(self.root).as_posix(),
                               "sha256": sha(archive.read_bytes()),
                               "sha512": hashlib.sha512(archive.read_bytes()).hexdigest()}}
        (self.root / "config/firefox-baseline.json").write_text(json.dumps(baseline))
        supplier = {"schema_version": 1, "task": "GB100-M15-12", "supplier": "Google Safe Browsing",
                    "allowed_api_services": ["safebrowsing.googleapis.com"], "key_file_sha256": "f" * 64,
                    "key_value_in_source": False, "key_value_in_build_logs": False,
                    "key_embedded_in_browser_binary_by_design": True}
        supplier_path = self.root / "config/m15-12-safebrowsing-build-input.json"
        supplier_path.write_text(json.dumps(supplier))
        (self.root / "patches/series").write_text("0001-fixture.patch\n")
        patch = self.root / "patches/0001-fixture.patch"
        patch.write_text("# synthetic patch for binding test\n")
        marker = {"version": "156.0", "baseline_config_sha256": sha((self.root / "config/firefox-baseline.json").read_bytes()),
                  "source_sha256": baseline["source"]["sha256"], "source_sha512": baseline["source"]["sha512"],
                  "patches": [{"path": patch.name, "sha256": sha(patch.read_bytes())}], "overlay_files": []}
        (self.source / ".good-bear-materialization.json").write_text(json.dumps(marker))
        (self.source / "browser/config").mkdir(parents=True)
        (self.source / "browser/config/version.txt").write_text("156.0\n")
        self.files = sorted(ENGINE.REQUIRED | {archive.relative_to(self.root).as_posix(),
                                             patch.relative_to(self.root).as_posix()})
        self.upstream = {"product": baseline["product"], "version": "156.0", "revision": "b" * 40,
                         "archive": baseline["source"]["archive_path"], "archive_sha256": baseline["source"]["sha256"]}
        self.rebundle()
        self.args.expected_source_marker_sha256 = sha((self.source / ".good-bear-materialization.json").read_bytes())

    def rebundle(self):
        supplier_path = self.root / "config/m15-12-safebrowsing-build-input.json"
        document = {"task": "GB100-M15-01", "source_commit": "a" * 40, "upstream": self.upstream,
                    "declared_inputs": [{"path": relative, "size": (self.root / relative).stat().st_size,
                                         "sha256": sha((self.root / relative).read_bytes())} for relative in self.files],
                    "private_build_inputs": ENGINE.transport.supplier_binding(json.loads(supplier_path.read_text()),
                                                                                sha(supplier_path.read_bytes()))}
        content = ENGINE.transport.canonical_json(document)
        self.manifest.write_bytes(content)
        ENGINE.transport.write_bundle(self.bundle, content, self.root, document)
        self.args.expected_manifest_sha256 = sha(content)
        self.args.expected_bundle_sha256 = sha(self.bundle.read_bytes())

    def test_real_frozen_file_verification_accepts_consistent_fixture(self):
        self.frozen_fixture()
        with redirect_stdout(io.StringIO()):
            evidence = ENGINE.verify_source(self.args)
        self.assertEqual(evidence["patches"], 1)
        self.assertEqual(evidence["bundle_sha256"], self.args.expected_bundle_sha256)
        self.assertNotIn("runtime_passed", evidence)

    def test_bundle_and_extracted_owner_tampering_are_rejected(self):
        self.frozen_fixture()
        (self.root / "tools/host_build_context.py").write_text("changed\n")
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ENGINE.EngineError, "extracted input"):
            ENGINE.verify_source(self.args)
        self.rebundle()
        self.bundle.write_bytes(self.bundle.read_bytes() + b"tamper")
        with redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            ENGINE.verify_source(self.args)

    def test_new_frozen_patch_still_requires_matching_materialization(self):
        self.frozen_fixture()
        (self.root / "patches/0001-fixture.patch").write_text("changed reviewed patch\n")
        self.rebundle()
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ENGINE.EngineError, "patch series"):
            ENGINE.verify_source(self.args)

    def test_undeclared_python_and_stale_overlay_inventory_are_rejected(self):
        self.frozen_fixture()
        extra = self.root / "tools/foreign.py"
        extra.write_text("# undeclared import\n")
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ENGINE.EngineError, "undeclared Python"):
            ENGINE.verify_source(self.args)
        extra.unlink()
        overlay = self.root / "overlay/new-file"
        overlay.parent.mkdir()
        overlay.write_text("new overlay")
        self.files.append("overlay/new-file")
        self.rebundle()
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ENGINE.EngineError, "overlay inventory"):
            ENGINE.verify_source(self.args)

    def test_marker_pin_mismatch_is_rejected(self):
        self.frozen_fixture()
        self.args.expected_source_marker_sha256 = "0" * 64
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ENGINE.EngineError, "marker digest"):
            ENGINE.verify_source(self.args)

    def test_native_plan_uses_hashed_owners_and_rejects_drift(self):
        owners = {"security/manager/ssl/tests/gtest/Example.cpp": "TEST_F(Example, Positive) {}\n",
                  "netwerk/test/unit/example.js": "add_task(function example() {});\n",
                  "toolkit/components/url-classifier/tests/unit/secondary.js": "add_task(function secondary() {});\n",
                  "browser/components/example/browser_example.js": "add_task(function example() {});\n"}
        pins = {}
        for owner, content in owners.items():
            path = self.source / owner
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            pins[owner] = sha(path.read_bytes())
            if "/tests/unit/" in owner or owner.startswith("netwerk/test/unit/"):
                (path.parent / "xpcshell.toml").write_text('["' + path.name + '"]\n')
        contract = self.root / "config/m13-03-decision-coverage-contract.json"
        contract.parent.mkdir()
        contract.write_text(json.dumps({"native_test_owner_sha256": pins}))
        commands = ENGINE.native_commands()
        self.assertEqual(commands[0], ("gtest", ("gtest", "Example.Positive")))
        self.assertEqual({kind for kind, _ in commands}, {"gtest", "xpcshell", "mochitest"})
        secondary = self.source / "toolkit/components/url-classifier/tests/unit/xpcshell.toml"
        secondary.write_text('["different.js"]\n')
        with self.assertRaisesRegex(ENGINE.EngineError, "unsupported native test owner"):
            ENGINE.native_commands()
        secondary.write_text('["secondary.js"]\n')
        (self.source / next(iter(owners))).write_text("changed")
        with self.assertRaisesRegex(ENGINE.EngineError, "coverage binding"):
            ENGINE.native_commands()

    def test_successful_external_socket_or_timeout_cannot_pass_selftest(self):
        for observed in (0, errno.ECONNREFUSED, errno.ETIMEDOUT):
            with mock.patch.object(ENGINE.socket, "socket") as socket_factory:
                socket_factory.return_value.__enter__.return_value.connect_ex.return_value = observed
                with self.assertRaisesRegex(ENGINE.EngineError, "definitively denied"):
                    ENGINE.network_selftest()

    def test_failed_loopback_cannot_return_an_offline_success_record(self):
        with mock.patch.object(ENGINE.socket, "socket") as socket_factory, \
                mock.patch.object(ENGINE.socket, "create_connection", side_effect=OSError("unavailable")):
            socket_factory.return_value.__enter__.return_value.connect_ex.return_value = errno.ENETUNREACH
            with self.assertRaises(OSError):
                ENGINE.network_selftest()

    def package_fixture(self):
        lock = {"target": {"platform": "ubuntu", "series": "24.04", "codename": "noble", "architecture": "amd64"},
                "apt": {"direct_packages": {"python3.12": "3.12.3-1ubuntu0.17", "g++-13": "13.2.0-23ubuntu4"}}}
        release = {"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION_CODENAME": "noble"}
        metadata = "python3.12\t3.12.3-1ubuntu0.17\tii \ng++-13:amd64\t13.2.0-23ubuntu4\tii \n"
        return lock, metadata, release

    def test_direct_package_parser_accepts_exact_versions_including_architecture_suffix(self):
        lock, metadata, release = self.package_fixture()
        result = ENGINE.validate_package_versions(lock, metadata, release, "amd64")
        self.assertEqual(result["direct_packages"], lock["apt"]["direct_packages"])
        self.assertNotIn("native_run_passed", result)

    def test_package_version_missing_duplicate_foreign_architecture_and_half_installed_rejected(self):
        lock, metadata, release = self.package_fixture()
        for bad in (metadata.replace("0.17", "0.16"), metadata.splitlines(keepends=True)[0],
                    metadata + metadata.splitlines(keepends=True)[0], metadata.replace(":amd64", ":arm64"),
                    metadata.replace("ii ", "iU "), metadata + "extra\t1.0\tii \n", ""):
            with self.subTest(metadata=bad), self.assertRaises(ENGINE.EngineError):
                ENGINE.validate_package_versions(lock, bad, release, "amd64")

    def test_package_check_rejects_different_distribution_or_architecture(self):
        lock, metadata, release = self.package_fixture()
        for field, value in (("ID", "debian"), ("VERSION_ID", "26.04"), ("VERSION_CODENAME", "other")):
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.validate_package_versions(lock, metadata, release | {field: value}, "amd64")
        with self.assertRaises(ENGINE.EngineError):
            ENGINE.validate_package_versions(lock, metadata, release, "arm64")

    def test_empty_or_command_like_package_inventory_cannot_reach_query(self):
        for packages in ({}, {"--help": "1.0"}, {"python3.12": "bad\nversion"}, {"python3.12": 1}):
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.direct_packages({"apt": {"direct_packages": packages}})

    def test_native_package_query_failure_cannot_be_treated_as_an_empty_success(self):
        lock, _, _ = self.package_fixture()
        path = self.root / "config/ubuntu-environment-lock.json"
        path.parent.mkdir()
        path.write_text(json.dumps(lock))
        with mock.patch.object(ENGINE.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="")) as run, \
                redirect_stdout(io.StringIO()), self.assertRaisesRegex(ENGINE.EngineError, "query failed"):
            ENGINE.verify_installed_packages()
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/dpkg-query")
        self.assertEqual(run.call_args.kwargs["env"], ENGINE.clean_environment())

    def test_native_executable_measurement_records_real_bytes_and_internal_alias(self):
        prefix = self.root / "tools-fixture"
        prefix.mkdir()
        compiler = prefix / "compiler"
        compiler.write_bytes(b"synthetic executable bytes; never run")
        compiler.chmod(0o700)
        (prefix / "c++").symlink_to("compiler")
        result = ENGINE.executable_hashes(prefix, {"compiler", "c++"})
        self.assertEqual(result["compiler"], {"resolved": "compiler", "sha256": sha(compiler.read_bytes())})
        self.assertEqual(result["compiler"], result["c++"])
        compiler.write_bytes(b"changed executable bytes")
        self.assertNotEqual(result, ENGINE.executable_hashes(prefix, {"compiler", "c++"}))

    def test_native_executable_measurement_rejects_missing_nonexecutables_and_escape(self):
        prefix = self.root / "tools-fixture"
        prefix.mkdir()
        tool = prefix / "tool"
        with self.assertRaises(ENGINE.EngineError):
            ENGINE.executable_hashes(prefix, {"tool"})
        tool.write_bytes(b"no execute bit")
        tool.chmod(0o600)
        with self.assertRaises(ENGINE.EngineError):
            ENGINE.executable_hashes(prefix, {"tool"})
        tool.unlink()
        tool.symlink_to(self.key)
        with self.assertRaises(RuntimeError):
            ENGINE.executable_hashes(prefix, {"tool"})

    def test_gtest_log_requires_every_exact_selector_and_rejects_skips(self):
        command = ("gtest", "Suite.Positive:Suite.Negative")
        text = ("[ RUN      ] Suite.Positive\n[       OK ] Suite.Positive (1 ms)\n"
                "[ RUN      ] Suite.Negative\n[       OK ] Suite.Negative (2 ms)\n")
        result = ENGINE.executed_test_evidence("gtest", command, text)
        self.assertEqual(result["selectors_proven"], ["Suite.Negative", "Suite.Positive"])
        for bad in ("[ PASSED ] 2 tests", text.replace("[ RUN      ] Suite.Negative", ""),
                    text.replace("[       OK ] Suite.Positive", ""), text + "[ SKIPPED ] other",
                    text + "[ FAILED ] other", text + "TEST-UNEXPECTED-PASS", text + "DISABLED_hidden",
                    text + "[ RUN      ] Suite.Unselected\n[       OK ] Suite.Unselected\n"):
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.executed_test_evidence("gtest", command, bad)

    def test_javascript_log_proves_exact_selected_file_without_claiming_function_coverage(self):
        command = ("xpcshell-test", "toolkit/components/url-classifier/tests/unit/test_example.js")
        text = ("TEST-START | " + command[-1] + "\nTEST-PASS | " + command[-1] + " | actual assertion\n")
        result = ENGINE.executed_test_evidence("xpcshell", command, text)
        self.assertEqual(result["selected_test_file_proven"], command[-1])
        self.assertFalse(result["per_function_selector_proven"])
        for bad in (text.replace("test_example.js", "another.js"), text.replace("TEST-START", "START"),
                    text.replace("TEST-PASS", "PASS"), text + "TEST-SKIP | selected task",
                    text + "TEST-UNEXPECTED-FAIL | assertion",
                    text + "TEST-START | toolkit/components/url-classifier/tests/unit/another.js\n"):
            with self.assertRaises(ENGINE.EngineError):
                ENGINE.executed_test_evidence("xpcshell", command, bad)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Run only Ubuntu configure/engine tests in a verified offline Docker worker.

Image/dependency preparation and VM power control are separate operator steps.
This route neither installs Docker nor downloads, packages, repacks or releases.
"""
from __future__ import annotations

import argparse
import codecs
from contextlib import redirect_stdout
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import time
import tomllib
import uuid

if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise SystemExit("Ubuntu engine entry requires python3 -I -S -B")
    # -B disables writes, not reads of old bytecode. Select a fresh, absent
    # cache tree before importing any frozen project module.
    sys.pycache_prefix = str(Path(__file__).resolve().parents[1] / "artifacts" /
                            ".engine-import-cache" / uuid.uuid4().hex)
    if Path(sys.pycache_prefix).exists():
        raise SystemExit("Ubuntu engine import cache must be absent")

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_host_russian as build
import install_toolchain
import m15_remote_transport as transport
import materialize_firefox_source as materializer
import provision_m13_ubuntu_container_runtime as container_runtime
from host_build_context import ARTIFACTS, ROOT, SOURCE, TOOLCHAIN, TOOLCHAIN_LOCK, HostBuildContext


HEX = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
EXPECTED_HOSTNAME = "ubuntu-server"
DOCKER = ["/usr/bin/sudo", "-n", "--", "/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
BOOTSTRAP = (
    "import pathlib,runpy,sys;entry=sys.argv.pop(1);"
    "sys.path.insert(0,str(pathlib.Path(entry).parent));sys.argv[0]=entry;"
    "runpy.run_path(entry,run_name='__main__')"
)
REQUIRED = {
    "config/firefox-baseline.json", "config/toolchain-lock.json", "config/ubuntu-environment-lock.json",
    "config/m13-ubuntu-container-runtime-lock.json",
    "config/m13-03-decision-coverage-contract.json", "config/m15-12-safebrowsing-build-input.json",
    "build/ubuntu/mozconfig.host", "patches/series", "tools/run_m13_ubuntu_engine.py",
    "tools/host_build_context.py", "tools/safebrowsing_build_input.py",
    "tools/build_host_russian.py", "tools/project_temp.py", "tools/install_toolchain.py",
    "tools/m15_remote_transport.py", "tools/materialize_firefox_source.py",
    "tools/provision_m13_ubuntu_container_runtime.py",
    "tools/verify_m3_04_certificate_supply_chain.py", "tools/wasm2c_host_cpp_preflight.py",
    *transport.REQUIRED_RUSSIAN_L10N,
}


class EngineError(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise EngineError(message)


def progress(message: str) -> None:
    print("[Ubuntu engine] " + message, flush=True)


def safe_path(value: Path) -> Path:
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and
            not any(char in str(path) for char in ",\n\r\0"), "unsafe explicit mount path")
    require(path.resolve() == path and not path.is_symlink(), "mount paths must not use symlinks")
    return path


def load(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), "expected a JSON object")
    return value


def verify_source(args: argparse.Namespace) -> dict:
    progress("verifying immutable source bundle, extracted inputs and materialization")
    for digest in (args.expected_manifest_sha256, args.expected_bundle_sha256,
                   args.expected_source_marker_sha256):
        require(isinstance(digest, str) and HEX.fullmatch(digest) is not None,
                "exact source SHA-256 pins are required")
    manifest = transport.verify_bundle(ROOT, args.manifest, args.bundle,
                                       args.expected_bundle_sha256, args.expected_manifest_sha256)
    entries = manifest.get("declared_inputs", [])
    declared = {item["path"] for item in entries}
    require(REQUIRED <= declared, "snapshot lacks the reviewed Ubuntu engine input owners")
    for index, item in enumerate(entries, 1):
        path = transport.resolve_relative(ROOT, item["path"], "frozen source input")
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == item["size"] and
                transport.sha256_file(path) == item["sha256"], "extracted input differs from the frozen snapshot")
        if index % 250 == 0 or index == len(entries):
            progress(f"verified extracted inputs {index}/{len(entries)}")
    # Frozen Python imports must not discover an undeclared source module.
    for path in (ROOT / "tools").rglob("*.py"):
        require(path.relative_to(ROOT).as_posix() in declared and not path.is_symlink(),
                "undeclared Python import owner in the frozen tools tree")
    baseline_path = ROOT / "config/firefox-baseline.json"
    baseline = load(baseline_path)
    version, archive, pin = materializer.baseline_values(baseline, baseline_path)
    canonical = archive.parent / "worktrees" / materializer.archive_root_name(version)
    require(SOURCE == canonical and version == "156.0", "unexpected canonical engine baseline")
    require(manifest["upstream"] == {
        "product": baseline["product"], "version": version, "revision": baseline["vcs"]["revision"],
        "archive": pin["archive_path"], "archive_sha256": pin["sha256"],
    }, "source manifest baseline binding differs")
    marker_path = SOURCE / ".good-bear-materialization.json"
    require(transport.sha256_file(marker_path) == args.expected_source_marker_sha256,
            "materialization marker digest differs")
    marker = load(marker_path)
    expected = {"version": version, "source_sha256": pin["sha256"], "source_sha512": pin["sha512"],
                "baseline_config_sha256": transport.sha256_file(baseline_path)}
    require(all(marker.get(key) == value for key, value in expected.items()), "materialized baseline differs")
    patches = [{"path": path.relative_to(ROOT / "patches").as_posix(), "sha256": transport.sha256_file(path)}
               for path in materializer.read_series(ROOT / "patches")]
    require(marker.get("patches") == patches, "current ordered patch series differs from materialization")
    overlay = sorted(name.removeprefix("overlay/") for name in declared
                     if name.startswith("overlay/") and Path(name).name != ".gitkeep")
    require(marker.get("overlay_files") == overlay, "materialized overlay inventory differs from frozen source")
    require((SOURCE / "browser/config/version.txt").read_text().strip() == version,
            "materialized browser version differs")
    return {"manifest_sha256": args.expected_manifest_sha256,
            "bundle_sha256": args.expected_bundle_sha256,
            "materialization_sha256": args.expected_source_marker_sha256, "patches": len(patches)}


def context_for(args: argparse.Namespace) -> HostBuildContext:
    context = HostBuildContext.create(args.objdir)
    development = ARTIFACTS / "development"
    require(context.objdir.is_relative_to(development) and context.objdir != development,
            "engine object directory must be a child of canonical artifacts/development")
    return context.with_safebrowsing_key(args.safebrowsing_key_file)


def worker_paths(context: HostBuildContext) -> dict[str, Path]:
    return {name: context.objdir / ".engine-worker" / name
            for name in ("home", "state", "cache", "build-tmp")}


def clean_environment(paths: dict[str, Path] | None = None) -> dict[str, str]:
    result = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    if paths:
        result.update(HOME=str(paths["home"]), MOZBUILD_STATE_PATH=str(paths["state"]),
                      XDG_CACHE_HOME=str(paths["cache"]), CARGO_HOME=str(paths["cache"] / "cargo"),
                      PYTHONDONTWRITEBYTECODE="1", PIP_NO_INDEX="1", CARGO_NET_OFFLINE="true",
                      MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE="system", MOZ_HEADLESS="1",
                      TMPDIR=str(ARTIFACTS / "build-tmp"), TMP=str(ARTIFACTS / "build-tmp"),
                      TEMP=str(ARTIFACTS / "build-tmp"))
    return result


def mounts(args: argparse.Namespace, context: HostBuildContext) -> list[tuple[Path, Path, bool]]:
    result = [(ROOT, ROOT, True), (context.objdir, context.objdir, False),
              (worker_paths(context)["build-tmp"], ARTIFACTS / "build-tmp", False)]
    for path in (args.manifest, args.bundle, args.safebrowsing_key_file):
        safe_path(path)
        if not path.is_relative_to(ROOT):
            result.append((path, path, True))
    require(not args.safebrowsing_key_file.is_relative_to(ROOT), "private key must remain outside frozen root")
    for source, destination, _ in result:
        safe_path(source)
        safe_path(destination)
    require(len({str(item[1]) for item in result}) == len(result), "duplicate mount destinations")
    return result


def worker_arguments(args: argparse.Namespace) -> list[str]:
    return [args.phase, "--worker", "--objdir", str(args.objdir.resolve()),
            "--image", args.image, "--uid", str(args.uid), "--gid", str(args.gid),
            "--manifest", str(args.manifest), "--bundle", str(args.bundle),
            "--expected-manifest-sha256", args.expected_manifest_sha256,
            "--expected-bundle-sha256", args.expected_bundle_sha256,
            "--expected-source-marker-sha256", args.expected_source_marker_sha256,
            "--safebrowsing-key-file", str(args.safebrowsing_key_file),
            "--host-netns", args.host_netns, "--run-id", args.run_id]


def docker_create(args: argparse.Namespace, context: HostBuildContext, control: Path, token: str) -> list[str]:
    require(IMAGE.fullmatch(args.image) is not None, "a local immutable Docker image SHA-256 ID is required")
    require(type(args.uid) is int and type(args.gid) is int and args.uid > 0 and args.gid > 0,
            "worker UID and GID must be explicit and non-root")
    command = [*DOCKER, "create", "--pull=never", "--network=none", "--read-only",
               "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--security-opt=apparmor=docker-default", "--user", f"{args.uid}:{args.gid}",
               "--cpus=4", "--pids-limit=4096", "--init", "--label", "goodbear.engine=" + token,
               "--workdir", str(ROOT), "--entrypoint", "/usr/bin/python3"]
    for source, destination, readonly in mounts(args, context):
        command += ["--mount", f"type=bind,src={source},dst={destination}" + (",readonly" if readonly else "")]
    for name, value in clean_environment(worker_paths(context)).items():
        command += ["--env", name + "=" + value]
    command += [args.image, "-I", "-S", "-B", "-u", "-X", "pycache_prefix=" + str(control / "pycache"),
                "-c", BOOTSTRAP, str(ROOT / "tools/run_m13_ubuntu_engine.py"), *worker_arguments(args)]
    return command


def verify_container(document: dict, args: argparse.Namespace, context: HostBuildContext, token: str) -> None:
    host = document.get("HostConfig", {})
    config = document.get("Config", {})
    require(document.get("Image") == args.image and config.get("User") == f"{args.uid}:{args.gid}" and
            config.get("Labels", {}).get("goodbear.engine") == token and
            document.get("AppArmorProfile") == "docker-default", "created container identity differs")
    require(host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True and
            host.get("Privileged") is False and host.get("CapDrop") == ["ALL"] and
            not host.get("CapAdd") and set(host.get("SecurityOpt", [])) == {
                "no-new-privileges", "apparmor=docker-default"} and
            host.get("PidMode") != "host" and host.get("IpcMode") != "host",
            "created container lacks mandatory isolation")
    actual = {(m.get("Source"), m.get("Destination"), not m.get("RW")) for m in document.get("Mounts", [])}
    expected = {(str(src), str(dst), ro) for src, dst, ro in mounts(args, context)}
    require(actual == expected, "container has missing or unexpected mounted inputs")


def mount_flags(text: str) -> dict[str, set[str]]:
    result = {}
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and "-" in fields, "malformed native mount table")
        path = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
        result[path] = set(fields[5].split(","))
    return result


def verify_worker_boundary(args: argparse.Namespace, context: HostBuildContext) -> None:
    require(sys.platform == "linux" and os.getuid() == args.uid > 0 and os.getgid() == args.gid > 0,
            "native Linux worker identity differs")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(status.get("NoNewPrivs", "").strip() == "1" and
            all(int(status.get(key, "1").strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapBnd", "CapAmb")),
            "worker retains privileges or capabilities")
    require(os.readlink("/proc/self/ns/net") != args.host_netns and args.host_netns.startswith("net:["),
            "worker did not enter a distinct network namespace")
    flags = mount_flags(Path("/proc/self/mountinfo").read_text())
    require("ro" in flags.get("/", set()), "worker root filesystem is writable")
    for _, destination, readonly in mounts(args, context):
        require(("ro" if readonly else "rw") in flags.get(str(destination), set()),
                "worker mount access differs from the reviewed plan")
    require(sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["lo"],
            "offline worker exposes a non-loopback interface")


def network_selftest() -> dict:
    """Real kernel socket probes; no environment variable or cached receipt can pass."""
    denied = {}
    allowed_errors = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM, errno.EADDRNOTAVAIL}
    for family, name, address in ((socket.AF_INET, "ipv4", "198.51.100.1"),
                                  (socket.AF_INET6, "ipv6", "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                observed = connection.connect_ex((address, 443))
            require(observed in allowed_errors, "external network probe was not definitively denied")
            denied[name] = observed
        except OSError as error:
            require(family == socket.AF_INET6 and error.errno == errno.EAFNOSUPPORT,
                    "unexpected native network probe failure")
            denied[name] = "address-family-unavailable"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.settimeout(2)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=2) as client:
            accepted, _ = server.accept()
            with accepted:
                accepted.settimeout(2)
                client.sendall(b"goodbear-loopback")
                require(accepted.recv(64) == b"goodbear-loopback", "loopback test server is unusable")
    return {"external_denied": denied, "loopback_tcp": "passed"}


def direct_packages(lock: dict) -> dict[str, str]:
    packages = lock.get("apt", {}).get("direct_packages", {})
    require(isinstance(packages, dict) and bool(packages) and
            all(isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) and
                isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z.+:~_-]+", version)
                for name, version in packages.items()), "invalid locked direct package inventory")
    return packages


def validate_package_versions(lock: dict, metadata: str, release: dict, architecture: str) -> dict:
    expected = direct_packages(lock)
    target = lock.get("target", {})
    require(target.get("platform") == release.get("ID") == "ubuntu" and
            target.get("series") == release.get("VERSION_ID") == "24.04" and
            target.get("codename") == release.get("VERSION_CODENAME") == "noble" and
            target.get("architecture") == architecture == "amd64",
            "native worker distribution or architecture differs from the Ubuntu lock")
    observed = {}
    for line in metadata.splitlines():
        fields = line.split("\t")
        require(len(fields) == 3 and fields[2] == "ii ", "direct package is absent or not fully installed")
        name = fields[0].removesuffix(":" + architecture)
        require(name in expected and name not in observed, "unexpected or duplicate direct package metadata")
        observed[name] = fields[1]
    require(observed == expected, "installed direct package versions differ from the frozen Ubuntu lock")
    return {"architecture": architecture, "distribution": "ubuntu", "series": target["series"],
            "direct_packages": dict(sorted(observed.items()))}


def verify_installed_packages() -> dict:
    """Query the running worker's dpkg database; an image ID alone is insufficient."""
    path = ROOT / "config/ubuntu-environment-lock.json"
    lock = load(path)
    progress("checking installed direct package versions against the frozen Ubuntu lock")
    architecture = subprocess.run(["/usr/bin/dpkg", "--print-architecture"],
                                  env=clean_environment(), text=True, capture_output=True,
                                  timeout=30, check=False)
    query = subprocess.run(["/usr/bin/dpkg-query", "--show",
                            "--showformat=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
                            *sorted(direct_packages(lock))], env=clean_environment(), text=True,
                           capture_output=True, timeout=30, check=False)
    require(architecture.returncode == query.returncode == 0, "native direct package query failed")
    result = validate_package_versions(lock, query.stdout, platform.freedesktop_os_release(),
                                       architecture.stdout.strip())
    result["environment_lock_sha256"] = transport.sha256_file(path)
    progress(f"verified {len(result['direct_packages'])} locked direct packages")
    return result


def executable_hashes(prefix: Path, names: set[str]) -> dict:
    observed = {}
    cached = {}
    for name in sorted(names):
        declared = transport.resolve_relative(prefix, name, "locked native tool")
        executable = declared.resolve()
        require(executable.is_relative_to(prefix) and executable.is_file() and os.access(executable, os.X_OK),
                "native tool is absent, non-executable or outside the locked prefix")
        if executable not in cached:
            cached[executable] = transport.sha256_file(executable)
        observed[name] = {"resolved": executable.relative_to(prefix).as_posix(),
                          "sha256": cached[executable]}
    return observed


def native_tool_hashes() -> dict:
    """Record observed executables after the existing lock/version/compile checks.

    The lock pins supplier archives, not per-binary digests. These measurements
    bind the executed worker tools without pretending to prove archive extraction.
    """
    prefix = TOOLCHAIN.resolve()
    lock = load(TOOLCHAIN_LOCK)
    names = {"llvm/bin/clang", "llvm/bin/clang++", "llvm/bin/lld", "llvm/bin/llvm-objdump"}
    for component in lock["components"]:
        names.update(str(Path(component["install"]["prefix"]) / "bin" / name)
                     for name in component["expected_commands"])
    observed = executable_hashes(prefix, names)
    python = Path(sys.executable).resolve()
    require(python.is_file() and python.is_relative_to(Path("/usr/bin")),
            "worker Python is not supplied by the immutable image")
    return {"toolchain_lock_sha256": transport.sha256_file(TOOLCHAIN_LOCK),
            "toolchain_marker_sha256": transport.sha256_file(prefix / ".good-bear-toolchain.json"),
            "observed_executables": observed,
            "image_python": {"path": str(python), "sha256": transport.sha256_file(python)},
            "archive_to_executable_reextraction_proven": False}


def native_commands() -> list[tuple[str, tuple[str, ...]]]:
    coverage = load(ROOT / "config/m13-03-decision-coverage-contract.json")
    commands = []
    selectors = set()
    for owner, expected in sorted(coverage["native_test_owner_sha256"].items()):
        path = transport.resolve_relative(SOURCE, owner, "native test owner")
        require(transport.sha256_file(path) == expected, "native test owner differs from coverage binding")
        if owner.endswith(".cpp"):
            require(not re.search(r"\bTEST_P\s*\(", path.read_text()), "parameterized native selectors require review")
            found = re.findall(r"\bTEST(?:_F)?\s*\(\s*(\w+)\s*,\s*(\w+)", path.read_text())
            require(bool(found), "native gtest owner has no executable selectors")
            selectors.update(suite + "." + test for suite, test in found)
        elif owner.endswith(".js") and (path.parent / "xpcshell.toml").is_file() and \
                path.name in tomllib.loads((path.parent / "xpcshell.toml").read_text()):
            commands.append(("xpcshell", ("xpcshell-test", owner)))
        elif owner.endswith(".js") and owner.startswith("browser/"):
            commands.append(("mochitest", ("mochitest", "--headless", owner)))
        else:
            raise EngineError("unsupported native test owner in the frozen contract")
    require(bool(selectors) and bool(commands) and not any("DISABLED_" in name for name in selectors),
            "native test plan is empty or contains disabled selectors")
    return [("gtest", ("gtest", ":".join(sorted(selectors)))), *commands]


def executed_test_evidence(kind: str, command: tuple[str, ...], text: str) -> dict:
    require(not re.search(r"TEST-(?:UNEXPECTED|SKIP)|\[\s*(?:FAILED|SKIPPED)\s*\]|DISABLED_", text),
            "native harness reported an unexpected failure, skip or disabled test")
    if kind == "gtest":
        expected = set(command[1].split(":"))
        require(all(re.fullmatch(r"\w+\.\w+", selector) for selector in expected),
                "native gtest command has an invalid exact selector")
        started = set(re.findall(r"\[\s*RUN\s*\]\s+(\w+\.\w+)\b", text))
        passed = set(re.findall(r"\[\s*OK\s*\]\s+(\w+\.\w+)\b", text))
        require(bool(expected) and started == expected and passed == expected,
                "native gtest log does not prove exactly the selected tests started and passed")
        return {"selectors_proven": sorted(expected), "selectors_not_proven": []}
    require(kind in {"xpcshell", "mochitest"}, "unsupported native test harness")
    selected = command[-1]
    events = re.findall(r"^TEST-(START|PASS)\s*\|\s*([^|\n]+?)(?:\s*\||\s*$)", text, re.MULTILINE)
    started = [owner.strip() for status, owner in events if status == "START"]
    passed = [owner.strip() for status, owner in events if status == "PASS"]
    require(started == [selected] and selected in passed,
            "native JavaScript log does not prove the exactly selected test file started and passed")
    return {"selected_test_file_proven": selected,
            "file_started_and_assertions_passed": True,
            "per_function_selector_proven": False}


class LogTee:
    def __init__(self, target, report):
        self.target, self.report = target, report

    def write(self, text):
        self.report.write(text)
        return self.target.write(text)

    def flush(self):
        self.report.flush()
        self.target.flush()


def worker(args: argparse.Namespace) -> None:
    require(re.fullmatch(r"[0-9a-f]{32}", args.run_id) is not None, "worker attempt identity is missing")
    plain = HostBuildContext.create(args.objdir)
    verify_worker_boundary(args, plain)
    os.environ.clear()
    os.environ.update(clean_environment(worker_paths(plain)))
    context = context_for(args)
    frozen = verify_source(args)
    context.validate()
    print(context.render("engine-test"), flush=True)
    progress("performing native external-denial and loopback socket selftest")
    boundary = network_selftest()
    packages = verify_installed_packages()
    environment = context.environment()
    pki = build.RUSSIAN_PKI_BUILD_INPUT_DIR.resolve()
    build.verify_russian_pki_build_inputs(pki)
    environment["GOODBEAR_RUSSIAN_PKI_BUILD_INPUT_DIR"] = str(pki)
    install_toolchain.verify_installed_toolchain(TOOLCHAIN.resolve(), load(TOOLCHAIN_LOCK),
                                                host_native=True, target_image=args.image)
    build.wasm2c_host_cpp_probe(Path(environment["CXX"]), environment)
    tools = native_tool_hashes()
    commands = [("configure", ("configure",))]
    if args.phase == "engine":
        commands += [("build", ("build", "-j4")), *native_commands()]
    result = {"kind": "offline-ubuntu-engine", "phase": args.phase, "run_id": args.run_id,
              "started_unix": int(time.time()), "frozen_source": frozen,
              "network_selftest": boundary, "installed_environment": packages, "native_tool_hashes": tools,
              "safebrowsing_input": context.safebrowsing_evidence(), "image": args.image,
              "completed_commands": [],
              "runtime_coverage_percent": None, "m13_acceptance_completed": False,
              "product_artifacts": [], "public_release_allowed": False}
    for index, (kind, command) in enumerate(commands, 1):
        verify_worker_boundary(args, context)
        require(verify_source(args) == frozen, "frozen inputs changed between phases")
        context.validate()
        require(verify_installed_packages() == packages, "installed environment changed between phases")
        build.verify_russian_pki_build_inputs(pki)
        if kind != "configure":
            build.verify_configured_key(context)
        progress(f"running {kind} ({index}/{len(commands)})")
        log = context.private_input_dir / f"engine-{index:02d}-{kind}.log"
        with log.open("w", encoding="utf-8") as output, redirect_stdout(LogTee(sys.stdout, output)):
            build.run(command, environment, context=context)
        build.verify_configured_key(context)
        evidence = executed_test_evidence(kind, command, log.read_text()) if kind in {"gtest", "xpcshell", "mochitest"} else None
        result["completed_commands"].append({"kind": kind, "argv": list(command),
                                            "log_sha256": transport.sha256_file(log), "execution_evidence": evidence})
    result_path = context.private_input_dir / ("engine-" + args.run_id + "-result.json")
    with result_path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    progress("current attempt result: " + str(result_path))
    progress("engine route completed; no package or Russian artifact was produced")


def docker_json(arguments: list[str]) -> dict:
    completed = subprocess.run([*DOCKER, *arguments], env=clean_environment(),
                               text=True, capture_output=True, timeout=30, check=False)
    require(completed.returncode == 0, "local Docker inspection failed")
    value = json.loads(completed.stdout)
    require(isinstance(value, list) and len(value) == 1, "unexpected local Docker inspection result")
    return value[0]


def launch(args: argparse.Namespace) -> None:
    require(sys.platform == "linux" and socket.gethostname() == EXPECTED_HOSTNAME,
            "execution is restricted to the recorded native Ubuntu builder")
    require(os.getuid() == args.uid > 0 and os.getgid() == args.gid > 0,
            "launcher and worker must use the same explicit non-root owner")
    require(IMAGE.fullmatch(args.image) is not None, "an immutable local image ID is required")
    require(1 <= args.timeout_minutes <= 360, "execution timeout must be within 1..360 minutes")
    verify_source(args)
    context = context_for(args)
    context.validate()
    print(context.render("engine-test"), flush=True)
    runtime_lock = load(ROOT / "config/m13-ubuntu-container-runtime-lock.json")
    runtime_before = container_runtime.verify_runtime(runtime_lock)
    image = docker_json(["image", "inspect", args.image])
    require(image.get("Id") == args.image and image.get("Os") == "linux" and
            image.get("Architecture") == "amd64" and not image.get("Config", {}).get("Volumes"),
            "local image identity, architecture or declared volumes differ")
    for path in worker_paths(context).values():
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        safe_path(path)
    (ARTIFACTS / "build-tmp").mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    args.run_id = token
    control = ARTIFACTS / "m13-ubuntu-engine-control" / token
    control.mkdir(parents=True, mode=0o700)
    (control / "container-runtime.json").write_text(
        json.dumps(runtime_before, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (control / "pycache").mkdir(mode=0o500)
    args.host_netns = os.readlink("/proc/self/ns/net")
    created = subprocess.run(docker_create(args, context, control, token), env=clean_environment(),
                             text=True, capture_output=True, timeout=30, check=False)
    require(created.returncode == 0 and HEX.fullmatch(created.stdout.strip()) is not None,
            "local Docker container creation failed")
    identifier = created.stdout.strip()
    process = None
    try:
        verify_container(docker_json(["inspect", identifier]), args, context, token)
        progress("starting the verified offline worker; dependencies must already be cached")
        redactor = context.safebrowsing_log_redactor()
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        # A pipe reader plus select enforces a deadline even when the worker is
        # silent. Removing the owned container below kills its entire cgroup.
        import selectors
        process = subprocess.Popen([*DOCKER, "start", "--attach", identifier], env=clean_environment(),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + args.timeout_minutes * 60
        heartbeat = time.monotonic()
        with process.stdout, selectors.DefaultSelector() as selector, (control / "worker.log").open("w") as output:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                require(time.monotonic() < deadline, "offline worker exceeded its deadline")
                if not selector.select(timeout=1):
                    if time.monotonic() - heartbeat >= 30:
                        progress("waiting for the running offline worker; deadline remains enforced")
                        heartbeat = time.monotonic()
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                text = decoder.decode(redactor.feed(chunk))
                output.write(text)
                output.flush()
                print(text, end="", flush=True)
            tail = decoder.decode(redactor.finish(), final=True)
            output.write(tail)
            print(tail, end="", flush=True)
        require(process.wait(timeout=30) == 0, "offline worker failed; inspect the redacted local log")
        result = load(context.private_input_dir / ("engine-" + token + "-result.json"))
        require(result.get("run_id") == token and result.get("phase") == args.phase and
                result.get("image") == args.image and bool(result.get("completed_commands")),
                "worker did not return evidence for this exact attempt")
        require(container_runtime.verify_runtime(runtime_lock) == runtime_before,
                "host container runtime changed during the engine attempt")
    finally:
        stopped = subprocess.run([*DOCKER, "rm", "--force", identifier], env=clean_environment(),
                                 text=True, capture_output=True, timeout=30, check=False)
        require(stopped.returncode == 0, "owned container cleanup failed; external VM stop is required")
        if process is not None:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
    progress("owned container removed; VM lifecycle remains with the external controller")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("phase", choices=("configure", "engine"))
    result.add_argument("--objdir", type=Path, required=True)
    result.add_argument("--image", required=True)
    result.add_argument("--uid", type=int, required=True)
    result.add_argument("--gid", type=int, required=True)
    result.add_argument("--manifest", type=Path, required=True)
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument("--expected-manifest-sha256", required=True)
    result.add_argument("--expected-bundle-sha256", required=True)
    result.add_argument("--expected-source-marker-sha256", required=True)
    result.add_argument("--safebrowsing-key-file", type=Path, required=True)
    result.add_argument("--timeout-minutes", type=int, default=360)
    result.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    result.add_argument("--host-netns", default="", help=argparse.SUPPRESS)
    result.add_argument("--run-id", default="", help=argparse.SUPPRESS)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.worker:
            worker(args)
        else:
            launch(args)
    except EngineError as error:
        progress("FAILED: " + str(error))
        return 1
    except Exception:
        # Arbitrary tool/JSON/OS exceptions can contain private data. Detailed
        # child logs are already filtered; do not print untrusted exception text.
        progress("FAILED: offline engine preflight or execution did not complete")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

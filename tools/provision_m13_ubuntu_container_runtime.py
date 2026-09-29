#!/usr/bin/env python3
"""Provision or verify the pinned Docker runtime on the one Cloud.ru Ubuntu builder.

The prepare action installs only an exact package plan from the signed Ubuntu
snapshot.  It rejects any additional package, removal, or downgrade before
changing the host.  Both actions verify the live daemon through its Unix socket;
the build login is deliberately not granted docker-group membership.  This
runtime is for M13 configure/engine tests and is not a prerequisite or execution
route for the final host-VM full-LTO build.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import platform
import pwd
import re
import socket
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "config/m13-ubuntu-container-runtime-lock.json"
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*\Z")
VERSION = re.compile(r"[0-9A-Za-z.+:~_-]+\Z")
APT_INSTALL = re.compile(r"^Inst\s+([^\s:]+)(?::[^\s]+)?(?:\s+\[[^]]+\])?\s+\(([^\s)]+)", re.MULTILINE)


class RuntimeError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def progress(message: str) -> None:
    print("[Ubuntu container runtime] " + message, flush=True)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("cannot load the container-runtime lock") from exc
    require(isinstance(value, dict), "container-runtime lock must be an object")
    return value


def validate_lock(lock: dict) -> dict[str, str]:
    require(lock.get("schema_version") == 1 and lock.get("task") == "GB100-M15-02",
            "unsupported container-runtime lock")
    host = lock.get("host", {})
    require(host == {"hostname": "ubuntu-server", "distribution": "ubuntu", "series": "24.04",
                     "codename": "noble", "architecture": "amd64", "login": "user1", "uid": 1000},
            "Cloud.ru Ubuntu host identity lock differs")
    apt = lock.get("apt", {})
    require(apt.get("snapshot_id") == "20260913T000000Z" and
            apt.get("signed_by") == "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
            "signed Ubuntu snapshot lock differs")
    expected_sources = [
        "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
        f"https://snapshot.ubuntu.com/ubuntu/{apt['snapshot_id']} {suite} main restricted universe multiverse"
        for suite in ("noble", "noble-updates", "noble-security")
    ]
    require(apt.get("sources") == expected_sources, "runtime APT sources are not the exact signed snapshot")
    packages = apt.get("runtime_packages", {})
    require(isinstance(packages, dict) and set(packages) >= {
        "ca-certificates", "apparmor", "libapparmor1", "docker.io", "containerd", "runc",
        "iptables", "iproute2",
    }, "runtime package closure is incomplete")
    require(all(isinstance(name, str) and PACKAGE.fullmatch(name) and isinstance(version, str) and
                VERSION.fullmatch(version) for name, version in packages.items()),
            "runtime package lock contains an unsafe name or version")
    require(apt.get("automatic_install_outside_runtime_packages") == "forbidden" and
            apt.get("recommended_packages") == "forbidden" and
            apt.get("package_removal") == "forbidden" and apt.get("downgrade") == "forbidden",
            "runtime APT fail-closed policy differs")
    runtime = lock.get("runtime", {})
    require(runtime.get("client_path") == "/usr/bin/docker" and
            runtime.get("daemon_path") == "/usr/bin/dockerd" and
            runtime.get("socket") == "unix:///var/run/docker.sock" and
            runtime.get("server_version") == "29.1.3" and
            runtime.get("operating_system") == "linux" and runtime.get("architecture") == "amd64" and
            runtime.get("cgroup_version") == "2" and runtime.get("storage_driver") == "overlayfs" and
            runtime.get("daemon_tcp_listener") == "forbidden" and
            runtime.get("login_in_docker_group") == "forbidden",
            "runtime identity or isolation lock differs")
    require(set(runtime.get("required_security_option_prefixes", [])) == {
        "name=apparmor", "name=seccomp",
    }, "required Docker security options differ")
    boundary = lock.get("worker_boundary", {})
    require(boundary == {"network": "none", "root_filesystem": "read-only",
                         "capabilities": "drop all", "no_new_privileges": True,
                         "immutable_local_image_id_required": True,
                         "image_pull_during_engine_run": False,
                         "allowed_use": "M13 configure and engine tests only",
                         "final_host_vm_lto_prerequisite": False},
            "offline worker boundary differs")
    return packages


def clean_environment() -> dict[str, str]:
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "DEBIAN_FRONTEND": "noninteractive"}


def execute(command: list[str], *, timeout: int = 120, allow_failure: bool = False) -> subprocess.CompletedProcess:
    completed = subprocess.run(command, env=clean_environment(), text=True, capture_output=True,
                               timeout=timeout, check=False)
    if not allow_failure:
        require(completed.returncode == 0, "native runtime command failed: " + Path(command[0]).name)
    return completed


def sudo(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    require(command and Path(command[0]).is_absolute(), "privileged command path must be absolute")
    return execute(["/usr/bin/sudo", "-n", "--", *command], timeout=timeout)


def verify_host(lock: dict) -> dict:
    expected = lock["host"]
    require(sys.platform == "linux" and os.getuid() == expected["uid"] and
            pwd.getpwuid(os.getuid()).pw_name == expected["login"] and socket.gethostname() == expected["hostname"],
            "execution is restricted to the recorded non-root Cloud.ru Ubuntu login")
    release = platform.freedesktop_os_release()
    require(release.get("ID") == expected["distribution"] and release.get("VERSION_ID") == expected["series"] and
            release.get("VERSION_CODENAME") == expected["codename"],
            "native distribution differs from the runtime lock")
    architecture = execute(["/usr/bin/dpkg", "--print-architecture"], timeout=30).stdout.strip()
    require(architecture == expected["architecture"], "native architecture differs from the runtime lock")
    sudo(["/usr/bin/true"], timeout=30)
    groups = {grp.getgrgid(identifier).gr_name for identifier in os.getgroups()}
    require("docker" not in groups, "build login must not have persistent docker-group authority")
    return {"hostname": expected["hostname"], "login": expected["login"],
            "uid": expected["uid"], "distribution": release["ID"], "series": release["VERSION_ID"],
            "codename": release["VERSION_CODENAME"], "architecture": architecture,
            "docker_group_member": False}


def installed_packages(packages: dict[str, str]) -> dict[str, str]:
    command = ["/usr/bin/dpkg-query", "--show", "--showformat=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
               *sorted(packages)]
    completed = execute(command, timeout=30, allow_failure=True)
    observed = {}
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[2] == "ii ":
            name = fields[0].split(":", 1)[0]
            require(name in packages and name not in observed, "unexpected runtime package query output")
            observed[name] = fields[1]
    return observed


def apt_options(state: Path, sources: Path) -> list[str]:
    return ["-o", "Dir::Etc::sourcelist=" + str(sources), "-o", "Dir::Etc::sourceparts=-",
            "-o", "Dir::State::lists=" + str(state / "lists")]


def exact_package_arguments(packages: dict[str, str]) -> list[str]:
    return [name + "=" + packages[name] for name in sorted(packages)]


def validate_simulation(output: str, packages: dict[str, str], installed: dict[str, str]) -> dict[str, str]:
    require(not re.search(r"^Remv\s", output, re.MULTILINE), "APT plan would remove a package")
    planned = {}
    for name, version in APT_INSTALL.findall(output):
        require(name in packages and name not in planned, "APT plan includes an unlocked or duplicate package")
        require(version == packages[name], "APT plan selected a version outside the runtime lock")
        planned[name] = version
    expected = {name: version for name, version in packages.items() if installed.get(name) != version}
    require(planned == expected, "APT plan does not exactly cover the locked runtime changes")
    return planned


def prepare(lock: dict) -> dict:
    packages = validate_lock(lock)
    host = verify_host(lock)
    require(Path(lock["apt"]["signed_by"]).is_file(), "Ubuntu archive signing keyring is absent")
    require(Path("/etc/ssl/certs/ca-certificates.crt").is_file(), "HTTPS CA bundle is absent")
    with tempfile.TemporaryDirectory(prefix="goodbear-runtime-") as temporary:
        state = Path(temporary)
        state.chmod(0o755)
        (state / "lists").mkdir(mode=0o755)
        sources = state / "sources.list"
        sources.write_text("\n".join(lock["apt"]["sources"]) + "\n", encoding="utf-8")
        options = apt_options(state, sources)
        progress("refreshing only the signed immutable Ubuntu snapshot metadata")
        sudo(["/usr/bin/apt-get", *options, "update", "-o", "APT::Update::Error-Mode=any",
              "-o", "Acquire::Retries=3"], timeout=300)
        before = installed_packages(packages)
        simulation = sudo(["/usr/bin/apt-get", *options, "--simulate", "--no-install-recommends",
                           "--no-remove", "install", *exact_package_arguments(packages)], timeout=120)
        plan = validate_simulation(simulation.stdout, packages, before)
        progress(f"validated exact runtime package plan ({len(plan)} changes)")
        if plan:
            sudo(["/usr/bin/apt-get", *options, "-y", "--no-install-recommends", "--no-remove",
                  "install", *exact_package_arguments(packages)], timeout=900)
    progress("starting pinned AppArmor, containerd and Docker system services")
    sudo(["/usr/bin/systemctl", "enable", "--now", "apparmor.service", "containerd.service",
          "docker.socket", "docker.service"], timeout=120)
    result = verify_runtime(lock)
    result["package_plan"] = dict(sorted(plan.items()))
    result["provisioning_performed"] = True
    result["host"] = host
    return result


def docker_command(lock: dict, *arguments: str) -> list[str]:
    return [lock["runtime"]["client_path"], "--host", lock["runtime"]["socket"], *arguments]


def docker_json(lock: dict, *arguments: str) -> dict | list:
    completed = sudo(docker_command(lock, *arguments), timeout=60)
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Docker returned malformed runtime metadata") from exc


def verify_runtime(lock: dict, *, verify_native_host: bool = True) -> dict:
    packages = validate_lock(lock)
    host = verify_host(lock) if verify_native_host else None
    observed = installed_packages(packages)
    require(observed == packages, "installed runtime package versions differ from the exact lock")
    for key in ("client_path", "daemon_path", "containerd_path", "runc_path"):
        path = Path(lock["runtime"][key])
        require(path.is_file() and not path.is_symlink() and os.access(path, os.X_OK),
                "locked runtime executable is absent, aliased, or not executable")
    socket_path = Path(lock["runtime"]["socket"].removeprefix("unix://"))
    require(socket_path.exists() and stat.S_ISSOCK(socket_path.stat().st_mode), "Docker Unix socket is absent")
    version = docker_json(lock, "version", "--format", "{{json .}}")
    server = version.get("Server", {}) if isinstance(version, dict) else {}
    require(server.get("Version") == lock["runtime"]["server_version"] and
            server.get("Os") == lock["runtime"]["operating_system"] and
            server.get("Arch") == lock["runtime"]["architecture"],
            "live Docker server identity differs from the runtime lock")
    info = docker_json(lock, "info", "--format", "{{json .}}")
    require(isinstance(info, dict) and info.get("OSType") == "linux" and info.get("Architecture") == "x86_64" and
            str(info.get("CgroupVersion")) == lock["runtime"]["cgroup_version"] and
            info.get("Driver") == lock["runtime"]["storage_driver"],
            "live Docker kernel/storage boundary differs")
    security = set(info.get("SecurityOptions", []))
    require(all(any(option == prefix or option.startswith(prefix + ",") for option in security)
                for prefix in lock["runtime"]["required_security_option_prefixes"]),
            "live Docker daemon lacks a required security option")
    listeners = sudo(["/usr/bin/ss", "-H", "-ltnp"], timeout=30).stdout
    require(not any("dockerd" in line for line in listeners.splitlines()),
            "Docker daemon exposes a TCP listener")
    result = {"runtime_verified": True, "provisioning_performed": False,
              "packages": dict(sorted(observed.items())),
              "docker": {"server_version": server["Version"], "os": server["Os"], "architecture": server["Arch"],
                         "storage_driver": info["Driver"], "cgroup_version": str(info["CgroupVersion"]),
                         "security_options": sorted(security), "tcp_listener": False},
              "worker_boundary": lock["worker_boundary"]}
    if host is not None:
        result["host"] = host
    return result


def write_report(path: Path, report: dict) -> None:
    require(path.is_absolute() and not path.exists() and not path.is_symlink() and not path.is_relative_to(ROOT),
            "runtime evidence must be written outside the source authority")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(path.parent.resolve() == path.parent and not path.parent.is_relative_to(ROOT),
            "runtime evidence parent must be an external real directory")
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("action", choices=("prepare", "verify"))
    result.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    result.add_argument("--report", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        lock = load(args.lock)
        report = prepare(lock) if args.action == "prepare" else verify_runtime(lock)
        report["action"] = args.action
        write_report(args.report, report)
        progress("verified pinned sudo-only Docker runtime; evidence: " + str(args.report))
        return 0
    except RuntimeError as exc:
        progress("FAILED: " + str(exc))
        return 1
    except Exception:
        progress("FAILED: runtime preparation or verification did not complete")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

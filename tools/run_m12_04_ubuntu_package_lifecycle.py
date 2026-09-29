#!/usr/bin/env python3
"""Clean-target Ubuntu lifecycle evidence for GB100-M12-04.

This is a package *test*, not a build entry point.  It creates a disposable
Ubuntu 26.04 amd64 Docker target, resolves the candidate's declared runtime
dependencies during a controlled preparation phase, and then disables network
access for every install/lifecycle operation.  The host-only build policy is
therefore unaffected.

The test deliberately distinguishes a recovery that was observed (reinstalling
the verified candidate after a deliberately failing maintainer script) from an
automatic package-manager rollback, which Debian does not promise here.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
IDENTITY = json.loads((ROOT / "config/product-identity.json").read_text(encoding="utf-8"))
PACKAGE = "goodbear-browser"
TARGET_IMAGE = "ubuntu:26.04"
DEFAULT_PACKAGE = ROOT / "artifacts" / "m12-02-ubuntu-candidates" / f"goodbear-browser_{IDENTITY['version_pair']['package_version']}-1_amd64.deb"
DEFAULT_EVIDENCE_ROOT = ROOT / "artifacts" / "m12-04-ubuntu-lifecycle"
WINDOWS_MANUAL_BLOCKER = {
    "status": "deferred-until-maintainer-provides-a-windows-environment",
    "automation": "not-run",
    "release_blocker": True,
    "required_manual_checks": [
        "fresh install", "normal launch", "profile creation", "default-browser registration",
        "upgrade", "failed-upgrade recovery", "uninstall",
    ],
}


class LifecycleError(RuntimeError):
    """The clean-target lifecycle contract was not met."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LifecycleError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def one(command: list[str], *, check: bool = True, text: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a short command and expose the command without concealing failures."""
    print("[M12-04] $ " + " ".join(command), flush=True)
    result = subprocess.run(command, text=text, capture_output=True, check=False)
    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr, flush=True)
    if check and result.returncode:
        raise LifecycleError(f"command failed ({result.returncode}): {' '.join(command)}")
    return result


def stream(command: list[str]) -> None:
    """Run a potentially slow command with line-flushed, real command output."""
    print("[M12-04] $ " + " ".join(command), flush=True)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, bufsize=1)
    assert process.stdout is not None
    for line in process.stdout:
        print(line.rstrip(), flush=True)
    if process.wait() != 0:
        raise LifecycleError(f"command failed ({process.returncode}): {' '.join(command)}")


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return one(["docker", *args], check=check)


def image_metadata(image: str) -> dict[str, str]:
    result = docker("image", "inspect", image, "--format", "{{json .}}")
    value = json.loads(result.stdout)
    require(value.get("Os") == "linux" and value.get("Architecture") == "amd64",
            "Ubuntu clean target is not linux/amd64")
    digests = value.get("RepoDigests") or []
    digest = next((item for item in digests if item.startswith("ubuntu@sha256:")), "")
    require(re.fullmatch(r"ubuntu@sha256:[0-9a-f]{64}", digest) is not None,
            "Ubuntu clean target has no immutable digest")
    return {"reference": image, "digest": digest, "image_id": value["Id"]}


def control_field(deb: Path, field: str) -> str:
    return one(["dpkg-deb", "-f", str(deb), field]).stdout.strip()


def runtime_dependency_names(deb: Path) -> list[str]:
    depends = control_field(deb, "Depends")
    names: list[str] = []
    for expression in depends.split(","):
        match = re.match(r"\s*([a-z0-9][a-z0-9+.-]*)", expression)
        require(match is not None, f"cannot parse Debian dependency: {expression}")
        names.append(match.group(1))
    require(names, "candidate package has no declared runtime dependencies")
    return names


def replace_control_version(control: Path, version: str) -> None:
    source = control.read_text(encoding="utf-8")
    changed, count = re.subn(r"^Version: .+$", f"Version: {version}", source,
                             count=1, flags=re.MULTILINE)
    require(count == 1, "fixture control file has no Version field")
    control.write_text(changed, encoding="utf-8")


def make_fixture(candidate: Path, root: Path, version: str, *, broken_postinst: bool) -> Path:
    """Create a minimal test-only transaction fixture, never a release asset.

    Repacking the 100 MiB browser payload merely to alter Debian control metadata
    would make this package-manager test look like a browser rebuild.  The real
    candidate is installed and launched separately; these tiny fixtures exercise
    only dpkg's version/state transition and recovery paths.
    """
    unpacked = root / ("bad" if broken_postinst else "previous")
    output = root / f"{PACKAGE}_{version}_amd64.deb"
    del candidate  # The fixture must never copy a release payload.
    (unpacked / "DEBIAN").mkdir(parents=True)
    (unpacked / "DEBIAN" / "control").write_text(
        f"Package: {PACKAGE}\nVersion: {version}\nArchitecture: amd64\n"
        "Maintainer: Good Bear M12-04 test fixture <noreply@example.invalid>\n"
        "Description: lifecycle transaction fixture; never a release asset\n",
        encoding="utf-8",
    )
    if broken_postinst:
        (unpacked / "DEBIAN" / "postinst").write_text(
            "#!/bin/sh\n# M12-04 test fixture: intentionally fails after unpacking.\nexit 42\n",
            encoding="utf-8",
        )
        (unpacked / "DEBIAN" / "postinst").chmod(0o755)
    one(["dpkg-deb", "--root-owner-group", "--build", str(unpacked), str(output)])
    return output


def container_exec(name: str, *command: str, check: bool = True, user: str | None = None) -> subprocess.CompletedProcess[str]:
    arguments = ["exec"]
    if user:
        arguments += ["--user", user]
    arguments += [name, *command]
    return docker(*arguments, check=check)


def status(name: str) -> str:
    return container_exec(name, "dpkg-query", "-W", "-f=${Status} ${Version}\\n", PACKAGE).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE)
    parser.add_argument("--image", default=TARGET_IMAGE)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    args = parser.parse_args()
    candidate = args.package.resolve()
    name = f"goodbear-m12-04-{uuid.uuid4().hex[:12]}"
    prepared_image = f"goodbear-m12-04-prepared:{uuid.uuid4().hex[:12]}"
    target_created = False
    setup_created = False
    image_created = False

    try:
        require(candidate.is_file(), f"Ubuntu candidate does not exist: {candidate}")
        require(control_field(candidate, "Package") == PACKAGE, "wrong package identity")
        require(control_field(candidate, "Architecture") == "amd64", "candidate is not amd64")
        version = control_field(candidate, "Version")
        match = re.fullmatch(r"(.+)-(\d+)", version)
        require(match is not None and int(match.group(2)) > 0,
                "candidate version must end in a positive Debian revision for lifecycle fixtures")
        previous_version = f"{match.group(1)}-{int(match.group(2)) - 1}"
        broken_version = f"{match.group(1)}-{int(match.group(2)) + 1}"

        print("[M12-04 1/6] Checking the immutable clean Ubuntu target and package input", flush=True)
        image = image_metadata(args.image)
        dependencies = runtime_dependency_names(candidate)
        print(f"  target: {image['digest']}; package SHA-256: {sha256(candidate)}", flush=True)
        print(f"  declared runtime packages: {len(dependencies)}", flush=True)

        with tempfile.TemporaryDirectory(prefix="good-bear-m12-04-", dir=ROOT / "artifacts") as raw:
            work = Path(raw)
            previous = make_fixture(candidate, work, previous_version, broken_postinst=False)
            broken = make_fixture(candidate, work, broken_version, broken_postinst=True)

            print("[M12-04 2/6] Preparing a disposable Ubuntu target (controlled dependency fetch)", flush=True)
            setup_name = f"{name}-setup"
            provision = (
                "set -eu; export DEBIAN_FRONTEND=noninteractive; "
                "apt-get update; apt-get install -y --no-install-recommends "
                + " ".join([*dependencies, "desktop-file-utils", "shared-mime-info", "xdg-utils", "xvfb"])
            )
            setup_created = True
            # The controlled fetch is a normal Ubuntu package-manager operation:
            # apt changes ownership of its own cache to _apt.  It needs Docker's
            # default container capabilities for that setup only.  This
            # disposable setup container is committed locally, removed, and the
            # actual lifecycle target below has no network at all.
            stream(["docker", "run", "--name", setup_name, args.image, "sh", "-ceu", provision])
            one(["docker", "commit", setup_name, prepared_image])
            image_created = True
            one(["docker", "rm", setup_name])
            setup_created = False

            print("[M12-04 3/6] Starting isolated test target and checking fresh install/launcher/profile", flush=True)
            # Docker's default seccomp profile blocks clone(CLONE_NEWUSER), which
            # prevents Firefox from constructing its own content sandbox.  Keep
            # the lifecycle target offline and no-new-privileges; only remove
            # that host-side syscall filter so the package's normal sandbox can
            # execute during the real headless profile creation below.
            one(["docker", "run", "-d", "--name", name, "--network", "none",
                 "--security-opt=no-new-privileges:true", "--security-opt=seccomp=unconfined",
                 prepared_image, "sleep", "infinity"])
            target_created = True
            one(["docker", "cp", str(previous), f"{name}:/work-previous.deb"])
            one(["docker", "cp", str(candidate), f"{name}:/work-current.deb"])
            one(["docker", "cp", str(broken), f"{name}:/work-broken.deb"])
            container_exec(name, "sh", "-ceu", "useradd --create-home --shell /bin/sh goodbear; "
                           "install -d -o goodbear -g goodbear /home/goodbear/m12-profile; "
                           "printf retained-profile-data > /home/goodbear/m12-profile/sentinel")
            container_exec(name, "dpkg", "-i", "/work-current.deb")
            install_status = status(name)
            require(install_status == f"install ok installed {version}",
                    f"fresh install status unexpected: {install_status}")
            launcher_before = container_exec(
                name, "env", "HOME=/home/goodbear", "LANG=ru_RU.UTF-8", "LANGUAGE=ru:ru_RU",
                "/usr/bin/good-bear", "--version", user="goodbear").stdout.strip()
            require(launcher_before, "installed launcher did not produce a version")
            # Materialise an empty fixture through Firefox's own profile
            # service, then start a real browser runtime and wait for its
            # active Linux `.parentlock`.  The fixture command is deliberately
            # separate: --createprofile exits before a browser runtime exists,
            # whereas the subsequent launch proves real profile use.
            # Firefox 154's software-headless compositor cannot allocate a
            # draw target in this X-less Docker kernel (upstream bug 1693011).
            # A test-only Xvfb display is therefore used for an equally
            # non-interactive runtime probe. It changes neither the package nor
            # its normal runtime configuration and keeps the target offline.
            # The profile-service fixture creates times.json; an active lock
            # in the following runtime is the distinct proof that the browser
            # actually used that profile.
            container_exec(
                name, "sh", "-ceu",
                "Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/tmp/m12-xvfb.log 2>&1 & "
                "for retry in $(seq 1 50); do test -S /tmp/.X11-unix/X99 && break; sleep 0.1; done; "
                "test -S /tmp/.X11-unix/X99",
            )
            container_exec(
                name, "env", "DISPLAY=:99", "HOME=/home/goodbear", "/usr/bin/good-bear",
                "--createprofile", "M12Lifecycle /home/goodbear/m12-created-profile",
                user="goodbear",
            )
            container_exec(name, "test", "-f", "/home/goodbear/m12-created-profile/times.json")
            container_exec(
                name, "sh", "-ceu",
                "cd /home/goodbear; "
                "DISPLAY=:99 HOME=/home/goodbear /usr/bin/good-bear "
                "--no-remote --marionette --remote-allow-system-access "
                "--profile /home/goodbear/m12-created-profile about:blank "
                ">/home/goodbear/m12-headless.log 2>&1 & browser=$!; "
                "for retry in $(seq 1 150); do test -e /home/goodbear/m12-created-profile/.parentlock && break; sleep 0.2; done; "
                "if ! test -e /home/goodbear/m12-created-profile/.parentlock; then cat /home/goodbear/m12-headless.log; "
                "find /home/goodbear/m12-created-profile -maxdepth 1 -printf '%f\\n' 2>/dev/null || true; exit 1; fi; "
                "kill $browser; wait $browser || true; "
                "test -f /home/goodbear/m12-created-profile/times.json",
                user="goodbear",
            )
            container_exec(name, "test", "-f", "/home/goodbear/m12-created-profile/times.json")
            container_exec(name, "sh", "-ceu", "XDG_DATA_HOME=/home/goodbear/.local/share xdg-mime default com.ledovskoy.goodbear.desktop text/html; "
                           "test \"$(XDG_DATA_HOME=/home/goodbear/.local/share xdg-mime query default text/html)\" = com.ledovskoy.goodbear.desktop",
                           user="goodbear")
            owned = container_exec(name, "dpkg-query", "-L", PACKAGE).stdout.splitlines()

            print("[M12-04 4/6] Upgrading to the verified candidate and preserving user state", flush=True)
            container_exec(name, "dpkg", "-i", "--force-downgrade", "/work-previous.deb")
            predecessor_status = status(name)
            require(predecessor_status == f"install ok installed {previous_version}",
                    f"synthetic predecessor status unexpected: {predecessor_status}")
            container_exec(name, "dpkg", "-i", "/work-current.deb")
            upgrade_status = status(name)
            require(upgrade_status == f"install ok installed {version}",
                    f"upgrade status unexpected: {upgrade_status}")
            container_exec(name, "sh", "-ceu", "test \"$(cat /home/goodbear/m12-profile/sentinel)\" = retained-profile-data")

            print("[M12-04 5/6] Exercising a failed upgrade and only the recovery actually observed", flush=True)
            failed = container_exec(name, "dpkg", "-i", "/work-broken.deb", check=False)
            require(failed.returncode != 0, "intentionally broken upgrade unexpectedly succeeded")
            failed_status = status(name)
            require(broken_version in failed_status and "installed" not in failed_status,
                    f"failed upgrade did not leave the expected non-installed state: {failed_status}")
            container_exec(name, "dpkg", "-i", "/work-current.deb")
            recovery_status = status(name)
            require(recovery_status == f"install ok installed {version}",
                    f"verified candidate did not recover failed upgrade: {recovery_status}")
            container_exec(name, "sh", "-ceu", "test \"$(cat /home/goodbear/m12-profile/sentinel)\" = retained-profile-data; "
                           "test -f /home/goodbear/m12-created-profile/times.json")
            launcher_after = container_exec(
                name, "env", "HOME=/home/goodbear", "LANG=ru_RU.UTF-8", "LANGUAGE=ru:ru_RU",
                "/usr/bin/good-bear", "--version", user="goodbear").stdout.strip()
            require(launcher_after, "recovered launcher did not produce a version")

            print("[M12-04 6/6] Removing the package while retaining user profiles", flush=True)
            container_exec(name, "apt-get", "remove", "-y", PACKAGE)
            # `apt-get remove` is deliberately not `purge`: dpkg can retain a
            # `config-files` database record even though the package is no
            # longer installed.  Assert the semantic state, then separately
            # prove that every package-owned regular file and symlink vanished.
            removed_status = status(name)
            require(not removed_status.startswith("install ok installed "),
                    f"package remains installed after remove: {removed_status}")
            for path in owned:
                if path.startswith("/"):
                    container_exec(name, "sh", "-ceu", f"test ! -f '{path}' && test ! -L '{path}'")
            container_exec(name, "sh", "-ceu", "test \"$(cat /home/goodbear/m12-profile/sentinel)\" = retained-profile-data; "
                           "test -f /home/goodbear/m12-created-profile/times.json")

            evidence = {
                "schema_version": 1,
                "task": "GB100-M12-04",
                "observed_at": datetime.now(UTC).isoformat(),
                "platform": "Ubuntu 26.04 amd64 clean Docker target",
                "target_image": image,
                "package": {"path": str(candidate.relative_to(ROOT)), "sha256": sha256(candidate), "version": version},
                "network": {
                    "preparation": "controlled dependency fetch only",
                    "lifecycle": "docker --network none",
                },
                "fresh_install": {"status": install_status, "launcher_version": launcher_before},
                "desktop_registration": {"mime": "text/html", "desktop_id": "com.ledovskoy.goodbear.desktop"},
                "profile_creation": {"created_by": "Good Bear profile service fixture and active virtual-display runtime",
                                     "user_profile_retained": True},
                "upgrade": {"from_test_only_synthetic_predecessor": previous_version,
                            "to_version": version, "status": upgrade_status},
                "failed_upgrade": {
                    "fixture_version": broken_version,
                    "dpkg_exit": failed.returncode,
                    "state_after_failure": failed_status,
                    "automatic_rollback": "not claimed",
                    "observed_recovery": "reinstalling the verified candidate restored install ok installed",
                    "recovered_status": recovery_status,
                },
                "uninstall": {"method": "apt-get remove", "dpkg_status_after_remove": removed_status,
                              "package_owned_regular_files_remaining": 0,
                              "user_profiles_preserved": True},
                "windows_manual_validation": WINDOWS_MANUAL_BLOCKER,
            }
            args.evidence_root.mkdir(parents=True, exist_ok=True)
            output = args.evidence_root / f"m12-04-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
            output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"M12-04 Ubuntu lifecycle evidence: {output}", flush=True)
    except (LifecycleError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        if target_created:
            docker("rm", "-f", name, check=False)
        if setup_created:
            docker("rm", "-f", f"{name}-setup", check=False)
        if image_created:
            docker("image", "rm", "-f", prepared_image, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

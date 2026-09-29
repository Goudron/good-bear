#!/usr/bin/env python3
"""Open a Russian Good Bear archive for durable local manual checking.

The developer environment is itself a Snap application.  A Good Bear archive
must not inherit that runtime's library and GTK variables, and the browser
must not remain attached to the short-lived command shell.  This launcher
uses a clean, explicit desktop environment and starts a separate session.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
IDENTITY = json.loads((ROOT / "config/product-identity.json").read_text(encoding="utf-8"))
DEFAULT_ARCHIVE = (
    ROOT
    / "artifacts/development/m15-02-ubuntu-obj/dist/"
    f"goodbear-{IDENTITY['version_pair']['package_version']}.ru.linux-x86_64.tar.xz"
)
RUN_CANDIDATES = ROOT / "artifacts/run-candidates"
RUN_PROFILES = ROOT / "artifacts/run-profiles"
DESKTOP_VARIABLES = (
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "XAUTHORITY",
    "PULSE_SERVER",
    "SSH_AUTH_SOCK",
)


class LaunchError(RuntimeError):
    pass


def clean_desktop_environment() -> dict[str, str]:
    """Pass only the desktop connection values required by a native browser."""
    environment = {
        "HOME": str(Path.home()),
        "USER": os.environ.get("USER", "valery"),
        "LOGNAME": os.environ.get("LOGNAME", os.environ.get("USER", "valery")),
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "ru_RU.UTF-8",
        "LANGUAGE": "ru_RU:ru",
    }
    for name in DESKTOP_VARIABLES:
        if value := os.environ.get(name):
            environment[name] = value
    return environment


def extract_archive(archive: Path) -> Path:
    if not archive.is_file():
        raise LaunchError(f"archive does not exist: {archive}")
    RUN_CANDIDATES.mkdir(parents=True, exist_ok=True)
    destination = Path(
        tempfile.mkdtemp(prefix="goodbear-local-", dir=RUN_CANDIDATES)
    )
    try:
        with tarfile.open(archive, "r:xz") as bundle:
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise LaunchError(f"cannot extract {archive}: {exc}") from exc
    return destination


def create_profile() -> Path:
    RUN_PROFILES.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="goodbear-local-", dir=RUN_PROFILES))


def launch(candidate: Path, profile: Path, *, startup_timeout: int) -> int:
    binary = candidate / "goodbear" / "goodbear"
    if not binary.is_file():
        raise LaunchError(f"Good Bear executable is missing: {binary}")
    log = profile / "goodbear.log"
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [str(binary), "--no-remote", "--profile", str(profile), "about:blank"],
            cwd=candidate,
            env=clean_desktop_environment(),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    deadline = time.monotonic() + startup_timeout
    marker = profile / "compatibility.ini"
    while time.monotonic() < deadline:
        status = process.poll()
        if status is not None:
            detail = log.read_text(encoding="utf-8", errors="replace")
            raise LaunchError(f"Good Bear exited with status {status}: {detail}")
        if marker.is_file():
            print(f"Good Bear window is ready (PID {process.pid})", flush=True)
            print(f"candidate: {candidate}", flush=True)
            print(f"profile: {profile}", flush=True)
            print(f"log: {log}", flush=True)
            return process.pid
        time.sleep(0.25)
    process.terminate()
    raise LaunchError(
        f"Good Bear did not initialize a profile within {startup_timeout}s; see {log}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--startup-timeout", type=int, default=30)
    args = parser.parse_args()
    if args.startup_timeout < 5:
        parser.error("--startup-timeout must be at least 5")
    try:
        candidate = extract_archive(args.archive.resolve())
        profile = create_profile()
        launch(candidate, profile, startup_timeout=args.startup_timeout)
    except LaunchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

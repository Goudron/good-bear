#!/usr/bin/env python3
"""Fail-closed Windows x64 NSIS installer workflow for GB100-M12-03.

Firefox's supported full Windows installer is an NSIS offline ``.exe``.  Good
Bear deliberately uses that format instead of inventing a cross-platform
installer or claiming that an MSI wrapper is a native product installer.  The
actual build is intentionally unavailable until a Windows x64 host/VM, Windows
SDK, and MSVC cache are all pinned in the M12 lock.  This tool validates that
boundary before it can create or promote any artifact.

It never downloads dependencies, signs a binary, or falls back to a Linux
candidate.  An unsigned Windows candidate remains local and is a public-release
blocker even after the missing Windows inputs become available.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_build_context import SOURCE  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config" / "m12-release-build-inputs-lock.json"
NSIS_BRANDING_VERIFIER = ROOT / "tools" / "verify_nsis_branding_assets.py"
PLATFORM = "windows-x64"
FORMAT = "NSIS full offline installer (.exe)"


class WindowsInstallerError(RuntimeError):
    """A Windows packaging prerequisite or evidence gate failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WindowsInstallerError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_contract(path: Path = LOCK) -> dict:
    """Load the shared M12 lock and reject any unsafe Windows drift."""
    sys.path.insert(0, str(ROOT / "tools"))
    import prepare_m12_release_build_inputs as inputs  # pylint: disable=import-outside-toplevel

    lock = inputs.load_lock(path)
    windows = lock["platforms"][PLATFORM]
    installer = windows.get("installer", {})
    require(installer.get("format") == FORMAT, "Windows installer must use the pinned NSIS full offline format")
    require(installer.get("architecture") == "x64", "Windows installer must be x64")
    require(installer.get("release_locale") == "ru", "Windows installer must be Russian-only")
    require(installer.get("filename") == "GoodBear Setup 1.0+firefox156.0 x64 ru.exe", "Windows installer filename drift")
    require(installer.get("build_steps") == [["./mach", "build"], ["./mach", "build", "installers-ru"]],
            "Windows installer must use the pinned Russian repack steps")
    pins = installer.get("source_owner_pins")
    require(isinstance(pins, list) and len(pins) == 3, "Windows NSIS source-owner pins are missing")
    for pin in pins:
        require(isinstance(pin, dict) and isinstance(pin.get("path"), str), "malformed Windows source-owner pin")
        digest = pin.get("sha256", "")
        require(len(digest) == 64 and all(char in "0123456789abcdef" for char in digest),
                f"Windows source-owner pin lacks SHA-256: {pin.get('path')}")
    signing = installer.get("code_signing", {})
    require(signing.get("candidate") == "unsigned local candidate only", "unsigned candidate boundary drift")
    require(signing.get("public_release") == "blocked until a separately approved signing authority is supplied",
            "Windows public-release signing boundary drift")
    require(signing.get("self_signed_or_invented_trust") == "forbidden", "invented Windows signing trust is forbidden")
    require(windows.get("execution_status") == "ready-for-local-windows-build",
            "Windows execution status must be ready only after cached inputs are verified")
    return lock


def verify_source_owners(lock: dict) -> None:
    """Ensure the selected supported installer owner has not silently changed."""
    for pin in lock["platforms"][PLATFORM]["installer"]["source_owner_pins"]:
        path = (SOURCE / pin["path"]).resolve()
        try:
            path.relative_to(SOURCE.resolve())
        except ValueError as exc:
            raise WindowsInstallerError(f"Windows source-owner pin escapes source tree: {pin['path']}") from exc
        require(path.is_file(), f"pinned Windows source owner is missing: {pin['path']}")
        actual = sha256_file(path)
        require(actual == pin["sha256"],
                f"pinned Windows source owner changed: {pin['path']}; update the reviewed M12 lock explicitly")


def require_ready_windows_inputs(lock: dict) -> None:
    """Refuse execution before all unavailable host/SDK/MSVC inputs are pinned."""
    windows = lock["platforms"][PLATFORM]
    vm_input = windows.get("vm_input", {})
    required = vm_input.get("required_before_execution", [])
    require(vm_input.get("status") == "cached-and-sha256-verified",
            "Windows installer build blocked: cached and SHA-256-verified Windows media, SDK, and MSVC inputs are required "
            f"before execution (currently: {', '.join(required)})")
    require(windows.get("execution_status") == "ready-for-local-windows-build",
            "Windows installer build blocked: execution status is not ready-for-local-windows-build")
    require(sys.platform == "win32", "Windows installer build only runs on a Windows x64 host or VM")
    require(os.environ.get("GOODBEAR_WINDOWS_NETWORK") == "forbidden",
            "Windows installer build requires GOODBEAR_WINDOWS_NETWORK=forbidden after controlled fetch")


def verify_nsis_branding_assets() -> None:
    """Require the complete Good Bear NSIS wizard artwork before packaging.

    The installer script silently falls back to the upstream branding tree when
    these bitmap resources are absent.  Running the dedicated verifier here
    makes that regression a packaging preflight failure instead of a visual
    discovery after a long native build.
    """
    require(NSIS_BRANDING_VERIFIER.is_file(), "Windows NSIS branding verifier is missing")
    result = subprocess.run(
        [sys.executable, str(NSIS_BRANDING_VERIFIER)],
        cwd=ROOT,
        check=False,
    )
    require(result.returncode == 0,
            "Windows installer build blocked: Good Bear NSIS wizard branding assets failed verification")


def preflight(lock: dict) -> None:
    print("[M12-03 1/4] Verifying pinned Windows NSIS installer source owners", flush=True)
    verify_source_owners(lock)
    print("[M12-03 2/4] Verifying Good Bear NSIS wizard branding assets", flush=True)
    verify_nsis_branding_assets()
    print("[M12-03 3/4] Checking cached Windows media, SDK, MSVC, and network boundary", flush=True)
    require_ready_windows_inputs(lock)
    print("[M12-03 4/4] Windows x64 installer environment is ready; no artifact created by preflight", flush=True)


def build(lock: dict, output: Path) -> None:
    """Execute the supported Russian installer build only after fail-closed preflight.

    This code is deliberately unreachable with the current lock.  It preserves
    the exact sequence for the later maintainer-provided Windows environment
    without manufacturing a candidate on another platform.
    """
    preflight(lock)
    output = output.resolve()
    require(output.name == lock["platforms"][PLATFORM]["installer"]["filename"], "unexpected Windows installer filename")
    require(not output.exists(), f"refusing to replace existing Windows candidate: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    for index, command in enumerate(lock["platforms"][PLATFORM]["installer"]["build_steps"], start=1):
        print(f"[M12-03 build {index}/2] Running {' '.join(command)}", flush=True)
        result = subprocess.run(command, cwd=SOURCE, check=False, text=True)
        require(result.returncode == 0, f"Windows Russian installer build step failed: {' '.join(command)}")
    # The exact object-directory output must be supplied only by the locked
    # Windows builder; guessing a glob could promote a stale en-US package.
    raise WindowsInstallerError(
        "Windows build completed but candidate discovery is intentionally blocked: add the reviewed exact installer path and "
        "SHA-256 evidence after the first cached Windows build; do not promote a guessed or unsigned artifact"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "build"))
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "m12-03-windows-candidates" / "GoodBear Setup 1.0+firefox156.0 x64 ru.exe")
    args = parser.parse_args()
    try:
        contract = load_contract(args.lock)
        if args.action == "preflight":
            preflight(contract)
        else:
            build(contract, args.output)
    except WindowsInstallerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

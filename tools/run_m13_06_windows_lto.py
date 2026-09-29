#!/usr/bin/env python3
"""Run the frozen native Windows x64 Good Bear full-LTO candidate.

The host only orchestrates a guest-native build.  Firefox sources, locales,
toolchains and object files are resolved by paths inside the Windows VM; no
host worktree path is accepted as a build input.  Network must already be
disabled by the VirtualBox machine configuration.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MOZCONFIG = ROOT / "build" / "windows" / "mozconfig.release-lto"


def guest_source_default() -> str:
    baseline = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
    return rf"C:\GoodBear\freeze-source\worktree\firefox-{baseline['version']}"


class BuildError(RuntimeError):
    pass


def run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, check=False, capture_output=capture)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def vbox(args: argparse.Namespace, *parts: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    require(parts, "missing VBox guest-control operation")
    operation, *operation_args = parts
    return run([
        "VBoxManage", "guestcontrol", args.vm, operation,
        "--username", args.username, "--passwordfile", str(args.password_file),
        *operation_args,
    ], capture=capture)


def vm_info(vm: str) -> dict[str, str]:
    result = run(["VBoxManage", "showvminfo", vm, "--machinereadable"], capture=True)
    require(result.returncode == 0, result.stderr.strip() or "cannot inspect Windows VM")
    values = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    return values


def guest_exists(args: argparse.Namespace, path: str) -> bool:
    result = vbox(args, "stat", path, capture=True)
    return result.returncode == 0


def validate(args: argparse.Namespace) -> None:
    require(MOZCONFIG.is_file(), f"missing Windows release mozconfig: {MOZCONFIG}")
    require(args.jobs == 3, "Windows LTO build must retain the approved three-way limit")
    info = vm_info(args.vm)
    require(info.get("VMState") == "running", "Windows VM must be running")
    require(info.get("memory") == "3072", "Windows VM memory must be exactly 3072 MiB")
    require(info.get("cpus") == "3", "Windows VM must use three CPUs")
    require(info.get("cableconnected1", "off") == "off", "network cable must be disconnected for M13-06")
    for label, path in {
        "frozen source": args.guest_source,
        "frozen Russian l10n": args.guest_l10n,
        "pinned LLVM": args.guest_llvm,
        "pinned Python": args.guest_python,
        "MozillaBuild": args.guest_mozillabuild,
        "MSVC vcvars": args.guest_vcvars,
    }.items():
        require(guest_exists(args, path), f"missing {label}: {path}")


def stage_mozconfig(args: argparse.Namespace) -> None:
    target_dir, _, _ = args.guest_mozconfig.rpartition("\\")
    require(target_dir, "guest mozconfig must have an absolute Windows path")
    created = vbox(args, "mkdir", "--parents", target_dir, capture=True)
    require(created.returncode == 0, created.stderr.strip() or "cannot create guest release-input directory")
    copied = vbox(args, "copyto", str(MOZCONFIG), args.guest_mozconfig, capture=True)
    require(copied.returncode == 0, copied.stderr.strip() or "cannot stage frozen Windows mozconfig")


def command_line(args: argparse.Namespace, phase: str) -> str:
    source = args.guest_source
    clang_bin = args.guest_llvm.replace("\\", "/").rstrip("/") + "/bin"
    env = " && ".join((
        # Use the verified 8.3 VC environment path.  Guest Control applies its
        # own argument quoting; adding a second quote layer makes cmd treat the
        # batch path as a literal command name.
        f"call {args.guest_vcvars}",
        f"set \"PATH={args.guest_python};{args.guest_llvm}\\bin;%PATH%\"",
        # Configure rewrites PATH for MozillaBuild.  Pin both compiler entry
        # points explicitly so that this does not make it fall back to MSVC.
        f"set \"CC={clang_bin}/clang-cl.exe\"",
        f"set \"CXX={clang_bin}/clang-cl.exe\"",
        f"set \"LINKER={clang_bin}/lld-link.exe\"",
        f"set \"MOZCONFIG={args.guest_mozconfig}\"",
        f"set \"MOZ_OBJDIR={args.guest_objdir}\"",
        f"set \"GOODBEAR_L10N_BASE={args.guest_l10n}\"",
        "set \"GOODBEAR_WINDOWS_NETWORK=forbidden\"",
        # The frozen, offline wheel closure is installed into the pinned Python.
        # Firefox explicitly supports the system package source for its mach and
        # build sites, avoiding an implicit network bootstrap in the VM.
        "set \"MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE=system\"",
        # In cmd.exe, the unquoted form leaves the separator before the next
        # command in the value.  Mozilla's bootstrap rejects that path.
        f"set \"MOZILLABUILD={args.guest_mozillabuild}\"",
    ))
    mach = f"{source}\\mach.cmd"
    if phase == "build":
        invocation = f'{mach} build -j{args.jobs}'
    elif phase == "repack":
        invocation = f'{mach} build installers-ru'
    else:
        raise BuildError(f"unknown phase: {phase}")
    return f"{env} && cd /d {source} && {invocation}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vm", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--guest-source", default=guest_source_default())
    parser.add_argument("--guest-l10n", required=True)
    parser.add_argument("--guest-llvm", required=True)
    parser.add_argument("--guest-python", default=r"C:\GoodBear\tools\Python312")
    parser.add_argument("--guest-mozillabuild", default=r"C:\mozilla-build")
    parser.add_argument("--guest-vcvars", default=r"C:\PROGRA~2\MICROS~2\2022\BUILDT~1\VC\AUXILI~1\Build\vcvars64.bat")
    parser.add_argument("--guest-mozconfig", default=r"C:\GoodBear\release-inputs\mozconfig.release-lto")
    parser.add_argument("--guest-objdir", default=r"C:\GoodBear\obj\windows-x64-release-lto")
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        validate(args)
        stage_mozconfig(args)
        plan = {"build": command_line(args, "build"), "repack": command_line(args, "repack")}
        print(json.dumps({"validated": True, "network": "forbidden", "commands": plan}, ensure_ascii=False, indent=2), flush=True)
        if not args.execute:
            return 0
        for phase, command in plan.items():
            print(f"[M13-06 Windows {phase}] starting", flush=True)
            result = vbox(args, "run", "--wait-stdout", "--wait-stderr", "--timeout", "0", "--", r"C:\Windows\System32\cmd.exe", "/d", "/c", command)
            require(result.returncode == 0, f"Windows {phase} failed with exit code {result.returncode}")
            print(f"[M13-06 Windows {phase}] completed", flush=True)
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

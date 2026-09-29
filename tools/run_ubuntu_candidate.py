#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Run one reproducible M1-06 candidate command inside the pinned Ubuntu image."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import FIREFOX_WORKTREE_NAME, SOURCE

IMAGE = "goodbear-ubuntu-m1-06:local"
CONTAINER_SOURCE = f"/workspace/source/worktrees/{FIREFOX_WORKTREE_NAME}"
L10N = ROOT / "source" / "l10n" / "firefox-l10n"
ARTIFACTS = ROOT / "artifacts"
CANDIDATE_ROOT = ARTIFACTS / "build-candidates" / "m1-06-goodbear-ru"
TOOLCHAIN = ARTIFACTS / "toolchains" / "current"
MOZCONFIG = ROOT / "build" / "ubuntu" / "mozconfig.dev"

SPEC = importlib.util.spec_from_file_location(
    "ubuntu_environment", ROOT / "tools" / "verify_ubuntu_environment.py"
)
assert SPEC and SPEC.loader
ENVIRONMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENVIRONMENT)


class CandidateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateError(message)


def mount(source: Path, target: str, mode: str) -> str:
    suffix = ",readonly" if mode == "ro" else ""
    return f"type=bind,src={source.resolve()},dst={target}{suffix}"


def command_for(action: str) -> str:
    commands = {
        "configure": "./mach configure",
        "build": (
            "gmake -C /workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/browser/locales merge-ru && "
            "IS_LANGUAGE_REPACK=1 "
            "REAL_LOCALE_MERGEDIR=/workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/browser/locales/merge-dir/ru "
            "./mach build -j1 && "
            "gmake -C /workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/browser/locales chrome-ru && "
            "gmake -C /workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/browser/locales multilocale.txt-ru && "
            "install -m 0644 "
            "/workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/dist/xpi-stage/res/multilocale.txt "
            "/workspace/artifacts/build-candidates/m1-06-goodbear-ru/obj/dist/bin/res/multilocale.txt"
        ),
        "package": "./mach package",
        "repack-ru": "./mach package-multi-locale --locales ru",
    }
    return commands[action]


def validate_inputs() -> None:
    lock = ENVIRONMENT.load(ROOT / "config" / "ubuntu-environment-lock.json")
    ENVIRONMENT.verify(lock, MOZCONFIG.read_text(encoding="utf-8"))
    for path, label in ((SOURCE, "Firefox worktree"), (L10N / "ru", "pinned Russian l10n"),
                        (TOOLCHAIN / "llvm" / "bin" / "clang", "pinned LLVM"),
                        (TOOLCHAIN / "wasi-sdk" / "share" / "wasi-sysroot" / "include" / "wasm32-wasi" / "time.h", "pinned WASI sysroot"),
                        (TOOLCHAIN / "wasi-sdk" / "bin" / "clang++", "pinned WASI C++ compiler")):
        require(path.exists(), f"missing {label}: {path}")


def run(action: str, image: str, log: Path) -> None:
    validate_inputs()
    log.parent.mkdir(parents=True, exist_ok=True)
    command = command_for(action)
    docker = [
        "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "1000:1000",
        "-e", "HOME=/workspace/artifacts/build-candidates/m1-06-goodbear-ru/home",
        "-e", "PIP_NO_INDEX=1", "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "-e", "MOZCONFIG=/workspace/mozconfig", "--mount", mount(SOURCE, CONTAINER_SOURCE, "rw"),
        "--mount", mount(L10N, "/workspace/source/l10n/firefox-l10n", "ro"),
        "--mount", mount(ARTIFACTS, "/workspace/artifacts", "rw"),
        "--mount", mount(TOOLCHAIN, "/workspace/toolchains/current", "ro"),
        "--mount", mount(MOZCONFIG, "/workspace/mozconfig", "ro"),
        "--workdir", CONTAINER_SOURCE, image,
        "bash", "-lc", command,
    ]
    print("Running pinned target command: " + command, flush=True)
    print("Network is disabled; only declared source, l10n, artifacts, toolchain, and mozconfig mounts are available.", flush=True)
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(docker, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, bufsize=1)
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            output.write(line)
            output.flush()
        status = process.wait()
    if status:
        raise CandidateError(f"pinned target command failed with exit status {status}; see {log}")
    print(f"Pinned target command completed; log: {log}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("configure", "build", "package", "repack-ru"))
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()
    log = args.log or ARTIFACTS / "logs" / f"m1-06-{args.action}-wasi.log"
    try:
        run(args.action, args.image, log)
    except CandidateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Run the executable GB100-M2-01 PSM/NSS verification contract."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ubuntu_candidate", ROOT / "tools" / "run_ubuntu_candidate.py"
)
assert SPEC and SPEC.loader
CANDIDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANDIDATE)

UPSTREAM_TESTS = (
    "security/manager/ssl/tests/unit/test_self_signed_certs.js",
    "security/manager/ssl/tests/unit/test_cert_overrides.js",
)


class ProbeError(RuntimeError):
    pass


def docker_command(image: str, test: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "1000:1000",
        "-e",
        "HOME=/workspace/artifacts/build-candidates/m1-06-goodbear-ru/home",
        "-e",
        "PIP_NO_INDEX=1",
        "-e",
        "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "-e",
        "MOZCONFIG=/workspace/mozconfig",
        "--mount",
        CANDIDATE.mount(
            CANDIDATE.SOURCE,
            CANDIDATE.CONTAINER_SOURCE,
            "ro",
        ),
        "--mount",
        CANDIDATE.mount(
            CANDIDATE.L10N,
            "/workspace/source/l10n/firefox-l10n",
            "ro",
        ),
        "--mount",
        CANDIDATE.mount(CANDIDATE.ARTIFACTS, "/workspace/artifacts", "rw"),
        "--mount",
        CANDIDATE.mount(
            CANDIDATE.TOOLCHAIN,
            "/workspace/toolchains/current",
            "ro",
        ),
        "--mount",
        CANDIDATE.mount(CANDIDATE.MOZCONFIG, "/workspace/mozconfig", "ro"),
        "--workdir",
        CANDIDATE.CONTAINER_SOURCE,
        image,
        "./mach",
        "xpcshell-test",
        test,
    ]


def stream(command: list[str], log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            output.write(line)
            output.flush()
        status = process.wait()
    if status:
        raise ProbeError(f"probe failed with exit status {status}; see {log}")


def run(image: str) -> None:
    CANDIDATE.validate_inputs()
    contract_log = CANDIDATE.ARTIFACTS / "logs/m2-01-source-contract.log"
    print("[M2-01 1/3] Checking the pinned PSM/NSS source contract", flush=True)
    stream(
        [
            sys.executable,
            "-m",
            "unittest",
            "-v",
            "tests.test_m2_01_verification_contract",
        ],
        contract_log,
    )

    for index, test in enumerate(UPSTREAM_TESTS, start=2):
        stem = Path(test).stem
        log = CANDIDATE.ARTIFACTS / "logs" / f"m2-01-{stem}.log"
        print(f"[M2-01 {index}/3] Running upstream PSM probe: {test}", flush=True)
        stream(docker_command(image, test), log)

    print("GB100-M2-01 executable verification contract passed", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default=CANDIDATE.IMAGE)
    args = parser.parse_args()
    try:
        run(args.image)
    except (CANDIDATE.CandidateError, ProbeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

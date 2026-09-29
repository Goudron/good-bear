#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Run the executable GB100-M2-04 typed trust-domain contract."""

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


class ProbeError(RuntimeError):
    pass


def docker_command(image: str, mach_args: list[str]) -> list[str]:
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
        CANDIDATE.mount(CANDIDATE.TOOLCHAIN, "/workspace/toolchains/current", "ro"),
        "--mount",
        CANDIDATE.mount(CANDIDATE.MOZCONFIG, "/workspace/mozconfig", "ro"),
        "--workdir",
        CANDIDATE.CONTAINER_SOURCE,
        image,
        "./mach",
        *mach_args,
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
    probes = (
        (
            "gtest",
            ["gtest", "psm_GoodBearTrustDomain.*"],
            CANDIDATE.ARTIFACTS / "logs/m2-04-goodbear-trust-domain-gtest.log",
        ),
        (
            "browser UI exposure",
            [
                "mochitest",
                "--headless",
                "browser/base/content/test/siteIdentity/browser_getSecurityInfo.js",
            ],
            CANDIDATE.ARTIFACTS / "logs/m2-04-goodbear-trust-domain-ui.log",
        ),
    )
    total = 1 + len(probes)
    print("[M2-04 1/3] Checking the pinned typed trust-domain source contract", flush=True)
    stream(
        [
            sys.executable,
            "-m",
            "unittest",
            "-v",
            "tests.test_m2_04_trust_domain_contract",
            "tests.test_run_m2_04_trust_domain_probe",
        ],
        CANDIDATE.ARTIFACTS / "logs/m2-04-source-contract.log",
    )
    for index, (label, mach_args, log) in enumerate(probes, start=2):
        print(f"[M2-04 {index}/{total}] Running {label} probe", flush=True)
        stream(docker_command(image, mach_args), log)
    print("GB100-M2-04 executable typed trust-domain contract passed", flush=True)


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

#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Run the executable GB100-M2-03 state-partitioning contract."""

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

XPCSHELL_TESTS = (
    "toolkit/components/passwordmgr/test/unit/test_LoginManagerParent_getGeneratedPassword.js",
    "security/manager/ssl/tests/unit/test_client_auth_remember_service_read.js",
    "security/manager/ssl/tests/unit/test_session_resumption.js",
    "netwerk/test/unit/test_cache_jar.js",
    "netwerk/test/unit/test_separate_connections.js",
    "netwerk/test/unit/test_retry_0rtt.js",
)

BROWSER_TESTS = (
    "dom/serviceworkers/test/browser_unregister_with_containers.js",
    "browser/components/contextualidentity/test/browser/browser_usercontextid_new_window.js",
    "browser/components/contextualidentity/test/browser/browser_forgetaboutsite.js",
)


class ProbeError(RuntimeError):
    pass


def docker_command(image: str, suite: str, test: str) -> list[str]:
    if suite == "xpcshell":
        mach_args = ["./mach", "xpcshell-test", test]
    elif suite == "browser":
        mach_args = ["./mach", "mochitest", "--headless", test]
    else:
        raise ValueError(f"unsupported test suite: {suite}")

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
    total = 1 + len(XPCSHELL_TESTS) + len(BROWSER_TESTS)
    current = 1
    contract_log = CANDIDATE.ARTIFACTS / "logs/m2-03-source-contract.log"
    print(
        f"[M2-03 {current}/{total}] Checking the pinned state-partitioning source contract",
        flush=True,
    )
    stream(
        [
            sys.executable,
            "-m",
            "unittest",
            "-v",
            "tests.test_m2_03_state_partitioning_contract",
            "tests.test_run_m2_03_state_partitioning_probe",
        ],
        contract_log,
    )

    for test in XPCSHELL_TESTS:
        current += 1
        stem = Path(test).stem
        log = CANDIDATE.ARTIFACTS / "logs" / f"m2-03-{stem}.log"
        print(
            f"[M2-03 {current}/{total}] Running upstream xpcshell probe: {test}",
            flush=True,
        )
        stream(docker_command(image, "xpcshell", test), log)

    for test in BROWSER_TESTS:
        current += 1
        stem = Path(test).stem
        log = CANDIDATE.ARTIFACTS / "logs" / f"m2-03-{stem}.log"
        print(
            f"[M2-03 {current}/{total}] Running upstream browser probe: {test}",
            flush=True,
        )
        stream(docker_command(image, "browser", test), log)

    print("GB100-M2-03 executable state-partitioning contract passed", flush=True)


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

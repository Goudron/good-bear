#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Validate Good Bear's sole Ubuntu M1-06 build/test environment lock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "config" / "ubuntu-environment-lock.json"
DEFAULT_MOZCONFIG = ROOT / "build" / "ubuntu" / "mozconfig.dev"


class EnvironmentError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EnvironmentError(message)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvironmentError(f"cannot load Ubuntu environment lock: {exc}") from exc
    require(isinstance(value, dict), "Ubuntu environment lock must be an object")
    return value


def verify(lock: dict, mozconfig: str | None = None) -> None:
    require(lock.get("schema_version") == 1, "unsupported Ubuntu environment lock schema")
    target = lock.get("target", {})
    require(target.get("platform") == "ubuntu" and target.get("series") == "24.04" and
            target.get("codename") == "noble", "target must be Ubuntu 24.04 Noble")
    require(target.get("architecture") == "amd64", "target architecture must be amd64")
    require(target.get("release_locale") == "ru" and target.get("test_locale") == "ru_RU.UTF-8",
            "environment must be Russian-only")
    require(target.get("timezone") == "Europe/Moscow", "timezone must be Europe/Moscow")
    require(target.get("only_distribution_target") is True, "Ubuntu must be the only target")
    oci = lock.get("oci", {})
    require(re.fullmatch(r"docker\.io/library/ubuntu:24\.04@sha256:[0-9a-f]{64}",
                         str(oci.get("reference"))), "base image must be exact official Ubuntu 24.04 digest")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", str(oci.get("manifest_list_digest"))),
            "OCI manifest-list digest is malformed")
    require(oci.get("platform") == "linux/amd64", "OCI platform must be linux/amd64")
    apt = lock.get("apt", {})
    require(apt.get("snapshot_id") == "20260913T000000Z", "Ubuntu snapshot pin is missing")
    packages = apt.get("direct_packages")
    require(isinstance(packages, dict) and packages, "direct package lock is missing")
    for package in ("python3.12", "make", "git", "gnupg", "dpkg-dev", "locales", "ca-certificates",
                    "build-essential", "g++", "g++-13", "libstdc++-13-dev"):
        require(isinstance(packages.get(package), str) and packages[package],
                f"direct package lock misses {package}")
    require(packages["python3.12"].startswith("3.12."), "Python must remain in the 3.12 series")
    require(packages["build-essential"] == "12.10ubuntu1", "build-essential package pin drift")
    require(packages["g++"] == "4:13.2.0-7ubuntu1", "g++ package pin drift")
    require(packages["g++-13"] == packages["libstdc++-13-dev"],
            "g++ and libstdc++ development ABI package pins must match")
    branding = lock.get("candidate_branding", {})
    require(branding.get("allowed") == "browser/branding/goodbear", "only Good Bear candidate branding is allowed")
    require(branding.get("promotion") == "quarantine_until_all_release_gates_pass",
            "candidate output must remain quarantined")
    wasm = lock.get("wasm_sandboxing", {})
    require(wasm.get("enabled") is True, "WASM sandboxed libraries must remain enabled")
    require(wasm.get("sdk_component") == "wasi-sdk", "WASI SDK component drift")
    sysroot = wasm.get("sysroot_path_in_target")
    require(sysroot == "/workspace/toolchains/current/wasi-sdk/share/wasi-sysroot", "WASI sysroot path is unsafe")
    require(wasm.get("compiler_path_in_target") == "/workspace/toolchains/current/wasi-sdk/bin",
            "WASI compiler path is unsafe")
    require(wasm.get("escape_hatch") == "forbidden: --without-wasm-sandboxed-libraries",
            "WASM sandboxing escape hatch disposition drift")
    if mozconfig is not None:
        require(". $topsrcdir/build/goodbear/mozconfig" in mozconfig,
                "mozconfig must compose the canonical Good Bear identity")
        require("browser/branding/unofficial" not in mozconfig,
                "mozconfig must not select unofficial Firefox branding")
        require("--without-wasm-sandboxed-libraries" not in mozconfig,
                "mozconfig must not disable WASM sandboxed libraries")
        require("ac_add_options --enable-ui-locale=ru" in mozconfig,
                "mozconfig must start the candidate in Russian")
        require("mk_add_options MOZ_CO_LOCALES=ru" in mozconfig,
                "mozconfig must declare ru as the sole shipped locale")
        require("ac_add_options --with-l10n-base=/workspace/source/l10n/firefox-l10n" in mozconfig,
                "mozconfig must use the pinned Russian l10n input")
        require(f"ac_add_options --with-wasi-sysroot={sysroot}" in mozconfig,
                "mozconfig must use the pinned target WASI sysroot")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    args = parser.parse_args()
    try:
        verify(load(args.lock), DEFAULT_MOZCONFIG.read_text(encoding="utf-8"))
    except EnvironmentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Good Bear Ubuntu 24.04 amd64 Russian environment lock verified", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Fast host C++ ABI check used before a WASM-to-C build.

WABT's wasm2c host sources are C++.  The locked LLVM driver deliberately uses
Ubuntu's pinned libstdc++ ABI, so a missing g++/libstdc++ development closure
otherwise appears only late in a Firefox build.  This small native program
checks the needed RTTI, exceptions, and virtual dispatch path first.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


class PreflightError(RuntimeError):
    pass


CPP_SOURCE = r"""
#include <stdexcept>
#include <typeinfo>

struct Base {
  virtual ~Base() = default;
  virtual int dispatch() const = 0;
};

struct Derived final : Base {
  int dispatch() const override { return 17; }
};

int main() {
  try {
    Derived derived;
    Base& base = derived;
    if (typeid(base) != typeid(Derived) || base.dispatch() != 17) {
      return 2;
    }
    throw std::runtime_error("wasm2c host C++ ABI");
  } catch (const std::runtime_error&) {
    return 0;
  }
}
""".lstrip()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def run_checked(command: list[str], environment: dict[str, str], label: str) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.run(
            command,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise PreflightError(f"wasm2c host C++ {label} could not start: {exc}") from exc
    if process.returncode:
        detail = (process.stderr or process.stdout).strip()
        raise PreflightError(
            f"wasm2c host C++ {label} failed with exit status {process.returncode}: {detail}"
        )
    return process


def driver_links_libstdcxx(transcript: str) -> bool:
    """Accept the clang driver's explicit libstdc++ link argument only."""
    return re.search(r"(?<![A-Za-z0-9_+.-])-lstdc\+\+(?![A-Za-z0-9_+.-])", transcript) is not None


def probe(cxx: Path, environment: dict[str, str]) -> None:
    # Keep the clang++ symlink spelling: clang derives its C++ driver mode
    # from argv[0].  Resolve only for the executable check, not invocation.
    cxx = cxx.absolute()
    real_cxx = cxx.resolve()
    require(real_cxx.is_file() and os.access(real_cxx, os.X_OK), f"locked clang++ is not executable: {cxx}")
    require(environment.get("CXX") == str(cxx), "CXX must be the locked clang++ path")
    require(environment.get("LDFLAGS") == "-fuse-ld=lld", "LDFLAGS must select locked lld")
    locked_lld = (cxx.parent / "lld").resolve()
    require(
        environment.get("LD") == str(locked_lld),
        "LD must be the locked lld sibling of clang++",
    )

    with tempfile.TemporaryDirectory(prefix="goodbear-wasm2c-host-cpp-") as temporary:
        workdir = Path(temporary)
        source = workdir / "wasm2c-host-cpp.cpp"
        binary = workdir / "wasm2c-host-cpp"
        source.write_text(CPP_SOURCE, encoding="utf-8")
        command = [str(cxx), "-fuse-ld=lld", str(source), "-o", str(binary)]
        transcript = run_checked(command[:2] + ["-###", *command[2:]], environment, "driver trace")
        require(
            driver_links_libstdcxx(transcript.stdout + transcript.stderr),
            "locked clang++ driver link does not include libstdc++",
        )
        run_checked(command, environment, "compile/link")
        run_checked([str(binary)], environment, "runtime")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cxx", type=Path, required=True)
    args = parser.parse_args()
    try:
        probe(args.cxx, dict(os.environ))
    except PreflightError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("wasm2c host C++ ABI preflight passed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

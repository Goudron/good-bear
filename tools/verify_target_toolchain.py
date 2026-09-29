#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Run compiler and WASI sysroot gates only inside the pinned Ubuntu target."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
from project_temp import temporary_directory


class TargetToolchainError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TargetToolchainError(message)


def run(command: list[str]) -> None:
    print("Running " + " ".join(command), flush=True)
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args()
    try:
        prefix = args.prefix.resolve()
        clang = prefix / "llvm" / "bin" / "clang"
        clangxx = prefix / "llvm" / "bin" / "clang++"
        lld = prefix / "llvm" / "bin" / "ld.lld"
        wasi_clang = prefix / "wasi-sdk" / "bin" / "clang"
        wasi_clangxx = prefix / "wasi-sdk" / "bin" / "clang++"
        sysroot = prefix / "wasi-sdk" / "share" / "wasi-sysroot"
        for path in (clang, clangxx, lld, wasi_clang, wasi_clangxx, sysroot / "include" / "wasm32-wasi" / "time.h",
                     sysroot / "lib" / "wasm32-wasi" / "libc.a",
                     sysroot / "lib" / "wasm32-wasi" / "libwasi-emulated-process-clocks.a",
                     prefix / "wasi-sdk" / "lib" / "clang" / "22" / "lib" /
                     "wasm32-unknown-wasi" / "libclang_rt.builtins.a"):
            require(path.exists(), f"missing pinned target input: {path}")
        for executable, expected in ((clang, "clang version 22.1.8"),
                                     (clangxx, "clang version 22.1.8"),
                                     (lld, "LLD 22.1.8"),
                                     (wasi_clang, "clang version 22.1.0"),
                                     (wasi_clangxx, "clang version 22.1.0")):
            result = subprocess.run([str(executable), "--version"], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
            require(expected in result.stdout, f"unexpected target compiler version: {result.stdout.strip()}")
        with temporary_directory(prefix="good-bear-target-toolchain-") as temporary:
            work = Path(temporary)
            c = work / "check.c"
            cpp = work / "check.cpp"
            wasi = work / "check-wasi.c"
            wasi_cpp = work / "check-wasi.cpp"
            c.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            cpp.write_text("int main() { return 0; }\n", encoding="utf-8")
            wasi.write_text("#include <time.h>\nint main(void) { return 0; }\n", encoding="utf-8")
            wasi_cpp.write_text("#include <cstring>\nint main() { return std::strlen(\"ru\") != 2; }\n", encoding="utf-8")
            run([str(clang), "-fuse-ld=lld", str(c), "-o", str(work / "check-c")])
            run([str(work / "check-c")])
            run([str(clangxx), "-fuse-ld=lld", str(cpp), "-o", str(work / "check-cpp")])
            run([str(work / "check-cpp")])
            common = ["--target=wasm32-wasi", f"--sysroot={sysroot}"]
            run([str(wasi_clang), *common, str(wasi), "-o", str(work / "check-wasi-c.wasm")])
            clock = work / "check-wasi-clock.c"
            clock.write_text("#include <time.h>\nint main(void) { return clock() == (clock_t)-1; }\n", encoding="utf-8")
            run([str(wasi_clang), *common, "-D_WASI_EMULATED_PROCESS_CLOCKS", str(clock),
                 "-lwasi-emulated-process-clocks", "-o", str(work / "check-wasi-clock.wasm")])
            run([str(wasi_clangxx), *common, str(wasi_cpp), "-o", str(work / "check-wasi-cpp.wasm")])
    except (OSError, subprocess.CalledProcessError, TargetToolchainError) as exc:
        print(f"ERROR: {exc}", flush=True)
        return 1
    print("Pinned Ubuntu LLVM/WASI target compatibility verified", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

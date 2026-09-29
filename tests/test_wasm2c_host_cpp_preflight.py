#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "wasm2c_host_cpp_preflight", ROOT / "tools" / "wasm2c_host_cpp_preflight.py"
)
assert SPEC and SPEC.loader
PREFLIGHT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PREFLIGHT
SPEC.loader.exec_module(PREFLIGHT)


class Wasm2cHostCppPreflightTest(unittest.TestCase):
    def fixture(self, temporary: Path) -> tuple[Path, dict[str, str]]:
        cxx = temporary / "llvm/bin/clang++"
        lld = temporary / "llvm/bin/lld"
        cxx.parent.mkdir(parents=True)
        for executable in (cxx, lld):
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
        return cxx, {
            "CXX": str(cxx.resolve()),
            "LD": str(lld.resolve()),
            "LDFLAGS": "-fuse-ld=lld",
        }

    def test_probe_traces_libstdcxx_then_compiles_links_and_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cxx, environment = self.fixture(Path(temporary))
            trace = subprocess.CompletedProcess([], 0, "", '"-lstdc++"')
            ok = subprocess.CompletedProcess([], 0, "", "")
            with mock.patch.object(PREFLIGHT.subprocess, "run", side_effect=(trace, ok, ok)) as run:
                PREFLIGHT.probe(cxx, environment)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn("-###", commands[0])
            self.assertIn("-fuse-ld=lld", commands[0])
            self.assertIn("-fuse-ld=lld", commands[1])
            self.assertEqual(commands[2][0], commands[1][-1])

    def test_probe_rejects_a_driver_trace_without_libstdcxx(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cxx, environment = self.fixture(Path(temporary))
            trace = subprocess.CompletedProcess([], 0, "", "ld.lld input.o")
            with mock.patch.object(PREFLIGHT.subprocess, "run", return_value=trace):
                with self.assertRaisesRegex(PREFLIGHT.PreflightError, "libstdc\\+\\+"):
                    PREFLIGHT.probe(cxx, environment)

    def test_probe_rejects_a_foreign_cxx_or_linker_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cxx, environment = self.fixture(Path(temporary))
            environment["CXX"] = "/usr/bin/g++"
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "locked clang\\+\\+ path"):
                PREFLIGHT.probe(cxx, environment)
            environment["CXX"] = str(cxx.resolve())
            environment["LDFLAGS"] = "-fuse-ld=gold"
            with self.assertRaisesRegex(PREFLIGHT.PreflightError, "locked lld"):
                PREFLIGHT.probe(cxx, environment)


if __name__ == "__main__":
    unittest.main()

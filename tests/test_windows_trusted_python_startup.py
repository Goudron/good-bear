#!/usr/bin/env python3
"""Actual local interpreter probes; these do not prove native Windows startup."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("trusted_windows_startup", ROOT / "tools/windows_offline_worker.py")
assert SPEC and SPEC.loader
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


class TrustedPythonStartupTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.entry = self.tools / "entry.py"
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.upper().startswith("PYTHON")}

    def command(self, *arguments):
        return NATIVE.trusted_python_command(sys.executable, self.entry, list(arguments), self.root / "private-cache")

    def run_command(self, command):
        result = subprocess.run(command, env=self.environment, capture_output=True, text=True, check=True)
        self.assertEqual(result.stderr, "")
        return result.stdout.strip()

    def test_environment_site_hook_is_blocked_and_reviewed_import_and_arguments_work(self):
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "sitecustomize.py").write_text("print('UNREVIEWED_STARTUP')\n")
        (self.tools / "reviewed_helper.py").write_text("VALUE = 'reviewed'\n")
        self.entry.write_text(
            "import json, sys, reviewed_helper\n"
            "print(json.dumps([reviewed_helper.VALUE, sys.argv[1:], sys.flags.isolated, sys.flags.no_site]))\n"
        )
        self.environment["PYTHONPATH"] = str(foreign)
        self.assertEqual(self.run_command([sys.executable, "-c", "print('ENTRY')"]),
                         "UNREVIEWED_STARTUP\nENTRY")
        self.environment["PYTHONHOME"] = str(foreign / "not-a-python-home")
        command = self.command("literal spaces", "$(not-a-command)")
        self.assertEqual(json.loads(self.run_command(command)),
                         ["reviewed", ["literal spaces", "$(not-a-command)"], 1, 1])
        cache = Path(command[6].split("=", 1)[1])
        self.assertEqual(list(cache.iterdir()), [])

    def test_matching_old_bytecode_is_ignored_with_a_fresh_cache_prefix(self):
        helper = self.tools / "reviewed_helper.py"
        helper.write_text("VALUE = 'stale-cache'\n")
        original = helper.stat()
        py_compile.compile(str(helper), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        helper.write_text("VALUE = 'source-code'\n")
        self.assertEqual(helper.stat().st_size, original.st_size)
        os.utime(helper, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.entry.write_text("import reviewed_helper\nprint(reviewed_helper.VALUE)\n")
        # -B only suppresses writing: a timestamp-valid old cache still executes.
        self.assertEqual(self.run_command([sys.executable, "-S", "-B", str(self.entry)]), "stale-cache")
        first, second = self.command(), self.command()
        self.assertNotEqual(first[6], second[6])
        for command in (first, second):
            self.assertEqual(self.run_command(command), "source-code")
            self.assertEqual(list(Path(command[6].split("=", 1)[1]).iterdir()), [])
            self.assertEqual(self.run_command(command), "source-code")

    def test_cache_parent_cannot_be_a_symlink(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "private-cache").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(NATIVE.NativeError, "reparse point"):
            self.command()
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Synthetic key bytes and modeled ACL decisions; not native Windows proof."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_m13_cloud_windows as fixtures
import safebrowsing_build_input as INPUT


ROUTE = fixtures.ROUTE
KEY = b"AIza" + b"0" * 35  # Deliberately synthetic; never a supplier key.


class WindowsPrivateBuildInputTest(unittest.TestCase):
    def setUp(self):
        fixtures.NativeCloudRouteTest.setUp(self)
        self.frozen = self.base / "frozen"
        self.source = self.frozen / "source"
        self.source.mkdir(parents=True)
        self.mozconfig = self.frozen / "build/windows/mozconfig.engine-test"
        self.mozconfig.parent.mkdir(parents=True)
        self.mozconfig.write_text("# Frozen Windows fixture\nac_add_options --disable-release\n")
        self.key = self.base / "supplier.key"
        self.key.write_bytes(KEY + b"\n")
        self.key.chmod(0o600)
        self.digest = hashlib.sha256(self.key.read_bytes()).hexdigest()
        self.contract = {"key_file_sha256": self.digest}
        self.contract_digest = "a" * 64
        self.job = {"id": "1" * 32, "phase": "engine-test"}
        self.stage = self.jobs / self.job["id"]
        self.stage.mkdir(parents=True)
        self.args.safebrowsing_key_file = self.key
        self.args.safebrowsing_contract_sha256 = self.contract_digest
        # Use the actual helper's Windows ACL branch without changing the host
        # pathlib/OS implementation or pretending these are native NTFS ACLs.
        modeled_os = SimpleNamespace(**{**vars(os), "name": "nt"})
        for patcher in (patch.object(ROUTE, "ROOT", self.frozen),
                        patch.object(ROUTE, "SOURCE", self.source),
                        patch.object(ROUTE, "WindowsBackend", return_value=self.backend),
                        patch.object(ROUTE, "load_safebrowsing_contract",
                                     return_value=(self.contract, self.contract_digest)),
                        patch.object(INPUT, "os", modeled_os)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def prepare(self):
        self.job["private_build_inputs"] = ROUTE.prepare_private_inputs(self.args, self.job, self.backend)
        return ROUTE.private_context(self.job, self.backend)

    def test_input_is_external_read_verified_and_metadata_contains_no_secret(self):
        context = self.prepare()
        key, wrapper = ROUTE.private_input_paths(self.job)
        self.assertEqual(key.read_bytes(), KEY + b"\n")
        self.assertFalse(key.is_relative_to(self.frozen))
        self.assertFalse(key.is_relative_to(context.objdir.parent))
        self.assertEqual(context.base_mozconfig, self.mozconfig)
        self.assertEqual(context.mozconfig, wrapper)
        self.assertNotIn(KEY, wrapper.read_bytes())
        self.assertNotIn(KEY.decode(), json.dumps(self.job))
        self.assertNotIn(KEY.decode(), repr(context))
        self.assertEqual(context.safebrowsing_evidence()["safebrowsing_keyfile_sha256"], self.digest)
        self.assertIn("verify-acl", self.backend.events)

    def test_wrong_contract_rejects_before_reading_key_or_creating_private_stage(self):
        self.args.safebrowsing_contract_sha256 = "b" * 64
        with patch.object(ROUTE, "verify_key_file") as verify, \
                self.assertRaisesRegex(ROUTE.RouteError, "contract hash differs"):
            ROUTE.prepare_private_inputs(self.args, self.job, self.backend)
        verify.assert_not_called()
        self.assertFalse((self.stage / "private-inputs").exists())

    def test_untrusted_acl_and_wrong_key_bytes_reject_before_staging(self):
        self.backend.trusted = False
        with self.assertRaisesRegex(INPUT.BuildInputError, "ACL verification"):
            ROUTE.prepare_private_inputs(self.args, self.job, self.backend)
        self.backend.trusted = True
        self.key.write_bytes(b"AIza" + b"1" * 35 + b"\n")
        with self.assertRaisesRegex(INPUT.BuildInputError, "SHA-256 mismatch"):
            ROUTE.prepare_private_inputs(self.args, self.job, self.backend)
        self.assertFalse((self.stage / "private-inputs").exists())

    def test_source_local_key_is_rejected_and_existing_private_stage_is_not_reused(self):
        inside = self.frozen / "supplier.key"
        inside.write_bytes(self.key.read_bytes())
        self.args.safebrowsing_key_file = inside
        with self.assertRaisesRegex(INPUT.BuildInputError, "outside source"):
            ROUTE.prepare_private_inputs(self.args, self.job, self.backend)
        self.args.safebrowsing_key_file = self.key
        self.prepare()
        with self.assertRaises(FileExistsError):
            ROUTE.prepare_private_inputs(self.args, self.job, self.backend)

    def test_context_rechecks_key_wrapper_base_acl_and_contract_before_use(self):
        context = self.prepare()
        key, wrapper = ROUTE.private_input_paths(self.job)
        for path in (key, wrapper, self.mozconfig):
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(path=path.name), self.assertRaises(INPUT.BuildInputError):
                context.validate_safebrowsing()
            path.write_bytes(original)
        self.backend.trusted = False
        with self.assertRaisesRegex(INPUT.BuildInputError, "ACL verification"):
            context.validate_safebrowsing()
        self.backend.trusted = True
        with patch.object(ROUTE, "load_safebrowsing_contract", return_value=(self.contract, "c" * 64)), \
                self.assertRaisesRegex(ROUTE.RouteError, "canonical native context"):
            context.validate_safebrowsing()

    def test_forged_descriptor_cannot_redirect_private_key_or_mozconfig(self):
        self.prepare()
        original = self.job["private_build_inputs"].copy()
        for field, replacement in (("key_file", str(self.key)), ("mozconfig", str(self.mozconfig)),
                                   ("supplier_contract_sha256", "b" * 64),
                                   ("safebrowsing_keyfile_sha256", "b" * 64),
                                   ("base_mozconfig_sha256", "b" * 64),
                                   ("effective_mozconfig_sha256", "b" * 64)):
            self.job["private_build_inputs"] = {**original, field: replacement}
            with self.subTest(field=field), self.assertRaises((ROUTE.RouteError, INPUT.BuildInputError)):
                ROUTE.private_context(self.job, self.backend)

    def test_selftest_never_opens_supplier_contract_or_key(self):
        self.job["phase"] = "isolation-selftest"
        with patch.object(ROUTE, "load_safebrowsing_contract", side_effect=AssertionError("supplier read")), \
                patch.object(ROUTE, "verify_key_file", side_effect=AssertionError("key read")):
            context = ROUTE.private_context(self.job, self.backend)
            self.assertIsNone(context._safebrowsing)
            self.job["private_build_inputs"] = {"key_file": str(self.key)}
            with self.assertRaisesRegex(ROUTE.RouteError, "cannot consume"):
                ROUTE.private_context(self.job, self.backend)
        self.args.phase = "isolation-selftest"
        with patch.object(ROUTE, "require_native"), self.assertRaisesRegex(ROUTE.RouteError, "must not consume"):
            ROUTE.arm(self.args, self.backend)
        self.assertEqual(self.backend.events, [])

    def write_status(self, context, **overrides):
        values = {"mozconfig": str(context.mozconfig), "topobjdir": str(context.objdir),
                  "topsrcdir": str(self.source), "substs": {"MOZ_GOOGLE_SAFEBROWSING_API_KEY": KEY.decode()},
                  "defines": {}, "__all__": ["topobjdir", "topsrcdir", "defines", "substs", "mozconfig"]}
        values.update(overrides)
        context.objdir.mkdir(parents=True, exist_ok=True)
        path = context.objdir / "config.status"
        path.write_text("from mozbuild.configure.constants import *\n" +
                        "\n".join(f"{name} = {value!r}" for name, value in values.items()))
        return path

    def test_configure_output_must_bind_current_paths_and_exact_supplier_key(self):
        context = self.prepare()
        self.write_status(context)
        ROUTE.verify_configured_private_input(context)
        for changes in ({"mozconfig": str(self.mozconfig)}, {"topobjdir": "foreign"},
                        {"topsrcdir": "foreign"}, {"substs": {}},
                        {"substs": {"MOZ_GOOGLE_SAFEBROWSING_API_KEY": "wrong"}}):
            self.write_status(context, **changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ROUTE.RouteError, "did not bind"):
                ROUTE.verify_configured_private_input(context)

    def test_config_status_is_parsed_without_executing_code(self):
        context = self.prepare()
        path = self.write_status(context)
        marker = self.base / "must-not-exist"
        with path.open("a") as stream:
            stream.write(f"\nopen({str(marker)!r}, 'w').write('executed')\n")
        with self.assertRaisesRegex(ROUTE.RouteError, "unsupported native config.status statement"):
            ROUTE.verify_configured_private_input(context)
        self.assertFalse(marker.exists())
        path = self.write_status(context)
        with path.open("a") as stream:
            stream.write("\nsubsts = dict()\n")
        with self.assertRaisesRegex(ROUTE.RouteError, "ambiguous"):
            ROUTE.verify_configured_private_input(context)

    def test_only_exact_upstream_config_status_entrypoint_is_accepted(self):
        context = self.prepare()
        path = self.write_status(context)
        main = ("\nif __name__ == '__main__':\n"
                "    from mozbuild.config_status import config_status\n"
                "    args = dict([(name, globals()[name]) for name in __all__])\n"
                "    config_status(**args)\n")
        original = path.read_text()
        path.write_text(original + main)
        ROUTE.verify_configured_private_input(context)
        for replacement in (main + main, main.replace("config_status(**args)", "print(args)"),
                            "\nimport os\n", "\nsubsts = dict()\n"):
            path.write_text(original + replacement)
            with self.subTest(replacement=replacement), self.assertRaises(ROUTE.RouteError):
                ROUTE.verify_configured_private_input(context)

    def test_live_process_stdout_and_stderr_are_redacted_before_log_write(self):
        context = self.prepare()
        log = self.base / "configure.log"
        script = ("import os\n"
                  f"key={KEY!r}\n"
                  "os.write(1,b'x'*65530+key[:17])\n"
                  "os.write(1,key[17:]+b' end\\n')\n"
                  "os.write(2,key+b' stderr\\n')\n")
        code = ROUTE.run_redacted_command([sys.executable, "-I", "-S", "-c", script], {}, log, context)
        self.assertEqual(code, 0)
        data = log.read_bytes()
        self.assertNotIn(KEY, data)
        self.assertEqual(data.count(b"[REDACTED-SAFEBROWSING-KEY]"), 2)
        self.assertIn(b"stderr", data)

    def test_collection_does_not_export_private_input_or_generated_config(self):
        context = self.prepare()
        self.write_status(context)
        self.job["workspace"] = str(context.objdir.parent)
        path = self.stage / "job.json"
        ROUTE.atomic_json(path, self.job)
        (context.objdir.parent / "configure.log").write_bytes(b"redacted only\n")
        output = self.base / "collected"
        ROUTE.collect(self.job, {"network_restored": True, "status": "finished", "exit_code": 0}, path, output)
        self.assertEqual({item.name for item in output.iterdir()}, {"job.json", "configure.log", "sha256.json"})
        for item in output.iterdir():
            self.assertNotIn(KEY, item.read_bytes())


if __name__ == "__main__":
    unittest.main()

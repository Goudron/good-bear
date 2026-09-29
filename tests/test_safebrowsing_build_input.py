"""Synthetic keys only; POSIX file and shell checks are not Windows ACL proof."""

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import safebrowsing_build_input as INPUT


# Deliberately synthetic format fixture, never a supplier credential.
KEY = b"AIza" + b"0" * 35
OTHER_KEY = b"AIza" + b"1" * 35


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SafeBrowsingInputTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="goodbear-key-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "frozen-source"
        self.source.mkdir()
        self.base = self.source / "mozconfig.host"
        self.base.write_text("# Frozen fixture\nac_add_options --disable-release\n")
        self.key = self.root / "supplier.key"
        self.key.write_bytes(KEY + b"\n")
        self.key.chmod(0o600)
        self.wrapper = self.root / "effective.mozconfig"

    def verify(self, path=None, expected=None):
        return INPUT.verify_key_file(path or self.key, expected or digest(self.key.read_bytes()),
                                     forbidden_roots=(self.source,))

    def create(self, **overrides):
        arguments = {"base_mozconfig": self.base,
                     "expected_base_sha256": digest(self.base.read_bytes()),
                     "key_input": self.verify(), "wrapper_path": self.wrapper,
                     "source_root": self.source}
        arguments.update(overrides)
        return INPUT.create_effective_mozconfig(**arguments)

    def test_exact_bytes_and_metadata_have_no_key_value(self):
        verified = self.verify()
        self.assertEqual(verified.sha256, digest(KEY + b"\n"))
        self.assertEqual(verified.size, 40)
        self.assertNotIn(KEY.decode(), repr(verified))
        binding = self.create()
        self.assertEqual(binding.key_sha256, verified.sha256)
        self.assertEqual(binding.environment(), {"MOZCONFIG": str(self.wrapper)})
        self.assertNotIn(KEY.decode(), repr(binding))
        self.assertNotIn(KEY.decode(), repr(binding.evidence()))
        self.assertNotIn(KEY, self.wrapper.read_bytes())
        self.assertEqual(stat.S_IMODE(self.wrapper.stat().st_mode), 0o400)
        INPUT.verify_effective_mozconfig(binding)

    def test_optional_lf_crlf_are_distinct_frozen_bytes(self):
        hashes = set()
        for suffix in (b"", b"\n", b"\r\n"):
            self.key.write_bytes(KEY + suffix)
            verified = self.verify()
            hashes.add(verified.sha256)
            self.assertEqual(verified.log_redactor().feed(KEY), b"[REDACTED-SAFEBROWSING-KEY]")
        self.assertEqual(len(hashes), 3)

    def test_digest_absence_wrong_case_and_mismatch_fail(self):
        for value in ("", "0" * 64, digest(self.key.read_bytes()).upper(), KEY.decode()):
            with self.subTest(value_length=len(value)):
                with self.assertRaises(INPUT.BuildInputError) as caught:
                    INPUT.verify_key_file(self.key, value, forbidden_roots=(self.source,))
                self.assertNotIn(KEY.decode(), str(caught.exception))

    def test_format_and_size_reject_placeholders_and_multiple_values(self):
        for content in (b"", b"no-google-safebrowsing-api-key", b"test", b" " + KEY,
                        KEY + b" ", KEY + b"\n" + OTHER_KEY, KEY + b"\0", b"x" * 129,
                        b"AIza" + b"0" * 34, b"AIza" + b"0" * 36):
            self.key.write_bytes(content)
            with self.subTest(size=len(content)), self.assertRaises(INPUT.BuildInputError):
                self.verify()

    def test_missing_file_relative_path_traversal_and_source_location_rejected(self):
        for path in (self.root / "absent", Path("supplier.key"),
                     self.root / "unused" / ".." / "supplier.key"):
            with self.subTest(path_kind=path.name), self.assertRaises(INPUT.BuildInputError):
                self.verify(path, digest(KEY + b"\n"))
        inside = self.source / "supplier.key"
        inside.write_bytes(KEY)
        inside.chmod(0o600)
        with self.assertRaisesRegex(INPUT.BuildInputError, "outside"):
            self.verify(inside, digest(KEY))
        with self.assertRaisesRegex(INPUT.BuildInputError, "excluded source roots"):
            INPUT.verify_key_file(self.key, digest(KEY + b"\n"), forbidden_roots=())

    @unittest.skipIf(os.name == "nt", "POSIX permission semantics")
    def test_posix_exact_0600_and_current_owner_required(self):
        for mode in (0o400, 0o640, 0o644, 0o660, 0o700, 0o1600):
            self.key.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(INPUT.BuildInputError):
                self.verify()
        self.key.chmod(0o600)
        with mock.patch.object(INPUT.os, "geteuid", return_value=self.key.stat().st_uid + 1):
            with self.assertRaisesRegex(INPUT.BuildInputError, "foreign owner"):
                self.verify()

    def test_symlink_leaf_and_parent_and_hardlink_rejected(self):
        leaf = self.root / "key-link"
        leaf.symlink_to(self.key)
        parent = self.root / "linked-parent"
        parent.symlink_to(self.root, target_is_directory=True)
        for path in (leaf, parent / self.key.name):
            with self.assertRaisesRegex(INPUT.BuildInputError, "symlinks"):
                self.verify(path)
        linked = self.root / "hardlink"
        os.link(self.key, linked)
        with self.assertRaisesRegex(INPUT.BuildInputError, "hard-linked"):
            self.verify()

    def test_reparse_attribute_is_rejected_before_read(self):
        original = Path.lstat

        def observed(path):
            info = original(path)
            if path == self.key:
                return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
            return info

        with mock.patch.object(Path, "lstat", observed):
            with self.assertRaisesRegex(INPUT.BuildInputError, "reparse"):
                self.verify()

    def test_windows_path_requires_explicit_successful_external_acl_check(self):
        # Exercise delegation only; this does not assert any native ACL works.
        with mock.patch.object(INPUT.os, "name", "nt"):
            with self.assertRaisesRegex(INPUT.BuildInputError, "ACL verification is required"):
                INPUT._read(self.key, limit=128, private_mode=0o600)
            for result in (False, None, 1, "passed"):
                checker = mock.Mock(return_value=result)
                with self.assertRaisesRegex(INPUT.BuildInputError, "ACL verification failed"):
                    INPUT._read(self.key, limit=128, private_mode=0o600,
                                windows_acl_verifier=checker, purpose="private-key")
            checker = mock.Mock(return_value=True)
            self.assertEqual(INPUT._read(self.key, limit=128, private_mode=0o600,
                                         windows_acl_verifier=checker, purpose="private-key"),
                             KEY + b"\n")
            checker.assert_called_once_with(self.key, "private-key")
            checker.side_effect = RuntimeError(KEY.decode())
            with self.assertRaises(INPUT.BuildInputError) as caught:
                INPUT._read(self.key, limit=128, private_mode=0o600,
                            windows_acl_verifier=checker, purpose="private-key")
            self.assertNotIn(KEY.decode(), str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)

    def test_permission_change_between_stat_and_open_is_rejected(self):
        original = INPUT.os.open

        def changed(path, flags, *args):
            descriptor = original(path, flags, *args)
            if path == self.key:
                self.key.chmod(0o644)
            return descriptor

        with mock.patch.object(INPUT.os, "open", changed):
            with self.assertRaisesRegex(INPUT.BuildInputError, "changed while being opened"):
                self.verify()

    def test_foreign_directory_and_fifo_are_not_regular_inputs(self):
        with self.assertRaisesRegex(INPUT.BuildInputError, "regular input"):
            self.verify(self.root)
        if hasattr(os, "mkfifo"):
            fifo = self.root / "pipe"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(INPUT.BuildInputError, "regular input"):
                self.verify(fifo)

    def test_key_in_path_and_control_characters_are_not_exposed(self):
        for name in (KEY.decode(), "bad\nname"):
            path = self.root / name
            path.write_bytes(KEY)
            path.chmod(0o600)
            with self.assertRaises(INPUT.BuildInputError) as caught:
                self.verify(path, digest(KEY))
            self.assertNotIn(KEY.decode(), str(caught.exception))

    def test_wrapper_requires_exact_base_and_cannot_enter_source(self):
        with self.assertRaisesRegex(INPUT.BuildInputError, "SHA-256"):
            self.create(expected_base_sha256="0" * 64)
        with self.assertRaisesRegex(INPUT.BuildInputError, "outside"):
            self.create(wrapper_path=self.source / "wrapper")
        with self.assertRaisesRegex(INPUT.BuildInputError, "control"):
            self.create(wrapper_path=self.root / "bad\rname")
        self.assertFalse(self.wrapper.exists())

    def test_wrapper_does_not_replace_existing_file_or_symlink(self):
        self.wrapper.write_text("keep existing")
        with self.assertRaises(INPUT.BuildInputError):
            self.create()
        self.assertEqual(self.wrapper.read_text(), "keep existing")
        self.wrapper.unlink()
        self.wrapper.symlink_to(self.base)
        with self.assertRaises(INPUT.BuildInputError):
            self.create()
        self.assertTrue(self.wrapper.is_symlink())

    def test_key_rotation_and_base_edit_require_new_binding(self):
        binding = self.create()
        self.key.write_bytes(OTHER_KEY + b"\n")
        with self.assertRaisesRegex(INPUT.BuildInputError, "SHA-256"):
            INPUT.verify_effective_mozconfig(binding)
        self.key.write_bytes(KEY + b"\n")
        self.base.write_text("changed frozen base\n")
        with self.assertRaisesRegex(INPUT.BuildInputError, "SHA-256"):
            INPUT.verify_effective_mozconfig(binding)

    def test_wrapper_tamper_is_rejected_even_with_updated_digest(self):
        binding = self.create()
        self.wrapper.chmod(0o600)
        self.wrapper.write_text("# no keyfile\n")
        self.wrapper.chmod(0o400)
        with self.assertRaisesRegex(INPUT.BuildInputError, "SHA-256"):
            INPUT.verify_effective_mozconfig(binding)
        forged = replace(binding, sha256=digest(self.wrapper.read_bytes()))
        with self.assertRaisesRegex(INPUT.BuildInputError, "does not match"):
            INPUT.verify_effective_mozconfig(forged)

    @unittest.skipIf(os.name == "nt", "POSIX permission semantics")
    def test_existing_wrapper_becoming_writable_is_rejected(self):
        binding = self.create()
        self.wrapper.chmod(0o600)
        with self.assertRaisesRegex(INPUT.BuildInputError, "permissions"):
            INPUT.verify_effective_mozconfig(binding)

    def test_creation_failure_cleans_only_new_unverified_file(self):
        with mock.patch.object(INPUT, "verify_effective_mozconfig",
                               side_effect=INPUT.BuildInputError("test verification failure")):
            with self.assertRaises(INPUT.BuildInputError):
                self.create()
        self.assertFalse(self.wrapper.exists())

    def test_secret_cannot_be_in_frozen_base_or_wrapper_path(self):
        self.base.write_bytes(b"# " + KEY + b"\n")
        with self.assertRaisesRegex(INPUT.BuildInputError, "secret bytes"):
            self.create()
        self.base.write_text("# fixture\n")
        with self.assertRaisesRegex(INPUT.BuildInputError, "key value"):
            self.create(wrapper_path=self.root / KEY.decode())
        named_source = self.root / KEY.decode()
        named_source.mkdir()
        with self.assertRaisesRegex(INPUT.BuildInputError, "key value"):
            self.create(source_root=named_source)

    @unittest.skipUnless(shutil.which("sh"), "requires a local POSIX shell")
    def test_effective_wrapper_shell_quotes_paths_without_execution(self):
        self.base.rename(self.root / "base'$(touch EXPLOITED) config")
        self.base = self.root / "base'$(touch EXPLOITED) config"
        self.base.write_text('ac_add_options() { printf "%s\\n" "$1"; }\n')
        moved = self.root / "key'$(touch EXPLOITED) file"
        self.key.rename(moved)
        self.key = moved
        binding = self.create()
        with mock.patch.dict(os.environ, {"MOZCONFIG": "untrusted", "MOZ_CONFIGURE_OPTIONS": "ignored"}):
            self.assertEqual(binding.environment(), {"MOZCONFIG": str(self.wrapper)})
            completed = subprocess.run([shutil.which("sh"), str(self.wrapper)], cwd=self.root,
                                       text=True, capture_output=True, check=True)
        self.assertEqual(completed.stdout.strip(),
                         "--with-google-safebrowsing-api-keyfile=" + self.key.as_posix())
        self.assertFalse((self.root / "EXPLOITED").exists())
        self.assertNotIn(KEY.decode(), completed.stdout + completed.stderr)


class KeyLogRedactorTest(unittest.TestCase):
    def test_every_single_split_boundary_and_repeated_secrets(self):
        raw = b"before " + KEY + b" middle " + KEY + b" after"
        expected = raw.replace(KEY, b"[REDACTED-SAFEBROWSING-KEY]")
        for boundary in range(len(raw) + 1):
            redactor = INPUT.KeyLogRedactor(KEY)
            pieces = [redactor.feed(raw[:boundary]), redactor.feed(raw[boundary:]), redactor.finish()]
            self.assertEqual(b"".join(pieces), expected)
            self.assertNotIn(KEY, b"".join(pieces))

    def test_bytewise_chunks_unicode_and_partial_tail_preserve_nonsecret_output(self):
        raw = "Проверка: ".encode() + KEY + b"\npartial AIza000"
        redactor = INPUT.KeyLogRedactor(KEY)
        output = b"".join(redactor.feed(bytes([value])) for value in raw) + redactor.finish()
        self.assertEqual(output, raw.replace(KEY, b"[REDACTED-SAFEBROWSING-KEY]"))
        self.assertNotIn(KEY, output)

    def test_prefix_is_held_before_any_fragment_can_complete_secret(self):
        redactor = INPUT.KeyLogRedactor(KEY)
        self.assertEqual(redactor.feed(b"prefix:" + KEY[:-1]), b"prefix:")
        self.assertEqual(redactor.feed(KEY[-1:]), b"[REDACTED-SAFEBROWSING-KEY]")
        self.assertEqual(redactor.finish(), b"")
        self.assertNotIn(KEY.decode(), repr(redactor))

    def test_finished_stream_and_wrong_types_fail_without_value_echo(self):
        redactor = INPUT.KeyLogRedactor(KEY)
        with self.assertRaises(INPUT.BuildInputError):
            redactor.feed(KEY.decode())
        redactor.finish()
        for action in (lambda: redactor.feed(KEY), redactor.finish):
            with self.assertRaises(INPUT.BuildInputError) as caught:
                action()
            self.assertNotIn(KEY.decode(), str(caught.exception))
        for malformed in (KEY + b"\n", b"placeholder"):
            with self.assertRaises(INPUT.BuildInputError):
                INPUT.KeyLogRedactor(malformed)


if __name__ == "__main__":
    unittest.main()

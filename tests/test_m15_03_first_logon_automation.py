#!/usr/bin/env python3
"""Focused safety tests for the one-shot M15-03 LogonUI recovery helper."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import automate_m15_03_boot_prompt as RFB  # noqa: E402
import automate_m15_03_first_logon as FIRST  # noqa: E402


class _FakeSocket:
    def __init__(self, incoming: bytes) -> None:
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    def recv(self, length: int) -> bytes:
        result = bytes(self.incoming[:length])
        del self.incoming[:length]
        return result

    def sendall(self, value: bytes) -> None:
        self.sent.extend(value)

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _server_init(width: int = 16, height: int = 8, name: bytes = b"local") -> bytes:
    return (width.to_bytes(2, "big") + height.to_bytes(2, "big") + bytes(16)
            + len(name).to_bytes(4, "big") + name)


def _raw_frame(width: int = 16, height: int = 8, *, painted: bool = True) -> bytes:
    pixels = (b"\x01\x02\x03\x00" if painted else b"\x00\x00\x00\x00") * (width * height)
    rectangle = ((0).to_bytes(2, "big") * 2 + width.to_bytes(2, "big")
                 + height.to_bytes(2, "big") + (0).to_bytes(4, "big", signed=True) + pixels)
    return b"\x00\x00\x00\x01" + rectangle


def _rfb_session() -> bytes:
    return RFB.RFB_VERSION + b"\x01\x01" + b"\x00\x00\x00\x00" + _server_init() + _raw_frame() + _raw_frame()


class M1503FirstLogonAutomationTest(unittest.TestCase):
    def _runner(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.assertEqual(command[:3], ["virsh", "-c", "qemu:///system"])
        self.assertEqual(command[3], FIRST.EXPECTED_DOMAIN if command[3] == FIRST.EXPECTED_DOMAIN else command[3])
        if command[3] == "domstate":
            self.assertEqual(command, ["virsh", "-c", "qemu:///system", "domstate", FIRST.EXPECTED_DOMAIN])
            return subprocess.CompletedProcess(command, 0, stdout="running\n", stderr="")
        self.assertEqual(command, ["virsh", "-c", "qemu:///system", "domdisplay", FIRST.EXPECTED_DOMAIN, "--type", "vnc"])
        # libvirt domdisplay reports a display number, not an RFB TCP port.
        return subprocess.CompletedProcess(command, 0, stdout="vnc://127.0.0.1:1\n", stderr="")

    def _temporary_project_root(self) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        (Path(temporary.name) / "build" / FIRST.VM_DIRECTORY_NAME).mkdir(parents=True)
        return temporary

    def test_credential_is_mutable_complex_and_clearable(self) -> None:
        credential = FIRST.make_temporary_credential()
        self.assertIsInstance(credential, bytearray)
        self.assertEqual(len(credential), FIRST.TEMPORARY_CREDENTIAL_LENGTH)
        for group in (FIRST.UPPERCASE, FIRST.LOWERCASE, FIRST.DIGITS, FIRST.SYMBOLS):
            self.assertTrue(any(value in group for value in credential))
        FIRST.clear_credential(credential)
        self.assertEqual(credential, bytearray(FIRST.TEMPORARY_CREDENTIAL_LENGTH))

    def test_libvirt_display_number_is_normalized_and_nonlocal_or_out_of_range_forms_fail_closed(self) -> None:
        self.assertEqual(FIRST.parse_libvirt_local_vnc_display("vnc://127.0.0.1:0"), "vnc://127.0.0.1:5900")
        self.assertEqual(FIRST.parse_libvirt_local_vnc_display("vnc://127.0.0.1:99"), "vnc://127.0.0.1:5999")
        for unsafe in (
            "vnc://127.0.0.1:100", "vnc://127.0.0.1:5900", "vnc://localhost:0",
            "vnc://0.0.0.0:0", "https://127.0.0.1:0", "vnc://user@127.0.0.1:0",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(FIRST.FirstLogonAutomationError):
                FIRST.parse_libvirt_local_vnc_display(unsafe)

    def test_first_logon_readiness_accepts_late_painted_frames_without_uefi_assumptions(self) -> None:
        # The first frame can still be black while LogonUI is being painted;
        # this helper accepts the initial later painted frame and never assumes
        # that the guest is in UEFI Boot Manager.
        fake = _FakeSocket(_raw_frame(painted=False) + _raw_frame())
        RFB.set_raw_pixel_format(fake)
        # Reset the sent bytes after setup so the assertion below focuses on
        # the fact that this readiness path sends no input keys.
        fake.sent.clear()
        FIRST.wait_for_first_logon_readiness(fake, 16, 8, sleeper=lambda _seconds: None,
                                             settle_seconds=0.5, attempts=3)
        self.assertNotIn(b"\x04", fake.sent)

    def test_dispatch_derives_only_exact_domain_loopback_target_and_never_records_credential(self) -> None:
        temporary = self._temporary_project_root()
        self.addCleanup(temporary.cleanup)
        captured = bytearray((65, 98, 51, 33) * 8)
        fake = _FakeSocket(_rfb_session())
        with mock.patch.object(FIRST, "ROOT", Path(temporary.name)):
            result = FIRST.dispatch_first_logon(
                runner=self._runner, connector=lambda *_args, **_kwargs: fake,
                sleeper=lambda _seconds: None, credential_factory=lambda: captured,
            )
            marker = Path(temporary.name) / "build" / FIRST.VM_DIRECTORY_NAME / FIRST.MARKER_NAME
            evidence = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual(result["target"], "vnc://127.0.0.1:5901")
        self.assertFalse(result["credential_recorded"])
        self.assertTrue(result["vnc_loopback_only"])
        self.assertEqual(captured, bytearray(FIRST.TEMPORARY_CREDENTIAL_LENGTH))
        self.assertFalse(evidence["credential_recorded"])
        self.assertEqual(evidence["credential_length"], FIRST.TEMPORARY_CREDENTIAL_LENGTH)
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertIn(RFB.KEY_ENTER.to_bytes(4, "big"), fake.sent)
        self.assertIn(FIRST.KEY_TAB.to_bytes(4, "big"), fake.sent)

    def test_exact_reserved_marker_is_retried_once_without_recording_credential(self) -> None:
        temporary = self._temporary_project_root()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        marker = root / "build" / FIRST.VM_DIRECTORY_NAME / FIRST.MARKER_NAME
        marker.write_bytes(FIRST.RESERVED_MARKER)
        marker.chmod(0o600)
        captured = bytearray((65, 98, 51, 33) * 8)
        fake = _FakeSocket(_rfb_session())
        with mock.patch.object(FIRST, "ROOT", root):
            result = FIRST.dispatch_first_logon(
                runner=self._runner, connector=lambda *_args, **_kwargs: fake,
                sleeper=lambda _seconds: None, credential_factory=lambda: captured,
            )
            evidence = json.loads(marker.read_text(encoding="utf-8"))
        self.assertTrue(result["reserved_marker_retried"])
        self.assertEqual(result["reserved_marker_retry_number"], 1)
        self.assertFalse(evidence["credential_recorded"])
        self.assertEqual(captured, bytearray(FIRST.TEMPORARY_CREDENTIAL_LENGTH))

    def test_exact_reserved_retry_marker_is_consumed_for_one_final_precredential_retry(self) -> None:
        temporary = self._temporary_project_root()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        marker = root / "build" / FIRST.VM_DIRECTORY_NAME / FIRST.MARKER_NAME
        marker.write_bytes(FIRST.RESERVED_RETRY_MARKER)
        marker.chmod(0o600)
        captured = bytearray((65, 98, 51, 33) * 8)
        fake = _FakeSocket(_rfb_session())
        with mock.patch.object(FIRST, "ROOT", root):
            result = FIRST.dispatch_first_logon(
                runner=self._runner, connector=lambda *_args, **_kwargs: fake,
                sleeper=lambda _seconds: None, credential_factory=lambda: captured,
            )
        self.assertEqual(result["reserved_marker_retry_number"], 2)
        self.assertEqual(captured, bytearray(FIRST.TEMPORARY_CREDENTIAL_LENGTH))

    def test_completed_or_credential_dispatch_marker_fails_closed_before_a_second_connection(self) -> None:
        for content in (FIRST.RESERVED_RETRY_CONSUMED_MARKER, FIRST.DISPATCHING_MARKER,
                        b'{"schema_version":1,"state":"completed"}\n', b"not-json\n"):
            with self.subTest(content=content):
                temporary = self._temporary_project_root()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name)
                marker = root / "build" / FIRST.VM_DIRECTORY_NAME / FIRST.MARKER_NAME
                marker.write_bytes(content)
                marker.chmod(0o600)
                with mock.patch.object(FIRST, "ROOT", root):
                    with self.assertRaisesRegex(FIRST.FirstLogonAutomationError, "completed, malformed"):
                        FIRST.dispatch_first_logon(
                            runner=self._runner,
                            connector=lambda *_args, **_kwargs: self.fail("must not connect after marker rejection"),
                            sleeper=lambda _seconds: None,
                        )

    def test_confirmed_static_logonui_fallback_accepts_only_exhausted_precredential_marker(self) -> None:
        temporary = self._temporary_project_root()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        marker = root / "build" / FIRST.VM_DIRECTORY_NAME / FIRST.MARKER_NAME
        marker.write_bytes(FIRST.RESERVED_RETRY_CONSUMED_MARKER)
        marker.chmod(0o600)
        captured = bytearray((65, 98, 51, 33) * 8)
        # The fallback deliberately consumes no framebuffer bytes after
        # ServerInit; static LogonUI is confirmed by a separate libvirt probe.
        handshake_only = RFB.RFB_VERSION + b"\x01\x01" + b"\x00\x00\x00\x00" + _server_init()
        fake = _FakeSocket(handshake_only)
        with mock.patch.object(FIRST, "ROOT", root):
            result = FIRST.dispatch_confirmed_static_logonui(
                runner=self._runner, connector=lambda *_args, **_kwargs: fake,
                sleeper=lambda _seconds: None, credential_factory=lambda: captured,
            )
            evidence = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual(result["action"], "confirmed-static-logonui-temporary-credential-dispatched")
        self.assertFalse(result["framebuffer_read"])
        self.assertFalse(evidence["credential_recorded"])
        self.assertEqual(captured, bytearray(FIRST.TEMPORARY_CREDENTIAL_LENGTH))
        self.assertIn(RFB.KEY_ENTER.to_bytes(4, "big"), fake.sent)
        self.assertIn(FIRST.KEY_TAB.to_bytes(4, "big"), fake.sent)

    def test_confirmed_static_logonui_fallback_rejects_any_nonexhausted_marker(self) -> None:
        for content in (FIRST.RESERVED_MARKER, FIRST.RESERVED_RETRY_MARKER,
                        FIRST.DISPATCHING_MARKER, b"invalid\n"):
            with self.subTest(content=content):
                temporary = self._temporary_project_root()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name)
                marker = root / "build" / FIRST.VM_DIRECTORY_NAME / FIRST.MARKER_NAME
                marker.write_bytes(content)
                marker.chmod(0o600)
                with mock.patch.object(FIRST, "ROOT", root):
                    with self.assertRaisesRegex(FIRST.FirstLogonAutomationError, "exact exhausted"):
                        FIRST.dispatch_confirmed_static_logonui(
                            runner=self._runner,
                            connector=lambda *_args, **_kwargs: self.fail("must not connect after marker rejection"),
                            sleeper=lambda _seconds: None,
                        )

    def test_pre_credential_readiness_failure_leaves_only_the_exact_retryable_reserved_marker(self) -> None:
        temporary = self._temporary_project_root()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake = _FakeSocket(
            RFB.RFB_VERSION + b"\x01\x01" + b"\x00\x00\x00\x00" + _server_init()
            + b"".join(_raw_frame(painted=False) for _ in range(10))
        )
        with mock.patch.object(FIRST, "ROOT", root):
            with self.assertRaisesRegex(FIRST.FirstLogonAutomationError, "initial painted"):
                FIRST.dispatch_first_logon(
                    runner=self._runner, connector=lambda *_args, **_kwargs: fake,
                    sleeper=lambda _seconds: None,
                    credential_factory=lambda: self.fail("credential must not be generated before readiness"),
                )
        marker = root / "build" / FIRST.VM_DIRECTORY_NAME / FIRST.MARKER_NAME
        self.assertEqual(marker.read_bytes(), FIRST.RESERVED_MARKER)
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def test_non_loopback_endpoint_is_rejected_before_marker_or_connection(self) -> None:
        temporary = self._temporary_project_root()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        def unsafe_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            if command[3] == "domstate":
                return subprocess.CompletedProcess(command, 0, stdout="running\n", stderr="")
            return subprocess.CompletedProcess(command, 0, stdout="vnc://0.0.0.0:1\n", stderr="")

        with mock.patch.object(FIRST, "ROOT", root):
            with self.assertRaisesRegex(FIRST.FirstLogonAutomationError, "endpoint rejected"):
                FIRST.dispatch_first_logon(
                    runner=unsafe_runner,
                    connector=lambda *_args, **_kwargs: self.fail("must not connect to non-loopback VNC"),
                    sleeper=lambda _seconds: None,
                )
        self.assertFalse((root / "build" / FIRST.VM_DIRECTORY_NAME / FIRST.MARKER_NAME).exists())


if __name__ == "__main__":
    unittest.main()

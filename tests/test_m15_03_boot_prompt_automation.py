#!/usr/bin/env python3
"""Narrow structural tests for the M15-03 local-only boot prompt helper."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import automate_m15_03_boot_prompt as BOOT  # noqa: E402
import execute_m15_03_local_kvm as EXEC  # noqa: E402


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
    # The pixel format is ignored because the client selects its fixed raw BGRX
    # format immediately after ServerInit.
    return (width.to_bytes(2, "big") + height.to_bytes(2, "big") + bytes(16)
            + len(name).to_bytes(4, "big") + name)


def _raw_frame(width: int = 16, height: int = 8, *, painted: bool = True) -> bytes:
    pixels = (b"\x01\x02\x03\x00" if painted else b"\x00\x00\x00\x00") * (width * height)
    rectangle = ((0).to_bytes(2, "big") * 2 + width.to_bytes(2, "big")
                 + height.to_bytes(2, "big") + (0).to_bytes(4, "big", signed=True) + pixels)
    return b"\x00\x00\x00\x01" + rectangle


def _rfb_session(*frames: bytes) -> bytes:
    return BOOT.RFB_VERSION + b"\x01\x01" + b"\x00\x00\x00\x00" + _server_init() + b"".join(frames)


class M1503BootPromptAutomationTest(unittest.TestCase):
    def test_vnc_url_is_exact_loopback_and_a_narrow_libvirt_port_range(self) -> None:
        self.assertEqual(BOOT.parse_local_vnc_url("vnc://127.0.0.1:5900"), ("127.0.0.1", 5900))
        for forbidden in ("vnc://localhost:5900", "vnc://0.0.0.0:5900", "vnc://192.0.2.1:5900",
                          "vnc://127.0.0.1:22", "vnc://user:secret@127.0.0.1:5900"):
            with self.subTest(forbidden=forbidden), self.assertRaises(BOOT.BootAutomationError):
                BOOT.parse_local_vnc_url(forbidden)

    def test_xml_derivation_adds_only_loopback_vnc_to_headless_marker(self) -> None:
        headless = "<domain><devices>\n    <!-- Deliberately no graphical device: libvirt's supported headless form. -->\n</devices></domain>"
        result = EXEC.render_loopback_boot_automation_xml(headless)
        self.assertIn('<graphics type="vnc" port="-1" autoport="yes" listen="127.0.0.1">', result)
        self.assertIn('<listen type="address" address="127.0.0.1"/>', result)
        self.assertNotIn("0.0.0.0", result)
        with self.assertRaises(EXEC.KvmExecutionError):
            EXEC.render_loopback_boot_automation_xml("<domain><graphics/></domain>")

    def test_inject_uses_only_none_auth_and_the_two_fixed_keys(self) -> None:
        # Server banner, only security type None, ServerInit, then two painted
        # frames.  The helper must not inject before both frame gates pass.
        fake = _FakeSocket(_rfb_session(_raw_frame(), _raw_frame()))
        result = BOOT.inject("vnc://127.0.0.1:5901", connector=lambda *_args, **_kwargs: fake,
                             sleeper=lambda _seconds: None)
        self.assertEqual(result["keys_sent"], ["Enter", "Space"])
        self.assertEqual(result["authentication_supported"], False)
        self.assertEqual(result["readiness_gate"], "two-transient-nonblank-raw-framebuffer-updates")
        self.assertIn(BOOT.RFB_VERSION, fake.sent)
        self.assertIn(BOOT.KEY_ENTER.to_bytes(4, "big"), fake.sent)
        self.assertIn(BOOT.KEY_SPACE.to_bytes(4, "big"), fake.sent)

    def test_inject_refuses_password_or_other_authentication(self) -> None:
        fake = _FakeSocket(BOOT.RFB_VERSION + b"\x01\x02")
        with self.assertRaisesRegex(BOOT.BootAutomationError, "only unauthenticated"):
            BOOT.inject("vnc://127.0.0.1:5901", connector=lambda *_args, **_kwargs: fake,
                        sleeper=lambda _seconds: None)

    def test_inject_refuses_a_blank_pre_display_frame_without_sending_keys(self) -> None:
        fake = _FakeSocket(_rfb_session(_raw_frame(painted=False)))
        with self.assertRaisesRegex(BOOT.BootAutomationError, "not yet displaying"):
            BOOT.inject("vnc://127.0.0.1:5901", connector=lambda *_args, **_kwargs: fake,
                        sleeper=lambda _seconds: None)
        self.assertNotIn(b"\x04\x01\x00\x00" + BOOT.KEY_ENTER.to_bytes(4, "big"), fake.sent)
        self.assertNotIn(b"\x04\x01\x00\x00" + BOOT.KEY_SPACE.to_bytes(4, "big"), fake.sent)

    def test_inject_requires_a_second_stable_painted_frame_before_keys(self) -> None:
        fake = _FakeSocket(_rfb_session(_raw_frame(), _raw_frame(painted=False)))
        with self.assertRaisesRegex(BOOT.BootAutomationError, "became stable"):
            BOOT.inject("vnc://127.0.0.1:5901", connector=lambda *_args, **_kwargs: fake,
                        sleeper=lambda _seconds: None)
        self.assertNotIn(b"\x04\x01\x00\x00" + BOOT.KEY_ENTER.to_bytes(4, "big"), fake.sent)

    def test_visual_readiness_consumes_a_complete_large_raw_frame_before_returning(self) -> None:
        # Real LogonUI frames exceed MIN_VISUAL_PIXELS.  The parser must not
        # return after the first painted pixels and leave trailing raw data to
        # corrupt the next RFB message boundary.
        fake = _FakeSocket(_raw_frame(width=32, height=8))
        self.assertTrue(BOOT.framebuffer_is_visually_ready(fake, 32, 8))
        self.assertEqual(fake.incoming, bytearray())


if __name__ == "__main__":
    unittest.main()

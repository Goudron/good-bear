#!/usr/bin/env python3
"""Render and drive the *local-only* M15-03 UEFI CD boot prompt.

Some Microsoft installation media displays an early ``Press any key to boot
from CD or DVD`` prompt before a guest agent, serial console, or ``virsh
send-key`` is usable.  This tool provides the deliberately narrow recovery
mechanism used for that prompt:

* ``render`` derives a temporary domain XML from a reviewed M15-03 plan.  The
  sole difference is a VNC device listening on 127.0.0.1; it never listens on
  a LAN address and is not a general remote-desktop configuration.
* ``inject`` speaks only unauthenticated RFB over an explicitly supplied
  ``vnc://127.0.0.1:5900..5999`` URL.  It rejects every authentication scheme,
  waits for two non-blank framebuffer updates (with a settle interval) before
  sending the fixed Enter then Space sequence, and records no screen contents.

This tool never creates, starts, stops, defines, undefines, or otherwise
changes a virtual machine.  A caller must use the reviewed executor's exact
storage and libvirt checks before defining the rendered temporary XML, and
must return to the normal headless XML after the pre-OS hand-off.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import sys
import time
from typing import Callable
from urllib.parse import urlparse

import execute_m15_03_local_kvm as EXEC


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_NAME = "m15-03-local-kvm-boot-automation.xml"
EVIDENCE_SCHEMA = 1
RFB_VERSION = b"RFB 003.008\n"
KEY_ENTER = 0xFF0D
KEY_SPACE = 0x20
LOOPBACK_HOST = "127.0.0.1"
VNC_PORT_MIN = 5900
VNC_PORT_MAX = 5999
RFB_PIXEL_FORMAT_SIZE = 16
RFB_SERVER_INIT_FIXED_SIZE = 24
RFB_RAW_ENCODING = 0
MIN_VISUAL_PIXELS = 128
UEFI_KEY_HOLD_SECONDS = 0.25


class BootAutomationError(ValueError):
    """The local-only boot hand-off could not be performed safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BootAutomationError(message)


def read_exact(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise BootAutomationError("local VNC connection closed during RFB handshake")
        result.extend(part)
    return bytes(result)


def parse_local_vnc_url(value: str) -> tuple[str, int]:
    parsed = urlparse(value)
    require(parsed.scheme == "vnc", "VNC URL must use the vnc:// scheme")
    require(parsed.username is None and parsed.password is None, "VNC credentials are forbidden")
    require(parsed.hostname == LOOPBACK_HOST, "VNC target must be exactly 127.0.0.1")
    require(parsed.path in ("", "/") and not parsed.query and not parsed.fragment,
            "VNC URL must not contain a path, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise BootAutomationError("VNC URL port is malformed") from exc
    require(isinstance(port, int) and VNC_PORT_MIN <= port <= VNC_PORT_MAX,
            f"VNC port must be in the local libvirt range {VNC_PORT_MIN}..{VNC_PORT_MAX}")
    return LOOPBACK_HOST, port


def validate_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to((ROOT / "build").resolve())
    except ValueError as exc:
        raise BootAutomationError("--output must be inside this project's build/ directory") from exc
    require(resolved.name == OUTPUT_NAME, f"--output filename must be exactly {OUTPUT_NAME}")
    require(not resolved.exists() and not resolved.is_symlink(), "refusing to overwrite an existing boot-automation XML")
    return resolved


def render(plan_dir: Path, output: Path) -> dict[str, object]:
    try:
        evidence = EXEC.validate_plan(plan_dir)
    except EXEC.KvmExecutionError as exc:
        raise BootAutomationError(f"reviewed M15-03 plan rejected: {exc}") from exc
    headless = (Path(str(evidence["plan_dir"])) / EXEC.DOMAIN_NAME).read_text(encoding="utf-8")
    try:
        temporary = EXEC.render_loopback_boot_automation_xml(headless)
    except EXEC.KvmExecutionError as exc:
        raise BootAutomationError(f"reviewed headless XML rejected: {exc}") from exc
    destination = validate_output(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
            stream.write(temporary)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    return {
        "action": "render",
        "mutation": "one-new-local-build-file",
        "plan_dir": evidence["plan_dir"],
        "temporary_domain_xml": str(destination),
        "vnc_listen": LOOPBACK_HOST,
        "vnc_autoport_range": f"{VNC_PORT_MIN}-{VNC_PORT_MAX}",
        "external_network_exposure": False,
        "human_input_required": False,
        "return_to_headless_xml_required_after_pre_os_handoff": True,
    }


def rfb_handshake(connection: socket.socket) -> tuple[int, int]:
    server_version = read_exact(connection, len(RFB_VERSION))
    require(server_version.startswith(b"RFB 003."), "local VNC endpoint did not present a supported RFB version")
    connection.sendall(RFB_VERSION)
    count = read_exact(connection, 1)[0]
    methods = read_exact(connection, count)
    require(methods == b"\x01", "local VNC must offer only unauthenticated RFB; credentials and other schemes are forbidden")
    connection.sendall(b"\x01")
    status = int.from_bytes(read_exact(connection, 4), "big")
    require(status == 0, "local VNC rejected unauthenticated RFB")
    connection.sendall(b"\x01")  # shared-flag; framebuffer reads below are transient only
    fixed = read_exact(connection, RFB_SERVER_INIT_FIXED_SIZE)
    width = int.from_bytes(fixed[0:2], "big")
    height = int.from_bytes(fixed[2:4], "big")
    name_length = int.from_bytes(fixed[20:24], "big")
    require(0 < width <= 8192 and 0 < height <= 8192, "local VNC reported invalid framebuffer dimensions")
    require(name_length <= 4096, "local VNC desktop name is unexpectedly long")
    # Discard, rather than retain or print, the server-provided desktop name.
    read_exact(connection, name_length)
    return width, height


def set_raw_pixel_format(connection: socket.socket) -> None:
    """Ask for fixed little-endian BGRX raw pixels, without retaining frames."""
    pixel_format = (
        b"\x20\x18\x00\x01"  # 32 bits/pixel, 24-bit depth, little endian, true colour
        + (255).to_bytes(2, "big") * 3
        + bytes((16, 8, 0))
        + b"\x00\x00\x00"
    )
    require(len(pixel_format) == RFB_PIXEL_FORMAT_SIZE, "internal RFB pixel format is malformed")
    connection.sendall(b"\x00\x00\x00\x00" + pixel_format)
    connection.sendall(b"\x02\x00\x00\x01" + RFB_RAW_ENCODING.to_bytes(4, "big", signed=True))


def framebuffer_is_visually_ready(connection: socket.socket, width: int, height: int) -> bool:
    """Request one transient raw frame and reject blank/pre-display output.

    This deliberately checks *only* whether the local VNC server has painted a
    stable pre-OS screen.  Pixels are consumed in memory and immediately
    discarded: no screenshot, framebuffer, desktop name, or OCR text is ever
    written to disk or emitted in evidence.
    """
    connection.sendall(b"\x03\x00" + (0).to_bytes(2, "big") * 2
                       + width.to_bytes(2, "big") + height.to_bytes(2, "big"))
    message_type = read_exact(connection, 1)
    require(message_type == b"\x00", "local VNC did not return a framebuffer update")
    read_exact(connection, 1)  # padding
    rectangles = int.from_bytes(read_exact(connection, 2), "big")
    require(0 < rectangles <= 64, "local VNC returned an invalid framebuffer rectangle count")
    visual_pixels = 0
    for _ in range(rectangles):
        header = read_exact(connection, 12)
        rect_width = int.from_bytes(header[4:6], "big")
        rect_height = int.from_bytes(header[6:8], "big")
        encoding = int.from_bytes(header[8:12], "big", signed=True)
        require(encoding == RFB_RAW_ENCODING, "local VNC returned a non-raw framebuffer encoding")
        require(rect_width > 0 and rect_height > 0, "local VNC returned an empty framebuffer rectangle")
        pixels = read_exact(connection, rect_width * rect_height * 4)
        # A frame with only zero BGRX pixels is the QEMU/VNC pre-display state.
        # Consume the *entire* frame even once enough painted pixels were
        # observed.  Returning in the middle of raw rectangle data desyncs the
        # RFB stream, and a later request would mistake remaining pixels for a
        # new server message.  ``pixels`` is still transient: it is discarded
        # at the next rectangle/return and is never written or emitted.
        for offset in range(0, len(pixels), 4):
            if pixels[offset:offset + 3] != b"\x00\x00\x00":
                visual_pixels += 1
    return visual_pixels >= MIN_VISUAL_PIXELS


def wait_for_pre_os_readiness(connection: socket.socket, width: int, height: int, *, sleeper: Sleeper,
                               settle_seconds: float) -> None:
    """Require two painted frames separated by a settle interval before keys."""
    set_raw_pixel_format(connection)
    require(framebuffer_is_visually_ready(connection, width, height),
            "local VNC is not yet displaying the UEFI Boot Manager")
    sleeper(settle_seconds)
    require(framebuffer_is_visually_ready(connection, width, height),
            "local VNC display changed before UEFI Boot Manager became stable")


def key_event(connection: socket.socket, keysym: int, down: bool) -> None:
    connection.sendall(b"\x04" + (b"\x01" if down else b"\x00") + b"\x00\x00" + keysym.to_bytes(4, "big"))


Sleeper = Callable[[float], None]
Connector = Callable[..., socket.socket]


def inject(url: str, *, connector: Connector = socket.create_connection, sleeper: Sleeper = time.sleep,
           delay_seconds: float = 2.0, readiness_settle_seconds: float = 1.0) -> dict[str, object]:
    host, port = parse_local_vnc_url(url)
    require(0.5 <= delay_seconds <= 10.0, "delay must be from 0.5 through 10 seconds")
    require(0.5 <= readiness_settle_seconds <= 10.0, "readiness settle delay must be from 0.5 through 10 seconds")
    with connector((host, port), timeout=10) as connection:
        width, height = rfb_handshake(connection)
        wait_for_pre_os_readiness(connection, width, height, sleeper=sleeper,
                                  settle_seconds=readiness_settle_seconds)
        # OVMF accepts an ordinary RFB press during its optical-media prompt,
        # but its boot-device picker can drop a zero-duration key event.  Hold
        # the fixed key briefly; no user-controlled input is ever accepted.
        key_event(connection, KEY_ENTER, True)
        sleeper(UEFI_KEY_HOLD_SECONDS)
        key_event(connection, KEY_ENTER, False)
        sleeper(delay_seconds)
        key_event(connection, KEY_SPACE, True)
        sleeper(UEFI_KEY_HOLD_SECONDS)
        key_event(connection, KEY_SPACE, False)
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "action": "inject-fixed-pre-os-keys",
        "vnc_target": f"vnc://{host}:{port}",
        "vnc_loopback_only": True,
        "authentication_supported": False,
        "keys_sent": ["Enter", "Space"],
        "readiness_gate": "two-transient-nonblank-raw-framebuffer-updates",
        "screen_contents_recorded": False,
        "human_input_required": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    render_parser = subparsers.add_parser("render")
    render_parser.add_argument("--plan-dir", type=Path, required=True)
    render_parser.add_argument("--output", type=Path, required=True)
    inject_parser = subparsers.add_parser("inject")
    inject_parser.add_argument("--vnc-url", required=True)
    inject_parser.add_argument("--delay-seconds", type=float, default=2.0)
    inject_parser.add_argument("--readiness-settle-seconds", type=float, default=1.0)
    args = parser.parse_args()
    try:
        result = (render(args.plan_dir, args.output) if args.action == "render"
                  else inject(args.vnc_url, delay_seconds=args.delay_seconds,
                              readiness_settle_seconds=args.readiness_settle_seconds))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
        return 0
    except (BootAutomationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

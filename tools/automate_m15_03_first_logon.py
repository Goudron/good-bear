#!/usr/bin/env python3
"""One-shot, local-only recovery for the pinned M15-03 first-logon screen.

Windows Server Setup can finish unattended while its initial built-in
administrator account still requires a credential change at LogonUI.  This is
not a general VNC client.  It is deliberately limited to the one currently
known M15-03 guest and performs this exact sequence only:

1. derive that guest's VNC endpoint from local libvirt and require loopback;
2. require one initial full painted, transient RFB framebuffer update (with
   bounded retries only while the server still reports a blank display);
3. dismiss the already-observed initial LogonUI notice with Enter;
4. type one freshly generated temporary credential into New / Confirm, then
   submit it with Enter.

The credential is generated with ``secrets`` as a mutable bytearray, is never
rendered, logged, returned, passed to a subprocess, or saved, and is cleared
before the process returns.  A fixed O_EXCL marker permits no second dispatch,
including after an interrupted invocation.  The later SYSTEM bootstrap rotates
this recovery-only credential before Sysprep, so the temporary value cannot be
carried into the Cloud.ru image.

The RFB channel is the short-lived local loopback-only graphical transport
already needed for Microsoft's pre-OS DVD prompt.  It does not expose a VNC
service to a network and requires no human click or typed secret.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import stat
import tempfile
import time
from typing import Callable
from urllib.parse import urlparse

import automate_m15_03_boot_prompt as RFB


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DOMAIN = "goodbear-m15-03-windows-server-2025-prep"
VM_DIRECTORY_NAME = "m15-03-local-vm"
MARKER_NAME = "goodbear-m15-03-first-logon-dispatched.json"
TEMPORARY_CREDENTIAL_LENGTH = 32
KEY_TAB = 0xFF09
EVIDENCE_SCHEMA = 1
RESERVED_MARKER = b'{"schema_version":1,"state":"reserved","sensitive_material_absent":true}\n'
RESERVED_RETRY_MARKER = b'{"schema_version":1,"state":"reserved_retry","sensitive_material_absent":true}\n'
RESERVED_RETRY_CONSUMED_MARKER = b'{"schema_version":1,"state":"reserved_retry_consumed","sensitive_material_absent":true}\n'
DISPATCHING_MARKER = b'{"schema_version":1,"state":"credential_dispatch_started","sensitive_material_absent":true}\n'
EMERGENCY_DISPATCHING_MARKER = b'{"schema_version":1,"state":"confirmed_static_logonui_credential_dispatch_started","sensitive_material_absent":true}\n'
UPPERCASE = b"ABCDEFGHJKLMNPQRSTUVWXYZ"
LOWERCASE = b"abcdefghijkmnopqrstuvwxyz"
DIGITS = b"23456789"
SYMBOLS = b"!@#$%^&*-_"
ALPHABET = UPPERCASE + LOWERCASE + DIGITS + SYMBOLS


class FirstLogonAutomationError(ValueError):
    """The pinned one-shot LogonUI recovery cannot proceed safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FirstLogonAutomationError(message)


def system_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def run_virsh(command: list[str], runner: Runner, label: str) -> str:
    result = runner(command)
    if result.returncode != 0:
        raise FirstLogonAutomationError(f"{label} failed (exit {result.returncode})")
    return result.stdout.strip()


def parse_libvirt_local_vnc_display(value: str) -> str:
    """Normalize libvirt's display-number URI to the only allowed TCP range.

    ``virsh domdisplay --type vnc`` reports the VNC *display* (``:0`` for
    TCP 5900), rather than an RFB TCP port.  This conversion is intentionally
    separate from the generic RFB endpoint parser: display numbers are
    accepted only as direct output of the exact local ``virsh`` query below.
    """
    parsed = urlparse(value)
    require(parsed.scheme == "vnc", "pinned domain display must use vnc://")
    require(parsed.username is None and parsed.password is None, "pinned domain display must not contain credentials")
    require(parsed.hostname == RFB.LOOPBACK_HOST, "pinned domain display must be exactly 127.0.0.1")
    require(parsed.path in ("", "/") and not parsed.query and not parsed.fragment,
            "pinned domain display must not contain a path, query, or fragment")
    try:
        display = parsed.port
    except ValueError as exc:
        raise FirstLogonAutomationError("pinned domain display number is malformed") from exc
    require(isinstance(display, int) and 0 <= display <= 99,
            "pinned domain VNC display must be in the local 0..99 range")
    # Delegate the final TCP endpoint validation to the RFB helper as a second
    # boundary.  Display 0 maps to 5900 and display 99 maps to 5999.
    target = f"vnc://{RFB.LOOPBACK_HOST}:{RFB.VNC_PORT_MIN + display}"
    try:
        RFB.parse_local_vnc_url(target)
    except RFB.BootAutomationError as exc:  # defensive invariant, never expected
        raise FirstLogonAutomationError(f"normalized local VNC endpoint rejected: {exc}") from exc
    return target


def resolve_pinned_local_vnc_target(runner: Runner = system_runner) -> str:
    """Resolve only the exact running local M15-03 guest, never caller input."""
    prefix = ["virsh", "-c", "qemu:///system"]
    state = run_virsh(prefix + ["domstate", EXPECTED_DOMAIN], runner, "pinned domain state query")
    require(state == "running", "pinned M15-03 domain is not running")
    url = run_virsh(prefix + ["domdisplay", EXPECTED_DOMAIN, "--type", "vnc"], runner,
                    "pinned local VNC discovery")
    try:
        target = parse_libvirt_local_vnc_display(url)
    except FirstLogonAutomationError as exc:
        raise FirstLogonAutomationError(f"pinned domain VNC endpoint rejected: {exc}") from exc
    return target


def marker_path() -> Path:
    candidate = ROOT / "build" / VM_DIRECTORY_NAME
    require(candidate.is_dir() and not candidate.is_symlink(),
            "pinned local M15-03 VM directory is absent or unsafe")
    directory = candidate.resolve()
    build = (ROOT / "build").resolve()
    require(directory.parent == build and directory.name == VM_DIRECTORY_NAME,
            "pinned local M15-03 VM directory escaped this project build tree")
    return directory / MARKER_NAME


def require_safe_marker_stat(details: os.stat_result) -> None:
    require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1 and (details.st_mode & 0o777) == 0o600,
            "first-logon dispatch marker must be one regular 0600 non-linked file")


def read_marker_exact(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FirstLogonAutomationError("cannot securely inspect the first-logon dispatch marker") from exc
    try:
        require_safe_marker_stat(os.fstat(descriptor))
        content = os.read(descriptor, 4096)
        require(os.read(descriptor, 1) == b"", "first-logon dispatch marker is unexpectedly large")
        return content
    finally:
        os.close(descriptor)


def replace_reserved_marker_atomically(path: Path) -> int:
    """Consume only the exact pre-credential marker left by a safe failure.

    The initial marker is written before opening RFB.  A retry is possible
    only while its exact pre-credential state remains: that state is the proof
    that this helper has not yet generated a credential or emitted keys.  Two
    retries are permitted in total; the replacement deliberately consumes the
    second retry state so a third retry is impossible.
    """
    current = read_marker_exact(path)
    if current == RESERVED_MARKER:
        replacement, retry_number = RESERVED_RETRY_MARKER, 1
    elif current == RESERVED_RETRY_MARKER:
        replacement, retry_number = RESERVED_RETRY_CONSUMED_MARKER, 2
    else:
        raise FirstLogonAutomationError(
            "first-logon dispatch marker is completed, malformed, or has already begun credential delivery"
        )
    temporary: Path | None = None
    descriptor: int | None = None
    try:
        for _ in range(16):
            candidate = path.parent / f".{MARKER_NAME}.{secrets.token_hex(12)}.retry"
            try:
                descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                temporary = candidate
                break
            except FileExistsError:
                continue
        require(descriptor is not None and temporary is not None, "cannot allocate atomic retry marker")
        os.write(descriptor, replacement)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        # The source was validated before replacement.  If another party
        # changed it between those operations, this remains fail-closed on all
        # future calls because the replacement is no longer `reserved`.
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise FirstLogonAutomationError("cannot atomically consume the reserved first-logon marker") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
    return retry_number


def reserve_one_time_marker(path: Path) -> tuple[int, int]:
    require(path.name == MARKER_NAME and path.parent == marker_path().parent,
            "first-logon dispatch marker path is not pinned")
    require(not path.is_symlink(), "first-logon dispatch marker must not be a symlink")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        # A previous invocation may have safely failed before it generated a
        # credential (for example, while waiting for a painted LogonUI frame).
        # Only the exact initial marker has that proof; all other states fail.
        del exc
        retry_number = replace_reserved_marker_atomically(path)
        try:
            descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as retry_exc:
            raise FirstLogonAutomationError("cannot reopen the atomically replaced first-logon marker") from retry_exc
        require_safe_marker_stat(os.fstat(descriptor))
        return descriptor, retry_number
    except OSError as exc:
        raise FirstLogonAutomationError("cannot reserve the one-shot first-logon recovery marker") from exc
    try:
        os.write(descriptor, RESERVED_MARKER)
        os.fsync(descriptor)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor, 0


def update_marker(descriptor: int, payload: bytes, label: str) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    except OSError as exc:
        raise FirstLogonAutomationError(f"cannot persist first-logon marker state before {label}") from exc


def reserve_confirmed_static_logonui_recovery(path: Path) -> int:
    """Permit one last recovery only after all failures predated key delivery.

    ``reserved_retry_consumed`` is written only by the normal helper before
    either a credential is generated or a key is emitted.  It is therefore
    the exact auditable state left by the observed RFB framebuffer failures.
    This emergency route intentionally skips framebuffer reads: a fresh
    libvirt screenshot was separately inspected immediately before invoking
    it.  No completed or partially dispatched state is ever accepted.
    """
    require(read_marker_exact(path) == RESERVED_RETRY_CONSUMED_MARKER,
            "confirmed-static-logonui recovery requires the exact exhausted pre-credential marker")
    descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        require_safe_marker_stat(os.fstat(descriptor))
        update_marker(descriptor, EMERGENCY_DISPATCHING_MARKER, "confirmed static LogonUI credential delivery")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def dispatch_confirmed_static_logonui(*, runner: Runner = system_runner,
                                      connector: RFB.Connector = RFB.socket.create_connection,
                                      sleeper: RFB.Sleeper = time.sleep,
                                      credential_factory: Callable[[], bytearray] | None = None,
                                      transition_seconds: float = 1.5) -> dict[str, object]:
    """One-time fallback for the freshly confirmed, static Server Core LogonUI.

    It performs no framebuffer request or capture.  The only accepted target
    is still the exact running domain discovered through local libvirt.
    """
    require(0.5 <= transition_seconds <= 10.0, "LogonUI transition delay must be from 0.5 through 10 seconds")
    if credential_factory is None:
        credential_factory = make_temporary_credential
    target = resolve_pinned_local_vnc_target(runner)
    descriptor = reserve_confirmed_static_logonui_recovery(marker_path())
    credential: bytearray | None = None
    try:
        with connector((RFB.LOOPBACK_HOST, RFB.parse_local_vnc_url(target)[1]), timeout=10) as connection:
            RFB.rfb_handshake(connection)
            # The current display was reviewed through libvirt immediately
            # before this action; do not request a VNC framebuffer here.
            send_key(connection, RFB.KEY_ENTER)
            sleeper(transition_seconds)
            credential = credential_factory()
            require(isinstance(credential, bytearray), "temporary credential must remain mutable process memory")
            require(len(credential) == TEMPORARY_CREDENTIAL_LENGTH, "temporary credential length drifted")
            for key in credential:
                send_key(connection, key)
            send_key(connection, KEY_TAB)
            for key in credential:
                send_key(connection, key)
            send_key(connection, RFB.KEY_ENTER)
        finish_marker(descriptor, target=target)
        return {
            "schema_version": EVIDENCE_SCHEMA,
            "action": "confirmed-static-logonui-temporary-credential-dispatched",
            "target": target,
            "vnc_loopback_only": True,
            "credential_length": TEMPORARY_CREDENTIAL_LENGTH,
            "credential_recorded": False,
            "screen_contents_recorded": False,
            "framebuffer_read": False,
            "future_pre_sysprep_rotation_required": True,
            "human_input_required": False,
        }
    finally:
        if credential is not None:
            clear_credential(credential)
        os.close(descriptor)


def finish_marker(descriptor: int, *, target: str) -> None:
    """Persist only non-secret dispatch evidence in the already reserved inode."""
    evidence = {
        "schema_version": EVIDENCE_SCHEMA,
        "action": "one-shot-first-logon-temporary-credential-dispatched",
        "target": target,
        "vnc_loopback_only": True,
        "credential_length": TEMPORARY_CREDENTIAL_LENGTH,
        "credential_recorded": False,
        "screen_contents_recorded": False,
        "future_pre_sysprep_rotation_required": True,
        "sensitive_material_absent": True,
    }
    payload = (json.dumps(evidence, sort_keys=True) + "\n").encode("utf-8")
    update_marker(descriptor, payload, "completion")


def random_byte_from(alphabet: bytes) -> int:
    return alphabet[secrets.randbelow(len(alphabet))]


def make_temporary_credential() -> bytearray:
    """Return a policy-complex, printable credential without creating a str."""
    candidate = bytearray(random_byte_from(group) for group in (UPPERCASE, LOWERCASE, DIGITS, SYMBOLS))
    candidate.extend(random_byte_from(ALPHABET) for _ in range(TEMPORARY_CREDENTIAL_LENGTH - len(candidate)))
    for index in range(len(candidate) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        candidate[index], candidate[other] = candidate[other], candidate[index]
    require(len(candidate) == TEMPORARY_CREDENTIAL_LENGTH, "temporary credential length drifted")
    require(all(32 < value < 127 for value in candidate), "temporary credential contains a non-printable byte")
    require(all(any(value in group for value in candidate) for group in (UPPERCASE, LOWERCASE, DIGITS, SYMBOLS)),
            "temporary credential no longer satisfies all required character classes")
    return candidate


def clear_credential(candidate: bytearray) -> None:
    for index in range(len(candidate)):
        candidate[index] = 0


def send_key(connection: object, key: int) -> None:
    RFB.key_event(connection, key, True)
    RFB.key_event(connection, key, False)


def wait_for_first_logon_readiness(connection: object, width: int, height: int, *, sleeper: RFB.Sleeper,
                                   settle_seconds: float, attempts: int = 10) -> None:
    """Accept an initial complete painted frame; this is not UEFI-specific.

    QEMU VNC sends one complete frame for a static LogonUI immediately after a
    pixel-format change, then correctly sends no delta updates.  Requiring a
    second update would reject that healthy static screen.  We therefore
    accept one nonblank raw frame and only retry while the display itself is
    blank; pixels remain transient and are never stored.
    """
    require(2 <= attempts <= 20, "first-logon readiness attempts must be from 2 through 20")
    RFB.set_raw_pixel_format(connection)
    for _ in range(attempts):
        if RFB.framebuffer_is_visually_ready(connection, width, height):
            return
        sleeper(settle_seconds)
    raise FirstLogonAutomationError("local VNC did not provide an initial painted first-logon frame")


def dispatch_first_logon(*, runner: Runner = system_runner, connector: RFB.Connector = RFB.socket.create_connection,
                         sleeper: RFB.Sleeper = time.sleep,
                         credential_factory: Callable[[], bytearray] = make_temporary_credential,
                         readiness_settle_seconds: float = 1.0,
                         transition_seconds: float = 1.5) -> dict[str, object]:
    """Perform the one fixed recovery flow; never accepts target or credential input."""
    require(0.5 <= readiness_settle_seconds <= 10.0, "readiness settle delay must be from 0.5 through 10 seconds")
    require(0.5 <= transition_seconds <= 10.0, "LogonUI transition delay must be from 0.5 through 10 seconds")
    target = resolve_pinned_local_vnc_target(runner)
    marker = marker_path()
    descriptor, reserved_marker_retry_number = reserve_one_time_marker(marker)
    credential: bytearray | None = None
    try:
        with connector((RFB.LOOPBACK_HOST, RFB.parse_local_vnc_url(target)[1]), timeout=10) as connection:
            width, height = RFB.rfb_handshake(connection)
            wait_for_first_logon_readiness(connection, width, height, sleeper=sleeper,
                                           settle_seconds=readiness_settle_seconds)
            # The observed Russian LogonUI notice has a default approval button.
            # After its fixed transition, focus is New credential, then Confirm.
            send_key(connection, RFB.KEY_ENTER)
            sleeper(transition_seconds)
            # From this point a crash must stay fail-closed: its marker proves
            # neither a retry nor a second credential submission is safe.
            update_marker(descriptor, DISPATCHING_MARKER, "credential delivery")
            credential = credential_factory()
            require(isinstance(credential, bytearray), "temporary credential must remain mutable process memory")
            require(len(credential) == TEMPORARY_CREDENTIAL_LENGTH, "temporary credential length drifted")
            for key in credential:
                send_key(connection, key)
            send_key(connection, KEY_TAB)
            for key in credential:
                send_key(connection, key)
            send_key(connection, RFB.KEY_ENTER)
        finish_marker(descriptor, target=target)
        return {
            "schema_version": EVIDENCE_SCHEMA,
            "action": "one-shot-first-logon-temporary-credential-dispatched",
            "target": target,
            "vnc_loopback_only": True,
            "credential_length": TEMPORARY_CREDENTIAL_LENGTH,
            "credential_recorded": False,
            "screen_contents_recorded": False,
            "future_pre_sysprep_rotation_required": True,
            "reserved_marker_retried": reserved_marker_retry_number > 0,
            "reserved_marker_retry_number": reserved_marker_retry_number,
            "human_input_required": False,
        }
    finally:
        if credential is not None:
            clear_credential(credential)
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("dispatch", "dispatch-confirmed-static-logonui"))
    args = parser.parse_args()
    try:
        result = (dispatch_first_logon() if args.action == "dispatch"
                  else dispatch_confirmed_static_logonui())
        print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
        return 0
    except (FirstLogonAutomationError, RFB.BootAutomationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Private Safe Browsing configure input; no provider calls or environment fallback.

Callers own the frozen source contract and native Windows ACL policy. They must
repeat verification before every mach phase and protect object directories:
upstream configure and the intended browser binary contain the API key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import os
from pathlib import Path
import re
import shlex
import stat
from typing import Callable, Iterable


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GOOGLE_KEY = re.compile(rb"(AIza[A-Za-z0-9_-]{35})(?:\r?\n)?\Z")
ACLVerifier = Callable[[Path, str], bool]
MAX_KEY_BYTES = 128
MAX_MOZCONFIG_BYTES = 1024 * 1024


class BuildInputError(RuntimeError):
    """Messages deliberately exclude input bytes, paths and OS error details."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildInputError(message)


def _path(value: Path) -> Path:
    path = Path(value)
    _require(path.is_absolute() and ".." not in path.parts,
             "an explicit absolute path without traversal is required")
    _require(not any(ord(char) < 32 or ord(char) == 127 for char in str(path)),
             "control characters in input paths are forbidden")
    return path


def _regular(path: Path, *, directory: bool = False) -> os.stat_result:
    # Check the entire spelling, not just resolve(), which would conceal links.
    try:
        for component in (*reversed(path.parents), path):
            info = component.lstat()
            _require(not stat.S_ISLNK(info.st_mode) and not
                     (getattr(info, "st_file_attributes", 0) &
                      getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)),
                     "symlinks and reparse points are forbidden")
            _require(stat.S_ISDIR(info.st_mode) if component != path or directory
                     else stat.S_ISREG(info.st_mode), "a regular input is required")
        return info
    except OSError:
        raise BuildInputError("input path is unavailable") from None


def _outside(path: Path, roots: Iterable[Path]) -> tuple[Path, ...]:
    checked = tuple(_path(root) for root in roots)
    _require(bool(checked), "explicit excluded source roots are required")
    for root in checked:
        _regular(root, directory=True)
        _require(not path.is_relative_to(root), "private input must be outside source roots")
    return checked


def _read(path: Path, *, limit: int, private_mode: int | None = None,
          windows_acl_verifier: ACLVerifier | None = None, purpose: str = "") -> bytes:
    info = _regular(path)
    if private_mode is not None:
        if os.name == "nt":
            _require(callable(windows_acl_verifier), "native Windows ACL verification is required")
            try:
                approved = windows_acl_verifier(path, purpose) is True
            except Exception:
                raise BuildInputError("native Windows ACL verification failed") from None
            _require(approved, "native Windows ACL verification failed")
        else:
            _require(stat.S_IMODE(info.st_mode) == private_mode,
                     "private input permissions do not match the required mode")
            _require(info.st_uid == os.geteuid(), "private input has a foreign owner")
    _require(info.st_nlink == 1, "hard-linked inputs are forbidden")
    _require(0 < info.st_size <= limit, "input size is outside the allowed bounds")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
        opened = os.fstat(descriptor)
        _require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                  opened.st_mode, opened.st_uid, opened.st_nlink) ==
                 (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                  info.st_mode, info.st_uid, info.st_nlink),
                 "input changed while being opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            data = stream.read(limit + 1)
        _require(len(data) == info.st_size and len(data) <= limit,
                 "input changed while being read")
        return data
    except OSError:
        raise BuildInputError("input could not be read safely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _digest(data: bytes, expected: str) -> str:
    _require(isinstance(expected, str) and SHA256.fullmatch(expected) is not None,
             "an explicit lowercase SHA-256 pin is required")
    actual = hashlib.sha256(data).hexdigest()
    _require(actual == expected, "private or frozen input SHA-256 mismatch")
    return actual


@dataclass(frozen=True)
class VerifiedKeyInput:
    path: Path
    sha256: str
    size: int
    _secret: bytes = field(repr=False, compare=False)
    _forbidden_roots: tuple[Path, ...] = field(repr=False, compare=False)

    def log_redactor(self) -> "KeyLogRedactor":
        return KeyLogRedactor(self._secret)

    def matches_configured_key(self, value: object) -> bool:
        if not isinstance(value, str):
            return False
        try:
            return hmac.compare_digest(value.encode("ascii"), self._secret)
        except UnicodeError:
            return False


def verify_key_file(path: Path, expected_sha256: str, *, forbidden_roots: Iterable[Path],
                    windows_acl_verifier: ACLVerifier | None = None) -> VerifiedKeyInput:
    """Verify exact file bytes; the optional line ending is included in SHA-256."""
    path = _path(path)
    roots = _outside(path, forbidden_roots)
    data = _read(path, limit=MAX_KEY_BYTES, private_mode=0o600,
                 windows_acl_verifier=windows_acl_verifier, purpose="private-key")
    digest = _digest(data, expected_sha256)
    match = GOOGLE_KEY.fullmatch(data)
    _require(match is not None, "unsupported Google API key file format")
    secret = match.group(1)
    _require(secret.decode("ascii") not in str(path), "key value in an input path is forbidden")
    return VerifiedKeyInput(path, digest, len(data), secret, roots)


@dataclass(frozen=True)
class EffectiveMozconfig:
    base_path: Path
    base_sha256: str
    path: Path
    sha256: str
    key_sha256: str
    source_root: Path
    _key_input: VerifiedKeyInput = field(repr=False, compare=False)

    def environment(self) -> dict[str, str]:
        """Only the explicit override; never read or forward the process environment."""
        return {"MOZCONFIG": str(self.path)}

    def evidence(self) -> dict[str, str]:
        return {"base_mozconfig_sha256": self.base_sha256,
                "effective_mozconfig_sha256": self.sha256,
                "safebrowsing_keyfile_sha256": self.key_sha256}


def _wrapper(base: Path, key: VerifiedKeyInput) -> bytes:
    option = "--with-google-safebrowsing-api-keyfile=" + key.path.as_posix()
    return ("# Generated private-input wrapper; contains paths, never key bytes.\n"
            f". {shlex.quote(base.as_posix())}\n"
            f"ac_add_options {shlex.quote(option)}\n").encode("utf-8")


def _verified_base(base: Path, expected: str, key: VerifiedKeyInput) -> None:
    _require(key._secret.decode("ascii") not in str(base),
             "key value in an input path is forbidden")
    data = _read(base, limit=MAX_MOZCONFIG_BYTES)
    _digest(data, expected)
    _require(key._secret not in data, "secret bytes in source mozconfig are forbidden")


def create_effective_mozconfig(*, base_mozconfig: Path, expected_base_sha256: str,
                              key_input: VerifiedKeyInput, wrapper_path: Path,
                              source_root: Path,
                              windows_acl_verifier: ACLVerifier | None = None,
                              reuse_verified: bool = False) -> EffectiveMozconfig:
    """Wrap the caller's canonical base; never modify source or overwrite a file.

    On Windows the external owner must pre-protect the parent directory. Its
    ACL verifier checks the new file before this function returns it for use.
    """
    key = verify_key_file(key_input.path, key_input.sha256,
                          forbidden_roots=key_input._forbidden_roots,
                          windows_acl_verifier=windows_acl_verifier)
    base, destination, source = map(_path, (base_mozconfig, wrapper_path, source_root))
    _outside(destination, (source,))
    _regular(destination.parent, directory=True)
    _require(all(key._secret.decode("ascii") not in str(path)
                 for path in (destination, source)),
             "key value in an input path is forbidden")
    _verified_base(base, expected_base_sha256, key)
    content = _wrapper(base, key)
    binding = EffectiveMozconfig(base, expected_base_sha256, destination,
                                 hashlib.sha256(content).hexdigest(), key.sha256, source, key)
    if reuse_verified and (destination.exists() or destination.is_symlink()):
        verify_effective_mozconfig(binding, windows_acl_verifier=windows_acl_verifier)
        return binding
    descriptor = None
    created = False
    verified = False
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            destination.chmod(0o400)
        verify_effective_mozconfig(binding, windows_acl_verifier=windows_acl_verifier)
        verified = True
        return binding
    except OSError:
        raise BuildInputError("effective mozconfig could not be created safely") from None
    except BuildInputError:
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        # Never remove a preexisting file. A newly created but unverified file
        # is not a usable build input; cleanup is best-effort and not logged.
        if created and not verified:
            try:
                destination.unlink()
            except OSError:
                pass


def verify_effective_mozconfig(binding: EffectiveMozconfig, *,
                              windows_acl_verifier: ACLVerifier | None = None) -> None:
    key = verify_key_file(binding._key_input.path, binding.key_sha256,
                          forbidden_roots=binding._key_input._forbidden_roots,
                          windows_acl_verifier=windows_acl_verifier)
    base, destination = _path(binding.base_path), _path(binding.path)
    _require(all(key._secret.decode("ascii") not in str(path)
                 for path in (destination, binding.source_root)),
             "key value in an input path is forbidden")
    _outside(destination, (binding.source_root,))
    _verified_base(base, binding.base_sha256, key)
    data = _read(destination, limit=MAX_MOZCONFIG_BYTES, private_mode=0o400,
                 windows_acl_verifier=windows_acl_verifier, purpose="effective-mozconfig")
    _digest(data, binding.sha256)
    _require(data == _wrapper(base, key), "effective mozconfig does not match verified inputs")


class KeyLogRedactor:
    """Exact-key byte-stream filter for LOGS ONLY; never use on binary artifacts."""

    def __init__(self, secret: bytes):
        _require(isinstance(secret, bytes) and len(secret) == 39 and
                 GOOGLE_KEY.fullmatch(secret) is not None,
                 "a verified Google API key is required for log filtering")
        self._secret = secret
        self._pending = b""
        self._finished = False

    def feed(self, chunk: bytes) -> bytes:
        _require(not self._finished, "log stream is already finished")
        _require(isinstance(chunk, bytes), "log chunks must be bytes")
        data = (self._pending + chunk).replace(self._secret, b"[REDACTED-SAFEBROWSING-KEY]")
        held = 0
        for length in range(min(len(data), len(self._secret) - 1), 0, -1):
            if data.endswith(self._secret[:length]):
                held = length
                break
        self._pending = data[-held:] if held else b""
        return data[:-held] if held else data

    def finish(self) -> bytes:
        _require(not self._finished, "log stream is already finished")
        self._finished = True
        tail, self._pending = self._pending, b""
        return tail

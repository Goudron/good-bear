#!/usr/bin/env python3
"""Encrypt or decrypt the M15-03 source bundle for a public GitHub asset.

The public asset is ciphertext. The passphrase lives only in a mode-0600 local
file and in a GitHub Actions secret; it is never printed or placed on a command
line. The existing M15-01 manifest/hash checks remain mandatory after decrypt.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path


class TransportError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TransportError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_passphrase(path: Path) -> None:
    require(path.is_file(), f"файл ключа отсутствует: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    require(mode == 0o600, f"файл ключа обязан иметь права 0600, сейчас {mode:03o}")
    value = path.read_text(encoding="ascii").strip()
    require(len(value) >= 48, "ключ шифрования слишком короткий")
    require(value.isascii() and value.replace("-", "").replace("_", "").isalnum(),
            "ключ шифрования имеет недопустимый формат")


def make_key(path: Path) -> None:
    require(not path.exists(), f"отказ: ключ уже существует: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(secrets.token_urlsafe(48) + "\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    print(f"M15-03: создан закрытый ключ {path}; sha256={sha256(path)}")


def crypt(action: str, source: Path, destination: Path, key_file: Path) -> None:
    read_passphrase(key_file)
    require(source.is_file(), f"входной файл отсутствует: {source}")
    require(not destination.exists(), f"отказ: выходной файл уже существует: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "600000",
        "-md", "sha512", "-pass", f"file:{key_file}", "-in", str(source), "-out", str(destination),
    ]
    if action == "decrypt":
        command.insert(2, "-d")
    try:
        subprocess.run(command, check=True, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as exc:
        destination.unlink(missing_ok=True)
        raise TransportError("openssl не смог обработать зашифрованный bundle") from exc
    print(f"M15-03: {action}; file={destination.name}; bytes={destination.stat().st_size}; sha256={sha256(destination)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Шифрованный GitHub transport для M15-03")
    parser.add_argument("action", choices=("init-key", "encrypt", "decrypt", "sha256"))
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--path", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "init-key":
            require(args.key_file is not None, "init-key требует --key-file")
            make_key(args.key_file)
        elif args.action == "sha256":
            require(args.path is not None and args.path.is_file(), "sha256 требует существующий --path")
            print(sha256(args.path))
        else:
            require(args.key_file is not None and args.input is not None and args.output is not None,
                    f"{args.action} требует --key-file, --input и --output")
            crypt(args.action, args.input, args.output, args.key_file)
    except TransportError as exc:
        print(f"ОШИБКА M15-03: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

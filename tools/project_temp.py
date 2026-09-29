#!/usr/bin/env python3
"""Project-owned temporary workspace for Good Bear tooling.

The system ``/tmp`` is a deliberately small tmpfs on supported developer hosts.
Builds and archive checks can create multi-gigabyte intermediate files, so they
must use the project filesystem instead.
"""

from __future__ import annotations

from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BUILD_TEMP = ROOT / "artifacts" / "build-tmp"


def build_temp_dir() -> Path:
    """Return the durable, project-owned temporary directory."""
    BUILD_TEMP.mkdir(parents=True, exist_ok=True)
    return BUILD_TEMP.resolve()


def temporary_directory(*, prefix: str) -> tempfile.TemporaryDirectory[str]:
    """Create a temporary directory on the project filesystem, never /tmp."""
    return tempfile.TemporaryDirectory(prefix=prefix, dir=build_temp_dir())

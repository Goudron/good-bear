#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Materialize a patchable Firefox worktree from Good Bear's pinned archive."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from windows_offline_worker import trusted_python_command

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class MaterializationError(RuntimeError):
    pass


def progress(message: str) -> None:
    print(message, flush=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MaterializationError(message)


@contextlib.contextmanager
def exclusive_lock(path: Path):
    """Hold a one-byte advisory lock on both POSIX and native Windows Python."""
    with path.open("a+b") as lock:
        if os.name == "nt":
            lock.seek(0)
            lock.write(b"\\0")
            lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_config(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MaterializationError(f"cannot load baseline config {path}: {exc}") from exc


def project_root(config_path: Path) -> Path:
    require(config_path.name == "firefox-baseline.json" and config_path.parent.name == "config",
            "baseline config must be config/firefox-baseline.json")
    return config_path.parent.parent


def resolve_under(root: Path, relative: str, label: str) -> Path:
    require(relative and not Path(relative).is_absolute(), f"{label} must be a relative path")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise MaterializationError(f"{label} escapes {root}") from exc
    return candidate


def baseline_values(config: dict, config_path: Path) -> tuple[str, Path, dict]:
    root = project_root(config_path)
    version = config.get("version")
    source = config.get("source")
    require(isinstance(version, str) and version, "baseline version is missing")
    require(isinstance(source, dict), "baseline source block is missing")
    archive_path = source.get("archive_path")
    require(isinstance(archive_path, str), "baseline archive_path is missing")
    expected_archive = resolve_under(root, archive_path, "baseline archive_path")
    for algorithm in ("sha256", "sha512"):
        value = source.get(algorithm)
        require(isinstance(value, str) and value,
                f"baseline source {algorithm} is missing")
    return version, expected_archive, source


def run_baseline_verifier(verifier: Path, config_path: Path, archive: Path, *, offline: bool = False) -> None:
    require(verifier.is_file(), f"baseline verifier is missing: {verifier}")
    progress("Verifying the pinned Firefox archive" + (" offline" if offline else " and release metadata"))
    arguments = ["--config", str(config_path), "--archive", str(archive)]
    if offline:
        arguments.append("--offline")
    completed = subprocess.run(
        trusted_python_command(
            sys.executable, verifier, arguments,
            project_root(config_path) / "artifacts/build-tmp/python-startup"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise MaterializationError(f"baseline verification failed: {detail}")
    progress(completed.stdout.strip() or "Pinned Firefox baseline verified")


def read_series(patches_root: Path) -> list[Path]:
    series = patches_root / "series"
    require(series.is_file(), f"patch series is missing: {series}")
    patches: list[Path] = []
    names: set[str] = set()
    for line_number, raw_line in enumerate(series.read_text(encoding="utf-8").splitlines(), 1):
        entry = raw_line.strip()
        if not entry or entry.startswith("#"):
            continue
        require(entry not in names, f"duplicate patch at {series}:{line_number}: {entry}")
        require(entry.endswith(".patch"), f"patch at {series}:{line_number} must end in .patch")
        patch = resolve_under(patches_root, entry, f"patch at {series}:{line_number}")
        require(patch.is_file(), f"patch listed at {series}:{line_number} is missing: {entry}")
        names.add(entry)
        patches.append(patch)
    return patches


def archive_root_name(version: str) -> str:
    return f"firefox-{version}"


def validate_archive(archive: Path, version: str) -> None:
    required_root = archive_root_name(version)
    try:
        with tarfile.open(archive, "r:xz") as tar:
            members = tar.getmembers()
    except (OSError, tarfile.TarError) as exc:
        raise MaterializationError(f"cannot read source archive {archive}: {exc}") from exc
    require(members, "source archive is empty")
    for member in members:
        name = member.name.rstrip("/")
        # Mozilla's release archive begins with a harmless explicit current-directory
        # entry. It is not a second top-level payload and must not make an otherwise
        # pinned archive unmaterializable.
        if name in {"", "."}:
            continue
        require(name == required_root or name.startswith(required_root + "/"),
                f"archive contains unexpected top-level member: {member.name}")
        require(not member.isdev() and not member.isfifo(),
                f"archive contains unsupported special member: {member.name}")


def extract_pristine(archive: Path, version: str, destination: Path) -> Path:
    validate_archive(archive, version)
    try:
        with tarfile.open(archive, "r:xz") as tar:
            tar.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise MaterializationError(f"safe archive extraction failed: {exc}") from exc
    extracted = destination / archive_root_name(version)
    require(extracted.is_dir(), "archive did not materialize its expected source root")
    return extracted


def set_pristine_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        if path.is_dir():
            path.chmod((mode & ~0o222) | stat.S_IXUSR)
        else:
            path.chmod(mode & ~0o222)
    mode = root.stat().st_mode
    root.chmod((mode & ~0o222) | stat.S_IXUSR)


def make_worktree_writable(root: Path) -> None:
    for path in (root, *sorted(root.rglob("*"))):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        if path.is_dir():
            path.chmod(mode | stat.S_IWUSR | stat.S_IXUSR)
        else:
            path.chmod(mode | stat.S_IWUSR)


def copy_pristine_to_staging(pristine: Path, staged_worktree: Path) -> None:
    """Copy a verified pristine tree without carrying its read-only ACLs forward.

    Python's Windows ``copytree`` uses one CopyFile2 call per file and is
    prohibitively slow for the Firefox source tree on remote NTFS volumes.
    Robocopy is the native bulk-copy primitive there.  Its documented return
    codes 0--7 describe successful copies (including files skipped), while
    8 and above are failures.  POSIX retains the existing semantics.
    """
    if os.name != "nt":
        shutil.copytree(pristine, staged_worktree, symlinks=True)
        return

    progress("Copying pristine source with Windows robocopy")
    result = subprocess.run(
        ["robocopy", str(pristine), str(staged_worktree), "/E", "/SL",
         "/COPY:DAT", "/DCOPY:DAT", "/R:2", "/W:1", "/XJ",
         "/NFL", "/NDL", "/NJH", "/NJS", "/NP"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode >= 8:
        detail = (result.stderr or result.stdout).strip()
        raise MaterializationError(
            f"Windows robocopy failed with exit code {result.returncode}: {detail}"
        )


def copy_overlay(overlay_root: Path, worktree: Path) -> list[str]:
    copied: list[str] = []
    for source in sorted(overlay_root.rglob("*")):
        require(not source.is_symlink(), f"overlay symlinks are not allowed: {source}")
        if source.is_dir() or source.name == ".gitkeep":
            continue
        relative = source.relative_to(overlay_root)
        destination = worktree / relative
        require(not destination.exists() and not destination.is_symlink(),
                f"overlay would overwrite upstream or another overlay file: {relative}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied.append(relative.as_posix())
    return copied


def verify_patch_hunk_counts(patch: Path) -> None:
    """Reject text left outside declared hunks that git apply can silently ignore.

    Git still validates patch syntax and applicability. This extra check only
    counts unified text hunks; binary payloads and other Git metadata stay with
    Git. Empty context lines are accepted, as they are by git apply.
    """
    lines = patch.read_bytes().splitlines()
    header = re.compile(rb"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
    binary = False
    for position, line in enumerate(lines):
        if line.startswith(b"diff --git "):
            binary = False
        elif line == b"GIT binary patch":
            binary = True
        match = None if binary else header.match(line)
        if match is None:
            continue
        expected = tuple(int(count) if count is not None else 1 for count in match.groups())
        old = new = 0
        for index in range(position + 1, len(lines)):
            content = lines[index]
            if content.startswith((b"@@ ", b"diff --git ")) or content == b"-- ":
                break
            # Plain unified diffs need no 'diff --git' separator. Only treat
            # this pair as file headers after consuming the current hunk:
            # the same spelling can be legitimate removed/added source text.
            if ((old, new) == expected and content.startswith(b"--- ") and
                    index + 1 < len(lines) and lines[index + 1].startswith(b"+++ ")):
                break
            if content == b"\\ No newline at end of file":
                continue
            if not content:
                if (old, new) == expected:
                    continue  # Blank separator after a complete hunk.
                old += 1
                new += 1
            elif content[:1] in (b" ", b"+", b"-"):
                old += content[:1] in (b" ", b"-")
                new += content[:1] in (b" ", b"+")
            else:
                break
        require((old, new) == expected,
                f"text hunk counts differ in {patch.name}:{position + 1}: "
                f"declared old/new {expected[0]}/{expected[1]}, "
                f"actual {old}/{new}; possible ignored patch lines")


def apply_patches(patches: list[Path], worktree: Path, patches_root: Path) -> list[dict[str, str]]:
    applied: list[dict[str, str]] = []
    for patch in patches:
        relative = patch.relative_to(patches_root).as_posix()
        progress(f"Checking patch {relative}")
        verify_patch_hunk_counts(patch)
        # The worktree lives below Good Bear's own Git repository. Stop Git's repository
        # discovery at the worktree parent, so ignored materialized source files are
        # patched directly rather than being handled by the outer project repository.
        command = ["git", "apply", "--no-index", "--check", "--whitespace=error-all", str(patch)]
        git_environment = os.environ.copy()
        git_environment["GIT_CEILING_DIRECTORIES"] = str(worktree.parent.resolve())
        checked = subprocess.run(command, cwd=worktree, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=git_environment)
        if checked.returncode:
            raise MaterializationError(
                f"patch check failed for {relative}: {checked.stderr.strip() or checked.stdout.strip()}"
            )
        progress(f"Applying patch {relative}")
        applied_result = subprocess.run(command[:3] + command[4:], cwd=worktree,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                        env=git_environment)
        if applied_result.returncode:
            raise MaterializationError(
                f"patch application failed for {relative}: "
                f"{applied_result.stderr.strip() or applied_result.stdout.strip()}"
            )
        applied.append({"path": relative, "sha256": hash_file(patch, "sha256")})
    return applied


def audit_patches(patches: list[Path], worktree: Path, patches_root: Path) -> list[dict[str, str]]:
    """Apply every independently applicable patch and return all failures.

    A failed patch is deliberately not applied. Later failures are therefore
    annotated when they may be a consequence of an earlier missing patch,
    rather than being reported as independent source incompatibilities.
    """
    failures: list[dict[str, str]] = []
    prior_failures: list[str] = []
    git_environment = os.environ.copy()
    git_environment["GIT_CEILING_DIRECTORIES"] = str(worktree.parent.resolve())
    for patch in patches:
        relative = patch.relative_to(patches_root).as_posix()
        try:
            verify_patch_hunk_counts(patch)
            command = ["git", "apply", "--no-index", "--check", "--whitespace=error-all", str(patch)]
            checked = subprocess.run(command, cwd=worktree, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, env=git_environment)
            if checked.returncode:
                raise MaterializationError(checked.stderr.strip() or checked.stdout.strip())
            applied = subprocess.run(command[:3] + command[4:], cwd=worktree,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env=git_environment)
            if applied.returncode:
                raise MaterializationError(applied.stderr.strip() or applied.stdout.strip())
            progress(f"Audit passed {relative}")
        except MaterializationError as exc:
            failure = {"path": relative, "error": str(exc)}
            if prior_failures:
                failure["may_depend_on"] = prior_failures[-1]
            failures.append(failure)
            prior_failures.append(relative)
            progress(f"Audit failed {relative}: {exc}")
    return failures


def quarantine(staging: Path, source_root: Path) -> Path | None:
    if not staging.exists():
        return None
    quarantine_root = source_root / "quarantine"
    quarantine_root.mkdir(parents=True, exist_ok=True)
    destination = quarantine_root / f"{staging.name}-{uuid.uuid4().hex}"
    os.replace(staging, destination)
    return destination


def materialize(config_path: Path, archive: Path, verifier: Path, *, baseline_offline: bool = False,
                audit_patches_only: bool = False) -> Path | None:
    config_path = config_path.resolve()
    config = load_config(config_path)
    version, expected_archive, source = baseline_values(config, config_path)
    archive = archive.resolve()
    require(archive == expected_archive,
            f"archive must be the pinned path from config: {expected_archive}")
    require(archive.is_file(), f"pinned source archive is missing: {archive}")

    root = project_root(config_path)
    source_root = expected_archive.parent
    pristine = source_root / "pristine" / archive_root_name(version)
    worktree = source_root / "worktrees" / archive_root_name(version)
    patches_root = root / "patches"
    overlay_root = root / "overlay"
    require(overlay_root.is_dir(), f"overlay directory is missing: {overlay_root}")
    patches = read_series(patches_root)

    run_baseline_verifier(verifier, config_path, archive, offline=baseline_offline)
    source_root.mkdir(parents=True, exist_ok=True)
    lock_path = source_root / ".materialize.lock"
    with exclusive_lock(lock_path):
        try:
            pristine_marker = pristine / ".good-bear-pristine.json"
            pristine_provenance = {
                "baseline_config_sha256": hash_file(config_path, "sha256"),
                "source_sha256": source["sha256"],
                "source_sha512": source["sha512"],
                "version": version,
            }
            if pristine.exists():
                require(pristine_marker.is_file(),
                        f"existing pristine source is unverified: {pristine_marker}")
                require(json.loads(pristine_marker.read_text(encoding="utf-8")) == pristine_provenance,
                        "existing pristine source does not match the pinned baseline")
            else:
                progress("Extracting immutable pristine Firefox source")
                pristine.parent.mkdir(parents=True, exist_ok=True)
                staging_root = Path(tempfile.mkdtemp(prefix=".pristine-", dir=source_root))
                try:
                    extracted = extract_pristine(archive, version, staging_root)
                    (extracted / ".good-bear-pristine.json").write_text(
                        json.dumps(pristine_provenance, sort_keys=True, indent=2) + "\n", encoding="utf-8"
                    )
                    os.replace(extracted, pristine)
                    set_pristine_read_only(pristine)
                except Exception:
                    quarantined = quarantine(staging_root, source_root)
                    if quarantined:
                        progress(f"Quarantined incomplete pristine extraction at {quarantined}")
                    raise
                finally:
                    if staging_root.exists():
                        shutil.rmtree(staging_root)

            require(not worktree.exists() and not worktree.is_symlink(),
                    f"refusing to overwrite existing materialized worktree: {worktree}")
            staging = Path(tempfile.mkdtemp(prefix=".worktree-", dir=source_root))
            try:
                progress("Copying pristine source into an isolated staging worktree")
                staged_worktree = staging / worktree.name
                copy_pristine_to_staging(pristine, staged_worktree)
                make_worktree_writable(staged_worktree)
                overlay_files = copy_overlay(overlay_root, staged_worktree)
                if audit_patches_only:
                    failures = audit_patches(patches, staged_worktree, patches_root)
                    require(not failures,
                            "patch audit found incompatible patches: "
                            + json.dumps(failures, ensure_ascii=False, sort_keys=True))
                    progress("Patch audit passed every patch in the series")
                    return None
                applied = apply_patches(patches, staged_worktree, patches_root)
                marker = {
                    "baseline_config_sha256": hash_file(config_path, "sha256"),
                    "overlay_files": overlay_files,
                    "patches": applied,
                    "source_sha256": source["sha256"],
                    "source_sha512": source["sha512"],
                    "version": version,
                }
                (staged_worktree / ".good-bear-materialization.json").write_text(
                    json.dumps(marker, sort_keys=True, indent=2) + "\n", encoding="utf-8"
                )
                worktree.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staged_worktree, worktree)
                progress(f"Materialized Good Bear worktree at {worktree}")
                return worktree
            except Exception:
                if audit_patches_only:
                    progress("Discarding audit staging worktree")
                else:
                    quarantined = quarantine(staging, source_root)
                    if quarantined:
                        progress(f"Quarantined incomplete worktree at {quarantined}")
                raise
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
        finally:
            # exclusive_lock releases the platform-specific lock.
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path,
                        default=Path(__file__).resolve().parents[1] / "config" / "firefox-baseline.json")
    parser.add_argument("--archive", type=Path,
                        help="required pinned archive; it must equal source.archive_path in --config")
    parser.add_argument("--baseline-verifier", type=Path,
                        default=Path(__file__).resolve().with_name("verify_firefox_baseline.py"))
    parser.add_argument("--baseline-offline", action="store_true",
                        help="verify the pinned local archive without network access")
    parser.add_argument("--audit-patches", action="store_true",
                        help="check the full patch series once without promoting a worktree")
    args = parser.parse_args()
    if args.archive is None:
        parser.error("--archive is required; the materializer never downloads source archives")
    try:
        materialize(args.config, args.archive, args.baseline_verifier,
                    baseline_offline=args.baseline_offline,
                    audit_patches_only=args.audit_patches)
    except MaterializationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

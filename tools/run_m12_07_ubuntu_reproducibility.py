#!/usr/bin/env python3
"""Host-only, clean-scratch Ubuntu reproducibility check for GB100-M12-07.

This intentionally reruns only M12-02's deterministic package construction
from the immutable staged Russian archive.  It is not a Firefox product build
and it never uses Docker: Docker is permitted for clean *validation* only,
while release construction remains host-only.  A mismatch is retained with an
exact semantic diff under this task's quarantine and is never guessed away.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "goodbear-browser_1.0+firefox154.0-1_amd64.deb"
DEFAULT_CANDIDATE = ROOT / "artifacts/m12-02-ubuntu-candidates-r3" / PACKAGE_NAME
DEFAULT_CANDIDATE_EVIDENCE = DEFAULT_CANDIDATE.with_name(DEFAULT_CANDIDATE.name + ".evidence.json")
DEFAULT_SNAPSHOT = ROOT / "artifacts/m12-01-input-snapshot-ubuntu2604"
DEFAULT_ARCHIVE = ROOT / "artifacts/development/m10-03-host-obj/dist/goodbear-1.0+firefox154.0.ru.linux-x86_64.tar.xz"
DEFAULT_EVIDENCE_ROOT = ROOT / "artifacts/m12-07-ubuntu-reproducibility"
EXPECTED_CANDIDATE_SHA256 = "b4b44e9b69f583e1de5c6a9a3a79e7731547b9c9610f2a73a8e59026f11da9f4"

# Deliberately a release blocker, not an automated result or an implied claim.
WINDOWS_MANUAL_RELEASE_BLOCKER = {
    "status": "manual-windows-reproducibility-required",
    "automation": "not-run",
    "release_blocker": True,
}


class ReproducibilityError(RuntimeError):
    """A locked input or artifact comparison failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReproducibilityError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_packager() -> Any:
    spec = importlib.util.spec_from_file_location("m12_02_packager", ROOT / "tools/build_m12_02_ubuntu_deb.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def project_path(value: Path) -> Path:
    resolved = value.resolve()
    require(resolved.is_relative_to(ROOT), f"input must remain inside the project: {resolved}")
    return resolved


def checked_candidate_evidence(candidate: Path, evidence_path: Path, archive: Path, snapshot_manifest: dict[str, Any], packager: Any, temporary_root: Path) -> dict[str, Any]:
    candidate, evidence_path, archive = map(project_path, (candidate, evidence_path, archive))
    require(candidate.is_file() and evidence_path.is_file(), "candidate or its M12-02 evidence is missing")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    require(evidence.get("task") == "GB100-M12-02", "candidate evidence is not M12-02 evidence")
    require(evidence.get("package") == candidate.name, "candidate evidence names another package")
    actual = sha256(candidate)
    require(actual == EXPECTED_CANDIDATE_SHA256, f"candidate SHA-256 differs: expected {EXPECTED_CANDIDATE_SHA256}, got {actual}")
    require(evidence.get("package_sha256") == actual, "candidate evidence SHA-256 does not match package")
    require(evidence.get("archive_sha256") == sha256(archive), "locked staged archive SHA-256 differs from M12-02 evidence")
    manifest = evidence.get("input_manifest")
    require(isinstance(manifest, dict), "candidate evidence has no input manifest")
    require(manifest.get("platform") == "ubuntu-amd64" and manifest.get("release_locale") == "ru", "candidate is not Ubuntu Russian-only")
    require(manifest.get("lto") == "forbidden" and manifest.get("network_after_fetch") == "network forbidden", "candidate violates M12 non-LTO/network lock")
    require(manifest == snapshot_manifest, "candidate evidence inputs differ from the current M12 Ubuntu input lock")
    packager.validate_deb(candidate, temporary_root=temporary_root)
    return evidence


@contextmanager
def clean_construction_environment(work: Path) -> Iterator[None]:
    """Make package construction independent of caller locale, umask, and HOME."""
    saved_environment = os.environ.copy()
    saved_umask = os.umask(0o022)
    try:
        os.environ.clear()
        os.environ.update({
            "HOME": str(work / "home"), "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SOURCE_DATE_EPOCH": "0",
        })
        (work / "home").mkdir()
        yield
    finally:
        os.umask(saved_umask)
        os.environ.clear()
        os.environ.update(saved_environment)


def rebuild_from_locked_staged_inputs(snapshot: Path, archive: Path, work: Path, packager: Any) -> Path:
    """Rerun M12-02 construction in a fresh project-local scratch directory."""
    manifest = packager.checked_snapshot(snapshot)
    require(manifest["platform"] == "ubuntu-amd64", "snapshot is not the Ubuntu lock")
    packager.verify_russian_archive(archive)
    stage = work / "stage"
    output = work / PACKAGE_NAME
    with clean_construction_environment(work):
        packager.extract_payload(archive, stage)
        packager.install_desktop_integration(stage)
        packager.normalize_package_modes(stage)
        packager.build_deb(stage, output)
    packager.validate_deb(output, temporary_root=work)
    return output


def normalized_package(deb: Path) -> dict[str, Any]:
    """Return content/metadata semantic form, excluding archive compression bytes."""
    result: dict[str, Any] = {"debian_binary": "", "control": [], "data": []}
    result["debian_binary"] = subprocess.check_output(
        ["dpkg-deb", "--showformat=${Package} ${Version} ${Architecture}", "-f", str(deb)], text=True
    ).strip()
    for label, option in (("control", "--ctrl-tarfile"), ("data", "--fsys-tarfile")):
        raw = subprocess.check_output(["dpkg-deb", option, str(deb)])
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as bundle:
            for member in sorted(bundle.getmembers(), key=lambda item: item.name):
                record: dict[str, Any] = {
                    "name": member.name, "type": member.type.decode("ascii"), "mode": member.mode,
                    "uid": member.uid, "gid": member.gid, "linkname": member.linkname,
                }
                if member.isfile():
                    source = bundle.extractfile(member)
                    assert source is not None
                    record["sha256"] = hashlib.sha256(source.read()).hexdigest()
                result[label].append(record)
    return result


def normalized_diff(candidate: dict[str, Any], rebuilt: dict[str, Any]) -> list[dict[str, Any]]:
    differences: list[dict[str, Any]] = []
    for key in ("debian_binary", "control", "data"):
        if candidate[key] != rebuilt[key]:
            differences.append({"section": key, "candidate": candidate[key], "rebuilt": rebuilt[key]})
    return differences


def write_json_atomically(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def run(candidate: Path, evidence_path: Path, snapshot: Path, archive: Path, evidence_root: Path) -> Path:
    packager = load_packager()
    snapshot_manifest = packager.checked_snapshot(snapshot)
    evidence_root = project_path(evidence_root)
    evidence_root.mkdir(parents=True, exist_ok=True)
    candidate_evidence = checked_candidate_evidence(candidate, evidence_path, archive, snapshot_manifest, packager, evidence_root / "validation")
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    quarantine = evidence_root / "quarantine" / run_id
    quarantine.mkdir(parents=True)
    print("[M12-07 1/4] Verifying the locked Ubuntu candidate, M12-02 evidence, and staged Russian archive", flush=True)
    print(f"  candidate SHA-256: {sha256(candidate)}", flush=True)
    try:
        print("[M12-07 2/4] Reconstructing the Debian archive in a fresh host-only, network-free scratch environment", flush=True)
        rebuilt = rebuild_from_locked_staged_inputs(snapshot, archive, quarantine, packager)
        print("[M12-07 3/4] Validating the reconstructed Russian-only package and comparing archive bytes", flush=True)
        candidate_sha, rebuilt_sha = sha256(candidate), sha256(rebuilt)
        candidate_normalized, rebuilt_normalized = normalized_package(candidate), normalized_package(rebuilt)
        differences = normalized_diff(candidate_normalized, rebuilt_normalized)
        equivalence = "byte-identical" if candidate_sha == rebuilt_sha else "normalized-equivalent"
        require(candidate_sha == rebuilt_sha or not differences,
                "unexplained Ubuntu package delta: " + json.dumps(differences, sort_keys=True))
        print(f"[M12-07 4/4] PASS: {equivalence}; rebuilt SHA-256: {rebuilt_sha}", flush=True)
        result = {
            "schema_version": 1, "task": "GB100-M12-07", "platform": "ubuntu-amd64",
            "candidate": str(project_path(candidate).relative_to(ROOT)), "candidate_sha256": candidate_sha,
            "rebuilt_sha256": rebuilt_sha, "equivalence": equivalence,
            "normalized_diff": differences, "candidate_evidence": candidate_evidence,
            "construction": {"environment": "fresh host-only project-local scratch", "docker": "not used", "network": "forbidden", "lto": "forbidden"},
            "windows": WINDOWS_MANUAL_RELEASE_BLOCKER,
        }
        output = evidence_root / f"m12-07-{run_id}.json"
        write_json_atomically(output, result)
        shutil.rmtree(quarantine)
        return output
    except BaseException as exc:
        failure = {"schema_version": 1, "task": "GB100-M12-07", "platform": "ubuntu-amd64", "status": "failed", "error": str(exc), "candidate_sha256": sha256(candidate), "windows": WINDOWS_MANUAL_RELEASE_BLOCKER}
        write_json_atomically(quarantine / "reproducibility-failure.json", failure)
        print(f"M12-07 failure retained in quarantine: {quarantine}", flush=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--candidate-evidence", type=Path, default=DEFAULT_CANDIDATE_EVIDENCE)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    args = parser.parse_args()
    try:
        output = run(args.candidate, args.candidate_evidence, args.snapshot, args.archive, args.evidence_root)
    except (ReproducibilityError, OSError, subprocess.CalledProcessError, tarfile.TarError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"M12-07 Ubuntu reproducibility evidence: {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

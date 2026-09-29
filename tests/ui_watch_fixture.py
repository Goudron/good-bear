"""Disposable synthetic approval fixtures; never runtime or visual evidence."""

from contextlib import contextmanager
import copy
import hashlib
from itertools import product
import json
from pathlib import Path
import struct
import tempfile
import zlib


def write_record(root: Path, path: Path, contents) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = contents if isinstance(contents, bytes) else json.dumps(contents, sort_keys=True).encode()
    path.write_bytes(data)
    return {"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(data).hexdigest()}


def synthetic_png(scale: float) -> bytes:
    width, height = round(1920 * scale), round(1080 * scale)
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(bytes((width * 3 + 1) * height))) + chunk(b"IEND", b""))


@contextmanager
def reviewed_fixture(root: Path, contract: dict):
    """Temporary files exercise schema and hashes; all pixels are synthetic."""
    parent = root / "artifacts/build-tmp"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="unit-ui-watch-only-", dir=parent) as directory:
        base = Path(directory)
        watch = copy.deepcopy(contract)
        transition, matrix = watch["transitions"][0], watch["visual_matrix"]
        report = {"status": "passed", "method": "pinned_fluent_ast_and_registered_consumers",
                  "source_manifest_sha256": "a" * 64, "owner_sha256": {"synthetic-owner": "b" * 64},
                  "checked_message_count": 10, "bound_message_count": 10,
                  "structural_findings": [], "fallback_findings": [], "binding_findings": []}
        fluent_ref = write_record(root, base / "fluent.json", report)
        manual = {"maintainer": "synthetic-unit-test-reviewer", "reviewed_at": "2026-09-20T00:00:00Z",
                  "decision": "promote", "visual_result": "accepted", "unexplained_drift": [],
                  "firefox_baseline": watch["current_baseline"], "candidate_hash": {}, "build_hash": {},
                  "observed_evidence": {}, "fluent_audit_sha256": fluent_ref["sha256"]}
        visual = []
        images = {scale: synthetic_png(scale) for scale in matrix["scales"]}
        for platform in matrix["platforms"]:
            platform_root = base / platform
            candidate = write_record(root, platform_root / "candidate.bin", b"synthetic candidate only")
            build = write_record(root, platform_root / "build.json", {
                "status": "passed", "locale": "ru", "firefox_baseline": watch["current_baseline"],
                "source_manifest_sha256": report["source_manifest_sha256"],
                "candidate_sha256": candidate["sha256"],
            })
            captures = []
            cells = list(product(watch["good_bear_surfaces"], matrix["themes"], matrix["scales"],
                                 matrix["accessibility_states"]))
            rows = [(*cell, None) for cell in cells]
            rows += [("security_popup", theme, scale, "default", shield)
                     for theme, scale, shield in product(matrix["themes"], matrix["scales"], matrix["trust_panel_states"])]
            for index, (surface, theme, scale, state, shield) in enumerate(rows):
                captures.append({"surface": surface, "theme": theme, "scale": scale,
                                 "accessibility_state": state, "trust_panel_state": shield,
                                 "result": "accepted", "locale": "ru", "viewport": [1920, 1080],
                                 "png": write_record(root, platform_root / f"synthetic-{index}.png", images[scale])})
            runtime = write_record(root, platform_root / "runtime.json", {
                "status": "passed", "runtime_verified": True, "errors": [], "locale": "ru",
                "platform": platform, "firefox_baseline": watch["current_baseline"],
                "candidate_sha256": candidate["sha256"], "build_sha256": build["sha256"], "captures": captures,
            })
            visual.append({"platform": platform, "candidate": candidate, "build": build, "runtime_report": runtime})
            manual["candidate_hash"][platform] = candidate["sha256"]
            manual["build_hash"][platform] = build["sha256"]
            manual["observed_evidence"][platform] = runtime["sha256"]
        transition.update(status="reviewed", promotion_allowed=True, fluent_audit=fluent_ref,
                          visual_evidence=visual, manual_promotion=manual)
        transition["ru_shield_source_audit"].update(status="source_and_visual_reviewed", visual_parity_proven=True)
        yield watch, report

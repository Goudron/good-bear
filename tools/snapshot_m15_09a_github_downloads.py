#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Create a reproducible offline snapshot of GitHub Release download counts.

This tool never performs network I/O.  A maintainer saves the GitHub Releases
API response separately and supplies that JSON file as input.  Counts are
download events reported by GitHub, not people or active installations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


REPOSITORY = "Goudron/good-bear"
API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases"
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class SnapshotError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SnapshotError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def platform_for(name: str) -> str | None:
    lowered = name.lower()
    if lowered.endswith(".deb"):
        return "ubuntu-amd64"
    if lowered.endswith(".exe"):
        return "windows-x64"
    return None


def create_snapshot(payload: object, *, observed_at: str, source_sha256: str) -> dict:
    require(TIMESTAMP.fullmatch(observed_at) is not None,
            "observed-at must be an explicit UTC timestamp ending in Z")
    require(isinstance(payload, list), "GitHub Releases response must be a JSON list")
    records: list[dict] = []
    seen_assets: set[int] = set()
    for release in payload:
        require(isinstance(release, dict), "release entry must be an object")
        if release.get("draft") is True:
            continue
        release_id = release.get("id")
        tag = release.get("tag_name")
        require(isinstance(release_id, int) and release_id > 0,
                "published release requires a positive integer id")
        require(isinstance(tag, str) and tag and "/" not in tag,
                "published release requires a safe non-empty tag")
        assets = release.get("assets")
        require(isinstance(assets, list), f"release {tag} assets must be a list")
        for asset in assets:
            require(isinstance(asset, dict), f"release {tag} asset must be an object")
            name = asset.get("name")
            require(isinstance(name, str) and name and Path(name).name == name,
                    f"release {tag} has an unsafe asset name")
            platform = platform_for(name)
            if platform is None:
                continue
            asset_id = asset.get("id")
            count = asset.get("download_count")
            updated_at = asset.get("updated_at")
            require(isinstance(asset_id, int) and asset_id > 0 and asset_id not in seen_assets,
                    "distribution asset id must be positive and unique")
            require(isinstance(count, int) and not isinstance(count, bool) and count >= 0,
                    f"distribution asset {name} has an invalid download_count")
            require(isinstance(updated_at, str) and TIMESTAMP.fullmatch(updated_at) is not None,
                    f"distribution asset {name} has an invalid updated_at")
            seen_assets.add(asset_id)
            records.append({
                "release_tag": tag,
                "release_id": release_id,
                "asset_id": asset_id,
                "asset_name": name,
                "asset_updated_at": updated_at,
                "platform": platform,
                "download_count": count,
            })
    records.sort(key=lambda item: (item["release_tag"], item["platform"], item["asset_name"],
                                   item["asset_id"]))
    totals = {
        platform: sum(item["download_count"] for item in records
                      if item["platform"] == platform)
        for platform in ("ubuntu-amd64", "windows-x64")
    }
    return {
        "schema_version": 1,
        "task": "GB100-M15-09a",
        "repository": REPOSITORY,
        "observed_at": observed_at,
        "source_api_url": API_URL,
        "source_response_sha256": source_sha256,
        "interpretation": "distribution_download_events_not_people_or_active_installations",
        "assets": records,
        "totals_by_platform": totals,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True,
                        help="saved JSON response from the GitHub Releases API")
    parser.add_argument("--observed-at", required=True,
                        help="UTC observation timestamp, for example 2026-09-15T12:00:00Z")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = args.input.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        snapshot = create_snapshot(payload, observed_at=args.observed_at,
                                   source_sha256=sha256_bytes(raw))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2,
                                          sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, UnicodeError, ValueError, SnapshotError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"M15-09a GitHub download snapshot written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

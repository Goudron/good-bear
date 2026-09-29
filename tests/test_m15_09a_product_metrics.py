#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


VERIFY = load_module("verify_m15_09a", "tools/verify_m15_09a_product_metrics.py")
SNAPSHOT = load_module("snapshot_m15_09a", "tools/snapshot_m15_09a_github_downloads.py")


class ProductMetricsContractTest(unittest.TestCase):
    def load_contract(self) -> dict:
        return json.loads(VERIFY.CONTRACT.read_text(encoding="utf-8"))

    def verify_mutation(self, mutate) -> str:
        contract = copy.deepcopy(self.load_contract())
        mutate(contract)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaises(VERIFY.MetricsError) as raised:
                VERIFY.verify(contract_path=path)
        return str(raised.exception)

    def test_repository_contract_passes(self) -> None:
        VERIFY.verify()

    def test_stale_firefox_contract_is_rejected(self) -> None:
        self.assertIn("contract identity", self.verify_mutation(
            lambda contract: contract.__setitem__("firefox_base", "155.0.1")))

    def test_inactive_placeholder_cannot_acquire_an_endpoint(self) -> None:
        def mutate(contract: dict) -> None:
            contract["browser_placeholder"]["runtime"]["endpoint"] = (
                "https://telemetry.ledovskoy.com/v1/active-installations")
        self.assertIn("endpoint", self.verify_mutation(mutate))

    def test_enabled_default_cannot_open_a_transport(self) -> None:
        def mutate(contract: dict) -> None:
            contract["browser_placeholder"]["runtime"]["transport_gate"] = True
        self.assertIn("network path", self.verify_mutation(mutate))

    def test_future_domain_is_not_treated_as_an_endpoint(self) -> None:
        def mutate(contract: dict) -> None:
            contract["browser_placeholder"]["future_collector"]["status"] = "ready"
        self.assertIn("future collector", self.verify_mutation(mutate))

    def test_downloads_cannot_be_labelled_active_users(self) -> None:
        def mutate(contract: dict) -> None:
            contract["github_release_downloads"]["interpretation"] = "MAU"
        self.assertIn("must not be presented", self.verify_mutation(mutate))


class GitHubDownloadSnapshotTest(unittest.TestCase):
    def payload(self) -> list[dict]:
        return [
            {
                "id": 20,
                "tag_name": "v1.0.0",
                "draft": False,
                "assets": [
                    {"id": 202, "name": "GoodBear Setup 1.0+firefox156.0 x64 ru.exe",
                     "updated_at": "2026-09-15T11:00:00Z", "download_count": 7},
                    {"id": 201, "name": "goodbear-browser_1.0-1_amd64.deb",
                     "updated_at": "2026-09-15T10:00:00Z", "download_count": 5},
                    {"id": 203, "name": "SHA256SUMS",
                     "updated_at": "2026-09-15T12:00:00Z", "download_count": 30},
                ],
            },
            {
                "id": 19,
                "tag_name": "draft",
                "draft": True,
                "assets": [
                    {"id": 190, "name": "hidden.exe",
                     "updated_at": "2026-09-15T09:00:00Z", "download_count": 99},
                ],
            },
        ]

    def test_snapshot_is_deterministic_and_counts_only_distribution_assets(self) -> None:
        first = SNAPSHOT.create_snapshot(
            self.payload(), observed_at="2026-09-15T12:30:00Z", source_sha256="a" * 64)
        second = SNAPSHOT.create_snapshot(
            self.payload(), observed_at="2026-09-15T12:30:00Z", source_sha256="a" * 64)
        self.assertEqual(first, second)
        self.assertEqual(first["totals_by_platform"], {
            "ubuntu-amd64": 5, "windows-x64": 7})
        self.assertEqual([item["asset_id"] for item in first["assets"]], [201, 202])
        self.assertEqual(
            first["interpretation"],
            "distribution_download_events_not_people_or_active_installations")

    def test_negative_or_non_integer_download_count_is_rejected(self) -> None:
        payload = self.payload()
        payload[0]["assets"][0]["download_count"] = -1
        with self.assertRaises(SNAPSHOT.SnapshotError):
            SNAPSHOT.create_snapshot(
                payload, observed_at="2026-09-15T12:30:00Z", source_sha256="b" * 64)

    def test_observation_time_must_be_explicit_and_reproducible(self) -> None:
        with self.assertRaises(SNAPSHOT.SnapshotError):
            SNAPSHOT.create_snapshot(
                self.payload(), observed_at="now", source_sha256="c" * 64)


if __name__ == "__main__":
    unittest.main()

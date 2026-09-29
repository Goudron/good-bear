#!/usr/bin/env python3
"""Mocked GET-only and redaction tests for GB100-M15-03 Cloud inventory."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import inspect_m15_03_cloud_inventory as INVENTORY  # noqa: E402


class M1503CloudInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(
            (ROOT / "config" / "m15-03-cloud-api-contract.json").read_text(encoding="utf-8")
        )

    def credentials(self) -> dict[str, str]:
        return {"key_id": "test-key", "secret": "test-secret", "project_id": self.contract["project_id"]}

    def test_mocked_inventory_is_get_only_and_selects_exact_builder_flavor(self) -> None:
        requests: list[tuple[str, str, dict[str, str], bytes | None]] = []

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            requests.append((method, url, headers, body))
            if method == "POST":
                self.assertEqual(url, self.contract["api"]["iam_token_endpoint"])
                return {"access_token": "test-bearer-token"}
            if url.endswith("/vms?project_id=" + self.contract["project_id"]):
                return {"items": [{
                    "id": "vm-ubuntu", "name": "GoodBear Ubuntu builder", "status": "stopped",
                    "availability_zone": {"id": "az-1", "name": "ru.AZ-1"},
                    "flavor": {"id": "flavor-4-16", "name": "builder", "cpu": 4, "ram": 16},
                    "tags": ["good-bear", "ubuntu", "m15-02"],
                    "interfaces": [{"ip": "192.0.2.10"}], "metadata": {"user_data": "drop"},
                    "user_data": "drop", "secret": "drop",
                }]}
            if url.endswith("/availability-zones?project_id=" + self.contract["project_id"]):
                return [{"id": "az-1", "name": "ru.AZ-1", "private_note": "drop"}]
            if "/subnets?" in url:
                return {"items": [{
                    "id": "subnet-1", "name": "builders", "status": "available",
                    "availability_zone_id": "az-1", "cidr": "192.0.2.0/24", "gateway_ip": "192.0.2.1",
                }]}
            if "/security-groups?" in url:
                return {"items": [{
                    "id": "sg-1", "name": "builders", "status": "available",
                    "availability_zone_id": "az-1", "rules": [{"remote_ip_prefix": "198.51.100.0/24"}],
                }]}
            if "/floating-ips?" in url:
                return {"items": [{
                    "id": "fip-1", "name": "builder-public", "status": "available",
                    "availability_zone_id": "az-1", "ip_address": "203.0.113.10",
                }]}
            if "/images?" in url:
                return {"items": [{
                    "id": "image-1", "name": "windows-builder", "status": "active",
                    "availability_zone_id": "az-1", "metadata": {"key": "drop"},
                }]}
            if "availability_zone_id=az-1" in url:
                return {"items": [
                    {"id": "flavor-4-16", "name": "builder", "cpu": 4, "ram": 16, "secret": "drop"},
                ]}
            return {"items": [
                {"id": "flavor-4-8", "name": "nearby", "cpu": 4, "ram": 8, "secret": "drop"},
                {"id": "flavor-4-16", "name": "builder", "cpu": 4, "ram": 16},
                {"id": "flavor-8-16", "name": "wrong-cpu", "cpu": 8, "memory_gib": 16},
            ]}

        inventory = INVENTORY.collect_inventory(self.contract, self.credentials(), sender)
        self.assertEqual([entry[0] for entry in requests], ["POST", "GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET"])
        self.assertEqual(inventory["flavor_selection"], {
            "status": "unique-match",
            "required": {"vcpu": 4, "memory_gib": 16},
            "candidates": [{"id": "flavor-4-16", "memory_gib": 16, "name": "builder", "vcpu": 4}],
            "nearby_4vcpu": [{"id": "flavor-4-8", "memory_gib": 8, "name": "nearby", "vcpu": 4}],
        })
        self.assertEqual(inventory["flavor_selection_by_availability_zone"], [{
            "availability_zone": {"id": "az-1", "name": "ru.AZ-1"},
            "selection": {
                "status": "unique-match",
                "required": {"vcpu": 4, "memory_gib": 16},
                "candidates": [{"id": "flavor-4-16", "memory_gib": 16, "name": "builder", "vcpu": 4}],
                "nearby_4vcpu": [],
            },
        }])
        self.assertEqual(inventory["stopped_ubuntu_builder_parity"], {
            "status": "unique-match",
            "tag_status": "tagged",
            "mutation_eligibility": "tagged-only; untagged candidates are inventory evidence only",
            "candidates": [{
                "id": "vm-ubuntu", "name": "GoodBear Ubuntu builder", "status": "stopped",
                "availability_zone": {"id": "az-1", "name": "ru.AZ-1"},
                "flavor": {"id": "flavor-4-16", "name": "builder", "vcpu": 4, "memory_gib": 16},
                "tags": ["good-bear", "m15-02", "ubuntu"],
            }],
        })
        self.assertEqual(inventory["network_and_image_inventory"], {
            "subnets": [{"availability_zone": {"id": "az-1"}, "id": "subnet-1", "name": "builders", "status": "available"}],
            "security_groups": [{"availability_zone": {"id": "az-1"}, "id": "sg-1", "name": "builders", "status": "available"}],
            "floating_ips": [{"availability_zone": {"id": "az-1"}, "id": "fip-1", "name": "builder-public", "status": "available"}],
            "images": [{"availability_zone": {"id": "az-1"}, "id": "image-1", "name": "windows-builder", "status": "active"}],
        })
        self.assertEqual(inventory["not_in_this_compute_openapi"], ["vpcs", "ssh_keys"])
        rendered = json.dumps(inventory)
        self.assertNotIn("test-secret", rendered)
        self.assertNotIn("test-bearer-token", rendered)
        self.assertNotIn("private_note", rendered)
        self.assertNotIn("192.0.2.10", rendered)
        self.assertNotIn("192.0.2.0/24", rendered)
        self.assertNotIn("198.51.100.0/24", rendered)
        self.assertNotIn("203.0.113.10", rendered)
        self.assertNotIn("user_data", rendered)

    def test_arbitrary_host_method_and_query_are_rejected_before_network(self) -> None:
        valid = INVENTORY.approved_compute_url(self.contract, "/api/v1/flavors")
        with self.assertRaisesRegex(INVENTORY.ContractError, "GET only"):
            INVENTORY.validate_compute_request("POST", valid, self.contract)
        with self.assertRaisesRegex(INVENTORY.ContractError, "official endpoint"):
            INVENTORY.validate_compute_request("GET", "https://example.invalid/api/v1/flavors?project_id=x", self.contract)
        with self.assertRaisesRegex(INVENTORY.ContractError, "only declared project"):
            INVENTORY.validate_compute_request("GET", valid + "&page=2", self.contract)
        with self.assertRaisesRegex(INVENTORY.ContractError, "only declared project"):
            INVENTORY.validate_compute_request("GET", valid + "&cpu=4", self.contract)
        with self.assertRaisesRegex(INVENTORY.ContractError, "only declared project"):
            INVENTORY.validate_compute_request("GET", "https://compute.api.cloud.ru/api/v1/vms?project_id="
                                              + self.contract["project_id"] + "&page=2", self.contract)

    def test_missing_or_nonexternal_credentials_are_rejected(self) -> None:
        with self.assertRaisesRegex(INVENTORY.ContractError, "absolute external"):
            INVENTORY.load_external_credentials(Path("credentials.json"), self.contract)
        missing = Path("/tmp/m15-03-missing-cloudru-access.json")
        changed_missing = copy.deepcopy(self.contract)
        changed_missing["credential_reference"]["path"] = str(missing)
        with self.assertRaisesRegex(INVENTORY.ContractError, "regular non-symlink"):
            INVENTORY.load_external_credentials(missing, changed_missing)
        changed = copy.deepcopy(self.contract)
        changed["credential_reference"]["path"] = str(ROOT / "credentials.json")
        with self.assertRaisesRegex(INVENTORY.ContractError, "outside the repository"):
            INVENTORY.validate_inventory_contract(changed)

    def test_external_credentials_are_strict_and_never_logged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            credential = Path(temporary) / "cloudru-access.json"
            credential.write_text(json.dumps(self.credentials()), encoding="utf-8")
            credential.chmod(0o600)
            changed = copy.deepcopy(self.contract)
            changed["credential_reference"]["path"] = str(credential)
            self.assertEqual(INVENTORY.load_external_credentials(credential, changed), self.credentials())
            credential.chmod(0o644)
            with self.assertRaisesRegex(INVENTORY.ContractError, "group/world"):
                INVENTORY.load_external_credentials(credential, changed)


if __name__ == "__main__":
    unittest.main()

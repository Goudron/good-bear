#!/usr/bin/env python3
"""Fail-closed tests for the direct Cloud.ru M15-03 builder lifecycle."""

from __future__ import annotations

import copy
import base64
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import provision_m15_03_cloud_windows as PROVISION  # noqa: E402


class M1503DirectCloudLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(
            (ROOT / "config" / "m15-03-direct-cloud-windows-2022.json").read_text(encoding="utf-8")
        )
        self.builder = self.contract["builder"]
        self.tag_ids = ["tag-goodbear", "tag-windows", "tag-task"]

    def vm(self, state: str = "stopped") -> dict:
        return {
            "id": "vm-exact", "name": self.builder["name"], "project_id": self.contract["project_id"],
            "state": state,
            "availability_zone": {"id": self.builder["availability_zone_id"]},
            "flavor": {"id": self.builder["flavor_id"], "name": self.builder["flavor_name"],
                       "cpu": 4, "ram": 16},
            "tags": [{"id": identifier} for identifier in self.tag_ids],
            "interfaces": [{"floating_ip": {"id": self.builder["public_ip_id"]}}],
        }

    def detail(self, state: str = "stopped") -> dict:
        value = self.vm(state)
        value["project"] = {"id": self.contract["project_id"]}
        value["disks"] = [{
            "id": "boot-disk", "name": self.builder["boot_disk_name"], "size": 250, "primary": True,
            "disk_type": {"id": self.builder["ssd_disk_type_id"]},
        }]
        value["interfaces"] = [{
            "id": "interface", "primary": True, "type": "regular", "interface_security_enabled": True,
            "subnet": {"id": self.builder["subnet_id"]},
            "floating_ip": {"id": self.builder["public_ip_id"]},
            "security_groups": [{"id": self.builder["security_group_id"]}],
        }]
        return value

    def responses(self, *, vm: dict | None = None, detail: dict | None = None):
        builder = self.builder
        tags = [{"id": identifier, "name": name}
                for identifier, name in zip(self.tag_ids, builder["tags"], strict=True)]

        def caller(method: str, url: str, _headers: dict, body=None):
            self.assertEqual(method, "GET")
            if "/subnets?" in url:
                return {"items": [{"id": builder["subnet_id"]}]}
            if "/api/tags/v1/tags?" in url:
                return {"tags": tags}
            if "/security-groups/" in url and url.endswith("/rules"):
                return {"items": [
                    {"direction": "ingress", "ether_type": "IPv4", "ip_protocol": "tcp",
                     "port_range": "22:22", "remote_ip_prefix": self.contract["remote_access"]["allowed_source_cidr"]},
                    {"direction": "ingress", "ether_type": "IPv4", "ip_protocol": "tcp",
                     "port_range": "3389:3389", "remote_ip_prefix": self.contract["remote_access"]["allowed_source_cidr"]},
                    {"direction": "ingress", "ether_type": "IPv4", "ip_protocol": "tcp",
                     "port_range": "5986:5986", "remote_ip_prefix": self.contract["remote_access"]["allowed_source_cidr"]},
                    {"direction": "egress", "ether_type": "IPv4", "ip_protocol": "tcp",
                     "port_range": "1:65535", "remote_ip_prefix": "0.0.0.0/0"},
                    {"direction": "egress", "ether_type": "IPv4", "ip_protocol": "udp",
                     "port_range": "1:65535", "remote_ip_prefix": "0.0.0.0/0"},
                ]}
            if "/security-groups?" in url:
                return {"items": [{"id": builder["security_group_id"], "state": "created"}]}
            if "/floating-ips?" in url:
                return {"items": [{"id": builder["public_ip_id"], "state": "in_use"}]}
            if url.endswith("/api/v1/vms/vm-exact?project_id=" + self.contract["project_id"]):
                return detail
            if "/api/v1/vms?" in url:
                return {"items": [] if vm is None else [vm]}
            self.fail(f"catalog or unexpected endpoint reached during existing-VM inspection: {url}")

        return caller

    def test_existing_exact_vm_is_inspectable_after_catalog_flavor_disappears(self) -> None:
        summary = self.vm()
        detail = self.detail()
        calls: list[str] = []
        caller = self.responses(vm=summary, detail=detail)

        def recording(method: str, url: str, headers: dict, body=None):
            calls.append(url)
            return caller(method, url, headers, body)

        with mock.patch.object(PROVISION, "call_json", side_effect=recording):
            evidence = PROVISION.preflight(self.contract, {"Authorization": "Bearer redacted"})
        self.assertTrue(evidence["existing_vm_verified"])
        self.assertEqual(evidence["catalog_validation"], "existing-instance-pinned")
        self.assertFalse(any("/flavors" in url or "/images/" in url for url in calls))

    def test_global_rdp_requires_recorded_maintainer_authorization(self) -> None:
        PROVISION.validate_contract(self.contract)
        unrecorded = copy.deepcopy(self.contract)
        unrecorded["remote_access"].pop("inbound_exposure")
        with self.assertRaisesRegex(PROVISION.CloudProvisionError, "recorded global"):
            PROVISION.validate_contract(unrecorded)

    def test_new_windows_payload_bootstraps_rdp_without_language_specific_firewall_names(self) -> None:
        evidence = {"tag_ids": self.tag_ids}
        access = {"username": "gbbuild", "password": "Gb!test-password-that-is-long-enough"}
        calls: list[tuple[str, str, object]] = []

        def caller(method: str, url: str, _headers: dict, body=None):
            calls.append((method, url, body))
            return {"items": [{"id": "new-vm"}]}

        with mock.patch.object(PROVISION, "call_json", side_effect=caller):
            created = PROVISION.create_vm(self.contract, {}, evidence, access)

        self.assertEqual(created["id"], "new-vm")
        self.assertEqual(len(calls), 1)
        payload = calls[0][2][0]
        cloud_init = base64.b64decode(payload["cloud_init"], validate=True).decode("utf-8")
        self.assertIn("name: 'gbbuild'", cloud_init)
        self.assertIn("passwd: 'Gb!test-password-that-is-long-enough'", cloud_init)
        self.assertIn("fDenyTSConnections", cloud_init)
        self.assertIn("Set-Service -Name 'TermService' -StartupType Automatic", cloud_init)
        self.assertIn("netsh advfirewall firewall add rule name='Good Bear RDP'", cloud_init)
        self.assertIn("localport=3389", cloud_init)
        self.assertIn("Set-Service -Name 'WinRM' -StartupType Automatic", cloud_init)
        self.assertIn("Transport=HTTPS", cloud_init)
        self.assertIn("netsh advfirewall firewall add rule name='Good Bear WinRM HTTPS'", cloud_init)
        self.assertIn("OpenSSH.Server", cloud_init)
        self.assertIn("localport=22", cloud_init)
        self.assertIn("localport=5986", cloud_init)
        self.assertNotIn("NetFirewallRule", cloud_init)
        self.assertNotIn("DisplayGroup", cloud_init)
        self.assertNotIn("image_metadata", payload)

    def test_mismatched_tags_or_network_fail_before_any_lifecycle_mutation(self) -> None:
        summary = self.vm()
        summary["tags"] = summary["tags"][:-1]
        with mock.patch.object(PROVISION, "call_json", side_effect=self.responses(vm=summary, detail=self.detail())):
            with self.assertRaisesRegex(PROVISION.CloudProvisionError, "tags differ"):
                PROVISION.preflight(self.contract, {})

        summary = self.vm()
        detail = self.detail()
        detail["interfaces"][0]["security_groups"] = [{"id": "wrong-group"}]
        with mock.patch.object(PROVISION, "call_json", side_effect=self.responses(vm=summary, detail=detail)):
            with self.assertRaisesRegex(PROVISION.CloudProvisionError, "network boundary"):
                PROVISION.preflight(self.contract, {})

    def evidence(self, state: str = "stopped") -> dict:
        return {"existing_vm_verified": True, "existing_vm": self.detail(state)}

    def test_start_and_stop_use_only_the_exact_set_power_endpoint(self) -> None:
        calls: list[tuple[str, str, object]] = []

        def caller(method: str, url: str, _headers: dict, body=None):
            calls.append((method, url, body))

        vm, applied, action = PROVISION.execute_lifecycle(
            self.contract, {}, self.evidence("stopped"), "start", caller=caller,
        )
        self.assertTrue(applied)
        self.assertEqual((vm["state"], action), ("starting", "start-requested"))
        self.assertEqual(calls, [("POST", self.contract["api"]["compute_endpoint"]
                                  + "/api/v1/vms/vm-exact/set-power", {"state": "power_on"})])

        calls.clear()
        vm, applied, action = PROVISION.execute_lifecycle(
            self.contract, {}, self.evidence("running"), "stop",
            lifecycle_reason="completed", caller=caller,
        )
        self.assertTrue(applied)
        self.assertEqual((vm["state"], action), ("stopping", "stop-requested"))
        self.assertEqual(calls, [("POST", self.contract["api"]["compute_endpoint"]
                                  + "/api/v1/vms/vm-exact/set-power", {"state": "power_off"})])

    def test_power_operations_are_idempotent_and_stop_requires_reason(self) -> None:
        caller = mock.Mock()
        _vm, applied, action = PROVISION.execute_lifecycle(
            self.contract, {}, self.evidence("running"), "start", caller=caller,
        )
        self.assertFalse(applied)
        self.assertEqual(action, "already-running")
        _vm, applied, action = PROVISION.execute_lifecycle(
            self.contract, {}, self.evidence("stopped"), "stop",
            lifecycle_reason="unsuccessful", caller=caller,
        )
        self.assertFalse(applied)
        self.assertEqual(action, "already-stopped")
        caller.assert_not_called()
        with self.assertRaisesRegex(PROVISION.CloudProvisionError, "requires --lifecycle-reason"):
            PROVISION.execute_lifecycle(self.contract, {}, self.evidence("running"), "stop", caller=caller)

    def test_delete_requires_verified_return_exact_name_and_stopped_state(self) -> None:
        caller = mock.Mock(return_value=None)
        name = self.builder["name"]
        for kwargs, message in (
            ({"confirm_delete": name}, "verified-return"),
            ({"verified_return": True, "confirm_delete": "another-vm"}, "exact builder name"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(PROVISION.CloudProvisionError, message):
                    PROVISION.execute_lifecycle(self.contract, {}, self.evidence(), "delete", caller=caller, **kwargs)
        with self.assertRaisesRegex(PROVISION.CloudProvisionError, "must be stopped"):
            PROVISION.execute_lifecycle(self.contract, {}, self.evidence("running"), "delete",
                                        verified_return=True, confirm_delete=name, caller=caller)
        caller.assert_not_called()

        vm, applied, action = PROVISION.execute_lifecycle(
            self.contract, {}, self.evidence(), "delete",
            verified_return=True, confirm_delete=name, caller=caller,
        )
        self.assertTrue(applied)
        self.assertEqual((vm["state"], action), ("deleting", "delete-requested"))
        caller.assert_called_once_with(
            "DELETE", self.contract["api"]["compute_endpoint"] + "/api/v1/vms/vm-exact", {}, {},
        )

    def test_lifecycle_rejects_unverified_or_mismatched_target(self) -> None:
        caller = mock.Mock()
        with self.assertRaisesRegex(PROVISION.CloudProvisionError, "exact verified"):
            PROVISION.execute_lifecycle(self.contract, {}, {"existing_vm_verified": False}, "start", caller=caller)
        changed = self.evidence()
        changed["existing_vm"] = dict(changed["existing_vm"], name="wrong-builder")
        with self.assertRaisesRegex(PROVISION.CloudProvisionError, "target name differs"):
            PROVISION.execute_lifecycle(self.contract, {}, changed, "start", caller=caller)
        caller.assert_not_called()


if __name__ == "__main__":
    unittest.main()

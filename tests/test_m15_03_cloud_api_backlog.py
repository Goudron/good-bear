#!/usr/bin/env python3
"""Focused planning contract for GB100-M15-03 Cloud.ru VM control."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BACKLOG = ROOT / "backlogs" / "good_bear_1_0_russian_pki_container_backlog_2026-08-22.md"


def m15_03_row() -> str:
    for line in BACKLOG.read_text(encoding="utf-8").splitlines():
        if line.startswith("| `GB100-M15-03` "):
            return line
    raise AssertionError("GB100-M15-03 backlog row is missing")


class CloudApiBacklogContractTest(unittest.TestCase):
    def test_control_plane_is_idempotent_and_uses_external_secret_references(self) -> None:
        row = m15_03_row()
        self.assertIn("API/IaC control-plane contract", row)
        self.assertIn("official Cloud.ru API", row)
        self.assertIn("outside-the-repository", row)
        self.assertIn("API-endpoint and authentication-secret references", row)
        self.assertIn("idempotent create, inspect, start, stop, and delete", row)
        self.assertIn("uniquely tagged Good Bear Windows builder", row)

    def test_builder_parity_network_cost_and_inventory_boundaries_are_explicit(self) -> None:
        row = m15_03_row()
        for requirement in (
            "four vCPUs, 16 GiB RAM, 250 GB SSD workspace storage",
            "least-privilege security group",
            "attached public IP",
            "SSH/WinRM access restricted to approved maintainer source ranges",
            "fail-closed cost/lifecycle guard",
            "stop/delete after an unsuccessful or completed run",
            "Record non-secret VM/image/network/security-group/public-IP identifiers",
            "redact/reject credentials, tokens, passwords, and private keys",
            "headless API/IaC operations",
            "makes no Cloud API call and logs no credential",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, row)
        self.assertNotIn("200 GB", row)

    def test_headless_image_path_and_narrow_manual_gates_remain_required(self) -> None:
        row = m15_03_row()
        self.assertIn("RAW VirtIO disk", row)
        self.assertIn("`autounattend.xml`", row)
        self.assertIn("`sysprep /oobe /generalize /shutdown`", row)
        self.assertIn("only for unavoidable Cloud account/billing/quota or secret provisioning", row)
        self.assertIn("provider console recovery when no documented API/IaC path exists", row)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Offline fail-closed contract tests for GB100-M15-03."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import validate_m15_03_cloud_contract as CONTRACT  # noqa: E402


class M1503CloudContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(
            (ROOT / "config" / "m15-03-cloud-api-contract.json").read_text(encoding="utf-8")
        )

    def test_current_plan_is_offline_and_reports_every_unresolved_pin(self) -> None:
        CONTRACT.validate_shape(self.contract)
        blockers = CONTRACT.readiness_blockers(self.contract)
        self.assertIn("Windows Server 2025 Evaluation ISO path", blockers)
        self.assertIn("VirtIO media SHA-256", blockers)
        self.assertIn("verified VirtIO signature", blockers)
        self.assertIn("Cloudbase-Init bootstrap path", blockers)
        self.assertIn("verified Cloudbase-Init Authenticode", blockers)
        self.assertIn("Cloud.ru builder.user_image_id", blockers)
        self.assertIn("approved maintainer source CIDR", blockers)
        with self.assertRaisesRegex(CONTRACT.ContractError, "preflight blocked"):
            CONTRACT.require(not blockers, "M15-03 preflight blocked: " + "; ".join(blockers))

    def test_credential_reference_never_moves_into_the_repository(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["credential_reference"]["path"] = str(ROOT / "cloudru-access.json")
        with self.assertRaisesRegex(CONTRACT.ContractError, "outside the repository"):
            CONTRACT.validate_shape(changed)

    def test_broad_ingress_and_mutation_intent_fail_closed(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["remote_access"]["allowed_source_cidrs"] = ["0.0.0.0/0"]
        with self.assertRaisesRegex(CONTRACT.ContractError, "broad public ingress"):
            CONTRACT.validate_shape(changed)
        changed = copy.deepcopy(self.contract)
        changed["mutation_authorized"] = True
        with self.assertRaisesRegex(CONTRACT.ContractError, "separate explicit authorization"):
            CONTRACT.validate_shape(changed)

    def test_complete_nonsecret_shape_has_no_readiness_blockers(self) -> None:
        changed = copy.deepcopy(self.contract)
        windows = changed["image_inputs"]["windows_server_2025_evaluation"]
        virtio = changed["image_inputs"]["virtio_win"]
        bootstrap = changed["image_inputs"]["bootstrap"]
        windows.update(path="/input/server-2025.iso", sha256="a" * 64)
        virtio.update(path="/input/virtio-win.iso", sha256="b" * 64,
                      signature_path="/input/virtio-win.iso.sig", signature_sha256="d" * 64,
                      signature_verified=True)
        bootstrap.update(cloudbase_init_path="/input/cloudbase-init.msi", cloudbase_init_sha256="c" * 64,
                         cloudbase_init_authenticode_verified=True,
                         cloudbase_init_publisher="Cloudbase Solutions",
                         openssh_or_winrm="openssh-and-winrm")
        changed["builder"].update(flavor_id="flavor-4c16g", availability_zone_id="zone-a", subnet_id="subnet-a",
                                  security_group_id="sg-goodbear", public_ip_id="pip-goodbear",
                                  user_image_id="image-goodbear")
        changed["remote_access"]["allowed_source_cidrs"] = ["198.51.100.42/32"]
        CONTRACT.validate_shape(changed)
        self.assertEqual(CONTRACT.readiness_blockers(changed), [])


if __name__ == "__main__":
    unittest.main()

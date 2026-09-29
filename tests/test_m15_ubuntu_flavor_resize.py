"""Mocked safety checks for the one approved Ubuntu builder flavor change."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import m15_builder_power as power  # noqa: E402
import m15_ubuntu_flavor_resize as resize  # noqa: E402


class M15UbuntuFlavorResizeTest(unittest.TestCase):
    def credentials(self) -> dict[str, str]:
        return {"key_id": "mock-key", "secret": "mock-secret", "project_id": power.PROJECT_ID}

    def vm(self, *, target: bool = False, state: str = "stopped", **changes: object) -> dict[str, object]:
        flavor = ({"id": resize.TARGET_FLAVOR_ID, "name": resize.TARGET_FLAVOR_NAME,
                   "cpu": resize.TARGET_CPU, "ram": resize.TARGET_RAM_GIB}
                  if target else {"id": "800df814-9478-49ad-99f5-086c3d85a19e",
                                   "name": "gen-4-32", "cpu": 4, "ram": 32})
        value: dict[str, object] = {"id": power.VM_ID, "name": power.VM_NAME,
                                    "project_id": power.PROJECT_ID, "status": state,
                                    "floating_ips": [{"ip_address": power.PUBLIC_IP}], "flavor": flavor}
        value.update(changes)
        return value

    def test_resize_is_pinned_and_polls_until_stopped_target(self) -> None:
        calls: list[tuple[str, str, bytes | None]] = []
        vms = iter([self.vm(), self.vm(target=True, state="updating"), self.vm(target=True)])

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            calls.append((method, url, body))
            if url == power.IAM_TOKEN_ENDPOINT:
                self.assertEqual(json.loads(body or b"{}"), {"keyId": "mock-key", "secret": "mock-secret"})
                return {"access_token": "mock-bearer"}
            self.assertEqual(headers["Authorization"], "Bearer mock-bearer")
            if method == "PUT":
                self.assertEqual((url, body), (power.vm_url(), b'{"flavor_id":"1e332e48-ddbd-402b-aff5-66c87e411f06"}'))
                return {"vm": self.vm(target=True, state="updating")}
            return {"vm": next(vms)}

        sleeps: list[float] = []
        resize.resize(self.credentials(), sender, sleeps.append)
        self.assertEqual([method for method, _, _ in calls], ["POST", "GET", "PUT", "GET", "GET"])
        self.assertEqual(sleeps, [resize.POLL_SECONDS])

    def test_rejects_identity_or_unapproved_flavor_before_put(self) -> None:
        for vm in (self.vm(name="other"), self.vm(project_id="other"), self.vm(floating_ips=[]),
                   self.vm(state="active"), self.vm(target=True),
                   self.vm(flavor={"id": "other", "name": "other", "cpu": 4, "ram": 64})):
            with self.subTest(vm=vm):
                calls: list[str] = []
                def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
                    calls.append(method)
                    return {"access_token": "mock"} if url == power.IAM_TOKEN_ENDPOINT else {"vm": vm}
                with self.assertRaises(resize.ResizeError):
                    resize.resize(self.credentials(), sender, lambda _: None)
                self.assertNotIn("PUT", calls)

    def test_request_surface_and_inspect(self) -> None:
        with self.assertRaises(resize.ResizeError):
            resize.validate_request("PUT", power.vm_url(), b'{"flavor_id":"other"}')
        with self.assertRaises(resize.ResizeError):
            resize.validate_request("DELETE", power.vm_url(), None)
        with self.assertRaises(resize.ResizeError):
            resize.validate_request("PUT", "https://example.invalid/api/v1/vms/x", b"{}")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            resize.parse_action([])
        self.assertEqual(resize.parse_action(["--inspect-ubuntu-flavor"]), "inspect")
        self.assertEqual(resize.parse_action(["--resize-ubuntu-to-64gib"]), "resize")

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            return {"access_token": "mock"} if url == power.IAM_TOKEN_ENDPOINT else {"vm": self.vm(target=True)}
        self.assertEqual(resize.inspect(self.credentials(), sender), "stopped")


if __name__ == "__main__":
    unittest.main()

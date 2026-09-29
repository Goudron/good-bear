"""Mocked API tests for the pinned Ubuntu primary-disk resize guard."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import m15_builder_power as power  # noqa: E402
import m15_ubuntu_disk_resize as resize  # noqa: E402


DISK_ID = "2f87eb1c-2d7e-4c72-ac31-7840f4a9c596"


class M15UbuntuDiskResizeTest(unittest.TestCase):
    def credentials(self) -> dict[str, str]:
        return {"key_id": "mock-key", "secret": "mock-secret", "project_id": power.PROJECT_ID}

    def vm(self, size: int = 80, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "id": power.VM_ID,
            "name": power.VM_NAME,
            "project_id": power.PROJECT_ID,
            "status": "active",
            "floating_ips": [{"ip_address": power.PUBLIC_IP}],
            "disks": [{"id": DISK_ID, "name": "ubuntu-root", "primary": True, "size": size}],
        }
        value.update(changes)
        return value

    def disk(self, size: int = 80, state: str = "in_use", **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "id": DISK_ID,
            "name": "ubuntu-root",
            "size": size,
            "state": state,
            "project": {"id": power.PROJECT_ID},
            "bootable": True,
            "readonly": False,
            "shared": False,
            "vms": [{"id": power.VM_ID, "name": power.VM_NAME, "primary": True}],
        }
        value.update(changes)
        return value

    def test_resize_uses_discovered_primary_only_and_polls_to_250(self) -> None:
        requests: list[tuple[str, str, bytes | None]] = []
        vms = iter([self.vm(), self.vm(), self.vm(250)])
        disks = iter([self.disk(), self.disk(80, "updating"), self.disk(250)])

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            requests.append((method, url, body))
            if url == power.IAM_TOKEN_ENDPOINT:
                self.assertEqual(json.loads(body or b"{}"), {"keyId": "mock-key", "secret": "mock-secret"})
                return {"access_token": "mock-bearer"}
            self.assertEqual(headers["Authorization"], "Bearer mock-bearer")
            if method == "PUT":
                self.assertEqual((url, body), (resize.disk_url(DISK_ID), b'{"size":250}'))
                self.assertEqual(headers["Content-Type"], "application/json")
                return self.disk(80, "updating")
            if url == power.vm_url():
                return {"vm": next(vms)}
            self.assertEqual(url, resize.disk_url(DISK_ID))
            return next(disks)

        sleeps: list[float] = []
        self.assertEqual(resize.resize(self.credentials(), sender, sleeps.append), (DISK_ID, 250))
        self.assertEqual([method for method, _, _ in requests],
                         ["POST", "GET", "GET", "PUT", "GET", "GET", "GET", "GET"])
        self.assertEqual(sleeps, [resize.POLL_SECONDS])

    def test_mutation_is_rejected_for_wrong_identity_or_disk(self) -> None:
        cases = [
            (self.vm(name="someone-else"), self.disk()),
            (self.vm(project_id="different"), self.disk()),
            (self.vm(floating_ips=[]), self.disk()),
            (self.vm(disks=[]), self.disk()),
            (self.vm(disks=[{"id": DISK_ID, "name": "ubuntu-root", "primary": True, "size": 80},
                                  {"id": "7488086b-b5db-4a91-a205-fab34943406d", "primary": True, "size": 80}]),
             self.disk()),
            (self.vm(), self.disk(project={"id": "different"})),
            (self.vm(), self.disk(id="7488086b-b5db-4a91-a205-fab34943406d")),
            (self.vm(), self.disk(bootable=False)),
            (self.vm(), self.disk(readonly=True)),
            (self.vm(), self.disk(shared=True)),
            (self.vm(), self.disk(vms=[])),
            (self.vm(), self.disk(vms=[{"id": power.VM_ID, "name": power.VM_NAME, "primary": True},
                                         {"id": "other"}])),
            (self.vm(), self.disk(size=81)),
            (self.vm(250), self.disk(250)),
            (self.vm(), self.disk(state="error")),
        ]
        for vm, disk in cases:
            with self.subTest(vm=vm, disk=disk):
                requests: list[tuple[str, str]] = []

                def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
                    requests.append((method, url))
                    if url == power.IAM_TOKEN_ENDPOINT:
                        return {"access_token": "mock-bearer"}
                    return {"vm": vm} if url == power.vm_url() else disk

                with self.assertRaises(resize.ResizeError):
                    resize.resize(self.credentials(), sender, lambda _: None)
                self.assertFalse(any(method == "PUT" for method, _ in requests))

    def test_post_mutation_identity_change_fails_closed(self) -> None:
        vm_count = 0
        requests: list[str] = []

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            nonlocal vm_count
            requests.append(method)
            if url == power.IAM_TOKEN_ENDPOINT:
                return {"access_token": "mock-bearer"}
            if method == "PUT":
                return self.disk(80, "updating")
            if url == power.vm_url():
                vm_count += 1
                if vm_count == 1:
                    return self.vm()
                return self.vm(disks=[{"id": "7488086b-b5db-4a91-a205-fab34943406d",
                                       "name": "new-root", "primary": True, "size": 80}])
            return self.disk()

        with self.assertRaisesRegex(resize.ResizeError, "changed during resize"):
            resize.resize(self.credentials(), sender, lambda _: None)
        self.assertEqual(requests.count("PUT"), 1)

    def test_request_surface_and_read_only_inspect(self) -> None:
        with self.assertRaises(resize.ResizeError):
            resize.validate_disk_request("DELETE", resize.disk_url(DISK_ID), None, DISK_ID)
        with self.assertRaises(resize.ResizeError):
            resize.validate_disk_request("PUT", resize.disk_url(DISK_ID), b'{"size":500}', DISK_ID)
        with self.assertRaises(resize.ResizeError):
            resize.validate_disk_request("PUT", resize.disk_url(DISK_ID) + "?project_id=x", b'{"size":250}', DISK_ID)
        with self.assertRaises(resize.ResizeError):
            resize.validate_disk_request("PUT", "https://example.invalid/api/v1/disks/" + DISK_ID,
                                         b'{"size":250}', DISK_ID)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            resize.parse_action([])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            resize.parse_action(["--resize-ubuntu-disk-to", "251"])
        self.assertEqual(resize.parse_action(["--inspect-ubuntu-disk"]), "inspect")
        self.assertEqual(resize.parse_action(["--resize-ubuntu-disk-to", "250"]), "resize")

        requests: list[str] = []

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            requests.append(method)
            if url == power.IAM_TOKEN_ENDPOINT:
                return {"access_token": "mock-bearer"}
            return self.vm() if url == power.vm_url() else self.disk()

        self.assertEqual(resize.inspect(self.credentials(), sender), (DISK_ID, 80, "in_use"))
        self.assertEqual(requests, ["POST", "GET", "GET"])

    def test_cli_never_prints_secret_or_server_body(self) -> None:
        output = io.StringIO()
        with patch.object(power, "load_credentials", return_value=self.credentials()), \
                patch.object(resize, "inspect", return_value=(DISK_ID, 80, "in_use")):
            with contextlib.redirect_stdout(output):
                self.assertEqual(resize.main(["--inspect-ubuntu-disk"]), 0)
        self.assertEqual(output.getvalue(),
                         f"Pinned Ubuntu primary disk verified: {DISK_ID}; size: 80 GB; state: in_use.\n")
        self.assertNotIn("mock-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()

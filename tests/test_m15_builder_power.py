#!/usr/bin/env python3
"""Mocked HTTP tests for the intentionally narrow M15 builder power tool."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import contextlib
import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import m15_builder_power as POWER  # noqa: E402


class M15BuilderPowerTest(unittest.TestCase):
    def credentials(self) -> dict[str, str]:
        return {"key_id": "test-key", "secret": "test-secret", "project_id": POWER.PROJECT_ID}

    def vm(self, status: str, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "id": POWER.VM_ID,
            "project_id": POWER.PROJECT_ID,
            "name": POWER.VM_NAME,
            "status": status,
            "floating_ips": [{"ip_address": POWER.PUBLIC_IP}],
        }
        value.update(changes)
        return value

    def test_start_fetches_exact_vm_posts_only_official_power_on_and_polls(self) -> None:
        requests: list[tuple[str, str, dict[str, str], bytes | None]] = []
        states = iter(["stopped", "starting", "active"])

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            requests.append((method, url, headers, body))
            if url == POWER.IAM_TOKEN_ENDPOINT:
                self.assertEqual((method, headers), ("POST", {"Content-Type": "application/json"}))
                self.assertEqual(json.loads((body or b"").decode()), {"keyId": "test-key", "secret": "test-secret"})
                return {"access_token": "mock-bearer-token"}
            if method == "POST":
                self.assertEqual(url, POWER.vm_url(action=True))
                self.assertEqual(json.loads((body or b"").decode()), {"state": "power_on"})
                self.assertEqual(headers["Authorization"], "Bearer mock-bearer-token")
                return {"accepted": True}
            self.assertEqual((method, url, body), ("GET", POWER.vm_url(), None))
            return {"vm": self.vm(next(states))}

        sleeps: list[float] = []
        self.assertEqual(POWER.execute("power_on", self.credentials(), sender, sleeps.append), "active")
        self.assertEqual([request[0] for request in requests], ["POST", "GET", "POST", "GET", "GET"])
        self.assertEqual(sleeps, [POWER.POLL_SECONDS])
        self.assertNotIn("test-secret", repr(sleeps))
        self.assertNotIn("mock-bearer-token", repr(sleeps))

    def test_identity_or_source_status_conflict_aborts_before_power_post(self) -> None:
        cases = [
            self.vm("stopped", id="another-vm"),
            self.vm("stopped", name="another VM"),
            self.vm("stopped", project_id="another-project"),
            self.vm("stopped", floating_ips=[{"ip_address": "203.0.113.1"}]),
            self.vm("active"),
        ]
        for vm in cases:
            with self.subTest(vm=vm):
                requests: list[tuple[str, str]] = []

                def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
                    requests.append((method, url))
                    if url == POWER.IAM_TOKEN_ENDPOINT:
                        return {"access_token": "mock-bearer-token"}
                    return {"vm": vm}

                with self.assertRaises(POWER.PowerControlError):
                    POWER.execute("power_on", self.credentials(), sender, lambda _: None)
                self.assertEqual(requests, [("POST", POWER.IAM_TOKEN_ENDPOINT), ("GET", POWER.vm_url())])

    def test_stop_posts_only_power_off_after_a_running_identity_check(self) -> None:
        requests: list[tuple[str, str, bytes | None]] = []
        statuses = iter(["active", "stopping", "stopped"])

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            requests.append((method, url, body))
            if url == POWER.IAM_TOKEN_ENDPOINT:
                return {"access_token": "mock-bearer-token"}
            if method == "POST":
                self.assertEqual(json.loads((body or b"").decode()), {"state": "power_off"})
                return {"accepted": True}
            return self.vm(next(statuses))

        self.assertEqual(POWER.execute("power_off", self.credentials(), sender, lambda _: None), "stopped")
        self.assertEqual([item[0] for item in requests], ["POST", "GET", "POST", "GET", "GET"])
        self.assertEqual(requests[2][1], POWER.vm_url(action=True))

    def test_status_reads_and_reports_only_the_verified_pinned_vm_without_compute_post(self) -> None:
        requests: list[tuple[str, str, dict[str, str], bytes | None]] = []

        def sender(method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict:
            requests.append((method, url, headers, body))
            if url == POWER.IAM_TOKEN_ENDPOINT:
                self.assertEqual(method, "POST")
                return {"access_token": "mock-bearer-token"}
            self.assertEqual((method, url, body), ("GET", POWER.vm_url(), None))
            return {"vm": self.vm("active")}

        self.assertEqual(POWER.status_ubuntu(self.credentials(), sender), "active")
        compute_requests = [request for request in requests if request[1] != POWER.IAM_TOKEN_ENDPOINT]
        self.assertEqual([request[0] for request in compute_requests], ["GET"])
        self.assertFalse(any(method == "POST" for method, _url, _headers, _body in compute_requests))

    def test_status_main_prints_only_verified_nonsecret_identity_summary(self) -> None:
        output = io.StringIO()
        with patch.object(POWER, "load_credentials", return_value=self.credentials()), \
                patch.object(POWER, "status_ubuntu", return_value="active") as status:
            with contextlib.redirect_stdout(output):
                self.assertEqual(POWER.main(["--status-ubuntu"]), 0)
        status.assert_called_once_with(self.credentials(), POWER.urllib_sender)
        self.assertEqual(output.getvalue(),
                         "Pinned M15 Ubuntu builder verified; name match: yes; status: active; "
                         "project match: yes; public-IP match: yes.\n")

    def test_request_allowlist_and_argument_surface_are_closed(self) -> None:
        with self.assertRaisesRegex(POWER.PowerControlError, "pinned official endpoint"):
            POWER.validate_request("GET", "https://example.invalid/api/v1/vms/x?project_id=" + POWER.PROJECT_ID, None)
        with self.assertRaisesRegex(POWER.PowerControlError, "only pinned VM set-power POST"):
            POWER.validate_request("POST", POWER.vm_url(), b'{"state":"power_on"}')
        with self.assertRaisesRegex(POWER.PowerControlError, "approved state"):
            POWER.validate_request("POST", POWER.vm_url(action=True), b'{"state":"reboot"}')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            POWER.parse_action([])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            POWER.parse_action(["--start-ubuntu", "--status-ubuntu"])
        self.assertEqual(POWER.parse_action(["--start-ubuntu"]), "power_on")
        self.assertEqual(POWER.parse_action(["--stop-ubuntu"]), "power_off")
        self.assertEqual(POWER.parse_action(["--status-ubuntu"]), "status")

    def test_non_json_iam_response_reports_only_safe_metadata(self) -> None:
        class Response:
            status = 200
            headers = {"Content-Type": "text/html; charset=utf-8; token=do-not-report"}

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b"<html>secret=do-not-report</html>"

        with patch.object(POWER, "urlopen", return_value=Response()) as urlopen:
            with self.assertRaises(POWER.PowerControlError) as caught:
                POWER.retrieve_bearer(self.credentials(), POWER.urllib_sender)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, POWER.IAM_TOKEN_ENDPOINT)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(json.loads(request.data), {"keyId": "test-key", "secret": "test-secret"})
        self.assertEqual(str(caught.exception),
                         "approved Cloud.ru response is not JSON (HTTP 200; Content-Type: text/html)")
        self.assertNotIn("do-not-report", str(caught.exception))
        self.assertNotIn("test-secret", str(caught.exception))

    def test_empty_http_204_is_accepted_as_successful_no_content(self) -> None:
        class Response:
            status = 204
            headers = {}

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b""

        with patch.object(POWER, "urlopen", return_value=Response()):
            self.assertEqual(
                POWER.urllib_sender("POST", POWER.vm_url(action=True), {}, b'{"state":"power_on"}'),
                {},
            )

    def test_non_empty_http_204_is_rejected(self) -> None:
        class Response:
            status = 204
            headers = {"Content-Type": "application/json"}

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b"{}"

        with patch.object(POWER, "urlopen", return_value=Response()):
            with self.assertRaisesRegex(POWER.PowerControlError, "204 response must be empty"):
                POWER.urllib_sender("POST", POWER.vm_url(action=True), {}, b'{"state":"power_on"}')

    def test_http_error_reports_status_and_sanitized_type_without_body(self) -> None:
        error = HTTPError(POWER.IAM_TOKEN_ENDPOINT, 502, "secret=do-not-report",
                          {"Content-Type": "text/plain; token=do-not-report"},
                          io.BytesIO(b"secret=do-not-report"))
        with patch.object(POWER, "urlopen", side_effect=error):
            with self.assertRaises(POWER.PowerControlError) as caught:
                POWER.retrieve_bearer(self.credentials(), POWER.urllib_sender)
        self.assertEqual(str(caught.exception),
                         "approved Cloud.ru request returned HTTP 502; Content-Type: text/plain")
        self.assertNotIn("do-not-report", str(caught.exception))
        self.assertNotIn("test-secret", str(caught.exception))

    def test_untrusted_metadata_is_never_echoed(self) -> None:
        self.assertEqual(POWER.safe_response_metadata("token=do-not-report", "secret/do-not-report"),
                         "HTTP unknown; Content-Type: unknown")


if __name__ == "__main__":
    unittest.main()

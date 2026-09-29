"""The provider web console is the only permitted M15-03 VNC route."""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path
from contextlib import redirect_stderr
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m15_console_policy", ROOT / "tools/capture_m15_03_cloud_console.py")
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class CloudConsolePolicyTest(unittest.TestCase):
    def test_direct_console_helper_fails_closed_before_any_connection(self) -> None:
        error = io.StringIO()
        with patch("sys.argv", ["capture_m15_03_cloud_console.py"]), redirect_stderr(error):
            self.assertEqual(POLICY.main(), 2)
        self.assertIn("disabled", error.getvalue())
        self.assertIn("Cloud.ru web console", error.getvalue())

    def test_direct_websocket_or_desktop_vnc_path_is_not_present(self) -> None:
        source = (ROOT / "tools/capture_m15_03_cloud_console.py").read_text()
        for forbidden in ("import websocket", "vnc_ws", "remote-console", "remmina", "create_connection("):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source.lower())


if __name__ == "__main__":
    unittest.main()

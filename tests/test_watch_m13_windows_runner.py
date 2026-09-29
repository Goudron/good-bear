#!/usr/bin/env python3
"""Focused behaviour tests for the bounded Windows runner watchdog."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import watch_m13_windows_runner as WATCH  # noqa: E402


class WatchM13WindowsRunnerTest(unittest.TestCase):
    now = datetime(2026, 9, 26, 20, 0, tzinfo=timezone.utc)

    def test_only_stale_queued_idle_runner_is_eligible(self) -> None:
        action_run = {"status": "queued", "conclusion": None, "updated_at": "2026-09-26T19:50:00Z"}
        runner = {"status": "online", "busy": False}
        self.assertTrue(WATCH.restart_is_safe(action_run, runner, now=self.now, stale_after=timedelta(minutes=3)))
        runner["busy"] = True
        self.assertFalse(WATCH.restart_is_safe(action_run, runner, now=self.now, stale_after=timedelta(minutes=3)))

    def test_rejects_unrecognised_service_before_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary) / "key"; key.write_text("not a real key", encoding="ascii")
            with self.assertRaisesRegex(WATCH.WatchdogError, "unrecognised"):
                WATCH.restart_runner("host", "user", key, "Dhcp")

    def test_three_confirmations_restart_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary) / "key"; key.write_text("key", encoding="ascii")
            answers = iter([
                {"status": "queued", "conclusion": None, "updated_at": "2026-09-26T19:50:00Z"},
                {"status": "online", "busy": False, "name": "runner"},
            ] * 3 + [
                {"status": "in_progress", "conclusion": None, "updated_at": "2026-09-26T20:00:01Z"},
                {"status": "online", "busy": True, "name": "runner"},
            ])
            def command(*_args, **_kwargs):
                return subprocess.CompletedProcess([], 0, __import__('json').dumps(next(answers)), "")
            args = WATCH.parser().parse_args([
                "--repository", "Goudron/good-bear", "--run-id", "1", "--runner-id", "2",
                "--host", "host", "--user", "user", "--identity-file", str(key),
                "--service", "actions.runner.Goudron-good-bear.goodbear-m15-03-win2022",
                "--stale-seconds", "60", "--confirm-polls", "3", "--poll-seconds", "1",
            ])
            with patch.object(WATCH, "restart_runner") as restart:
                self.assertEqual(WATCH.watch(args, run=command, now=lambda: self.now, sleep=lambda _: None), 0)
            restart.assert_called_once()


if __name__ == "__main__":
    unittest.main()

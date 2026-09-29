#!/usr/bin/env python3
"""Bounded SSH watchdog for one queued Windows GitHub Actions job.

The watchdog has no VM-creation, source-transfer, or build responsibilities.
It observes one explicit run and one explicit runner through the GitHub CLI.
Only after repeated evidence that the run is queued while that exact runner is
online and idle may it restart the nominated runner service through key-based
SSH.  It never accepts a password, logs a command's standard output, or
restarts an arbitrary Windows service.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Callable


SERVICE = re.compile(r"^actions\.runner\.[A-Za-z0-9.-]+$")


class WatchdogError(RuntimeError):
    """A malformed controller response or unsafe watchdog request."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchdogError(message)


def parse_utc(value: object) -> datetime:
    require(isinstance(value, str), "GitHub response has no updated_at timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WatchdogError("GitHub response has an invalid updated_at timestamp") from exc
    require(parsed.tzinfo is not None, "GitHub response timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def checked_json(command: list[str], run: Runner = subprocess.run) -> dict:
    completed = run(command, check=False, capture_output=True, text=True)
    require(completed.returncode == 0, "controller command failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise WatchdogError("controller returned invalid JSON") from exc
    require(isinstance(value, dict), "controller returned a non-object JSON value")
    return value


def read_state(repository: str, run_id: int, runner_id: int,
               run: Runner = subprocess.run) -> tuple[dict, dict]:
    action_run = checked_json(
        ["gh", "api", f"repos/{repository}/actions/runs/{run_id}",
         "--jq", "{status,conclusion,updated_at}"], run)
    runner = checked_json(
        ["gh", "api", f"repos/{repository}/actions/runners/{runner_id}",
         "--jq", "{status,busy,name}"], run)
    return action_run, runner


def restart_is_safe(action_run: dict, runner: dict, *, now: datetime,
                    stale_after: timedelta) -> bool:
    return (
        action_run.get("status") == "queued"
        and action_run.get("conclusion") is None
        and runner.get("status") == "online"
        and runner.get("busy") is False
        and now - parse_utc(action_run.get("updated_at")) >= stale_after
    )


def restart_runner(host: str, user: str, key: Path, service: str,
                   run: Runner = subprocess.run) -> None:
    require(SERVICE.fullmatch(service) is not None, "refusing an unrecognised runner service name")
    require(key.is_file() and not key.is_symlink(), "SSH private key is absent or unsafe")
    remote = (
        "$svc=Get-Service -Name '" + service + "' -ErrorAction Stop;"
        "if($svc.Status -ne 'Stopped'){Stop-Service -Name '" + service + "' -Force -ErrorAction Stop};"
        "Start-Service -Name '" + service + "' -ErrorAction Stop;"
        "if((Get-Service -Name '" + service + "').Status -ne 'Running'){throw 'runner service did not start'}"
    )
    completed = run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
         "-o", "StrictHostKeyChecking=accept-new", "-i", str(key),
         f"{user}@{host}", "powershell", "-NoLogo", "-NoProfile",
         "-NonInteractive", "-Command", remote],
        check=False, capture_output=True, text=True)
    require(completed.returncode == 0, "SSH runner-service restart failed")


def watch(args: argparse.Namespace, *, run: Runner = subprocess.run,
          now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
          sleep: Callable[[float], None] = time.sleep,
          emit: Callable[[str], None] = print) -> int:
    stale_after = timedelta(seconds=args.stale_seconds)
    eligible_polls = 0
    restarts = 0
    while True:
        action_run, runner = read_state(args.repository, args.run_id, args.runner_id, run)
        eligible = restart_is_safe(action_run, runner, now=now(), stale_after=stale_after)
        eligible_polls = eligible_polls + 1 if eligible else 0
        event = {"run_status": action_run.get("status"), "runner_status": runner.get("status"),
                 "runner_busy": runner.get("busy"), "eligible_polls": eligible_polls,
                 "restart_count": restarts}
        if action_run.get("status") in {"completed", "in_progress"}:
            event["outcome"] = "job-progressed"; emit(json.dumps(event, sort_keys=True)); return 0
        if eligible_polls >= args.confirm_polls:
            if restarts >= args.max_restarts:
                raise WatchdogError("queued job remained stuck after the allowed runner restart")
            restart_runner(args.host, args.user, args.identity_file, args.service, run)
            restarts += 1; eligible_polls = 0
            event["outcome"] = "runner-restarted"; event["restart_count"] = restarts
        emit(json.dumps(event, sort_keys=True))
        if args.once:
            return 0
        sleep(args.poll_seconds)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", required=True, help="owner/repository")
    result.add_argument("--run-id", required=True, type=int)
    result.add_argument("--runner-id", required=True, type=int)
    result.add_argument("--host", required=True)
    result.add_argument("--user", required=True)
    result.add_argument("--identity-file", required=True, type=Path)
    result.add_argument("--service", required=True)
    result.add_argument("--stale-seconds", type=int, default=180)
    result.add_argument("--confirm-polls", type=int, default=3)
    result.add_argument("--poll-seconds", type=int, default=30)
    result.add_argument("--max-restarts", type=int, default=1)
    result.add_argument("--once", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        require(args.stale_seconds > 0 and args.confirm_polls > 0 and args.poll_seconds > 0,
                "watchdog durations and confirmation count must be positive")
        return watch(args)
    except WatchdogError as exc:
        print(f"watchdog rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

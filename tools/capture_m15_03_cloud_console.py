#!/usr/bin/env python3
"""Fail closed: M15-03 VNC is available only in the Cloud.ru web console.

The provider web console is the sole reviewed interactive recovery route for
Good Bear's Windows builder.  Direct VNC WebSocket clients, local TCP proxies,
and desktop VNC clients must not mint or consume a console endpoint.
"""

from __future__ import annotations

import argparse
import sys


MESSAGE = (
    "M15-03 direct VNC capture is disabled: open the exact tagged builder only "
    "through the Cloud.ru web console on the dedicated display"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", help=argparse.SUPPRESS)
    parser.add_argument("--out", help=argparse.SUPPRESS)
    parser.parse_args()
    print("ERROR: " + MESSAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

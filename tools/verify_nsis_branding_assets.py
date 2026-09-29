#!/usr/bin/env python3
"""Fail closed if Windows NSIS wizard artwork regresses to upstream Firefox assets."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
ARTWORK = ROOT / 'config/m10-03-artwork-system.json'
OVERLAY = ROOT / 'overlay/browser/branding/goodbear'
UPSTREAM = ROOT / 'source/worktrees/firefox-156.0/browser/branding/official'
EXPECTED = {
    'wizWatermark.bmp': (164, 314),
    'wizHeader.bmp': (150, 57),
    'wizHeaderRTL.bmp': (150, 57),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    data = json.loads(ARTWORK.read_text(encoding='utf-8'))
    contract = data.get('windows_nsis_wizard')
    if not isinstance(contract, dict):
        raise SystemExit('missing windows_nsis_wizard artwork contract')
    if contract.get('source') != 'artwork/final/m10-03/goodbear-welcome.png':
        raise SystemExit('wizard artwork must derive from the approved Good Bear welcome asset')
    assets = contract.get('assets')
    if not isinstance(assets, dict) or set(assets) != set(EXPECTED):
        raise SystemExit('wizard artwork contract must cover exactly the three NSIS resources')
    for name, dimensions in EXPECTED.items():
        path = OVERLAY / name
        entry = assets[name]
        if not path.is_file():
            raise SystemExit(f'missing NSIS branding asset: {path}')
        image = Image.open(path)
        if image.size != dimensions or image.mode != 'RGB':
            raise SystemExit(f'{name}: expected RGB {dimensions}, got {image.mode} {image.size}')
        if entry.get('canvas_px') != list(dimensions) or entry.get('sha256') != digest(path):
            raise SystemExit(f'{name}: contract dimensions or digest differs')
        upstream = UPSTREAM / name
        if upstream.is_file() and digest(path) == digest(upstream):
            raise SystemExit(f'{name}: must not be the upstream Firefox NSIS artwork')
    result = subprocess.run([sys.executable, str(ROOT / 'tools/generate_nsis_branding_assets.py'), '--check'], check=False)
    if result.returncode:
        raise SystemExit('NSIS branding assets are not reproducible from the approved source artwork')
    print('PASS: Good Bear NSIS wizard artwork is sized, pinned, non-upstream, and reproducible')


if __name__ == '__main__':
    main()

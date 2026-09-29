#!/usr/bin/env python3
"""Generate deterministic Good Bear artwork for NSIS wizard surfaces."""
import argparse
import io
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'artwork/final/m10-03/goodbear-welcome.png'
OUT = ROOT / 'overlay/browser/branding/goodbear'
FONT = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf')
BG_TOP = (19, 50, 39)
BG_BOTTOM = (11, 31, 25)
ACCENT = (230, 181, 78)
TEXT = (255, 255, 255)


def font(size: int):
    return ImageFont.truetype(str(FONT), size=size)


def vertical_gradient(size: tuple[int, int]) -> Image.Image:
    width, height = size
    image = Image.new('RGB', size)
    pixels = image.load()
    for y in range(height):
        ratio = y / max(height - 1, 1)
        color = tuple(round(BG_TOP[i] * (1 - ratio) + BG_BOTTOM[i] * ratio) for i in range(3))
        for x in range(width):
            pixels[x, y] = color
    return image


def mascot(max_size: tuple[int, int]) -> Image.Image:
    source = Image.open(SOURCE).convert('RGBA')
    alpha = source.getchannel('A')
    source = source.crop(alpha.getbbox())
    source.thumbnail(max_size, Image.Resampling.LANCZOS)
    return source


def watermark() -> Image.Image:
    image = vertical_gradient((164, 314))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((9, 9, 155, 305), radius=14, outline=ACCENT, width=2)
    draw.text((23, 22), 'Good Bear', font=font(18), fill=TEXT)
    draw.line((25, 53, 139, 53), fill=ACCENT, width=2)
    bear = mascot((146, 176))
    image.paste(bear, ((164 - bear.width) // 2, 100), bear)
    return image


def header(rtl: bool) -> Image.Image:
    image = vertical_gradient((150, 57))
    draw = ImageDraw.Draw(image)
    bear = mascot((43, 48))
    if rtl:
        image.paste(bear, (7, 6), bear)
        draw.text((54, 19), 'Good Bear', font=font(14), fill=TEXT)
        draw.line((55, 40, 139, 40), fill=ACCENT, width=1)
    else:
        draw.text((10, 19), 'Good Bear', font=font(14), fill=TEXT)
        draw.line((11, 40, 95, 40), fill=ACCENT, width=1)
        image.paste(bear, (100, 6), bear)
    return image


def bmp_bytes(image: Image.Image) -> bytes:
    data = io.BytesIO()
    image.convert('RGB').save(data, format='BMP')
    return data.getvalue()


def build_assets() -> dict[str, bytes]:
    return {
        'wizWatermark.bmp': bmp_bytes(watermark()),
        'wizHeader.bmp': bmp_bytes(header(False)),
        'wizHeaderRTL.bmp': bmp_bytes(header(True)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true', help='verify committed BMP assets match deterministic generation')
    args = parser.parse_args()
    if not SOURCE.is_file():
        raise SystemExit(f'missing approved source artwork: {SOURCE}')
    if not FONT.is_file():
        raise SystemExit(f'missing deterministic font: {FONT}')
    assets = build_assets()
    if args.check:
        mismatches = [name for name, data in assets.items() if not (OUT / name).is_file() or (OUT / name).read_bytes() != data]
        if mismatches:
            raise SystemExit('NSIS branding assets differ from generator: ' + ', '.join(mismatches))
        return
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in assets.items():
        (OUT / name).write_bytes(data)


if __name__ == '__main__':
    main()

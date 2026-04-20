# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Rebuild the SandGNAT logo pack from the master `SandGNAT-logo.png`.

Outputs every size + the multi-resolution favicon + the Apple touch icon +
a 1200x630 Open Graph / Twitter card + a 1200x400 README banner.

Usage:
    pip install pillow
    python tools/build_logo_pack.py

Inputs:
    SandGNAT-logo.png   master 1024x1024 PNG, repo root.

Outputs (all written to `assets/logo/`):
    sandgnat-logo-{16,32,48,64,96,128,180,192,256,384,512,1024}.png
    favicon.ico           multi-res (16+32+48)
    apple-touch-icon.png  180x180
    social-card.png       1200x630, for og:image / twitter:image
    readme-banner.png     1200x400, for the repo README hero
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "SandGNAT-logo.png"
OUT = ROOT / "assets" / "logo"

SIZES = (16, 32, 48, 64, 96, 128, 180, 192, 256, 384, 512, 1024)
ICO_SIZES = [(16, 16), (32, 32), (48, 48)]


def _backdrop_colour(src: Image.Image) -> tuple[int, int, int]:
    """Average the four corner pixels of the logo. If the result is near
    pure black or white, fall back to a neutral navy so the social card
    doesn't look washed out."""
    sample = src.resize((4, 4), Image.LANCZOS)
    pixels = [sample.getpixel((x, y))[:3] for x, y in
              ((0, 0), (3, 0), (0, 3), (3, 3))]
    avg = tuple(sum(c[i] for c in pixels) // 4 for i in range(3))
    if max(avg) < 30 or min(avg) > 225:
        return (14, 18, 30)
    return avg


def _contrast_text(bg: tuple[int, int, int]) -> tuple[int, int, int]:
    """Pick a body text colour with legible contrast against `bg`."""
    lum = 0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2]
    return (245, 245, 245) if lum < 140 else (15, 15, 15)


def _font(path: str, size: int) -> ImageFont.ImageFont:
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


def build_sizes(src: Image.Image) -> None:
    for size in SIZES:
        img = src.resize((size, size), Image.LANCZOS)
        img.save(OUT / f"sandgnat-logo-{size}.png", optimize=True)


def build_favicon(src: Image.Image) -> None:
    src.copy().save(OUT / "favicon.ico", format="ICO", sizes=ICO_SIZES)


def build_apple_touch(src: Image.Image) -> None:
    img = src.resize((180, 180), Image.LANCZOS)
    img.save(OUT / "apple-touch-icon.png", optimize=True)


def build_social_card(src: Image.Image) -> None:
    bg = _backdrop_colour(src)
    text_rgb = _contrast_text(bg)
    og = Image.new("RGB", (1200, 630), bg)
    logo = src.resize((460, 460), Image.LANCZOS)
    og.paste(logo, (90, 85), mask=logo)
    draw = ImageDraw.Draw(og)
    title_font = _font("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 84)
    sub_font = _font("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 38)
    draw.text((600, 230), "SandGNAT", fill=text_rgb, font=title_font)
    draw.text((600, 330), "Malware runtime analysis", fill=text_rgb, font=sub_font)
    draw.text(
        (600, 380),
        "Proxmox detonation \u00b7 STIX 2.1 \u00b7 trigram similarity",
        fill=text_rgb, font=sub_font,
    )
    og.save(OUT / "social-card.png", optimize=True)


def build_readme_banner(src: Image.Image) -> None:
    bg = _backdrop_colour(src)
    text_rgb = _contrast_text(bg)
    banner = Image.new("RGB", (1200, 400), bg)
    logo = src.resize((320, 320), Image.LANCZOS)
    banner.paste(logo, (60, 40), mask=logo)
    draw = ImageDraw.Draw(banner)
    title_font = _font("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 84)
    sub_font = _font("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 38)
    draw.text((430, 135), "SandGNAT", fill=text_rgb, font=title_font)
    draw.text(
        (430, 235),
        "Automated malware runtime analysis",
        fill=text_rgb, font=sub_font,
    )
    banner.save(OUT / "readme-banner.png", optimize=True)


def main() -> int:
    if not SRC.exists():
        print(f"error: master logo not found at {SRC}", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    src = Image.open(SRC).convert("RGBA")
    build_sizes(src)
    build_favicon(src)
    build_apple_touch(src)
    build_social_card(src)
    build_readme_banner(src)
    print(f"wrote {len(list(OUT.iterdir()))} files to {OUT.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

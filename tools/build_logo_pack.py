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

from PIL import Image, ImageChops, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "SandGNAT-logo.png"
OUT = ROOT / "assets" / "logo"

SIZES = (16, 32, 48, 64, 96, 128, 180, 192, 256, 384, 512, 1024)
ICO_SIZES = [(16, 16), (32, 32), (48, 48)]

# Tolerance for what counts as "background" when finding the logo's content
# bounding box. Pixels where every channel >= this are considered white-ish
# and get trimmed. 235 catches paper-white without eating light-gold or
# off-white highlights inside the logo itself.
BACKGROUND_RGB_THRESHOLD = 235


def _content_bbox(rgba: Image.Image) -> tuple[int, int, int, int] | None:
    """Return the bounding box of non-background pixels, or None if empty.

    Treats any pixel brighter than `BACKGROUND_RGB_THRESHOLD` on every
    channel as background, and any pixel with near-zero alpha as
    transparent background. The bbox is the rectangle that contains
    everything else.
    """
    rgb = rgba.convert("RGB")
    # 1. White-out the bright background: ImageChops.difference against a
    #    synthetic white canvas gives us a monochrome image whose non-zero
    #    pixels are anything "darker than white". Threshold it so near-
    #    white pixels round to zero and don't inflate the bbox.
    white = Image.new("RGB", rgb.size, (255, 255, 255))
    diff = ImageChops.difference(rgb, white).convert("L")
    darkness = diff.point(lambda p: 255 if p > (255 - BACKGROUND_RGB_THRESHOLD) else 0)
    bbox = darkness.getbbox()

    # 2. Also respect the alpha channel: any opaque pixel counts, even if
    #    it happens to be pure white (the master doesn't use that shape
    #    but guarding is cheap).
    if "A" in rgba.getbands():
        alpha = rgba.getchannel("A").point(lambda p: 255 if p >= 16 else 0)
        alpha_bbox = alpha.getbbox()
        if alpha_bbox and bbox:
            bbox = (
                min(bbox[0], alpha_bbox[0]),
                min(bbox[1], alpha_bbox[1]),
                max(bbox[2], alpha_bbox[2]),
                max(bbox[3], alpha_bbox[3]),
            )
        elif alpha_bbox:
            bbox = alpha_bbox
    return bbox


def _crop_for_small_sizes(rgba: Image.Image, padding_ratio: float = 0.04) -> Image.Image:
    """Trim whitespace and pad back a thin margin so the design fills the
    icon frame. Returns a square RGBA with transparent padding; downsampling
    this produces favicons whose silhouette is actually visible at 16px."""
    bbox = _content_bbox(rgba)
    if bbox is None:
        return rgba
    x0, y0, x1, y1 = bbox
    cropped = rgba.crop((x0, y0, x1, y1))
    w, h = cropped.size
    side = max(w, h)
    pad = int(side * padding_ratio)
    canvas_side = side + pad * 2
    canvas = Image.new("RGBA", (canvas_side, canvas_side), (0, 0, 0, 0))
    canvas.paste(cropped, ((canvas_side - w) // 2, (canvas_side - h) // 2))
    return canvas


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


def build_sizes(src: Image.Image, cropped: Image.Image) -> None:
    """Full-frame renditions use the uncropped master (preserves the
    designed margin). Small ones (<=64px) use the cropped variant so the
    design is still legible."""
    for size in SIZES:
        source = cropped if size <= 64 else src
        img = source.resize((size, size), Image.LANCZOS)
        img.save(OUT / f"sandgnat-logo-{size}.png", optimize=True)


def build_favicon(cropped: Image.Image) -> None:
    """Multi-resolution ICO + per-size PNG favicons.

    Browsers prefer PNG `<link rel="icon">` over ICO these days; we emit
    both so every client picks something sharp. All derived from the
    cropped master so the design fills the icon frame.
    """
    # Individual PNG renditions at favicon-friendly sizes.
    for size in (16, 32, 48):
        img = cropped.resize((size, size), Image.LANCZOS)
        img.save(OUT / f"favicon-{size}.png", optimize=True)

    # Multi-resolution ICO. Give Pillow the cropped 256x256 rendition so
    # each downsample happens from a rich source rather than the (lossy)
    # 16x16 we just wrote — Pillow's `sizes=` picks the closest matching
    # sub-image and downsamples from there.
    seed = cropped.resize((256, 256), Image.LANCZOS)
    seed.save(OUT / "favicon.ico", format="ICO", sizes=ICO_SIZES)


def build_apple_touch(cropped: Image.Image) -> None:
    img = cropped.resize((180, 180), Image.LANCZOS)
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
    cropped = _crop_for_small_sizes(src)
    build_sizes(src, cropped)
    build_favicon(cropped)
    build_apple_touch(cropped)
    build_social_card(src)
    build_readme_banner(src)
    print(f"wrote {len(list(OUT.iterdir()))} files to {OUT.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

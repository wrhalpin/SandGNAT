# SandGNAT logo pack

All variants derived from the 1024×1024 PNG at the repo root
(`SandGNAT-logo.png`). Regenerate with:

```bash
python3 tools/build_logo_pack.py
```

## Contents

| File                         | Size       | Purpose                                     |
|------------------------------|------------|---------------------------------------------|
| `sandgnat-logo-16.png`       | 16 × 16    | Favicon fallback                            |
| `sandgnat-logo-32.png`       | 32 × 32    | Favicon / small UI                          |
| `sandgnat-logo-48.png`       | 48 × 48    | Windows jump-list / small desktop icon      |
| `sandgnat-logo-64.png`       | 64 × 64    | Docs sidebar                                |
| `sandgnat-logo-96.png`       | 96 × 96    | Mid-size UI / avatar                        |
| `sandgnat-logo-128.png`      | 128 × 128  | macOS app icon (small)                      |
| `sandgnat-logo-180.png`      | 180 × 180  | Same as `apple-touch-icon.png`              |
| `sandgnat-logo-192.png`      | 192 × 192  | Android home-screen icon                    |
| `sandgnat-logo-256.png`      | 256 × 256  | Hero image on docs landing page             |
| `sandgnat-logo-384.png`      | 384 × 384  | macOS app icon (large)                      |
| `sandgnat-logo-512.png`      | 512 × 512  | Maskable PWA icon / pack master             |
| `sandgnat-logo-1024.png`     | 1024 × 1024| Original / print                            |
| `favicon-16.png`             | 16 × 16    | Modern browser favicon (PNG preferred over ICO) |
| `favicon-32.png`             | 32 × 32    | Modern browser favicon                      |
| `favicon-48.png`             | 48 × 48    | Modern browser favicon (high-DPI)           |
| `favicon.ico`                | 16+32+48   | Multi-resolution legacy icon (IE / pre-2015) |
| `apple-touch-icon.png`       | 180 × 180  | iOS home-screen icon                        |
| `social-card.png`            | 1200 × 630 | Open Graph / Twitter card                   |
| `readme-banner.png`          | 1200 × 400 | Wide banner for the repo README             |

## Usage

### HTML / GitHub Pages

```html
<!-- Modern: browser picks the closest match -->
<link rel="icon" type="image/png" sizes="32x32" href="/assets/logo/favicon-32.png">
<link rel="icon" type="image/png" sizes="16x16" href="/assets/logo/favicon-16.png">
<!-- Legacy fallback for IE + some feed readers -->
<link rel="icon" type="image/x-icon" href="/assets/logo/favicon.ico">
<link rel="apple-touch-icon" href="/assets/logo/apple-touch-icon.png">
<meta property="og:image" content="https://<your-domain>/assets/logo/social-card.png">
```

Note: the small-size icons (≤64px) are generated from a **content-cropped**
version of the master logo — we auto-trim the white border so the design
fills the icon frame. Without cropping, a detailed 1024×1024 logo with
~40% background ends up as a pale smudge at 16×16 and browsers display
it as a near-blank tile.

### Markdown (e.g. the repo README)

```markdown
![SandGNAT](assets/logo/readme-banner.png)
```

### Don't

- Don't re-compress the PNGs through lossy formats (WebP is fine,
  JPEG is not — the logo has hard edges that JPEG smears).
- Don't recolour the logo without updating `SandGNAT-logo.png` at the
  repo root first; the variants should always derive from the master.
- Don't embed the logo in places with a conflicting background colour
  that hides the distinguishing details — there's no inverted/mono
  variant yet.

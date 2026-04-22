<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Bill Halpin
-->

# Seed data for guest profile

`seed-user-profile.ps1` populates the template user's `Documents/`,
`Downloads/`, and `Pictures/` folders from this directory. It's
intentionally empty in the repo — drop your own realistic content in
before baking the template. The script falls back to tiny placeholder
files when a subdirectory is missing.

## Expected layout

```
seed-data/
├── Documents/     # .docx, .xlsx, .pdf, .txt — meeting notes, receipts, etc.
├── Downloads/     # installer .exe/.msi/.zip — realistic app installers
└── Pictures/      # .jpg/.png — real camera output, not stock gradient
```

## What to put here

For a convincing "business desktop" profile:

- **Documents**: 20–40 files spanning the last 18 months. Real file
  sizes (50 KB – 5 MB), not empty placeholders. Mix of `.docx`,
  `.xlsx`, `.pdf`, `.txt`.
- **Downloads**: 5–15 installer artefacts. Vendors' actual installers
  are ideal. Retain original filenames (`setup.exe`,
  `chromesetup.exe`, `vlc-3.0.21-win64.msi`).
- **Pictures**: 30–100 `.jpg`/`.png`. Camera output with EXIF is best
  — malware occasionally checks EXIF metadata. Avoid stock imagery
  (identical hash across sandboxes is itself a signal).

## What NOT to put here

- Copyrighted content you don't have redistribution rights for. The
  repo is Apache-2.0, and commits are public.
- Anything containing PII or real corporate data. Treat this directory
  the same as any other committed asset.
- The actual template image, snapshot files, or any VM artefacts.
  Those belong in your Proxmox storage, not git.

## Generating plausible content

A quick way to build a convincing corpus:

```powershell
# Fake Office docs (PowerShell + Word COM).
$word = New-Object -ComObject Word.Application
foreach ($i in 1..30) {
    $doc = $word.Documents.Add()
    $doc.Content.Text = "Meeting notes " + (Get-Date).AddDays(-$i * 5)
    $doc.SaveAs([ref] "C:\seed-data\Documents\notes-$i.docx")
    $doc.Close()
}
$word.Quit()
```

```bash
# Fake JPEGs with EXIF on Linux.
for i in {1..50}; do
    convert -size 1920x1080 gradient: /tmp/seed.jpg
    exiftool -Make=Canon -Model="EOS R6" -DateTimeOriginal="2025:09:15 14:32:$(printf "%02d" $i)" \
        /tmp/seed.jpg
    mv /tmp/seed.jpg "seed-data/Pictures/IMG_$(printf "%04d" $i).jpg"
done
```

## Version control

The repo tracks only this README. Add a project-level `.gitignore`
entry for `infra/guest/seed-data/*` (excluding this file) so operators
can stage content locally without committing it.

<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Bill Halpin
-->

# Curated HTTP/HTTPS responses

INetSim serves these fixtures when a request's host + path match.
Without them, every `GET` returns the same stub, which is an obvious
sandbox tell.

## Layout

```
responses/
├── www.msftncsi.com/
│   └── ncsi.txt                         → "Microsoft NCSI"
├── www.msftconnecttest.com/
│   └── connecttest.txt                  → "Microsoft Connect Test"
├── www.apple.com/
│   └── library/test/success.html        → Apple captive-portal magic
├── www.google.com/
│   ├── index.html
│   └── generate_204                     → zero-byte 204
└── (add more as real corpus shows up)
```

Each file is served **verbatim** — headers are synthesised by INetSim
from the file's extension, not from the file contents.

## Must-have fixtures

The Windows connectivity probe is non-negotiable. If
`www.msftncsi.com/ncsi.txt` does not return the byte sequence
`Microsoft NCSI`, Windows drops into "limited connectivity" mode and
malware keys off the NCSI failure as a sandbox signal.

The identical concern applies to:

- `msftconnecttest.com/connecttest.txt` → `Microsoft Connect Test`
- `www.apple.com/library/test/success.html` → the exact Apple HTML
  (magic string is "Success" inside a `<HTML>` doc)
- `clients3.google.com/generate_204` → empty 204 (Chrome probe)

## Custom corpus

After running a real detonation, review the ProcMon CSV for
`GET /<path>` that landed on INetSim's default page. For the top
hosts, stage a fixture here so the next detonation returns a
plausible body instead of INetSim's "you reached the honeypot"
placeholder.

## Not in git

Real-world response bodies for mainstream sites (Google homepage,
Microsoft product pages, bank landing pages) are third-party content.
We don't commit them. Operators stage those locally and keep the
corpus out of version control — only the magic-string fixtures (which
Microsoft publishes as RFC-style specs) are safe to ship.

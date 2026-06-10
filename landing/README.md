# MobileCheck landing page

Static ARGUS (C-LAB cyan) landing for `mobilecheck.c-lab.tools`. Bilingual
EN-ES, no trackers, no external CDNs (fonts + assets are vendored, CSP-locked via
`_headers`).

## Deploy (Cloudflare Pages)

Point a Pages project at this `landing/` folder (build command: none; output dir:
`landing/`). Map it to `mobilecheck.c-lab.tools` and link it from the C-LAB desk
page + the ARGUS network map. Mirrors how `api-pass/landing` is deployed.

## Download links

The CTAs point at GitHub Releases "latest" with stable asset names:
- macOS: `…/releases/latest/download/MobileCheck-macOS.dmg`
- Windows: `…/releases/latest/download/MobileCheck-Windows-Setup.exe`

These resolve once a `v*` release is published:
- macOS asset comes from `scripts/release-macos.sh` (build + notarize + publish).
- Windows asset comes from the `Release (Windows)` Actions workflow on a `v*` tag.

Until a release exists, the buttons 404 — publish a release first.

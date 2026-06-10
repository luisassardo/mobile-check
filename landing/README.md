# MobileCheck landing page

Static ARGUS (C-LAB cyan) landing for `mobilecheck.c-lab.tools`. Bilingual
EN-ES, no trackers, no external CDNs (fonts + assets are vendored, CSP-locked via
`_headers`).

## Deploy (Cloudflare Pages, Git-connected — same as the siblings)

The repo `luisassardo/mobile-check` is the source. In the Cloudflare dashboard:
Workers & Pages > Create > Pages > Connect to Git > pick `mobile-check`, then:
- Production branch: `main`
- Build command: (none)
- Build output directory: `landing`
Name the project `mobilecheck`, then add the custom domain
`mobilecheck.c-lab.tools`. Link it from the C-LAB desk page + the ARGUS network
map. Mirrors `computercheck` / `apipass` / `hashcheck`.

Because the repo is PRIVATE, authorize the Cloudflare GitHub app for it when
prompted (it needs read access to build).

## Download links

The CTAs point at GitHub Releases "latest" with stable asset names:
- macOS: `…/releases/latest/download/MobileCheck-macOS.dmg`
- Windows: `…/releases/latest/download/MobileCheck-Windows-Setup.exe`

These resolve once a `v*` release is published:
- macOS asset comes from `scripts/release-macos.sh` (build + notarize + publish).
- Windows asset comes from the `Release (Windows)` Actions workflow on a `v*` tag.

Two caveats before the buttons work for the public:
1. No release exists yet — publish one first (and it gates on real-device testing).
2. **The repo is private**, so release assets are NOT anonymously downloadable.
   Before the public landing's buttons work, either flip the repo to public, or
   host the installers elsewhere (e.g. R2 / a public releases mirror) and point
   the CTAs there.

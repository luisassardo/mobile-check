# Building MobileCheck

## Prerequisites

- Node 18+, Rust stable, Python 3.11+ (universal2 build from python.org on
  macOS if you want a universal engine), `pip3 install --user pyinstaller fpdf2`
- `bash scripts/fetch-platform-tools.sh` once (downloads adb, verifies against
  the pins in `scripts/platform-tools.sha256`).

## Dev

```bash
npm run dev
```

`tauri dev` runs the engine from the Python source tree (`python3 -m
engine.mobilecheck`) and points `MC_RESOURCES` at `src-tauri/resources` so the
bundled adb resolves.

## Release (macOS)

```bash
bash scripts/build-engine.sh        # PyInstaller universal2 sidecar -> src-tauri/engine-dist/
bash scripts/release-macos.sh       # sign + notarize + DMG + GitHub release
```

`build-engine.sh` excludes Pillow/cryptography/cffi (text-only PDFs need
none of them) — that is what keeps the universal2 build possible. The engine
data files (`engine/data/*.json`) ride along via `--add-data`.

Signing: the engine sidecar is Developer-ID signed with hardened runtime by
`build-engine.sh` when `MAC_SIGN_IDENTITY` is set. The bundled
`resources/adb/macos/adb` must be signed the same way before notarization
(release script responsibility, Phase 4).

## Release (Windows)

CI: `.github/workflows/release-windows.yml` — `build-engine.ps1` then
`tauri build`. Push a `v*` tag.

## Engine contract (shell <-> engine)

- stdout: one JSON document — findings payload (`securityscan.findings/2`,
  `tool: "mobile-check"`) or `{"error": "..."}` with exit code 2.
- stderr: NDJSON progress events (`engine/progress.py`), forwarded by the
  shell to the webview as `scan://progress` events. Non-JSON stderr lines are
  forwarded too; the frontend ignores them.
- Cancel: shell sends SIGTERM (taskkill on Windows); the engine traps it and
  cleans up (iOS backup deletion is a context-manager `finally`, Phase 3).

## Per-phone pseudonym

`HMAC-SHA256(key, usb_serial)` truncated to 16 hex chars, key in the OS
keystore (`phone-pseudonym-hmac-key`). Stable per phone per install; not
reversible; not linkable across installs. Computed in Rust, passed to the
engine as `--device-pseudonym`.

## iOS toolchain (Phase 2+, design)

MVT and pymobiledevice3 are NOT compiled into the sidecar (licenses: GPL-3 /
MVT-1.1; C-extension deps break universal2). On first iOS scan, with explicit
consent, the app builds an app-managed venv and installs them
(`pip install --require-hashes -r engine/data/ios-requirements.lock`), then
`mvt-ios download-iocs`.

The relocatable CPython that builds that venv is **downloaded at first iOS
setup, not bundled** — Apple's notary inspects inside bundled `.tar.gz` files
and rejects CPython's unsigned Mach-O (`python3.12`, the `.dylib`/`.so`), so a
bundled runtime makes the whole .app un-notarizable. The download is
hash-verified against `engine/data/python-runtime.json` (keep it in sync with
`scripts/fetch-python-runtime.sh`). So the product makes three network calls,
all download-only, hash-verified, and consent-gated: the Python runtime, the
pip install, and the IoC refresh. `_bundled_python_tarball()` still takes
precedence if a runtime is pre-placed under `resources/python/` for an offline
build, but the notarized release ships none.

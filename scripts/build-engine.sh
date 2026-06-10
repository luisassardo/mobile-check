#!/usr/bin/env bash
# Build the read-only scan engine into a single self-contained binary so the
# notarized app needs NO system Python. Output lands where tauri.conf.json's
# bundle resources expects it.
#
# Run this BEFORE `npm run tauri build` (the release script does it for you).
#
# Requires: python3 with pyinstaller (pip3 install --user pyinstaller).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT_DIR="src-tauri/engine-dist"
NAME="mobile-check-engine"

echo "==> Building engine binary with PyInstaller…"
rm -rf build "${OUT_DIR}" *.spec

# On macOS, build universal2 (Intel + Apple Silicon) so the engine runs on both,
# matching the universal Tauri app. Requires a universal2 Python; if the Python
# isn't universal2 we fall back to the host arch with a warning.
ARCH_ARGS=()
if [[ "$(uname)" == "Darwin" ]]; then
  PY_BIN="$(python3 -c 'import sys; print(sys.executable)')"
  PY_ARCHS="$(lipo -archs "$PY_BIN" 2>/dev/null || echo "")"
  if [[ "$PY_ARCHS" == *x86_64* && "$PY_ARCHS" == *arm64* ]]; then
    echo "==> Universal2 Python detected ($PY_ARCHS) → building universal2 engine"
    ARCH_ARGS=(--target-arch universal2)
  else
    echo "==> WARNING: Python is not universal2 ($PY_ARCHS); engine will be $(uname -m)-only."
    echo "    For Intel + Apple Silicon support, install the python.org universal2 build."
  fi
fi

# Exclude optional C-extension deps we never use: Pillow (fpdf2 image embedding)
# and cryptography/cffi (fpdf2 PDF *encryption*). Our reports are text-only and
# unencrypted, so these aren't needed — and dropping them removes the only
# arch-specific binaries, which is what lets the universal2 build succeed.
python3 -m PyInstaller \
  --onefile \
  --name "${NAME}" \
  --distpath "${OUT_DIR}" \
  --workpath build/pyinstaller \
  --specpath build \
  --paths . \
  --add-data "../engine/data:engine/data" \
  --exclude-module PIL \
  --exclude-module cryptography \
  --exclude-module cffi \
  --exclude-module _cffi_backend \
  "${ARCH_ARGS[@]+"${ARCH_ARGS[@]}"}" \
  scripts/engine_entry.py

# macOS: the bundled engine is its own executable inside the .app, so Apple
# notarization requires IT to be Developer-ID signed with hardened runtime + a
# secure timestamp (PyInstaller only ad-hoc signs it). Sign here, before Tauri
# bundles it. Set MAC_SIGN_IDENTITY in the release script; skipped otherwise (CI/Windows).
if [ -n "${MAC_SIGN_IDENTITY:-}" ]; then
  echo "==> Signing engine binary (Developer ID + hardened runtime + timestamp)…"
  codesign --force --options runtime --timestamp \
    --entitlements scripts/engine.entitlements \
    --sign "$MAC_SIGN_IDENTITY" "${OUT_DIR}/${NAME}"
  codesign --verify --strict --verbose=2 "${OUT_DIR}/${NAME}" 2>&1 | tail -2 || true
fi

echo "==> Smoke test (expect detection JSON on stdout)…"
"${OUT_DIR}/${NAME}" --detect | head -c 200; echo " …"
echo "✅ Engine binary at ${OUT_DIR}/${NAME}"

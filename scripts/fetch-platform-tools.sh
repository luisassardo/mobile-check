#!/usr/bin/env bash
# Fetch Google platform-tools and extract the adb binaries that MobileCheck
# bundles in src-tauri/resources/adb/. Apache-2.0, redistribution permitted;
# the NOTICE file written alongside satisfies the attribution requirement.
#
# Hash pinning: scripts/platform-tools.sha256 records the SHA-256 of each zip.
# - File present  -> downloads MUST match, or the script aborts.
# - File missing  -> first run (TOFU): hashes are recorded and printed so you
#   can cross-check them against another network/machine before trusting them.
#
# Run from anywhere:  bash scripts/fetch-platform-tools.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PINS="$ROOT/scripts/platform-tools.sha256"
RES="$ROOT/src-tauri/resources/adb"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BASE="https://dl.google.com/android/repository"
PLATFORMS=("darwin" "windows")

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

declare -a NEW_PINS=()
for plat in "${PLATFORMS[@]}"; do
  ZIP="platform-tools-latest-${plat}.zip"
  echo "==> Downloading ${ZIP}…"
  curl -fSL --proto '=https' --tlsv1.2 -o "$TMP/$ZIP" "$BASE/$ZIP"
  HASH="$(sha256 "$TMP/$ZIP")"
  if [ -f "$PINS" ]; then
    PINNED="$(grep " ${ZIP}\$" "$PINS" | awk '{print $1}' || true)"
    if [ -z "$PINNED" ]; then
      echo "ERROR: no pin recorded for ${ZIP} in $PINS. Delete the pins file to re-TOFU, or add the pin." >&2
      exit 1
    fi
    if [ "$HASH" != "$PINNED" ]; then
      echo "ERROR: SHA-256 mismatch for ${ZIP}." >&2
      echo "  pinned:     $PINNED" >&2
      echo "  downloaded: $HASH" >&2
      echo "Google publishes new platform-tools regularly; if this is an expected update, delete $PINS and re-run, then commit the new pins." >&2
      exit 1
    fi
    echo "    SHA-256 OK ($HASH)"
  else
    NEW_PINS+=("$HASH  $ZIP")
    echo "    SHA-256 (TOFU, will record): $HASH"
  fi
  unzip -oq "$TMP/$ZIP" -d "$TMP/$plat"
done

if [ ! -f "$PINS" ] && [ "${#NEW_PINS[@]}" -gt 0 ]; then
  printf '%s\n' "${NEW_PINS[@]}" > "$PINS"
  echo "==> Recorded pins in $PINS — verify them out-of-band before committing."
fi

echo "==> Extracting adb binaries into $RES…"
mkdir -p "$RES/macos" "$RES/windows"
cp "$TMP/darwin/platform-tools/adb" "$RES/macos/adb"
chmod +x "$RES/macos/adb"
cp "$TMP/windows/platform-tools/adb.exe" \
   "$TMP/windows/platform-tools/AdbWinApi.dll" \
   "$TMP/windows/platform-tools/AdbWinUsbApi.dll" "$RES/windows/"
cp "$TMP/darwin/platform-tools/NOTICE.txt" "$RES/NOTICE.txt"

VERSION="$("$RES/macos/adb" version 2>/dev/null | head -1 || echo 'version check skipped (non-macOS host)')"
echo "==> Done. $VERSION"

#!/usr/bin/env bash
# Fetch relocatable CPython runtimes (python-build-standalone, PSF-licensed)
# that MobileCheck bundles in src-tauri/resources/python/. On first iOS scan
# the app extracts the matching tarball and builds the MVT venv from it, so
# release builds never depend on a system Python.
#
# Hash pinning works like fetch-platform-tools.sh: pins live in
# scripts/python-runtime.sha256 (TOFU on first run, hard-verify afterwards).
#
# Update RELEASE/PYVER together when bumping; see
# https://github.com/astral-sh/python-build-standalone/releases
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PINS="$ROOT/scripts/python-runtime.sha256"
RES="$ROOT/src-tauri/resources/python"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

RELEASE="20260602"
PYVER="3.12.13"
BASE="https://github.com/astral-sh/python-build-standalone/releases/download/${RELEASE}"

# target-triple -> bundled filename
declare -a TARGETS=(
  "aarch64-apple-darwin macos-aarch64.tar.gz"
  "x86_64-apple-darwin macos-x86_64.tar.gz"
  "x86_64-pc-windows-msvc windows-x86_64.tar.gz"
)

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

mkdir -p "$RES"
declare -a NEW_PINS=()
for entry in "${TARGETS[@]}"; do
  triple="${entry%% *}"
  out="${entry##* }"
  SRC="cpython-${PYVER}+${RELEASE}-${triple}-install_only_stripped.tar.gz"
  echo "==> Downloading ${SRC}…"
  curl -fSL --proto '=https' --tlsv1.2 -o "$TMP/$out" "$BASE/$SRC"
  HASH="$(sha256 "$TMP/$out")"
  if [ -f "$PINS" ]; then
    PINNED="$(grep " ${out}\$" "$PINS" | awk '{print $1}' || true)"
    if [ -z "$PINNED" ] || [ "$HASH" != "$PINNED" ]; then
      echo "ERROR: SHA-256 mismatch or missing pin for ${out} (got $HASH)." >&2
      exit 1
    fi
    echo "    SHA-256 OK"
  else
    NEW_PINS+=("$HASH  $out")
    echo "    SHA-256 (TOFU, will record): $HASH"
  fi
  mv "$TMP/$out" "$RES/$out"
done

if [ ! -f "$PINS" ] && [ "${#NEW_PINS[@]}" -gt 0 ]; then
  printf '%s\n' "${NEW_PINS[@]}" > "$PINS"
  echo "==> Recorded pins in $PINS — verify out-of-band before committing."
fi
echo "==> Done. Runtimes in $RES"

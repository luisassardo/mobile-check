#!/usr/bin/env bash
# Build the engine, then build, sign, and notarize the universal macOS app.
# Mirrors the ApiPass release flow (same Developer ID + notarytool pattern).
#
# Auth: EITHER a Keychain profile (recommended — the password never touches your
# shell or env after the one-time store), OR inline Apple ID + app password.
#
# Recommended (one-time, you type the password into Apple's tool):
#   xcrun notarytool store-credentials "mobilecheck-notary" \
#     --apple-id "your-apple-id@example.com" --team-id "LWSXUT3Y4S"
#   APPLE_KEYCHAIN_PROFILE="mobilecheck-notary" APPLE_TEAM_ID="LWSXUT3Y4S" \
#     bash scripts/release-macos.sh
#
# Inline alternative:
#   APPLE_ID="…" APPLE_PASSWORD="xxxx-xxxx-xxxx-xxxx" APPLE_TEAM_ID="LWSXUT3Y4S" \
#     bash scripts/release-macos.sh
set -euo pipefail

: "${APPLE_TEAM_ID:?set APPLE_TEAM_ID (e.g. LWSXUT3Y4S)}"
if [ -n "${APPLE_KEYCHAIN_PROFILE:-}" ]; then
  NOTARY_AUTH=(--keychain-profile "$APPLE_KEYCHAIN_PROFILE")
else
  : "${APPLE_ID:?set APPLE_ID or APPLE_KEYCHAIN_PROFILE}"
  : "${APPLE_PASSWORD:?set APPLE_PASSWORD or APPLE_KEYCHAIN_PROFILE}"
  NOTARY_AUTH=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID")
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

VERSION="$(node -p "require('./package.json').version")"
TAG="v${VERSION}"
DMG="src-tauri/target/universal-apple-darwin/release/bundle/dmg/MobileCheck_${VERSION}_universal.dmg"

echo "==> MobileCheck v${VERSION} — universal release"
rustup target add x86_64-apple-darwin aarch64-apple-darwin >/dev/null 2>&1 || true

export MAC_SIGN_IDENTITY="Developer ID Application: Luis Assardo (${APPLE_TEAM_ID})"

# 0. Fetch the bundled adb if missing (hash-pinned, Apache-2.0). The Python
#    runtime is NOT bundled — it is downloaded (hash-verified) at first iOS setup,
#    because Apple's notary rejects the unsigned Mach-O inside a bundled CPython.
[ -x "src-tauri/resources/adb/macos/adb" ] || bash scripts/fetch-platform-tools.sh

# 1. Build the self-contained engine binary, signed for notarization (the engine
#    is its own executable inside the .app, so it must be Developer-ID signed with
#    hardened runtime + timestamp). build-engine.sh signs it when MAC_SIGN_IDENTITY is set.
bash scripts/build-engine.sh

# 1b. The bundled adb is also an executable inside the .app — sign it the same
#     way (hardened runtime + timestamp) so notarization accepts it. The python
#     runtime tarballs are inert data (extracted to app-data at runtime, outside
#     the .app), so they need no signing here.
echo "==> Signing bundled adb…"
codesign --force --options runtime --timestamp \
  --sign "$MAC_SIGN_IDENTITY" "src-tauri/resources/adb/macos/adb"
codesign --verify --strict "src-tauri/resources/adb/macos/adb"

# 2. Build + sign the app (release config adds the bundled engine). With the
#    keychain-profile flow we sign here and notarize the .dmg below; with the
#    inline APPLE_PASSWORD flow tauri also notarizes the .app during build.
echo "==> Building + signing the universal app…"
npx tauri build --target universal-apple-darwin --config src-tauri/tauri.release.conf.json

# 3. Notarize + staple the .dmg (retry loop: notarytool uploads can be flaky).
echo "==> Notarizing + stapling the .dmg…"
ok=0
for a in 1 2 3 4 5; do
  xcrun notarytool submit "$DMG" "${NOTARY_AUTH[@]}" \
    --wait > /tmp/cc-notary.log 2>&1 || true
  if grep -q "status: Accepted" /tmp/cc-notary.log; then ok=1; break; fi
  echo "   notary retry ${a}…"; sleep 4
done
[ "$ok" = 1 ] || { echo "Notarization failed — see /tmp/cc-notary.log"; exit 1; }
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
spctl -a -t open --context context:primary-signature -vv "$DMG"

echo "==> Staging assets with a stable name…"
REL="$(mktemp -d)"
cp "$DMG" "$REL/MobileCheck_${VERSION}_universal.dmg"
cp "$DMG" "$REL/MobileCheck-macOS.dmg"   # stable name the landing button links to
( cd "$REL" && shasum -a 256 MobileCheck_${VERSION}_universal.dmg MobileCheck-macOS.dmg > SHA256SUMS-macos.txt && cat SHA256SUMS-macos.txt )

echo "==> Publishing GitHub release ${TAG}…"
REPO="luisassardo/mobile-check"
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  gh release upload "$TAG" --repo "$REPO" --clobber \
    "$REL/MobileCheck_${VERSION}_universal.dmg" "$REL/MobileCheck-macOS.dmg" "$REL/SHA256SUMS-macos.txt"
else
  gh release create "$TAG" --repo "$REPO" --title "MobileCheck ${VERSION}" \
    --notes "macOS (Apple-notarized) + Windows installers. Verify against SHA256SUMS before opening." \
    "$REL/MobileCheck_${VERSION}_universal.dmg" "$REL/MobileCheck-macOS.dmg" "$REL/SHA256SUMS-macos.txt"
fi
echo "✅ Released macOS ${TAG}: $REL/MobileCheck-macOS.dmg"

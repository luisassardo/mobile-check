# MobileCheck

Read-only security self-assessment for **your own phone**, scanned over USB
from your own computer. The mobile sibling of ComputerCheck, built for
journalists and human-rights defenders at risk. Part of C-LAB.

A phone app cannot meaningfully audit the phone it runs on (iOS especially), so
MobileCheck is a desktop companion: download it to macOS or Windows, plug your
phone in with a USB data cable, and run the deepest scan available without
jailbreak or root.

## What it does

- **Android (v0.1, working):** adb-based scan ported from `../android-triage` —
  security patch age, verified boot, root/Magisk indicators, known-stalkerware
  package matching, hidden-icon apps with spy permissions, sideloaded apps,
  accessibility services, notification listeners, device admin apps, default
  SMS handler, global proxy, always-on VPN, user CA certificates.
- **iOS (planned, Phases 2–3):** live lockdownd checks via pymobiledevice3,
  then a temporary encrypted backup analyzed with Amnesty's MVT against
  Citizen Lab / Amnesty IoCs (Pegasus, Predator). Backup deleted after the scan.
- Plain-language report in the app (EN/ES), PDF reports in EN/ES/DE,
  encrypted local history, optional age-encrypted export to C-LAB
  (routine channel excludes spyware IoCs; urgent channel is consent-gated).

## What it is not

- Not a forensic acquisition tool (that is `../securityscan-usb`, operator mode).
- A clean result is NOT proof of safety — advanced zero-click implants may
  leave no USB-visible trace. For court-grade evidence, capture a full
  acquisition and analyze with MVT before changing anything on the device.
- If an abusive-partner situation is possible: removing spyware or alerting
  the suspected abuser can escalate danger. Document first, reach a safety
  plan, then act. Access Now Digital Security Helpline:
  https://www.accessnow.org/help/

## Dev quickstart

```bash
bash scripts/fetch-platform-tools.sh   # bundled adb (hash-pinned)
npm install
npm run dev                            # tauri dev, engine runs from source
```

Engine alone (no app):

```bash
python3 -m engine.mobilecheck --detect          # which phone is plugged in?
python3 -m engine.mobilecheck --pretty          # scan (Android, auto-detect)
```

Release build: see [BUILD.md](BUILD.md).

## Layout

| Path | What |
|---|---|
| `engine/` | Python engine: `mobilecheck.py` entrypoint, `checks_android/`, `checks_ios/` (Phase 2+), reporters, `data/stalkerware_packages.json` |
| `frontend/` | Tauri webview UI (vanilla JS, ARGUS, CSP-locked, EN/ES) |
| `src-tauri/` | Rust shell: scan streaming, per-phone pseudonym (HMAC), encrypted history, age export |
| `scripts/` | engine build (PyInstaller), adb fetch, release |

Conventions: `../CONVENTIONS.md`. Engine code is a vendored copy from siblings
(computer-check, securityscan-usb) per the no-shared-library-until-v1.0 rule.

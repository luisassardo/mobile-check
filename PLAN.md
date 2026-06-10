# mobile-check v1 — Desktop companion for mobile device self-assessment

## Context

Next tool in the `tools-cybersecurity/` portfolio (empty dir already exists at `tools-cybersecurity/mobile-check/`). Like computer-check, it's a downloadable app for journalists/HRDs at risk — but it scans their **phone**, not their laptop. A self-check app *on* the phone can't see anything useful (iOS sandbox especially), so v1 is a **desktop companion**: the user downloads the app to their macOS/Windows laptop, plugs in their own phone via USB, and gets the most advanced no-jailbreak/no-root scan available — the same class of analysis Amnesty Tech uses.

**Decisions made with the user:**
- Architecture: hybrid by phases — v1 = desktop companion (this plan); v2 future = on-device Android lite APK (out of scope, just noted).
- Platforms: iOS + Android both in v1.
- iOS depth: full — live lockdownd checks + temporary encrypted backup + MVT scan against Citizen Lab/Amnesty IoCs (Pegasus, Predator). Backup deleted after scan.
- C-LAB export: same age/X25519 scheme as computer-check (routine + urgent channels), extend `cc_ingest.py`.

**Donors (copy-paste per CONVENTIONS — no shared lib until v1.0):**
- `computer-check/` — Tauri 2.x shell, Python engine + PyInstaller sidecar, Finding model, reporters (HTML/JSON/PDF EN-ES-DE), encrypted history, age export, landing, release scripts.
- `securityscan-usb/engine/ios_backup.py` + `checks_ios/` — working iOS pipeline (pymobiledevice3 detection, encrypted backup, MVT, guaranteed deletion via context-manager `finally`). IDs `IOS-CAT01/02-*` preserved as-is; add missing `*_es` translations.
- `android-triage/android-triage.command` (lines 153–352) — the spec for every Android check, severity, and remediation; port to Python with EN+ES+DE text.

## Key design decisions

### MVT packaging (riskiest problem): split toolchain
**Do NOT bundle MVT/pymobiledevice3 into the PyInstaller sidecar.** Reasons: C-extension deps (`cryptography`, `pyahocorasick`) break the universal2 macOS build that the release flow depends on; pymobiledevice3 is GPL-3 and MVT License 1.1 — compiling them into a signed proprietary binary is a licensing problem (subprocess invocation of separately-installed tools is clean); MVT goes stale chasing iOS releases.

Instead:
- App bundles: engine sidecar (pure-Python + fpdf2), `adb` per OS (Apache 2.0), a relocatable CPython runtime per arch (python-build-standalone tarballs in Tauri resources), and a hash-pinned lockfile `engine/data/ios-requirements.lock`.
- On first iOS scan, a **one-time consent screen** (lists the exact endpoints and what's fetched) bootstraps an app-managed venv: extract CPython → `pip install --require-hashes -r ios-requirements.lock` → `mvt-ios download-iocs` into app data. The only two allowed network calls — download-only, user-initiated, nothing about the user transmitted. After bootstrap everything runs offline. Add an "allowed network calls" paragraph to `CONVENTIONS.md`.
- Fallback for offline deployments: "install from local folder" (`pip install --no-index --find-links <wheelhouse-dir>` from the encrypted USB).

### Progress streaming (new pattern — computer-check blocks on `run_scan`)
A 10–30 min backup needs live progress. Contract: engine **stdout = final JSON only** (unchanged); **stderr = NDJSON events** (`{"ev":"progress","stage":"backup","pct":42,...}` + `{"ev":"need_action","kind":"trust_dialog"|"adb_authorize"}`). In `lib.rs`, `run_scan` switches from `Command::output()` to `spawn()` + a thread emitting `scan://progress` events; frontend subscribes via `TAURI.event.listen`. Add `cancel_scan` (engine traps SIGTERM; backup `finally` still wipes temp files).

### Per-phone pseudonym
Keychain gains `phone-pseudonym-hmac-key` (32 random bytes, reuse `secret_get_or_create`). Pseudonym = hex(HMAC-SHA256(key, UDID_or_serial))[:16], computed in Rust, passed as `--device-pseudonym`. Stable per phone, not reversible, unlinkable across installs. History records gain `platform` + pseudonym for per-phone trends.

### One disclosed exception to read-only
MVT needs an encrypted backup. If the phone has no backup password, the app sets a temporary one and **restores the prior state afterwards** (`backup2 encryption off <pw>`), disclosed on the consent screen. If a password already exists, ask the user for it (Reset-All-Settings recovery text already drafted in securityscan-usb).

### Finding ID namespaces
| Category | iOS | Android |
|---|---|---|
| CAT-1 OS, updates & integrity | `IOS-CAT01-001..006` (ported as-is) | `ANDROID-CAT01-001..005` (+`-1xx` root-deep, SKIP unless rooted) |
| CAT-2 Spyware & IoCs | `IOS-CAT02-*` MVT detections (ported) | `ANDROID-CAT02-001..004` stalkerware/hidden-icon/sideload/perm-heavy |
| CAT-3 Surveillance surface & persistence | `IOS-CAT03-*` NEW live checks | `ANDROID-CAT03-001..006` accessibility, notif listeners, device admin, SMS handler |
| CAT-4 Network & interception | (reserved) | `ANDROID-CAT04-001..003` proxy, always-on VPN, user CA certs |

Vectors per existing map (M-/O-/N-/A-/F-), standards: Citizen Lab IoCs, Amnesty MVT, OWASP MASVS, Apple Platform Security. All findings EN+ES+DE (Du) from day one.

## Directory structure

```
mobile-check/
├── engine/
│   ├── core.py, i18n.py, report_pdf.py, reporters/    ← copy from computer-check
│   ├── mobilecheck.py        NEW entrypoint: detect → dispatch android|ios → JSON stdout
│   ├── progress.py           NEW NDJSON progress on stderr
│   ├── device_detect.py      NEW adb devices + iOS USB presence + trust state machine
│   ├── adb.py                NEW wrapper, resolves bundled adb via MC_RESOURCES env
│   ├── ios_toolchain.py      NEW venv bootstrap / pip --require-hashes / IoC refresh
│   ├── ios_backup.py         ← copy securityscan-usb, adapted (progress, MC_BACKUP_PASSWORD env)
│   ├── checks_android/cat01_integrity.py … cat04_network.py   NEW (ported from bash)
│   ├── checks_ios/cat01_lockdown.py, cat02_backup.py (← copy +*_es), cat03_live.py (NEW)
│   └── data/stalkerware_packages.json, ios-requirements.lock
├── frontend/                 ← copy computer-check (app.js rewritten: device panel, wizard, progress)
├── src-tauri/                ← copy computer-check (lib.rs: streaming, detect_device, cancel_scan,
│   │                            ios_toolchain_* commands, phone pseudonym)
│   └── resources/adb/{macos,windows}/, python/{per-arch tarballs}
├── scripts/                  ← copy build-engine.sh|ps1, release-macos.sh, engine_entry.py
│   ├── fetch-platform-tools.sh   NEW (pinned-hash adb download)
│   └── fetch-python-runtime.sh   NEW (pinned-hash python-build-standalone)
├── landing/                  ← copy computer-check landing, re-skinned (ARGUS cyan, EN-ES)
└── .github/workflows/release-windows.yml
```

Plus sibling edit in Phase 4: `computer-check/ingest/cc_ingest.py` accepts `tool: "mobile-check"` / `MobileCheck-*.age`.

## Phases (ordered by risk × value)

### Phase 1 — Scaffold + Android end-to-end (shippable v0.1)
Copy/rename the computer-check shell (identifier `com.luisassardo.mobilecheck`); strip desktop checks. Fetch + commit pinned adb binaries. Write `mobilecheck.py`, `progress.py`, `device_detect.py`, `adb.py`, and the four `checks_android/` modules porting every android-triage check (identical severities; stalkerware-safety/DV warning preserved verbatim in the report intro; `STALKER_HINTS` externalized to JSON). `lib.rs` streaming + pseudonym. Frontend device panel + live progress.
**Verify:** real Android phone — unauthorized→authorize flow, full scan, findings parity vs a same-day `android-triage.command` run on the same phone; `npm run tauri dev` + PyInstaller release smoke build proving adb resolves from resources.

### Phase 2 — iOS toolchain bootstrap + live checks
`fetch-python-runtime.sh`, lockfile via `pip-compile --generate-hashes`, `ios_toolchain.py` + Tauri commands (`ios_toolchain_status/install`, `refresh_iocs`), consent screen with IoC-age badge. Copy `cat01_lockdown.py` (+`*_es`), write `cat03_live.py`. Wire "iOS quick scan" (no backup).
**Verify:** real iPhone — fresh bootstrap on macOS arm64 (+ Intel/Rosetta sanity), trust dialog, quick scan findings, airplane-mode test proves post-bootstrap scans are offline. **Pull risk #1 forward:** confirm notarized hardened-runtime app can spawn the extracted venv python (strip quarantine xattrs on extraction).

### Phase 3 — iOS encrypted backup + MVT
Adapt `ios_backup.py`: tqdm→progress events, password via env (never argv), disk-space pre-flight (device usage × 1.3 vs host free), encryption-state restore. Copy `cat02_backup.py` (+`*_es`). Frontend wizard (cable → trust → password → progress+ETA → analysis → report), cancel + "do not unplug" guard. Report says backup "deleted" not "securely erased" (APFS honesty).
**Verify:** real iPhone, both password states; full 15–30 min run; mid-scan cancel AND mid-scan unplug leave zero backup remnants; MVT detection path tested by injecting a benign test IoC into a local STIX2 file; encryption flag restored.

### Phase 4 — Export, ingest, landing, release
Export verbatim from computer-check: routine `.age` strips IoC findings, urgent channel behind consent + Access Now link, filename `MobileCheck-<ORG>-<YYYYMMDD>-<pseudonym8>.age`, same `CLAB_AGE_RECIPIENT`. Extend `cc_ingest.py`. Landing (honesty block: "a clean result is not proof — zero-click implants may leave no trace"; ARGUS rules: no em dashes, `data-en`/`data-es`, accent hue 178). Release: codesign bundled adb like the engine sidecar; python tarballs ship as data, extracted at runtime to app-data. Update `CONVENTIONS.md` (tool index + allowed-network-calls rule + v2 APK note).
**Verify:** signed+notarized DMG on a clean Mac (no dev tools): Android scan, iOS bootstrap, full iOS scan, PDFs EN/ES/DE, export decrypts via `cc_ingest.py` with the dev identity.

## Open risks
1. Notarization/quarantine friction spawning extracted-at-runtime python (tested early, Phase 2).
2. `backup2 encryption` edge cases across iOS versions (forgotten existing password → Reset All Settings path; UX must not dead-end).
3. pymobiledevice3 full backups on Windows less battle-tested — fallback: ship Windows iOS as "live checks only" first (honest SKIP for the backup layer).
4. Per-arch python runtimes add ~45 MB to the DMG (engine itself stays universal2) — acceptable, confirm installer time.
5. `stalkerware_packages.json` staleness — maintenance can ride the IoC refresh later.
6. Lockfile maintenance: MVT point releases require regenerating the lock + app point release; document in BUILD.md.

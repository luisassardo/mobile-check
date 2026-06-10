"""MobileCheck engine entrypoint.

The journalist's own phone is scanned over USB from their own laptop. The Tauri
shell invokes this binary; the contract is:

  stdout  -> ONE JSON document (findings payload, or {"error": ...})
  stderr  -> NDJSON progress events (see engine/progress.py), streamed live

Modes:
  --detect                    print connected-device detection JSON and exit
  (default scan)              scan the connected phone, print findings payload

Usage:
    python3 -m engine.mobilecheck [--platform auto|android|ios] [--serial S]
                                  [--org-code CODE] [--device-pseudonym ID]
                                  [--device-label NAME] [--only CAT-1,CAT-2]
                                  [--pretty]

Design notes:
- Read-only on the phone. The one device-side trace of an Android scan is the
  adb authorization the user explicitly approved; the report explains how to
  revoke it.
- Exit code 0 even when checks fail; failures surface as ERROR findings. A
  non-zero exit means the engine itself broke (or no usable device, exit 2,
  with an {"error": ...} JSON on stdout the shell can show).
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time

from . import __version__
from . import adb as adb_mod
from . import device_detect
from .core import ScanContext, Scanner, summarize
from .progress import progress


def _register_android_checks(scanner: Scanner, only: str = "") -> None:
    from .checks_android import cat01_integrity, cat02_stalkerware, cat03_surveillance, cat04_network

    wanted = {c.strip() for c in only.split(",") if c.strip()} if only else None
    available = [
        ("CAT-1: OS & Device Integrity", cat01_integrity.run),
        ("CAT-2: Spyware & Stalkerware", cat02_stalkerware.run),
        ("CAT-3: Surveillance Surface & Persistence", cat03_surveillance.run),
        ("CAT-4: Network & Interception", cat04_network.run),
    ]
    for name, fn in available:
        cat_id = name.split(":")[0].strip()
        if wanted and cat_id not in wanted:
            continue
        scanner.register(name, fn)


def build_payload(ctx: ScanContext, findings: list, summary: dict) -> dict:
    """Schema v2 payload, same shape as computer-check so ingest/dashboard reuse works."""
    return {
        "schema": "securityscan.findings/2",
        "tool": "mobile-check",
        "tool_version": __version__,
        "scan": {
            "id": ctx.scan_id,
            "started_at": ctx.started_at,
            "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ctx.started_at)),
            "hostname": ctx.hostname,
            "device_label": ctx.device_label,
            "os_name": ctx.os_name,
            "os_version": ctx.os_version,
            "arch": ctx.arch,
            "tags": list(ctx.tags),
            "host_info": ctx.host_info,
            "app_mode": ctx.app_mode,
            "org_code": ctx.org_code,
            "device_pseudonym": ctx.device_pseudonym,
        },
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }


def _error_payload(message: str) -> dict:
    return {
        "schema": "securityscan.findings/2",
        "tool": "mobile-check",
        "tool_version": __version__,
        "error": message,
    }


# Stage weights for the Android scan progress bar.
_ANDROID_STAGES = {
    "CAT-1: OS & Device Integrity": (5, "Checking system integrity…", "Revisando integridad del sistema…", "Systemintegrität wird geprüft…"),
    "CAT-2: Spyware & Stalkerware": (25, "Analyzing installed apps…", "Analizando apps instaladas…", "Installierte Apps werden analysiert…"),
    "CAT-3: Surveillance Surface & Persistence": (82, "Checking surveillance surface…", "Revisando superficie de vigilancia…", "Überwachungsfläche wird geprüft…"),
    "CAT-4: Network & Interception": (92, "Checking network settings…", "Revisando configuración de red…", "Netzwerkeinstellungen werden geprüft…"),
}


def scan_android(args: argparse.Namespace) -> int:
    progress("detect", 1, "Looking for your phone…", "Buscando tu teléfono…", "Telefon wird gesucht…")
    dev = device_detect.detect_android()
    if dev["state"] == "none":
        json.dump(_error_payload("No Android device detected over USB. Connect the phone with a data cable and enable USB debugging."), sys.stdout)
        return 2
    if dev["state"] == "unauthorized":
        json.dump(_error_payload("The phone is connected but not authorized. Tap 'Allow' on the USB debugging prompt on the phone, then scan again."), sys.stdout)
        return 2
    serial = args.serial or dev["serial"]

    brand = adb_mod.getprop("ro.product.manufacturer", serial)
    model = adb_mod.getprop("ro.product.model", serial)
    version = adb_mod.getprop("ro.build.version.release", serial)
    label = " ".join(p for p in (brand, model) if p) or "Android device"

    ctx = ScanContext.for_remote_target(
        target_os_name="Android",
        target_os_version=version or "unknown",
        target_arch=adb_mod.getprop("ro.product.cpu.abi", serial) or "unknown",
        target_hostname=label,
        device_label=args.device_label or label,
        app_mode="self-check",
        org_code=args.org_code,
        device_pseudonym=args.device_pseudonym,
        target_serial=serial,
    )

    scanner = Scanner(ctx)
    _register_android_checks(scanner, only=args.only)

    def on_module(name: str) -> None:
        pct, en, es, de = _ANDROID_STAGES.get(name, (50, name, name, name))
        progress("scan", pct, en, es, de)

    findings = scanner.run(on_module_start=on_module)
    progress("report", 97, "Building your report…", "Generando tu informe…", "Bericht wird erstellt…")
    payload = build_payload(ctx, findings, summarize(findings))
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    progress("done", 100, "Done.", "Listo.", "Fertig.")
    return 0


def scan_ios(args: argparse.Namespace) -> int:
    """iOS scan. quick = live lockdownd checks; deep = + encrypted backup + MVT.

    The deep mode's backup password arrives via $MC_BACKUP_PASSWORD (never argv).
    """
    import os
    import tempfile
    from pathlib import Path

    from . import ios_backup, ios_toolchain
    from .checks_ios import cat01_lockdown, cat03_live

    if not ios_toolchain.status()["installed"]:
        json.dump(_error_payload("The iOS toolchain is not installed. Run the one-time iOS setup from the scan screen."), sys.stdout)
        return 2

    progress("detect", 3, "Looking for your iPhone…", "Buscando tu iPhone…", "iPhone wird gesucht…")
    try:
        phone = ios_backup.detect_iphone()
    except ios_backup.NoDeviceError as e:
        json.dump(_error_payload(f"No iPhone detected. Unlock the phone, tap 'Trust' when asked, and try again. ({e})"), sys.stdout)
        return 2
    except ios_backup.DepsMissingError as e:
        json.dump(_error_payload(str(e)), sys.stdout)
        return 2

    ctx = ScanContext.for_remote_target(
        target_os_name="iOS",
        target_os_version=phone.product_version or "unknown",
        target_arch=phone.product_type or "unknown",
        target_hostname=phone.name or "iPhone",
        device_label=args.device_label or phone.name or "iPhone",
        app_mode="self-check",
        org_code=args.org_code,
        device_pseudonym=args.device_pseudonym,
        target_serial=phone.udid,
    )

    findings = []
    progress("scan", 6, "Checking iOS version, profiles and settings…",
             "Revisando versión de iOS, perfiles y ajustes…",
             "iOS-Version, Profile und Einstellungen werden geprüft…")
    findings.extend(cat01_lockdown.run(ctx, phone=phone))
    findings.extend(cat03_live.run(ctx, phone=phone))

    if args.ios_mode == "deep":
        from .checks_ios import cat02_backup
        password = os.environ.get("MC_BACKUP_PASSWORD", "")
        if not password:
            json.dump(_error_payload("Deep scan needs a backup password (MC_BACKUP_PASSWORD). The app provides it from the wizard."), sys.stdout)
            return 2
        work = Path(tempfile.mkdtemp(prefix="mobilecheck-ios-"))
        try:
            with ios_backup.make_encrypted_backup(phone.udid, work / "backup", password) as backup_dir:
                mvt_out = work / "mvt-output"
                r = ios_backup.run_mvt_check_backup(backup_dir, mvt_out, password)
                mvt_summary = ios_backup.parse_mvt_output(mvt_out)
                if r.returncode != 0 and not mvt_summary.get("modules_run"):
                    # MVT failed outright (usually a wrong existing backup password).
                    mvt_summary.setdefault("errors", []).append(
                        (r.stderr or r.stdout)[-800:])
                findings.extend(cat02_backup.run(ctx, phone=phone,
                                                 mvt_summary=mvt_summary,
                                                 backup_dir=backup_dir))
        finally:
            import shutil
            shutil.rmtree(work, ignore_errors=True)

    progress("report", 97, "Building your report…", "Generando tu informe…", "Bericht wird erstellt…")
    payload = build_payload(ctx, findings, summarize(findings))
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    progress("done", 100, "Done.", "Listo.", "Fertig.")
    return 0


def main(argv: list[str] | None = None) -> int:
    # The shell kills the engine with SIGTERM on cancel; exit quietly (Android
    # scans hold no temp state worth cleaning; iOS backup cleanup is Phase 3).
    try:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    except (ValueError, OSError):
        pass

    parser = argparse.ArgumentParser(
        prog="mobile-check",
        description="MobileCheck v%s — read-only self-assessment for your own phone, over USB." % __version__,
    )
    parser.add_argument("--detect", action="store_true", help="Print device detection JSON and exit.")
    parser.add_argument("--toolchain", default="",
                        choices=("", "status", "install", "refresh-iocs"),
                        help="iOS toolchain management subcommand (status | install | refresh-iocs).")
    parser.add_argument("--wheelhouse", default="",
                        help="Local wheel directory for offline toolchain installs.")
    parser.add_argument("--platform", default="auto", choices=("auto", "android", "ios"))
    parser.add_argument("--ios-mode", default="quick", choices=("quick", "deep"),
                        help="iOS scan depth: quick = live checks; deep = + encrypted backup + MVT.")
    parser.add_argument("--serial", default="", help="USB serial of the phone (when several are connected).")
    parser.add_argument("--org-code", default="", help="Organization enrollment code (optional).")
    parser.add_argument("--device-pseudonym", default="",
                        help="Stable opaque per-phone id. The app derives and passes this.")
    parser.add_argument("--device-label", default="", help="Human label for the phone.")
    parser.add_argument("--only", default="", help="Comma-separated categories (e.g. 'CAT-1').")
    parser.add_argument("--pretty", action="store_true", help="Indent the JSON output.")
    args = parser.parse_args(argv)

    if args.detect:
        return device_detect.main()

    if args.toolchain:
        from . import ios_toolchain
        tc_args = [args.toolchain]
        if args.wheelhouse:
            tc_args += ["--wheelhouse", args.wheelhouse]
        return ios_toolchain.cli(tc_args)

    platform_choice = args.platform
    if platform_choice == "auto":
        det = device_detect.detect()
        if det["android"]["state"] != "none":
            platform_choice = "android"
        elif det["ios"]["present"]:
            platform_choice = "ios"
        else:
            json.dump(_error_payload("No phone detected over USB. Connect your phone with a data cable."), sys.stdout)
            return 2

    if platform_choice == "android":
        return scan_android(args)
    return scan_ios(args)


if __name__ == "__main__":
    sys.exit(main())

"""USB phone detection for the scan screen.

Called by the shell as `engine --detect`; prints one JSON object on stdout:

  {
    "android": {"state": "device"|"unauthorized"|"offline"|"none",
                "serial": "...", "model": "..."},
    "ios":     {"present": true|false, "name": "...", "source": "usb"|"none"},
    "adb_available": true|false
  }

Android detection uses the bundled adb. iOS detection here is presence-only
(USB descriptor level) so it works BEFORE the iOS toolchain is installed; full
identity (UDID, iOS version) comes from pymobiledevice3 once the toolchain
exists (Phase 2). Detection is read-only on both platforms.
"""
from __future__ import annotations

import json
import platform
import sys

from . import adb as adb_mod
from .core import run_cmd

APPLE_USB_VENDOR = "0x05ac"  # Apple Inc.


def detect_android() -> dict:
    if not adb_mod.adb_path():
        return {"state": "none", "serial": "", "model": ""}
    adb_mod.start_server()
    devices = adb_mod.list_devices()
    if not devices:
        return {"state": "none", "serial": "", "model": ""}
    # Prefer an authorized device; otherwise surface the first one so the UI
    # can show "tap Allow on the phone".
    devices.sort(key=lambda d: 0 if d["state"] == "device" else 1)
    return devices[0]


def detect_ios_usb() -> dict:
    """Presence-only iPhone/iPad detection at the USB layer."""
    system = platform.system()
    if system == "Darwin":
        r = run_cmd(["system_profiler", "SPUSBDataType", "-json"], timeout=20)
        if r.ok:
            try:
                data = json.loads(r.stdout)
            except json.JSONDecodeError:
                data = {}
            name = _find_apple_mobile_mac(data.get("SPUSBDataType", []))
            if name:
                return {"present": True, "name": name, "source": "usb"}
        return {"present": False, "name": "", "source": "none"}
    if system == "Windows":
        # Look for the Apple Mobile Device USB entry. pnputil ships with Windows 10+.
        r = run_cmd(["pnputil", "/enum-devices", "/connected"], timeout=20)
        if r.ok:
            text = r.stdout.lower()
            if "apple mobile device" in text or "vid_05ac" in text:
                return {"present": True, "name": "iPhone or iPad", "source": "usb"}
        return {"present": False, "name": "", "source": "none"}
    return {"present": False, "name": "", "source": "none"}


def _find_apple_mobile_mac(items: list) -> str:
    """Recursively walk system_profiler USB tree looking for an iPhone/iPad."""
    for item in items:
        name = str(item.get("_name", ""))
        vendor = str(item.get("vendor_id", ""))
        if APPLE_USB_VENDOR in vendor and any(k in name for k in ("iPhone", "iPad", "iPod")):
            return name
        child = _find_apple_mobile_mac(item.get("_items", []))
        if child:
            return child
    return ""


def detect() -> dict:
    return {
        "android": detect_android(),
        "ios": detect_ios_usb(),
        "adb_available": bool(adb_mod.adb_path()),
    }


def main() -> int:
    json.dump(detect(), sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

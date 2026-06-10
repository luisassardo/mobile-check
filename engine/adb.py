"""adb wrapper. Resolves the bundled platform-tools binary, falls back to PATH.

Resolution order:
  1. $MC_ADB — explicit override (tests, unusual setups).
  2. $MC_RESOURCES/adb/<os>/adb — the binary bundled in the app's Tauri
     resources. The shell sets MC_RESOURCES to its resource dir in release and
     to src-tauri/resources in dev.
  3. `adb` on PATH (developer machines with platform-tools installed).

All helpers are read-only: they query the device, never modify it. The only
device-side effect of using adb at all is the adbd authorization entry the
user explicitly approves on the phone; the report tells them how to revoke it.
"""
from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

from .core import CmdResult, run_cmd

_ADB_CACHE: str | None = None


def adb_path() -> str | None:
    """Return the adb binary to use, or None if none is available."""
    global _ADB_CACHE
    if _ADB_CACHE:
        return _ADB_CACHE

    override = os.environ.get("MC_ADB", "").strip()
    if override and Path(override).exists():
        _ADB_CACHE = override
        return _ADB_CACHE

    res = os.environ.get("MC_RESOURCES", "").strip()
    if res:
        sub = "windows" if platform.system() == "Windows" else "macos"
        name = "adb.exe" if platform.system() == "Windows" else "adb"
        cand = Path(res) / "adb" / sub / name
        if cand.exists():
            _ADB_CACHE = str(cand)
            return _ADB_CACHE

    found = shutil.which("adb")
    if found:
        _ADB_CACHE = found
    return _ADB_CACHE


def adb(args: list[str], timeout: int = 20) -> CmdResult:
    """Run an adb command. Returns a CmdResult; never raises."""
    binary = adb_path()
    if not binary:
        return CmdResult(cmd="adb " + " ".join(args), returncode=-1, stdout="", stderr="",
                         exception="adb binary not found (bundled or on PATH)")
    return run_cmd([binary] + args, timeout=timeout)


def shell(cmd: str, serial: str = "", timeout: int = 20) -> str:
    """Run `adb shell <cmd>` and return stripped stdout ('' on any failure)."""
    args = (["-s", serial] if serial else []) + ["shell", cmd]
    r = adb(args, timeout=timeout)
    if not r.ok:
        return ""
    return r.stdout.replace("\r", "").strip()


def getprop(name: str, serial: str = "") -> str:
    return shell(f"getprop {name}", serial=serial)


def list_devices() -> list[dict]:
    """Parse `adb devices -l` into [{serial, state, model}]."""
    r = adb(["devices", "-l"], timeout=10)
    out: list[dict] = []
    if not r.ok and not r.stdout:
        return out
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        if state not in ("device", "unauthorized", "offline", "recovery", "sideload"):
            continue
        model = ""
        for p in parts[2:]:
            if p.startswith("model:"):
                model = p.split(":", 1)[1].replace("_", " ")
        out.append({"serial": serial, "state": state, "model": model})
    return out


def start_server() -> None:
    adb(["start-server"], timeout=20)

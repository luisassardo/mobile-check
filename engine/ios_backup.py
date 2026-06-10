"""iOS audit orchestration: device detection, encrypted backup, MVT analysis, cleanup.

Adapted from securityscan-usb/engine/ios_backup.py for self-service use:
  - the iOS CLIs come from the app-managed venv (engine/ios_toolchain.py),
    resolved lazily because the toolchain can be installed mid-session;
  - operator print() lines became NDJSON progress events for the app UI;
  - the backup password arrives via the MC_BACKUP_PASSWORD env var (never argv);
  - if THIS scan enabled backup encryption, it disables it again afterwards —
    the one disclosed exception to read-only, stated on the consent screen.

`make_encrypted_backup` remains a context manager that GUARANTEES backup
deletion on exit, even if the surrounding code crashes. Privacy-by-default.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .core import CmdResult, run_cmd
from .ios_toolchain import iocs_dir, mvt_ios_path, pymd3_path
from .progress import progress, need_action


class NoDeviceError(RuntimeError):
    pass


class DepsMissingError(RuntimeError):
    pass


# --- Device detection ------------------------------------------------------

@dataclass(frozen=True)
class IPhoneInfo:
    udid: str
    name: str
    product_type: str        # e.g. "iPhone12,8" (SE 2nd gen)
    product_version: str     # iOS version, e.g. "17.5.1"
    build_version: str       # e.g. "21F90"
    serial: str
    model_marketing: str     # human-friendly model, when available
    password_protected: bool = True

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "IPhoneInfo":
        return cls(
            udid=str(raw.get("UniqueDeviceID", "")),
            name=str(raw.get("DeviceName", "(unnamed)")),
            product_type=str(raw.get("ProductType", "")),
            product_version=str(raw.get("ProductVersion", "")),
            build_version=str(raw.get("BuildVersion", "")),
            serial=str(raw.get("SerialNumber", "")),
            model_marketing=str(raw.get("ModelNumber", "")),
            password_protected=bool(raw.get("PasswordProtected", True)),
        )


def detect_iphone(timeout_per_attempt: int = 10, attempts: int = 3) -> IPhoneInfo:
    """Poll for a connected, paired iPhone. Raise NoDeviceError after retries.

    pymobiledevice3 wart: `lockdown info` exits 0 even when no device is
    connected (it logs "Device is not connected" to stderr). We detect that
    case by checking stdout has real data AND stderr lacks the signal.
    """
    pymd3 = pymd3_path()
    if not pymd3:
        raise DepsMissingError("pymobiledevice3 is not installed")

    last_err = ""
    for _ in range(attempts):
        # NOTE: --no-color is a GLOBAL pymobiledevice3 option, must come before the subcommand.
        r = run_cmd([pymd3, "--no-color", "lockdown", "info"], timeout=timeout_per_attempt)
        combined = (r.stderr + r.stdout).lower()
        not_connected = "device is not connected" in combined
        if "trust" in combined and "dialog" in combined:
            need_action("trust_dialog",
                        "Tap 'Trust' on the iPhone and enter its passcode.",
                        "Toca 'Confiar' en el iPhone e ingresa su código.",
                        "Tippe 'Vertrauen' auf dem iPhone und gib den Code ein.")
        if r.ok and not not_connected and r.stdout.strip():
            try:
                data = json.loads(r.stdout)
            except json.JSONDecodeError:
                data = _parse_lockdown_text(r.stdout)
            if data.get("UniqueDeviceID") or data.get("UDID"):
                return IPhoneInfo.parse(data)
            last_err = "lockdown info returned data but no UDID — pairing may have failed"
        else:
            last_err = (r.stderr or r.stdout or r.exception or "no output")[:300]
        time.sleep(2)
    raise NoDeviceError(f"No iPhone detected after {attempts} attempts. Last error: {last_err}")


def _parse_lockdown_text(txt: str) -> dict[str, Any]:
    """Best-effort parse of pymobiledevice3 lockdown info text output."""
    out: dict[str, Any] = {}
    for line in txt.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        v = v.strip()
        if k and v:
            out[k] = v
    return out


# --- Backup orchestration --------------------------------------------------

def backup_encryption_will_change(pymd3: str) -> bool:
    """True if the device has NO backup password yet (we would set a temporary one)."""
    r = run_cmd([pymd3, "--no-color", "backup2", "encryption", "info"], timeout=20)
    txt = (r.stdout + r.stderr).lower()
    # pymobiledevice3 prints e.g. "encryption: off" / WillEncrypt False variants.
    return ("off" in txt or "false" in txt) and r.ok


@contextlib.contextmanager
def make_encrypted_backup(udid: str, backup_root: Path, password: str) -> Iterator[Path]:
    """Create an encrypted backup of the iPhone, yield its path, delete on exit.

    The deletion in the `finally` block is the privacy-critical step. Even if
    the caller raises (or the scan is cancelled via SIGTERM, which surfaces
    here as SystemExit), the backup is wiped. Backups are NEVER retained.
    """
    pymd3 = pymd3_path()
    if not pymd3:
        raise DepsMissingError("pymobiledevice3 is not installed")

    backup_root.mkdir(parents=True, exist_ok=True)
    target_dir = backup_root / udid   # pymobiledevice3 writes <backup_root>/<UDID>/
    we_enabled_encryption = False

    try:
        # 1. Ensure encryption is on (MVT needs it to read protected artifacts).
        #    If the device has no backup password we set a temporary one and
        #    remember to turn it off afterwards (disclosed in the consent UI).
        if backup_encryption_will_change(pymd3):
            progress("backup", 8, "Enabling temporary backup encryption…",
                     "Activando cifrado temporal del respaldo…",
                     "Temporäre Backup-Verschlüsselung wird aktiviert…")
            r = run_cmd([pymd3, "backup2", "encryption", "true", password], timeout=60)
            if r.ok:
                we_enabled_encryption = True
            else:
                raise RuntimeError(f"could not enable backup encryption: {(r.stderr or r.stdout)[:300]}")

        # 2. Run the backup (15-30 min). Parse pymobiledevice3's progress output.
        progress("backup", 10, "Backing up the iPhone — do not unplug (15-30 min)…",
                 "Respaldando el iPhone — no lo desconectes (15-30 min)…",
                 "iPhone-Backup läuft — nicht abstecken (15-30 Min.)…")
        proc = subprocess.Popen(
            [pymd3, "--no-color", "backup2", "backup", "--full", str(backup_root)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        pct_re = re.compile(r"(\d{1,3})\s*%")
        for line in proc.stdout or []:
            m = pct_re.search(line)
            if m:
                # Map the backup's 0-100% into the 10-70% slice of the scan bar.
                pct = 10 + int(int(m.group(1)) * 0.6)
                progress("backup", pct, "Backing up the iPhone — do not unplug…",
                         "Respaldando el iPhone — no lo desconectes…",
                         "iPhone-Backup läuft — nicht abstecken…")
        rc = proc.wait()
        if rc != 0:
            raise RuntimeError(f"pymobiledevice3 backup2 backup failed (exit {rc})")
        if not target_dir.exists():
            raise RuntimeError(f"backup completed but expected directory missing: {target_dir}")
        progress("backup", 70, f"Backup complete ({_dir_size_mb(target_dir):.0f} MB). Analyzing…",
                 f"Respaldo completo ({_dir_size_mb(target_dir):.0f} MB). Analizando…",
                 f"Backup fertig ({_dir_size_mb(target_dir):.0f} MB). Analyse läuft…")
        yield target_dir
    finally:
        # PRIVACY-CRITICAL: wipe the backup unconditionally.
        if target_dir.exists():
            try:
                shutil.rmtree(target_dir)
                progress("cleanup", 96, "Temporary backup deleted.",
                         "Respaldo temporal eliminado.", "Temporäres Backup gelöscht.")
            except Exception as e:
                progress("cleanup", 96,
                         f"WARNING: could not delete the backup at {target_dir}: {e}. Delete it manually.",
                         f"ADVERTENCIA: no se pudo eliminar el respaldo en {target_dir}: {e}. Elimínalo manualmente.",
                         f"WARNUNG: Backup unter {target_dir} konnte nicht gelöscht werden: {e}. Bitte manuell löschen.")
        # Restore the device's prior encryption state if WE enabled it.
        if we_enabled_encryption:
            r = run_cmd([pymd3, "backup2", "encryption", "off", password], timeout=60)
            if r.ok:
                progress("cleanup", 98, "Backup encryption restored to its previous state.",
                         "El cifrado de respaldo volvió a su estado anterior.",
                         "Backup-Verschlüsselung wieder auf vorherigen Zustand gesetzt.")
            else:
                progress("cleanup", 98,
                         "Could not disable the temporary backup password. On the iPhone: Settings > General > Transfer or Reset > Reset > Reset All Settings clears it.",
                         "No se pudo desactivar la contraseña temporal de respaldo. En el iPhone: Ajustes > General > Transferir o restablecer > Restablecer > Restablecer todos los ajustes la elimina.",
                         "Das temporäre Backup-Passwort konnte nicht deaktiviert werden. Auf dem iPhone: Einstellungen > Allgemein > Übertragen/Zurücksetzen > Zurücksetzen > Alle Einstellungen löscht es.")


def _dir_size_mb(p: Path) -> float:
    total = 0
    for root, _, files in os.walk(p):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                pass
    return total / (1024 * 1024)


# --- MVT wrapper -----------------------------------------------------------

def run_mvt_check_backup(backup_dir: Path, output_dir: Path, password: str,
                         iocs_paths: list[Path] | None = None,
                         fast: bool = False) -> CmdResult:
    """Run mvt-ios check-backup against a backup directory.

    MVT writes one JSON per analyzed module under output_dir. The backup
    password travels via the MVT_IOS_BACKUP_PASSWORD env var, never argv.
    """
    mvt = mvt_ios_path()
    if not mvt:
        raise DepsMissingError("mvt-ios is not installed")

    output_dir.mkdir(parents=True, exist_ok=True)
    args = [mvt, "check-backup", "--output", str(output_dir)]
    for ip in (iocs_paths if iocs_paths is not None else list_ioc_files()):
        args.extend(["--iocs", str(ip)])
    if fast:
        args.append("--fast")
    args.append(str(backup_dir))

    env = os.environ.copy()
    env["MVT_IOS_BACKUP_PASSWORD"] = password

    progress("mvt", 75, "Running MVT spyware analysis…", "Ejecutando análisis de spyware MVT…",
             "MVT-Spyware-Analyse läuft…")
    proc = subprocess.run(args, capture_output=True, text=True, env=env, timeout=1800)
    return CmdResult(
        cmd=" ".join(a for a in args if a != password),
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def list_ioc_files() -> list[Path]:
    """All STIX2 IoC files in the app-managed indicators dir."""
    d = iocs_dir()
    if not d.exists():
        return []
    return sorted(d.rglob("*.json"))


def parse_mvt_output(output_dir: Path) -> dict[str, Any]:
    """Aggregate every per-module JSON MVT produced into a single dict.

    MVT writes both `<module>.json` (raw extracted artifacts) and
    `<module>_detected.json` (matches against IoCs). The `_detected` files are
    what we surface.
    """
    summary: dict[str, Any] = {"detected": {}, "modules_run": [], "errors": []}
    if not output_dir.exists():
        return summary

    for p in sorted(output_dir.glob("*.json")):
        module = p.stem
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            summary["errors"].append(f"{p.name}: {e}")
            continue

        if module.endswith("_detected"):
            base = module[: -len("_detected")]
            if isinstance(data, list) and data:
                summary["detected"].setdefault(base, []).extend(data)
        else:
            summary["modules_run"].append(module)

    return summary

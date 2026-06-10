"""App-managed iOS toolchain: pymobiledevice3 + mvt-ios in a private venv.

Why not bundle MVT in the PyInstaller sidecar: C-extension deps break the
universal2 build, GPL-3 / MVT-1.1 licensing forbids compiling them into the
signed binary, and MVT must track new iOS releases faster than app updates.
See BUILD.md.

Layout (under the app's data dir, overridable via $MC_APPDATA):
  <appdata>/ios-toolchain/python/   relocatable CPython (extracted from resources)
  <appdata>/ios-toolchain/venv/     venv with mvt + pymobiledevice3 (hash-pinned)
  <appdata>/iocs/                   STIX2 indicator files (mvt-ios download-iocs)

Network policy (CONVENTIONS: default reservado): this module performs the ONLY
two network operations in the product — `pip install` against pypi.org with
--require-hashes, and the IoC download from the MVT indicators repo. Both are
download-only, user-initiated, consent-gated by the UI, and send nothing about
the user or the scan. Everything else runs offline.

Resolution order for the iOS CLIs (pymobiledevice3, mvt-ios):
  1. $MC_PYMD3 / $MC_MVT explicit overrides (tests)
  2. the app-managed venv
  3. PATH and ~/Library/Python/*/bin (developer machines, securityscan-usb style)
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

from .core import run_cmd
from .progress import progress

IOC_MAX_AGE_WARN_DAYS = 30


# --- Locations ----------------------------------------------------------------

def appdata_dir() -> Path:
    override = os.environ.get("MC_APPDATA", "").strip()
    if override:
        return Path(override)
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "com.luisassardo.mobilecheck"
    if platform.system() == "Windows":
        base = os.environ.get("APPDATA", str(Path.home()))
        return Path(base) / "com.luisassardo.mobilecheck"
    return Path.home() / ".mobile-check"


def toolchain_dir() -> Path:
    return appdata_dir() / "ios-toolchain"


def venv_dir() -> Path:
    return toolchain_dir() / "venv"


def iocs_dir() -> Path:
    return appdata_dir() / "iocs"


def _venv_bin(name: str) -> Path:
    sub = "Scripts" if platform.system() == "Windows" else "bin"
    exe = f"{name}.exe" if platform.system() == "Windows" else name
    return venv_dir() / sub / exe


def _which_fallback(*candidates: str) -> str | None:
    """PATH + pip --user dir lookup (same approach as securityscan-usb)."""
    user_bin = Path.home() / "Library" / "Python"
    for c in candidates:
        p = shutil.which(c)
        if p:
            return p
        if user_bin.exists():
            for ver_dir in user_bin.iterdir():
                bin_path = ver_dir / "bin" / c
                if bin_path.exists() and os.access(bin_path, os.X_OK):
                    return str(bin_path)
    return None


def pymd3_path() -> str | None:
    override = os.environ.get("MC_PYMD3", "").strip()
    if override:
        return override
    venv_bin = _venv_bin("pymobiledevice3")
    if venv_bin.exists():
        return str(venv_bin)
    return _which_fallback("pymobiledevice3")


def mvt_ios_path() -> str | None:
    override = os.environ.get("MC_MVT", "").strip()
    if override:
        return override
    venv_bin = _venv_bin("mvt-ios")
    if venv_bin.exists():
        return str(venv_bin)
    return _which_fallback("mvt-ios")


# --- Status --------------------------------------------------------------------

def ioc_files() -> list[Path]:
    if not iocs_dir().exists():
        return []
    return sorted(iocs_dir().rglob("*.json"))


def ioc_age_days() -> int | None:
    files = ioc_files()
    if not files:
        return None
    newest = max(f.stat().st_mtime for f in files)
    return int((time.time() - newest) / 86400)


def status() -> dict:
    """Machine-readable toolchain status for the UI."""
    pymd3 = pymd3_path()
    mvt = mvt_ios_path()
    age = ioc_age_days()
    return {
        "installed": bool(pymd3 and mvt),
        "pymobiledevice3": pymd3,
        "mvt_ios": mvt,
        "venv": str(venv_dir()) if venv_dir().exists() else None,
        "ioc_count": len(ioc_files()),
        "ioc_age_days": age,
        "ioc_stale": age is None or age > IOC_MAX_AGE_WARN_DAYS,
    }


# --- Bootstrap -------------------------------------------------------------------

def _runtime_target_key() -> str | None:
    """Map the current platform to a python-runtime.json target key."""
    system = platform.system()
    arch = platform.machine().lower()
    if system == "Darwin":
        return "macos-aarch64" if arch in ("arm64", "aarch64") else "macos-x86_64"
    if system == "Windows":
        return "windows-x86_64"
    return None


def _bundled_python_tarball() -> Path | None:
    """An optionally pre-bundled python-build-standalone tarball in app resources.

    Not used by the notarized release (Apple's notary inspects inside tarballs
    and rejects CPython's unsigned Mach-O), but kept as a first choice for
    offline/custom builds that pre-bundle a signed or otherwise trusted runtime.
    """
    res = os.environ.get("MC_RESOURCES", "").strip()
    if not res:
        return None
    key = _runtime_target_key()
    if not key:
        return None
    p = Path(res) / "python" / f"{key}.tar.gz"
    return p if p.exists() else None


def _runtime_spec() -> dict | None:
    """Read engine/data/python-runtime.json -> {url, sha256} for this platform."""
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", "."))
        data_path = base / "engine" / "data" / "python-runtime.json"
    else:
        data_path = Path(__file__).resolve().parent / "data" / "python-runtime.json"
    try:
        data = json.loads(data_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    key = _runtime_target_key()
    target = (data.get("targets") or {}).get(key or "")
    if not target:
        return None
    return {
        "url": f"{data['base_url']}/{target['asset']}",
        "sha256": target["sha256"],
        "asset": target["asset"],
    }


def _download_python_runtime() -> Path | None:
    """Download the hash-pinned CPython tarball into app data, verify, return it.

    This is the second of the consent-gated, download-only network calls (the
    others are pip install + IoC refresh). Nothing about the user is sent.
    """
    spec = _runtime_spec()
    if not spec:
        return None
    dest_dir = toolchain_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / spec["asset"]
    if dest.exists() and _sha256(dest) == spec["sha256"]:
        return dest
    progress("toolchain", 5, "Downloading the Python runtime…",
             "Descargando el entorno de Python…", "Python-Laufzeit wird heruntergeladen…")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(spec["url"], timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f)
    got = _sha256(tmp)
    if got != spec["sha256"]:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"python runtime hash mismatch: expected {spec['sha256']}, got {got}")
    tmp.replace(dest)
    return dest


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _base_python() -> str:
    """Python interpreter used to create the venv.

    Release: the relocatable CPython extracted from app resources.
    Dev (no bundled tarball): the running interpreter / system python3.
    """
    extracted = toolchain_dir() / "python"
    candidates = [
        extracted / "bin" / "python3",                       # python-build-standalone (unix)
        extracted / "python" / "bin" / "python3",
        extracted / "python.exe",                            # windows layout
        extracted / "python" / "python.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    # Obtain a relocatable runtime: a pre-bundled tarball if present (offline
    # builds), otherwise download the hash-pinned one. The release does NOT
    # bundle it (Apple's notary rejects unsigned Mach-O inside bundled tarballs).
    tarball = _bundled_python_tarball() or _download_python_runtime()
    if tarball:
        progress("toolchain", 12, "Unpacking the Python runtime…",
                 "Desempacando el entorno de Python…", "Python-Laufzeit wird entpackt…")
        toolchain_dir().mkdir(parents=True, exist_ok=True)
        with tarfile.open(tarball) as tf:
            tf.extractall(extracted)
        if platform.system() == "Darwin":
            # Clear quarantine so the hardened-runtime app can spawn it.
            subprocess.run(["xattr", "-dr", "com.apple.quarantine", str(extracted)],
                           capture_output=True)
        for c in candidates:
            if c.exists():
                return str(c)
        raise RuntimeError(f"extracted python runtime but found no interpreter under {extracted}")

    # Dev fallback: a system python3 (>=3.10 required by mvt).
    if not getattr(sys, "frozen", False):
        return sys.executable
    sys3 = shutil.which("python3") or shutil.which("python")
    if sys3:
        return sys3
    raise RuntimeError("could not obtain a Python runtime (download failed and no system python3 found)")


def lockfile_path() -> Path:
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", "."))
        return base / "engine" / "data" / "ios-requirements.lock"
    return Path(__file__).resolve().parent / "data" / "ios-requirements.lock"


def bootstrap(wheelhouse: str = "") -> dict:
    """Create the venv and install the pinned iOS toolchain.

    `wheelhouse`: optional local directory of wheels for fully-offline installs
    (pip --no-index --find-links). Otherwise pip talks to pypi.org with
    --require-hashes against the bundled lockfile.
    """
    lock = lockfile_path()
    if not lock.exists():
        raise RuntimeError(f"lockfile missing: {lock}")

    base_py = _base_python()
    progress("toolchain", 25, "Creating the isolated environment…",
             "Creando el entorno aislado…", "Isolierte Umgebung wird erstellt…")
    venv_dir().parent.mkdir(parents=True, exist_ok=True)
    r = run_cmd([base_py, "-m", "venv", "--clear", str(venv_dir())], timeout=120)
    if not r.ok:
        raise RuntimeError(f"venv creation failed: {r.stderr or r.exception}")

    venv_py = _venv_bin("python") if platform.system() == "Windows" else _venv_bin("python3")
    if not venv_py.exists():
        venv_py = _venv_bin("python")

    progress("toolchain", 35, "Installing MVT and pymobiledevice3 (this downloads from PyPI)…",
             "Instalando MVT y pymobiledevice3 (descarga desde PyPI)…",
             "MVT und pymobiledevice3 werden installiert (Download von PyPI)…")
    pip_args = [str(venv_py), "-m", "pip", "install", "--no-input", "--disable-pip-version-check"]
    if wheelhouse:
        pip_args += ["--no-index", "--find-links", wheelhouse]
    pip_args += ["--require-hashes", "-r", str(lock)]
    proc = subprocess.run(pip_args, capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        raise RuntimeError(f"pip install failed:\n{proc.stderr[-2000:]}")

    progress("toolchain", 90, "Verifying the tools…", "Verificando las herramientas…",
             "Werkzeuge werden überprüft…")
    st = status()
    if not st["installed"]:
        raise RuntimeError("toolchain install finished but binaries were not found in the venv")
    progress("toolchain", 100, "iOS toolchain ready.", "Herramientas de iOS listas.",
             "iOS-Werkzeuge bereit.")
    return st


def refresh_iocs() -> dict:
    """Download/refresh the MVT indicator (IoC) files into the app data dir.

    Network: hits the MVT indicators sources (github.com/mvt-project). Download
    only; user-initiated.
    """
    mvt = mvt_ios_path()
    if not mvt:
        raise RuntimeError("mvt-ios is not installed; run the toolchain setup first")
    iocs_dir().mkdir(parents=True, exist_ok=True)
    progress("iocs", 20, "Downloading threat indicators…", "Descargando indicadores de amenazas…",
             "Bedrohungsindikatoren werden heruntergeladen…")
    env = os.environ.copy()
    env["MVT_INDICATORS_FOLDER"] = str(iocs_dir())
    proc = subprocess.run([mvt, "download-iocs"], capture_output=True, text=True,
                          env=env, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"mvt-ios download-iocs failed:\n{(proc.stderr or proc.stdout)[-1500:]}")
    progress("iocs", 100, "Indicators updated.", "Indicadores actualizados.",
             "Indikatoren aktualisiert.")
    return status()


def cli(args: list[str]) -> int:
    """Subcommands used by the shell: status | install [--wheelhouse DIR] | refresh-iocs."""
    cmd = args[0] if args else "status"
    try:
        if cmd == "status":
            out = status()
        elif cmd == "install":
            wheelhouse = ""
            if "--wheelhouse" in args:
                wheelhouse = args[args.index("--wheelhouse") + 1]
            out = bootstrap(wheelhouse=wheelhouse)
        elif cmd == "refresh-iocs":
            out = refresh_iocs()
        else:
            json.dump({"error": f"unknown toolchain command: {cmd}"}, sys.stdout)
            return 2
        json.dump(out, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0
    except Exception as e:
        json.dump({"error": str(e)}, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        return 2

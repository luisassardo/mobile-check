"""Core data model and orchestrator for SecurityScan-USB.

The Finding is the unit of audit output. Every check produces one Finding.
Reporters consume a list of Findings and render HTML/JSON/PDF.

Design principles:
- Findings are immutable once produced.
- A check that cannot run (permission denied, tool missing) produces a
  Finding with status=ERROR or SKIP, never raises.
- Severity is independent of status: a check can PASS (no issue) or FAIL
  (issue present); severity describes how bad the issue would be IF present.
"""
from __future__ import annotations

import json
import platform
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    PASS = "PASS"           # Check ran, no issue
    FAIL = "FAIL"           # Check ran, issue present
    WARN = "WARN"           # Check ran, ambiguous / needs human review
    ERROR = "ERROR"         # Check could not run (e.g. permission denied)
    SKIP = "SKIP"           # Check intentionally skipped (e.g. needs sudo, user opted out)


@dataclass(frozen=True)
class Finding:
    id: str                              # Stable check ID, e.g. "MACOS-CAT01-001"
    title: str                           # One-line human title (English)
    description: str                     # What the check verifies (English)
    category: str                        # e.g. "CAT-1: Updates"
    severity: Severity
    status: Status
    vector_ids: tuple[str, ...] = ()     # IDs from Luis's attack-surface map (F-01, M-02, ...)
    standards: tuple[str, ...] = ()      # e.g. ("CIS L1 1.1", "MITRE T1547")
    command: str = ""                    # The command that was executed
    evidence: str = ""                   # Truncated stdout/stderr
    remediation: str = ""                # What to do, primary action (English)
    interim_mitigation: str = ""         # If primary not viable, budget/EOL device (English)
    references: tuple[str, ...] = ()     # URLs (vendor advisories, blog posts, etc.)
    cve_ids: tuple[str, ...] = ()        # CVE identifiers — rendered as links to NVD

    # German translations (Du form). When empty, reporters fall back to English.
    title_de: str = ""
    description_de: str = ""
    remediation_de: str = ""
    interim_mitigation_de: str = ""
    category_de: str = ""

    # Spanish translations. When empty, reporters fall back to English.
    title_es: str = ""
    description_es: str = ""
    remediation_es: str = ""
    interim_mitigation_es: str = ""
    category_es: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["vector_ids"] = list(self.vector_ids)
        d["standards"] = list(self.standards)
        d["references"] = list(self.references)
        d["cve_ids"] = list(self.cve_ids)
        return d

    def localized(self, lang: str = "en") -> dict[str, str]:
        """Return the translatable fields in the requested language, with EN fallback."""
        if lang == "de":
            return {
                "title": self.title_de or self.title,
                "description": self.description_de or self.description,
                "remediation": self.remediation_de or self.remediation,
                "interim_mitigation": self.interim_mitigation_de or self.interim_mitigation,
                "category": self.category_de or self.category,
            }
        if lang == "es":
            return {
                "title": self.title_es or self.title,
                "description": self.description_es or self.description,
                "remediation": self.remediation_es or self.remediation,
                "interim_mitigation": self.interim_mitigation_es or self.interim_mitigation,
                "category": self.category_es or self.category,
            }
        return {
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "interim_mitigation": self.interim_mitigation,
            "category": self.category,
        }


@dataclass
class ScanContext:
    """Information about the device and scan run, shared across all checks.

    For host self-scans (macOS, Windows): os_name/os_version/arch describe the
    machine being audited.

    For remote-target scans (iOS via Mac host): os_name/os_version/arch describe
    the iPhone being audited, and host_info records the auditing Mac separately
    (e.g. "macOS 26.5 arm64 NSA01").
    """
    scan_id: str
    started_at: float
    hostname: str
    os_name: str           # "macOS", "Windows", "Linux", "iOS"
    os_version: str
    arch: str
    operator_note: str = ""
    tags: tuple[str, ...] = ()    # Operator-defined scope tags, e.g. ("personal",) or ("org-ddhh:ana",)
    device_label: str = ""        # Optional human label, defaults to hostname
    host_info: str = ""           # For remote-target scans: which machine ran the scan

    # Mode B (mobile-check / SelfCheck) fields. Defaults keep Mode A unaffected.
    # See ../securityscan-usb/SELFCHECK-SPEC.md.
    app_mode: str = "self-check"  # "self-check" (this app) vs "forensic" (USB tool)
    org_code: str = ""            # Organization enrollment code, mapped out-of-band by the operator
    device_pseudonym: str = ""    # Opaque per-phone id (HMAC of hardware serial; key in OS keystore)

    # mobile-check: USB serial / UDID of the phone being scanned, used by check
    # modules to address the right device. Never serialized into the payload.
    target_serial: str = ""

    @classmethod
    def detect(cls, operator_note: str = "", tags: tuple[str, ...] = (), device_label: str = "",
               app_mode: str = "self-check", org_code: str = "", device_pseudonym: str = "") -> "ScanContext":
        host = socket.gethostname()
        return cls(
            scan_id=str(uuid.uuid4())[:8],
            started_at=time.time(),
            hostname=host,
            os_name=_detect_os_name(),
            os_version=_detect_os_version(),
            arch=platform.machine(),
            operator_note=operator_note,
            tags=tags,
            device_label=device_label or host,
            app_mode=app_mode,
            org_code=org_code,
            device_pseudonym=device_pseudonym or str(uuid.uuid4()),
        )

    @classmethod
    def for_remote_target(cls, *, target_os_name: str, target_os_version: str, target_arch: str,
                          target_hostname: str, device_label: str,
                          operator_note: str = "", tags: tuple[str, ...] = (),
                          app_mode: str = "self-check", org_code: str = "",
                          device_pseudonym: str = "", target_serial: str = "") -> "ScanContext":
        """Build a ScanContext for a remote target (a phone over USB), recording the
        host (this machine) in `host_info` so the report knows where the scan ran from."""
        host_summary = f"{_detect_os_name()} {_detect_os_version()} {platform.machine()} {socket.gethostname()}"
        return cls(
            scan_id=str(uuid.uuid4())[:8],
            started_at=time.time(),
            hostname=target_hostname,
            os_name=target_os_name,
            os_version=target_os_version,
            arch=target_arch,
            operator_note=operator_note,
            tags=tags,
            device_label=device_label or target_hostname,
            host_info=host_summary,
            app_mode=app_mode,
            org_code=org_code,
            device_pseudonym=device_pseudonym or str(uuid.uuid4()),
            target_serial=target_serial,
        )

    def report_dirname(self) -> str:
        date = time.strftime("%Y-%m-%d", time.localtime(self.started_at))
        safe_host = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.hostname)
        return f"{date}_{safe_host}_{self.scan_id}"


def _detect_os_name() -> str:
    s = platform.system()
    if s == "Darwin":
        return "macOS"
    return s


def _detect_os_version() -> str:
    s = platform.system()
    if s == "Darwin":
        try:
            r = subprocess.run(["sw_vers", "-productVersion"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception:
            pass
    elif s == "Windows":
        # platform.release() = "10" or "11"; platform.version() = "10.0.22631".
        # We surface both: human-friendly + build number.
        try:
            return f"{platform.release()} (build {platform.version()})"
        except Exception:
            pass
    return platform.release()


# ---------------------------------------------------------------------------
# Command execution helpers — every check uses these, never subprocess directly.
# ---------------------------------------------------------------------------

# Hard cap on stored evidence per finding (keep reports small, no leak of huge user data).
MAX_EVIDENCE_BYTES = 4096


@dataclass
class CmdResult:
    cmd: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    exception: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.exception

    def truncated_output(self) -> str:
        combined = self.stdout
        if self.stderr.strip():
            combined += ("\n[stderr]\n" + self.stderr) if combined else self.stderr
        if len(combined) > MAX_EVIDENCE_BYTES:
            combined = combined[:MAX_EVIDENCE_BYTES] + f"\n... [truncated, {len(combined) - MAX_EVIDENCE_BYTES} more bytes]"
        return combined


def run_cmd(args: list[str] | str, timeout: int = 15, shell: bool = False) -> CmdResult:
    """Run a command read-only and capture its output.

    Never raises; always returns a CmdResult. Timeouts are caught.
    """
    cmd_str = args if isinstance(args, str) else " ".join(args)
    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        return CmdResult(cmd=cmd_str, returncode=r.returncode, stdout=r.stdout, stderr=r.stderr)
    except subprocess.TimeoutExpired:
        return CmdResult(cmd=cmd_str, returncode=-1, stdout="", stderr="", timed_out=True)
    except FileNotFoundError as e:
        return CmdResult(cmd=cmd_str, returncode=-1, stdout="", stderr="", exception=f"command not found: {e}")
    except Exception as e:
        return CmdResult(cmd=cmd_str, returncode=-1, stdout="", stderr="", exception=f"{type(e).__name__}: {e}")


def safe_check(check_id: str, category: str, fn, *args, **kwargs) -> "Finding":
    """Run a single check function with full crash isolation.

    A check that raises any exception produces a CRASH Finding for THAT check
    only — instead of taking down the whole category module. Includes a
    truncated traceback in the evidence so the bug can be diagnosed without
    a debugger session.

    Use inside each module's `run()`:
        out.append(safe_check("WIN-CAT02-003", CATEGORY, _check_run_keys))
    """
    import traceback
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        tb = traceback.format_exc()
        return Finding(
            id=f"{check_id}-CRASH",
            title=f"Check crashed: {fn.__name__}",
            description="An internal error in this check prevented it from running. The other checks in this category were unaffected. Report the evidence to the SecurityScan-USB maintainer.",
            category=category,
            severity=Severity.INFO,
            status=Status.ERROR,
            command=f"{fn.__module__}.{fn.__name__}(...)",
            evidence=f"{type(e).__name__}: {e}\n\nTraceback (truncated):\n{tb[-1500:]}",
            remediation="Send this finding ID and evidence to the maintainer. Re-run the scan to see if the crash reproduces.",
            title_de=f"Prüfung abgestürzt: {fn.__name__}",
            description_de="Ein interner Fehler in dieser Prüfung verhinderte ihre Ausführung. Die anderen Prüfungen dieser Kategorie waren nicht betroffen. Den Nachweis an die SecurityScan-USB-Maintainer:in melden.",
            remediation_de="Diese Befund-ID und den Nachweis an die Maintainer:in senden. Scan neu starten, um zu prüfen, ob der Absturz reproduzierbar ist.",
            category_de=category,
        )


def run_ps(script: str, timeout: int = 30) -> CmdResult:
    """Run a PowerShell command on Windows. Use for read-only system queries.

    Notes:
    - We use `-NoProfile -NonInteractive -Command` so the user's $PROFILE doesn't run
      and the call won't block on a prompt.
    - We do NOT pass `-ExecutionPolicy Bypass` because -Command strings are not subject
      to the script execution policy. Using Bypass would look like script-policy
      evasion in event logs without actually being needed.
    - Prefer scripts that emit JSON (`| ConvertTo-Json -Compress`) and parse the JSON
      in Python, instead of scraping table output.
    """
    return run_cmd(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

CheckFn = Callable[[ScanContext], list[Finding]]


@dataclass
class CheckModule:
    name: str
    fn: CheckFn


class Scanner:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.modules: list[CheckModule] = []
        self.findings: list[Finding] = []

    def register(self, name: str, fn: CheckFn) -> None:
        self.modules.append(CheckModule(name=name, fn=fn))

    def run(self, on_module_start: Callable[[str], None] | None = None) -> list[Finding]:
        for mod in self.modules:
            if on_module_start:
                on_module_start(mod.name)
            try:
                self.findings.extend(mod.fn(self.ctx))
            except Exception as e:
                # A check module crashed. Record an ERROR finding so the report shows it.
                self.findings.append(Finding(
                    id=f"ENGINE-{mod.name}-CRASH",
                    title=f"Check module {mod.name!r} crashed",
                    description="The check module raised an unhandled exception. This is a tool bug, not a finding about the device.",
                    category=mod.name,
                    severity=Severity.INFO,
                    status=Status.ERROR,
                    evidence=f"{type(e).__name__}: {e}",
                    remediation="Report this to the SecurityScan-USB maintainer.",
                ))
        return self.findings


# ---------------------------------------------------------------------------
# Summary stats for the report header
# ---------------------------------------------------------------------------

def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_severity_failing: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}

    for f in findings:
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
        if f.status == Status.FAIL:
            by_severity_failing[f.severity.value] = by_severity_failing.get(f.severity.value, 0) + 1
        cat = by_category.setdefault(f.category, {"total": 0, "PASS": 0, "FAIL": 0, "WARN": 0, "ERROR": 0, "SKIP": 0})
        cat["total"] += 1
        cat[f.status.value] += 1

    # Score: simple weighted model. CRITICAL FAIL = -25, HIGH = -10, MEDIUM = -4, LOW = -1.
    # Start at 100, floor at 0.
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    penalty = sum(by_severity_failing.get(sev, 0) * w for sev, w in weights.items())
    score = max(0, 100 - penalty)

    return {
        "total": len(findings),
        "by_status": by_status,
        "by_severity_failing": by_severity_failing,
        "by_category": by_category,
        "score": score,
    }

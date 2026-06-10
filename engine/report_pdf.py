"""Generate a PDF report (default German) from a v2 findings payload.

The app calls this only when the user asks for a PDF. The payload (the exact
JSON that mobilecheck.py produced and that lives in the encrypted history) is
read from stdin; the PDF is written to --out.

    cat payload.json | python3 -m engine.report_pdf --out report-de.pdf --lang de

Reuses engine/reporters/pdf.py, which already renders EN and DE (Du form).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import Finding, ScanContext, Severity, Status

# fpdf2 warns at import that Pillow is unavailable; we ship without Pillow on
# purpose (text-only reports), so silence that one benign warning.
import warnings
warnings.filterwarnings("ignore", message=".*Pillow.*")


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d["id"],
        title=d.get("title", ""),
        description=d.get("description", ""),
        category=d.get("category", ""),
        severity=Severity(d.get("severity", "INFO")),
        status=Status(d.get("status", "SKIP")),
        vector_ids=tuple(d.get("vector_ids", [])),
        standards=tuple(d.get("standards", [])),
        command=d.get("command", ""),
        evidence=d.get("evidence", ""),
        remediation=d.get("remediation", ""),
        interim_mitigation=d.get("interim_mitigation", ""),
        references=tuple(d.get("references", [])),
        cve_ids=tuple(d.get("cve_ids", [])),
        title_de=d.get("title_de", ""),
        description_de=d.get("description_de", ""),
        remediation_de=d.get("remediation_de", ""),
        interim_mitigation_de=d.get("interim_mitigation_de", ""),
        category_de=d.get("category_de", ""),
        title_es=d.get("title_es", ""),
        description_es=d.get("description_es", ""),
        remediation_es=d.get("remediation_es", ""),
        interim_mitigation_es=d.get("interim_mitigation_es", ""),
        category_es=d.get("category_es", ""),
    )


def _ctx_from_payload(p: dict) -> ScanContext:
    s = p.get("scan", {})
    return ScanContext(
        scan_id=s.get("id", ""),
        started_at=float(s.get("started_at", 0) or 0),
        hostname=s.get("hostname", ""),
        os_name=s.get("os_name", ""),
        os_version=s.get("os_version", ""),
        arch=s.get("arch", ""),
        tags=tuple(s.get("tags", [])),
        device_label=s.get("device_label", ""),
        app_mode=s.get("app_mode", "self-check"),
        org_code=s.get("org_code", ""),
        device_pseudonym=s.get("device_pseudonym", ""),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mobile-check pdf")
    parser.add_argument("--out", required=True, help="Destination PDF path.")
    parser.add_argument("--lang", default="de", choices=("en", "de", "es"),
                        help="Report language: en, de (German, Du form), or es (Spanish).")
    parser.add_argument("--in", dest="in_path", default="",
                        help="Read payload from this file instead of stdin.")
    args = parser.parse_args(argv)

    raw = Path(args.in_path).read_text(encoding="utf-8") if args.in_path else sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"invalid payload JSON: {e}", file=sys.stderr)
        return 2

    ctx = _ctx_from_payload(payload)
    findings = [_finding_from_dict(d) for d in payload.get("findings", [])]
    summary = payload.get("summary", {})
    tool_version = payload.get("tool_version", __version__)

    try:
        from .reporters import pdf
        pdf.write(Path(args.out), ctx, findings, summary, tool_version=tool_version, lang=args.lang)
    except ImportError as e:
        print(f"{e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"PDF generation failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 4

    print(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

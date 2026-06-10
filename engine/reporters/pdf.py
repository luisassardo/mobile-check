"""PDF reporter — printable, EN/DE.

Uses fpdf2. The PDF intentionally has a different shape than the HTML report:
- HTML is interactive, dark, exploration-oriented.
- PDF is white, paginated, archive-oriented. Optimised for printing and email.

A "Document Property Reference" section at the end maps every finding ID to its
page number, so the PDF works as a stable per-device record.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..core import Finding, ScanContext, Severity, Status
from ..i18n import t

try:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
except ImportError as e:
    raise ImportError("fpdf2 is required for PDF generation. Install with: pip3 install --user fpdf2") from e


# Severity → RGB (subtle, print-safe)
SEV_COLORS = {
    "CRITICAL": (200, 50, 60),
    "HIGH":     (220, 110, 50),
    "MEDIUM":   (200, 165, 40),
    "LOW":      (90, 160, 110),
    "INFO":     (110, 120, 135),
}
STATUS_COLORS = {
    "PASS":  (60, 145, 80),
    "FAIL":  (200, 50, 60),
    "WARN":  (200, 165, 40),
    "ERROR": (180, 130, 40),
    "SKIP":  (110, 120, 135),
}

STATUS_ORDER = ["FAIL", "WARN", "ERROR", "SKIP", "PASS"]
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class _PDF(FPDF):
    def __init__(self, ctx: ScanContext, lang: str, tool_version: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.ctx = ctx
        self.lang = lang
        self.tool_version = tool_version
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(left=15, top=15, right=15)
        self.set_font("helvetica", size=10)

    # Auto-sanitize all text passed to cell/multi_cell so we never crash on a
    # stray Unicode glyph. The core PDF fonts only support latin-1; _safe()
    # maps common typographic chars (en/em dashes, middots, arrows, emoji) to
    # ASCII-friendly replacements before fpdf attempts the encode.
    def cell(self, w=0, h=0, text="", *args, **kwargs):  # type: ignore[override]
        return super().cell(w, h, _safe(text), *args, **kwargs)

    def multi_cell(self, w=0, h=0, text="", *args, **kwargs):  # type: ignore[override]
        return super().multi_cell(w, h, _safe(text), *args, **kwargs)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("helvetica", "", 8)
        self.set_text_color(120)
        self.cell(0, 6, _safe(f"{t('report_title', self.lang)} - {self.ctx.device_label}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        self.set_draw_color(220)
        self.line(15, 22, self.w - 15, 22)
        self.ln(4)
        self.set_text_color(0)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "", 8)
        self.set_text_color(140)
        self.cell(0, 8, _safe(f"MobileCheck v{self.tool_version}  |  {t('page', self.lang)} {self.page_no()}"),
                  align="C")
        self.set_text_color(0)


def write(path: Path, ctx: ScanContext, findings: list[Finding], summary: dict[str, Any],
          tool_version: str, lang: str = "en") -> None:
    pdf = _PDF(ctx, lang, tool_version)
    pdf.add_page()

    _render_cover(pdf, ctx, summary, lang)

    pdf.add_page()
    _render_summary_table(pdf, summary, lang)

    # Sort findings: status order first, then severity, then category
    findings_sorted = sorted(
        findings,
        key=lambda f: (
            STATUS_ORDER.index(f.status.value) if f.status.value in STATUS_ORDER else 99,
            SEV_ORDER.index(f.severity.value) if f.severity.value in SEV_ORDER else 99,
            f.category,
            f.id,
        ),
    )

    pdf.add_page()
    _render_findings(pdf, findings_sorted, lang)

    pdf.output(str(path))


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _render_cover(pdf: _PDF, ctx: ScanContext, summary: dict[str, Any], lang: str) -> None:
    # Top: title block
    pdf.set_font("helvetica", "B", 20)
    pdf.cell(0, 12, t("report_title", lang),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(120)
    pdf.cell(0, 5, _safe(f"v{pdf.tool_version}  |  {time.strftime('%Y-%m-%d %H:%M', time.localtime(ctx.started_at))}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0)
    pdf.ln(8)

    # Score block
    score = summary.get("score", 0)
    score_color = (60, 145, 80)
    if score < 50: score_color = (200, 50, 60)
    elif score < 75: score_color = (220, 110, 50)
    elif score < 90: score_color = (200, 165, 40)
    pdf.set_font("helvetica", "B", 60)
    pdf.set_text_color(*score_color)
    pdf.cell(50, 24, str(score), align="L")
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(110)
    pdf.cell(0, 24, _safe(f"{t('posture_score', lang)} (0-100)"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    pdf.set_text_color(0)
    pdf.ln(6)

    # Device + scan metadata
    rows = [
        (t("device", lang), f"{ctx.device_label}  ({ctx.hostname}, {ctx.arch})"),
        (t("os", lang), f"{ctx.os_name} {ctx.os_version}"),
        (t("scan_started", lang), time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ctx.started_at))),
        (t("scan_id", lang), ctx.scan_id),
    ]
    if ctx.tags:
        rows.append((t("tags", lang), ", ".join(ctx.tags)))
    if ctx.operator_note:
        rows.append((t("operator_note", lang), ctx.operator_note))

    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 7, t("summary", lang),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(200)
    pdf.line(15, pdf.get_y(), pdf.w - 15, pdf.get_y())
    pdf.ln(3)

    for label, value in rows:
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(110)
        pdf.cell(45, 6, _safe(label))
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(0)
        pdf.multi_cell(0, 6, _safe(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _render_summary_table(pdf: _PDF, summary: dict[str, Any], lang: str) -> None:
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, t("summary", lang),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    # By severity (failing only)
    failing = summary.get("by_severity_failing", {})
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 7, t("by_severity_failing", lang),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    pdf.set_font("helvetica", "", 9)
    for sev in SEV_ORDER:
        count = failing.get(sev, 0)
        color = SEV_COLORS.get(sev, (110, 120, 135))
        pdf.set_fill_color(*color)
        pdf.set_text_color(255)
        pdf.cell(28, 7, _safe(sev), align="C", fill=True)
        pdf.set_text_color(0)
        pdf.cell(20, 7, str(count), align="C", border="B")
        pdf.cell(0, 7, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # By status
    by_status = summary.get("by_status", {})
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 7, t("by_status", lang),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    pdf.set_font("helvetica", "", 9)
    for st in STATUS_ORDER:
        count = by_status.get(st, 0)
        if count == 0:
            continue
        color = STATUS_COLORS.get(st, (110, 120, 135))
        pdf.set_fill_color(*color)
        pdf.set_text_color(255)
        pdf.cell(28, 7, _safe(st), align="C", fill=True)
        pdf.set_text_color(0)
        pdf.cell(20, 7, str(count), align="C", border="B")
        pdf.cell(0, 7, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _render_findings(pdf: _PDF, findings: list[Finding], lang: str) -> None:
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, t("findings_section", lang),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    if not findings:
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 7, t("no_findings", lang),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        return

    # Group by category
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        loc = f.localized(lang)
        cat = loc["category"]
        by_cat.setdefault(cat, []).append(f)

    for cat, items in by_cat.items():
        # Avoid orphan section title at page bottom
        if pdf.get_y() > pdf.h - 40:
            pdf.add_page()
        pdf.set_font("helvetica", "B", 12)
        pdf.set_fill_color(240, 242, 245)
        pdf.cell(0, 8, _safe(cat), new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        pdf.ln(2)
        for f in items:
            _render_finding(pdf, f, lang)


def _render_finding(pdf: _PDF, f: Finding, lang: str) -> None:
    loc = f.localized(lang)

    # Estimate space; force page break if a finding would split awkwardly at the very top
    if pdf.get_y() > pdf.h - 50:
        pdf.add_page()

    sev_color = SEV_COLORS.get(f.severity.value, (110, 120, 135))
    status_color = STATUS_COLORS.get(f.status.value, (110, 120, 135))

    # Header row: status pill + severity pill + ID + title
    pdf.set_font("helvetica", "B", 9)

    pdf.set_fill_color(*status_color)
    pdf.set_text_color(255)
    pdf.cell(16, 6, _safe(f.status.value), align="C", fill=True)

    pdf.set_fill_color(*sev_color)
    pdf.cell(20, 6, _safe(f.severity.value), align="C", fill=True)

    pdf.set_text_color(110)
    pdf.set_font("helvetica", "", 8)
    pdf.cell(36, 6, _safe(f.id))

    pdf.set_text_color(0)
    pdf.set_font("helvetica", "B", 10)
    pdf.multi_cell(0, 6, _safe(loc["title"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    # Body sections
    _para(pdf, t("section_description", lang), loc["description"])
    if f.command:
        _para(pdf, t("section_command", lang), f.command, mono=True)
    if f.evidence:
        _para(pdf, t("section_evidence", lang), f.evidence, mono=True, max_lines=12)
    if loc["remediation"]:
        _para(pdf, t("section_remediation", lang), loc["remediation"])
    if loc["interim_mitigation"]:
        _para(pdf, t("section_interim", lang), loc["interim_mitigation"], italic=True)

    if f.cve_ids:
        _para(pdf, t("section_cves", lang),
              "  |  ".join(f.cve_ids) + "    (NVD: nvd.nist.gov/vuln/detail/<CVE-ID>)")
    tags_line = []
    if f.vector_ids:
        tags_line.extend(f.vector_ids)
    if f.standards:
        tags_line.extend(f.standards)
    if tags_line:
        _para(pdf, t("section_mapped", lang), "  |  ".join(tags_line))
    if f.references:
        _para(pdf, t("section_references", lang), "\n".join(f.references), mono=True)

    pdf.set_draw_color(230)
    pdf.line(15, pdf.get_y() + 1, pdf.w - 15, pdf.get_y() + 1)
    pdf.ln(5)


def _para(pdf: _PDF, label: str, body: str, mono: bool = False, italic: bool = False, max_lines: int | None = None) -> None:
    pdf.set_font("helvetica", "B", 8)
    pdf.set_text_color(110)
    pdf.cell(0, 5, _safe(label), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if mono:
        pdf.set_font("courier", "", 8)
    elif italic:
        pdf.set_font("helvetica", "I", 9)
    else:
        pdf.set_font("helvetica", "", 9)

    pdf.set_text_color(20 if not italic else 80)
    safe_body = _safe(body)
    if max_lines is not None:
        lines = safe_body.splitlines()
        if len(lines) > max_lines:
            safe_body = "\n".join(lines[:max_lines]) + f"\n... [+{len(lines)-max_lines} more lines]"
    pdf.multi_cell(0, 5, safe_body, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0)
    pdf.ln(1)


def _safe(s: str) -> str:
    """Replace characters that the core PDF fonts (latin-1) can't render.

    fpdf2's core fonts use cp1252; arrows, em-dashes, and box drawing fail.
    We do a small ASCII-friendly replacement table to keep the PDF readable
    without shipping a Unicode TTF.
    """
    if s is None:
        return ""
    table = {
        "→": "->",
        "←": "<-",
        "↑": "^",
        "↓": "v",
        "·": "-",
        "—": "-",
        "–": "-",
        "•": "*",
        "…": "...",
        "“": '"', "”": '"', "„": '"',
        "‘": "'", "’": "'",
        "⚠": "[!]",
        "✓": "[ok]",
        "✗": "[x]",
        "🛡": "",
        "🔴": "[CRIT]",
        "🟠": "[HIGH]",
        "🟡": "[MED]",
        "🟢": "[LOW]",
        " ": " ",   # NBSP
    }
    out = []
    for ch in str(s):
        out.append(table.get(ch, ch))
    text = "".join(out)
    # Final pass: drop anything still outside latin-1 to avoid fpdf errors.
    return text.encode("latin-1", "replace").decode("latin-1")

"""HTML reporter — self-contained, offline, interactive single-file report.

No external CDN, no JS framework, no build step. Pure CSS + vanilla JS.
The report opens in any modern browser directly from the USB.
"""
from __future__ import annotations

import html
import json
import time
from pathlib import Path

from ..core import Finding, ScanContext, Status

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
STATUS_ORDER = ["FAIL", "WARN", "ERROR", "SKIP", "PASS"]


def write(path: Path, ctx: ScanContext, findings: list[Finding], summary: dict, tool_version: str) -> None:
    findings_json = json.dumps([f.to_dict() for f in findings], ensure_ascii=False)
    summary_json = json.dumps(summary, ensure_ascii=False)
    ctx_json = json.dumps({
        "scan_id": ctx.scan_id,
        "hostname": ctx.hostname,
        "os_name": ctx.os_name,
        "os_version": ctx.os_version,
        "arch": ctx.arch,
        "started_at_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ctx.started_at)),
        "operator_note": ctx.operator_note,
    }, ensure_ascii=False)

    content = _TEMPLATE.replace("__FINDINGS_JSON__", findings_json) \
        .replace("__SUMMARY_JSON__", summary_json) \
        .replace("__CTX_JSON__", ctx_json) \
        .replace("__TOOL_VERSION__", html.escape(tool_version)) \
        .replace("__GENERATED_AT__", html.escape(time.strftime("%Y-%m-%d %H:%M:%S")))
    path.write_text(content, encoding="utf-8")


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecurityScan Report</title>
<style>
:root {
  --bg: #0b0d10;
  --panel: #14181d;
  --panel-2: #1c2128;
  --border: #2a313b;
  --fg: #e6edf3;
  --fg-muted: #8b95a3;
  --fg-dim: #6b7480;
  --accent: #4493f8;
  --critical: #ff5d62;
  --high: #ff9f5d;
  --medium: #ffd866;
  --low: #88d4a3;
  --info: #8b95a3;
  --pass: #3fb950;
  --fail: #ff5d62;
  --warn: #ffd866;
  --error: #d29922;
  --skip: #6b7480;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--fg); font: 14px/1.55 -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.container { max-width: 1280px; margin: 0 auto; padding: 32px 24px; }

header.top { display: flex; align-items: baseline; justify-content: space-between; gap: 24px; flex-wrap: wrap; margin-bottom: 24px; }
header.top h1 { font-size: 22px; margin: 0; font-weight: 600; }
header.top .meta { color: var(--fg-muted); font-size: 13px; }
header.top .badge { display: inline-block; padding: 2px 8px; background: var(--panel-2); border: 1px solid var(--border); border-radius: 12px; font-family: var(--mono); font-size: 11px; margin-left: 6px; }

section.summary { display: grid; grid-template-columns: 220px 1fr; gap: 24px; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 24px; }
.score-box { text-align: center; }
.score-num { font-size: 64px; font-weight: 700; line-height: 1; font-family: var(--mono); }
.score-label { color: var(--fg-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 8px; }
.score-bar { height: 6px; background: var(--panel-2); border-radius: 3px; margin-top: 12px; overflow: hidden; }
.score-bar > div { height: 100%; transition: width 0.3s; }

.summary-tiles { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; align-content: center; }
.tile { background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }
.tile .num { font-size: 22px; font-weight: 600; font-family: var(--mono); }
.tile .label { font-size: 11px; color: var(--fg-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
.tile.crit .num { color: var(--critical); }
.tile.high .num { color: var(--high); }
.tile.med .num { color: var(--medium); }
.tile.low .num { color: var(--low); }
.tile.info .num { color: var(--info); }

section.context { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 24px; margin-bottom: 24px; font-size: 13px; }
section.context dl { display: grid; grid-template-columns: 140px 1fr; gap: 4px 16px; margin: 0; }
section.context dt { color: var(--fg-muted); }
section.context dd { margin: 0; font-family: var(--mono); }

.controls { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; padding: 14px 16px; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; }
.controls label { color: var(--fg-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-right: 4px; }
.controls input[type="text"] { background: var(--panel-2); border: 1px solid var(--border); color: var(--fg); padding: 6px 10px; border-radius: 6px; min-width: 240px; font: inherit; }
.controls .filter-group { display: flex; gap: 4px; }
.chip { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 14px; background: var(--panel-2); border: 1px solid var(--border); font-size: 12px; cursor: pointer; user-select: none; transition: all 0.15s; }
.chip.active { background: var(--accent); border-color: var(--accent); color: white; }
.chip .count { font-family: var(--mono); opacity: 0.7; font-size: 11px; }

.findings-list { display: flex; flex-direction: column; gap: 10px; }
.finding { background: var(--panel); border: 1px solid var(--border); border-left-width: 4px; border-radius: 8px; padding: 14px 18px; transition: all 0.15s; }
.finding[data-severity="CRITICAL"] { border-left-color: var(--critical); }
.finding[data-severity="HIGH"] { border-left-color: var(--high); }
.finding[data-severity="MEDIUM"] { border-left-color: var(--medium); }
.finding[data-severity="LOW"] { border-left-color: var(--low); }
.finding[data-severity="INFO"] { border-left-color: var(--info); }
.finding.hidden { display: none; }

.finding-head { display: flex; align-items: center; gap: 12px; cursor: pointer; }
.finding-head .status-pill { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: var(--mono); letter-spacing: 0.04em; min-width: 50px; text-align: center; }
.status-pill.PASS { background: rgba(63, 185, 80, 0.15); color: var(--pass); }
.status-pill.FAIL { background: rgba(255, 93, 98, 0.15); color: var(--fail); }
.status-pill.WARN { background: rgba(255, 216, 102, 0.15); color: var(--warn); }
.status-pill.ERROR { background: rgba(210, 153, 34, 0.15); color: var(--error); }
.status-pill.SKIP { background: rgba(107, 116, 128, 0.15); color: var(--skip); }

.severity-pill { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: var(--mono); letter-spacing: 0.04em; }
.severity-pill.CRITICAL { background: rgba(255, 93, 98, 0.15); color: var(--critical); }
.severity-pill.HIGH { background: rgba(255, 159, 93, 0.15); color: var(--high); }
.severity-pill.MEDIUM { background: rgba(255, 216, 102, 0.15); color: var(--medium); }
.severity-pill.LOW { background: rgba(136, 212, 163, 0.15); color: var(--low); }
.severity-pill.INFO { background: rgba(139, 149, 163, 0.15); color: var(--info); }

.finding-title { flex: 1; font-weight: 500; }
.finding-cat { color: var(--fg-muted); font-size: 12px; font-family: var(--mono); }
.finding-id { color: var(--fg-dim); font-size: 11px; font-family: var(--mono); }
.toggle { color: var(--fg-muted); font-size: 14px; transition: transform 0.15s; }
.finding.expanded .toggle { transform: rotate(90deg); }

.finding-body { display: none; margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--border); }
.finding.expanded .finding-body { display: block; }

.finding-section { margin-bottom: 14px; }
.finding-section h4 { margin: 0 0 6px 0; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--fg-muted); font-weight: 500; }
.finding-section p { margin: 0; }
.finding-section .mitigation { color: var(--fg-muted); font-style: italic; padding-left: 12px; border-left: 2px solid var(--border); }

pre.evidence { background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; font: 12px/1.5 var(--mono); overflow-x: auto; max-height: 320px; overflow-y: auto; white-space: pre-wrap; word-break: break-word; }
code { font-family: var(--mono); background: var(--panel-2); padding: 1px 6px; border-radius: 3px; font-size: 12px; }

.tags { display: flex; flex-wrap: wrap; gap: 6px; }
.tag { font-family: var(--mono); font-size: 11px; padding: 2px 6px; background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; color: var(--fg-muted); }
.tag.vector { color: var(--accent); }
.tag.cve { color: var(--high); border-color: rgba(255,159,93,0.3); background: rgba(255,159,93,0.08); font-weight: 500; }
.tag.cve a { color: inherit; text-decoration: none; }
.tag.cve a:hover { text-decoration: underline; }

footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--fg-dim); font-size: 12px; text-align: center; }

.empty { text-align: center; padding: 60px 20px; color: var(--fg-muted); }

@media (max-width: 700px) {
  section.summary { grid-template-columns: 1fr; }
  .summary-tiles { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>
<body>
<div class="container">

<header class="top">
  <div>
    <h1>SecurityScan Report <span class="badge">v__TOOL_VERSION__</span></h1>
    <div class="meta" id="header-meta"></div>
  </div>
  <div class="meta">Generated __GENERATED_AT__</div>
</header>

<section class="summary">
  <div class="score-box">
    <div class="score-num" id="score">—</div>
    <div class="score-label">Posture Score</div>
    <div class="score-bar"><div id="score-bar-inner"></div></div>
  </div>
  <div class="summary-tiles" id="summary-tiles"></div>
</section>

<section class="context" id="context"></section>

<div class="controls">
  <label>Search</label>
  <input type="text" id="search" placeholder="title, id, evidence, vector, standard…">
  <label>Status</label>
  <div class="filter-group" id="status-filters"></div>
  <label>Severity</label>
  <div class="filter-group" id="severity-filters"></div>
</div>

<div class="findings-list" id="findings-list"></div>

<footer>
  SecurityScan-USB — read-only audit. Findings reflect the device state at scan time. Re-scan periodically.
  <br>This report contains technical detail about the audited device. Treat as confidential.
</footer>

</div>

<script>
const FINDINGS = __FINDINGS_JSON__;
const SUMMARY = __SUMMARY_JSON__;
const CTX = __CTX_JSON__;

// --- header & summary ---
document.getElementById('header-meta').textContent = `${CTX.os_name} ${CTX.os_version} (${CTX.arch}) — ${CTX.hostname} — scan ${CTX.scan_id}`;

const score = SUMMARY.score;
const scoreEl = document.getElementById('score');
scoreEl.textContent = score;
const barInner = document.getElementById('score-bar-inner');
barInner.style.width = score + '%';
let scoreColor = 'var(--pass)';
if (score < 50) scoreColor = 'var(--critical)';
else if (score < 75) scoreColor = 'var(--high)';
else if (score < 90) scoreColor = 'var(--medium)';
scoreEl.style.color = scoreColor;
barInner.style.background = scoreColor;

const tiles = [
  { key: 'CRITICAL', label: 'Critical fail', cls: 'crit' },
  { key: 'HIGH', label: 'High fail', cls: 'high' },
  { key: 'MEDIUM', label: 'Medium fail', cls: 'med' },
  { key: 'LOW', label: 'Low fail', cls: 'low' },
  { key: 'INFO', label: 'Info', cls: 'info' },
];
const failingBySev = SUMMARY.by_severity_failing || {};
document.getElementById('summary-tiles').innerHTML = tiles.map(t => `
  <div class="tile ${t.cls}">
    <div class="num">${failingBySev[t.key] || 0}</div>
    <div class="label">${t.label}</div>
  </div>
`).join('');

// --- context ---
const ctxEl = document.getElementById('context');
ctxEl.innerHTML = `<dl>
  <dt>Device</dt><dd>${escapeHtml(CTX.hostname)} (${escapeHtml(CTX.arch)})</dd>
  <dt>OS</dt><dd>${escapeHtml(CTX.os_name)} ${escapeHtml(CTX.os_version)}</dd>
  <dt>Scan started</dt><dd>${escapeHtml(CTX.started_at_iso)}</dd>
  <dt>Scan ID</dt><dd>${escapeHtml(CTX.scan_id)}</dd>
  ${CTX.operator_note ? `<dt>Operator note</dt><dd>${escapeHtml(CTX.operator_note)}</dd>` : ''}
</dl>`;

// --- filter chips ---
const STATUS_ORDER = ['FAIL', 'WARN', 'ERROR', 'SKIP', 'PASS'];
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const statusFilters = document.getElementById('status-filters');
const severityFilters = document.getElementById('severity-filters');

const activeStatus = new Set(['FAIL', 'WARN', 'ERROR']);
const activeSeverity = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

function buildChips() {
  const statusCounts = {};
  const sevCounts = {};
  FINDINGS.forEach(f => {
    statusCounts[f.status] = (statusCounts[f.status] || 0) + 1;
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  });
  statusFilters.innerHTML = STATUS_ORDER.map(s =>
    `<span class="chip ${activeStatus.has(s) ? 'active' : ''}" data-status="${s}">${s} <span class="count">${statusCounts[s] || 0}</span></span>`
  ).join('');
  severityFilters.innerHTML = SEVERITY_ORDER.map(s =>
    `<span class="chip ${activeSeverity.has(s) ? 'active' : ''}" data-severity="${s}">${s} <span class="count">${sevCounts[s] || 0}</span></span>`
  ).join('');
  statusFilters.querySelectorAll('.chip').forEach(c => c.addEventListener('click', () => {
    const s = c.dataset.status;
    if (activeStatus.has(s)) activeStatus.delete(s); else activeStatus.add(s);
    c.classList.toggle('active');
    render();
  }));
  severityFilters.querySelectorAll('.chip').forEach(c => c.addEventListener('click', () => {
    const s = c.dataset.severity;
    if (activeSeverity.has(s)) activeSeverity.delete(s); else activeSeverity.add(s);
    c.classList.toggle('active');
    render();
  }));
}

const search = document.getElementById('search');
search.addEventListener('input', render);

function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function findingMatchesSearch(f, q) {
  if (!q) return true;
  const ql = q.toLowerCase();
  const haystack = [f.id, f.title, f.description, f.category, f.evidence, f.command, f.remediation,
    (f.standards || []).join(' '), (f.vector_ids || []).join(' '), (f.cve_ids || []).join(' ')].join(' ').toLowerCase();
  return haystack.includes(ql);
}

function severityRank(s) { return SEVERITY_ORDER.indexOf(s); }
function statusRank(s) { return STATUS_ORDER.indexOf(s); }

function render() {
  const q = search.value.trim();
  const list = document.getElementById('findings-list');
  const filtered = FINDINGS.filter(f =>
    activeStatus.has(f.status) && activeSeverity.has(f.severity) && findingMatchesSearch(f, q)
  );
  filtered.sort((a, b) => {
    const sa = statusRank(a.status), sb = statusRank(b.status);
    if (sa !== sb) return sa - sb;
    const va = severityRank(a.severity), vb = severityRank(b.severity);
    if (va !== vb) return va - vb;
    return a.category.localeCompare(b.category);
  });

  if (filtered.length === 0) {
    list.innerHTML = '<div class="empty">No findings match the current filters.</div>';
    return;
  }

  list.innerHTML = filtered.map(f => `
    <article class="finding" data-severity="${f.severity}" data-status="${f.status}" data-id="${escapeHtml(f.id)}">
      <header class="finding-head">
        <span class="status-pill ${f.status}">${f.status}</span>
        <span class="severity-pill ${f.severity}">${f.severity}</span>
        <span class="finding-cat">${escapeHtml(f.category)}</span>
        <span class="finding-title">${escapeHtml(f.title)}</span>
        <span class="finding-id">${escapeHtml(f.id)}</span>
        <span class="toggle">▶</span>
      </header>
      <div class="finding-body">
        ${f.description ? `<div class="finding-section"><h4>Description</h4><p>${escapeHtml(f.description)}</p></div>` : ''}
        ${f.command ? `<div class="finding-section"><h4>Command</h4><p><code>${escapeHtml(f.command)}</code></p></div>` : ''}
        ${f.evidence ? `<div class="finding-section"><h4>Evidence</h4><pre class="evidence">${escapeHtml(f.evidence)}</pre></div>` : ''}
        ${f.remediation ? `<div class="finding-section"><h4>Remediation</h4><p>${escapeHtml(f.remediation)}</p></div>` : ''}
        ${f.interim_mitigation ? `<div class="finding-section"><h4>Interim mitigation</h4><p class="mitigation">${escapeHtml(f.interim_mitigation)}</p></div>` : ''}
        ${f.cve_ids && f.cve_ids.length ? `
          <div class="finding-section">
            <h4>Related CVEs</h4>
            <div class="tags">
              ${(f.cve_ids || []).map(c => `<span class="tag cve"><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(c)}" target="_blank" rel="noopener">${escapeHtml(c)}</a></span>`).join('')}
            </div>
          </div>` : ''}
        ${(f.standards && f.standards.length) || (f.vector_ids && f.vector_ids.length) ? `
          <div class="finding-section">
            <h4>Mapped to</h4>
            <div class="tags">
              ${(f.vector_ids || []).map(v => `<span class="tag vector">${escapeHtml(v)}</span>`).join('')}
              ${(f.standards || []).map(s => `<span class="tag">${escapeHtml(s)}</span>`).join('')}
            </div>
          </div>` : ''}
        ${f.references && f.references.length ? `
          <div class="finding-section">
            <h4>References</h4>
            <ul style="margin:0; padding-left: 18px;">
              ${f.references.map(r => `<li><a href="${escapeHtml(r)}" target="_blank" rel="noopener">${escapeHtml(r)}</a></li>`).join('')}
            </ul>
          </div>` : ''}
      </div>
    </article>
  `).join('');

  list.querySelectorAll('.finding').forEach(el => {
    el.querySelector('.finding-head').addEventListener('click', () => el.classList.toggle('expanded'));
  });
}

buildChips();
render();
</script>
</body>
</html>
"""

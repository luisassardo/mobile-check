"""JSON reporter — machine-readable findings.json for the dashboard and tooling."""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from ..core import Finding, ScanContext


def write(path: Path, ctx: ScanContext, findings: list[Finding], summary: dict, tool_version: str) -> None:
    payload = {
        "schema": "securityscan.findings/1",
        "tool_version": tool_version,
        "scan": {
            "id": ctx.scan_id,
            "started_at": ctx.started_at,
            "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ctx.started_at)),
            "hostname": ctx.hostname,
            "device_label": ctx.device_label,
            "os_name": ctx.os_name,
            "os_version": ctx.os_version,
            "arch": ctx.arch,
            "operator_note": ctx.operator_note,
            "tags": list(ctx.tags),
            "host_info": ctx.host_info,  # populated for remote-target scans (iOS via Mac)
        },
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }
    # Force UTF-8: on Windows, Path.write_text defaults to cp1252 which fails
    # on non-Latin-1 characters (arrows, em-dashes, etc.) commonly found in
    # check evidence and remediation text.
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

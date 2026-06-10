"""NDJSON progress events for the Tauri shell.

Contract with the shell (src-tauri/src/lib.rs):
  - stdout carries ONLY the final findings JSON payload.
  - stderr carries one JSON object per line, streamed while the scan runs.

Event shapes:
  {"ev": "progress", "stage": "apps", "pct": 42, "msg": "...", "msg_es": "...", "msg_de": "..."}
  {"ev": "need_action", "kind": "adb_authorize", "msg": "...", "msg_es": "...", "msg_de": "..."}
  {"ev": "log", "msg": "..."}

The shell forwards each line verbatim to the webview as a `scan://progress`
event; the frontend decides how to render it. Plain-text stderr (tracebacks,
warnings from third-party tools) is forwarded too, so receivers must tolerate
non-JSON lines.
"""
from __future__ import annotations

import json
import sys


def _emit(obj: dict) -> None:
    try:
        sys.stderr.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stderr.flush()
    except Exception:
        pass  # progress is best-effort; never break the scan over it


def progress(stage: str, pct: int, msg: str, msg_es: str = "", msg_de: str = "") -> None:
    _emit({"ev": "progress", "stage": stage, "pct": max(0, min(100, int(pct))),
           "msg": msg, "msg_es": msg_es, "msg_de": msg_de})


def need_action(kind: str, msg: str, msg_es: str = "", msg_de: str = "") -> None:
    _emit({"ev": "need_action", "kind": kind, "msg": msg, "msg_es": msg_es, "msg_de": msg_de})


def log(msg: str) -> None:
    _emit({"ev": "log", "msg": msg})
